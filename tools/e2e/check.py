"""Offline self-check for the end-to-end harness assets.

These invariants are easy to verify without Docker and expensive to discover in
CI, so they are checked here rather than trusted:

1. every generated value is removed from a captured log by the redaction script;
2. the generated environment file survives shell sourcing intact;
3. the topology exposes no port and keeps the sentinel off the client network.

Run through ``make e2e_check``. Nothing here contacts a network or starts Docker.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

from generate import (
    redaction_values,
    redaction_values_path,
    shell_environment_path,
    write_environment,
    write_redaction_values,
)

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = os.path.join(HERE, "docker-compose.yml")
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "e2e.yml")
PRIVATE_ONLY_SERVICES = ("sentinel", "camouflage")

# Synthetic values shaped like the generator's real output.
SAMPLE = {
    "V2RAY_SUBSCRIPTION": "http://subscription:8081/subscription",
    "JERRYPROXY_E2E_SENTINEL_HOST": "sentinel",
    "JERRYPROXY_E2E_SENTINEL_PORT": "8080",
    "JERRYPROXY_E2E_BACKEND": "mihomo",
    "JERRYPROXY_E2E_BACKEND_VERSION": "1.19.29",
    "JERRYPROXY_E2E_MARKER": "a1b2c3d4" * 6,
    "JERRYPROXY_E2E_SS_NODE": (
        "ss://YWVzLTI1Ni1nY206c3ludGhldGljc2FtcGxlcGFzc3dvcmQ@ss-server:10001#e2e-ss"
    ),
    "JERRYPROXY_E2E_VMESS_NODE": (
        "vmess://eyJhZGQiOiJ2bWVzcy1zZXJ2ZXIiLCJpZCI6IjEyMzQ1Njc4LWFiY2QtZWZhYi0xMjM0LTU2Nzg5MGFiY2RlZiJ9"
    ),
    "JERRYPROXY_E2E_VLESS_NODE": (
        "vless://12345678-abcd-efab-1234-567890abcdef@vless-server:10003"
        "?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.test"
        "&fp=chrome&pbk=SYNTHETICREALITYPUBLICKEYSAMPLE&sid=0f1e2d3c4b5a6978#e2e-vless"
    ),
}
SECRET_NAMES = ("JERRYPROXY_E2E_MARKER",) + tuple(
    name for name in SAMPLE if name.endswith("_NODE")
)
# Secrets that exist only inside an encoded field, or that no client ever
# receives. A server echoing its rejected configuration can still print them,
# so redaction must cover them even though no export contains them.
# Synthetic stand-ins for the values the generator produces. Passing them
# through the generator's own classifier means dropping one there is caught,
# while comparing the result back against this mapping means narrowing the
# classifier is caught too — a shared definition alone cannot detect that,
# because the check would narrow with it.
SUPPLIED_SECRETS = {
    "ss_password": "c3ludGhldGljc2FtcGxlcGFzc3dvcmQ=",
    "vmess_id": "12345678-abcd-efab-1234-567890abcdef",
    "vless_id": "abcdef12-3456-7890-abcd-ef1234567890",
    "reality_private_key": "SYNTHETICREALITYPRIVATEKEYSAMPLEVALUE",
    "reality_public_key": "SYNTHETICREALITYPUBLICKEYSAMPLEVALUE",
    "short_id": "0f1e2d3c4b5a6978",
    "marker": "a1b2c3d4" * 6,
}
ENCODED_ONLY_SECRETS = redaction_values(**SUPPLIED_SECRETS)


def _write_env(path):  # type: (str) -> None
    # Use the generator's own writers: a second copy of these rules here would
    # keep passing after the real writer regressed.
    write_environment(path, SAMPLE)
    write_redaction_values(path, ENCODED_ONLY_SECRETS)


def _check_redaction(env_file):  # type: (str) -> list
    """Every generated secret must be gone; diagnostics must stay readable."""

    script = os.path.join(os.path.dirname(env_file), "redact.sed")
    subprocess.run(
        [
            sys.executable,
            os.path.join(HERE, "redact.py"),
            "--env-file",
            env_file,
            "--secrets-file",
            redaction_values_path(env_file),
            "--output",
            script,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    secrets = list(ENCODED_ONLY_SECRETS.values())
    for name in SECRET_NAMES:
        value = SAMPLE[name]
        secrets.append(value)
        secrets.extend(part for part in re.split(r"[:/@?&#=,;]+", value) if len(part) >= 16)
    sample_log = "\n".join(secrets + ["listening on sentinel:8080 for mihomo 1.19.29"])
    rendered = subprocess.run(
        ["sed", "-f", script], input=sample_log.encode("utf-8"), stdout=subprocess.PIPE, check=True
    ).stdout.decode("utf-8")
    failures = []
    lookup = {value: name for name, value in ENCODED_ONLY_SECRETS.items()}
    lookup.update((SAMPLE[name], name) for name in SECRET_NAMES)
    for secret in secrets:
        if secret in rendered:
            # Name the value that survived, never the value itself.
            failures.append(
                "redaction left a generated value in the log: %s" % lookup.get(secret, "a node token")
            )
    if "sentinel:8080" not in rendered or "mihomo" not in rendered:
        failures.append("redaction removed the service information a failure log needs")
    return failures


def _check_shell_safety(env_file):  # type: (str) -> list
    """A sourced env file must yield every value, not silently drop one.

    A node URI contains ``&``; unquoted, ``set -a; . env`` parses the line as
    asynchronous assignments and the variable ends up unset with no error.
    """

    reader = (
        'set -euo pipefail; set -a; . "%s"; set +a; '
        'for name in %s; do '
        'eval "printf \'%%s=%%s\\n\' \\"$name\\" \\"\\${$name:-__UNSET__}\\""; '
        "done"
    ) % (shell_environment_path(env_file), " ".join(sorted(SAMPLE)))
    result = subprocess.run(["bash", "-c", reader], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = result.stdout.decode("utf-8")
    failures = []
    if result.returncode != 0:
        failures.append("sourcing the generated environment file failed")
    for name, value in sorted(SAMPLE.items()):
        if "%s=%s" % (name, value) not in output:
            failures.append("sourcing did not preserve %s" % name)
    return failures


def _check_workflow_uses_the_harness():  # type: () -> list
    """The workflow must actually pass what redaction needs, and clean it up.

    Verifying the tool in isolation is not enough: redaction covered every
    generated value here while the workflow invoked it without the secrets file,
    so in the real run those values were never removed. A check that only
    exercises its own call has nothing to say about the call that matters.
    """

    try:
        with open(WORKFLOW, "r", encoding="utf-8") as stream:
            text = stream.read()
    except OSError:
        # A missing workflow means the lane cannot run at all.
        return ["the end-to-end workflow is missing"]
    failures = []
    if "redact.py" not in text:
        failures.append("the workflow never builds a redaction script")
    elif "--secrets-file" not in text:
        failures.append(
            "the workflow invokes redact.py without --secrets-file, so secrets that "
            "exist only inside an encoded field would be published"
        )
    for companion in ("e2e.env.sh", "e2e.env.secrets"):
        if companion not in text:
            failures.append("the workflow never references %s" % companion)
        elif text.count(companion) < 2:
            failures.append("%s is used but never removed in teardown" % companion)
    return failures


def _check_secret_classification():  # type: () -> list
    """Nothing supplied as a secret may be dropped from the classified set."""

    dropped = sorted(set(SUPPLIED_SECRETS) - set(ENCODED_ONLY_SECRETS))
    return [
        "the generator no longer classifies %s as a secret, so log redaction "
        "would never cover it" % name
        for name in dropped
    ]


def _check_docker_env_is_literal(env_file):  # type: (str) -> list
    """The Docker env file must carry bare values.

    ``docker --env-file`` does no quote processing, so a wrapping quote becomes
    part of the value and every contract check downstream rejects it. This has
    happened once already, when quoting was added for shell safety and applied
    to both files.
    """

    failures = []
    with open(env_file, "r", encoding="utf-8") as stream:
        for line in stream:
            name, separator, value = line.rstrip("\n").partition("=")
            if not separator:
                continue
            if value[:1] in ("'", '"'):
                failures.append(
                    "%s is quoted; docker --env-file would keep the quote in the value" % name
                )
    return failures


def _check_topology():  # type: () -> list
    """No published port anywhere, and the private services stay private."""

    with open(COMPOSE, "r", encoding="utf-8") as stream:
        text = stream.read()
    failures = []
    if re.search(r"^\s*ports:", text, re.MULTILINE):
        failures.append("the topology publishes a port; the sentinel must stay unreachable")
    if not re.search(r"^\s*internal:\s*true\s*$", text, re.MULTILINE):
        failures.append("the private network is not declared internal")
    for service in PRIVATE_ONLY_SERVICES:
        block = re.search(
            r"^  %s:\n(?:(?:    .*|\n)*)" % re.escape(service), text, re.MULTILINE
        )
        if block is None:
            failures.append("service %s is missing from the topology" % service)
            continue
        if "client-net" in block.group(0):
            failures.append("service %s joins client-net and is no longer isolated" % service)
    return failures


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    directory = tempfile.mkdtemp(prefix="jerryproxy-e2e-check-")
    env_file = os.path.join(directory, "e2e.env")
    _write_env(env_file)
    checks = (
        ("every supplied secret stays classified", _check_secret_classification()),
        ("workflow passes what redaction needs", _check_workflow_uses_the_harness()),
        ("redaction covers every generated value", _check_redaction(env_file)),
        ("generated environment survives shell sourcing", _check_shell_safety(env_file)),
        ("docker environment file stays literal", _check_docker_env_is_literal(env_file)),
        ("topology exposes no port and isolates the sentinel", _check_topology()),
    )
    failed = False
    for label, failures in checks:
        if failures:
            failed = True
            for failure in failures:
                sys.stdout.write("FAIL %s: %s\n" % (label, failure))
        else:
            sys.stdout.write("OK   %s\n" % label)
    for name in os.listdir(directory):
        os.unlink(os.path.join(directory, name))
    os.rmdir(directory)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
