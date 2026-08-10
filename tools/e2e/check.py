"""Offline checks for the data-plane fixtures.

These invariants are cheap to verify without Docker and expensive to discover in
CI, so they are checked here rather than trusted:

1. the sentinel and camouflage services publish no port, which is the only
   reason a test cannot reach the nonce without going through a proxy;
2. every value the provisioner emits can be removed from a captured log;
3. the workflow references only outputs the provisioner emits, and supplies
   every variable the fixture images require.

Run through ``make e2e_check``. Nothing here contacts a network or starts Docker.
"""

import argparse
import inspect
import os
import re
import subprocess
import sys
import tempfile

import provision

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from test.e2e import _contract as contract  # noqa: E402 - path is set immediately above

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "images"))
import xray_entrypoint  # noqa: E402 - path is set immediately above

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "test.yml")
IMAGE_WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "e2e-images.yml")
IMAGES = os.path.join(HERE, "images")
PRIVATE_ONLY_SERVICES = ("sentinel", "camouflage")

# Synthetic stand-ins shaped like the provisioner's real output. Comparing this
# mapping against what the provisioner emits catches both dropping a value and
# narrowing the set: a shared definition alone cannot detect the latter, because
# the check would narrow along with it.
SUPPLIED_SECRETS = {
    "marker": "a1b2c3d4" * 6,
    "ss_password": "c3ludGhldGljc2FtcGxlcGFzc3dvcmQ=",
    "vmess_id": "12345678-abcd-efab-1234-567890abcdef",
    "vless_id": "abcdef12-3456-7890-abcd-ef1234567890",
    "reality_private_key": "SYNTHETICREALITYPRIVATEKEYSAMPLE",
    "reality_public_key": "SYNTHETICREALITYPUBLICKEYSAMPLEV",
    "short_id": "0f1e2d3c4b5a6978",
    "ss_node": "ss://c3ludGhldGljc2FtcGxldXNlcmluZm8@127.0.0.1:10001#e2e-ss",
    "vmess_node": "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJpZCI6ImFiY2RlZiJ9",
    "vless_node": (
        "vless://abcdef12-3456-7890-abcd-ef1234567890@127.0.0.1:10003"
        "?type=tcp&security=reality&pbk=SYNTHETICREALITYPUBLICKEYSAMPLEV&sid=0f1e2d3c4b5a6978#e2e"
    ),
}


def _workflow():  # type: () -> str
    with open(WORKFLOW, "r", encoding="utf-8") as stream:
        return stream.read()


def _service_block(text, service):  # type: (str, str) -> str
    parts = text.split("    services:", 1)
    if len(parts) < 2:
        return ""
    body = parts[1].split("\n    steps:", 1)[0]
    found = re.search(
        r"^      %s:\n((?:        .*\n|\n)*)" % re.escape(service), body, re.MULTILINE
    )
    return found.group(1) if found else ""


def _check_private_services_publish_nothing():  # type: () -> list
    """`ports` is the isolation boundary, so these services must not have one.

    A job on the runner reaches a service only through a published port. Giving
    the sentinel one would let a test fetch the nonce with no proxy involved,
    and every data-plane assertion would then prove nothing.
    """

    text = _workflow()
    failures = []
    for service in PRIVATE_ONLY_SERVICES:
        block = _service_block(text, service)
        if not block:
            failures.append("service %s is missing from the workflow" % service)
        elif re.search(r"^\s*ports:", block, re.MULTILINE):
            failures.append(
                "service %s publishes a port, so the runner could reach it without a proxy"
                % service
            )
        elif re.search(r"(?:--publish|(?<![\w-])-p)[= ]", block):
            # `options` is passed to `docker create`, so it can publish a port
            # without a `ports:` key ever appearing.
            failures.append(
                "service %s publishes a port through options, so the runner could reach it"
                % service
            )
    return failures


def _check_every_value_stays_emitted():  # type: () -> list
    """Nothing supplied here may quietly stop being emitted by the provisioner."""

    dropped = sorted(set(SUPPLIED_SECRETS) - set(provision.OUTPUT_NAMES))
    return [
        "the provisioner no longer emits %s, so redaction would never cover it" % name
        for name in dropped
    ]


def _check_redaction():  # type: () -> list
    """Every emitted value must disappear from a captured log."""

    directory = tempfile.mkdtemp(prefix="jerryproxy-e2e-redact-")
    secrets_file = os.path.join(directory, "secrets")
    script = os.path.join(directory, "redact.sed")
    try:
        with open(secrets_file, "w", encoding="utf-8") as stream:
            for name in sorted(SUPPLIED_SECRETS):
                stream.write("%s=%s\n" % (name, SUPPLIED_SECRETS[name]))
        subprocess.run(
            [
                sys.executable,
                os.path.join(HERE, "redact.py"),
                "--env-file",
                secrets_file,
                "--output",
                script,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        values = []
        for name in sorted(SUPPLIED_SECRETS):
            value = SUPPLIED_SECRETS[name]
            values.append(value)
            values.extend(part for part in re.split(r"[:/@?&#=,;]+", value) if len(part) >= 16)
        sample = "\n".join(values + ["listening on sentinel:8080 for mihomo 1.19.29"])
        rendered = subprocess.run(
            ["sed", "-f", script],
            input=sample.encode("utf-8"),
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.decode("utf-8")
    finally:
        for name in os.listdir(directory):
            os.unlink(os.path.join(directory, name))
        os.rmdir(directory)

    lookup = {value: name for name, value in SUPPLIED_SECRETS.items()}
    failures = [
        "redaction left a value in the log: %s" % lookup.get(value, "an embedded token")
        for value in values
        if value in rendered
    ]
    if "sentinel:8080" not in rendered or "mihomo" not in rendered:
        failures.append("redaction removed the service information a failure log needs")
    return failures


def _check_workflow_matches_the_provisioner():  # type: () -> list
    """The workflow may reference only outputs the provisioner emits.

    Renaming an output without updating the workflow yields an empty service
    environment variable, and the fixture then fails at start complaining about
    a missing credential rather than about the rename that caused it.
    """

    referenced = set(re.findall(r"needs\.provision\.outputs\.([a-z_0-9]+)", _workflow()))
    failures = [
        "the workflow references needs.provision.outputs.%s, which is not emitted" % name
        for name in sorted(referenced - set(provision.OUTPUT_NAMES))
    ]
    if not referenced:
        failures.append("the workflow references no provisioner output")
    return failures


def _check_enforcement_is_declared():  # type: () -> list
    """The data-plane step must demand the contract, not merely offer it.

    Dropping any other required variable fails closed, because enforcement
    turns a missing contract into an error. Dropping enforcement itself turns
    the whole module into a skip, and the job then reports success with no
    data-plane coverage at all — indistinguishable from a real pass.
    """

    text = _workflow()
    step = re.search(
        r"Run unit tests with the data plane present\n((?:.*\n)*?)\s+- name:", text
    )
    if step is None:
        return ["the workflow has no data-plane test step"]
    block = step.group(1)
    failures = []
    if not re.search(r'JERRYPROXY_E2E_ENFORCE:\s*"1"', block):
        failures.append(
            "the data-plane step does not set JERRYPROXY_E2E_ENFORCE=1, so a missing "
            "contract would skip silently and still report success"
        )
    for name in contract.REQUIRED:
        if "%s:" % name not in block:
            failures.append("the data-plane step does not supply %s" % name)
    return failures


def _check_the_lane_cannot_skip_silently():  # type: () -> list
    """A skipped data-plane lane must fail, not look like it had nothing to do.

    A housekeeping job inside the image workflow once failed, and because a
    caller's ``needs:`` waits for every job in a reusable workflow, the whole
    data-plane lane skipped while the run still read as green. Silence has to
    be an error, so the gate that turns it into one must exist.
    """

    text = _workflow()
    failures = []
    gate = re.search(r"^  data-plane-gate:\n((?:    .*\n|\n)*)", text, re.MULTILINE)
    if gate is None:
        return ["the workflow has no data-plane-gate job, so a skipped lane reads as success"]
    block = gate.group(1)
    if "if: always()" not in block:
        failures.append("data-plane-gate is not always(), so it skips with the lane it guards")
    if "needs: [unit-data-plane]" not in block:
        failures.append("data-plane-gate does not depend on unit-data-plane")
    if "exit 1" not in block:
        failures.append("data-plane-gate never fails, so it asserts nothing")
    return failures


def _check_housekeeping_cannot_gate_the_lane():  # type: () -> list
    """The image workflow may only contain the job the lane consumes.

    ``needs:`` on a reusable workflow waits for all of its jobs, so any extra
    job there can veto the tests. Storage pruning belongs in its own workflow.
    """

    with open(IMAGE_WORKFLOW, "r", encoding="utf-8") as stream:
        text = stream.read()
    jobs = re.findall(r"^  ([a-z][a-z0-9-]*):$", text, re.MULTILINE)
    extra = [name for name in jobs if name != "publish"]
    return [
        "the image workflow also defines %r, which a caller's needs: would wait "
        "for -- a failure there would veto the data-plane lane" % name
        for name in extra
    ]


def _check_images_get_what_they_require():  # type: () -> list
    """Each proxy service must supply the variables its entrypoint demands.

    The requirement set is read out of each builder's source, not from a table
    kept beside it: a table drifts the moment someone adds a `_required` call
    without updating it. Inferring from variable names is also wrong, because
    "SS" is a substring of "VMESS".
    """

    text = _workflow()
    failures = []
    for service in ("ss-server", "vmess-server", "vless-server"):
        block = _service_block(text, service)
        if not block:
            failures.append("service %s is missing from the workflow" % service)
            continue
        supplied = set(re.findall(r"^\s+([A-Z0-9_]+):", block, re.MULTILINE))
        protocol = re.search(r"E2E_PROTOCOL:\s*(\w+)", block)
        if protocol is None:
            failures.append("service %s does not declare E2E_PROTOCOL" % service)
            continue
        builder = xray_entrypoint.BUILDERS.get(protocol.group(1))
        if builder is None:
            failures.append("service %s declares an unknown protocol" % service)
            continue
        needed = re.findall(r'_required\("([A-Z0-9_]+)"\)', inspect.getsource(builder))
        failures.extend(
            "service %s does not supply %s, which its entrypoint requires" % (service, name)
            for name in sorted(set(needed) | {"E2E_PROTOCOL"} - supplied)
            if name not in supplied
        )
    return failures


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    checks = (
        ("private services publish no port", _check_private_services_publish_nothing()),
        ("every provisioned value stays emitted", _check_every_value_stays_emitted()),
        ("redaction covers every provisioned value", _check_redaction()),
        ("workflow references only real outputs", _check_workflow_matches_the_provisioner()),
        ("the data-plane step demands the contract", _check_enforcement_is_declared()),
        ("services supply what their images require", _check_images_get_what_they_require()),
        ("a skipped data-plane lane fails", _check_the_lane_cannot_skip_silently()),
        ("housekeeping cannot gate the lane", _check_housekeeping_cannot_gate_the_lane()),
    )
    failed = False
    for label, failures in checks:
        if failures:
            failed = True
            for failure in failures:
                sys.stdout.write("FAIL %s: %s\n" % (label, failure))
        else:
            sys.stdout.write("OK   %s\n" % label)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
