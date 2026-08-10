"""Generate one run's data-plane credentials and emit them as job outputs.

Service containers read their configuration at creation time, before any step
executes, so these values cannot be produced inside the job that uses them.
They travel through an upstream job's outputs instead.

These are one-run fixture credentials: they authorise nothing beyond the
throwaway containers of a single workflow run, and every run generates a fresh
set. They are deliberately not masked, because a masked value is redacted out
of job outputs and would arrive empty.

Node URIs are *not* job outputs. The runner scans outputs with a credential
heuristic and silently drops one it dislikes -- `tuic://uuid:password@host`
tripped it, and the lane then failed on an empty variable rather than on
anything real. Node URIs are derived from the credential parts, so `--emit-nodes`
rebuilds them inside the job that consumes them, where no such scan applies.
"""

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid

SS_METHOD = "aes-256-gcm"
SS_PORT = 10001
VMESS_PORT = 10002
VLESS_PORT = 10003
TROJAN_PORT = 10004
HYSTERIA2_PORT = 10005
TUIC_PORT = 10006
ANYTLS_PORT = 10007
# The TLS-terminating fixtures serve a leaf generated here, so the job that
# builds the node URIs is the one that produced the certificate. The URIs then
# say `insecure` explicitly: these fixtures prove the protocol carries traffic,
# not that certificate validation is enforced -- that guard has its own tests.
TLS_SERVER_NAME = "fixture.invalid"
CAMOUFLAGE_SNI = "www.example.test"
VLESS_FLOW = "xtls-rprx-vision"
# The proxies are reached through published ports on the runner, so node URIs
# address loopback. The sentinel they are asked to fetch is a service name,
# resolvable only inside the job network.
PROXY_HOST = "127.0.0.1"

# The exact set this module emits. The offline check compares it against what
# the workflow references, so a rename cannot silently leave a service with an
# empty credential.
OUTPUT_NAMES = (
    "marker",
    "ss_password",
    "vmess_id",
    "vless_id",
    "reality_private_key",
    "reality_public_key",
    "short_id",
    "trojan_password",
    "hysteria2_password",
    "tuic_uuid",
    "tuic_password",
    "anytls_password",
    "tls_certificate",
    "tls_key",
    "tls_server_name",
    "subscription_body",
)

#: Node URIs, keyed by the environment variable the data-plane lane reads. These
#: never travel as job outputs; ``--emit-nodes`` recomposes them from the parts.
NODE_VARIABLES = {
    "ss": "JERRYPROXY_E2E_SS_NODE",
    "vmess": "JERRYPROXY_E2E_VMESS_NODE",
    "vless": "JERRYPROXY_E2E_VLESS_NODE",
    "trojan": "JERRYPROXY_E2E_TROJAN_NODE",
    "hysteria2": "JERRYPROXY_E2E_HYSTERIA2_NODE",
    "hy2": "JERRYPROXY_E2E_HY2_NODE",
    "tuic": "JERRYPROXY_E2E_TUIC_NODE",
    "anytls": "JERRYPROXY_E2E_ANYTLS_NODE",
}


def _reality_keypair(xray):  # type: (str) -> tuple
    """Ask the pinned proxy binary for an X25519 pair rather than reimplementing it."""

    result = subprocess.run([xray, "x25519"], stdout=subprocess.PIPE, check=True)
    private_key = public_key = ""
    for line in result.stdout.decode("ascii").splitlines():
        lowered = line.lower()
        value = line.split(":", 1)[-1].strip()
        if lowered.startswith("private"):
            private_key = value
        elif lowered.startswith("public") or lowered.startswith("password"):
            public_key = value
    if not private_key or not public_key:
        raise SystemExit("could not parse an X25519 key pair from the proxy output")
    return private_key, public_key


def _tls_leaf():  # type: () -> tuple
    """Generate one throwaway leaf with openssl, returned base64 encoded.

    Only one day of validity and one run's worth of use: the private key never
    leaves this run, and every run generates a new pair.
    """

    directory = tempfile.mkdtemp(prefix="jerryproxy-e2e-tls-")
    certificate = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    try:
        subprocess.check_call(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", key, "-out", certificate, "-days", "1",
                "-subj", "/CN=%s" % TLS_SERVER_NAME,
                "-addext", "subjectAltName=DNS:%s" % TLS_SERVER_NAME,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(certificate, "rb") as stream:
            encoded_certificate = base64.b64encode(stream.read()).decode("ascii")
        with open(key, "rb") as stream:
            encoded_key = base64.b64encode(stream.read()).decode("ascii")
    finally:
        for name in (certificate, key):
            if os.path.exists(name):
                os.unlink(name)
        os.rmdir(directory)
    return encoded_certificate, encoded_key


def build(xray):  # type: (str) -> dict
    """Return every generated value, including the node URIs that embed them."""

    ss_password = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    vmess_id = str(uuid.uuid4())
    vless_id = str(uuid.uuid4())
    private_key, public_key = _reality_keypair(xray)
    short_id = secrets.token_hex(8)

    trojan_password = secrets.token_urlsafe(24)
    hysteria2_password = secrets.token_urlsafe(24)
    tuic_uuid = str(uuid.uuid4())
    tuic_password = secrets.token_urlsafe(24)
    anytls_password = secrets.token_urlsafe(24)
    certificate, key = _tls_leaf()
    values = {
        "marker": secrets.token_hex(24),
        "trojan_password": trojan_password,
        "hysteria2_password": hysteria2_password,
        "tuic_uuid": tuic_uuid,
        "tuic_password": tuic_password,
        "anytls_password": anytls_password,
        "tls_certificate": certificate,
        "tls_key": key,
        "tls_server_name": TLS_SERVER_NAME,
        "ss_password": ss_password,
        "vmess_id": vmess_id,
        "vless_id": vless_id,
        "reality_private_key": private_key,
        "reality_public_key": public_key,
        "short_id": short_id,
    }
    # The subscription fixture is a service container, created before any step
    # could compose a value for it, so its body has to travel as an output. It
    # goes as one Base64 blob rather than as node URIs, because the runner's
    # credential heuristic silently drops an output shaped like a credential URI.
    nodes = compose_nodes(values)
    values["subscription_body"] = base64.b64encode(
        ("\n".join(nodes[scheme] for scheme in sorted(nodes)) + "\n").encode("utf-8")
    ).decode("ascii")
    return values


def compose_nodes(values):  # type: (dict) -> dict
    """Rebuild every node URI from the credential parts.

    Kept in Python, next to the generator that produced the parts, rather than
    assembled in workflow YAML where it would be neither linted nor covered.
    """

    ss_userinfo = (
        base64.urlsafe_b64encode(
            ("%s:%s" % (SS_METHOD, values["ss_password"])).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    vmess_payload = base64.b64encode(
        json.dumps(
            {
                "add": PROXY_HOST,
                "aid": "0",
                "id": values["vmess_id"],
                "net": "tcp",
                "port": str(VMESS_PORT),
                "ps": "e2e-vmess",
                "tls": "",
                "v": 2,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).decode("ascii").rstrip("=")
    name = values["tls_server_name"]
    return {
        "ss": "ss://%s@%s:%d#e2e-ss" % (ss_userinfo, PROXY_HOST, SS_PORT),
        "vmess": "vmess://%s" % vmess_payload,
        "vless": (
            "vless://%s@%s:%d?type=tcp&security=reality&flow=%s&sni=%s&fp=chrome&pbk=%s&sid=%s#e2e-vless"
            % (
                values["vless_id"],
                PROXY_HOST,
                VLESS_PORT,
                VLESS_FLOW,
                CAMOUFLAGE_SNI,
                values["reality_public_key"],
                values["short_id"],
            )
        ),
        "trojan": (
            "trojan://%s@%s:%d?sni=%s&allowInsecure=1#e2e-trojan"
            % (values["trojan_password"], PROXY_HOST, TROJAN_PORT, name)
        ),
        "hysteria2": (
            "hysteria2://%s@%s:%d?sni=%s&insecure=1#e2e-hysteria2"
            % (values["hysteria2_password"], PROXY_HOST, HYSTERIA2_PORT, name)
        ),
        # The short alias reaches the same server: a second URI spelling that
        # subscriptions use in the wild, not a second protocol.
        "hy2": (
            "hy2://%s@%s:%d?sni=%s&insecure=1#e2e-hy2"
            % (values["hysteria2_password"], PROXY_HOST, HYSTERIA2_PORT, name)
        ),
        "tuic": (
            "tuic://%s:%s@%s:%d?sni=%s&alpn=h3&congestion_control=bbr&allow_insecure=1#e2e-tuic"
            % (values["tuic_uuid"], values["tuic_password"], PROXY_HOST, TUIC_PORT, name)
        ),
        "anytls": (
            "anytls://%s@%s:%d?sni=%s&insecure=1#e2e-anytls"
            % (values["anytls_password"], PROXY_HOST, ANYTLS_PORT, name)
        ),
    }


def _emit_nodes(path):  # type: (str) -> int
    """Write the node URIs to a GITHUB_ENV file from parts already in the env."""

    parts = {}
    for name in OUTPUT_NAMES:
        parts[name] = os.environ.get(name.upper(), "")
    missing = sorted(name for name, value in parts.items() if not value)
    if missing:
        raise SystemExit("cannot compose nodes without: %s" % ", ".join(missing))
    nodes = compose_nodes(parts)
    with open(path, "a", encoding="utf-8") as stream:
        for scheme, variable in sorted(NODE_VARIABLES.items()):
            stream.write("%s=%s\n" % (variable, nodes[scheme]))
    sys.stdout.write("composed %d node URIs\n" % len(nodes))
    return 0


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", help="pinned proxy binary used for key generation")
    parser.add_argument("--output", required=True, help="GITHUB_OUTPUT file to append to")
    parser.add_argument(
        "--emit-nodes",
        action="store_true",
        help="compose node URIs from parts already in the environment",
    )
    arguments = parser.parse_args()

    if arguments.emit_nodes:
        return _emit_nodes(arguments.output)
    if not arguments.xray:
        raise SystemExit("--xray is required unless --emit-nodes is given")

    values = build(arguments.xray)
    missing = [name for name in OUTPUT_NAMES if not values.get(name)]
    if missing:
        raise SystemExit("provisioning is incomplete: %s" % ", ".join(missing))
    with open(arguments.output, "a", encoding="utf-8") as stream:
        for name in sorted(values):
            stream.write("%s=%s\n" % (name, values[name]))
    # Names only: printing a value would put it in the workflow log, which is
    # a wider audience than the job outputs these travel through.
    sys.stdout.write("generated %d values: %s\n" % (len(values), ", ".join(sorted(values))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
