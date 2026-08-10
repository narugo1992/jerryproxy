"""Generate one run's data-plane credentials and emit them as job outputs.

Service containers read their configuration at creation time, before any step
executes, so these values cannot be produced inside the job that uses them.
They travel through an upstream job's outputs instead.

These are one-run fixture credentials: they authorise nothing beyond the
throwaway containers of a single workflow run, and every run generates a fresh
set. They are deliberately not masked, because a masked value is redacted out
of job outputs and would arrive empty.
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
    "ss_node",
    "vmess_node",
    "vless_node",
    "trojan_node",
    "hysteria2_node",
    "hy2_node",
    "tuic_node",
    "anytls_node",
)


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

    ss_userinfo = (
        base64.urlsafe_b64encode(("%s:%s" % (SS_METHOD, ss_password)).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    vmess_payload = base64.b64encode(
        json.dumps(
            {
                "add": PROXY_HOST,
                "aid": "0",
                "id": vmess_id,
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

    trojan_password = secrets.token_urlsafe(24)
    hysteria2_password = secrets.token_urlsafe(24)
    tuic_uuid = str(uuid.uuid4())
    tuic_password = secrets.token_urlsafe(24)
    anytls_password = secrets.token_urlsafe(24)
    certificate, key = _tls_leaf()

    return {
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
        "ss_node": "ss://%s@%s:%d#e2e-ss" % (ss_userinfo, PROXY_HOST, SS_PORT),
        "vmess_node": "vmess://%s" % vmess_payload,
        "vless_node": (
            "vless://%s@%s:%d?type=tcp&security=reality&flow=%s&sni=%s&fp=chrome&pbk=%s&sid=%s#e2e-vless"
            % (vless_id, PROXY_HOST, VLESS_PORT, VLESS_FLOW, CAMOUFLAGE_SNI, public_key, short_id)
        ),
        "trojan_node": (
            "trojan://%s@%s:%d?sni=%s&allowInsecure=1#e2e-trojan"
            % (trojan_password, PROXY_HOST, TROJAN_PORT, TLS_SERVER_NAME)
        ),
        "hysteria2_node": (
            "hysteria2://%s@%s:%d?sni=%s&insecure=1#e2e-hysteria2"
            % (hysteria2_password, PROXY_HOST, HYSTERIA2_PORT, TLS_SERVER_NAME)
        ),
        # The short alias reaches the same server: it is a second URI spelling
        # rather than a second protocol, and a build that accepted only the long
        # form would still reject half of the subscriptions in the wild.
        "hy2_node": (
            "hy2://%s@%s:%d?sni=%s&insecure=1#e2e-hy2"
            % (hysteria2_password, PROXY_HOST, HYSTERIA2_PORT, TLS_SERVER_NAME)
        ),
        "tuic_node": (
            "tuic://%s:%s@%s:%d?sni=%s&alpn=h3&congestion_control=bbr&allow_insecure=1#e2e-tuic"
            % (tuic_uuid, tuic_password, PROXY_HOST, TUIC_PORT, TLS_SERVER_NAME)
        ),
        "anytls_node": (
            "anytls://%s@%s:%d?sni=%s&insecure=1#e2e-anytls"
            % (anytls_password, PROXY_HOST, ANYTLS_PORT, TLS_SERVER_NAME)
        ),
    }


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", required=True, help="pinned proxy binary used for key generation")
    parser.add_argument("--output", required=True, help="GITHUB_OUTPUT file to append to")
    arguments = parser.parse_args()

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
