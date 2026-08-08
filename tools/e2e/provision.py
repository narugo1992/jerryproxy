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
import secrets
import subprocess
import sys
import uuid

SS_METHOD = "aes-256-gcm"
SS_PORT = 10001
VMESS_PORT = 10002
VLESS_PORT = 10003
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
    "ss_node",
    "vmess_node",
    "vless_node",
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

    return {
        "marker": secrets.token_hex(24),
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
