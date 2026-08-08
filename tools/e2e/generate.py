"""Generate every ephemeral credential, config, and URI for one E2E run.

The workflow calls this once before starting the topology.  Nothing produced
here is committed: it lands under a private directory the workflow mounts
read-only.  Each run gets fresh material, so a leaked value from one run cannot
authorise the next, and the sentinel nonce differs every time.

The generated node URIs address Compose service names rather than container IP
addresses, because service IPs are not stable across a service recreation.
"""

import argparse
import base64
import json
import os
import secrets
import stat
import subprocess
import sys
import uuid

SS_METHOD = "aes-256-gcm"
SS_PORT = 10001
VMESS_PORT = 10002
VLESS_PORT = 10003
SENTINEL_PORT = 8080
SUBSCRIPTION_PORT = 8081
CAMOUFLAGE_SNI = "www.example.test"
VLESS_FLOW = "xtls-rprx-vision"


def write_environment(path, exports):  # type: (str, dict) -> None
    """Write both env formats the harness needs, because they disagree.

    ``docker --env-file`` parses each line literally, so a quote would become
    part of the value. A POSIX shell sourcing the same line needs the quotes,
    because a VLESS URI contains ``&`` and an unquoted line is parsed as
    asynchronous assignments that leave the variable unset with no error.

    One file cannot satisfy both, so ``path`` is written literally for Docker
    and ``path`` with a ``.sh`` suffix is written quoted for shells. The harness
    self-check imports this function so it verifies the real writer rather than
    a second copy of these rules.
    """

    path = os.path.abspath(path)
    _private_write(
        path,
        "".join("%s=%s\n" % (item, exports[item]) for item in sorted(exports)).encode("utf-8"),
    )
    _private_write(
        shell_environment_path(path),
        "".join(
            "%s='%s'\n" % (item, exports[item].replace("'", "'\\''"))
            for item in sorted(exports)
        ).encode("utf-8"),
    )


def shell_environment_path(path):  # type: (str) -> str
    """Return the shell-sourceable companion of a Docker env file."""

    return "%s.sh" % os.path.abspath(path)


def redaction_values(**generated):  # type: (**str) -> dict
    """Return every generated secret that log redaction must cover.

    This is the single decision about which values are secret. The harness
    self-check calls it so that omitting one here fails the check, rather than
    the check listing its own expectations and silently agreeing with itself.
    """

    required = (
        "ss_password",
        "vmess_id",
        "vless_id",
        "reality_private_key",
        "reality_public_key",
        "short_id",
        "marker",
    )
    missing = [name for name in required if not generated.get(name)]
    if missing:
        raise SystemExit("redaction values are incomplete: %s" % ", ".join(missing))
    return {name: generated[name] for name in required}


def redaction_values_path(path):  # type: (str) -> str
    """Return the companion file listing raw secrets for log redaction."""

    return "%s.secrets" % os.path.abspath(path)


def write_redaction_values(path, values):  # type: (str, dict) -> None
    """Record every generated secret so log redaction can cover all of them.

    Deriving redaction from the environment file alone misses whatever is only
    embedded inside an encoded field: the SS password and the VMess UUID live
    inside base64 payloads, and the Reality private key is never exported at
    all because no client needs it. A server that rejects its configuration can
    still echo those values into a captured log, so they are listed here.

    This file is never injected into the test container. It exists only so the
    workflow's log capture can remove these values.
    """

    _private_write(
        redaction_values_path(path),
        "".join("%s=%s\n" % (item, values[item]) for item in sorted(values)).encode("utf-8"),
    )


def _private_write(path, payload):  # type: (str, bytes) -> None
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _reality_keypair(xray):  # type: (str) -> tuple
    """Ask the pinned Xray binary for an X25519 pair rather than reimplementing it."""

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
        raise SystemExit("could not parse an X25519 key pair from the Xray output")
    return private_key, public_key


def _camouflage(output):  # type: (str) -> None
    """Create the private TLS target the Reality handshake borrows.

    Reality needs a real TLS 1.3 endpoint to mirror. This certificate is
    synthetic, lives only on the private network, and is trusted by nothing
    outside this run; it is never a recommendation for a production source.
    """

    key = os.path.join(output, "camouflage.key")
    certificate = os.path.join(output, "camouflage.crt")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", certificate, "-days", "1",
            "-subj", "/CN=%s" % CAMOUFLAGE_SNI,
            "-addext", "subjectAltName=DNS:%s" % CAMOUFLAGE_SNI,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.chmod(key, 0o644)
    os.chmod(certificate, 0o644)
    _private_write(
        os.path.join(output, "camouflage.conf"),
        (
            "server {\n"
            "    listen 8443 ssl;\n"
            "    http2 on;\n"
            "    server_name %s;\n"
            "    ssl_certificate /etc/nginx/tls/camouflage.crt;\n"
            "    ssl_certificate_key /etc/nginx/tls/camouflage.key;\n"
            "    ssl_protocols TLSv1.3;\n"
            "    location / { return 200 'camouflage'; }\n"
            "}\n" % CAMOUFLAGE_SNI
        ).encode("utf-8"),
    )
    os.chmod(os.path.join(output, "camouflage.conf"), 0o644)


def _server_config(inbound):  # type: (dict) -> dict
    """One protocol inbound, a direct outbound, and no controller listener."""

    return {
        "log": {"loglevel": "info"},
        "inbounds": [inbound],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="private directory for generated material")
    parser.add_argument("--xray", required=True, help="pinned Xray binary used for key generation")
    parser.add_argument("--env-file", required=True, help="shell env file the workflow sources")
    arguments = parser.parse_args()

    output = os.path.abspath(arguments.output)
    os.makedirs(output, mode=0o700, exist_ok=True)
    os.chmod(output, 0o700)

    marker = secrets.token_hex(24)
    ss_password = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    vmess_id = str(uuid.uuid4())
    vless_id = str(uuid.uuid4())
    private_key, public_key = _reality_keypair(arguments.xray)
    short_id = secrets.token_hex(8)
    _camouflage(output)

    configs = {
        "ss-server.json": _server_config(
            {
                "tag": "ss",
                "port": SS_PORT,
                "protocol": "shadowsocks",
                "settings": {
                    "method": SS_METHOD,
                    "password": ss_password,
                    "network": "tcp,udp",
                },
            }
        ),
        "vmess-server.json": _server_config(
            {
                "tag": "vmess",
                "port": VMESS_PORT,
                "protocol": "vmess",
                "settings": {"clients": [{"id": vmess_id}]},
            }
        ),
        "vless-server.json": _server_config(
            {
                "tag": "vless-reality",
                "port": VLESS_PORT,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": vless_id, "flow": VLESS_FLOW}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "camouflage:8443",
                        "serverNames": [CAMOUFLAGE_SNI],
                        "privateKey": private_key,
                        "shortIds": [short_id],
                    },
                },
            }
        ),
    }
    for name, value in configs.items():
        _private_write(
            os.path.join(output, name),
            (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    ss_userinfo = base64.urlsafe_b64encode(
        ("%s:%s" % (SS_METHOD, ss_password)).encode("utf-8")
    ).decode("ascii").rstrip("=")
    ss_uri = "ss://%s@ss-server:%d#e2e-ss" % (ss_userinfo, SS_PORT)
    vmess_uri = "vmess://%s" % base64.b64encode(
        json.dumps(
            {
                "add": "vmess-server",
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
    vless_uri = (
        "vless://%s@vless-server:%d"
        "?type=tcp&security=reality&flow=%s&sni=%s&fp=chrome&pbk=%s&sid=%s#e2e-vless"
        % (vless_id, VLESS_PORT, VLESS_FLOW, CAMOUFLAGE_SNI, public_key, short_id)
    )

    feed = "\n".join((ss_uri, vmess_uri, vless_uri)) + "\n"
    _private_write(
        os.path.join(output, "subscription"),
        base64.b64encode(feed.encode("utf-8")) + b"\n",
    )

    # Values the workflow exports into the pytest container.  Written with
    # private permissions because every line is bearer-like test input.
    exports = {
        "V2RAY_SUBSCRIPTION": "http://subscription:%d/subscription" % SUBSCRIPTION_PORT,
        "JERRYPROXY_E2E_SENTINEL_HOST": "sentinel",
        "JERRYPROXY_E2E_SENTINEL_PORT": str(SENTINEL_PORT),
        "JERRYPROXY_E2E_MARKER": marker,
        "JERRYPROXY_E2E_BACKEND": "mihomo",
        "JERRYPROXY_E2E_BACKEND_VERSION": "1.19.29",
        "JERRYPROXY_E2E_SS_NODE": ss_uri,
        "JERRYPROXY_E2E_VMESS_NODE": vmess_uri,
        "JERRYPROXY_E2E_VLESS_NODE": vless_uri,
    }
    write_environment(arguments.env_file, exports)
    # Raw secrets for log redaction only; several never appear in any export.
    write_redaction_values(
        arguments.env_file,
        redaction_values(
            ss_password=ss_password,
            vmess_id=vmess_id,
            vless_id=vless_id,
            reality_private_key=private_key,
            reality_public_key=public_key,
            short_id=short_id,
            marker=marker,
        ),
    )
    # Names only: the workflow log must not carry generated credentials.
    sys.stdout.write("generated %d configs and %d exports\n" % (len(configs), len(exports)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
