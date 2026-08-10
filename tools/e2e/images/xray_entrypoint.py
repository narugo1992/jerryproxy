"""Render one protocol's server configuration from the environment, then exec.

Service containers start before any workflow step, so their configuration
cannot be generated on the runner and mounted; it has to be produced inside the
container from environment variables. Keeping that logic here rather than in
workflow YAML means it is linted, reviewable, and covered by ``make e2e_check``.

Exactly one protocol inbound is configured per container, so a failure names one
protocol and one service rather than a shared process.
"""

import base64
import binascii
import json
import os
import sys

SENTINEL_FLOW = "xtls-rprx-vision"


XRAY_PATH = "/usr/local/bin/xray"


def _required(name):  # type: (str) -> str
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit("%s is required" % name)
    return value


def _port(name, default):  # type: (str, int) -> int
    value = os.environ.get(name) or str(default)
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise SystemExit("%s must be a TCP port" % name)
    return int(value)


def _tls_material():  # type: () -> tuple
    """Write this container's TLS material from the environment.

    The certificate and key are generated on the runner by the provisioning job
    and injected here, so the job that builds the node URIs is the same one that
    knows the certificate. Generating them in-container would leave the runner
    with no way to learn the leaf, since a service container has no channel back
    to the job.
    """

    certificate = "/tmp/fixture-cert.pem"
    key = "/tmp/fixture-key.pem"
    _write_private(certificate, _required("E2E_TLS_CERTIFICATE"))
    _write_private(key, _required("E2E_TLS_KEY"))
    return certificate, key


def _write_private(path, encoded):  # type: (str, str) -> None
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise SystemExit("TLS material must be base64")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _shadowsocks():  # type: () -> dict
    return {
        "tag": "ss",
        "port": _port("E2E_PORT", 10001),
        "protocol": "shadowsocks",
        "settings": {
            "method": os.environ.get("E2E_SS_METHOD", "aes-256-gcm"),
            "password": _required("E2E_SS_PASSWORD"),
            "network": "tcp,udp",
        },
    }


def _vmess():  # type: () -> dict
    return {
        "tag": "vmess",
        "port": _port("E2E_PORT", 10002),
        "protocol": "vmess",
        "settings": {"clients": [{"id": _required("E2E_VMESS_ID")}]},
    }


def _vless():  # type: () -> dict
    return {
        "tag": "vless-reality",
        "port": _port("E2E_PORT", 10003),
        "protocol": "vless",
        "settings": {
            "clients": [{"id": _required("E2E_VLESS_ID"), "flow": SENTINEL_FLOW}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": os.environ.get("E2E_REALITY_DEST", "camouflage:8443"),
                "serverNames": [os.environ.get("E2E_REALITY_SNI", "www.example.test")],
                "privateKey": _required("E2E_REALITY_PRIVATE_KEY"),
                "shortIds": [_required("E2E_REALITY_SHORT_ID")],
            },
        },
    }


def _trojan():  # type: () -> dict
    certificate, key = _tls_material()
    return {
        "tag": "trojan",
        "port": _port("E2E_PORT", 10004),
        "protocol": "trojan",
        "settings": {"clients": [{"password": _required("E2E_TROJAN_PASSWORD")}]},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": _required("E2E_TLS_SERVER_NAME"),
                "certificates": [{"certificateFile": certificate, "keyFile": key}],
            },
        },
    }


BUILDERS = {"ss": _shadowsocks, "vmess": _vmess, "vless": _vless, "trojan": _trojan}


def main():  # type: () -> int
    protocol = _required("E2E_PROTOCOL")
    if protocol not in BUILDERS:
        raise SystemExit("E2E_PROTOCOL must be one of %s" % ", ".join(sorted(BUILDERS)))
    config = {
        # Access records are needed to attribute a request to this protocol;
        # debug would widen what a captured log can carry for no extra evidence.
        "log": {"loglevel": "info"},
        "inbounds": [BUILDERS[protocol]()],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    path = "/tmp/xray-config.json"
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2, sort_keys=True)
    sys.stderr.write("rendered %s inbound on port %d\n" % (protocol, config["inbounds"][0]["port"]))
    # exec so the proxy is PID 1's successor and receives signals directly.
    os.execv(XRAY_PATH, ["xray", "run", "-c", path])
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
