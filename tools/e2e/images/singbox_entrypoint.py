"""Render one sing-box protocol server from the environment, then exec.

Xray's exact validator rejects Hysteria2, TUIC, and AnyTLS outright, so those
protocols need a different server than the Xray fixture provides. sing-box
implements all three, and the packaged catalog already records an official
sing-box release with a SHA-256 GitHub issued, so this image pins from the same
release evidence the product uses rather than introducing a second pin.

Exactly one inbound is configured per container, so a failure names one protocol
and one service rather than a shared process.
"""

import base64
import binascii
import json
import os
import sys

SINGBOX_PATH = "/usr/local/bin/sing-box"
CERTIFICATE_PATH = "/tmp/fixture-cert.pem"
KEY_PATH = "/tmp/fixture-key.pem"


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


def _write_private(path, encoded):  # type: (str, str) -> None
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise SystemExit("TLS material must be base64")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _tls():  # type: () -> dict
    """Serve the leaf the provisioning job generated on the runner.

    The runner generates this material and injects it, because the job that
    builds the node URIs has to be the one that knows the certificate; a service
    container has no channel back to the job.
    """

    _write_private(CERTIFICATE_PATH, _required("E2E_TLS_CERTIFICATE"))
    _write_private(KEY_PATH, _required("E2E_TLS_KEY"))
    return {
        "enabled": True,
        "server_name": _required("E2E_TLS_SERVER_NAME"),
        "certificate_path": CERTIFICATE_PATH,
        "key_path": KEY_PATH,
    }


def _hysteria2():  # type: () -> dict
    return {
        "type": "hysteria2",
        "tag": "hysteria2",
        "listen": "::",
        "listen_port": _port("E2E_PORT", 10005),
        "users": [{"password": _required("E2E_HYSTERIA2_PASSWORD")}],
        "tls": _tls(),
    }


def _tuic():  # type: () -> dict
    return {
        "type": "tuic",
        "tag": "tuic",
        "listen": "::",
        "listen_port": _port("E2E_PORT", 10006),
        "users": [
            {
                "uuid": _required("E2E_TUIC_UUID"),
                "password": _required("E2E_TUIC_PASSWORD"),
            }
        ],
        "congestion_control": "bbr",
        # h3 is what the client URI advertises; an inbound that negotiated
        # something else would make a protocol mismatch look like a network fault.
        "tls": dict(_tls(), alpn=["h3"]),
    }


def _anytls():  # type: () -> dict
    return {
        "type": "anytls",
        "tag": "anytls",
        "listen": "::",
        "listen_port": _port("E2E_PORT", 10007),
        "users": [{"password": _required("E2E_ANYTLS_PASSWORD")}],
        "tls": _tls(),
    }


BUILDERS = {"hysteria2": _hysteria2, "tuic": _tuic, "anytls": _anytls}


def main():  # type: () -> int
    protocol = _required("E2E_PROTOCOL")
    if protocol not in BUILDERS:
        raise SystemExit("E2E_PROTOCOL must be one of %s" % ", ".join(sorted(BUILDERS)))
    config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [BUILDERS[protocol]()],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    path = "/tmp/singbox-config.json"
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2, sort_keys=True)
    sys.stderr.write(
        "rendered %s inbound on port %d\n" % (protocol, config["inbounds"][0]["listen_port"])
    )
    # exec so the proxy is PID 1's successor and receives signals directly.
    os.execv(SINGBOX_PATH, ["sing-box", "run", "-c", path])
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
