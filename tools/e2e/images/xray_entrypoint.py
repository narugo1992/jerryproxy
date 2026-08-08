"""Render one protocol's server configuration from the environment, then exec.

Service containers start before any workflow step, so their configuration
cannot be generated on the runner and mounted; it has to be produced inside the
container from environment variables. Keeping that logic here rather than in
workflow YAML means it is linted, reviewable, and covered by ``make e2e_check``.

Exactly one protocol inbound is configured per container, so a failure names one
protocol and one service rather than a shared process.
"""

import json
import os
import sys

SENTINEL_FLOW = "xtls-rprx-vision"


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


BUILDERS = {"ss": _shadowsocks, "vmess": _vmess, "vless": _vless}

# What each protocol needs supplied. Declared rather than inferred from variable
# names: "SS" is a substring of "VMESS", so any name-based guess misattributes.
REQUIRED_BY_PROTOCOL = {
    "ss": ("E2E_SS_PASSWORD",),
    "vmess": ("E2E_VMESS_ID",),
    "vless": ("E2E_VLESS_ID", "E2E_REALITY_PRIVATE_KEY", "E2E_REALITY_SHORT_ID"),
}


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
    os.execv("/usr/local/bin/xray", ["xray", "run", "-c", path])
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
