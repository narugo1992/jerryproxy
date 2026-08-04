"""Opt-in, credential-free loopback integration harness for an installed v2ray.

The test is intentionally excluded from the normal unit-test contract unless
``JERRYPROXY_E2E_V2RAY`` is set.  It never contacts an external host.
"""

import base64
import http.server
import json
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from jerryproxy.home import JerryProxyPaths
from jerryproxy.runtime import HealthSnapshot, RecoveryPolicy, RuntimeSession
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import parse_subscription_body

_V2RAY_ENV = "JERRYPROXY_E2E_V2RAY"
_MARKER = b"jerryproxy-loopback-marker\n"


def _v2ray_executable():
    value = os.environ.get(_V2RAY_ENV, "").strip()
    if not value:
        pytest.skip("set %s to an installed v2ray binary to run the loopback harness" % _V2RAY_ENV)
    if value.lower() in ("1", "true", "yes"):
        value = shutil.which("v2ray") or ""
    if not value or not os.path.isfile(value) or not os.access(value, os.X_OK):
        pytest.skip("configured v2ray executable is unavailable")
    return value


class _MarkerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler API
        self.send_response(200)
        self.send_header("Content-Length", str(len(_MARKER)))
        self.end_headers()
        self.wfile.write(_MARKER)

    def log_message(self, format_string, *args):
        del format_string, args


def _local_marker_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MarkerHandler)
    thread = threading.Thread(target=server.serve_forever, name="jerryproxy-marker")
    thread.daemon = True
    thread.start()
    return server, thread


def _socks5_http_get(proxy_port, target_port):
    """Fetch the marker through a no-auth SOCKS5 CONNECT tunnel."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise AssertionError("v2ray SOCKS5 listener did not accept no-auth negotiation")
        request = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big")
        sock.sendall(request)
        response = sock.recv(10)
        if len(response) < 2 or response[:2] != b"\x05\x00":
            raise AssertionError("v2ray SOCKS5 CONNECT failed: %r" % (response,))
        sock.sendall(
            ("GET /marker HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").encode("ascii")
        )
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


def _assert_stopped(process):
    """Perform bounded graceful cleanup, escalating to a hard kill."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3.0)
    assert process.poll() is not None


class _InstalledMihomo(object):
    def __init__(self, executable):
        self.executable = executable

    def which(self, name, version):
        assert name == "mihomo"
        assert version == "1.19.29"
        return self


class _HealthyProbe(object):
    def check(self, port, username, password):
        del port, username, password
        return HealthSnapshot((), 1, 1, 0.0)


class _Subscription(object):
    def __init__(self, record):
        self.record = record

    def list(self):
        return (self.record,)


def _v2ray_server_config(protocol, port):
    if protocol == "shadowsocks":
        settings = {"method": "aes-128-gcm", "password": "jerryproxy-test", "network": "tcp,udp"}
        stream_settings = None
    elif protocol == "vless":
        settings = {
            "clients": [{"id": "11111111-1111-4111-8111-111111111111", "level": 0}],
            "decryption": "none",
        }
        stream_settings = {"network": "tcp", "security": "none"}
    else:
        settings = {"clients": [{"id": "11111111-1111-4111-8111-111111111111", "alterId": 0}]}
        stream_settings = {"network": "tcp"}
    value = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings}],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    if stream_settings is not None:
        value["inbounds"][0]["streamSettings"] = stream_settings
    return value


def _v2ray_node_uri(protocol, port):
    if protocol == "shadowsocks":
        payload = base64.urlsafe_b64encode(b"aes-128-gcm:jerryproxy-test").decode("ascii").rstrip("=")
        return "ss://%s@127.0.0.1:%d#loopback-ss" % (payload, port)
    if protocol == "vless":
        return (
            "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:%d"
            "?type=tcp&security=none#loopback-vless"
        ) % port
    payload = json.dumps({
        "v": "2", "ps": "loopback-vmess", "add": "127.0.0.1", "port": str(port),
        "id": "11111111-1111-4111-8111-111111111111", "aid": "0", "net": "tcp",
        "type": "none", "host": "", "path": "", "tls": "",
    }, separators=(",", ":")).encode("utf-8")
    return "vmess://%s" % base64.urlsafe_b64encode(payload).decode("ascii")


def _authenticated_http_get(port, username, password, target_port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    try:
        token = base64.b64encode((username + ":" + password).encode("ascii")).decode("ascii")
        request = (
            "GET http://127.0.0.1:%d/marker HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\nProxy-Authorization: Basic %s\r\nConnection: close\r\n\r\n"
        ) % (target_port, target_port, token)
        sock.sendall(request.encode("ascii"))
        return sock.recv(8192)
    finally:
        sock.close()


@pytest.mark.parametrize("protocol", ["shadowsocks", "vmess", "vless"])
def test_runtime_session_mihomo_authenticated_loopback_marker(tmp_path, protocol):
    mihomo = os.environ.get("JERRYPROXY_E2E_MIHOMO", "").strip()
    if not mihomo:
        pytest.skip("set JERRYPROXY_E2E_MIHOMO to run the RuntimeSession harness")
    if mihomo.lower() in ("1", "true", "yes"):
        mihomo = shutil.which("mihomo") or ""
    if not mihomo or not os.path.isfile(mihomo) or not os.access(mihomo, os.X_OK):
        pytest.skip("configured mihomo executable is unavailable")
    _v2ray_executable()
    marker_server, marker_thread = _local_marker_server()
    upstream_port = _free_port()
    v2ray_config = tmp_path / "upstream.json"
    v2ray_config.write_text(json.dumps(_v2ray_server_config(protocol, upstream_port)), encoding="ascii")
    upstream = subprocess.Popen(
        [_v2ray_executable(), "run", "-config", str(v2ray_config)],
        cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    runtime = None
    try:
        body = (_v2ray_node_uri(protocol, upstream_port) + "\n").encode("ascii")
        parsed = parse_subscription_body(body, format_hint="uri-lines")
        record = build_record("loopback", "a" * 32, parsed)
        paths = JerryProxyPaths(tmp_path / ".jerryproxy")
        paths.ensure()
        runtime = RuntimeSession(
            paths,
            manager=_InstalledMihomo(mihomo),
            subscription_manager=_Subscription(record),
            health_probe=_HealthyProbe(),
            authenticate=True,
            listener_protocol="http",
            process_factory=None,
            recovery_policy=RecoveryPolicy(startup_retry_delays=(0.0,), recovery_deadline=10.0),
        )
        runtime.start("loopback", node_id=record.nodes[0].node_id, install_missing=False)
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if upstream.poll() is not None:
                break
            try:
                response = _authenticated_http_get(
                    runtime.port, runtime.username, runtime.password, marker_server.server_port
                )
                if _MARKER in response:
                    break
            except (OSError, RuntimeError):
                time.sleep(0.05)
        else:
            raise AssertionError("RuntimeSession/Mihomo did not proxy the marker")
        assert _MARKER in response
    finally:
        if runtime is not None:
            runtime.stop()
        _assert_stopped(upstream)
        marker_server.shutdown()
        marker_server.server_close()
        marker_thread.join(timeout=3.0)
    assert not marker_thread.is_alive()


@pytest.mark.parametrize("protocol", ["shadowsocks", "vmess", "vless"])
def test_installed_v2ray_proxies_loopback_marker_and_leaves_no_child(tmp_path, protocol):
    executable = _v2ray_executable()
    marker_server, marker_thread = _local_marker_server()
    proxy_port = _free_port()
    server_port = _free_port()
    if protocol == "shadowsocks":
        server_settings = {"method": "aes-128-gcm", "password": "jerryproxy-test", "network": "tcp,udp"}
        client_outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",
                    "port": server_port,
                    "method": "aes-128-gcm",
                    "password": "jerryproxy-test",
                }]
            },
        }
        server_stream_settings = None
    elif protocol == "vless":
        server_settings = {
            "clients": [{"id": "11111111-1111-4111-8111-111111111111", "level": 0}],
            "decryption": "none",
        }
        client_outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": server_port,
                    "users": [{"id": "11111111-1111-4111-8111-111111111111", "encryption": "none"}],
                }]
            },
            "streamSettings": {"network": "tcp", "security": "none"},
        }
        server_stream_settings = {"network": "tcp", "security": "none"}
    else:
        server_settings = {"clients": [{"id": "11111111-1111-4111-8111-111111111111", "alterId": 0}]}
        client_outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": server_port,
                    "users": [{
                        "id": "11111111-1111-4111-8111-111111111111",
                        "alterId": 0,
                        "security": "auto",
                    }],
                }]
            },
            "streamSettings": {"network": "tcp"},
        }
        server_stream_settings = {"network": "tcp"}
    server_config = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": protocol, "settings": server_settings}],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    if server_stream_settings is not None:
        server_config["inbounds"][0]["streamSettings"] = server_stream_settings
    client_config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": proxy_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [client_outbound],
    }
    server_config_path = tmp_path / "server.json"
    client_config_path = tmp_path / "client.json"
    server_config_path.write_text(json.dumps(server_config), encoding="ascii")
    client_config_path.write_text(json.dumps(client_config), encoding="ascii")
    popen_options = {
        "cwd": str(tmp_path),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    processes = []
    try:
        processes.append(subprocess.Popen(
            [executable, "run", "-config", str(server_config_path)], **popen_options
        ))
        processes.append(subprocess.Popen(
            [executable, "run", "-config", str(client_config_path)], **popen_options
        ))
    except OSError:
        for process in reversed(processes):
            _assert_stopped(process)
        raise
    server_process, client_process = processes
    try:
        deadline = time.time() + 8.0
        while time.time() < deadline:
            for process in processes:
                if process.poll() is not None:
                    stderr = process.stderr.read().decode("utf-8", "replace")
                    raise AssertionError("v2ray exited before readiness: %s" % stderr[-500:])
            try:
                result = _socks5_http_get(proxy_port, marker_server.server_port)
                if _MARKER in result:
                    break
            except (OSError, AssertionError):
                time.sleep(0.05)
        else:
            raise AssertionError("v2ray SOCKS5 loopback proxy did not become ready")
        assert _MARKER in result
        client_process.kill()  # exercise hard-exit cleanup path
    finally:
        for process in reversed(processes):
            _assert_stopped(process)
        marker_server.shutdown()
        marker_server.server_close()
        marker_thread.join(timeout=3.0)
    assert not marker_thread.is_alive()


def _free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()
