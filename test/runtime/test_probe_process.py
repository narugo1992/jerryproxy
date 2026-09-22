"""Production probes must release network workers after a hard wall deadline."""

import socket
import threading
import time

import pytest

from jerryproxy.runtime.health import ConnectivityProbe, HealthTarget


@pytest.mark.timeout(30)
def test_slow_proxy_headers_do_not_occupy_future_probe_batches():
    import multiprocessing

    children_before = set(child.pid for child in multiprocessing.active_children())
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.1)
    stop = threading.Event()
    accepted = []

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            accepted.append(connection)
            connection.settimeout(1)
            try:
                connection.recv(8192)
                for byte in b"HTTP/1.1 200 Connection established\r\nX-Slow: " + b"x" * 2000:
                    if stop.wait(0.01):
                        break
                    connection.sendall(bytes([byte]))
            except OSError:
                # Deadline cancellation closes the client connection.
                pass
            finally:
                connection.close()

    server = threading.Thread(target=serve)
    server.start()
    # Native CI can spend over a second importing a cold spawned interpreter.
    # Give startup room while trickling longer than the complete probe budget.
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1, timeout=5)
    try:
        for _ in range(2):
            before = len(accepted)
            started = time.monotonic()
            snapshot = probe.check(listener.getsockname()[1], None, None)
            assert not snapshot.ok
            assert time.monotonic() - started < 8
            probe.close(timeout=1)
            assert set(child.pid for child in multiprocessing.active_children()) == children_before
            assert len(accepted) > before
    finally:
        stop.set()
        server.join(3)
        listener.close()
        probe.close(timeout=2)


def test_successful_isolated_probe_closes_process_and_preserves_quorum():
    import base64
    import multiprocessing
    from http.server import BaseHTTPRequestHandler, HTTPServer

    observed = []

    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - standard library callback
            observed.append(self.headers.get("Proxy-Authorization"))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    before = set(child.pid for child in multiprocessing.active_children())
    probe = ConnectivityProbe(targets=(HealthTarget("one", "http://example.invalid", 204),), quorum=1, timeout=5)
    try:
        snapshot = probe.check(server.server_port, "local-user", "local-password")
        assert snapshot.ok and snapshot.passed == 1
        assert snapshot.targets[0].name == "one"
        assert observed == ["Basic " + base64.b64encode(b"local-user:local-password").decode("ascii")]
        assert "local-password" not in repr(snapshot)
        assert set(child.pid for child in multiprocessing.active_children()) == before
    finally:
        probe.close()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_interrupted_isolated_probe_reaps_its_network_process(monkeypatch):
    import multiprocessing
    import multiprocessing.connection

    import pytest

    original = multiprocessing.connection._ConnectionBase.poll
    before = set(child.pid for child in multiprocessing.active_children())
    calls = []

    def interrupted(connection, timeout=0):
        calls.append(True)
        raise KeyboardInterrupt

    monkeypatch.setattr(multiprocessing.connection._ConnectionBase, "poll", interrupted)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1, timeout=5)
    with pytest.raises(KeyboardInterrupt):
        probe.check(1, "local-user", "local-password")
    monkeypatch.setattr(multiprocessing.connection._ConnectionBase, "poll", original)
    assert calls == [True]
    assert set(child.pid for child in multiprocessing.active_children()) == before
    probe.close()


def test_default_probe_zero_budget_starts_no_process():
    import multiprocessing

    before = set(child.pid for child in multiprocessing.active_children())
    probe = ConnectivityProbe()
    snapshot = probe.check(1, None, None, timeout=0)
    assert not snapshot.ok
    assert all(item.detail == "probe_deadline" for item in snapshot.targets)
    assert set(child.pid for child in multiprocessing.active_children()) == before
    probe.close()


def test_connect_authentication_refusal_is_terminal_across_process_boundary():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    methods = []

    class Proxy(BaseHTTPRequestHandler):
        def do_CONNECT(self):  # noqa: N802 - standard library callback
            methods.append(self.command)
            self.send_response(407, "private-provider-diagnostic")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1, timeout=5)
    try:
        snapshot = probe.check(server.server_port, "local-user", "local-password")
        assert methods == ["CONNECT"]
        assert not snapshot.ok
        assert snapshot.targets[0].detail == "proxy_authentication_failed"
        assert "private-provider-diagnostic" not in repr(snapshot)
        assert "local-password" not in repr(snapshot)
    finally:
        probe.close()
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("certificate", [False, True])
@pytest.mark.timeout(30)
def test_tls_refusal_is_a_failed_target_across_process_boundary(tmp_path, certificate):
    import shutil
    import ssl
    import subprocess

    if certificate and shutil.which("openssl") is None:
        pytest.skip("openssl is needed for a real untrusted certificate")
    context = None
    if certificate:
        key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=example.invalid"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    handshakes = []
    failures = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if context is not None:
                    try:
                        with context.wrap_socket(connection, server_side=True):
                            handshakes.append("accepted-untrusted-certificate")
                    except ssl.SSLError:
                        # Strict client validation must reject this certificate.
                        handshakes.append("rejected-certificate")
                else:
                    connection.recv(4096)
                    handshakes.append("closed-during-handshake")
        except OSError as error:
            # Surface fixture transport failures on the parent test thread.
            failures.append(type(error).__name__)

    worker = threading.Thread(target=serve)
    worker.start()
    probe = ConnectivityProbe(targets=(HealthTarget("tls-target", "https://example.invalid/", 204),),
                              quorum=1, timeout=10)
    try:
        snapshot = probe.check(listener.getsockname()[1], None, None)
        assert not snapshot.ok
        assert snapshot.targets[0].detail == "tls_failed"
        worker.join(5)
        assert not worker.is_alive()
        assert not failures
        assert handshakes == ["rejected-certificate" if certificate else "closed-during-handshake"]
        assert "example.invalid" not in repr(snapshot)
    finally:
        probe.close()
        listener.close()
        worker.join(5)
