import io
import os
import signal
import socket
import sys
import threading

import pytest

import jerryproxy.runtime.mihomo as mihomo_module
from jerryproxy.errors import RuntimeSessionError
from jerryproxy.runtime.health import ConnectivityProbe
from jerryproxy.runtime.mihomo import (
    MAXIMUM_LOG_BYTES,
    MihomoProcess,
    _listener_owned_by_process,
    _windows_tcp_port,
    build_provider_config,
    reserve_loopback_port,
)


def test_backend_drain_continues_after_log_alias_failure(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "outside.log"
    target.write_bytes(b"outside")
    log_path = logs / "runtime.log"
    if os.name != "nt":
        log_path.symlink_to(target)
    else:
        pytest.skip("POSIX alias primitive is not available on this runner")
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, log_path)
    class NonClosingBytesIO(io.BytesIO):
        def close(self):
            pass

    stream = NonClosingBytesIO(b"secret backend output\n" * 4)
    process._drain(stream)
    assert stream.tell() == len(stream.getvalue())
    assert process._drain_errors
    assert target.read_bytes() == b"outside"


def test_backend_drain_bounds_persisted_log(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    log_path = logs / "runtime.log"
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, log_path)
    process._drain(io.BytesIO(b"x" * (MAXIMUM_LOG_BYTES + 4096)))
    assert log_path.stat().st_size <= MAXIMUM_LOG_BYTES
    assert b"[mihomo]" in log_path.read_bytes()


def test_backend_drain_forwards_small_live_chunks_before_pipe_closes(tmp_path):
    read_descriptor, write_descriptor = os.pipe()
    stream = os.fdopen(read_descriptor, "rb")
    seen = []
    received = threading.Event()

    def sink(source, level, message):
        seen.append((source, level, message))
        received.set()

    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
        log_sink=sink,
    )
    worker = threading.Thread(target=process._drain, args=(stream,))
    worker.start()
    try:
        os.write(write_descriptor, b"[TCP] live request\n")
        assert received.wait(1.0)
        assert seen == [("mihomo", "INFO", "[TCP] live request")]
    finally:
        os.close(write_descriptor)
        worker.join(1.0)
    assert not worker.is_alive()
    assert process.log_path.read_text(encoding="utf-8") == "[mihomo] [TCP] live request\n"


def test_backend_process_drains_stdout_and_stderr_into_one_named_stream(tmp_path, monkeypatch):
    captured = {}
    events = []

    class FakeProcess(object):
        pid = 123
        stdout = io.BytesIO(b"stdout line\n")

        def poll(self):
            return 0

    def fake_popen(arguments, **options):
        captured["arguments"] = arguments
        captured.update(options)
        return FakeProcess()

    monkeypatch.setattr(mihomo_module.subprocess, "Popen", fake_popen)
    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
        log_sink=lambda *event: events.append(event),
        backend_name="v2ray",
    )

    process.start()
    for thread in process._threads:
        thread.join(1.0)

    assert captured["stdout"] is mihomo_module.subprocess.PIPE
    assert captured["stderr"] is mihomo_module.subprocess.STDOUT
    assert events == [("v2ray", "INFO", "stdout line")]
    persisted = process.log_path.read_text(encoding="utf-8")
    assert persisted == "[v2ray] stdout line\n"
    assert "stderr line" not in persisted
    assert "[backend:stdout]" not in persisted
    assert "[backend:stderr]" not in persisted


def test_linux_process_identity_rejects_reused_or_unknown_pid():
    if not sys.platform.startswith("linux"):
        pytest.skip("procfs identity is Linux-specific")
    pid = os.getpid()
    start_time = mihomo_module._linux_process_start_time(pid)
    assert start_time is not None
    assert mihomo_module._linux_process_identity_matches(pid, start_time)
    assert not mihomo_module._linux_process_identity_matches(pid, start_time + 1)
    assert not mihomo_module._linux_process_identity_matches(pid, None)


def test_windows_job_helper_is_inactive_off_windows():
    if os.name == "nt":
        pytest.skip("native Windows Job Object path")
    assert mihomo_module._windows_create_job() is None
    assert not mihomo_module._windows_assign_job(None, None)


def test_guardian_malformed_metadata_aborts_before_reraising(tmp_path, monkeypatch):
    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
    )
    process.process = type("Child", (), {"poll": lambda self: None})()
    aborted = []
    monkeypatch.setattr(process, "_abort_start", lambda: aborted.append(True))
    monkeypatch.setattr(mihomo_module, "_read_private_metadata", lambda path, maximum: b"{")

    with pytest.raises(RuntimeSessionError, match="identity could not be read"):
        process._load_guardian_identity(timeout=0.01)
    assert aborted == [True]


def test_guardian_owns_backend_and_forwards_redacted_output(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX guardian fixture")
    if sys.platform.startswith("linux"):
        # Exercise the Python 3.7/old-kernel fallback that relies on the
        # authenticated guardian process group instead of pidfd APIs.
        monkeypatch.setattr(mihomo_module, "_linux_optional_pidfd_open", lambda pid: None)
    executable = tmp_path / "backend-fixture"
    executable.write_text(
        "#!%s\n"
        "import sys, time\n"
        "sys.stdout.write('raw stdout secret\\n'); sys.stdout.flush()\n"
        "sys.stderr.write('raw stderr secret\\n'); sys.stderr.flush()\n"
        "time.sleep(30)\n" % sys.executable,
        encoding="utf-8",
    )
    executable.chmod(0o700)
    config = tmp_path / "config.yaml"
    config.write_text("fixture\n", encoding="ascii")
    logs = tmp_path / "logs"
    logs.mkdir()
    events = []
    process = MihomoProcess(
        executable,
        config,
        tmp_path,
        logs / "runtime.log",
        log_sink=lambda *event: events.append(event),
    )
    process.start()
    try:
        assert process.backend_pid and process.backend_pid != process.process.pid
        assert mihomo_module._posix_process_parent(process.backend_pid) == process.process.pid
        for thread in process._threads:
            thread.join(1.0)
        assert any("raw stdout secret" in item[2] for item in events)
        assert any("raw stderr secret" in item[2] for item in events)
    finally:
        process.stop(timeout=1.0)
    persisted = (logs / "runtime.log").read_text(encoding="ascii")
    assert "[mihomo] raw stdout secret\n" in persisted
    assert "[mihomo] raw stderr secret\n" in persisted
    assert process.process.poll() is not None


def test_guardian_crash_cleanup_kills_backend_grandchildren(tmp_path):
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux process-group census fixture")
    executable = tmp_path / "forking-backend"
    executable.write_text(
        "#!%s\n"
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    time.sleep(30)\n"
        "else:\n"
        "    time.sleep(30)\n" % sys.executable,
        encoding="ascii",
    )
    executable.chmod(0o700)
    config = tmp_path / "config.yaml"
    config.write_text("fixture\n", encoding="ascii")
    process = MihomoProcess(executable, config, tmp_path, tmp_path / "runtime.log")
    process.start()
    try:
        assert process.backend_pid is not None
        assert mihomo_module._linux_process_group_members(process._backend_pgid, process._backend_sid)
        os.kill(process.process.pid, signal.SIGKILL)
        process.process.wait(timeout=2.0)
        process.stop(timeout=0.5)
        assert not mihomo_module._linux_process_group_members(process._backend_pgid, process._backend_sid)
    finally:
        if process.process is not None and process.process.poll() is None:
            process.stop(timeout=1.0)


def test_backend_drain_forwards_redacted_core_lines_and_flushes_partial_line(tmp_path):
    events = []
    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
        log_sink=lambda *event: events.append(event),
        backend_name="xray",
    )
    process._drain(
        io.BytesIO(
            b"connected vless://11111111-1111-1111-1111-111111111111@example.test:443?token=secret\n"
            b"partial"
        )
    )

    assert [event[0:3] for event in events] == [
        ("xray", "INFO", "connected vless://example.test:443"),
        ("xray", "INFO", "partial"),
    ]
    persisted = process.log_path.read_text(encoding="utf-8")
    assert "[xray] connected vless://example.test:443\n" in persisted
    assert "[xray] partial\n" in persisted
    assert "11111111-1111-1111-1111-111111111111" not in persisted
    assert "secret" not in persisted


def test_backend_drain_bounds_a_newline_free_line_without_stalling(tmp_path):
    events = []
    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
        log_sink=lambda *event: events.append(event),
        backend_name="mihomo",
    )
    process._drain(io.BytesIO(b"x" * (mihomo_module.MAXIMUM_BACKEND_LINE_BYTES + 1)))

    assert len(events) == 2
    assert all(event[0:2] == ("mihomo", "INFO") for event in events)
    assert all("[line truncated]" in event[2] for event in events)


def test_backend_drain_bounds_newline_free_output_across_multiple_reads(tmp_path):
    events = []
    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
        log_sink=lambda *event: events.append(event),
        backend_name="mihomo",
    )
    process._drain(io.BytesIO(b"x" * (64 * 1024 * 3 + 1)))

    assert len(events) >= 13
    assert all(len(event[2].encode("utf-8")) <= mihomo_module.MAXIMUM_BACKEND_LINE_BYTES + 64 for event in events)


def test_backend_drain_bounds_a_single_oversized_newline_terminated_line(tmp_path):
    events = []
    process = MihomoProcess(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path,
        tmp_path / "runtime.log",
        log_sink=lambda *event: events.append(event),
        backend_name="mihomo",
    )
    process._drain(io.BytesIO(b"x" * (mihomo_module.MAXIMUM_BACKEND_LINE_BYTES * 4) + b"\n"))

    assert len(events) == 4
    assert all(len(event[2].encode("utf-8")) <= mihomo_module.MAXIMUM_BACKEND_LINE_BYTES + 64 for event in events)
    assert all("[line truncated]" in event[2] for event in events)


def test_strict_port_reservation_fails_when_requested_port_is_busy():
    import socket

    descriptor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    descriptor.bind(("127.0.0.1", 0))
    occupied = descriptor.getsockname()[1]
    try:
        with pytest.raises(RuntimeSessionError):
            reserve_loopback_port(preferred=occupied, strict=True)
    finally:
        descriptor.close()


@pytest.mark.parametrize(
    ("protocol", "directive"),
    [("mixed", "mixed-port"), ("http", "port"), ("socks5", "socks-port")],
)
def test_provider_config_selects_the_requested_listener(tmp_path, protocol, directive):
    config = build_provider_config(
        tmp_path / "provider.txt",
        b"ss://opaque\n",
        17777,
        None,
        None,
        listener_protocol=protocol,
        log_level="INFO",
    ).decode("utf-8")

    assert "%s: 17777" % directive in config
    assert "bind-address: 127.0.0.1" in config
    assert "log-level: info" in config
    assert "authentication:" not in config


def test_readiness_challenge_rejects_an_http_auth_substitute(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, tmp_path / "runtime.log")
    process.set_readiness_challenge("user", "password", "http", "127.0.0.1")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve_once():
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

    worker = threading.Thread(target=serve_once)
    worker.start()
    try:
        with pytest.raises(RuntimeSessionError, match="credentials"):
            process._challenge_listener(listener.getsockname()[1])
    finally:
        listener.close()
        worker.join(1.0)


def test_readiness_challenge_rejects_an_unexpected_http_success(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, tmp_path / "runtime.log")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve_once():
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 201 Created\r\n\r\n")

    worker = threading.Thread(target=serve_once)
    worker.start()
    try:
        with pytest.raises(RuntimeSessionError, match="unexpected HTTP"):
            process._challenge_listener(listener.getsockname()[1])
    finally:
        listener.close()
        worker.join(1.0)


def test_readiness_challenge_accepts_http_connect_success(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, tmp_path / "runtime.log")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve_once():
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    worker = threading.Thread(target=serve_once)
    worker.start()
    try:
        process._challenge_listener(listener.getsockname()[1])
    finally:
        listener.close()
        worker.join(1.0)


def test_linux_readiness_proves_listener_process_ownership(tmp_path):
    if not sys.platform.startswith("linux"):
        pytest.skip("procfs listener ownership is Linux-specific")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    process = type("Process", (), {"pid": os.getpid()})()
    try:
        assert _listener_owned_by_process(process, listener.getsockname()[1], "127.0.0.1") is True
    finally:
        listener.close()


@pytest.mark.parametrize(
    ("bound_address", "claimed_address", "expected"),
    [
        ("127.0.0.1", "127.0.0.1", True),
        ("127.0.0.1", "0.0.0.0", False),
        ("0.0.0.0", "0.0.0.0", True),
        ("0.0.0.0", "127.0.0.1", False),
    ],
)
def test_linux_readiness_requires_exact_listener_address(tmp_path, bound_address, claimed_address, expected):
    if not sys.platform.startswith("linux"):
        pytest.skip("procfs listener ownership is Linux-specific")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((bound_address, 0))
    listener.listen(1)
    process = type("Process", (), {"pid": os.getpid()})()
    try:
        assert _listener_owned_by_process(process, listener.getsockname()[1], claimed_address) is expected
    finally:
        listener.close()


def test_windows_tcp_port_decodes_the_network_order_low_word():
    assert _windows_tcp_port(socket.htons(17777)) == 17777


def test_macos_lsof_probe_uses_fixed_path_and_exact_wildcard(monkeypatch, tmp_path):
    executable = tmp_path / "lsof"
    executable.write_text(
        "#!/bin/sh\nprintf 'p%s\\nn%s\\n' \"$4\" \"$LPORT\"\n",
        encoding="ascii",
    )
    executable.chmod(0o700)
    monkeypatch.setattr(mihomo_module, "_MACOS_LSOF_PATHS", (str(executable),))
    process = type("Process", (), {"pid": 123})()
    monkeypatch.setattr(
        mihomo_module.subprocess,
        "run",
        lambda argv, **kwargs: type("Result", (), {"stdout": b"p123\nn127.0.0.1:17777\n"})(),
    )
    assert mihomo_module._listener_owned_by_macos_process(process, 17777, "0.0.0.0") is False
    monkeypatch.setattr(
        mihomo_module.subprocess,
        "run",
        lambda argv, **kwargs: type("Result", (), {"stdout": b"p123\nn*:17777\n"})(),
    )
    assert mihomo_module._listener_owned_by_macos_process(process, 17777, "0.0.0.0") is True


def test_readiness_fails_closed_when_owner_proof_is_unavailable(tmp_path, monkeypatch):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, tmp_path / "runtime.log")

    class Child(object):
        def poll(self):
            return None

    process.process = Child()
    monkeypatch.setattr(process, "_challenge_listener", lambda port: None)
    monkeypatch.setattr(mihomo_module, "_listener_owned_by_process", lambda *args: None)
    with pytest.raises(RuntimeSessionError, match="did not become ready"):
        process.wait_ready(17777, timeout=0.01)


def test_socks5_health_probe_uses_socks5h_transport():
    assert ConnectivityProbe._proxy_url(1080, "user", "pass", "socks5") == "socks5h://user:pass@127.0.0.1:1080"


def test_default_health_probe_url_is_unauthenticated():
    assert ConnectivityProbe._proxy_url(1080, None, None, "http") == "http://127.0.0.1:1080"


def test_provider_config_can_enable_authentication(tmp_path):
    config = build_provider_config(
        tmp_path / "provider.txt",
        b"ss://opaque\n",
        17777,
        "user",
        "password",
        listener_protocol="mixed",
        log_level="INFO",
    ).decode("utf-8")

    assert "authentication:" in config
    assert "  - 'user:password'" in config


def test_provider_config_can_bind_all_interfaces_explicitly(tmp_path):
    config = build_provider_config(
        tmp_path / "provider.txt",
        b"ss://opaque\n",
        17777,
        None,
        None,
        listener_protocol="mixed",
        bind_address="0.0.0.0",
    ).decode("utf-8")

    assert "bind-address: 0.0.0.0" in config
    assert "allow-lan: true" in config


def test_provider_config_rejects_an_unapproved_bind_address(tmp_path):
    with pytest.raises(ValueError):
        build_provider_config(
            tmp_path / "provider.txt",
            b"ss://opaque\n",
            17777,
            "user",
            "password",
            bind_address="192.0.2.1",
        )
