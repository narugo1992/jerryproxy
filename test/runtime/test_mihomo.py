import io
import os
import threading

import pytest

import jerryproxy.runtime.mihomo as mihomo_module
from jerryproxy.errors import RuntimeSessionError
from jerryproxy.runtime.health import ConnectivityProbe
from jerryproxy.runtime.mihomo import (
    MAXIMUM_LOG_BYTES,
    MihomoProcess,
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


def test_backend_process_merges_process_output_into_one_named_stream(tmp_path, monkeypatch):
    captured = {}
    events = []

    class FakeProcess(object):
        pid = 123
        stdout = io.BytesIO(b"stdout line\nstderr line\n")

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
    assert events == [("v2ray", "INFO", "stdout line stderr line")]
    persisted = process.log_path.read_text(encoding="utf-8")
    assert persisted == "[v2ray] stdout line stderr line\n"
    assert "[backend:stdout]" not in persisted
    assert "[backend:stderr]" not in persisted


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
    listener_lines = [
        line
        for line in config.splitlines()
        if line.split(":", 1)[0] in ("mixed-port", "port", "socks-port")
    ]
    assert listener_lines == ["%s: 17777" % directive]


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
        listener_protocol="http",
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
            None,
            None,
            bind_address="192.0.2.1",
        )
