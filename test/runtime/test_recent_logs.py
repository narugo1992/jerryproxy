"""Both log producers must retain recent diagnostics after the size bound."""

import io
import os

import pytest

from jerryproxy.runtime.mihomo import MAXIMUM_LOG_BYTES, MihomoProcess

from .test_session import FakeProbe, _record, _session


def test_backend_keeps_recent_lines_after_log_fills(tmp_path):
    path = tmp_path / "runtime.log"
    path.write_bytes(b"old-line\n" * (MAXIMUM_LOG_BYTES // 9))
    path.chmod(0o600)
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path)
    process._drain(io.BytesIO(b"latest-backend-failure\n" * 100))
    data = path.read_bytes()
    assert data.endswith(b"[mihomo] latest-backend-failure\n")
    assert b"old-line\n" in data
    assert len(data) <= MAXIMUM_LOG_BYTES


def test_session_keeps_recent_health_information_after_log_fills(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.log_path.write_bytes(b"old-line\n" * (MAXIMUM_LOG_BYTES // 9))
    runtime.log_path.chmod(0o600)
    try:
        runtime.start("main", record.nodes[0].node_id, install_missing=False)
        data = runtime.log_path.read_bytes()
        assert b"proxy listener ready" in data
        assert b"old-line\n" in data
        assert len(data) <= MAXIMUM_LOG_BYTES
    finally:
        runtime.stop()


@pytest.mark.parametrize("progress", [0, 3])
def test_backend_short_writes_are_completed_or_reported_without_stopping_drain(tmp_path, monkeypatch, progress):
    original = os.write
    seen = []
    path = tmp_path / "runtime.log"
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path,
                            log_sink=lambda *event: seen.append(event))

    def short_write(descriptor, payload):
        return original(descriptor, payload[:progress])

    monkeypatch.setattr(os, "write", short_write)
    process._drain(io.BytesIO(b"newest\n"))
    assert seen == [("mihomo", "INFO", "newest")]
    if progress:
        assert path.read_bytes() == b"[mihomo] newest\n"
    else:
        assert process._drain_errors


def test_compaction_discards_partial_old_line_and_keeps_new_line(tmp_path):
    path = tmp_path / "runtime.log"
    path.write_bytes(b"x" * MAXIMUM_LOG_BYTES)
    path.chmod(0o600)
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path)
    process._drain(io.BytesIO(b"newest\n"))
    assert path.read_bytes() == b"[mihomo] newest\n"


@pytest.mark.parametrize("producer", ["backend", "session"])
@pytest.mark.parametrize("unsafe", ["alias", "permissions", "directory"])
def test_recent_log_retention_refuses_unsafe_paths(tmp_path, producer, unsafe):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    path = runtime.log_path
    target = tmp_path / "untouched"
    target.write_bytes(b"must not change\n")
    if unsafe == "alias":
        try:
            path.symlink_to(target)
        except OSError:
            # Windows may deny unprivileged symbolic link creation.
            pytest.skip("symbolic links unavailable")
    elif unsafe == "permissions":
        if os.name != "posix":
            pytest.skip("POSIX mode boundary")
        path.write_bytes(b"must not change\n")
        path.chmod(0o644)
    else:
        path.mkdir(mode=0o700)
    if producer == "backend":
        process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path)
        process._drain(io.BytesIO(b"diagnostic\n" * 20))
        assert len(process._drain_errors) == 8
    else:
        try:
            runtime.start("main", record.nodes[0].node_id, install_missing=False)
            assert runtime._log_errors
        finally:
            runtime.stop()
    assert target.read_bytes() == b"must not change\n"
    if unsafe != "directory":
        assert path.read_bytes() == b"must not change\n"


def test_repeated_compaction_keeps_recent_redacted_complete_lines(tmp_path, monkeypatch):
    from jerryproxy.runtime import mihomo

    monkeypatch.setattr(mihomo, "MAXIMUM_LOG_BYTES", 512)
    path = tmp_path / "runtime.log"
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path)
    for batch in range(100):
        process._drain(io.BytesIO(
            ("batch-%03d https://example.org/?token=private-secret\n" % batch).encode("ascii") * 10
        ))
        data = path.read_bytes()
        assert len(data) <= 512
        assert b"private-secret" not in data
        assert data.startswith(b"[mihomo] ")
        assert data.endswith(b"\n")
        assert ("batch-%03d" % batch).encode("ascii") in data
    assert b"batch-000" not in data
    assert not process._drain_errors


@pytest.mark.skipif(os.name != "posix", reason="POSIX character device descriptor")
@pytest.mark.parametrize("producer", ["backend", "session"])
def test_log_writer_checks_the_opened_descriptor(tmp_path, monkeypatch, producer):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True] * 10))
    path = runtime.log_path
    original = os.open

    def substitute_device(filename, flags, mode=0o777, **kwargs):
        if filename == str(path):
            return original(os.devnull, os.O_RDWR)
        return original(filename, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", substitute_device)
    if producer == "backend":
        process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path)
        process._drain(io.BytesIO(b"diagnostic\n"))
        assert "not a regular file" in process._drain_errors[0]
    else:
        for _ in range(10):
            try:
                runtime.start("main", record.nodes[0].node_id, install_missing=False)
            finally:
                runtime.stop()
        assert len(runtime._log_errors) == 8
        assert all("not a regular file" in error for error in runtime._log_errors)
    assert not path.exists()


def test_blank_backend_lines_and_closed_sink_do_not_stop_recent_logging(tmp_path):
    def closed_sink(*event):
        raise OSError("closed terminal")

    path = tmp_path / "runtime.log"
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, path, log_sink=closed_sink)
    process._drain(io.BytesIO(b"  \r\nnewest\n"))
    assert path.read_bytes() == b"[mihomo] newest\n"
    assert not process._drain_errors
