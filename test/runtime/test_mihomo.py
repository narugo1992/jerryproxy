import io
import json
import os
import signal
import socket
import subprocess
import sys
import threading

import pytest

import jerryproxy.runtime.guardian as guardian_module
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
    monkeypatch.setattr(mihomo_module, "_posix_process_start_time", lambda pid: "test-start")

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


def test_guardian_parent_identity_requires_same_parent_and_start_token(monkeypatch):
    monkeypatch.setattr(guardian_module.os, "getppid", lambda: 42)
    monkeypatch.setattr(guardian_module, "_start_time", lambda pid: "started")

    assert guardian_module._parent_identity_matches(42, "started")
    assert not guardian_module._parent_identity_matches(41, "started")
    assert not guardian_module._parent_identity_matches(42, "reused")
    assert not guardian_module._parent_identity_matches(42, None)


@pytest.mark.parametrize("module", [guardian_module, mihomo_module])
def test_parent_death_signal_fails_closed_when_prctl_returns_error(monkeypatch, module):
    if os.name != "posix":
        pytest.skip("parent-death signal is POSIX-specific")

    import ctypes

    class FailingPrctl(object):
        argtypes = None
        restype = None

        def __call__(self, *args):
            del args
            return -1

    class FakeLibc(object):
        prctl = FailingPrctl()

    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: FakeLibc())
    monkeypatch.setattr(ctypes, "get_errno", lambda: 1)

    with pytest.raises(OSError):
        module._configure_parent_death_signal()


def test_guardian_converts_parent_death_setup_failure_to_launch_failure(tmp_path, monkeypatch):
    def fail_launch(*args, **kwargs):
        del args, kwargs
        raise subprocess.SubprocessError("pre-exec prctl failed")

    monkeypatch.setattr(guardian_module.subprocess, "Popen", fail_launch)
    assert guardian_module.run(tmp_path / "mihomo", tmp_path / "config", tmp_path / "meta", tmp_path) == 127


def test_guardian_main_reports_parent_death_setup_failure(monkeypatch):
    def fail_setup():
        raise OSError("prctl unavailable")

    monkeypatch.setattr(guardian_module, "_configure_parent_death_signal", fail_setup)
    assert guardian_module.main(["--executable", "x", "--config", "y", "--metadata", "z", "--session-root", "."]) == 127


def test_guardian_refuses_to_launch_without_authenticated_parent(tmp_path, monkeypatch):
    monkeypatch.setattr(guardian_module, "_parent_identity_matches", lambda pid, token: False)

    def unexpected_launch(*args, **kwargs):
        raise AssertionError("backend must not launch without parent authentication")

    monkeypatch.setattr(guardian_module.subprocess, "Popen", unexpected_launch)
    result = guardian_module.run(
        tmp_path / "mihomo",
        tmp_path / "config.yaml",
        tmp_path / "guardian.json",
        tmp_path,
        parent_pid=42,
        parent_start_time="started",
    )

    assert result == 125


def test_guardian_rejects_closed_start_gate_before_launch(tmp_path, monkeypatch):
    read_descriptor, write_descriptor = os.pipe()
    os.close(write_descriptor)
    launched = []

    def unexpected_launch(*args, **kwargs):
        launched.append((args, kwargs))
        raise AssertionError("backend must not launch after gate cancellation")

    monkeypatch.setattr(guardian_module.subprocess, "Popen", unexpected_launch)
    try:
        result = guardian_module.run(
            tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path / "guardian.json", tmp_path,
            start_gate=read_descriptor,
        )
    finally:
        try:
            os.close(read_descriptor)
        except OSError:
            pass
    assert result == 125
    assert launched == []


def test_guardian_returns_launch_error_without_creating_metadata(tmp_path, monkeypatch):
    def fail_launch(*args, **kwargs):
        raise OSError("executable missing")

    monkeypatch.setattr(guardian_module.subprocess, "Popen", fail_launch)
    metadata = tmp_path / "guardian.json"
    result = guardian_module.run(tmp_path / "missing", tmp_path / "config.yaml", metadata, tmp_path)
    assert result == 127
    assert not metadata.exists()


def test_guardian_rejects_aliased_metadata_parent(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "lease"
    if os.name == "nt":
        pytest.skip("symlink primitive is not available on this Windows runner")
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError, match="aliased"):
        guardian_module._write_metadata(alias / "guardian.json", {"pid": 1}, tmp_path)


def test_guardian_metadata_is_private_and_atomically_readable(tmp_path):
    metadata = tmp_path / "lease" / "guardian.json"
    guardian_module._write_metadata(metadata, {"pid": 7, "config": "x"}, tmp_path)
    assert json.loads(metadata.read_text(encoding="ascii")) == {"pid": 7, "config": "x"}
    if os.name == "posix":
        assert metadata.stat().st_mode & 0o777 == 0o600


def test_guardian_terminates_child_when_metadata_publication_fails(tmp_path, monkeypatch):
    class Child(object):
        pid = 123

        def __init__(self):
            self.terminated = False

        def wait(self, timeout=None):
            del timeout
            return 0

        def poll(self):
            return None

    child = Child()
    monkeypatch.setattr(guardian_module.subprocess, "Popen", lambda *args, **kwargs: child)
    monkeypatch.setattr(
        guardian_module,
        "_write_metadata",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("alias")),
    )
    monkeypatch.setattr(
        guardian_module,
        "_terminate_child_group",
        lambda value, hard=False: setattr(value, "terminated", hard),
    )
    monkeypatch.setattr(guardian_module, "_start_time", lambda pid: 1)
    monkeypatch.setattr(guardian_module.os, "getpgid", lambda pid: pid, raising=False)
    monkeypatch.setattr(guardian_module.os, "getsid", lambda pid: pid, raising=False)
    assert guardian_module.run(tmp_path / "mihomo", tmp_path / "config", tmp_path / "meta", tmp_path) == 127
    assert child.terminated is True


def test_guardian_publishes_identity_and_returns_child_status(tmp_path, monkeypatch):
    class Child(object):
        pid = 321

        def poll(self):
            return 0

        def wait(self, timeout=None):
            del timeout
            return 7

    monkeypatch.setattr(guardian_module.subprocess, "Popen", lambda *args, **kwargs: Child())
    monkeypatch.setattr(guardian_module, "_start_time", lambda pid: 99)
    monkeypatch.setattr(guardian_module.os, "getpgid", lambda pid: pid, raising=False)
    monkeypatch.setattr(guardian_module.os, "getsid", lambda pid: pid, raising=False)
    metadata = tmp_path / "guardian.json"
    assert guardian_module.run(tmp_path / "mihomo", tmp_path / "config", metadata, tmp_path) == 7
    value = json.loads(metadata.read_text(encoding="ascii"))
    assert value["pid"] == 321
    assert value["start_time"] == 99


def test_guardian_stops_child_when_parent_identity_changes(tmp_path, monkeypatch):
    class Child(object):
        pid = 322

        def __init__(self):
            self.waits = 0
            self.killed = False

        def poll(self):
            return None

        def wait(self, timeout=None):
            del timeout
            self.waits += 1
            if self.waits == 1:
                raise guardian_module.subprocess.TimeoutExpired("child", 0.2)
            return 0

    child = Child()
    identity = iter((True, False))
    monkeypatch.setattr(guardian_module.subprocess, "Popen", lambda *args, **kwargs: child)
    monkeypatch.setattr(guardian_module, "_parent_identity_matches", lambda *args: next(identity))
    monkeypatch.setattr(guardian_module, "_start_time", lambda pid: 99)
    monkeypatch.setattr(guardian_module.os, "getpgid", lambda pid: pid, raising=False)
    monkeypatch.setattr(guardian_module.os, "getsid", lambda pid: pid, raising=False)
    terminated = []
    monkeypatch.setattr(guardian_module, "_terminate_child_group", lambda value, hard=False: terminated.append(hard))
    result = guardian_module.run(
        tmp_path / "mihomo", tmp_path / "config", tmp_path / "meta", tmp_path,
        parent_pid=1, parent_start_time="token",
    )
    assert result == 125
    assert terminated == [True]


def test_windows_job_helper_is_inactive_off_windows():
    if os.name == "nt":
        pytest.skip("native Windows Job Object path")
    assert mihomo_module._windows_create_job() is None
    assert not mihomo_module._windows_assign_job(None, None)


def test_mihomo_rejects_invalid_log_lock_and_readiness_settings(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    with pytest.raises(ValueError, match="context-manager"):
        process.set_log_lock(object())
    with pytest.raises(ValueError, match="invalid listener"):
        process.set_readiness_challenge(None, None, "invalid", "127.0.0.1")
    with pytest.raises(ValueError, match="supplied together"):
        process.set_readiness_challenge("user", None, "http", "127.0.0.1")


def test_mihomo_start_reports_guardian_launch_failure(tmp_path, monkeypatch):
    if sys.platform == "darwin":
        monkeypatch.setattr(mihomo_module, "_posix_process_start_time", lambda pid: "test-start")
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")

    def fail_launch(*args, **kwargs):
        raise OSError("spawn failed")

    monkeypatch.setattr(mihomo_module.subprocess, "Popen", fail_launch)
    with pytest.raises(RuntimeSessionError, match="backend launch failed"):
        process.start()
    assert process.process is None
    assert process._start_gate_write is None


def test_mihomo_start_cleans_authorization_gate_after_preexec_failure(tmp_path, monkeypatch):
    if sys.platform == "darwin":
        monkeypatch.setattr(mihomo_module, "_posix_process_start_time", lambda pid: "test-start")
    class FailingPopen(object):
        def __init__(self, *args, **kwargs):
            del args, kwargs
            raise subprocess.SubprocessError("pre-exec prctl failed")

    monkeypatch.setattr(mihomo_module.subprocess, "Popen", FailingPopen)
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    with pytest.raises(RuntimeSessionError, match="backend launch failed"):
        process.start()
    assert process.process is None
    assert process._start_gate_write is None


def test_mihomo_start_authorizes_real_popen_shape_and_drains_child(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX process-group launch shape")
    captured = {}

    class FakePopen(object):
        def __init__(self, arguments, **options):
            captured["arguments"] = arguments
            captured["options"] = options
            self.pid = 12345
            self.stdout = io.BytesIO(b"ready\n")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            del timeout
            return 0

    monkeypatch.setattr(mihomo_module.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(mihomo_module, "_linux_optional_pidfd_open", lambda pid: None)
    monkeypatch.setattr(mihomo_module, "_linux_process_start_time", lambda pid: 1)
    monkeypatch.setattr(mihomo_module, "_posix_process_start_time", lambda pid: 1)
    monkeypatch.setattr(MihomoProcess, "_load_guardian_identity", lambda self, timeout=5.0: None)
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    monkeypatch.setattr(process, "_release_start_gate", lambda: captured.setdefault("authorized", True))
    process.start()
    for thread in process._threads:
        thread.join(1.0)
    assert captured["options"]["start_new_session"] is True
    assert captured["options"]["pass_fds"]
    assert "--start-gate" in captured["arguments"]
    assert process.log_path.read_text(encoding="ascii") == "[mihomo] ready\n"


def test_mihomo_start_rejects_unsafe_existing_log(tmp_path):
    log_path = tmp_path / "log"
    log_path.write_text("old", encoding="ascii")
    if os.name == "posix":
        log_path.chmod(0o644)
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, log_path)
    if os.name == "posix":
        with pytest.raises(RuntimeSessionError, match="unsafe permissions"):
            process.start()


def test_mihomo_private_environment_is_scrubbed_and_bounded(tmp_path):
    values = mihomo_module.build_environment(tmp_path / "bin" / "mihomo", tmp_path)
    assert values["HOME"].startswith(str(tmp_path))
    assert values["TMPDIR"].startswith(str(tmp_path))
    assert values["PATH"] == str(tmp_path / "bin")
    assert values["LANG"] == "C"
    assert values["LC_ALL"] == "C"
    assert values["TZ"] == "UTC"
    assert "HTTP_PROXY" not in values


def test_mihomo_environment_rejects_aliased_private_directory(tmp_path):
    if os.name == "nt":
        pytest.skip("symlink primitive is not available on this Windows runner")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "backend-home").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeSessionError, match="aliased"):
        mihomo_module.build_environment(tmp_path / "bin" / "mihomo", tmp_path)


@pytest.mark.parametrize("value, expected", [("OFF", "silent"), ("WARNING", "warning"), ("debug", "debug")])
def test_mihomo_log_levels_are_normalized(value, expected):
    assert mihomo_module._config_log_level(value) == expected


def test_mihomo_rejects_unknown_log_level():
    with pytest.raises(ValueError, match="unsupported"):
        mihomo_module._config_log_level("trace")


def test_mihomo_wait_ready_rejects_unstarted_or_exited_process(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    with pytest.raises(RuntimeSessionError, match="has not started"):
        process.wait_ready(17777, timeout=0.1)
    process.process = type("Exited", (), {"poll": lambda self: 1})()
    with pytest.raises(RuntimeSessionError, match="exited before readiness"):
        process.wait_ready(17777, timeout=0.1)
    with pytest.raises(RuntimeSessionError, match="deadline exhausted"):
        process.wait_ready(17777, timeout=0)


def test_mihomo_release_start_gate_authorizes_once_and_cancel_is_idempotent(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    read_descriptor, write_descriptor = os.pipe()
    process._start_gate_write = write_descriptor
    process._release_start_gate()
    assert os.read(read_descriptor, 1) == b"\x01"
    os.close(read_descriptor)
    process._release_start_gate()
    process._cancel_start_gate()


def test_mihomo_drain_off_level_does_not_publish_output(tmp_path):
    events = []
    process = MihomoProcess(
        tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log",
        backend_log_level="OFF", log_sink=lambda *event: events.append(event),
    )
    process._drain(io.BytesIO(b"secret\n"))
    assert events == []
    assert not process.log_path.exists()


def test_mihomo_driver_projects_secret_node_and_delegates_lifecycle(tmp_path):
    class Node(object):
        def secret_uri(self):
            return "ss://opaque-secret"

    class Process(object):
        def __init__(self):
            self.started = False
            self.stopped = False

        def start(self):
            self.started = True

        def wait_ready(self, port, timeout=5.0):
            self.ready = (port, timeout)

        def stop(self, timeout=2.0):
            self.stopped = timeout

    created = []
    driver = mihomo_module.MihomoDriver(
        process_factory=lambda *args, **kwargs: created.append(Process()) or created[-1]
    )
    projection = driver.projection(
        tmp_path / "provider", Node(), 17777, "user", "password", listener_protocol="http"
    )
    assert b"ss://opaque-secret" in projection.provider
    assert b"authentication:" in projection.config
    process = driver.create_process(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log", "INFO")
    driver.wait_ready(process, 17777, timeout=0.25)
    driver.stop(process, timeout=0.5)
    assert process.ready == (17777, 5.0)
    assert process.stopped == 2.0


def test_mihomo_stop_terminates_authorized_group_and_cleans_metadata(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX process-group termination")
    class Child(object):
        pid = 456

        def __init__(self):
            self.calls = 0

        def poll(self):
            return None if self.calls == 0 else 0

        def wait(self, timeout=None):
            del timeout
            self.calls += 1
            return 0

    child = Child()
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    process.process = child
    process._backend_pgid = 456
    process._backend_sid = 456
    process.backend_pid = 456
    process._backend_start_time = 1
    metadata = process._guardian_metadata_path
    metadata.write_text("{}", encoding="ascii")
    signals = []
    monkeypatch.setattr(mihomo_module, "_linux_process_identity_matches", lambda *args: True)
    monkeypatch.setattr(mihomo_module, "_linux_process_group", lambda pid: 456)
    monkeypatch.setattr(mihomo_module, "_linux_process_session", lambda pid: 456)
    monkeypatch.setattr(mihomo_module, "_linux_process_group_members", lambda *args: ())
    monkeypatch.setattr(mihomo_module.os, "killpg", lambda group, signal: signals.append((group, signal)))
    process.stop(timeout=0.05)
    assert signals and signals[0][0] == 456
    assert not metadata.exists()


def test_mihomo_stop_is_safe_before_start(tmp_path):
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log")
    process.stop(timeout=0.01)
    assert process.process is None


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
