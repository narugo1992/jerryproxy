import hashlib
import io
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import jerryproxy.selfcheck as selfcheck_module
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.errors import BackendCatalogError, IntegrityError, JerryProxyBusyError, UnsupportedPlatformError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock, filelock_status
from jerryproxy.selfcheck import CheckResult, ansi_color_enabled, build_checks, run_checks, run_self_check
from test.selfcheck.fakes import (
    FakeRelayResponse,
    RelaySessionFactory,
    relay_payload,
    verified_relay_session_factory,
)


def _write_maximum_relay_diagnostic(unused_profile, result_path):
    diagnostic = "relay child diagnostic start\n%s\nrelay child diagnostic end" % (
        "x" * (64 * 1024 - 128)
    )
    selfcheck_module.atomic_write_json(
        Path(result_path),
        {
            "level": "ERR",
            "detail": "maximum diagnostic from child",
            "diagnostics": [diagnostic],
        },
    )


def _write_partial_relay_result_and_stall(unused_profile, result_path):
    Path(result_path).write_text('{"level":', encoding="utf-8")
    time.sleep(10.0)


def _crash_with_sensitive_relay_diagnostic(unused_profile, result_path):
    del result_path
    raise RuntimeError(
        "https://user:pass@example.com/?token=secret "
        "Authorization: Bearer ghp_SUPERSECRET "
        "uuid=123e4567-e89b-12d3-a456-426614174000 "
        "private key: cHJpdmF0ZQ=="
    )


def _crash_with_sensitive_recovery_diagnostic(error_log):
    del error_log
    raise RuntimeError(
        "https://user:pass@example.com/?token=secret "
        "Authorization: Bearer ghp_SUPERSECRET "
        "uuid=123e4567-e89b-12d3-a456-426614174000 "
        "private key: cHJpdmF0ZQ=="
    )


def _write_start_gate_sentinel(path):
    Path(path).write_text("business code ran", encoding="utf-8")


def _fake_process_context(process_factory):
    events = []

    def event_factory():
        event = threading.Event()
        events.append(event)
        if len(events) == 3:
            event.set()
        return event

    return SimpleNamespace(
        Process=process_factory,
        Event=event_factory,
        Value=lambda typecode, value: SimpleNamespace(value=value),
    )


class _FakeProcessContextBase(object):
    def Event(self):
        count = getattr(self, "_event_count", 0) + 1
        self._event_count = count
        event = threading.Event()
        if count == 3:
            event.set()
        return event

    @staticmethod
    def Value(typecode, value):
        del typecode
        return SimpleNamespace(value=value)


def test_self_check_validates_an_empty_private_home(tmp_path, monkeypatch):
    lines = []
    relay_factory = verified_relay_session_factory(monkeypatch)

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    status = filelock_status()
    expected = (
        "Summary: 19 OK, 0 WARN, 0 SKIP, 0 FAIL, 0 ERR"
        if status.level == "OK"
        else "Summary: 18 OK, 1 WARN, 0 SKIP, 0 FAIL, 0 ERR"
    )
    assert expected in lines
    assert lines[-1] in ("Self-check PASSED", "Self-check PASSED with warnings")
    assert lines[1].startswith("Runtime: Python ")
    assert "; JerryProxy " in lines[1]
    assert lines[2].startswith("System: ")
    assert not list(tmp_path.glob(".self-check-*"))
    for name in ("active", "backends", "bin", "downloads", "locks", "logs", "providers", "runtimes"):
        assert (tmp_path / name).is_dir()


def test_check_runner_renders_all_five_levels_and_only_fails_on_fail_or_error():
    visited = []
    lines = []

    def first():
        visited.append("first")
        return CheckResult.ok("ready")

    def warning():
        visited.append("warning")
        return CheckResult.warn("legacy dependency")

    def skipped():
        visited.append("skipped")
        return CheckResult.skip("not applicable")

    def failure():
        visited.append("failure")
        return CheckResult.fail("requirement unmet")

    def error():
        visited.append("error")
        return CheckResult.err("OSError: read-only state directory")

    exit_code = run_checks(
        (
            ("first", first),
            ("compatibility", warning),
            ("platform-only", skipped),
            ("policy", failure),
            ("writable state", error),
        ),
        output=lines.append,
    )

    assert exit_code == 1
    assert visited == ["first", "warning", "skipped", "failure", "error"]
    assert "[2/5] compatibility: WARN - legacy dependency" in lines
    assert "[3/5] platform-only: SKIP - not applicable" in lines
    assert "[4/5] policy: FAIL - requirement unmet" in lines
    assert "[5/5] writable state: ERR - OSError: read-only state directory" in lines
    assert "Summary: 1 OK, 1 WARN, 1 SKIP, 1 FAIL, 1 ERR" in lines
    assert lines[-1] == "Self-check FAILED"


def test_check_runner_warning_keeps_zero_exit_code():
    lines = []

    exit_code = run_checks((("compatibility", lambda: CheckResult.warn("upgrade recommended")),), lines.append)

    assert exit_code == 0
    assert "Summary: 0 OK, 1 WARN, 0 SKIP, 0 FAIL, 0 ERR" in lines
    assert lines[-1] == "Self-check PASSED with warnings"


def test_check_runner_skip_is_cyan_and_keeps_zero_exit_code():
    lines = []

    exit_code = run_checks(
        (("platform-only", lambda: CheckResult.skip("not applicable")),),
        lines.append,
        color=True,
    )

    assert exit_code == 0
    assert "\033[1;36mSKIP\033[0m" in lines[0]
    assert "\033[1;36m0 SKIP\033[0m" not in lines[-2]
    assert "\033[1;36m1 SKIP\033[0m" in lines[-2]
    assert lines[-1] == "\033[1;36mSelf-check PASSED with skips\033[0m"


def test_check_runner_renders_multiline_error_diagnostics():
    lines = []

    exit_code = run_checks(
        (("crash", lambda: CheckResult.err("RuntimeError: broken", ("Traceback line\nfinal frame",))),),
        lines.append,
    )

    assert exit_code == 1
    assert lines[0] == "[1/1] crash: ERR - RuntimeError: broken"
    assert lines[1:3] == ["    Traceback line", "    final frame"]


def test_catalog_check_keeps_an_empty_exception_diagnosable(tmp_path, monkeypatch):
    def fail_without_message():
        raise OSError()

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_without_message)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["packaged backend catalog"]()

    assert result.level == "ERR"
    assert result.detail == "OSError: OSError()"
    assert result.diagnostics and "OSError" in result.diagnostics[0]


def test_check_runner_redacts_sensitive_error_details_and_diagnostics():
    lines = []
    secrets = (
        "https://alice:secret@example.com/provider?token=query-secret#fragment-secret",
        "vless://123e4567-e89b-f2d3-c456-426614174000@example.com:443?security=tls#private-node",
        "123e4567-e89b-f2d3-c456-426614174000",
        "password=hunter2",
        "public_key=QUJDREVGR0g=",
        "short_id=deadbeef",
        "public key: QUJDREVGR0g=",
        "private key: cHJpdmF0ZQ==",
        "API key: secret-value",
        "short id: deadbeef",
        "Authorization: Bearer ghp_SUPERSECRET",
    )
    exposed = " ".join(secrets)

    exit_code = run_checks(
        (("crash", lambda: CheckResult.err(exposed, ("Traceback: %s" % exposed,))),),
        lines.append,
    )

    rendered = "\n".join(lines)
    assert exit_code == 1
    assert "[REDACTED" in rendered
    assert all(secret not in rendered for secret in secrets)
    assert "query-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "hunter2" not in rendered
    assert "QUJDREVGR0g=" not in rendered
    assert "cHJpdmF0ZQ==" not in rendered
    assert "secret-value" not in rendered
    assert "deadbeef" not in rendered
    assert "ghp_SUPERSECRET" not in rendered


def test_error_result_redacts_exception_message_and_traceback():
    secret = "https://alice:secret@example.com/provider?token=query-secret#fragment-secret"

    try:
        raise RuntimeError("request failed for %s password=hunter2" % secret)
    except RuntimeError as error:
        result = selfcheck_module._error_result(error)

    rendered = "%s\n%s" % (result.detail, "\n".join(result.diagnostics))
    assert result.level == "ERR"
    assert "[REDACTED" in rendered
    assert "alice" not in rendered
    assert "query-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "hunter2" not in rendered


def test_check_runner_uses_ansi_status_colors_when_enabled():
    lines = []

    exit_code = run_checks(
        (("ready", lambda: CheckResult.ok("available")),),
        output=lines.append,
        color=True,
    )

    assert exit_code == 0
    assert "\033[1;36m[1/1] ready\033[0m" in lines[0]
    assert "\033[1;32mOK\033[0m" in lines[0]
    assert lines[-1] == "\033[1;32mSelf-check PASSED\033[0m"


def test_check_runner_colors_warning_failure_and_error_levels():
    lines = []

    exit_code = run_checks(
        (
            ("warning", lambda: CheckResult.warn("legacy")),
            ("failure", lambda: CheckResult.fail("unmet")),
            ("error", lambda: CheckResult.err("unavailable")),
        ),
        output=lines.append,
        color=True,
    )

    assert exit_code == 1
    assert "\033[1;33mWARN\033[0m" in lines[0]
    assert "\033[1;31mFAIL\033[0m" in lines[1]
    assert "\033[1;31mERR\033[0m" in lines[2]


def test_color_detection_honors_environment_and_explicit_override(monkeypatch):
    class Terminal(object):
        def isatty(self):
            return True

    terminal = Terminal()
    monkeypatch.setenv("NO_COLOR", "1")
    assert ansi_color_enabled(terminal) is False
    assert ansi_color_enabled(terminal, requested=True) is True

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ansi_color_enabled(object()) is True


def test_color_detection_falls_back_when_stream_has_no_usable_tty(monkeypatch):
    class BrokenTerminal(object):
        def isatty(self):
            raise OSError("terminal unavailable")

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert ansi_color_enabled(object()) is False
    assert ansi_color_enabled(BrokenTerminal()) is False


def test_self_check_reports_corrupt_active_inventory_without_stopping_other_checks(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    (paths.active / "mihomo.json").write_text("{not-json", encoding="ascii")
    lines = []

    exit_code = run_self_check(
        paths,
        output=lines.append,
        relay_session_factory=verified_relay_session_factory(monkeypatch),
    )

    assert exit_code == 1
    assert any("backend inventory: FAIL" in line for line in lines)
    assert any("IntegrityError" in line for line in lines)
    assert lines[-1] == "Self-check FAILED"


def test_backend_inventory_check_keeps_unexpected_internal_failures_as_errors(tmp_path, monkeypatch):
    class BrokenManager(object):
        def __init__(self, paths, platform_info=None):
            self.paths = paths
            self.platform_info = platform_info

        def inventory(self):
            raise RuntimeError("unexpected recovery failure")

    monkeypatch.setattr(selfcheck_module, "BackendManager", BrokenManager)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["backend inventory"]()

    assert result.level == "ERR"
    assert result.detail == "RuntimeError: unexpected recovery failure"
    assert result.diagnostics and "unexpected recovery failure" in result.diagnostics[0]


def test_recovery_checks_use_isolated_homes_and_exercise_real_hard_exit_recovery(tmp_path):
    paths = JerryProxyPaths(tmp_path / "user-home")
    checks = dict(build_checks(paths))

    results = [
        checks[name]()
        for name in (
            "recovery install rollback",
            "recovery activation rollback",
            "recovery activation rollforward",
            "recovery removal rollback",
            "recovery removal rollforward",
        )
    ]

    assert [result.level for result in results] == ["OK"] * 5
    assert not paths.root.exists()


def test_complete_recovery_matrix_works_with_spawn(tmp_path, monkeypatch):
    if "spawn" not in selfcheck_module.multiprocessing.get_all_start_methods():
        pytest.skip("spawn start method is unavailable")
    spawn_context = selfcheck_module.multiprocessing.get_context("spawn")
    monkeypatch.setattr(
        selfcheck_module,
        "_preferred_process_context",
        lambda: ("spawn", spawn_context),
    )
    checks = dict(build_checks(JerryProxyPaths(tmp_path / "configured-home")))

    results = [
        checks[name]()
        for name in (
            "recovery install rollback",
            "recovery activation rollback",
            "recovery activation rollforward",
            "recovery removal rollback",
            "recovery removal rollforward",
        )
    ]

    assert [result.level for result in results] == ["OK"] * 5
    assert not (tmp_path / "configured-home").exists()


def test_recovery_checks_skip_without_a_compatible_backend_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(
        selfcheck_module,
        "detect_platform",
        lambda: PlatformInfo("unsupported", "architecture"),
    )

    checks = dict(build_checks(JerryProxyPaths(tmp_path)))
    results = [
        checks[name]()
        for name in (
            "isolated backend lifecycle",
            "recovery install rollback",
            "recovery activation rollback",
            "recovery activation rollforward",
            "recovery removal rollback",
            "recovery removal rollforward",
        )
    ]

    assert [result.level for result in results] == ["SKIP"] * 6
    assert all("no " in result.detail and "fixture asset shape" in result.detail for result in results)


def test_install_recovery_check_fails_when_recovery_evidence_is_retained(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_recovery_artifacts", lambda paths: (paths.runtimes / "retained",))

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result == CheckResult.fail("hard-exit install rollback retained recovery evidence")


@pytest.mark.parametrize(
    "installed, active",
    (
        ((object(),), ()),
        ((), (object(),)),
    ),
)
def test_install_recovery_check_fails_when_public_backend_state_is_retained(
    tmp_path,
    monkeypatch,
    installed,
    active,
):
    manager = SimpleNamespace(inventory=lambda: SimpleNamespace(installed=installed, active=active))
    monkeypatch.setattr(
        selfcheck_module,
        "_recovery_platform",
        lambda: (PlatformInfo("linux", "amd64"), None, "linux-amd64"),
    )
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_probe_manager", lambda paths, platform_info: manager)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result == CheckResult.fail("hard-exit install rollback retained public backend state")


def test_activation_recovery_check_fails_when_recovery_evidence_is_retained(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_recovery_artifacts", lambda paths: (paths.runtimes / "retained",))

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery activation rollback"]()

    assert result == CheckResult.fail("activation rollback recovery did not converge cleanly")


def test_recovery_check_maps_integrity_failures_to_fail(tmp_path, monkeypatch):
    def fail_platform():
        raise IntegrityError("simulated retained recovery evidence")

    monkeypatch.setattr(selfcheck_module, "_recovery_platform", fail_platform)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result == CheckResult.fail("IntegrityError: simulated retained recovery evidence")


def test_recovery_check_maps_operational_failures_to_error_with_traceback(tmp_path, monkeypatch):
    def fail_platform():
        raise OSError("simulated temporary storage failure")

    monkeypatch.setattr(selfcheck_module, "_recovery_platform", fail_platform)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result.level == "ERR"
    assert result.detail == "OSError: simulated temporary storage failure"
    assert result.diagnostics and "simulated temporary storage failure" in result.diagnostics[0]


def test_recovery_child_runner_skips_when_no_supported_start_method_is_available(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ())

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.skip("no supported multiprocessing start method is available")


def test_recovery_child_runner_skips_when_process_start_is_rejected(tmp_path, monkeypatch):
    class RejectedProcess(object):
        def start(self):
            raise RuntimeError("spawn disabled")

    context = _fake_process_context(lambda **kwargs: RejectedProcess())
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.skip("spawn hard-exit probe unavailable: RuntimeError: spawn disabled")


def test_recovery_child_runner_bounds_a_stalled_process_start(tmp_path, monkeypatch):
    release = threading.Event()
    finished = threading.Event()
    captured = {}

    class StalledProcess(object):
        def start(self):
            release.wait(5.0)
            finished.set()

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            captured.update(kwargs)
            return StalledProcess()

    monkeypatch.setattr(selfcheck_module, "_RECOVERY_PROCESS_TIMEOUT", 0.1)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())
    started = time.monotonic()
    try:
        result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")
    finally:
        release.set()
        finished.wait(1.0)

    assert time.monotonic() - started < 1.0
    assert result == CheckResult.err("hard-exit recovery child startup exceeded the 0.1-second timeout")
    assert captured["daemon"] is True
    assert captured["args"][3].is_set() is False
    assert captured["args"][4].is_set() is True


def test_recovery_child_runner_reports_missing_start_supervisor_outcome(tmp_path, monkeypatch):
    class OutcomeLessThread(object):
        def __init__(self, target, name, daemon):
            del target, name, daemon

        def start(self):
            pass

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return False

    class Process(object):
        def start(self):
            pass

    context = _fake_process_context(lambda **kwargs: Process())
    monkeypatch.setattr(selfcheck_module.threading, "Thread", OutcomeLessThread)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err(
        "hard-exit recovery child startup supervision failed: RuntimeError: "
        "process start thread returned no outcome"
    )


def test_recovery_child_runner_skips_when_start_supervisor_thread_is_unavailable(tmp_path, monkeypatch):
    class RejectedThread(object):
        def __init__(self, target, name, daemon):
            del target, name, daemon

        def start(self):
            raise RuntimeError("thread creation denied")

        def join(self, timeout):
            del timeout

    context = _fake_process_context(lambda **kwargs: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(selfcheck_module.threading, "Thread", RejectedThread)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.skip(
        "spawn hard-exit probe unavailable: RuntimeError: thread creation denied"
    )


def test_recovery_child_runner_does_not_authorize_a_child_that_exits_before_ready(tmp_path, monkeypatch):
    events = []

    class ExitedProcess(object):
        exitcode = selfcheck_module._CHILD_STDERR_CAPTURE_ERROR

        def start(self):
            pass

        def is_alive(self):
            return False

        def join(self, timeout):
            del timeout

    class Context(object):
        def Event(self):
            event = threading.Event()
            events.append(event)
            return event

        def Value(self, typecode, value):
            del typecode
            return SimpleNamespace(value=value)

        def Process(self, **kwargs):
            return ExitedProcess()

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err("hard-exit recovery child returned 96 instead of 71")
    assert events[0].is_set() is False
    assert events[1].is_set() is True


def test_recovery_child_runner_reports_ready_event_observation_failure(tmp_path, monkeypatch):
    events = []

    class UnreadableReadyEvent(threading.Event):
        def wait(self, timeout=None):
            del timeout
            raise OSError("ready event unavailable")

    class Context(object):
        def Event(self):
            event = UnreadableReadyEvent() if len(events) == 2 else threading.Event()
            events.append(event)
            return event

        def Value(self, typecode, value):
            del typecode
            return SimpleNamespace(value=value)

        def Process(self, **kwargs):
            return SimpleNamespace(start=lambda: None)

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err(
        "hard-exit recovery child startup supervision failed: OSError: ready event unavailable"
    )
    assert events[1].is_set() is True


def test_recovery_child_runner_cancels_when_start_authorization_cannot_be_published(tmp_path, monkeypatch):
    events = []

    class AuthorizationEvent(threading.Event):
        def set(self):
            raise OSError("authorization event unavailable")

    class Context(object):
        def Event(self):
            event = AuthorizationEvent() if not events else threading.Event()
            events.append(event)
            if len(events) == 3:
                event.set()
            return event

        def Value(self, typecode, value):
            del typecode
            return SimpleNamespace(value=value)

        def Process(self, **kwargs):
            return SimpleNamespace(start=lambda: None)

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err(
        "hard-exit recovery child startup supervision failed: OSError: authorization event unavailable"
    )
    assert events[1].is_set() is True


def test_recovery_child_runner_skips_when_process_construction_is_rejected(tmp_path, monkeypatch):
    def reject_process(**kwargs):
        del kwargs
        raise OSError("process construction denied")

    context = _fake_process_context(reject_process)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.skip(
        "spawn hard-exit probe unavailable: OSError: process construction denied"
    )


def test_cancelled_spawn_child_never_enters_business_code(tmp_path):
    if "spawn" not in selfcheck_module.multiprocessing.get_all_start_methods():
        pytest.skip("spawn start method is unavailable")
    context = selfcheck_module.multiprocessing.get_context("spawn")
    start_allowed = context.Event()
    start_cancelled = context.Event()
    start_ready = context.Event()
    start_budget = context.Value("d", 10.0)
    start_cancelled.set()
    sentinel = tmp_path / "business-ran"
    process = context.Process(
        target=selfcheck_module._captured_child_entry,
        args=(
            _write_start_gate_sentinel,
            (str(sentinel),),
            str(tmp_path / "child.stderr"),
            start_allowed,
            start_cancelled,
            start_ready,
            start_budget,
        ),
    )

    process.start()
    process.join(10.0)

    assert process.exitcode == selfcheck_module._CHILD_START_CANCELLED
    assert not sentinel.exists()


def test_spawn_child_rejects_authorization_after_its_relative_budget_expires(tmp_path):
    if "spawn" not in selfcheck_module.multiprocessing.get_all_start_methods():
        pytest.skip("spawn start method is unavailable")
    context = selfcheck_module.multiprocessing.get_context("spawn")
    start_allowed = context.Event()
    start_cancelled = context.Event()
    start_ready = context.Event()
    start_budget = context.Value("d", 0.05)
    sentinel = tmp_path / "business-ran"
    process = context.Process(
        target=selfcheck_module._captured_child_entry,
        args=(
            _write_start_gate_sentinel,
            (str(sentinel),),
            str(tmp_path / "child.stderr"),
            start_allowed,
            start_cancelled,
            start_ready,
            start_budget,
        ),
    )

    process.start()
    assert start_ready.wait(10.0) is True
    time.sleep(0.1)
    start_allowed.set()
    process.join(10.0)

    assert process.exitcode == selfcheck_module._CHILD_START_CANCELLED
    assert not sentinel.exists()


def test_start_supervisor_cancels_a_process_that_completes_at_the_deadline(monkeypatch):
    class BoundaryThread(object):
        def __init__(self, target, name, daemon):
            del name, daemon
            self.target = target

        def start(self):
            pass

        def join(self, timeout):
            assert timeout == 0.0
            self.target()

        def is_alive(self):
            return False

    start_allowed = threading.Event()
    start_cancelled = threading.Event()
    start_ready = threading.Event()
    start_budget = SimpleNamespace(value=0.0)
    process = SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(selfcheck_module.threading, "Thread", BoundaryThread)
    monkeypatch.setattr(selfcheck_module.time, "monotonic", lambda: 10.0)

    status, error = selfcheck_module._start_process(
        process,
        start_allowed,
        start_cancelled,
        start_ready,
        start_budget,
        deadline=10.0,
    )

    assert status == "timeout"
    assert error is None
    assert start_allowed.is_set() is False
    assert start_cancelled.is_set() is True


@pytest.mark.parametrize("ready_after_wait", [False, True])
def test_start_supervisor_cancels_when_deadline_expires_around_child_ready(monkeypatch, ready_after_wait):
    class SynchronousThread(object):
        def __init__(self, target, name, daemon):
            del name, daemon
            self.target = target

        def start(self):
            pass

        def join(self, timeout):
            assert timeout == 5.0
            self.target()

        def is_alive(self):
            return False

    class ReadyEvent(threading.Event):
        def wait(self, timeout=None):
            del timeout
            if ready_after_wait:
                self.set()
                return True
            return False

    clock_values = iter((0.0, 0.0, 0.0, 5.0))
    start_allowed = threading.Event()
    start_cancelled = threading.Event()
    start_ready = ReadyEvent()
    start_budget = SimpleNamespace(value=0.0)
    process = SimpleNamespace(start=lambda: None, is_alive=lambda: True)
    monkeypatch.setattr(selfcheck_module.threading, "Thread", SynchronousThread)
    monkeypatch.setattr(selfcheck_module.time, "monotonic", lambda: next(clock_values))

    status, error = selfcheck_module._start_process(
        process,
        start_allowed,
        start_cancelled,
        start_ready,
        start_budget,
        deadline=5.0,
    )

    assert status == "timeout"
    assert error is None
    assert start_allowed.is_set() is False
    assert start_cancelled.is_set() is True


def test_start_supervisor_cancels_if_deadline_expires_immediately_after_authorization(monkeypatch):
    class SynchronousThread(object):
        def __init__(self, target, name, daemon):
            del name, daemon
            self.target = target

        def start(self):
            pass

        def join(self, timeout):
            assert timeout == 5.0
            self.target()

        def is_alive(self):
            return False

    clock_values = iter((0.0, 0.0, 0.0, 0.0, 5.0))
    start_allowed = threading.Event()
    start_cancelled = threading.Event()
    start_ready = threading.Event()
    start_ready.set()
    start_budget = SimpleNamespace(value=0.0)
    process = SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(selfcheck_module.threading, "Thread", SynchronousThread)
    monkeypatch.setattr(selfcheck_module.time, "monotonic", lambda: next(clock_values))

    status, error = selfcheck_module._start_process(
        process,
        start_allowed,
        start_cancelled,
        start_ready,
        start_budget,
        deadline=5.0,
    )

    assert status == "timeout"
    assert error is None
    assert start_allowed.is_set() is True
    assert start_cancelled.is_set() is True
    assert start_budget.value == 5.0


def test_recovery_child_runner_terminates_a_timeout(tmp_path, monkeypatch):
    class TimedOutProcess(object):
        exitcode = None

        def __init__(self):
            self.joins = []
            self.terminated = False

        def start(self):
            pass

        def join(self, timeout):
            self.joins.append(timeout)

        def is_alive(self):
            return not self.terminated

        def terminate(self):
            self.terminated = True

    process = TimedOutProcess()
    context = _fake_process_context(lambda **kwargs: process)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err("hard-exit recovery child exceeded the 30-second timeout")
    assert process.terminated is True
    assert 0.0 < process.joins[0] <= 30.0
    assert process.joins[1:] == [5.0]


def test_recovery_child_runner_kills_a_child_that_ignores_termination(tmp_path, monkeypatch):
    class StubbornProcess(object):
        exitcode = None

        def __init__(self):
            self.joins = []
            self.terminated = False
            self.killed = False

        def start(self):
            pass

        def join(self, timeout):
            self.joins.append(timeout)

        def is_alive(self):
            return not self.killed

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    process = StubbornProcess()
    context = _fake_process_context(lambda **kwargs: process)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err("hard-exit recovery child exceeded the 30-second timeout")
    assert process.terminated is True
    assert process.killed is True
    assert 0.0 < process.joins[0] <= 30.0
    assert process.joins[1:] == [5.0, 5.0]


def test_recovery_child_runner_reports_a_child_that_survives_kill(tmp_path, monkeypatch):
    class UnstoppableProcess(object):
        exitcode = None

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return True

        def terminate(self):
            pass

        def kill(self):
            pass

    context = _fake_process_context(lambda **kwargs: UnstoppableProcess())
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result == CheckResult.err("timed-out hard-exit recovery child remained alive after kill")


def test_recovery_child_runner_reports_rejected_termination(tmp_path, monkeypatch):
    class UnterminableProcess(object):
        exitcode = None

        def __init__(self):
            self.killed = False

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return not self.killed

        def terminate(self):
            raise OSError("termination denied")

        def kill(self):
            self.killed = True

    process = UnterminableProcess()
    context = _fake_process_context(lambda **kwargs: process)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result.level == "ERR"
    assert result.detail == "hard-exit recovery child exceeded the 30-second timeout"
    assert process.killed is True
    assert result.diagnostics and "terminate failed: OSError: termination denied" in result.diagnostics[0]


def test_recovery_child_runner_kills_after_join_failures(tmp_path, monkeypatch):
    class UnjoinableProcess(object):
        exitcode = None

        def __init__(self):
            self.killed = False
            self.kill_calls = 0

        def start(self):
            pass

        def join(self, timeout):
            del timeout
            raise OSError("join denied")

        def is_alive(self):
            return not self.killed

        def terminate(self):
            pass

        def kill(self):
            self.kill_calls += 1
            self.killed = True

    process = UnjoinableProcess()
    context = _fake_process_context(lambda **kwargs: process)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result.level == "ERR"
    assert result.detail == "hard-exit recovery child supervision failed"
    assert process.kill_calls == 1
    assert result.diagnostics and "join failed: OSError: join denied" in result.diagnostics[0]


def test_recovery_child_runner_treats_unknown_liveness_as_alive(tmp_path, monkeypatch):
    class UnknownLivenessProcess(object):
        exitcode = None

        def __init__(self):
            self.liveness_calls = 0
            self.killed = False

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            self.liveness_calls += 1
            if self.liveness_calls == 1:
                raise OSError("process state unavailable")
            return not self.killed

        def terminate(self):
            pass

        def kill(self):
            self.killed = True

    process = UnknownLivenessProcess()
    context = _fake_process_context(lambda **kwargs: process)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, tmp_path / "error.log")

    assert result.level == "ERR"
    assert result.detail == "hard-exit recovery child supervision failed"
    assert process.killed is True
    assert result.diagnostics and "liveness check failed: OSError: process state unavailable" in result.diagnostics[0]


def test_recovery_child_runner_reports_abnormal_exit_diagnostics(tmp_path, monkeypatch):
    class FailedProcess(object):
        exitcode = 90

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return False

    error_log = tmp_path / "error.log"
    error_log.write_text("child traceback\nfinal frame", encoding="utf-8")
    context = _fake_process_context(lambda **kwargs: FailedProcess())
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, error_log)

    assert result == CheckResult.err(
        "hard-exit recovery child returned 90 instead of 71",
        ("child traceback\nfinal frame",),
    )


def test_recovery_child_runner_redacts_abnormal_exit_diagnostics(tmp_path, monkeypatch):
    class FailedProcess(object):
        exitcode = 90

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return False

    secret_log = (
        "https://alice:secret@example.com/provider?token=query-secret#fragment-secret\n"
        "uuid=123e4567-e89b-f2d3-c456-426614174000 password=hunter2 "
        "public_key=QUJDREVGR0g= short_id=deadbeef\n"
        "public key: QUJDREVGR0g= private key: cHJpdmF0ZQ== API key: secret-value\n"
        "short id: deadbeef Authorization: Bearer ghp_SUPERSECRET"
    )
    error_log = tmp_path / "error.log"
    error_log.write_text(secret_log, encoding="utf-8")
    context = _fake_process_context(lambda **kwargs: FailedProcess())
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, error_log)

    rendered = "\n".join(result.diagnostics)
    assert result.level == "ERR"
    assert "[REDACTED" in rendered
    assert "query-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "123e4567-e89b-f2d3-c456-426614174000" not in rendered
    assert "hunter2" not in rendered
    assert "QUJDREVGR0g=" not in rendered
    assert "cHJpdmF0ZQ==" not in rendered
    assert "secret-value" not in rendered
    assert "deadbeef" not in rendered
    assert "ghp_SUPERSECRET" not in rendered


def test_recovery_child_runner_reports_unreadable_diagnostics(tmp_path, monkeypatch):
    class FailedProcess(object):
        exitcode = 90

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return False

    error_log = tmp_path / "error.log"
    error_log.write_bytes(b"not UTF-8: \xff")
    context = _fake_process_context(lambda **kwargs: FailedProcess())
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._run_recovery_child(lambda: None, (), 71, error_log)

    assert result.level == "ERR"
    assert result.diagnostics == ("not UTF-8: �",)


def test_bounded_child_stderr_caps_writes_and_exposes_text_stream_metadata():
    stream = io.BytesIO()
    writer = selfcheck_module._BoundedChildStderr(stream)
    oversized = "x" * (selfcheck_module._MAXIMUM_DIAGNOSTIC_CHARACTERS + 16)

    assert writer.encoding == "utf-8"
    assert writer.isatty() is False
    assert writer.write(oversized + "\n") == len(oversized) + 1
    assert writer.write("discarded") == len("discarded")
    writer.flush()
    writer.finish()

    assert stream.getvalue() == b"x" * selfcheck_module._MAXIMUM_DIAGNOSTIC_CHARACTERS


def test_bounded_child_stderr_redacts_split_secrets_before_persistence():
    stream = io.BytesIO()
    writer = selfcheck_module._BoundedChildStderr(stream)

    writer.write("token=SUPER")
    assert stream.getvalue() == b""
    writer.write("SECRET https://user:pass@exam")
    writer.write("ple.com/?key=value\n")
    writer.write("-----BEGIN PRIVATE KEY-----\n")
    writer.write("cHJpdmF0ZQ==\n")
    writer.write("-----END PRIVATE KEY-----\n")
    writer.finish()
    captured = stream.getvalue().decode("utf-8")

    assert "[REDACTED" in captured
    assert "SUPERSECRET" not in captured
    assert "user:pass" not in captured
    assert "key=value" not in captured
    assert "cHJpdmF0ZQ==" not in captured


def test_bounded_child_stderr_discards_an_oversized_split_line_and_resumes_at_newline():
    stream = io.BytesIO()
    writer = selfcheck_module._BoundedChildStderr(stream)

    oversized = "x" * (selfcheck_module._MAXIMUM_DIAGNOSTIC_INPUT_CHARACTERS + 1)
    assert writer.write(oversized) == len(oversized)
    assert writer.write("still-discarded") == len("still-discarded")
    writer.write("end-of-line\ntoken=SUPERSECRET\n")
    writer.write("tail")
    writer.finish()
    captured = stream.getvalue().decode("utf-8")

    assert captured.startswith("[child stderr line exceeded capture limit]\n")
    assert "still-discarded" not in captured
    assert "SUPERSECRET" not in captured
    assert captured.endswith("tail")


def test_child_diagnostic_reader_handles_empty_oversized_and_unreadable_logs(tmp_path):
    diagnostic = tmp_path / "diagnostic.log"
    diagnostic.write_bytes(b"")
    assert selfcheck_module._read_child_diagnostic(diagnostic) == ()

    diagnostic.write_bytes(b"x" * (selfcheck_module._MAXIMUM_DIAGNOSTIC_CHARACTERS + 1))
    oversized = selfcheck_module._read_child_diagnostic(diagnostic)
    assert len(oversized[0]) <= selfcheck_module._MAXIMUM_DIAGNOSTIC_CHARACTERS
    assert oversized[0].endswith("[diagnostic truncated]")

    unreadable = selfcheck_module._read_child_diagnostic(tmp_path)
    assert unreadable and unreadable[0].startswith("Unable to read child diagnostic:")


def test_recovery_child_runner_captures_bounds_and_redacts_unexpected_crashes(tmp_path, capfd):
    error_log = tmp_path / "error.log"

    result = selfcheck_module._run_recovery_child(
        _crash_with_sensitive_recovery_diagnostic,
        (),
        71,
        error_log,
    )
    lines = []
    exit_code = run_checks((("recovery crash", lambda: result),), lines.append)
    captured = capfd.readouterr()
    rendered = "\n".join(lines) + captured.out + captured.err

    assert exit_code == 1
    assert result.level == "ERR"
    assert result.diagnostics and "Traceback" in result.diagnostics[0]
    assert "[REDACTED" in rendered
    assert "user:pass" not in rendered
    assert "ghp_SUPERSECRET" not in rendered
    assert "123e4567-e89b-12d3-a456-426614174000" not in rendered
    assert "cHJpdmF0ZQ==" not in rendered


def test_recovery_checks_propagate_spawn_prerequisite_skips(tmp_path, monkeypatch):
    skipped = CheckResult.skip("spawn unavailable")
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: skipped)
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))

    results = [
        checks["recovery install rollback"](),
        checks["recovery activation rollback"](),
        checks["recovery removal rollback"](),
    ]

    assert results == [skipped, skipped, skipped]


def test_activation_rollforward_check_detects_wrong_recovered_version(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery activation rollforward"]()

    assert result == CheckResult.fail("activation rollforward recovery selected the wrong version")


def test_removal_rollforward_check_detects_undisposed_public_state(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery removal rollforward"]()

    assert result == CheckResult.fail("committed removal recovery did not dispose public state")


def test_removal_recovery_check_detects_retained_transaction_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_recovery_artifacts", lambda paths: (paths.runtimes / "retained",))

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery removal rollback"]()

    assert result == CheckResult.fail("removal rollback recovery retained transaction evidence")


@pytest.mark.parametrize(
    "check_name",
    (
        "isolated backend lifecycle",
        "recovery activation rollback",
        "recovery removal rollback",
    ),
)
def test_isolated_business_checks_report_platform_setup_errors(tmp_path, monkeypatch, check_name):
    def fail_platform():
        raise OSError("temporary platform probe failure")

    monkeypatch.setattr(selfcheck_module, "_recovery_platform", fail_platform)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))[check_name]()

    assert result.level == "ERR"
    assert result.detail == "OSError: temporary platform probe failure"
    assert result.diagnostics and "temporary platform probe failure" in result.diagnostics[0]


def test_runtime_check_reports_old_python_and_missing_package_version(tmp_path, monkeypatch):
    runtime_check = dict(build_checks(JerryProxyPaths(tmp_path)))["Python runtime"]

    monkeypatch.setattr(selfcheck_module.sys, "version_info", (3, 6))
    assert runtime_check() == CheckResult.fail("Python 3.7 or newer is required")

    monkeypatch.setattr(selfcheck_module.sys, "version_info", (3, 10))
    monkeypatch.setattr(selfcheck_module, "__VERSION__", "")
    assert runtime_check() == CheckResult.fail("package version is empty")


def test_platform_check_translates_detection_errors(tmp_path, monkeypatch):
    def fail_platform():
        raise UnsupportedPlatformError("unsupported host")

    monkeypatch.setattr(selfcheck_module, "detect_platform", fail_platform)
    result = dict(build_checks(JerryProxyPaths(tmp_path)))["platform detection"]()

    assert result.level == "FAIL"
    assert "UnsupportedPlatformError: unsupported host" in result.detail


def test_platform_check_bounds_multiline_operational_diagnostics(tmp_path, monkeypatch):
    def fail_platform():
        raise OSError(("unreadable metadata\n" * 10000).strip())

    monkeypatch.setattr(selfcheck_module, "detect_platform", fail_platform)
    result = dict(build_checks(JerryProxyPaths(tmp_path)))["platform detection"]()

    assert result.level == "ERR"
    assert "\n" not in result.detail
    assert len(result.detail) <= 2060
    assert result.diagnostics
    assert len(result.diagnostics[0]) <= 64 * 1024


def test_home_layout_and_permission_checks_report_unmet_requirements(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    original_directory_paths = selfcheck_module._directory_paths

    def remove_downloads_after_initialization(selected_paths):
        selected_paths.downloads.rmdir()
        return original_directory_paths(selected_paths)

    monkeypatch.setattr(selfcheck_module, "_directory_paths", remove_downloads_after_initialization)
    checks = dict(build_checks(paths))

    missing = checks["home directory layout"]()
    assert missing.level == "FAIL"
    assert "missing state directories" in missing.detail

    if selfcheck_module.os.name == "posix":

        def weaken_download_permissions_after_initialization(selected_paths):
            selected_paths.downloads.chmod(0o755)
            return original_directory_paths(selected_paths)

        monkeypatch.setattr(selfcheck_module, "_directory_paths", weaken_download_permissions_after_initialization)
        permissions = checks["private directory permissions"]()
        assert permissions.level == "FAIL"
        assert "not 0700" in permissions.detail
    else:
        assert checks["private directory permissions"]() == CheckResult.skip(
            "POSIX mode checks do not apply on %s" % selfcheck_module.os.name
        )


def test_home_layout_and_permission_reads_remain_under_the_operation_lock(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    original_directory_paths = selfcheck_module._directory_paths
    observations = []

    def assert_locked(selected_paths):
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(selected_paths):
                pass
        observations.append(selected_paths.root)
        return original_directory_paths(selected_paths)

    monkeypatch.setattr(selfcheck_module, "_directory_paths", assert_locked)
    checks = dict(build_checks(paths))

    assert checks["home directory layout"]().level == "OK"
    assert checks["private directory permissions"]().level == "OK"
    expected_observations = 2 if selfcheck_module.os.name == "posix" else 1
    assert observations == [paths.root] * expected_observations


def test_home_write_probe_remains_under_the_operation_lock(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    original_mkstemp = selfcheck_module.tempfile.mkstemp
    observations = []

    def assert_locked(*args, **kwargs):
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(paths):
                pass
        observations.append(paths.root)
        return original_mkstemp(*args, **kwargs)

    monkeypatch.setattr(selfcheck_module.tempfile, "mkstemp", assert_locked)

    result = dict(build_checks(paths))["home write access"]()

    assert result.level == "OK"
    assert observations == [paths.root]


def test_home_checks_report_lock_contention_as_errors(tmp_path):
    paths = JerryProxyPaths(tmp_path)
    checks = dict(build_checks(paths))

    with JerryProxyOperationLock(paths):
        results = [
            checks["home directory layout"](),
            checks["home write access"](),
            checks["private directory permissions"](),
        ]

    assert [result.level for result in results] == ["ERR", "ERR", "ERR"]
    assert all("JerryProxyBusyError" in result.detail for result in results)


def test_private_permission_check_is_not_applicable_off_posix(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    host_os = selfcheck_module.os

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(selfcheck_module, "os", WindowsOsProxy())

    result = dict(build_checks(paths))["private directory permissions"]()

    assert result == CheckResult.skip("POSIX mode checks do not apply on nt")


def test_registry_check_reports_empty_unsupported_and_invalid_registries(tmp_path, monkeypatch):
    registry_check = dict(build_checks(JerryProxyPaths(tmp_path)))["backend registry"]
    monkeypatch.setattr(selfcheck_module, "iter_backends", lambda: ())
    assert registry_check().level == "FAIL"

    class UnsupportedSpec(object):
        name = "unsupported"

        def expected_asset_name(self, platform_info, version):
            raise UnsupportedPlatformError("no asset")

    monkeypatch.setattr(selfcheck_module, "iter_backends", lambda: (UnsupportedSpec(),))
    monkeypatch.setattr(
        selfcheck_module,
        "detect_platform",
        lambda: PlatformInfo("linux", "amd64", "glibc"),
    )
    unsupported = registry_check()
    assert unsupported.level == "FAIL"
    assert "no registered backend supports" in unsupported.detail

    def invalid_registry():
        raise ValueError("invalid registry")

    monkeypatch.setattr(selfcheck_module, "iter_backends", invalid_registry)
    invalid = registry_check()
    assert invalid.level == "ERR"
    assert "ValueError: invalid registry" in invalid.detail


def test_catalog_checks_separate_resource_failures_from_platform_selection(tmp_path, monkeypatch):
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))
    catalog_check = checks["packaged backend catalog"]
    selection_check = checks["catalog platform selection"]

    def fail_load():
        raise BackendCatalogError("catalog unavailable")

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_load)
    error = catalog_check()
    assert error.level == "FAIL"
    assert "catalog unavailable" in error.detail
    skipped = selection_check()
    assert skipped.level == "SKIP"
    assert "packaged catalog prerequisite failed" in skipped.detail

    def fail_resource_read():
        raise OSError("packaged resource is unreadable")

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_resource_read)
    unavailable = catalog_check()
    assert unavailable.level == "ERR"
    assert unavailable.diagnostics and "packaged resource is unreadable" in unavailable.diagnostics[0]
    unavailable_selection = selection_check()
    assert unavailable_selection == CheckResult.skip(
        "packaged catalog prerequisite is unavailable: packaged resource is unreadable"
    )

    class EmptyCatalog(object):
        generated_at = "2026-01-01T00:00:00Z"

        def versions(self, name):
            return ()

        def compatible_versions(self, name, platform_info):
            return ()

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", lambda: EmptyCatalog())
    monkeypatch.setattr(
        selfcheck_module,
        "detect_platform",
        lambda: PlatformInfo("linux", "amd64", "glibc"),
    )
    missing = catalog_check()
    assert missing.level == "FAIL"
    assert "catalog has no stable releases" in missing.detail
    selection = selection_check()
    assert selection.level == "FAIL"
    assert "catalog has no verified stable" in selection.detail


def test_platform_dependents_skip_after_an_unsupported_platform(tmp_path, monkeypatch):
    def unsupported_platform():
        raise UnsupportedPlatformError("unsupported host")

    monkeypatch.setattr(selfcheck_module, "detect_platform", unsupported_platform)
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))

    assert checks["platform detection"]().level == "FAIL"
    dependent_names = (
        "backend registry",
        "catalog platform selection",
        "backend inventory",
        "isolated backend lifecycle",
        "recovery install rollback",
        "recovery activation rollback",
        "recovery activation rollforward",
        "recovery removal rollback",
        "recovery removal rollforward",
    )
    results = [checks[name]() for name in dependent_names]

    assert [result.level for result in results] == ["SKIP"] * len(dependent_names)
    assert all("platform prerequisite is unsupported" in result.detail for result in results)


def test_filelock_check_maps_legacy_status_to_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(
        selfcheck_module,
        "filelock_status",
        lambda: SimpleNamespace(level="WARN", detail="legacy filelock"),
    )

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result.level == "WARN"
    assert result.detail.startswith("legacy filelock;")
    assert "contention" in result.detail


def test_filelock_check_fails_if_exclusive_contention_is_not_enforced(tmp_path, monkeypatch):
    class NonExclusiveLock(object):
        def __init__(self, paths):
            self.paths = paths

        def __enter__(self):
            return self

        def __exit__(self, exception_type, exception, traceback):
            return False

    monkeypatch.setattr(selfcheck_module, "JerryProxyOperationLock", NonExclusiveLock)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result == CheckResult.fail("filelock allowed a concurrent exclusive acquisition")


def test_filelock_check_reports_operational_errors_with_traceback(tmp_path, monkeypatch):
    class BrokenLock(object):
        def __init__(self, paths):
            self.paths = paths

        def __enter__(self):
            raise OSError("lock backend unavailable")

        def __exit__(self, exception_type, exception, traceback):
            return False

    monkeypatch.setattr(selfcheck_module, "JerryProxyOperationLock", BrokenLock)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result.level == "ERR"
    assert result.detail == "OSError: lock backend unavailable"
    assert result.diagnostics and "lock backend unavailable" in result.diagnostics[0]


def test_relay_checks_use_exact_bounded_range_and_report_metrics(tmp_path, monkeypatch):
    lines = []
    relay_factory = verified_relay_session_factory(monkeypatch)

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    assert len(relay_factory.sessions) == 3
    assert (
        sum(
            "relay " in line and "verified 1 MiB; response" in line and "; first chunk" in line and "; stream " in line
            for line in lines
        )
        == 3
    )
    for session in relay_factory.sessions:
        assert session.closed is True
        assert session.max_redirects == 5
        assert len(session.calls) == 1
        url, options = session.calls[0]
        assert url.startswith("https://")
        assert options["headers"]["Range"] == "bytes=0-1048575"
        assert options["allow_redirects"] is True
        assert options["stream"] is True
        assert options["timeout"] == 5.0
        assert session.outcome.closed is True


@pytest.mark.parametrize(
    "error, expected",
    [
        (
            selfcheck_module.requests.exceptions.TooManyRedirects("private redirect URL"),
            "redirect limit exceeded",
        ),
        (selfcheck_module.requests.exceptions.Timeout("private timeout URL"), "request timed out"),
        (selfcheck_module.requests.exceptions.SSLError("private TLS URL"), "TLS validation failed"),
        (selfcheck_module.requests.exceptions.ConnectionError("private connect URL"), "connection failed"),
        (selfcheck_module.requests.exceptions.ProxyError("private proxy URL"), "system proxy connection failed"),
        (selfcheck_module.requests.exceptions.RequestException("private request URL"), "request failed"),
    ],
)
def test_relay_transport_failures_are_sanitized_warnings(tmp_path, error, expected):
    relay_factory = RelaySessionFactory(lambda: error)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail
    assert "private" not in result.detail


def test_relay_http_failure_is_a_sanitized_warning(tmp_path):
    response = FakeRelayResponse(relay_payload(), status_code=403)
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn("bounded 1 MiB verification failed: HTTP response was not 206")
    assert "signed-value" not in result.detail


@pytest.mark.parametrize(
    "response, expected",
    [
        (
            FakeRelayResponse(
                relay_payload(),
                history=[SimpleNamespace(url="https://relay.example/%d" % index) for index in range(6)],
            ),
            "redirect limit exceeded",
        ),
        (
            FakeRelayResponse(
                relay_payload(),
                history=[SimpleNamespace(url="http://private.example/signed-query")],
            ),
            "redirect chain did not remain HTTPS",
        ),
    ],
)
def test_relay_redirect_policy_failures_are_sanitized_warnings(tmp_path, response, expected):
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail
    assert "private" not in result.detail


@pytest.mark.parametrize(
    "response_factory, expected",
    [
        (
            lambda: FakeRelayResponse(relay_payload(), content_range="bytes 0-1/2"),
            "Content-Range did not match the pinned asset",
        ),
        (
            lambda: FakeRelayResponse(relay_payload()[:-1]),
            "response body was not exactly 1 MiB",
        ),
        (
            lambda: FakeRelayResponse(relay_payload()),
            "pinned 1 MiB sample digest did not match",
        ),
    ],
)
def test_relay_content_failures_are_warnings(tmp_path, response_factory, expected, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "RELAY_PROBE_SHA256", "0" * 64)
    relay_factory = RelaySessionFactory(response_factory)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail


def test_relay_probe_stops_after_one_bounded_overflow_chunk(tmp_path):
    response = FakeRelayResponse(relay_payload() + b"unexpected trailing response" * 4096)
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn("bounded 1 MiB verification failed: response body was not exactly 1 MiB")
    assert response.iterated_bytes <= selfcheck_module.RELAY_PROBE_BYTES + 64 * 1024


def test_relay_probe_ignores_empty_chunks_before_a_valid_stream(tmp_path, monkeypatch):
    payload = relay_payload()
    monkeypatch.setattr(
        selfcheck_module,
        "RELAY_PROBE_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    chunks = [b""] + [payload[offset : offset + 64 * 1024] for offset in range(0, len(payload), 64 * 1024)]
    relay_factory = RelaySessionFactory(lambda: FakeRelayResponse(payload, chunks=chunks))
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "OK"
    assert "over 16 chunks" in result.detail


def test_relay_probe_enforces_the_total_stream_budget(tmp_path, monkeypatch):
    moments = iter((0.0, 0.1, 30.1))
    monkeypatch.setattr(selfcheck_module.time, "monotonic", lambda: next(moments))
    response = FakeRelayResponse(relay_payload())
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn(
        "bounded 1 MiB verification failed: stream exceeded the 30-second total timeout"
    )
    assert response.closed is True


def test_production_relay_probe_uses_a_parent_enforced_deadline(monkeypatch):
    class TimedOutProcess(object):
        exitcode = None

        def __init__(self):
            self.join_timeouts = []
            self.terminated = False

        def start(self):
            pass

        def join(self, timeout):
            self.join_timeouts.append(timeout)

        def is_alive(self):
            return not self.terminated

        def terminate(self):
            self.terminated = True

    process = TimedOutProcess()
    profile = next(iter(selfcheck_module.iter_builtin_relays()))

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            assert kwargs["target"] is selfcheck_module._captured_child_entry
            assert kwargs["args"][0] is selfcheck_module._relay_probe_child
            assert kwargs["args"][1][0] is profile
            assert Path(kwargs["args"][1][1]).name == "result.json"
            assert Path(kwargs["args"][2]).name == "stderr.log"
            assert kwargs["daemon"] is True
            return process

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(profile)

    assert result == CheckResult.warn("bounded 1 MiB verification failed: total probe deadline exceeded")
    assert process.terminated is True
    assert 0.0 < process.join_timeouts[0] <= 30.0


def test_production_relay_probe_reports_an_unstoppable_timeout_as_error(monkeypatch):
    class UnstoppableProcess(object):
        exitcode = None

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return True

        def terminate(self):
            pass

        def kill(self):
            pass

    process = UnstoppableProcess()

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return process

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result == CheckResult.err("timed-out relay probe child remained alive after kill")


def test_production_relay_probe_returns_the_child_result(monkeypatch):
    class CompletedProcess(object):
        exitcode = 0

        def __init__(self, result_path):
            self.result_path = result_path

        def start(self):
            selfcheck_module.atomic_write_json(
                self.result_path,
                {"level": "OK", "detail": "verified from child", "diagnostics": []},
            )

        def join(self, timeout):
            assert 0.0 < timeout <= 30.0

        def is_alive(self):
            return False

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return CompletedProcess(Path(kwargs["args"][1][1]))

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result == CheckResult.ok("verified from child")


def test_production_relay_probe_reads_a_maximum_bounded_file_result(monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_relay_probe_child", _write_maximum_relay_diagnostic)

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result.level == "ERR"
    assert result.detail == "maximum diagnostic from child"
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].startswith("relay child diagnostic start")
    assert result.diagnostics[0].endswith("relay child diagnostic end")
    assert len(result.diagnostics[0]) > 63 * 1024


def test_production_relay_probe_never_blocks_on_a_partial_result_file(monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_RELAY_CHECK_TOTAL_TIMEOUT", 0.5)
    monkeypatch.setattr(selfcheck_module, "_relay_probe_child", _write_partial_relay_result_and_stall)
    started = time.monotonic()

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert time.monotonic() - started < 5.0
    assert result.level in ("WARN", "ERR")
    if result.level == "ERR":
        assert "JSON" in result.detail


def test_production_relay_probe_captures_and_redacts_unexpected_child_stderr(monkeypatch, capfd):
    monkeypatch.setattr(selfcheck_module, "_relay_probe_child", _crash_with_sensitive_relay_diagnostic)

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))
    lines = []
    exit_code = run_checks((("relay crash", lambda: result),), lines.append)
    captured = capfd.readouterr()
    rendered = "\n".join(lines) + captured.out + captured.err

    assert exit_code == 1
    assert result.level == "ERR"
    assert result.diagnostics and "Traceback" in result.diagnostics[0]
    assert "[REDACTED" in rendered
    assert "user:pass" not in rendered
    assert "ghp_SUPERSECRET" not in rendered
    assert "123e4567-e89b-12d3-a456-426614174000" not in rendered
    assert "cHJpdmF0ZQ==" not in rendered


def test_production_relay_probe_skips_without_a_process_start_method(monkeypatch):
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result == CheckResult.skip("no supported multiprocessing start method is available")


def test_production_relay_probe_bounds_a_stalled_process_start(monkeypatch):
    release = threading.Event()
    finished = threading.Event()
    captured = {}

    class StalledProcess(object):
        def start(self):
            release.wait(5.0)
            finished.set()

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            captured.update(kwargs)
            return StalledProcess()

    monkeypatch.setattr(selfcheck_module, "_RELAY_CHECK_TOTAL_TIMEOUT", 0.1)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())
    started = time.monotonic()
    try:
        result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))
    finally:
        release.set()
        finished.wait(1.0)

    assert time.monotonic() - started < 1.0
    assert result == CheckResult.err("relay probe child startup exceeded the 0.1-second total deadline")
    assert captured["daemon"] is True
    assert captured["args"][3].is_set() is False
    assert captured["args"][4].is_set() is True


def test_production_relay_probe_cancels_when_start_authorization_cannot_be_published(monkeypatch):
    events = []

    class AuthorizationEvent(threading.Event):
        def set(self):
            raise OSError("authorization event unavailable")

    class Context(object):
        def Event(self):
            event = AuthorizationEvent() if not events else threading.Event()
            events.append(event)
            if len(events) == 3:
                event.set()
            return event

        def Value(self, typecode, value):
            del typecode
            return SimpleNamespace(value=value)

        def Process(self, **kwargs):
            return SimpleNamespace(start=lambda: None)

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result == CheckResult.err(
        "relay probe child startup supervision failed: OSError: authorization event unavailable"
    )
    assert events[1].is_set() is True


def test_production_relay_probe_skips_when_process_construction_fails(monkeypatch):
    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            raise OSError("process construction denied")

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result == CheckResult.skip("spawn relay probe unavailable: OSError: process construction denied")


def test_production_relay_probe_skips_when_process_start_fails(monkeypatch):
    class RejectedProcess(object):
        def start(self):
            raise RuntimeError("spawn disabled")

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return RejectedProcess()

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result == CheckResult.skip("spawn relay probe unavailable: RuntimeError: spawn disabled")


def test_production_relay_probe_stops_a_child_after_join_failure(monkeypatch):
    class UnjoinableProcess(object):
        exitcode = None

        def __init__(self):
            self.terminated = False

        def start(self):
            pass

        def join(self, timeout):
            raise OSError("join denied")

        def is_alive(self):
            return not self.terminated

        def terminate(self):
            self.terminated = True

    process = UnjoinableProcess()

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return process

    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result.level == "ERR"
    assert result.detail == "relay probe child supervision failed"
    assert process.terminated is True
    assert result.diagnostics and "join failed: OSError: join denied" in result.diagnostics[0]


@pytest.mark.parametrize(
    "payload",
    (
        {"level": "BOGUS", "detail": "invalid", "diagnostics": []},
        {"level": "OK", "detail": 17, "diagnostics": []},
        {"level": "OK", "detail": "invalid", "diagnostics": "not a list"},
        {"level": "OK", "detail": "invalid", "diagnostics": ["one", "two"]},
        {"level": "OK", "detail": "invalid", "diagnostics": [17]},
        {"level": "OK", "detail": "invalid", "diagnostics": [], "extra": True},
    ),
)
def test_relay_child_result_rejects_invalid_contracts(tmp_path, payload):
    result_path = tmp_path / "result.json"
    selfcheck_module.atomic_write_json(result_path, payload)

    assert selfcheck_module._relay_child_result(result_path) == CheckResult.err(
        "relay probe child returned an invalid diagnostic result"
    )


def test_relay_child_result_handles_missing_invalid_and_oversized_files(tmp_path):
    result_path = tmp_path / "result.json"
    assert selfcheck_module._read_relay_child_result(result_path) is None

    result_path.write_text('{"level":', encoding="utf-8")
    invalid = selfcheck_module._relay_child_result(result_path)
    assert invalid.level == "ERR"
    assert "JSON" in invalid.detail

    result_path.write_bytes(b"{" + b" " * selfcheck_module._MAXIMUM_CHILD_RESULT_BYTES + b"}")
    oversized = selfcheck_module._relay_child_result(result_path)
    assert oversized.level == "ERR"
    assert "safety limit" in oversized.detail


def test_relay_child_result_accepts_valid_statuses_and_bounds_diagnostics(tmp_path):
    result_path = tmp_path / "result.json"
    diagnostic = "x" * selfcheck_module._MAXIMUM_DIAGNOSTIC_CHARACTERS
    selfcheck_module.atomic_write_json(
        result_path,
        {"level": "ERR", "detail": "child failure", "diagnostics": [diagnostic]},
    )

    result = selfcheck_module._relay_child_result(result_path)

    assert result == CheckResult.err("child failure", (diagnostic,))

    selfcheck_module.atomic_write_json(
        result_path,
        {"level": "OK", "detail": "ready", "diagnostics": []},
    )
    assert selfcheck_module._relay_child_result(result_path) == CheckResult.ok("ready")


def test_relay_probe_child_serializes_one_bounded_diagnostic(tmp_path, monkeypatch):
    result_path = tmp_path / "result.json"
    monkeypatch.setattr(
        selfcheck_module,
        "_check_relay",
        lambda profile, factory: CheckResult.err("failed", ("first", "second")),
    )

    selfcheck_module._relay_probe_child(next(iter(selfcheck_module.iter_builtin_relays())), result_path)

    assert selfcheck_module._relay_child_result(result_path) == CheckResult.err("failed", ("first",))


def test_relay_probe_child_serializes_operational_exceptions(tmp_path, monkeypatch):
    result_path = tmp_path / "result.json"

    def fail_check(profile, factory):
        del profile, factory
        raise ValueError("token=secret-value")

    monkeypatch.setattr(selfcheck_module, "_check_relay", fail_check)

    selfcheck_module._relay_probe_child(next(iter(selfcheck_module.iter_builtin_relays())), result_path)
    result = selfcheck_module._relay_child_result(result_path)
    rendered = result.detail + "\n" + "\n".join(result.diagnostics)

    assert result.level == "ERR"
    assert "[REDACTED]" in rendered
    assert "secret-value" not in rendered


@pytest.mark.parametrize(
    "exitcode, expected",
    (
        (17, "relay probe child returned exit code 17"),
        (0, "relay probe child exited without a diagnostic result"),
    ),
)
def test_production_relay_probe_reports_abnormal_child_results(monkeypatch, exitcode, expected):
    class CompletedProcess(object):
        def __init__(self):
            self.exitcode = exitcode

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return False

    context = _fake_process_context(lambda **kwargs: CompletedProcess())
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._check_relay_in_process(next(iter(selfcheck_module.iter_builtin_relays())))

    assert result.level == "ERR"
    assert result.detail == expected


def test_build_checks_keeps_injected_relay_sessions_inline(tmp_path, monkeypatch):
    relay_factory = verified_relay_session_factory(monkeypatch)

    def reject_process_probe(profile):
        raise AssertionError("injected session unexpectedly crossed the process boundary")

    monkeypatch.setattr(selfcheck_module, "_check_relay_in_process", reject_process_probe)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    assert relay_check().level == "OK"


def test_relay_warnings_keep_the_full_self_check_exit_code_zero(tmp_path):
    lines = []
    relay_factory = RelaySessionFactory(lambda: selfcheck_module.requests.exceptions.Timeout("secret request target"))

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    status = filelock_status()
    expected = (
        "Summary: 16 OK, 3 WARN, 0 SKIP, 0 FAIL, 0 ERR"
        if status.level == "OK"
        else "Summary: 15 OK, 4 WARN, 0 SKIP, 0 FAIL, 0 ERR"
    )
    assert expected in lines
    assert lines[-1] == "Self-check PASSED with warnings"
    assert all("secret" not in line for line in lines)
