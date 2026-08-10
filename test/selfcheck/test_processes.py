import io
import os
import stat
import threading
import time
from types import SimpleNamespace

import pytest

from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import CheckResult, build_checks, run_checks
from jerryproxy.selfcheck import processes as selfcheck_module
from jerryproxy.selfcheck import recovery as recovery_module
from test.selfcheck.children import (
    _crash_with_sensitive_recovery_diagnostic,
    _fake_process_context,
    _FakeProcessContextBase,
    _write_start_gate_sentinel,
)


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
    terminated = threading.Event()
    reaped = threading.Event()
    captured = {}

    class StalledProcess(object):
        alive = False

        def start(self):
            release.wait(5.0)
            self.alive = True
            finished.set()

        def join(self, timeout):
            del timeout
            reaped.set()

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False
            terminated.set()

        def kill(self):
            self.alive = False

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            captured.update(kwargs)
            return StalledProcess()

    monkeypatch.setattr(selfcheck_module, "_RECOVERY_PROCESS_TIMEOUT", 0.1)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())
    supervision = selfcheck_module._ProcessSupervision()
    started = time.monotonic()
    try:
        result = selfcheck_module._run_recovery_child(
            lambda: None,
            (),
            71,
            tmp_path / "error.log",
            supervision=supervision,
        )
        elapsed = time.monotonic() - started
    finally:
        release.set()
        finished.wait(1.0)
        reaped.wait(1.0)

    assert elapsed < 1.0
    assert result == CheckResult.err(
        "hard-exit recovery child startup exceeded the 0.1-second timeout",
        diagnostics=("delayed process-start cleanup will be verified by the final supervision check",),
    )
    assert captured["daemon"] is True
    assert captured["args"][3].is_set() is False
    assert captured["args"][4].is_set() is True
    assert terminated.is_set()
    assert reaped.is_set()
    assert supervision.wait(1.0)
    assert supervision.result() == CheckResult.ok("1 delayed child start was cancelled and reaped")


def test_start_supervision_reports_a_late_child_that_survives_termination_and_kill(tmp_path, monkeypatch):
    release = threading.Event()
    finished = threading.Event()

    class UnstoppableProcess(object):
        def start(self):
            release.wait(5.0)
            finished.set()

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return True

        def terminate(self):
            raise OSError("termination denied")

        def kill(self):
            raise OSError("kill denied")

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            del kwargs
            return UnstoppableProcess()

    monkeypatch.setattr(selfcheck_module, "_RECOVERY_PROCESS_TIMEOUT", 0.1)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())
    supervision = selfcheck_module._ProcessSupervision()

    result = selfcheck_module._run_recovery_child(
        lambda: None,
        (),
        71,
        tmp_path / "error.log",
        supervision=supervision,
    )
    release.set()
    assert finished.wait(1.0)
    assert supervision.wait(1.0)

    assert result.level == "ERR"
    audit = supervision.result()
    assert audit.level == "ERR"
    assert audit.detail == "1 delayed child remained alive after kill"
    assert any("terminate failed" in item for item in audit.diagnostics)
    assert any("kill failed" in item for item in audit.diagnostics)


def test_start_supervision_reaps_a_late_child_when_cancellation_publication_fails(
    tmp_path,
    monkeypatch,
):
    release = threading.Event()
    finished = threading.Event()
    terminated = threading.Event()
    reaped = threading.Event()
    events = []

    class RejectedCancellation(threading.Event):
        def set(self):
            raise OSError("cancellation publication denied")

    class DelayedProcess(object):
        alive = False

        def start(self):
            release.wait(5.0)
            self.alive = True
            finished.set()

        def join(self, timeout):
            del timeout
            reaped.set()

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False
            terminated.set()

        def kill(self):
            self.alive = False

    class Context(_FakeProcessContextBase):
        def Event(self):
            event = RejectedCancellation() if len(events) == 1 else threading.Event()
            events.append(event)
            return event

        def Process(self, **kwargs):
            del kwargs
            return DelayedProcess()

    monkeypatch.setattr(selfcheck_module, "_RECOVERY_PROCESS_TIMEOUT", 0.1)
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(selfcheck_module.multiprocessing, "get_context", lambda method: Context())
    supervision = selfcheck_module._ProcessSupervision()

    try:
        result = selfcheck_module._run_recovery_child(
            lambda: None,
            (),
            71,
            tmp_path / "error.log",
            supervision=supervision,
        )
    finally:
        release.set()
        finished.wait(1.0)
        reaped.wait(1.0)

    assert result == CheckResult.err(
        "hard-exit recovery child startup supervision failed: OSError: "
        "cancellation publication denied"
    )
    assert terminated.is_set()
    assert supervision.wait(1.0)
    assert supervision.result() == CheckResult.ok("1 delayed child start was cancelled and reaped")


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

    previous_umask = os.umask(0) if os.name == "posix" else None
    try:
        process.start()
        process.join(10.0)
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)

    assert process.exitcode == selfcheck_module._CHILD_START_CANCELLED
    assert not sentinel.exists()
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "child.stderr").stat().st_mode) == 0o600


def test_child_start_gate_reports_cancellation_and_deadline(monkeypatch):
    class Event(object):
        def __init__(self, value=False):
            self.value = value

        def is_set(self):
            return self.value

        def set(self):
            self.value = True

        def wait(self, unused_timeout):
            del unused_timeout
            return self.value

    ready = Event()
    assert (
        selfcheck_module._child_start_allowed(
            Event(False),
            Event(True),
            ready,
            SimpleNamespace(value=1.0),
        )
        is False
    )
    assert ready.is_set() is True

    clock = iter((0.0, selfcheck_module._CHILD_START_GATE_TIMEOUT + 1.0))
    monkeypatch.setattr(selfcheck_module.time, "monotonic", lambda: next(clock))
    assert (
        selfcheck_module._child_start_allowed(
            Event(False),
            Event(False),
            Event(),
            SimpleNamespace(value=1.0),
        )
        is False
    )


def test_captured_child_entry_rejects_an_unavailable_diagnostic_boundary(monkeypatch, tmp_path):
    class ChildExit(Exception):
        pass

    opened = []
    closed = []

    def fake_open(path, flags, mode=None):
        del path, flags, mode
        if not opened:
            opened.append(101)
            return opened[0]
        raise OSError("simulated stderr boundary failure")

    def fake_exit(code):
        assert code == selfcheck_module._CHILD_STDERR_CAPTURE_ERROR
        raise ChildExit()

    monkeypatch.setattr(selfcheck_module.os, "open", fake_open)
    monkeypatch.setattr(selfcheck_module.os, "close", lambda descriptor: closed.append(descriptor))
    monkeypatch.setattr(selfcheck_module.os, "_exit", fake_exit)

    with pytest.raises(ChildExit):
        selfcheck_module._captured_child_entry(
            lambda: None,
            (),
            str(tmp_path / "child.stderr"),
            None,
            None,
            None,
            None,
        )
    assert closed == [101]


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow diagnostic creation")
def test_spawn_child_refuses_a_preexisting_stderr_alias(tmp_path):
    if "spawn" not in selfcheck_module.multiprocessing.get_all_start_methods():
        pytest.skip("spawn start method is unavailable")
    context = selfcheck_module.multiprocessing.get_context("spawn")
    start_allowed = context.Event()
    start_cancelled = context.Event()
    start_ready = context.Event()
    start_budget = context.Value("d", 10.0)
    outside = tmp_path / "outside.log"
    outside.write_bytes(b"must survive")
    stderr_log = tmp_path / "child.stderr"
    stderr_log.symlink_to(outside)
    process = context.Process(
        target=selfcheck_module._captured_child_entry,
        args=(
            _write_start_gate_sentinel,
            (str(tmp_path / "business-ran"),),
            str(stderr_log),
            start_allowed,
            start_cancelled,
            start_ready,
            start_budget,
        ),
    )

    process.start()
    process.join(10.0)

    assert process.exitcode == selfcheck_module._CHILD_STDERR_CAPTURE_ERROR
    assert outside.read_bytes() == b"must survive"


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
    class Clock(object):
        value = 0.0

        def monotonic(self):
            return self.value

    clock = Clock()

    class ReadyEvent(threading.Event):
        def wait(self, timeout=None):
            del timeout
            clock.value = 5.0
            if ready_after_wait:
                self.set()
                return True
            return False

    class Process(object):
        alive = False

        def start(self):
            self.alive = True

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False

        def kill(self):
            self.alive = False

    start_allowed = threading.Event()
    start_cancelled = threading.Event()
    start_ready = ReadyEvent()
    start_budget = SimpleNamespace(value=0.0)
    process = Process()
    monkeypatch.setattr(selfcheck_module.time, "monotonic", clock.monotonic)

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
    class Clock(object):
        value = 0.0

        def monotonic(self):
            return self.value

    clock = Clock()

    class AuthorizationEvent(threading.Event):
        def set(self):
            super(AuthorizationEvent, self).set()
            clock.value = 5.0

    class Process(object):
        alive = False

        def start(self):
            self.alive = True

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False

        def kill(self):
            self.alive = False

    start_allowed = AuthorizationEvent()
    start_cancelled = threading.Event()
    start_ready = threading.Event()
    start_ready.set()
    start_budget = SimpleNamespace(value=0.0)
    process = Process()
    monkeypatch.setattr(selfcheck_module.time, "monotonic", clock.monotonic)

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


@pytest.mark.skipif(os.name != "posix", reason="POSIX diagnostic mode semantics")
def test_recovery_child_error_diagnostic_is_created_with_mode_0600(tmp_path):
    invalid_root = tmp_path / "not-a-directory"
    invalid_root.write_bytes(b"occupied")
    error_log = tmp_path / "child-error.log"
    previous_umask = os.umask(0)
    try:
        result = selfcheck_module._run_recovery_child(
            recovery_module._install_recovery_child,
            (str(invalid_root),),
            selfcheck_module._RECOVERY_CHILD_ERROR,
            error_log,
        )
    finally:
        os.umask(previous_umask)

    assert result is None
    assert stat.S_IMODE(error_log.stat().st_mode) == 0o600


def test_recovery_child_error_diagnostic_does_not_replace_the_child_exit_on_close_failure(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(selfcheck_module.os, "open", lambda *args, **kwargs: 91)
    monkeypatch.setattr(
        selfcheck_module.os,
        "fchmod",
        lambda descriptor, mode: None,
        raising=False,
    )
    monkeypatch.setattr(selfcheck_module.os, "write", lambda descriptor, payload: len(payload))

    def fail_close(descriptor):
        raise OSError("diagnostic close failed")

    monkeypatch.setattr(selfcheck_module.os, "close", fail_close)

    selfcheck_module._write_recovery_child_error(tmp_path / "child-error.log")
