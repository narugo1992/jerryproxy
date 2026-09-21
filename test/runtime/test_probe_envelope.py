"""The public default probe accepts only a bounded private worker verdict."""

import json

import pytest

import jerryproxy.runtime._probe as process_module
from jerryproxy.errors import RuntimeSessionError
from jerryproxy.runtime.health import ConnectivityProbe, HealthTarget


@pytest.fixture
def boundary(monkeypatch):
    state = {"payload": json.dumps([[True, 0.1, 0.0, 0.0, ""]]).encode("ascii"), "alive": False}

    class Pipe:
        def poll(self, timeout):
            return True

        def recv_bytes(self, maximum):
            if state.get("on_receive"):
                state["on_receive"]()
            if state.get("read_error"):
                raise state["read_error"]
            if state["payload"] is None:
                raise EOFError
            return state["payload"]

        def send_bytes(self, payload):
            state["payload"] = payload

        def close(self):
            pass

    class Gate:
        def wait(self, timeout):
            return state.get("authorized", True)

        def set(self):
            if state.get("execute"):
                state["payload"] = None
                state["target"](*state["args"])

    class Process:
        pid = None

        def start(self):
            if state.get("start_error"):
                raise state["start_error"]
            self.pid = 123
            state["alive"] = state.get("stay_alive", False)

        def is_alive(self):
            return state["alive"]

        def terminate(self):
            if not state.get("needs_kill"):
                state["alive"] = False

        def kill(self):
            state["alive"] = state.get("unstoppable", False)

        def join(self, timeout):
            pass

        def close(self):
            state["closed"] = True

    class Context:
        Event = Gate

        def Pipe(self, duplex=False):  # noqa: N802 - multiprocessing API
            return Pipe(), Pipe()

        def Process(self, target, args):  # noqa: N802 - multiprocessing API
            state["target"], state["args"] = target, args
            return Process()

    monkeypatch.setattr(process_module.multiprocessing, "get_context", lambda method: Context())
    return state


@pytest.mark.parametrize("value", [
    None, {}, [], [True], [[True]], [[1, 0, 0, 0, ""]],
    [[True, "0", 0, 0, ""]], [[True, False, 0, 0, ""]],
    [[True, -1, 0, 0, ""]], [[True, 10 ** 100, 0, 0, ""]], [[True, float("nan"), 0, 0, ""]],
    [[True, 0, 0, 0, "tls_failed"]], [[False, 0, 0, 0, ""]],
    [[True, 0, 0, 0, None]], [[True, 0, 0, 0, "provider-controlled text"]],
])
def test_malformed_worker_verdict_cannot_establish_health(boundary, value):
    boundary["payload"] = json.dumps(value).encode("ascii")
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1)
    with pytest.raises(RuntimeSessionError, match="result is invalid"):
        probe.check(1, None, None)
    assert boundary["closed"]


@pytest.mark.parametrize("payload", [b"\xff", b"[", b"[" * 10000])
def test_worker_payload_must_be_ascii_json(boundary, payload):
    boundary["payload"] = payload
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1)
    with pytest.raises(RuntimeSessionError, match="result is invalid"):
        probe.check(1, None, None)


@pytest.mark.parametrize("error", [EOFError(), OSError("bad message length")])
def test_broken_worker_pipe_is_terminal(boundary, error):
    boundary["read_error"] = error
    with pytest.raises(RuntimeSessionError, match="result is unavailable"):
        ConnectivityProbe().check(1, None, None)
    assert boundary["closed"]


def test_failed_worker_allocation_is_terminal(boundary):
    boundary["start_error"] = OSError("cannot spawn")
    with pytest.raises(RuntimeSessionError, match="could not start"):
        ConnectivityProbe().check(1, None, None)


@pytest.mark.parametrize("unstoppable", [False, True])
def test_worker_must_be_confirmed_stopped_before_result_acceptance(boundary, unstoppable):
    boundary.update(stay_alive=True, needs_kill=True, unstoppable=unstoppable)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1)
    try:
        if unstoppable:
            with pytest.raises(RuntimeSessionError, match="cleanup remains unconfirmed"):
                probe.check(1, None, None)
            assert "closed" not in boundary
        else:
            assert probe.check(1, None, None).ok
            assert boundary["closed"]
    finally:
        boundary["alive"] = False
        probe.close()


@pytest.mark.parametrize("size_limit", [1, 65536])
def test_real_worker_serializes_only_health_results(boundary, monkeypatch, size_limit):
    import requests

    from test.runtime.test_health import FakeResponse, FakeSession

    boundary["execute"] = True
    monkeypatch.setattr(process_module, "_MAXIMUM_RESULT", size_limit)
    monkeypatch.setattr(requests, "Session", lambda: FakeSession(FakeResponse()))
    monkeypatch.setenv("V2RAY_SUBSCRIPTION", "private-source")
    monkeypatch.setenv("HTTP_PROXY", "http://private-proxy.invalid")
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1)
    if size_limit == 1:
        with pytest.raises(RuntimeSessionError, match="result is unavailable"):
            probe.check(1, "private-user", "private-password")
    else:
        assert probe.check(1, "private-user", "private-password").ok
        assert b"private" not in boundary["payload"]


def test_worker_starter_thread_allocation_failure_is_terminal(boundary, monkeypatch):
    def refuse(thread):
        raise RuntimeError("thread allocation refused")

    monkeypatch.setattr(process_module.threading.Thread, "start", refuse)
    probe = ConnectivityProbe()
    with pytest.raises(RuntimeSessionError, match="starter could not start"):
        probe.check(1, None, None)
    probe.close()


def test_unfinished_process_start_retains_cleanup_ownership(boundary, monkeypatch):
    import threading

    release = threading.Event()
    original_start = threading.Thread.start
    original_wait = threading.Event.wait
    probe = ConnectivityProbe()

    def delayed(thread):
        if thread.name == "jerryproxy-health-start":
            original_run = thread.run

            def run():
                release.wait(5)
                original_run()

            thread.run = run
        original_start(thread)

    def timeout(event, seconds=None):
        if event is probe._network_process.started:
            return event.is_set()
        return original_wait(event, seconds)

    monkeypatch.setattr(threading.Thread, "start", delayed)
    monkeypatch.setattr(threading.Event, "wait", timeout)
    try:
        with pytest.raises(RuntimeSessionError, match="startup cleanup remains unconfirmed"):
            probe.check(1, None, None)
        assert probe._network_process.starter is not None
    finally:
        release.set()
        monkeypatch.setattr(threading.Event, "wait", original_wait)
        probe.close(timeout=1)


def test_starter_thread_must_exit_after_start_completion(boundary, monkeypatch):
    import threading

    release = threading.Event()
    original_thread = threading.Thread

    class DelayedExit(original_thread):
        def run(self):
            super(DelayedExit, self).run()
            release.wait(5)

    monkeypatch.setattr(threading, "Thread", DelayedExit)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1)
    try:
        with pytest.raises(RuntimeSessionError, match="startup cleanup remains unconfirmed"):
            probe.check(1, None, None)
    finally:
        release.set()
        probe.close(timeout=1)


def test_worker_without_start_authorization_performs_no_network(boundary, monkeypatch):
    import requests

    def forbidden():
        pytest.fail("unauthorized worker attempted network access")

    monkeypatch.setattr(requests, "Session", forbidden)
    boundary.update(execute=True, authorized=False)
    with pytest.raises(RuntimeSessionError, match="result is unavailable"):
        ConnectivityProbe().check(1, None, None)


def test_startup_deadline_after_late_completion_is_terminal(boundary, monkeypatch):
    import threading

    original = threading.Event.wait
    probe = ConnectivityProbe()
    waited = []

    def expired(event, seconds=None):
        if event is probe._network_process.started and not waited:
            waited.append(True)
            assert original(event, 1)
            return False
        return original(event, seconds)

    monkeypatch.setattr(threading.Event, "wait", expired)
    with pytest.raises(RuntimeSessionError, match="startup deadline exhausted"):
        probe.check(1, None, None)
    assert boundary["closed"]


def test_result_arriving_after_wall_deadline_cannot_establish_health(boundary, monkeypatch):
    from types import SimpleNamespace

    now = [0.0]
    monkeypatch.setattr(process_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    boundary["on_receive"] = lambda: now.__setitem__(0, 2.0)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1, timeout=1)
    result = probe.check(1, None, None)
    assert not result.ok and result.targets[0].detail == "probe_deadline"
