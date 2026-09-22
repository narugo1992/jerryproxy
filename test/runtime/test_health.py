import hashlib
import threading

import pytest
import requests

import jerryproxy.runtime.health as health_module
from jerryproxy.errors import RuntimeSessionError
from jerryproxy.runtime.health import (
    ConnectivityProbe,
    HealthSnapshot,
    HealthTarget,
    RecoveryDeadline,
    RecoveryPolicy,
    TargetHealth,
    require_health,
)


class FakeResponse(object):
    def __init__(self, status_code=204, chunks=(), headers=None, redirect=False):
        self.status_code = status_code
        self._chunks = tuple(chunks)
        self.headers = headers or {}
        self.is_redirect = redirect
        self.closed = False

    def iter_content(self, chunk_size):
        del chunk_size
        return iter(self._chunks)

    def close(self):
        self.closed = True


class FakeSession(object):
    def __init__(self, response):
        self.response = response
        self.trust_env = True
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response

    def close(self):
        pass


class MissingSocksSession(FakeSession):
    def get(self, url, **kwargs):
        del url, kwargs
        raise requests.exceptions.InvalidSchema("Missing dependencies for SOCKS support.")


def test_probe_requires_authenticated_proxy_and_returns_sanitized_quorum():
    target = HealthTarget("test", "https://example.invalid/204", 204)
    responses = []

    def factory():
        response = FakeResponse()
        responses.append(response)
        return FakeSession(response)

    probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=factory, timeout=1)
    result = probe.check(17777, "user", "password")

    assert result.ok
    assert result.passed == 1
    assert result.targets[0].name == "test"
    assert result.targets[0].detail == ""
    assert responses and all(response.closed for response in responses)


def test_probe_rejects_body_and_redirect_without_exposing_url():
    target = HealthTarget("test", "https://secret.invalid/path?token=secret", 204)

    def factory():
        return FakeSession(FakeResponse(status_code=204, chunks=(b"unexpected",), redirect=True))

    probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=factory, timeout=1)
    result = probe.check(17777, "user", "password")

    assert not result.ok
    assert result.targets[0].detail == "unexpected_redirect"
    assert "secret.invalid" not in repr(result)
    assert "token" not in repr(result)


def test_probe_validates_pinned_body_hash_and_first_chunk_metrics():
    body = b"fixed payload"
    target = HealthTarget("fixed", "https://example.invalid/fixed", 200, len(body), hashlib.sha256(body).hexdigest())

    def factory():
        return FakeSession(FakeResponse(status_code=200, chunks=(body[:5], body[5:])))

    probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=factory, timeout=1)
    result = probe.check(17777, "user", "password")

    assert result.ok
    assert result.targets[0].first_chunk_latency >= 0
    assert result.targets[0].speed_bytes_per_second >= 0


def test_socks_probe_reports_a_missing_transport_dependency_explicitly():
    target = HealthTarget("socks-target", "https://example.invalid/204", 204)

    probe = ConnectivityProbe(
        targets=(target,),
        quorum=1,
        session_factory=lambda: MissingSocksSession(None),
        timeout=1,
        protocol="socks5",
    )
    result = probe.check(17777, None, None)

    assert not result.ok
    assert result.targets[0].detail == "socks_dependency_missing"


def test_probe_rejects_invalid_constructor_values_and_partial_credentials():
    target = HealthTarget("test", "https://example.invalid/204", 204)
    with pytest.raises(ValueError):
        ConnectivityProbe(targets=())
    with pytest.raises(ValueError):
        ConnectivityProbe(targets=(target,), timeout=0)
    with pytest.raises(ValueError):
        ConnectivityProbe(targets=(target,), quorum=2)
    with pytest.raises(ValueError, match="unsupported local proxy protocol"):
        ConnectivityProbe(targets=(target,), quorum=1, protocol="ftp")
    with pytest.raises(ValueError):
        ConnectivityProbe._proxy_url(17777, "user", None)


@pytest.mark.parametrize(
    ("response", "target", "detail"),
    [
        (FakeResponse(status_code=500), HealthTarget("status", "https://example.invalid", 204), "unexpected_status"),
        (
            FakeResponse(headers={}),
            HealthTarget("header", "https://example.invalid", 204, required_header="X-Online: yes"),
            "required_header_missing",
        ),
        (
            FakeResponse(chunks=(b"too long",)),
            HealthTarget("size", "https://example.invalid", 204, maximum_bytes=1),
            "body_too_large",
        ),
        (
            FakeResponse(chunks=(b"short",)),
            HealthTarget("short", "https://example.invalid", 204, maximum_bytes=10),
            "body_size_mismatch",
        ),
        (
            FakeResponse(chunks=(b"wrong",)),
            HealthTarget("hash", "https://example.invalid", 204, maximum_bytes=5, sha256="0" * 64),
            "target_contract_invalid",
        ),
    ],
)
def test_probe_reports_sanitized_contract_failures(response, target, detail):
    probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=lambda: FakeSession(response), timeout=1)
    result = probe.check(17777, None, None)
    assert not result.ok
    assert result.targets[0].detail == detail


def test_probe_reports_timeout_and_transport_failures_without_raw_errors():
    target = HealthTarget("test", "https://secret.invalid/path?token=secret", 204)

    class TimeoutSession(FakeSession):
        def get(self, url, **kwargs):
            del url, kwargs
            raise requests.exceptions.Timeout("secret target")

    class RequestFailureSession(FakeSession):
        def get(self, url, **kwargs):
            del url, kwargs
            raise requests.exceptions.ConnectionError("secret target")

    for session_type, detail in ((TimeoutSession, "timeout"), (RequestFailureSession, "transport_failed")):
        probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=lambda: session_type(None), timeout=1)
        result = probe.check(17777, None, None)
        assert not result.ok
        assert result.targets[0].detail == detail
        assert "secret" not in repr(result)


def test_probe_respects_a_zero_remaining_deadline():
    target = HealthTarget("deadline", "https://example.invalid", 204)
    probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=lambda: FakeSession(None), timeout=1)
    result = probe.check(17777, None, None, timeout=0)
    assert not result.ok
    assert result.targets[0].detail == "probe_deadline"


def test_probe_marks_a_stalled_worker_as_failed_and_closes_it():
    target = HealthTarget("stalled", "https://example.invalid", 204)
    release = threading.Event()

    class StalledSession(FakeSession):
        def get(self, url, **kwargs):
            del url, kwargs
            release.wait(1.0)
            raise requests.exceptions.Timeout("stalled")

    probe = ConnectivityProbe(targets=(target,), quorum=1, session_factory=lambda: StalledSession(None), timeout=0.01)
    result = probe.check(17777, None, None)
    release.set()
    assert not result.ok
    assert result.targets[0].detail in ("probe_worker_alive", "probe_deadline")


def test_recovery_deadline_sleep_and_public_health_requirement(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(health_module.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    deadline = RecoveryDeadline(2.0, clock=lambda: now[0])
    assert deadline.remaining() == 2.0
    assert deadline.sleep(1.0)
    assert deadline.sleep(2.0) is False
    assert deadline.remaining() == 1.0
    good = HealthSnapshot((TargetHealth("ok", True),), 1, 1, 0.0)
    assert require_health(good) is good
    with pytest.raises(RuntimeSessionError, match="quorum failed"):
        require_health(HealthSnapshot((TargetHealth("bad", False),), 0, 1, 0.0))


def test_recovery_policy_defaults_match_persistent_strategy():
    policy = RecoveryPolicy()
    assert policy.retry_policy == "fallback"
    assert policy.health_interval == 30
    assert policy.confirmation_delay == 3
    assert policy.refresh_on_failure is True
    with pytest.raises(ValueError):
        RecoveryPolicy(health_interval=0)


@pytest.mark.parametrize(
    "changes",
    [
        {"confirmation_delay": -1},
        {"refresh_stale_seconds": float("inf")},
        {"refresh_interval": "300"},
        {"retry_policy": "unknown"},
        {"retry_policy": "fixed", "retry_chain": "random:all"},
        {"retry_chain": "random:0"},
        {"health_interval": float("nan")},
        {"refresh_on_failure": 1},
    ],
)
def test_recovery_policy_rejects_invalid_strategy_values(changes):
    with pytest.raises(ValueError):
        RecoveryPolicy(**changes)


def test_custom_closed_fallback_chain_is_accepted():
    policy = RecoveryPolicy(retry_chain="current:1,random:all")
    assert policy.retry_chain == "current:1,random:all"


def test_repeated_timeouts_do_not_accumulate_live_probe_workers():
    release = threading.Event()
    entered = threading.Event()
    calls = []

    class Stalled(FakeSession):
        def get(self, *args, **kwargs):
            calls.append(1)
            entered.set()
            assert release.wait(15)
            return FakeResponse()

    # Hold the logical deadline open until the worker enters; native scheduler
    # latency must not turn this stalled-request case into a pre-request expiry.
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),),
                              quorum=1, timeout=0.001, session_factory=lambda: Stalled(None), clock=lambda: 0.0)
    try:
        assert not probe.check(17777, None, None).ok
        assert entered.wait(1)
        for _ in range(100):
            assert not probe.check(17777, None, None).ok
        assert len(calls) == 1
    finally:
        release.set()
        probe.close()


def test_many_targets_use_at_most_three_workers_and_can_recover():
    release = threading.Event()
    closed = []
    workers = set()

    class Stalled(FakeSession):
        def get(self, *args, **kwargs):
            workers.add(threading.current_thread().ident)
            assert release.wait(15)
            return FakeResponse()

        def close(self):
            closed.append(1)

    targets = tuple(HealthTarget("target-%d" % index, "https://example.invalid", 204) for index in range(20))
    probe = ConnectivityProbe(targets=targets, quorum=2, timeout=0.01, session_factory=lambda: Stalled(None))
    try:
        assert not probe.check(17777, None, None).ok
        assert len(workers) <= 3
    finally:
        release.set()
    # Wait on known worker handles to prove completion before a fresh check.
    for thread in threading.enumerate():
        if thread.ident in workers:
            thread.join(1)
    assert len(closed) <= 3
    probe.session_factory = lambda: FakeSession(FakeResponse())
    assert probe.check(17777, None, None, timeout=1).ok


def test_probe_close_waits_for_real_worker_completion_and_cancels_pending_targets():
    release = threading.Event()
    entered = threading.Event()
    calls = []

    class Stalled(FakeSession):
        def get(self, *args, **kwargs):
            calls.append(1)
            entered.set()
            assert release.wait(5)
            return FakeResponse()

    probe = ConnectivityProbe(targets=tuple(HealthTarget(str(i), "https://example.invalid", 204) for i in range(12)),
                              quorum=2, timeout=0.01, session_factory=lambda: Stalled(None))
    try:
        assert not probe.check(17777, None, None).ok
        assert entered.wait(1)
        with pytest.raises(RuntimeSessionError, match="health.*cleanup"):
            probe.close(timeout=0.01)
        assert len(calls) <= 3
    finally:
        release.set()
    probe.close(timeout=1)
    assert len(calls) <= 3
    assert all(not worker.is_alive() for worker in probe._workers)
    probe.close(timeout=0)


def test_session_retains_lock_when_health_worker_cleanup_is_unconfirmed(tmp_path, monkeypatch):
    from jerryproxy.errors import JerryProxyBusyError
    from jerryproxy.lock import JerryProxyOperationLock
    from test.runtime.test_session import _record, _session

    release = threading.Event()
    entered = threading.Event()

    class Stalled(FakeSession):
        def get(self, *args, **kwargs):
            entered.set()
            assert release.wait(10)
            return FakeResponse()

    record = _record(nodes=1)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),),
                              quorum=1, timeout=0.001, session_factory=lambda: Stalled(None),
                              clock=lambda: 1.0 if entered.is_set() else 0.0)
    start_thread = threading.Thread.start

    def start_and_wait(worker):
        start_thread(worker)
        if worker.name.startswith("jerryproxy-health-"):
            assert entered.wait(2), "health worker did not reach the blocked transport"

    monkeypatch.setattr(threading.Thread, "start", start_and_wait)
    runtime = _session(tmp_path, record, probe, policy=RecoveryPolicy(retry_policy="none", confirmation_delay=0.001))
    events = []
    runtime.event_sink = events.append
    try:
        with pytest.raises(RuntimeSessionError, match="cleanup"):
            runtime.start("main", record.nodes[0].node_id, install_missing=False)
        assert runtime._operation_lock is not None
        assert not any(event["event"] == "session.stopped" for event in events)
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(runtime.paths):
                pass
    finally:
        release.set()
        for worker in probe._workers:
            worker.join(1)
        runtime.stop()
    assert runtime._operation_lock is None


def test_probe_interrupt_waits_on_completion_event_and_retains_live_worker(monkeypatch):
    release = threading.Event()
    entered = threading.Event()

    class Stalled(FakeSession):
        def get(self, *args, **kwargs):
            entered.set()
            assert release.wait(5)
            return FakeResponse()

    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),),
                              quorum=1, session_factory=lambda: Stalled(None))
    original_wait = threading.Event.wait

    def interrupt(event, timeout=None):
        if event in probe._worker_done and threading.current_thread() is threading.main_thread():
            assert original_wait(entered, 1)
            raise KeyboardInterrupt
        return original_wait(event, timeout)

    monkeypatch.setattr(threading.Event, "wait", interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            probe.check(17777, None, None)
        monkeypatch.setattr(threading.Event, "wait", original_wait)
        assert not probe.check(17777, None, None).ok
        with pytest.raises(RuntimeSessionError, match="cleanup"):
            probe.close(timeout=0)
    finally:
        monkeypatch.setattr(threading.Event, "wait", original_wait)
        release.set()
        probe.close(timeout=1)


def test_probe_reports_worker_allocation_failure_and_cleans_started_workers(monkeypatch):
    original = threading.Thread.start
    calls = []

    def refuse(thread):
        calls.append(thread)
        if len(calls) == 2:
            raise RuntimeError("thread allocation refused")
        original(thread)

    monkeypatch.setattr(threading.Thread, "start", refuse)
    probe = ConnectivityProbe(session_factory=lambda: FakeSession(FakeResponse()))
    with pytest.raises(RuntimeSessionError, match="could not start"):
        probe.check(17777, None, None)
    probe.close(timeout=1)
    assert len(probe._workers) == 1


def test_probe_close_requires_thread_exit_after_target_completion(monkeypatch):
    release = threading.Event()
    original_thread = threading.Thread

    class DelayedExit(original_thread):
        def run(self):
            super(DelayedExit, self).run()
            assert release.wait(5)

    monkeypatch.setattr(threading, "Thread", DelayedExit)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1,
                              session_factory=lambda: FakeSession(FakeResponse()))
    try:
        assert probe.check(17777, None, None).ok
        assert not probe.check(17777, None, None).ok
        with pytest.raises(RuntimeSessionError, match="cleanup"):
            probe.close(timeout=0.01)
    finally:
        release.set()
        probe.close(timeout=1)


@pytest.mark.parametrize("fault, detail", [("tls", "tls_failed"), ("proxy_auth", "proxy_authentication_failed")])
def test_explicit_none_disables_tls_and_authentication_recovery(tmp_path, fault, detail):
    from test.runtime.test_session import _record, _session

    calls = []

    class Refused(FakeSession):
        def get(self, *args, **kwargs):
            calls.append(1)
            assert len(calls) <= 2, "none permits confirmation but not recovery"
            if fault == "tls":
                raise requests.exceptions.SSLError("private TLS context")
            return FakeResponse(status_code=407)

    record = _record(nodes=1)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1,
                              session_factory=lambda: Refused(None))
    session = _session(tmp_path, record, probe, sleeper=lambda delay: None,
                       policy=RecoveryPolicy(retry_policy="none"))
    with pytest.raises(RuntimeSessionError, match="retry policy is none") as failure:
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert len(calls) == 2
    assert session.last_health.targets[0].detail == detail
    assert "private TLS context" not in str(failure.value)
    assert session._operation_lock is None
    assert not session.session_root.exists()


@pytest.mark.parametrize("late", [False, True])
def test_probe_enforces_body_deadline_and_required_header_with_minimal_transport(late):
    now = [0.0]

    class Response(FakeResponse):
        def iter_content(self, chunk_size):
            yield b""
            if late:
                now[0] = 2.0
                yield b"late"

    response = Response(headers={"X-Online": "yes"})

    class Session:
        def get(self, *args, **kwargs):
            return response

    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204,
                                                    required_header="X-Online: yes"),),
                              quorum=1, timeout=1, clock=lambda: now[0], session_factory=Session)
    result = probe.check(17777, None, None)
    assert result.ok is not late
    assert result.targets[0].detail == ("probe_deadline" if late else "")
    probe.close()


def test_session_missing_socks_dependency_is_terminal(tmp_path):
    from test.runtime.test_session import _record, _session

    record = _record(nodes=1)
    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),), quorum=1,
                              protocol="socks5", session_factory=lambda: MissingSocksSession(None))
    session = _session(tmp_path, record, probe)
    with pytest.raises(RuntimeSessionError, match="install PySocks"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert session._operation_lock is None


@pytest.mark.parametrize("shape", ["authentication", "other_status", "substring", "wrong_type", "wrong_args",
                                   "nontext", "unwrapped", "wrong_reason", "multiple_args"])
def test_proxy_error_classification_requires_the_exact_connect_chain(shape):
    from urllib3.exceptions import MaxRetryError, ProxyError

    cause = OSError("Tunnel connection failed: 407 private-diagnostic")
    if shape == "other_status":
        cause = OSError("Tunnel connection failed: 503 proxy unavailable")
    elif shape == "substring":
        cause = OSError("remote message mentions Tunnel connection failed: 407 private-diagnostic")
    elif shape == "wrong_type":
        cause = ValueError("Tunnel connection failed: 407 private-diagnostic")
    elif shape == "wrong_args":
        cause = OSError()
    elif shape == "nontext":
        cause = OSError(407)
    reason = ProxyError("proxy connection failed", cause)
    if shape == "wrong_reason":
        reason = cause
    wrapped = MaxRetryError(None, "/", reason=reason)
    if shape == "unwrapped":
        wrapped = cause
    args = (wrapped, "extra") if shape == "multiple_args" else (wrapped,)
    error = requests.exceptions.ProxyError(*args)

    class Session:
        def get(self, *args, **kwargs):
            raise error

    probe = ConnectivityProbe(targets=(HealthTarget("one", "https://example.invalid", 204),),
                              quorum=1, session_factory=Session)
    try:
        result = probe.check(17777, None, None)
        expected = "proxy_authentication_failed" if shape == "authentication" else "transport_failed"
        assert result.targets[0].detail == expected
        assert "private-diagnostic" not in repr(result)
    finally:
        probe.close()
