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
    with pytest.raises(ValueError):
        ConnectivityProbe(targets=(target,), protocol="ftp")
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


def test_recovery_policy_defaults_match_closed_foreground_strategy():
    policy = RecoveryPolicy()
    assert policy.startup_retry_delays == (0.0, 1.0, 2.0)
    assert policy.same_node_delay == 1.0
    assert policy.alternate_delays == (4.0, 8.0)
    assert policy.refresh_on_failure is True
    with pytest.raises(ValueError):
        RecoveryPolicy(health_interval=0)


@pytest.mark.parametrize(
    "changes",
    [
        {"same_node_delay": -1},
        {"refresh_stale_seconds": float("inf")},
        {"failure_cooldown": "300"},
        {"startup_retry_delays": ()},
        {"startup_retry_delays": (0.0, -1.0)},
        {"alternate_delays": ()},
        {"alternate_delays": (float("nan"),)},
        {"refresh_on_failure": 1},
    ],
)
def test_recovery_policy_rejects_invalid_strategy_values(changes):
    with pytest.raises(ValueError):
        RecoveryPolicy(**changes)
