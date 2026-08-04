import hashlib

import pytest

from jerryproxy.runtime.health import ConnectivityProbe, HealthTarget, RecoveryPolicy


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
