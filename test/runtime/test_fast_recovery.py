"""Bound discovery latency without starving slow but usable proxy nodes."""

import random

import pytest

from jerryproxy.runtime import ConnectivityProbe, HealthSnapshot, RecoveryPolicy
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import parse_subscription_body

from .test_persistent import Clock, ReloadingDriver
from .test_session import FakeSubscriptionManager, _record, _session


class TimedProbe(ConnectivityProbe):
    """Honor the production probe budget with an injected monotonic clock."""

    def __init__(self, clock, driver, working, latency=1.0):
        self.clock = clock
        self.driver = driver
        self.working = working
        self.latency = latency
        self.attempts = []
        self.available = True

    def check(self, port, username, password, timeout=None):
        budget = min(10.0, 10.0 if timeout is None else timeout)
        self.attempts.append((self.clock(), self.driver.loaded, budget))
        ok = self.available and self.driver.loaded == self.working and self.latency <= budget
        self.clock.now += self.latency if ok else budget
        return HealthSnapshot((), int(ok), 1, self.clock())

    def close(self, timeout=2.0):
        pass


def replacement(count):
    # The provider keeps its labels but replaces every server address.
    body = _record(nodes=count).body.replace(b"192.0.2.1", b"192.0.2.2")
    return build_record("main", "a" * 32, parse_subscription_body(body, format_hint="uri-lines"),
                        source_url="https://example.invalid/sub")


@pytest.mark.parametrize("count", [1, 5, 10, 20])
def test_replaced_pool_refreshes_before_linear_scan_and_resumes_without_backoff(tmp_path, count):
    clock = Clock()
    original = _record(nodes=count, source_url="https://example.invalid/sub")
    updated = replacement(1)
    driver = ReloadingDriver()
    wanted = (updated.nodes[0].secret_uri() + "\n").encode("utf-8")
    probe = TimedProbe(clock, driver, wanted)
    refreshes = []

    class Manager(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            refreshes.append((clock(), timeout))
            clock.now += 2
            return updated

    session = _session(tmp_path, original, probe, manager=Manager(original),
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy())
    session.driver = driver
    try:
        session.start("main", original.nodes[0].node_id, install_missing=False)
        # Startup has two ordinary failed probes and one confirmation delay.
        assert refreshes[0][0] <= 29
        assert refreshes[0][1] == 10
        assert clock.now <= 32
        assert session.node.node_id == updated.nodes[0].node_id
        assert session.preference_node_id == original.nodes[0].node_id
        assert driver.launches == 1
        assert clock.delays == [3.0]  # Startup confirmation only, no recovery backoff.
    finally:
        session.stop()


@pytest.mark.parametrize("count", [1, 5, 10, 20])
def test_fast_sweep_gives_slow_usable_node_a_normal_budget(tmp_path, count):
    clock = Clock()
    record = _record(nodes=count)
    driver = ReloadingDriver()
    wanted = (record.nodes[-1].secret_uri() + "\n").encode("utf-8")
    probe = TimedProbe(clock, driver, wanted, latency=5)
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="random"))
    session.driver = driver
    # Enter running recovery so even a one-node pool exercises both phases.
    try:
        probe.working = (record.nodes[0].secret_uri() + "\n").encode("utf-8")
        session.start("main", record.nodes[0].node_id, install_missing=False)
        probe.working = wanted
        probe.attempts.clear()
        session._schedule.rng = random.Random(0)
        session._recover()
        assert any(budget == 3 for _, _, budget in probe.attempts)
        assert probe.attempts[-1][1] == wanted
        assert probe.attempts[-1][2] > 3
        assert session.last_health.ok
    finally:
        session.stop()


def test_small_subscription_policy_defaults():
    policy = RecoveryPolicy()
    assert policy.fast_probe_timeout == 3
    assert policy.cache_retry_budget == 6
    assert policy.refresh_timeout == 10
    assert policy.refresh_interval == 60
    assert policy.recovery_deadline == 120
    assert policy.health_interval == 30


@pytest.mark.parametrize("round_budget", [3, 6, 10])
def test_refresh_has_its_own_budget_when_candidate_round_is_exhausted(tmp_path, round_budget):
    clock = Clock()
    record = _record(nodes=20, source_url="https://example.invalid/sub")
    updated = replacement(1)
    driver = ReloadingDriver()
    probe = TimedProbe(clock, driver, (record.nodes[0].secret_uri() + "\n").encode("utf-8"))
    refreshes = []

    class Manager(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            refreshes.append((clock(), timeout))
            clock.now += timeout  # Refresh uses its whole independent allowance.
            return updated

    session = _session(tmp_path, record, probe, manager=Manager(record), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(recovery_deadline=round_budget))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        probe.working = (updated.nodes[0].secret_uri() + "\n").encode("utf-8")
        started = clock()
        session._recover()
        assert refreshes[0][0] - started <= 6
        assert refreshes[0][1] == 10
        assert clock() - started <= 17
        assert not clock.delays
    finally:
        session.stop()


@pytest.mark.parametrize("mode", ["unchanged", "temporary", "retry_after", "disabled", "no_source"])
def test_recovery_refresh_is_throttled_and_preserves_usable_cache(tmp_path, mode):
    from jerryproxy.errors import SubscriptionTransportError

    clock = Clock()
    record = _record(nodes=20, source_url=None if mode == "no_source" else "https://example.invalid/sub")
    driver = ReloadingDriver()
    wanted = (record.nodes[0].secret_uri() + "\n").encode("utf-8")
    probe = TimedProbe(clock, driver, wanted)
    times = []

    class Manager(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            times.append(clock())
            if mode in ("temporary", "retry_after"):
                raise SubscriptionTransportError("temporary", retry_after=180 if mode == "retry_after" else 0)
            return record

    session = _session(tmp_path, record, probe, manager=Manager(record), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(refresh_on_failure=mode != "disabled"))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        probe.available = False
        original_check = probe.check

        def check(*args, **kwargs):
            probe.available = clock() >= 250
            return original_check(*args, **kwargs)

        probe.check = check
        session._recover()
        assert session.subscription.body == record.body
        assert session.last_health.ok
        if mode in ("disabled", "no_source"):
            assert not times
        else:
            assert len(times) >= 2
            interval = 180 if mode == "retry_after" else 60
            assert all(b >= a + interval for a, b in zip(times, times[1:])), times
    finally:
        session.stop()


@pytest.mark.parametrize("field", ["fast_probe_timeout", "cache_retry_budget", "refresh_timeout", "refresh_interval"])
@pytest.mark.parametrize("value", [0, -1, True, float("inf"), float("nan"), "3"])
def test_invalid_fast_recovery_durations_are_refused(field, value):
    with pytest.raises(ValueError, match="finite and positive"):
        RecoveryPolicy(**{field: value})


@pytest.mark.parametrize("count", [1, 5, 10, 20])
@pytest.mark.parametrize("latency", [1, 3])
@pytest.mark.parametrize("seed", [0, 1, 2, 3, 4])
def test_default_quick_recovery_budget_for_small_partially_failed_pools(tmp_path, count, latency, seed):
    clock = Clock()
    record = _record(nodes=count, source_url="https://example.invalid/sub")
    driver = ReloadingDriver()
    probe = TimedProbe(clock, driver, (record.nodes[0].secret_uri() + "\n").encode("utf-8"))
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy())
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        probe.working = (record.nodes[-1].secret_uri() + "\n").encode("utf-8")
        probe.latency = latency
        probe.attempts.clear()
        session._schedule.rng = random.Random(seed)
        started = clock()
        session._recover()
        assert clock() - started <= 3 * count
        assert len(probe.attempts) <= count
        assert not clock.delays
    finally:
        session.stop()
