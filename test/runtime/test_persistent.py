"""Public session recovery with a deterministic clock and external driver."""

import hashlib
import random

import pytest

from jerryproxy.errors import (
    RuntimeSessionError,
    SubscriptionFetchError,
    SubscriptionStateError,
    SubscriptionTransportError,
)
from jerryproxy.runtime import HealthSnapshot, LoadedNodes, MihomoDriver, RecoveryPolicy
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import parse_subscription_body

from .test_session import FakeProcess, FakeSubscriptionManager, _record, _session


class Clock(object):
    def __init__(self):
        self.now = 0.0
        self.delays = []

    def __call__(self):
        return self.now

    def sleep(self, delay):
        assert 0 < delay <= 60
        self.delays.append(delay)
        self.now += delay
        assert self.now < 2000, "recovery did not converge"


class ReloadingDriver(MihomoDriver):
    """Only replace the external backend, retaining real private publication."""

    def __init__(self):
        super(ReloadingDriver, self).__init__(process_factory=FakeProcess)
        self.path = None
        self.loaded = None
        self.reloads = 0
        self.launches = 0
        self.stale_reload = False

    def projection(self, provider_path, *args, **kwargs):
        self.path = provider_path
        return super(ReloadingDriver, self).projection(provider_path, *args, **kwargs)

    def create_process(self, *args, **kwargs):
        self.launches += 1
        self.loaded = self.path.read_bytes()
        return super(ReloadingDriver, self).create_process(*args, **kwargs)

    def loaded_nodes(self, control_port, control_secret, timeout):
        assert timeout > 0
        identity = hashlib.sha256(self.loaded).hexdigest()
        return LoadedNodes(("same-name",), "same-name", False, (identity,))

    def reload_provider(self, control_port, control_secret, timeout):
        assert timeout > 0
        self.reloads += 1
        if not self.stale_reload:
            self.loaded = self.path.read_bytes()


class Probe(object):
    def __init__(self, healthy):
        self.healthy = healthy
        self.calls = 0
        self.listeners = set()

    def check(self, port, username, password):
        self.calls += 1
        self.listeners.add((port, username, password))
        return HealthSnapshot((), int(self.healthy()), 1, 0)


def test_startup_keeps_retrying_beyond_old_deadline_without_restarting(tmp_path):
    clock = Clock()
    probe = Probe(lambda: clock.now >= 180)
    record = _record(nodes=1)
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep,
                       authenticate=True, policy=RecoveryPolicy(retry_policy="fixed", recovery_deadline=10))
    driver = ReloadingDriver()
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert clock.now >= 180
        assert session.last_health.ok
        assert session.node.node_id == record.nodes[0].node_id
        assert 3 < probe.calls < 40
        assert len(probe.listeners) == 1
        assert driver.launches == 1 and driver.reloads == 0
        assert session.access_path.exists()
    finally:
        session.stop()
    assert not session.session_root.exists()


def test_startup_fallback_hot_switches_to_usable_alternate(tmp_path):
    clock = Clock()
    record = _record(nodes=2)
    driver = ReloadingDriver()
    wanted = (record.nodes[1].secret_uri() + "\n").encode("utf-8")
    probe = Probe(lambda: driver.loaded == wanted)
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep,
                       authenticate=True, policy=RecoveryPolicy(retry_policy="fallback"))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.node.node_id == record.nodes[1].node_id
        assert session.preference_node_id == record.nodes[0].node_id
        assert driver.launches == 1 and driver.reloads == 1
        assert len(probe.listeners) == 1
        assert session.last_health.ok
    finally:
        session.stop()


def test_none_stops_after_confirmation_without_reload_or_refresh(tmp_path):
    clock = Clock()
    record = _record(nodes=2)
    probe = Probe(lambda: False)
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="none"))
    driver = ReloadingDriver()
    session.driver = driver
    with pytest.raises(RuntimeSessionError, match="retry policy is none"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert probe.calls == 2
    assert driver.reloads == 0
    assert session.subscription_manager.refresh_calls == 0
    assert not session.session_root.exists()


def test_acknowledged_reload_with_old_identity_fails_closed(tmp_path):
    clock = Clock()
    record = _record(nodes=2)
    events = []
    session = _session(tmp_path, record, Probe(lambda: False), clock=clock, sleeper=clock.sleep,
                       log_sink=lambda *event: events.append(event),
                       policy=RecoveryPolicy(retry_policy="fallback"))
    driver = ReloadingDriver()
    driver.stale_reload = True
    session.driver = driver
    with pytest.raises(RuntimeSessionError, match="previous provider identity"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert driver.reloads == 1
    assert not any("backend accepted node %s" % record.nodes[1].node_id in event[2] for event in events)
    assert not session.session_root.exists()


def test_periodic_outage_recovers_after_multiple_rounds(tmp_path):
    clock = Clock()
    record = _record(nodes=1)
    driver = ReloadingDriver()

    def healthy():
        if clock.now >= 180:
            session.process.process.returncode = 0
            return True
        return clock.now == 0

    session = _session(tmp_path, record, Probe(healthy), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fixed", health_interval=1, confirmation_delay=1,
                                             recovery_deadline=10))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.wait() == 0
        assert clock.now >= 180
        assert session.last_health.ok
        assert driver.launches == 1
    finally:
        session.stop()


def test_round_deadlines_preserve_progress_through_large_subscription(tmp_path):
    clock = Clock()
    record = _record(nodes=150)
    driver = ReloadingDriver()
    attempted = set()

    def healthy():
        attempted.add(driver.loaded)
        clock.now += 2
        return len(attempted) == 150

    probe = Probe(healthy)
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="random", recovery_deadline=10))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert len(attempted) == 150
        assert probe.calls <= 153
        assert driver.launches == 1
    finally:
        session.stop()


def test_startup_cancel_during_backoff_cleans_child_and_private_paths(tmp_path):
    record = _record(nodes=1)
    clock = Clock()

    def cancel(delay):
        if clock.now:
            raise KeyboardInterrupt
        clock.sleep(delay)

    session = _session(tmp_path, record, Probe(lambda: False), clock=clock, sleeper=cancel,
                       policy=RecoveryPolicy(retry_policy="fixed"))
    session.driver = ReloadingDriver()
    with pytest.raises(KeyboardInterrupt):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert session.process is None
    assert not session.session_root.exists()


def test_old_cache_does_not_exclude_a_working_alternate(tmp_path):
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone

    record = replace(_record(nodes=2), updated_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
    clock = Clock()
    driver = ReloadingDriver()
    wanted = (record.nodes[1].secret_uri() + "\n").encode("utf-8")
    session = _session(tmp_path, record, Probe(lambda: driver.loaded == wanted), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fallback"))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.node.node_id == record.nodes[1].node_id
    finally:
        session.stop()


def test_refresh_introduces_alternate_without_rewriting_preference(tmp_path):
    original = _record(nodes=1, source_url="https://example.invalid/sub")
    refreshed = _record(nodes=2, source_url="https://example.invalid/sub")
    manager = FakeSubscriptionManager(original, refreshed)
    clock = Clock()
    driver = ReloadingDriver()
    wanted = (refreshed.nodes[1].secret_uri() + "\n").encode("utf-8")
    session = _session(tmp_path, original, Probe(lambda: driver.loaded == wanted), manager=manager,
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy(retry_policy="fallback"))
    session.driver = driver
    try:
        session.start("main", original.nodes[0].node_id, install_missing=False)
        assert manager.refresh_calls == 1
        assert session.node.node_id == refreshed.nodes[1].node_id
        assert session.preference_node_id == original.nodes[0].node_id
    finally:
        session.stop()


def test_unhealthy_loaded_candidate_does_not_become_effective(tmp_path):
    record = _record(nodes=3)
    clock = Clock()
    driver = ReloadingDriver()
    seen = set()

    def healthy():
        assert session.node.node_id == record.nodes[0].node_id
        seen.add(driver.loaded)
        return len(seen) == 3

    session = _session(tmp_path, record, Probe(healthy), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fallback"))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.node.node_id != record.nodes[0].node_id
    finally:
        session.stop()


def test_bypassed_candidate_is_terminal_before_a_health_probe(tmp_path):
    class BypassingDriver(ReloadingDriver):
        def loaded_nodes(self, *args):
            if self.reloads:
                return LoadedNodes((), "COMPATIBLE", True)
            return super(BypassingDriver, self).loaded_nodes(*args)

    record = _record(nodes=2)
    clock = Clock()
    driver = BypassingDriver()
    probe = Probe(lambda: driver.reloads > 0)
    session = _session(tmp_path, record, probe, clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fallback"))
    session.driver = driver
    with pytest.raises(RuntimeSessionError, match="route traffic directly"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert probe.calls == 3
    assert not session.session_root.exists()


def test_fixed_node_removal_is_actionable_and_cleans_the_session(tmp_path):
    original = _record(nodes=1, source_url="https://example.invalid/sub")
    refreshed = _record(nodes=2, source_url="https://example.invalid/sub")
    clock = Clock()
    session = _session(tmp_path, original, Probe(lambda: False),
                       manager=FakeSubscriptionManager(original, refreshed), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fixed"))
    session.driver = ReloadingDriver()
    with pytest.raises(RuntimeSessionError, match="fixed node.*node list"):
        session.start("main", original.nodes[0].node_id, install_missing=False)
    assert not session.session_root.exists()


@pytest.mark.parametrize("policy", ["fixed", "random", "adaptive", "fallback"])
def test_healthy_periodic_checks_never_explore_or_switch(tmp_path, policy):
    clock = Clock()
    record = _record(nodes=3)
    driver = ReloadingDriver()

    def healthy():
        if clock.now >= 90:
            session.process.process.returncode = 0
        return True

    session = _session(tmp_path, record, Probe(healthy), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy=policy))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.wait() == 0
        assert driver.launches == 1 and driver.reloads == 0
        assert session.node.node_id == record.nodes[0].node_id
    finally:
        session.stop()


@pytest.mark.parametrize("fault, message", [
    ("no_identity", "establish a provider identity"),
    ("no_provider", "reloadable provider"),
    ("config_change", "change the session configuration"),
    ("child_exit", "exited during connectivity recovery"),
])
def test_recovery_contract_failures_are_terminal_and_cleaned(tmp_path, fault, message):
    from dataclasses import replace

    class FaultDriver(ReloadingDriver):
        def loaded_nodes(self, *args):
            loaded = super(FaultDriver, self).loaded_nodes(*args)
            return replace(loaded, identities=()) if fault == "no_identity" else loaded

        def projection(self, *args, **kwargs):
            projection = super(FaultDriver, self).projection(*args, **kwargs)
            if self.launches:
                if fault == "no_provider":
                    return replace(projection, provider=None)
                if fault == "config_change":
                    return replace(projection, config=b"changed")
            return projection

    clock = Clock()
    record = _record(nodes=2)
    driver = FaultDriver()

    def unhealthy():
        if fault == "child_exit":
            session.process.process.returncode = 7
        return False

    session = _session(tmp_path, record, Probe(unhealthy), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fallback"))
    session.driver = driver
    with pytest.raises(RuntimeSessionError, match=message):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert not session.session_root.exists()


def test_a_single_failed_startup_probe_does_not_trigger_recovery(tmp_path):
    clock = Clock()
    record = _record(nodes=2)
    driver = ReloadingDriver()
    session = _session(tmp_path, record, Probe(lambda: clock.now > 0), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="none"))
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert driver.launches == 1 and driver.reloads == 0
        assert session.last_health.ok
    finally:
        session.stop()


def test_unchanged_refreshed_content_cannot_change_backend_identity(tmp_path):
    class UnstableDriver(ReloadingDriver):
        def loaded_nodes(self, *args):
            from dataclasses import replace
            loaded = super(UnstableDriver, self).loaded_nodes(*args)
            if manager.refresh_calls:
                return replace(loaded, identities=("different-generation",))
            return loaded

    original = _record(nodes=1, source_url="https://example.invalid/sub")
    # Container whitespace changes the revision without changing the node.
    refreshed = build_record("main", "a" * 32, parse_subscription_body(original.body + b"\n"),
                             source_url=original.source_url)
    manager = FakeSubscriptionManager(original, refreshed)
    clock = Clock()
    session = _session(tmp_path, original, Probe(lambda: False), manager=manager,
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy())
    session.driver = UnstableDriver()
    with pytest.raises(RuntimeSessionError, match="unchanged provider identity"):
        session.start("main", original.nodes[0].node_id, install_missing=False)
    assert not session.session_root.exists()


def test_transient_refresh_failure_keeps_cache_and_retries_nodes(tmp_path):
    clock = Clock()
    record = _record(nodes=1, source_url="https://example.invalid/sub")

    class Unavailable(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            self.refresh_calls += 1
            assert timeout is not None and 0 < timeout <= 10
            raise SubscriptionTransportError("temporarily unavailable", retry_after=600)

    manager = Unavailable(record)
    session = _session(tmp_path, record, Probe(lambda: clock.now >= 400), manager=manager,
                       clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="fixed", recovery_deadline=10))
    session.driver = ReloadingDriver()
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.last_health.ok
        assert session.subscription.revision == record.revision
        assert manager.refresh_calls == 1
    finally:
        session.stop()


def test_unclassified_refresh_error_stays_terminal(tmp_path):
    clock = Clock()
    record = _record(nodes=1, source_url="https://example.invalid/sub")

    class Refused(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            raise SubscriptionFetchError("TLS verification failed")

    session = _session(tmp_path, record, Probe(lambda: False), manager=Refused(record),
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy())
    session.driver = ReloadingDriver()
    with pytest.raises(SubscriptionFetchError, match="TLS"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert not session.session_root.exists()


def test_healthy_stale_cache_refresh_failure_does_not_switch_or_stop(tmp_path):
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone

    clock = Clock()
    record = replace(_record(nodes=2, source_url="https://example.invalid/sub"),
                     updated_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())

    class Unavailable(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            self.refresh_calls += 1
            raise SubscriptionTransportError("temporary")

    manager = Unavailable(record)
    session = _session(tmp_path, record, Probe(lambda: True), manager=manager,
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy())
    driver = ReloadingDriver()
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert manager.refresh_calls == 1
        assert session.node.node_id == record.nodes[0].node_id
        assert driver.reloads == 0
    finally:
        session.stop()


@pytest.mark.parametrize("seed", [0, 63])
def test_refresh_backoff_is_independent_and_resets_after_success(tmp_path, seed):
    clock = Clock()
    record = _record(nodes=1, source_url="https://example.invalid/sub")
    times = []

    class Refreshing(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            times.append(clock.now)
            if len(times) <= 2:
                raise SubscriptionTransportError("temporary")
            return self.record

    session = _session(tmp_path, record, Probe(lambda: len(times) >= 4), manager=Refreshing(record),
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy(retry_policy="fixed"))
    session.driver = ReloadingDriver()
    session._backoff.rng = random.Random(seed)
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        # Discovery may run again before the next eligible probe. Its cadence,
        # rather than an exact count, is the contract under a 60-second interval.
        assert len(times) >= 4
        # Compare absolute deadlines, as the scheduler does: subtraction of
        # jittered floats can round an exact 120-second interval below 120.
        assert times[0] + 60 <= times[1] <= times[0] + 180
        assert times[1] + 120 <= times[2] <= times[1] + 240
        assert times[2] + 60 <= times[3] <= times[2] + 180
        assert all(later >= earlier + 60 for earlier, later in zip(times[3:], times[4:]))
    finally:
        session.stop()


@pytest.mark.parametrize("changes", [{"name": "other"}, {"subscription_id": "b" * 32}, {"enabled": False}])
def test_refresh_cannot_replace_the_selected_subscription_scope(tmp_path, changes):
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone

    record = replace(_record(nodes=1, source_url="https://example.invalid/sub"),
                     updated_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
    session = _session(tmp_path, record, Probe(lambda: True),
                       manager=FakeSubscriptionManager(record, replace(record, **changes)))
    session.driver = ReloadingDriver()
    with pytest.raises(SubscriptionStateError, match="selected source"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert not session.session_root.exists()
