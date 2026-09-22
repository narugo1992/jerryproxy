"""Recovery isolates unusable routes instead of terminating the server."""

import pytest

from jerryproxy.runtime import HealthSnapshot, RecoveryPolicy
from jerryproxy.runtime.health import TargetHealth
from jerryproxy.runtime.recovery import RetrySchedule

from .test_persistent import Clock, ReloadingDriver
from .test_session import _record, _session

pytestmark = pytest.mark.unittest


@pytest.mark.parametrize("detail", ["tls_failed", "proxy_authentication_failed", "transport_failed"])
@pytest.mark.parametrize("quorum_passes", [True, False])
def test_target_refusal_obeys_quorum_and_recovers(tmp_path, detail, quorum_passes):
    record = _record(nodes=2)
    clock = Clock()
    driver = ReloadingDriver()
    initial = (record.nodes[0].secret_uri() + "\n").encode("utf-8")

    class Probe:
        def check(self, port, username, password):
            failed = driver.loaded == initial
            return HealthSnapshot(
                (
                    TargetHealth("one", not failed, detail=detail if failed else ""),
                    TargetHealth("two", True),
                    TargetHealth("three", quorum_passes),
                ),
                (int(not failed) + 1 + int(quorum_passes)),
                2,
                clock(),
            )

    session = _session(
        tmp_path, record, Probe(), clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy(retry_policy="fallback")
    )
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.node.node_id == record.nodes[0 if quorum_passes else 1].node_id
        assert driver.reloads == (0 if quorum_passes else 1)
        assert session.last_health.ok
    finally:
        session.stop()


def test_fixed_identity_absence_waits_without_selecting_another():
    schedule = RetrySchedule("fixed", "wanted")
    schedule.update(["other"])
    assert schedule.next("wanted", 0) is None
    schedule.update(["other", "wanted"])
    assert schedule.next("wanted", 1) == "wanted"


@pytest.mark.parametrize("fault", ["bypass", "control", "readiness"])
def test_initial_backend_fault_is_isolated_before_another_node(tmp_path, fault):
    from jerryproxy.errors import RuntimeSessionError
    from jerryproxy.runtime import LoadedNodes

    from .test_persistent import Probe

    class Driver(ReloadingDriver):
        def loaded_nodes(self, *args):
            if self.launches == 1:
                if fault == "control":
                    raise RuntimeSessionError("control unavailable")
                if fault == "bypass":
                    return LoadedNodes((), "DIRECT", True, ())
            return super(Driver, self).loaded_nodes(*args)

        def wait_ready(self, *args, **kwargs):
            if self.launches == 1 and fault == "readiness":
                raise RuntimeSessionError("listener unavailable")
            return super(Driver, self).wait_ready(*args, **kwargs)

        def stop(self, process, timeout=None):
            self.stopped.append(process)
            return super(Driver, self).stop(process, timeout)

    record = _record(nodes=2)
    driver = Driver()
    driver.stopped = []
    clock = Clock()
    session = _session(tmp_path, record, Probe(lambda: True), clock=clock, sleeper=clock.sleep)
    session.driver = driver
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert driver.launches == 2
        assert driver.stopped[0].stopped
        assert session.last_health.ok
    finally:
        session.stop()


def test_backend_exit_rebuilds_and_returns_ready(tmp_path):
    from .test_persistent import Probe

    record = _record(nodes=1)
    driver = ReloadingDriver()
    clock = Clock()
    session = _session(tmp_path, record, Probe(lambda: True), clock=clock, sleeper=clock.sleep)
    session.driver = driver
    events = []
    session.event_sink = events.append
    session.start("main", record.nodes[0].node_id, install_missing=False)
    listener = (session.port, session.control_port, session.username, session.password)
    session.process.process.returncode = 23

    def stop_after_rebuild(delay):
        if driver.launches == 2:
            raise KeyboardInterrupt
        clock.sleep(delay)

    session.sleeper = stop_after_rebuild
    try:
        assert session.wait() == 130
        assert driver.launches == 2
        assert listener == (session.port, session.control_port, session.username, session.password)
        assert any(e["event"] == "session.ready" and e["data"]["reason"] == "backend_restored" for e in events)
    finally:
        session.stop()


def test_remote_source_refusal_keeps_cache_and_recovers(tmp_path):
    from jerryproxy.errors import SubscriptionSourceError

    from .test_persistent import Probe
    from .test_session import FakeSubscriptionManager

    record = _record(nodes=1, source_url="https://provider.example/feed")
    clock = Clock()

    class Manager(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            self.refresh_calls += 1
            raise SubscriptionSourceError("source rejected")

    manager = Manager(record)
    session = _session(
        tmp_path, record, Probe(lambda: clock.now >= 180), manager=manager, clock=clock, sleeper=clock.sleep
    )
    session.driver = ReloadingDriver()
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert clock.now >= 180
        assert manager.refresh_calls > 0
        assert session.subscription == record
        assert session.last_health.ok
    finally:
        session.stop()


def test_periodic_control_refusal_rebuilds_before_claiming_health(tmp_path):
    from jerryproxy.errors import RuntimeSessionError

    from .test_persistent import Probe

    clock = Clock()

    class Driver(ReloadingDriver):
        def loaded_nodes(self, *args):
            if clock.now > 0 and self.launches == 1:
                raise RuntimeSessionError('control authentication refused')
            return super(Driver, self).loaded_nodes(*args)

    driver = Driver()
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: True), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(health_interval=1))
    session.driver = driver
    session.start('main', record.nodes[0].node_id, install_missing=False)

    def finish(delay):
        if driver.launches > 1:
            raise KeyboardInterrupt
        assert clock.now < 5, 'control was never revalidated'
        clock.sleep(delay)

    session.sleeper = finish
    try:
        assert session.wait() == 130
        assert driver.launches == 2
    finally:
        session.stop()


def test_repeated_backend_crash_uses_backoff_then_recovers(tmp_path):
    from jerryproxy.errors import RuntimeCandidateError

    from .test_persistent import Probe

    clock = Clock()
    record = _record(nodes=1)

    class Driver(ReloadingDriver):
        def create_process(self, *args, **kwargs):
            child = super(Driver, self).create_process(*args, **kwargs)
            if clock.now < 180:
                def crash():
                    child.process.returncode = 23
                    raise RuntimeCandidateError('backend exited before ready')
                child.start = crash
            return child

    driver = Driver()
    session = _session(tmp_path, record, Probe(lambda: True), clock=clock, sleeper=clock.sleep)
    session.driver = driver
    try:
        session.start('main', record.nodes[0].node_id, install_missing=False)
        assert clock.now >= 180
        assert 2 < driver.launches < 20
        assert session.last_health.ok
        assert max(clock.delays) <= 60
    finally:
        session.stop()


def test_backend_flapping_is_rate_limited_even_when_probes_pass(tmp_path):
    from .test_persistent import Probe
    record = _record(nodes=1)
    clock = Clock()
    driver = ReloadingDriver()

    def healthy():
        session.process.process.returncode = 23
        return True

    session = _session(tmp_path, record, Probe(healthy), clock=clock, sleeper=clock.sleep)
    session.driver = driver
    session.start('main', record.nodes[0].node_id, install_missing=False)

    def finish(delay):
        if driver.launches >= 6:
            raise KeyboardInterrupt
        clock.sleep(delay)

    session.sleeper = finish
    try:
        assert session.wait() == 130
        assert clock.now >= 40
        assert driver.launches == 6
    finally:
        session.stop()


@pytest.mark.parametrize("phase", ["launch", "control"])
def test_exhausted_candidate_deadline_recovers_without_ending_session(tmp_path, phase):
    from .test_persistent import Probe

    clock = Clock()

    class Driver(ReloadingDriver):
        def create_process(self, *args, **kwargs):
            process = super(Driver, self).create_process(*args, **kwargs)
            original = process.start

            def start():
                original()
                if self.launches == 1 and phase == "launch":
                    clock.now += 121

            process.start = start
            return process

        def wait_ready(self, *args, **kwargs):
            super(Driver, self).wait_ready(*args, **kwargs)
            if self.launches == 1 and phase == "control":
                clock.now += 121

    record = _record(nodes=2)
    session = _session(tmp_path, record, Probe(lambda: True), clock=clock, sleeper=clock.sleep)
    session.driver = Driver()
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.driver.launches == 2
        assert session.last_health.ok
    finally:
        session.stop()
