import json
import re
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from jerryproxy.errors import (
    BackendNotInstalledError,
    RuntimeSessionError,
    SubscriptionNodesMismatchError,
    SubscriptionStateError,
)
from jerryproxy.home import JerryProxyPaths
from jerryproxy.runtime import (
    HealthSnapshot,
    RecoveryPolicy,
    RuntimeDriver,
    RuntimeProjection,
    RuntimeSession,
)
from jerryproxy.runtime.health import RecoveryDeadline
from jerryproxy.subscription import SingleNodeSource, SubscriptionManager, V2RaySubscriptionParser
from jerryproxy.subscription.model import ParsedSubscription
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import FetchedSubscription, parse_subscription_body

URI_TEMPLATE = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@192.0.2.1:%d#node-%d\n"


class FakeChild(object):
    def __init__(self):
        self.returncode = None

    def poll(self):
        return self.returncode


class FakeProcess(object):
    def __init__(self, executable, config_path, session_root, log_path, backend_log_level, log_sink=None):
        del executable, config_path, session_root, log_path, backend_log_level, log_sink
        self.process = FakeChild()
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        return self.process

    def wait_ready(self, port):
        del port

    def stop(self):
        self.stopped = True
        self.process.returncode = 0


@dataclass(frozen=True)
class Installed(object):
    executable: object


class FakeBackendManager(object):
    def __init__(self, executable):
        self.executable = executable

    def which(self, name, version):
        assert name == "mihomo"
        assert version == "1.19.29"
        return Installed(self.executable)


class FakeProbe(object):
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)

    def check(self, port, username, password):
        del port, username, password
        value = self.outcomes.pop(0)
        return HealthSnapshot((), 1 if value else 0, 1, 0.0)


class FakeSubscriptionManager(object):
    def __init__(self, record, refreshed=None):
        self.record = record
        self.refreshed = refreshed
        self.refresh_calls = 0

    def list(self):
        return (self.record,)

    def refresh(self, name):
        assert name == self.record.name
        self.refresh_calls += 1
        return self.refreshed or self.record


def _record(name="main", nodes=2, source_url=None):
    body = b"\n".join(
        URI_TEMPLATE.encode("ascii") % (443 + index, index) for index in range(nodes)
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")
    return build_record(name, "a" * 32, parsed, source_url=source_url)


def _session(
    tmp_path,
    record,
    probe,
    manager=None,
    policy=None,
    authenticate=False,
    bind_address="127.0.0.1",
    log_sink=None,
    clock=None,
    sleeper=None,
):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    executable = tmp_path / "mihomo"
    executable.write_bytes(b"fake")
    subscription_manager = manager or FakeSubscriptionManager(record)
    return RuntimeSession(
        paths,
        manager=FakeBackendManager(executable),
        subscription_manager=subscription_manager,
        health_probe=probe,
        authenticate=authenticate,
        bind_address=bind_address,
        log_sink=log_sink,
        process_factory=FakeProcess,
        recovery_policy=policy or RecoveryPolicy(
            startup_retry_delays=(0.0,),
            same_node_delay=0.0,
            alternate_delays=(0.0, 0.0),
            recovery_deadline=10.0,
        ),
        clock=clock,
        sleeper=sleeper or (lambda delay: None),
    )


def test_runtime_start_keeps_subscription_and_node_state_below_home(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)

    assert runtime.session_root.parent == runtime.paths.leases
    assert re.match(r"runtime-\d{8}T\d{6}Z-[0-9a-f]{32}\.log$", runtime.log_path.name)
    runtime_log = runtime.log_path.read_text(encoding="utf-8")
    assert "[INFO] starting backend" in runtime_log
    assert "[jerryproxy]" not in runtime_log
    assert "[jerryproxy:" not in runtime_log
    assert "[backend:" not in runtime_log
    assert runtime.access_path.is_file()
    assert runtime.node.node_id == record.nodes[0].node_id
    access = runtime.access_path.read_text(encoding="ascii")
    assert '"authentication":false' in access
    assert runtime.username is None and runtime.password is None
    assert "authentication:" not in runtime.config_path.read_text(encoding="utf-8")
    runtime.stop()
    assert not runtime.session_root.exists()


def test_startup_health_result_is_logged_as_info(tmp_path):
    record = _record(nodes=1)
    events = []
    runtime = _session(tmp_path, record, FakeProbe([True]), log_sink=lambda *event: events.append(event))
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)

    assert any(
        source == "jerryproxy"
        and level == "INFO"
        and "startup health check passed" in message
        for source, level, message in events
    )
    runtime.stop()


def test_startup_health_failure_logs_warning_then_error_and_action(tmp_path):
    record = _record(nodes=1)
    events = []
    policy = RecoveryPolicy(
        startup_retry_delays=(0.0, 0.0),
        recovery_deadline=10.0,
        same_node_delay=0.0,
        alternate_delays=(0.0, 0.0),
    )
    runtime = _session(
        tmp_path,
        record,
        FakeProbe([False, False]),
        policy=policy,
        log_sink=lambda *event: events.append(event),
    )

    with pytest.raises(RuntimeSessionError):
        runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)

    health_events = [event for event in events if "startup health check" in event[2]]
    assert any(event[1] == "WARN" and "retrying current node" in event[2] for event in health_events)
    assert any(event[1] == "ERROR" and "stopping session" in event[2] for event in health_events)


def test_periodic_health_failure_logs_recovery_action_and_failure(tmp_path):
    class Clock(object):
        def __init__(self):
            self.value = 0.0

        def __call__(self):
            return self.value

        def sleep(self, delay):
            self.value += max(0.2, delay)

    record = _record(nodes=1)
    clock = Clock()
    events = []
    policy = RecoveryPolicy(
        health_interval=1.0,
        startup_retry_delays=(0.0,),
        recovery_deadline=2.0,
        same_node_delay=0.0,
        alternate_delays=(0.0, 0.0),
    )
    runtime = _session(
        tmp_path,
        record,
        FakeProbe([True]),
        policy=policy,
        log_sink=lambda *event: events.append(event),
        clock=clock,
        sleeper=clock.sleep,
    )
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)
    runtime.health_probe = FakeProbe([False, False, False])
    runtime._next_health_at = clock.value

    with pytest.raises(RuntimeSessionError):
        runtime.wait()
    runtime.stop()

    periodic = [event for event in events if event[0] == "jerryproxy" and "periodic health check" in event[2]]
    assert any(event[1] == "WARN" and "one more failed check" in event[2] for event in periodic)
    assert any(event[1] == "ERROR" and "starting recovery" in event[2] for event in periodic)
    assert any(event[1] == "ERROR" and "health recovery action failed" in event[2] for event in events)


@pytest.mark.parametrize("protocol", ["mixed", "http", "socks5"])
def test_runtime_default_health_probe_matches_listener_protocol(tmp_path, protocol):
    record = _record(nodes=1)
    runtime = RuntimeSession(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        manager=FakeBackendManager(tmp_path / "mihomo"),
        subscription_manager=FakeSubscriptionManager(record),
        listener_protocol=protocol,
    )

    assert runtime.health_probe.protocol == protocol


def test_runtime_authentication_is_published_for_local_clients(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]), authenticate=True)
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)

    access = runtime.access_path.read_text(encoding="ascii")
    config = runtime.config_path.read_text(encoding="utf-8")
    assert '"authentication":true' in access
    assert runtime.username and runtime.password
    assert "authentication:" in config
    assert "  - '%s:%s'" % (runtime.username, runtime.password) in config
    runtime.stop()


def test_runtime_rejects_non_boolean_authentication(tmp_path):
    record = _record(nodes=1)
    with pytest.raises(ValueError, match="authenticate must be a boolean"):
        _session(tmp_path / "auth", record, FakeProbe([True]), authenticate=None)


def test_runtime_rejects_unapproved_listener_bind_address(tmp_path):
    record = _record(nodes=1)
    with pytest.raises(ValueError, match="unsupported listener bind address"):
        _session(tmp_path / "bind", record, FakeProbe([True]), bind_address="192.0.2.1")


def test_runtime_rejects_invalid_constructor_contracts(tmp_path):
    record = _record(nodes=1)
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    manager = FakeBackendManager(tmp_path / "mihomo")
    subscriptions = FakeSubscriptionManager(record)
    cases = (
        ("listener_protocol", {"listener_protocol": "tcp"}, "unsupported local proxy protocol"),
        ("preferred_port", {"preferred_port": True}, "preferred port"),
        ("strict_port", {"strict_port": 1}, "strict_port"),
        ("authenticate", {"authenticate": 1}, "authenticate"),
        ("log_level", {"log_level": "TRACE"}, "JerryProxy log level"),
        ("backend_log_level", {"backend_log_level": "TRACE"}, "backend log level"),
        ("session_id", {"session_id": "UPPER"}, "session_id"),
    )
    for name, options, message in cases:
        del name
        with pytest.raises((TypeError, ValueError), match=message):
            RuntimeSession(paths, manager=manager, subscription_manager=subscriptions, **options)
    with pytest.raises(TypeError, match="mutually exclusive"):
        RuntimeSession(
            paths,
            manager=manager,
            subscription_manager=subscriptions,
            process_factory=FakeProcess,
            driver=object(),
        )


@pytest.mark.parametrize(
    "value",
    ["not-a-timestamp", "2026-08-04T00:00:00"],
)
def test_runtime_rejects_invalid_subscription_timestamp(tmp_path, value):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    with pytest.raises(SubscriptionStateError, match="timestamp"):
        runtime._is_stale(replace(record, updated_at=value))


def test_runtime_public_info_is_credential_free_before_start(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]), authenticate=True)
    info = runtime.public_info()
    assert info["session"] == runtime.session_id
    assert info["backend"] == "mihomo"
    assert info["listener"]["port"] is None
    assert info["listener"]["authentication"] is True
    assert info["subscription"] is None
    assert "password" not in json.dumps(info, sort_keys=True)


def test_runtime_rejects_disabled_subscription_and_unknown_node(tmp_path):
    record = _record(nodes=1)
    disabled = replace(record, enabled=False)
    runtime = _session(tmp_path / "disabled", disabled, FakeProbe([True]))
    with pytest.raises(SubscriptionStateError, match="disabled"):
        runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)

    runtime = _session(tmp_path / "unknown", record, FakeProbe([True]))
    with pytest.raises(SubscriptionStateError, match="node not found"):
        runtime.start("main", node_id="f" * 32, install_missing=False)


def test_runtime_rejects_a_source_without_nodes(tmp_path):
    with pytest.raises(SubscriptionStateError, match="node collection"):
        RuntimeSession._select_node(object(), None)


def test_runtime_log_sink_failures_are_bounded_and_nonfatal(tmp_path):
    record = _record(nodes=1)

    def fail_sink(*event):
        del event
        raise ValueError("closed terminal")

    runtime = _session(tmp_path, record, FakeProbe([True]), log_sink=fail_sink)
    runtime._log("DEBUG", "filtered")
    runtime._log("INFO", "visible")
    runtime._log("INFO", "")
    assert runtime._log_errors == []


def test_runtime_bootstraps_missing_backend_through_manager_install(tmp_path):
    record = _record(nodes=1)

    class InstallingManager(FakeBackendManager):
        def which(self, name, version):
            del name, version
            raise BackendNotInstalledError("missing")

        def install(self, name, version, **kwargs):
            assert name == "mihomo"
            assert version == "1.19.29"
            assert kwargs["activate"] is False
            return Installed(self.executable)

    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    runtime = RuntimeSession(
        paths,
        manager=InstallingManager(tmp_path / "mihomo"),
        subscription_manager=FakeSubscriptionManager(record),
        health_probe=FakeProbe([True]),
        process_factory=FakeProcess,
        recovery_policy=RecoveryPolicy(startup_retry_delays=(0.0,), recovery_deadline=10.0),
    )
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=True)
    assert runtime.executable == tmp_path / "mihomo"
    runtime.stop()


def test_runtime_cleanup_failure_is_reported_and_retains_lock(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.process = FakeProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log", "INFO")
    runtime._enter_operation_lock()
    runtime.process.start()
    runtime.driver = type(
        "FailingDriver",
        (),
        {"stop": lambda self, process, timeout=None: (_ for _ in ()).throw(RuntimeError("stop failed"))},
    )()
    with pytest.raises(RuntimeSessionError, match="cleanup failed"):
        runtime._stop_process()
    assert runtime._operation_lock is not None
    runtime._leave_operation_lock()


def test_runtime_recovery_can_select_an_alternate_node(tmp_path):
    record = _record(nodes=2, source_url="https://provider.invalid/source")
    policy = RecoveryPolicy(
        health_interval=1.0,
        startup_retry_delays=(0.0,),
        recovery_deadline=10.0,
        same_node_delay=0.0,
        alternate_delays=(0.0, 0.0),
        refresh_on_failure=False,
    )

    runtime = _session(
        tmp_path,
        record,
        FakeProbe([True, False, True]),
        policy=policy,
    )
    initial_node_id = record.nodes[0].node_id
    runtime.start("main", node_id=initial_node_id, install_missing=False)
    runtime._recover()
    assert runtime.preference_node_id == initial_node_id
    assert runtime.node.node_id != initial_node_id
    assert runtime.node.node_id in {node.node_id for node in record.nodes}
    runtime.stop()


def test_runtime_rejects_unknown_subscription_and_releases_lock(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    with pytest.raises(Exception, match="subscription not found"):
        runtime.start("missing", node_id=record.nodes[0].node_id, install_missing=False)
    assert runtime._operation_lock is None
    assert runtime.process is None


def test_runtime_requires_explicit_node_for_multiple_nodes(tmp_path):
    record = _record(nodes=2)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    with pytest.raises(Exception, match="multiple nodes require"):
        runtime.start("main", install_missing=False)
    assert runtime._operation_lock is None


def test_runtime_rejects_multiple_enabled_subscriptions(tmp_path):
    first = _record("first", nodes=1)
    second = _record("second", nodes=1)

    class Subscriptions(FakeSubscriptionManager):
        def list(self):
            return (first, second)

    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    runtime = RuntimeSession(
        paths,
        manager=FakeBackendManager(tmp_path / "mihomo"),
        subscription_manager=Subscriptions(first),
        health_probe=FakeProbe([True]),
    )
    with pytest.raises(Exception, match="multiple subscriptions"):
        runtime.start(node_id=first.nodes[0].node_id, install_missing=False)
    assert runtime._operation_lock is None


def test_runtime_start_failure_removes_private_lease_and_stops_process(tmp_path):
    record = _record(nodes=1)
    events = []

    runtime = _session(
        tmp_path,
        record,
        FakeProbe([False]),
        policy=RecoveryPolicy(startup_retry_delays=(0.0,), recovery_deadline=10.0),
        log_sink=lambda *event: events.append(event),
    )
    with pytest.raises(RuntimeSessionError, match="connectivity quorum failed"):
        runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)
    assert runtime.process is None
    assert not runtime.session_root.exists()
    assert runtime._operation_lock is None
    assert any(event[1] == "ERROR" for event in events)


def test_runtime_health_check_rejects_missing_or_invalid_probe(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.port = None
    with pytest.raises(RuntimeSessionError, match="not configured"):
        runtime._check_health()
    runtime.port = 17777
    runtime.health_probe = object()
    with pytest.raises(RuntimeSessionError, match="unavailable"):
        runtime._check_health()


def test_runtime_health_check_rejects_invalid_probe_result(tmp_path):
    record = _record(nodes=1)

    class InvalidProbe(object):
        def check(self, port, username, password):
            del port, username, password
            return object()

    runtime = _session(tmp_path, record, InvalidProbe())
    runtime.port = 17777
    with pytest.raises(RuntimeSessionError, match="invalid result"):
        runtime._check_health()


def test_runtime_wait_returns_backend_exit_code(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.process = FakeProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log", "INFO")
    runtime.process.process.returncode = 17
    assert runtime.wait() == 17


def test_runtime_wait_converts_keyboard_interrupt_to_sigint_status(tmp_path):
    record = _record(nodes=1)
    runtime = _session(
        tmp_path,
        record,
        FakeProbe([True]),
        sleeper=lambda delay: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    runtime.process = FakeProcess(tmp_path / "mihomo", tmp_path / "config", tmp_path, tmp_path / "log", "INFO")
    runtime._next_health_at = runtime.clock() + 100.0
    assert runtime.wait() == 130
    assert runtime.process is None


def test_runtime_stop_is_idempotent_without_started_session(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.stop()
    runtime.stop()
    assert runtime.process is None


def test_foreground_session_holds_the_home_wide_lock_until_cleanup(tmp_path):
    record = _record(nodes=1)
    runtime = _session(tmp_path, record, FakeProbe([True]))
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)
    code = """
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock
from jerryproxy.errors import JerryProxyBusyError
paths = JerryProxyPaths(%r)
try:
    with JerryProxyOperationLock(paths, initialize=False):
        raise SystemExit(0)
except JerryProxyBusyError:
    raise SystemExit(3)
""" % str(runtime.paths.root)
    repository = Path(__file__).resolve().parents[2]
    blocked = subprocess.run([sys.executable, "-c", code], cwd=str(repository), check=False)
    assert blocked.returncode == 3
    runtime.stop()
    available = subprocess.run([sys.executable, "-c", code], cwd=str(repository), check=False)
    assert available.returncode == 0


def test_runtime_accepts_a_driver_without_changing_session_ownership(tmp_path):
    class FakeDriver(RuntimeDriver):
        @property
        def name(self):
            return "mihomo"

        def projection(
            self,
            provider_path,
            node,
            port,
            username,
            password,
            listener_protocol,
            backend_log_level,
            bind_address="127.0.0.1",
        ):
            del provider_path, node, port, username, password, listener_protocol, backend_log_level, bind_address
            return RuntimeProjection(config=b"fake-config\n", provider=b"fake-provider\n")

        def create_process(self, executable, config_path, session_root, log_path, backend_log_level, log_sink=None):
            del log_sink
            return FakeProcess(executable, config_path, session_root, log_path, backend_log_level)

        def wait_ready(self, process, port, timeout):
            del process, port, timeout

        def stop(self, process, timeout=None):
            del timeout
            process.stop()

    record = _record(nodes=1)
    runtime = RuntimeSession(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        manager=FakeBackendManager(tmp_path / "mihomo"),
        subscription_manager=FakeSubscriptionManager(record),
        health_probe=FakeProbe([True]),
        driver=FakeDriver(),
        recovery_policy=RecoveryPolicy(
            startup_retry_delays=(0.0,),
            recovery_deadline=10.0,
        ),
        sleeper=lambda delay: None,
    )
    runtime.paths.ensure()
    runtime.executable = tmp_path / "mihomo"
    runtime.executable.write_bytes(b"fake")
    runtime.start("main", node_id=record.nodes[0].node_id, install_missing=False)
    assert runtime.public_info()["backend"] == "mihomo"
    assert runtime.config_path.read_bytes() == b"fake-config\n"
    runtime.stop()


def test_recovery_restarts_current_then_uses_alternate_without_changing_preference(tmp_path):
    record = _record(nodes=2)
    first, second = record.nodes
    runtime = _session(tmp_path, record, FakeProbe([True, False, True]))
    runtime.start("main", node_id=first.node_id, install_missing=False)

    runtime._recover()

    assert runtime.preference_node_id == first.node_id
    assert runtime.node.node_id == second.node_id
    runtime.stop()


def test_recovery_refreshes_source_once_after_candidate_exhaustion(tmp_path):
    original = _record(nodes=1, source_url="https://example.invalid/sub")
    refreshed = _record(nodes=2, source_url="https://example.invalid/sub")
    manager = FakeSubscriptionManager(original, refreshed=refreshed)
    runtime = _session(tmp_path, original, FakeProbe([True, False, True]), manager=manager)
    runtime.start("main", node_id=original.nodes[0].node_id, install_missing=False)

    runtime._recover()

    assert manager.refresh_calls == 1
    assert runtime.subscription.revision == refreshed.revision
    assert runtime.preference_node_id == original.nodes[0].node_id
    assert runtime.node.node_id != original.nodes[0].node_id
    runtime.stop()


def test_recovery_skips_disabled_or_stale_alternates(tmp_path):
    record = _record(nodes=3)
    disabled = replace(record, enabled=False)
    runtime = _session(tmp_path, disabled, FakeProbe([True]), policy=RecoveryPolicy(
        startup_retry_delays=(0.0,),
        same_node_delay=0.0,
        alternate_delays=(0.0,),
        recovery_deadline=10.0,
    ))
    runtime.subscription = disabled
    runtime.node = disabled.nodes[0]
    assert runtime._eligible_alternates(disabled, {runtime.node.node_id}) == ()

    stale = replace(
        record,
        updated_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
    )
    runtime.subscription = stale
    assert runtime._eligible_alternates(stale, {stale.nodes[0].node_id}) == ()


def test_failed_recovery_candidate_does_not_replace_effective_node(tmp_path):
    record = _record(nodes=2)
    first, second = record.nodes
    runtime = _session(tmp_path, record, FakeProbe([True, False]), policy=RecoveryPolicy(
        startup_retry_delays=(0.0,),
        same_node_delay=0.0,
        alternate_delays=(0.0,),
        recovery_deadline=10.0,
    ))
    runtime.start("main", node_id=first.node_id, install_missing=False)
    deadline = RecoveryDeadline(10.0)
    assert not runtime._try_candidate(second, deadline)
    assert runtime.node.node_id == first.node_id
    runtime.stop()


def _drifted(record):
    """Return a record whose stored projection no longer matches its source.

    A JerryProxy upgrade can change how a node display is derived from the same
    digest-protected bytes.  Nothing is tampered with, but a fresh parse then
    stops reproducing the persisted projection.
    """

    nodes = tuple(replace(node, display="stale-%s" % node.display) for node in record.nodes)
    return replace(record, nodes=nodes)


class DriftingSubscriptionManager(FakeSubscriptionManager):
    """Serve a drifted record and delegate repair like the real manager does."""

    def __init__(self, drifted, repaired=None, failure=None):
        super(DriftingSubscriptionManager, self).__init__(drifted)
        self.repaired = repaired
        self.failure = failure
        self.repair_calls = 0

    def _repair_node_projection_locked(self, name):
        # The session owns the home lock, so it must reach the private locked
        # helper rather than a public entry point that would take it again.
        assert name == self.record.name
        self.repair_calls += 1
        if self.failure is not None:
            raise self.failure
        return self.repaired


def test_startup_repairs_a_drifted_node_projection_exactly_once(tmp_path):
    healthy = _record(nodes=1, source_url="https://provider.example/secret")
    manager = DriftingSubscriptionManager(_drifted(healthy), repaired=healthy)
    events = []
    runtime = _session(
        tmp_path,
        manager.record,
        FakeProbe([True]),
        manager=manager,
        log_sink=lambda *event: events.append(event),
    )

    runtime.start("main", install_missing=False)

    # Exactly one repair, and the session continues with the repaired record.
    assert manager.repair_calls == 1
    assert runtime.subscription.nodes[0].display == healthy.nodes[0].display
    assert runtime.node.node_id == healthy.nodes[0].node_id
    assert any(
        level == "WARN" and "no longer matches its source bytes" in message
        for _source, level, message in events
    )
    assert any(
        level == "INFO" and "refreshed; continuing startup" in message
        for _source, level, message in events
    )
    runtime.stop()


def test_startup_does_not_repair_a_consistent_subscription(tmp_path):
    healthy = _record(nodes=1, source_url="https://provider.example/secret")
    manager = DriftingSubscriptionManager(healthy, repaired=healthy)
    runtime = _session(tmp_path, healthy, FakeProbe([True]), manager=manager)

    runtime.start("main", node_id=healthy.nodes[0].node_id, install_missing=False)

    # A consistent projection must never contact the source during startup.
    assert manager.repair_calls == 0
    runtime.stop()


def test_startup_stops_when_a_drift_repair_fails(tmp_path):
    drifted = _drifted(_record(nodes=1, source_url="https://provider.example/secret"))
    manager = DriftingSubscriptionManager(
        drifted,
        failure=SubscriptionStateError(
            "subscription nodes do not match source bytes: main; refreshing its saved source failed, "
            "so run `jerryproxy subscription refresh main` or replace the source"
        ),
    )
    runtime = _session(tmp_path, drifted, FakeProbe([True]), manager=manager)

    with pytest.raises(SubscriptionStateError, match="subscription refresh main") as failure:
        runtime.start("main", install_missing=False)

    # One attempt only; the session must not retry a repair that already failed.
    assert manager.repair_calls == 1
    assert "provider.example" not in str(failure.value)


def test_startup_names_the_node_listing_command_for_a_vanished_node(tmp_path):
    record = _record(nodes=2)
    runtime = _session(tmp_path, record, FakeProbe([True]))

    with pytest.raises(SubscriptionStateError, match="node list main"):
        runtime.start("main", node_id="f" * 32, install_missing=False)


def test_direct_node_source_keeps_a_plain_missing_node_message(tmp_path):
    """A direct-node source has no subscription, so it names no listing command."""

    record = _record(nodes=1)
    source = SingleNodeSource(record.nodes[0])
    runtime = _session(tmp_path, record, FakeProbe([True]))

    with pytest.raises(SubscriptionStateError) as failure:
        runtime._select_node(source, node_id="f" * 32)

    assert "node list" not in str(failure.value)
    assert runtime._select_node(source) is record.nodes[0]


class _UpgradedParser(V2RaySubscriptionParser):
    """Stand in for a release that classifies the same bytes differently."""

    def parse(self, body, format_hint="auto"):
        parsed = super(_UpgradedParser, self).parse(body, format_hint=format_hint)
        records = tuple((scheme, display + "-upgraded", uri) for scheme, display, uri in parsed.records)
        return ParsedSubscription(parsed.format, parsed.body, records)


def test_startup_repairs_drift_through_the_session_home_lock(tmp_path, monkeypatch):
    """Repair must reach the manager's locked helper, not a second acquisition.

    The session already owns the home-wide lock, so a repair that took the lock
    again would fail closed on every real drifted start while a fake manager
    kept the suite green.
    """

    body = URI_TEMPLATE.encode("ascii") % (443, 0)
    monkeypatch.setattr(
        "jerryproxy.subscription.manager.fetch_subscription",
        lambda *args, **kwargs: FetchedSubscription(body, "https://provider.example/secret"),
    )
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    # Publish through an upgraded parser so the shipped parser sees real drift.
    SubscriptionManager(paths, parser=_UpgradedParser()).add(
        "main", "https://provider.example/secret", format_hint="uri-lines"
    )
    shipped = SubscriptionManager(paths)
    with pytest.raises(SubscriptionNodesMismatchError):
        shipped.get("main")

    runtime = _session(tmp_path, None, FakeProbe([True]), manager=shipped)
    runtime.start("main", install_missing=False)
    selected = runtime.subscription
    node = runtime.node
    # The session holds the home lock until it stops, so any public read here
    # would fail closed; that is exactly the contract this test protects.
    runtime.stop()

    repaired = shipped.get("main")
    assert not selected.nodes[0].display.endswith("-upgraded")
    assert selected.revision == repaired.revision
    assert node.node_id == repaired.nodes[0].node_id
