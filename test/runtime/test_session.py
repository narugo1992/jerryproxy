import re
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from jerryproxy.errors import RuntimeSessionError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.runtime import (
    HealthSnapshot,
    RecoveryPolicy,
    RuntimeDriver,
    RuntimeProjection,
    RuntimeSession,
)
from jerryproxy.runtime.health import RecoveryDeadline
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import parse_subscription_body

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
    assert '"username":null' in access
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
