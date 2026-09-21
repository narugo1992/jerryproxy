"""Lifecycle events describe public session behavior, including failed cleanup."""

import json
import random

import pytest

from jerryproxy.errors import RuntimeSessionError
from jerryproxy.runtime import RecoveryPolicy

from .test_persistent import Clock, Probe, ReloadingDriver
from .test_session import _record, _session


def test_startup_events_do_not_publish_ready_before_success(tmp_path):
    clock = Clock()
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: clock.now >= 20),
                       clock=clock, sleeper=clock.sleep, authenticate=True,
                       policy=RecoveryPolicy(retry_policy="fixed"))
    session.driver = ReloadingDriver()
    events = []
    session._backoff.rng = random.Random(0)

    def capture(event):
        if event["event"] == "session.ready":
            assert session.access_path.exists()
            assert session.last_health.ok
        if event["event"] == "session.stopped":
            assert not session.session_root.exists()
            assert session.process is None
        events.append(event)

    session.event_sink = capture
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
    finally:
        session.stop()
    session.stop()
    names = [event["event"] for event in events]
    assert names[0] == "session.starting"
    assert names[1] == "session.degraded"
    assert names[-2:] == ["session.ready", "session.stopped"]
    assert names.count("session.ready") == names.count("session.stopped") == 1
    for event in events[:-2]:
        assert event["data"]["node"] is None
        assert not event["data"]["health"]["ok"]
    ready = events[-2]["data"]
    assert ready["node"] == ready["loaded_node"] == record.nodes[0].node_id
    assert ready["attempts"] >= 2 and ready["rounds"] >= 1
    delays = [event["data"]["delay"] for event in events if event["data"]["delay"]]
    assert delays == clock.delays[1:]
    assert {event["data"]["reason"] for event in events} & {"candidates_cooling", "no_alternates"}
    persisted = session.log_path.read_text()
    assert '"event":"session.stopped"' in persisted
    for secret in (session.password, session.control_secret):
        assert secret not in json.dumps(events)
        assert secret not in persisted


def test_none_reports_degradation_and_stopped_without_ready(tmp_path):
    clock = Clock()
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: False), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(retry_policy="none"))
    events = []
    session.event_sink = events.append
    with pytest.raises(RuntimeSessionError, match="policy is none"):
        session.start("main", record.nodes[0].node_id, install_missing=False)
    assert [event["event"] for event in events] == [
        "session.starting", "session.degraded", "session.stopped",
    ]


def test_periodic_events_keep_last_healthy_node_until_recovery(tmp_path):
    clock = Clock()
    record = _record(nodes=2)
    driver = ReloadingDriver()
    wanted = (record.nodes[1].secret_uri() + "\n").encode("utf-8")

    def healthy():
        if driver.loaded == wanted:
            session.process.process.returncode = 0
            return True
        return clock.now == 0

    session = _session(tmp_path, record, Probe(healthy), clock=clock, sleeper=clock.sleep,
                       policy=RecoveryPolicy(health_interval=1, confirmation_delay=1))
    session.driver = driver
    events = []
    session.event_sink = events.append
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.wait() == 0
    finally:
        session.stop()
    names = [event["event"] for event in events]
    assert names.count("session.ready") == 2
    degraded = next(event["data"] for event in events if event["event"] == "session.degraded")
    assert degraded["node"] == record.nodes[0].node_id
    ready = [event["data"] for event in events if event["event"] == "session.ready"][-1]
    assert ready["node"] == ready["loaded_node"] == record.nodes[1].node_id
    assert ready["preference_node"] == record.nodes[0].node_id
    assert ready["health"]["ok"]


def test_failed_cleanup_never_announces_stopped(tmp_path, monkeypatch):
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: True))
    events = []
    session.event_sink = events.append
    session.start("main", record.nodes[0].node_id, install_missing=False)
    original = session.driver.stop

    def fail_stop(process, timeout=2.0):
        raise RuntimeSessionError("unconfirmed stop")

    monkeypatch.setattr(session.driver, "stop", fail_stop)
    with pytest.raises(RuntimeSessionError, match="backend cleanup failed"):
        session.stop()
    assert not any(event["event"] == "session.stopped" for event in events)
    assert session._operation_lock is not None
    monkeypatch.setattr(session.driver, "stop", original)
    session.stop()
    assert events[-1]["event"] == "session.stopped"


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_closed_event_sink_does_not_interrupt_service(tmp_path, error_type):
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: True))
    called = []

    def closed(event):
        called.append(event)
        raise error_type("closed output")

    session.event_sink = closed
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        assert session.last_health.ok
    finally:
        session.stop()
    assert len(called) == 3


@pytest.mark.parametrize("outcome", ["unchanged", "transport", "changed"])
def test_refresh_events_distinguish_stale_cache_and_refresh_result(tmp_path, outcome):
    from dataclasses import replace

    from jerryproxy.errors import SubscriptionTransportError

    from .test_session import FakeSubscriptionManager

    record = replace(_record(nodes=1, source_url="https://provider.invalid/sub?token=hidden"),
                     updated_at="2020-01-01T00:00:00+00:00")

    class Manager(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            if outcome == "transport":
                raise SubscriptionTransportError("temporary")
            if outcome == "changed":
                return _record(nodes=2, source_url=record.source_url)
            return record

    session = _session(tmp_path, record, Probe(lambda: True), manager=Manager(record))
    events = []
    session.event_sink = events.append
    try:
        session.start("main", record.nodes[0].node_id, install_missing=False)
        refresh = [event for event in events if event["event"] == "session.refresh"]
        assert [event["data"]["reason"] for event in refresh] == [
            "cache_stale", {"unchanged": "refresh_unchanged", "changed": "refresh_updated",
                            "transport": "refresh_transport_failed"}[outcome],
        ]
        assert all(event["data"]["state"] == "starting" for event in refresh)
        assert "hidden" not in json.dumps(events)
        assert sum(event["event"] == "session.ready" for event in events) == 1
    finally:
        session.stop()


@pytest.mark.parametrize("during_start", [False, True])
def test_artifact_cleanup_failure_retains_lock_and_omits_stopped(tmp_path, monkeypatch, during_start):
    import jerryproxy.runtime.session as session_module

    clock = Clock()
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: not during_start),
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy(retry_policy="none"))
    events = []
    session.event_sink = events.append
    remove = session_module._remove_private_tree

    def fail_remove(root):
        raise PermissionError("cleanup denied")

    if not during_start:
        session.start("main", record.nodes[0].node_id, install_missing=False)
    monkeypatch.setattr(session_module, "_remove_private_tree", fail_remove)
    with pytest.raises(RuntimeSessionError, match="cleanup failed"):
        if during_start:
            session.start("main", record.nodes[0].node_id, install_missing=False)
        else:
            session.stop()
    assert session._operation_lock is not None
    assert session.session_root.exists()
    assert not any(event["event"] == "session.stopped" for event in events)
    monkeypatch.setattr(session_module, "_remove_private_tree", remove)
    session.stop()
    assert events[-1]["event"] == "session.stopped"
    assert session._operation_lock is None


def test_wait_without_start_does_not_emit_readiness(tmp_path):
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: True))
    events = []
    session.event_sink = events.append
    with pytest.raises(RuntimeSessionError, match="not running"):
        session.wait()
    session.stop()
    assert events == []
