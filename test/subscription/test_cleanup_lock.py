"""Unconfirmed subscription workers must retain the caller's home lock."""

import threading
import time

import pytest

import jerryproxy.subscription.manager as manager_module
from jerryproxy.errors import JerryProxyBusyError, SubscriptionFetchError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock
from jerryproxy.subscription import SubscriptionManager

from .test_refresh_budget import worker_boundary as worker_boundary


def _wait_for_manager_cleanup(manager):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            return manager.list()
        except SubscriptionFetchError:
            # A cleanup-in-progress refusal is expected until the worker stops.
            time.sleep(0.01)
    pytest.fail("subscription cleanup did not finish")


@pytest.fixture
def late_worker(monkeypatch):
    release = threading.Event()

    class Process:
        exitcode = None

        def start(self):
            release.wait(2)
            self.exitcode = 0

        def is_alive(self):
            return not release.is_set()

        def join(self, timeout):
            pass

        def terminate(self):
            pass

        def kill(self):
            pass

    class Context:
        Event = threading.Event

        def Process(self, **kwargs):
            return Process()

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda method: Context())
    monkeypatch.setattr(manager_module, "_FETCH_START_SECONDS", 0.005)
    monkeypatch.setattr(manager_module, "_FETCH_STOP_SECONDS", 0.005)
    try:
        yield release
    finally:
        release.set()


def test_public_add_keeps_lock_until_late_worker_and_artifacts_are_gone(tmp_path, late_worker):
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / "home"))
    with pytest.raises(SubscriptionFetchError, match="cleanup"):
        manager.add("main", "https://provider.invalid/sub?token=private")
    with pytest.raises(JerryProxyBusyError):
        with JerryProxyOperationLock(manager.paths):
            pass
    with pytest.raises(SubscriptionFetchError, match="cleanup"):
        manager.list()
    late_worker.set()
    deadline = time.monotonic() + 2
    while tuple(manager.paths.runtimes.glob(".subscription-fetch-*")) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))
    assert _wait_for_manager_cleanup(manager) == ()
    with JerryProxyOperationLock(manager.paths):
        pass


def test_runtime_does_not_release_its_lock_or_emit_stopped_during_pending_refresh(tmp_path, late_worker):
    from jerryproxy.errors import RuntimeSessionError
    from jerryproxy.runtime import RecoveryPolicy
    from test.runtime.test_persistent import Clock, Probe
    from test.runtime.test_session import FakeSubscriptionManager, _record, _session

    record = _record(nodes=1, source_url="https://provider.invalid/sub?token=private")
    clock = Clock()
    worker_manager = SubscriptionManager(JerryProxyPaths(tmp_path / ".jerryproxy"))

    class Manager(FakeSubscriptionManager):
        def refresh(self, name, timeout=None):
            return worker_manager._fetch_remote(self.record.source_url, False, "uri-lines", timeout=timeout)

        def _require_fetch_cleanup(self):
            worker_manager._require_fetch_cleanup()

    session = _session(tmp_path, record, Probe(lambda: False), manager=Manager(record),
                       clock=clock, sleeper=clock.sleep, policy=RecoveryPolicy(retry_policy="fixed"))
    events = []
    session.event_sink = events.append
    try:
        with pytest.raises(RuntimeSessionError, match="cleanup"):
            session.start("main", record.nodes[0].node_id, install_missing=False)
        assert not any(event["event"] == "session.stopped" for event in events)
        assert session._operation_lock is not None
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(session.paths):
                pass
        with pytest.raises(RuntimeSessionError, match="cleanup"):
            session.stop()
    finally:
        late_worker.set()
        deadline = time.monotonic() + 2
        while tuple(session.paths.runtimes.glob(".subscription-fetch-*")) and time.monotonic() < deadline:
            time.sleep(0.01)
        while True:
            try:
                session.stop()
                break
            except RuntimeSessionError:
                # The supervisor may still be publishing its completion verdict.
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
    assert session._operation_lock is None
    assert events[-1]["event"] == "session.stopped"


def test_supervisor_start_failure_keeps_pending_ownership(tmp_path, late_worker, monkeypatch):
    original = threading.Thread.start

    def reject_cleanup(thread):
        if thread.name == "jerryproxy-subscription-cleanup":
            raise RuntimeError("thread creation denied")
        original(thread)

    monkeypatch.setattr(threading.Thread, "start", reject_cleanup)
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / "home"))
    with pytest.raises(SubscriptionFetchError, match="supervisor unavailable"):
        manager.add("main", "https://provider.invalid/sub")
    with pytest.raises(SubscriptionFetchError, match="cleanup remains unconfirmed"):
        manager.get("main")
    with pytest.raises(JerryProxyBusyError):
        with JerryProxyOperationLock(manager.paths):
            pass
    assert tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))


def test_artifact_removal_failure_retains_original_operation_lock(tmp_path, monkeypatch, worker_boundary):
    from .test_refresh_budget import _manager
    manager, record = _manager(tmp_path, monkeypatch, [None])
    release = threading.Event()
    original = manager_module._secure_remove_tree

    def denied(root, path, *args, **kwargs):
        if threading.current_thread() is threading.main_thread():
            raise PermissionError("removal denied")
        release.wait(2)
        original(root, path, *args, **kwargs)

    monkeypatch.setattr(manager_module, "_secure_remove_tree", denied)
    try:
        with pytest.raises(SubscriptionFetchError, match="cleanup failed"):
            manager.refresh("main")
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(manager.paths):
                pass
    finally:
        release.set()
    deadline = time.monotonic() + 2
    while tuple(manager.paths.runtimes.glob(".subscription-fetch-*")) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))
    _wait_for_manager_cleanup(manager)
    assert manager.get("main").revision == record.revision


def test_interrupt_during_worker_join_stops_child_before_unlocking(tmp_path, monkeypatch):
    class Process:
        alive = False
        joined = False
        exitcode = None

        def start(self):
            self.alive = True

        def is_alive(self):
            return self.alive

        def join(self, timeout):
            if not self.joined:
                self.joined = True
                raise KeyboardInterrupt

        def terminate(self):
            self.alive = False
            self.exitcode = -15

    child = Process()

    class Context:
        Event = threading.Event

        def Process(self, **kwargs):
            return child

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda method: Context())
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / "home"))
    with pytest.raises(KeyboardInterrupt):
        manager.add("main", "https://provider.invalid/sub")
    assert child.joined and not child.alive
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))
    with JerryProxyOperationLock(manager.paths):
        pass


def test_discarding_failed_manager_does_not_release_unconfirmed_home(tmp_path, late_worker):
    import gc
    import weakref

    paths = JerryProxyPaths(tmp_path / "home")
    manager = SubscriptionManager(paths)
    try:
        manager.add("main", "https://provider.invalid/sub")
    except SubscriptionFetchError:
        # The caller may drop both the failed manager and its exception.
        pass
    retained = weakref.ref(manager._retained_operation_lock)
    del manager
    gc.collect()
    try:
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(paths):
                pass
        assert retained() is not None
    finally:
        late_worker.set()
        deadline = time.monotonic() + 2
        while tuple(paths.runtimes.glob(".subscription-fetch-*")) and time.monotonic() < deadline:
            time.sleep(0.01)
        # Test teardown explicitly ends ownership only after real cleanup.
        if retained() is not None:
            retained().__exit__(None, None, None)


def test_interrupted_starter_join_cannot_hide_pending_process_start(tmp_path, monkeypatch):
    """Model old CPython's interrupted join reporting a live starter as dead."""
    release = threading.Event()
    stopped = threading.Event()
    poisoned = set()
    original_join = threading.Thread.join
    original_alive = threading.Thread.is_alive

    class Process:
        exitcode = None
        launched = False

        def start(self):
            release.wait(2)
            self.launched = True

        def is_alive(self):
            return self.launched and not stopped.is_set()

        def join(self, timeout):
            pass

        def terminate(self):
            stopped.set()
            self.exitcode = -15

    class Context:
        Event = threading.Event

        def Process(self, **kwargs):
            return Process()

    def interrupted_join(thread, timeout=None):
        if (threading.current_thread() is threading.main_thread()
                and thread.name == "jerryproxy-subscription-start" and not release.is_set()):
            poisoned.add(thread)
            raise KeyboardInterrupt
        return original_join(thread, timeout)

    monkeypatch.setattr(threading.Thread, "join", interrupted_join)
    monkeypatch.setattr(threading.Thread, "is_alive",
                        lambda thread: False if thread in poisoned else original_alive(thread))
    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda method: Context())
    monkeypatch.setattr(manager_module, "_FETCH_START_SECONDS", 0.005)
    monkeypatch.setattr(manager_module, "_FETCH_STOP_SECONDS", 0.005)
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / "home"))
    try:
        with pytest.raises((KeyboardInterrupt, SubscriptionFetchError)):
            manager.add("main", "https://provider.invalid/sub")
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(manager.paths):
                pass
        assert tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))
    finally:
        release.set()
        # Restore accurate thread state for the independent cleanup owner.
        poisoned.clear()
    _wait_for_manager_cleanup(manager)
    assert stopped.is_set()
