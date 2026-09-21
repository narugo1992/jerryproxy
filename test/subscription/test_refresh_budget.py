"""Public refresh preserves classified failures across the worker boundary."""

import json
import threading
from pathlib import Path

import pytest

import jerryproxy.subscription.manager as manager_module
from jerryproxy.errors import SubscriptionFetchError, SubscriptionTransportError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.subscription import SubscriptionManager
from jerryproxy.subscription.transport import FetchedSubscription

from .test_storage import SS


@pytest.fixture
def worker_boundary(monkeypatch):
    """Deterministically execute the real worker and private envelope reader."""
    joins = []

    class Gate(object):
        def __init__(self):
            self.value = False

        def wait(self, timeout):
            return True

        def set(self):
            self.value = True

        def is_set(self):
            return self.value

    class Process(object):
        def __init__(self, target, args):
            self.target, self.args = target, args
            self.exitcode = None

        def start(self):
            self.target(*self.args)
            self.exitcode = 0

        def join(self, timeout):
            joins.append(timeout)

        def is_alive(self):
            return False

    class Context(object):
        Event = Gate

        def Process(self, target, args):
            return Process(target, args)

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda method: Context())
    return joins


def _manager(tmp_path, monkeypatch, outcome):
    def transport(url, **kwargs):
        if outcome[0] is not None:
            raise outcome[0]
        return FetchedSubscription(SS, url)

    # Force the production worker path while replacing only network I/O.
    monkeypatch.setattr(manager_module, "fetch_subscription", transport)
    monkeypatch.setattr(manager_module, "_DEFAULT_FETCH_SUBSCRIPTION", transport)
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / "home"))
    record = manager.add("main", "https://provider.example/private?token=secret")
    return manager, record


@pytest.mark.parametrize("retryable", [True, False])
def test_worker_preserves_retry_classification_and_last_good_revision(
    tmp_path, monkeypatch, worker_boundary, retryable,
):
    outcome = [None]
    manager, original = _manager(tmp_path, monkeypatch, outcome)
    outcome[0] = SubscriptionTransportError("secret", 450) if retryable else SubscriptionFetchError("secret")
    with pytest.raises(SubscriptionFetchError) as failure:
        manager.refresh("main", timeout=0.5)
    assert isinstance(failure.value, SubscriptionTransportError) is retryable
    if retryable:
        assert failure.value.retry_after == 450
    assert "secret" not in str(failure.value)
    assert manager.get("main").revision == original.revision
    assert 0 < worker_boundary[-1] <= 0.5
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))


@pytest.mark.parametrize("value", [True, -1, "secret", 86401, float("nan"), float("inf")])
def test_worker_cannot_smuggle_invalid_retry_metadata(tmp_path, monkeypatch, worker_boundary, value):
    manager, original = _manager(tmp_path, monkeypatch, [None])

    def malformed(url, result_path, *args):
        path = Path(result_path)
        path.write_text(json.dumps({"ok": False, "error": "transport", "retry_after": value}))
        path.chmod(0o600)

    monkeypatch.setattr(manager_module, "_fetch_worker", malformed)
    with pytest.raises(SubscriptionFetchError, match="retry result is invalid") as failure:
        manager.refresh("main")
    assert not isinstance(failure.value, SubscriptionTransportError)
    assert manager.get("main").revision == original.revision


@pytest.mark.parametrize("timeout", [True, 0, -1, "1", float("nan"), float("inf")])
def test_refresh_budget_is_validated_before_network(tmp_path, monkeypatch, worker_boundary, timeout):
    manager, original = _manager(tmp_path, monkeypatch, [None])
    count = len(worker_boundary)
    with pytest.raises(ValueError, match="timeout"):
        manager.refresh("main", timeout=timeout)
    assert len(worker_boundary) == count
    assert manager.get("main").revision == original.revision


def test_timed_out_worker_is_retryable_only_after_confirmed_stop(tmp_path, monkeypatch, worker_boundary):
    manager, original = _manager(tmp_path, monkeypatch, [None])
    observed = []

    class Stalled(object):
        exitcode = None
        alive = False

        def start(self):
            self.alive = True

        def join(self, timeout):
            observed.append(timeout)

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False
            self.exitcode = -15

    child = Stalled()

    class Context(object):
        Event = threading.Event

        def Process(self, **kwargs):
            return child

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda method: Context())
    with pytest.raises(SubscriptionTransportError, match="deadline"):
        manager.refresh("main", timeout=0.5)
    assert not child.alive
    assert 0 < observed[0] <= 0.5
    assert manager.get("main").revision == original.revision
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))


@pytest.mark.parametrize("body", [None, 1, True, [], {}, "\u2603", "not base64!"])
def test_worker_body_type_and_encoding_are_closed_failures(tmp_path, monkeypatch, worker_boundary, body):
    manager, original = _manager(tmp_path, monkeypatch, [None])

    def malformed(url, result_path, *args):
        path = Path(result_path)
        path.write_text(json.dumps({"ok": True, "body": body, "final_url": url}))
        path.chmod(0o600)

    monkeypatch.setattr(manager_module, "_fetch_worker", malformed)
    with pytest.raises(SubscriptionFetchError, match="result body is invalid"):
        manager.refresh("main")
    assert manager.get("main").revision == original.revision
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))


@pytest.mark.parametrize("value", [
    [], None, {}, {"ok": True}, {"ok": False, "error": "unknown"},
    {"ok": True, "body": "", "final_url": 42},
    {"ok": True, "body": "", "final_url": "http://provider.example/sub"},
])
def test_untrusted_worker_envelopes_fail_without_replacing_cache(tmp_path, monkeypatch, worker_boundary, value):
    manager, original = _manager(tmp_path, monkeypatch, [None])

    def malformed(url, result_path, *args):
        path = Path(result_path)
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    monkeypatch.setattr(manager_module, "_fetch_worker", malformed)
    with pytest.raises(SubscriptionFetchError, match="worker result"):
        manager.refresh("main")
    assert manager.get("main").revision == original.revision


@pytest.mark.parametrize("payload", [b"\xff", b"not-json", b"[" * 10000])
def test_invalid_worker_json_is_a_bounded_source_failure(tmp_path, monkeypatch, worker_boundary, payload):
    manager, original = _manager(tmp_path, monkeypatch, [None])

    def malformed(url, result_path, *args):
        path = Path(result_path)
        path.write_bytes(payload)
        path.chmod(0o600)

    monkeypatch.setattr(manager_module, "_fetch_worker", malformed)
    with pytest.raises(SubscriptionFetchError, match="worker result is invalid"):
        manager.refresh("main")
    assert manager.get("main").revision == original.revision


@pytest.mark.parametrize("fault", ["missing", "oversized", "permissions", "unreadable", "body_oversized"])
def test_worker_result_file_and_body_bounds_are_enforced(tmp_path, monkeypatch, worker_boundary, fault):
    import base64
    import os

    if fault == "permissions" and os.name != "posix":
        pytest.skip("POSIX permission boundary")
    manager, original = _manager(tmp_path, monkeypatch, [None])
    original_open = os.open

    def unreadable(path, flags, *args, **kwargs):
        if str(path).endswith("result.json"):
            monkeypatch.setattr(os, "open", original_open)
            raise PermissionError("denied")
        return original_open(path, flags, *args, **kwargs)

    def malformed(url, result_path, *args):
        if fault == "missing":
            return
        path = Path(result_path)
        if fault == "oversized":
            with path.open("wb") as stream:
                stream.truncate(manager_module._FETCH_RESULT_MAXIMUM_BYTES + 1)
        else:
            body = b"a" * (8 * 1024 * 1024 + 1) if fault == "body_oversized" else SS
            path.write_text(json.dumps({"ok": True, "body": base64.b64encode(body).decode("ascii"),
                                        "final_url": url}))
        path.chmod(0o644 if fault == "permissions" else 0o600)
        if fault == "unreadable":
            monkeypatch.setattr(os, "open", unreadable)

    monkeypatch.setattr(manager_module, "_fetch_worker", malformed)
    with pytest.raises(SubscriptionFetchError, match="worker result"):
        manager.refresh("main")
    monkeypatch.setattr(os, "open", original_open)
    assert manager.get("main").revision == original.revision


@pytest.mark.parametrize("fault", ["device", "grows_after_stat"])
def test_result_descriptor_is_validated_and_read_is_independently_bounded(
    tmp_path, monkeypatch, worker_boundary, fault,
):
    import os

    if fault == "device" and os.name != "posix":
        pytest.skip("POSIX character device descriptor")
    manager, original = _manager(tmp_path, monkeypatch, [None])
    original_open = os.open
    original_fdopen = os.fdopen
    result_file = []
    monkeypatch.setattr(manager_module, "_FETCH_RESULT_MAXIMUM_BYTES", 1024)

    def substitute(path, flags, *args, **kwargs):
        if str(path) == result_file[0] and fault == "device":
            monkeypatch.setattr(os, "open", original_open)
            return original_open(os.devnull, os.O_RDONLY)
        return original_open(path, flags, *args, **kwargs)

    def grow(descriptor, *args, **kwargs):
        monkeypatch.setattr(os, "fdopen", original_fdopen)
        with open(result_file[0], "ab") as stream:
            stream.write(b" " * 1025)
        return original_fdopen(descriptor, *args, **kwargs)

    def malformed(url, result_path, *args):
        result_file.append(result_path)
        path = Path(result_path)
        path.write_bytes(b"{}")
        path.chmod(0o600)
        if fault == "device":
            monkeypatch.setattr(os, "open", substitute)
        else:
            monkeypatch.setattr(os, "fdopen", grow)

    monkeypatch.setattr(manager_module, "_fetch_worker", malformed)
    with pytest.raises(SubscriptionFetchError, match="worker result"):
        manager.refresh("main")
    assert manager.get("main").revision == original.revision
    assert not tuple(manager.paths.runtimes.glob(".subscription-fetch-*"))
