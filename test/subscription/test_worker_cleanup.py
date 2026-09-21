"""Process uncertainty must preserve cleanup ownership and private evidence."""

import threading

import pytest

import jerryproxy.subscription.manager as manager_module


@pytest.mark.parametrize("error", [AssertionError, OSError, RuntimeError])
def test_unreadable_worker_liveness_is_not_a_cleanup_confirmation(error):
    class Process:
        def is_alive(self):
            raise error("unreadable worker")

    assert manager_module._fetch_process_alive(Process())
    assert not manager_module._fetch_process_alive(None)


@pytest.mark.parametrize("error", [AssertionError, OSError, RuntimeError])
def test_failed_stop_operations_never_confirm_worker_cleanup(error):
    actions = []

    class Process:
        def is_alive(self):
            return True

        def terminate(self):
            actions.append("terminate")
            raise error("termination unavailable")

        def kill(self):
            actions.append("kill")
            raise error("kill unavailable")

        def join(self, timeout):
            actions.append("join")
            raise error("join unavailable")

    assert not manager_module._stop_fetch_process(Process())
    assert actions == ["terminate", "join", "kill", "join"]


@pytest.mark.parametrize("cancelled", [False, True])
def test_worker_does_not_fetch_without_live_start_permission(tmp_path, monkeypatch, cancelled):
    start = threading.Event()
    cancel = threading.Event()
    if cancelled:
        start.set()
        cancel.set()
    monkeypatch.setattr(manager_module, "_FETCH_START_SECONDS", 0)
    monkeypatch.setattr(manager_module, "fetch_subscription", lambda *a, **kw: pytest.fail("cancelled worker fetched"))
    # This function runs in the real child; isolate its environment scrubbing
    # from the pytest host while verifying both cancellation gates.
    monkeypatch.setattr(manager_module.os, "environ",
                        {"V2RAY_SUBSCRIPTION": "secret", "HTTP_PROXY": "secret", "KEEP": "yes"})
    result = tmp_path / "result.json"
    manager_module._fetch_worker("https://provider.invalid/sub", str(result), False, "auto", start, cancel)
    assert not result.exists()
    assert manager_module.os.environ == {"KEEP": "yes"}


@pytest.mark.parametrize("stage", ["starter", "process", "process_recovers"])
def test_supervisor_deadline_preserves_evidence_until_completion(tmp_path, monkeypatch, stage):
    supervisor = manager_module._FetchCleanupSupervisor()
    token = object()
    supervisor._pending.add(token)
    removed = []
    stops = iter([False, True]) if stage == "process_recovers" else iter([False])
    monkeypatch.setattr(manager_module, "_stop_fetch_process", lambda process: next(stops))
    monkeypatch.setattr(manager_module, "_secure_remove_tree", lambda *a, **kw: removed.append(True))
    monkeypatch.setattr(manager_module, "_FETCH_LATE_CLEANUP_SECONDS", 1 if stage == "process_recovers" else 0)

    class Starter:
        def is_alive(self):
            return True

    supervisor._cleanup(token, Starter() if stage == "starter" else None, object(), tmp_path, tmp_path / "worker")
    assert supervisor.pending is (stage != "process_recovers")
    assert bool(removed) is (stage == "process_recovers")


@pytest.mark.parametrize("failure", ["oversized", "open", "zero_write", "fsync", "short_write"])
def test_worker_result_publication_fails_closed_on_io_boundaries(tmp_path, monkeypatch, failure):
    import json

    path = tmp_path / "result.json"
    value = {"ok": False, "error": "source failed"}
    real_open, real_write = manager_module.os.open, manager_module.os.write
    if failure == "oversized":
        monkeypatch.setattr(manager_module, "_FETCH_RESULT_MAXIMUM_BYTES", 1)
    elif failure == "open":
        def denied(*args, **kwargs):
            raise PermissionError("private path")
        monkeypatch.setattr(manager_module.os, "open", denied)
    elif failure == "zero_write":
        monkeypatch.setattr(manager_module.os, "write", lambda *args: 0)
    elif failure == "fsync":
        def failed_flush(descriptor):
            raise OSError("flush failed")
        monkeypatch.setattr(manager_module.os, "fsync", failed_flush)
    else:
        monkeypatch.setattr(manager_module.os, "write", lambda descriptor, data: real_write(descriptor, data[:1]))
    manager_module._write_fetch_result(str(path), value)
    monkeypatch.setattr(manager_module.os, "open", real_open)
    if failure in ("oversized", "open"):
        assert not path.exists()
    elif failure == "zero_write":
        assert path.read_bytes() == b""
    else:
        assert json.loads(path.read_text()) == value
    # A closed descriptor allows immediate cleanup even on native Windows.
    if path.exists():
        path.unlink()
