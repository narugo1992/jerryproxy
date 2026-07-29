import multiprocessing
import os

import pytest

import jerryproxy.lock as lock_module
from jerryproxy.errors import JerryProxyBusyError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock, filelock_status


def _hold_lock(root, ready, release):
    paths = JerryProxyPaths(root)
    with JerryProxyOperationLock(paths):
        ready.set()
        release.wait(10)


def _acquire_then_exit(root, ready):
    paths = JerryProxyPaths(root)
    with JerryProxyOperationLock(paths):
        ready.set()
        os._exit(0)


def test_global_lock_is_exclusive_across_processes(tmp_path):
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    process = context.Process(target=_hold_lock, args=(str(tmp_path), ready, release))
    process.start()
    try:
        assert ready.wait(10)
        with pytest.raises(JerryProxyBusyError, match="JerryProxy operation already in progress"):
            with JerryProxyOperationLock(JerryProxyPaths(tmp_path)):
                pass
    finally:
        release.set()
        process.join(10)
    assert process.exitcode == 0


def test_global_lock_is_released_when_owner_process_exits(tmp_path):
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    process = context.Process(target=_acquire_then_exit, args=(str(tmp_path), ready))
    process.start()
    assert ready.wait(10)
    process.join(10)
    assert process.exitcode == 0

    with JerryProxyOperationLock(JerryProxyPaths(tmp_path)):
        assert (tmp_path / "locks" / "jerryproxy.lock").is_file()


def test_different_homes_can_be_locked_independently(tmp_path):
    first = JerryProxyPaths(tmp_path / "first")
    second = JerryProxyPaths(tmp_path / "second")

    with JerryProxyOperationLock(first):
        with JerryProxyOperationLock(second):
            assert first.lock_file.is_file()
            assert second.lock_file.is_file()


def test_layout_failure_releases_acquired_filelock(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)

    def fail_layout():
        raise PermissionError("layout unavailable")

    monkeypatch.setattr(paths, "_ensure_layout_locked", fail_layout)
    with pytest.raises(PermissionError, match="layout unavailable"):
        with JerryProxyOperationLock(paths):
            pass

    replacement = JerryProxyPaths(tmp_path)
    with JerryProxyOperationLock(replacement):
        assert replacement.backends.is_dir()


def test_filelock_status_is_observable():
    status = filelock_status()

    assert status.level in ("OK", "WARN")
    assert status.version
    assert "filelock" in status.detail


@pytest.mark.parametrize(
    ("python_version", "filelock_version", "message"),
    [
        ((3, 7), "3.12.2", "legacy Python compatibility line"),
        ((3, 8), "3.16.1", "legacy Python compatibility line"),
        ((3, 9), "3.19.1", "legacy Python compatibility line"),
        ((3, 10), "unrecognized", "unrecognized version metadata"),
        ((3, 10), "3.29.7", "older than the recommended"),
    ],
)
def test_filelock_status_reports_legacy_and_outdated_lines(
    monkeypatch, python_version, filelock_version, message
):
    monkeypatch.setattr(lock_module.sys, "version_info", python_version)
    monkeypatch.setattr(lock_module.filelock, "__version__", filelock_version)

    status = filelock_status()

    assert status.level == "WARN"
    assert message in status.detail
    if python_version < (3, 10):
        assert "CVE-2025-68146" in status.detail
