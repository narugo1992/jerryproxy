import os

import pytest

from jerryproxy.backend.lock import BackendOperationLock
from jerryproxy.errors import BackendBusyError


def test_live_backend_lock_is_exclusive(tmp_path):
    path = tmp_path / "backend.lock"
    with BackendOperationLock(path):
        with pytest.raises(BackendBusyError):
            BackendOperationLock(path).__enter__()


def test_dead_owner_lock_is_recovered(tmp_path, monkeypatch):
    path = tmp_path / "backend.lock"
    path.write_text("999999 stale-owner\n", encoding="ascii")
    monkeypatch.setattr(BackendOperationLock, "_process_exists", staticmethod(lambda pid: False))

    with BackendOperationLock(path):
        owner = path.read_text(encoding="ascii").strip()
        assert owner.startswith("%s " % os.getpid())
    assert not path.exists()


def test_old_owner_cannot_remove_replacement_lock(tmp_path):
    path = tmp_path / "backend.lock"
    first = BackendOperationLock(path)
    second = BackendOperationLock(path)
    first.__enter__()
    try:
        path.unlink()
        second.__enter__()
        try:
            first.__exit__(None, None, None)
            assert path.exists()
            assert path.read_text(encoding="ascii").strip() == second.owner
        finally:
            second.__exit__(None, None, None)
    finally:
        first.__exit__(None, None, None)
