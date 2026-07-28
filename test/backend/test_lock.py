import os

import pytest

from jerryproxy.backend.lock import BackendOperationLock
from jerryproxy.errors import BackendBusyError


def test_live_backend_lock_is_exclusive(tmp_path):
    path = tmp_path / "backend.lock"
    with BackendOperationLock(path):
        with pytest.raises(BackendBusyError):
            with BackendOperationLock(path):
                pass


def test_nonpositive_pid_lock_is_recovered_without_mocking_process_state(tmp_path):
    path = tmp_path / "backend.lock"
    path.write_text("-1 stale-owner\n", encoding="ascii")

    with BackendOperationLock(path):
        owner = path.read_text(encoding="ascii").strip()
        assert owner.startswith("%s " % os.getpid())
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process lookup semantics")
def test_missing_process_lock_is_recovered_through_real_process_lookup(tmp_path):
    path = tmp_path / "backend.lock"
    path.write_text("2147483647 stale-owner\n", encoding="ascii")

    with BackendOperationLock(path):
        assert path.read_text(encoding="ascii").startswith("%s " % os.getpid())
    assert not path.exists()


@pytest.mark.parametrize("owner", [b"", b"not-a-pid owner\n", b"\xff"])
def test_unverifiable_lock_owner_is_preserved(tmp_path, owner):
    path = tmp_path / "backend.lock"
    path.write_bytes(owner)

    with pytest.raises(BackendBusyError):
        with BackendOperationLock(path):
            pass

    assert path.read_bytes() == owner


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot unlink an open lock file")
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
