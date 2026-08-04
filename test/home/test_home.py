import os
import subprocess
from pathlib import Path

import pytest

import jerryproxy.home as home_module
from jerryproxy.errors import IntegrityError
from jerryproxy.home import JerryProxyPaths, is_path_alias, resolve_home
from jerryproxy.lock import JerryProxyOperationLock


def test_default_home(monkeypatch, tmp_path):
    monkeypatch.delenv("JERRYPROXY_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert resolve_home() == tmp_path / ".jerryproxy"


def test_explicit_home_wins_over_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("JERRYPROXY_HOME", str(tmp_path / "environment"))
    assert resolve_home(str(tmp_path / "explicit")) == tmp_path / "explicit"


@pytest.mark.parametrize("missing,attributes,expected", ((True, 0, False), (False, 0x400, True)))
def test_windows_alias_detection_handles_missing_paths_and_reparse_points(
    monkeypatch,
    missing,
    attributes,
    expected,
):
    class WindowsPath(object):
        def is_symlink(self):
            return False

        def lstat(self):
            if missing:
                raise FileNotFoundError("missing")
            return type("Status", (), {"st_file_attributes": attributes})()

    monkeypatch.setattr(home_module, "Path", lambda value: WindowsPath())
    monkeypatch.setattr(home_module.os, "name", "nt")

    assert is_path_alias("managed") is expected


def test_paths_create_single_private_tree(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    expected = {
        paths.root,
        paths.backends,
        paths.bin,
        paths.downloads,
        paths.providers,
        paths.runtimes,
        paths.logs,
        paths.locks,
        paths.active,
    }
    assert all(path.is_dir() for path in expected)
    if os.name == "posix":
        assert all((path.stat().st_mode & 0o777) == 0o700 for path in expected)


def test_read_only_access_rejects_a_complete_home_with_a_missing_lock(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    paths.lock_file.unlink()

    with pytest.raises(IntegrityError, match="home is incomplete"):
        with JerryProxyOperationLock(paths, initialize=False):
            pass

    assert not paths.lock_file.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_paths_reject_user_managed_directory_aliases(tmp_path):
    root = tmp_path / "home"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "downloads").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="must not be a symlink"):
        JerryProxyPaths(root).ensure()
    assert (root / "downloads").is_symlink()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_paths_reject_a_separate_lock_directory_alias(tmp_path):
    root = tmp_path / "home"
    root.mkdir()
    outside = tmp_path / "outside-locks"
    outside.mkdir()
    (root / "locks").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="must not be a symlink"):
        JerryProxyPaths(root).ensure()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_paths_reject_a_lock_file_alias_without_touching_its_target(tmp_path):
    paths = JerryProxyPaths(tmp_path / "home")
    paths.locks.mkdir(parents=True)
    outside = tmp_path / "outside-lock-target"
    outside.write_bytes(b"must remain unchanged")
    paths.lock_file.symlink_to(outside)

    with pytest.raises(IntegrityError, match="lock file must not be a symlink"):
        paths.ensure()

    assert outside.read_bytes() == b"must remain unchanged"


@pytest.mark.skipif(os.name != "nt", reason="Windows symlink creation may require elevated privileges")
def test_windows_paths_reject_a_lock_file_alias_without_touching_its_target(tmp_path):
    paths = JerryProxyPaths(tmp_path / "home")
    paths.locks.mkdir(parents=True)
    outside = tmp_path / "outside-lock-target"
    outside.write_bytes(b"must remain unchanged")
    paths.lock_file.symlink_to(outside)

    with pytest.raises(IntegrityError, match="lock file must not be a symlink"):
        paths.ensure()

    assert outside.read_bytes() == b"must remain unchanged"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_paths_recheck_managed_directory_aliases_after_creation(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / "home")
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_bytes(b"outside")
    original_mkdir = Path.mkdir
    replaced = []

    def replace_downloads_after_creation(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if path == paths.downloads and not replaced:
            path.rmdir()
            path.symlink_to(outside, target_is_directory=True)
            replaced.append(path)
        return result

    monkeypatch.setattr(Path, "mkdir", replace_downloads_after_creation)

    with pytest.raises(IntegrityError, match="must not be a symlink"):
        paths.ensure()

    assert replaced == [paths.downloads]
    assert marker.read_bytes() == b"outside"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_paths_reject_windows_junction_without_touching_external_data(tmp_path):
    paths = JerryProxyPaths(tmp_path / "home")
    paths.root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    subprocess.check_call(
        ["cmd", "/c", "mklink", "/J", str(paths.downloads), str(outside)],
        stdout=subprocess.DEVNULL,
    )

    try:
        with pytest.raises(IntegrityError, match="path alias"):
            paths.ensure()
        assert marker.read_bytes() == b"outside"
    finally:
        if os.path.lexists(str(paths.downloads)):
            os.rmdir(str(paths.downloads))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_windows_existing_layout_rejects_a_junction_alias(tmp_path):
    paths = JerryProxyPaths(tmp_path / "home")
    paths.ensure()
    outside = tmp_path / "outside-existing-layout"
    outside.mkdir()
    paths.downloads.rmdir()
    subprocess.check_call(
        ["cmd", "/c", "mklink", "/J", str(paths.downloads), str(outside)],
        stdout=subprocess.DEVNULL,
    )

    try:
        with pytest.raises(IntegrityError, match="invalid or aliased"):
            with JerryProxyOperationLock(paths, initialize=False):
                pass
    finally:
        if os.path.lexists(str(paths.downloads)):
            os.rmdir(str(paths.downloads))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_paths_recheck_windows_junction_after_directory_creation(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / "home")
    outside = tmp_path / "outside-after-create"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    original_mkdir = Path.mkdir
    replaced = []

    def replace_downloads_after_creation(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if path == paths.downloads and not replaced:
            path.rmdir()
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(path), str(outside)],
                check=True,
                capture_output=True,
                text=True,
            )
            replaced.append(path)
        return result

    monkeypatch.setattr(Path, "mkdir", replace_downloads_after_creation)

    try:
        with pytest.raises(IntegrityError, match="path alias"):
            paths.ensure()
        assert replaced == [paths.downloads]
        assert marker.read_bytes() == b"outside"
    finally:
        if os.path.lexists(str(paths.downloads)):
            os.rmdir(str(paths.downloads))
