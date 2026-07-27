import os
from pathlib import Path

from jerryproxy.home import JerryProxyPaths, resolve_home


def test_default_home(monkeypatch, tmp_path):
    monkeypatch.delenv("JERRYPROXY_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert resolve_home() == tmp_path / ".jerryproxy"


def test_explicit_home_wins_over_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("JERRYPROXY_HOME", str(tmp_path / "environment"))
    assert resolve_home(str(tmp_path / "explicit")) == tmp_path / "explicit"


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
