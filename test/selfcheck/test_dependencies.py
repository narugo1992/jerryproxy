from types import SimpleNamespace

from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import CheckResult, build_checks
from jerryproxy.selfcheck import dependencies as selfcheck_module


def test_filelock_check_maps_legacy_status_to_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(
        selfcheck_module,
        "filelock_status",
        lambda: SimpleNamespace(level="WARN", detail="legacy filelock"),
    )

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result.level == "WARN"
    assert result.detail.startswith("legacy filelock;")
    assert "contention" in result.detail


def test_filelock_check_runs_the_real_lock_probe_for_a_supported_line(tmp_path, monkeypatch):
    monkeypatch.setattr(
        selfcheck_module,
        "filelock_status",
        lambda: SimpleNamespace(level="OK", detail="supported filelock"),
    )

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result == CheckResult.ok(
        "supported filelock; exclusive acquire, contention, release, and reacquire succeeded"
    )


def test_filelock_check_fails_if_exclusive_contention_is_not_enforced(tmp_path, monkeypatch):
    class NonExclusiveLock(object):
        def __init__(self, paths):
            self.paths = paths

        def __enter__(self):
            return self

        def __exit__(self, exception_type, exception, traceback):
            return False

    monkeypatch.setattr(selfcheck_module, "JerryProxyOperationLock", NonExclusiveLock)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result == CheckResult.fail("filelock allowed a concurrent exclusive acquisition")


def test_filelock_check_reports_operational_errors_with_traceback(tmp_path, monkeypatch):
    class BrokenLock(object):
        def __init__(self, paths):
            self.paths = paths

        def __enter__(self):
            raise OSError("lock backend unavailable")

        def __exit__(self, exception_type, exception, traceback):
            return False

    monkeypatch.setattr(selfcheck_module, "JerryProxyOperationLock", BrokenLock)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result.level == "ERR"
    assert result.detail == "OSError: lock backend unavailable"
    assert result.diagnostics and "lock backend unavailable" in result.diagnostics[0]
