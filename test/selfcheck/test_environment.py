
import pytest

from jerryproxy.errors import JerryProxyBusyError, UnsupportedPlatformError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock
from jerryproxy.selfcheck import CheckResult, build_checks
from jerryproxy.selfcheck import environment as selfcheck_module


def test_runtime_check_reports_old_python_and_missing_package_version(tmp_path, monkeypatch):
    runtime_check = dict(build_checks(JerryProxyPaths(tmp_path)))["Python runtime"]

    monkeypatch.setattr(selfcheck_module.sys, "version_info", (3, 6))
    assert runtime_check() == CheckResult.fail("Python 3.7 or newer is required")

    monkeypatch.setattr(selfcheck_module.sys, "version_info", (3, 10))
    monkeypatch.setattr(selfcheck_module, "__VERSION__", "")
    assert runtime_check() == CheckResult.fail("package version is empty")


def test_platform_check_skips_unsupported_hosts(tmp_path, monkeypatch):
    def fail_platform():
        raise UnsupportedPlatformError("unsupported host")

    monkeypatch.setattr(selfcheck_module, "detect_platform", fail_platform)
    result = dict(build_checks(JerryProxyPaths(tmp_path)))["platform detection"]()

    assert result.level == "SKIP"
    assert "UnsupportedPlatformError: unsupported host" in result.detail


def test_platform_check_bounds_multiline_operational_diagnostics(tmp_path, monkeypatch):
    def fail_platform():
        raise OSError(("unreadable metadata\n" * 10000).strip())

    monkeypatch.setattr(selfcheck_module, "detect_platform", fail_platform)
    result = dict(build_checks(JerryProxyPaths(tmp_path)))["platform detection"]()

    assert result.level == "ERR"
    assert "\n" not in result.detail
    assert len(result.detail) <= 2060
    assert result.diagnostics
    assert len(result.diagnostics[0]) <= 64 * 1024


def test_home_layout_and_permission_checks_report_unmet_requirements(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    original_directory_paths = selfcheck_module._directory_paths

    def remove_downloads_after_initialization(selected_paths):
        selected_paths.downloads.rmdir()
        return original_directory_paths(selected_paths)

    monkeypatch.setattr(selfcheck_module, "_directory_paths", remove_downloads_after_initialization)
    checks = dict(build_checks(paths))

    missing = checks["home directory layout"]()
    assert missing.level == "FAIL"
    assert "missing state directories" in missing.detail

    if selfcheck_module.os.name == "posix":

        def weaken_download_permissions_after_initialization(selected_paths):
            selected_paths.downloads.chmod(0o755)
            return original_directory_paths(selected_paths)

        monkeypatch.setattr(selfcheck_module, "_directory_paths", weaken_download_permissions_after_initialization)
        permissions = checks["private directory permissions"]()
        assert permissions.level == "FAIL"
        assert "not 0700" in permissions.detail
    else:
        assert checks["private directory permissions"]() == CheckResult.skip(
            "POSIX mode checks do not apply on %s" % selfcheck_module.os.name
        )


def test_home_layout_and_permission_reads_remain_under_the_operation_lock(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    original_directory_paths = selfcheck_module._directory_paths
    observations = []

    def assert_locked(selected_paths):
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(selected_paths):
                pass
        observations.append(selected_paths.root)
        return original_directory_paths(selected_paths)

    monkeypatch.setattr(selfcheck_module, "_directory_paths", assert_locked)
    checks = dict(build_checks(paths))

    assert checks["home directory layout"]().level == "OK"
    expected_permission_level = "OK" if selfcheck_module.os.name == "posix" else "SKIP"
    assert checks["private directory permissions"]().level == expected_permission_level
    expected_observations = 2 if selfcheck_module.os.name == "posix" else 1
    assert observations == [paths.root] * expected_observations


def test_home_write_probe_remains_under_the_operation_lock(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    original_mkstemp = selfcheck_module.tempfile.mkstemp
    observations = []

    def assert_locked(*args, **kwargs):
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(paths):
                pass
        observations.append(paths.root)
        return original_mkstemp(*args, **kwargs)

    monkeypatch.setattr(selfcheck_module.tempfile, "mkstemp", assert_locked)

    result = dict(build_checks(paths))["home write access"]()

    assert result.level == "OK"
    assert observations == [paths.root]


def test_home_checks_report_lock_contention_as_errors(tmp_path):
    paths = JerryProxyPaths(tmp_path)
    checks = dict(build_checks(paths))

    with JerryProxyOperationLock(paths):
        results = [
            checks["home directory layout"](),
            checks["home write access"](),
            checks["private directory permissions"](),
        ]

    assert [result.level for result in results] == ["ERR", "ERR", "ERR"]
    assert all("JerryProxyBusyError" in result.detail for result in results)


def test_private_permission_check_is_not_applicable_off_posix(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    host_os = selfcheck_module.os

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(selfcheck_module, "os", WindowsOsProxy())

    result = dict(build_checks(paths))["private directory permissions"]()

    assert result == CheckResult.skip("POSIX mode checks do not apply on nt")
