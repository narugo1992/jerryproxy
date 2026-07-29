from types import SimpleNamespace

import pytest

import jerryproxy.selfcheck as selfcheck_module
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.errors import BackendCatalogError, JerryProxyBusyError, UnsupportedPlatformError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock, filelock_status
from jerryproxy.selfcheck import CheckResult, ansi_color_enabled, build_checks, run_checks, run_self_check


def test_self_check_validates_an_empty_private_home(tmp_path):
    lines = []

    exit_code = run_self_check(JerryProxyPaths(tmp_path), output=lines.append)

    assert exit_code == 0
    status = filelock_status()
    expected = (
        "Summary: 9 OK, 0 WARN, 0 FAIL, 0 ERR"
        if status.level == "OK"
        else "Summary: 8 OK, 1 WARN, 0 FAIL, 0 ERR"
    )
    assert expected in lines
    assert lines[-1] in ("Self-check PASSED", "Self-check PASSED with warnings")
    assert not list(tmp_path.glob(".self-check-*"))
    for name in ("active", "backends", "bin", "downloads", "locks", "logs", "providers", "runtimes"):
        assert (tmp_path / name).is_dir()


def test_check_runner_renders_all_four_levels_and_only_fails_on_fail_or_error():
    visited = []
    lines = []

    def first():
        visited.append("first")
        return CheckResult.ok("ready")

    def warning():
        visited.append("warning")
        return CheckResult.warn("legacy dependency")

    def failure():
        visited.append("failure")
        return CheckResult.fail("requirement unmet")

    def error():
        visited.append("error")
        return CheckResult.err("OSError: read-only state directory")

    exit_code = run_checks(
        (("first", first), ("compatibility", warning), ("policy", failure), ("writable state", error)),
        output=lines.append,
    )

    assert exit_code == 1
    assert visited == ["first", "warning", "failure", "error"]
    assert "[2/4] compatibility: WARN - legacy dependency" in lines
    assert "[3/4] policy: FAIL - requirement unmet" in lines
    assert "[4/4] writable state: ERR - OSError: read-only state directory" in lines
    assert "Summary: 1 OK, 1 WARN, 1 FAIL, 1 ERR" in lines
    assert lines[-1] == "Self-check FAILED"


def test_check_runner_warning_keeps_zero_exit_code():
    lines = []

    exit_code = run_checks((("compatibility", lambda: CheckResult.warn("upgrade recommended")),), lines.append)

    assert exit_code == 0
    assert "Summary: 0 OK, 1 WARN, 0 FAIL, 0 ERR" in lines
    assert lines[-1] == "Self-check PASSED with warnings"


def test_check_runner_uses_ansi_status_colors_when_enabled():
    lines = []

    exit_code = run_checks(
        (("ready", lambda: CheckResult.ok("available")),),
        output=lines.append,
        color=True,
    )

    assert exit_code == 0
    assert "\033[1;36m[1/1] ready\033[0m" in lines[0]
    assert "\033[1;32mOK\033[0m" in lines[0]
    assert lines[-1] == "\033[1;32mSelf-check PASSED\033[0m"


def test_check_runner_colors_warning_failure_and_error_levels():
    lines = []

    exit_code = run_checks(
        (
            ("warning", lambda: CheckResult.warn("legacy")),
            ("failure", lambda: CheckResult.fail("unmet")),
            ("error", lambda: CheckResult.err("unavailable")),
        ),
        output=lines.append,
        color=True,
    )

    assert exit_code == 1
    assert "\033[1;33mWARN\033[0m" in lines[0]
    assert "\033[1;31mFAIL\033[0m" in lines[1]
    assert "\033[1;31mERR\033[0m" in lines[2]


def test_color_detection_honors_environment_and_explicit_override(monkeypatch):
    class Terminal(object):
        def isatty(self):
            return True

    terminal = Terminal()
    monkeypatch.setenv("NO_COLOR", "1")
    assert ansi_color_enabled(terminal) is False
    assert ansi_color_enabled(terminal, requested=True) is True

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ansi_color_enabled(object()) is True


def test_color_detection_falls_back_when_stream_has_no_usable_tty(monkeypatch):
    class BrokenTerminal(object):
        def isatty(self):
            raise OSError("terminal unavailable")

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert ansi_color_enabled(object()) is False
    assert ansi_color_enabled(BrokenTerminal()) is False


def test_self_check_reports_corrupt_active_inventory_without_stopping_other_checks(tmp_path):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    (paths.active / "mihomo.json").write_text("{not-json", encoding="ascii")
    lines = []

    exit_code = run_self_check(paths, output=lines.append)

    assert exit_code == 1
    assert any("backend inventory: ERR" in line for line in lines)
    assert lines[-1] == "Self-check FAILED"


def test_runtime_check_reports_old_python_and_missing_package_version(tmp_path, monkeypatch):
    runtime_check = dict(build_checks(JerryProxyPaths(tmp_path)))["Python runtime"]

    monkeypatch.setattr(selfcheck_module.sys, "version_info", (3, 6))
    assert runtime_check() == CheckResult.fail("Python 3.7 or newer is required")

    monkeypatch.setattr(selfcheck_module.sys, "version_info", (3, 10))
    monkeypatch.setattr(selfcheck_module, "__VERSION__", "")
    assert runtime_check() == CheckResult.fail("package version is empty")


def test_platform_check_translates_detection_errors(tmp_path, monkeypatch):
    def fail_platform():
        raise UnsupportedPlatformError("unsupported host")

    monkeypatch.setattr(selfcheck_module, "detect_platform", fail_platform)
    result = dict(build_checks(JerryProxyPaths(tmp_path)))["platform detection"]()

    assert result.level == "ERR"
    assert "UnsupportedPlatformError: unsupported host" in result.detail


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
        assert checks["private directory permissions"]() == CheckResult.ok("POSIX mode check not applicable")


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
    assert checks["private directory permissions"]().level == "OK"
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

    assert result == CheckResult.ok("POSIX mode check not applicable")


def test_registry_check_reports_empty_unsupported_and_invalid_registries(tmp_path, monkeypatch):
    registry_check = dict(build_checks(JerryProxyPaths(tmp_path)))["backend registry"]
    monkeypatch.setattr(selfcheck_module, "iter_backends", lambda: ())
    assert registry_check().level == "FAIL"

    class UnsupportedSpec(object):
        name = "unsupported"

        def expected_asset_name(self, platform_info, version):
            raise UnsupportedPlatformError("no asset")

    monkeypatch.setattr(selfcheck_module, "iter_backends", lambda: (UnsupportedSpec(),))
    monkeypatch.setattr(
        selfcheck_module,
        "detect_platform",
        lambda: PlatformInfo("linux", "amd64", "glibc"),
    )
    unsupported = registry_check()
    assert unsupported.level == "FAIL"
    assert "no registered backend supports" in unsupported.detail

    def invalid_registry():
        raise ValueError("invalid registry")

    monkeypatch.setattr(selfcheck_module, "iter_backends", invalid_registry)
    invalid = registry_check()
    assert invalid.level == "ERR"
    assert "ValueError: invalid registry" in invalid.detail


def test_catalog_check_reports_errors_and_missing_platform_assets(tmp_path, monkeypatch):
    catalog_check = dict(build_checks(JerryProxyPaths(tmp_path)))["packaged backend catalog"]

    def fail_load():
        raise BackendCatalogError("catalog unavailable")

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_load)
    error = catalog_check()
    assert error.level == "ERR"
    assert "catalog unavailable" in error.detail

    class EmptyCatalog(object):
        generated_at = "2026-01-01T00:00:00Z"

        def versions(self, name):
            return ()

        def available_versions(self, name, platform_info):
            return ()

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", lambda: EmptyCatalog())
    monkeypatch.setattr(
        selfcheck_module,
        "detect_platform",
        lambda: PlatformInfo("linux", "amd64", "glibc"),
    )
    missing = catalog_check()
    assert missing.level == "FAIL"
    assert "catalog has no verified stable" in missing.detail


def test_filelock_check_maps_legacy_status_to_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(
        selfcheck_module,
        "filelock_status",
        lambda: SimpleNamespace(level="WARN", detail="legacy filelock"),
    )

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["filelock compatibility"]()

    assert result == CheckResult.warn("legacy filelock")
