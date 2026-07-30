import hashlib
from types import SimpleNamespace

import pytest

import jerryproxy.selfcheck as selfcheck_module
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.errors import BackendCatalogError, JerryProxyBusyError, UnsupportedPlatformError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock, filelock_status
from jerryproxy.selfcheck import CheckResult, ansi_color_enabled, build_checks, run_checks, run_self_check
from test.selfcheck.fakes import (
    FakeRelayResponse,
    RelaySessionFactory,
    relay_payload,
    verified_relay_session_factory,
)


def test_self_check_validates_an_empty_private_home(tmp_path, monkeypatch):
    lines = []
    relay_factory = verified_relay_session_factory(monkeypatch)

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    status = filelock_status()
    expected = (
        "Summary: 12 OK, 0 WARN, 0 FAIL, 0 ERR"
        if status.level == "OK"
        else "Summary: 11 OK, 1 WARN, 0 FAIL, 0 ERR"
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


def test_self_check_reports_corrupt_active_inventory_without_stopping_other_checks(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    (paths.active / "mihomo.json").write_text("{not-json", encoding="ascii")
    lines = []

    exit_code = run_self_check(
        paths,
        output=lines.append,
        relay_session_factory=verified_relay_session_factory(monkeypatch),
    )

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


def test_relay_checks_use_exact_bounded_range_and_report_metrics(tmp_path, monkeypatch):
    lines = []
    relay_factory = verified_relay_session_factory(monkeypatch)

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    assert len(relay_factory.sessions) == 3
    assert sum(
        "relay " in line
        and "verified 1 MiB; response" in line
        and "; first chunk" in line
        and "; stream " in line
        for line in lines
    ) == 3
    for session in relay_factory.sessions:
        assert session.closed is True
        assert session.max_redirects == 5
        assert len(session.calls) == 1
        url, options = session.calls[0]
        assert url.startswith("https://")
        assert options["headers"]["Range"] == "bytes=0-1048575"
        assert options["allow_redirects"] is True
        assert options["stream"] is True
        assert options["timeout"] == 5.0
        assert session.outcome.closed is True


@pytest.mark.parametrize(
    "error, expected",
    [
        (
            selfcheck_module.requests.exceptions.TooManyRedirects("private redirect URL"),
            "redirect limit exceeded",
        ),
        (selfcheck_module.requests.exceptions.Timeout("private timeout URL"), "request timed out"),
        (selfcheck_module.requests.exceptions.SSLError("private TLS URL"), "TLS validation failed"),
        (selfcheck_module.requests.exceptions.ConnectionError("private connect URL"), "connection failed"),
        (selfcheck_module.requests.exceptions.ProxyError("private proxy URL"), "system proxy connection failed"),
        (selfcheck_module.requests.exceptions.RequestException("private request URL"), "request failed"),
    ],
)
def test_relay_transport_failures_are_sanitized_warnings(tmp_path, error, expected):
    relay_factory = RelaySessionFactory(lambda: error)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail
    assert "private" not in result.detail


def test_relay_http_failure_is_a_sanitized_warning(tmp_path):
    response = FakeRelayResponse(relay_payload(), status_code=403)
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn("bounded 1 MiB verification failed: HTTP response was not 206")
    assert "signed-value" not in result.detail


@pytest.mark.parametrize(
    "response, expected",
    [
        (
            FakeRelayResponse(
                relay_payload(),
                history=[
                    SimpleNamespace(url="https://relay.example/%d" % index)
                    for index in range(6)
                ],
            ),
            "redirect limit exceeded",
        ),
        (
            FakeRelayResponse(
                relay_payload(),
                history=[SimpleNamespace(url="http://private.example/signed-query")],
            ),
            "redirect chain did not remain HTTPS",
        ),
    ],
)
def test_relay_redirect_policy_failures_are_sanitized_warnings(tmp_path, response, expected):
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail
    assert "private" not in result.detail


@pytest.mark.parametrize(
    "response_factory, expected",
    [
        (
            lambda: FakeRelayResponse(relay_payload(), content_range="bytes 0-1/2"),
            "Content-Range did not match the pinned asset",
        ),
        (
            lambda: FakeRelayResponse(relay_payload()[:-1]),
            "response body was not exactly 1 MiB",
        ),
        (
            lambda: FakeRelayResponse(relay_payload()),
            "pinned 1 MiB sample digest did not match",
        ),
    ],
)
def test_relay_content_failures_are_warnings(tmp_path, response_factory, expected, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "RELAY_PROBE_SHA256", "0" * 64)
    relay_factory = RelaySessionFactory(response_factory)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail


def test_relay_probe_stops_after_one_bounded_overflow_chunk(tmp_path):
    response = FakeRelayResponse(relay_payload() + b"unexpected trailing response" * 4096)
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn("bounded 1 MiB verification failed: response body was not exactly 1 MiB")
    assert response.iterated_bytes <= selfcheck_module.RELAY_PROBE_BYTES + 64 * 1024


def test_relay_probe_ignores_empty_chunks_before_a_valid_stream(tmp_path, monkeypatch):
    payload = relay_payload()
    monkeypatch.setattr(
        selfcheck_module,
        "RELAY_PROBE_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    chunks = [b""] + [
        payload[offset : offset + 64 * 1024]
        for offset in range(0, len(payload), 64 * 1024)
    ]
    relay_factory = RelaySessionFactory(
        lambda: FakeRelayResponse(payload, chunks=chunks)
    )
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "OK"
    assert "over 16 chunks" in result.detail


def test_relay_warnings_keep_the_full_self_check_exit_code_zero(tmp_path):
    lines = []
    relay_factory = RelaySessionFactory(
        lambda: selfcheck_module.requests.exceptions.Timeout("secret request target")
    )

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    assert "Summary: 9 OK, 3 WARN, 0 FAIL, 0 ERR" in lines
    assert lines[-1] == "Self-check PASSED with warnings"
    assert all("secret" not in line for line in lines)
