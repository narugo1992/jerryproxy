

from jerryproxy.backend.model import PlatformInfo
from jerryproxy.errors import BackendCatalogError, UnsupportedPlatformError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import CheckResult, build_checks
from jerryproxy.selfcheck import resources as selfcheck_module


def test_catalog_check_keeps_an_empty_exception_diagnosable(tmp_path, monkeypatch):
    def fail_without_message():
        raise OSError()

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_without_message)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["packaged backend catalog"]()

    assert result.level == "ERR"
    assert result.detail == "OSError: OSError()"
    assert result.diagnostics and "OSError" in result.diagnostics[0]


def test_platform_dependent_resource_checks_report_detection_errors(tmp_path, monkeypatch):
    def fail_platform():
        raise RuntimeError("platform metadata unavailable")

    monkeypatch.setattr(selfcheck_module, "detect_platform", fail_platform)
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))

    for name in ("backend registry", "catalog platform selection"):
        result = checks[name]()
        assert result.level == "ERR"
        assert result.detail == "RuntimeError: platform metadata unavailable"
        assert result.diagnostics and "platform metadata unavailable" in result.diagnostics[0]


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


def test_catalog_checks_separate_resource_failures_from_platform_selection(tmp_path, monkeypatch):
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))
    catalog_check = checks["packaged backend catalog"]
    selection_check = checks["catalog platform selection"]

    def fail_load():
        raise BackendCatalogError("catalog unavailable")

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_load)
    error = catalog_check()
    assert error.level == "FAIL"
    assert "catalog unavailable" in error.detail
    skipped = selection_check()
    assert skipped.level == "SKIP"
    assert "packaged catalog prerequisite failed" in skipped.detail

    def fail_resource_read():
        raise OSError("packaged resource is unreadable")

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", fail_resource_read)
    unavailable = catalog_check()
    assert unavailable.level == "ERR"
    assert unavailable.diagnostics and "packaged resource is unreadable" in unavailable.diagnostics[0]
    unavailable_selection = selection_check()
    assert unavailable_selection == CheckResult.skip(
        "packaged catalog prerequisite is unavailable: packaged resource is unreadable"
    )

    class EmptyCatalog(object):
        generated_at = "2026-01-01T00:00:00Z"

        def versions(self, name):
            return ()

        def compatible_versions(self, name, platform_info):
            return ()

    monkeypatch.setattr(selfcheck_module.BackendCatalog, "load", lambda: EmptyCatalog())
    monkeypatch.setattr(
        selfcheck_module,
        "detect_platform",
        lambda: PlatformInfo("linux", "amd64", "glibc"),
    )
    missing = catalog_check()
    assert missing.level == "FAIL"
    assert "catalog has no stable releases" in missing.detail
    selection = selection_check()
    assert selection.level == "FAIL"
    assert "catalog has no verified stable" in selection.detail
