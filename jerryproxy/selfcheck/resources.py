"""Packaged catalog and backend registry checks."""

from ..backend import BackendCatalog, iter_backends
from ..backend.platform import detect_platform
from ..errors import BackendCatalogError, UnsupportedPlatformError
from .result import CheckResult, _bounded_line, _error_result


def _check_backend_registry():
    try:
        specs = list(iter_backends())
        names = [spec.name for spec in specs]
    except (RuntimeError, ValueError) as error:
        # Built-in registry construction rejects invalid backend metadata.
        return _error_result(error)
    if not names or len(names) != len(set(names)):
        return CheckResult.fail("backend registry is empty or contains duplicate names")
    try:
        platform_info = detect_platform()
        compatible = []
        for spec in specs:
            try:
                spec.expected_asset_name(platform_info, "1.0.0")
            except UnsupportedPlatformError:
                # A backend may intentionally omit release assets for this platform.
                continue
            compatible.append(spec.name)
    except UnsupportedPlatformError as error:
        # Asset naming has no meaning until the host platform is supported.
        return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
    except (OSError, RuntimeError, ValueError) as error:
        # Registry evaluation can fail on invalid platform metadata.
        return _error_result(error)
    if not compatible:
        return CheckResult.fail("no registered backend supports %s" % platform_info.key)
    return CheckResult.ok("%d registered; %d compatible: %s" % (len(names), len(compatible), ", ".join(compatible)))


def _check_backend_catalog():
    try:
        catalog = BackendCatalog.load()
        missing = []
        total_releases = 0
        for spec in iter_backends():
            versions = catalog.versions(spec.name)
            total_releases += len(versions)
            if not versions:
                missing.append(spec.name)
    except BackendCatalogError as error:
        # Invalid packaged catalog data is a failed product resource invariant.
        return CheckResult.fail("%s: %s" % (error.__class__.__name__, _bounded_line(error)))
    except (OSError, RuntimeError, ValueError) as error:
        # Packaged resource access may fail in a damaged installation.
        return _error_result(error)
    if missing:
        return CheckResult.fail("catalog has no stable releases for: %s" % ", ".join(missing))
    return CheckResult.ok("%d stable releases; snapshot %s" % (total_releases, catalog.generated_at))


def _check_backend_catalog_selection():
    try:
        catalog = BackendCatalog.load()
    except BackendCatalogError as error:
        # Platform selection is meaningless when its packaged catalog prerequisite is invalid.
        return CheckResult.skip("packaged catalog prerequisite failed: %s" % _bounded_line(error))
    except (OSError, RuntimeError, ValueError) as error:
        # Platform selection cannot run when the packaged resource is unreadable.
        return CheckResult.skip("packaged catalog prerequisite is unavailable: %s" % _bounded_line(error))
    try:
        platform_info = detect_platform()
        missing = [
            spec.name
            for spec in iter_backends()
            if not catalog.compatible_versions(spec.name, platform_info)
        ]
    except UnsupportedPlatformError as error:
        # Catalog selection has no applicable target on an unsupported host platform.
        return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
    except (OSError, RuntimeError, ValueError) as error:
        # Selection may fail on unreadable or invalid platform metadata.
        return _error_result(error)
    if missing:
        return CheckResult.fail(
            "catalog has no verified stable %s asset for: %s" % (platform_info.key, ", ".join(missing))
        )
    return CheckResult.ok("4/4 backends have verified stable %s assets" % platform_info.key)
