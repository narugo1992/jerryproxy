"""Synthetic local backend fixtures shared by the mutating probes."""

import hashlib
import zipfile
from pathlib import Path

from ..backend import BackendManager, get_backend, iter_backend_platforms
from ..backend.platform import detect_platform
from ..errors import IntegrityError
from .result import CheckResult, _bounded_line, _error_result


def _recovery_platform():
    platform_info = detect_platform()
    spec = get_backend("mihomo")
    supported = {item.asset_key for item in iter_backend_platforms(spec.name)}
    compatible = [key for key in platform_info.compatible_asset_keys if key in supported]
    if not compatible:
        return platform_info, spec, None
    return platform_info, spec, compatible[0]


def _write_probe_archive(root, spec, platform_info, version, payload):
    archive = Path(root) / ("%s-%s.zip" % (spec.name, version))
    executable_name = spec.executable_filename(platform_info)
    with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr(executable_name, payload)
    return archive, executable_name, hashlib.sha256(archive.read_bytes()).hexdigest()


def _install_probe_version(manager, root, spec, platform_info, asset_platform, version, payload):
    archive, executable_name, digest = _write_probe_archive(
        root,
        spec,
        platform_info,
        version,
        payload,
    )
    return manager.install_from_archive(
        spec.name,
        version,
        archive,
        expected_sha256=digest,
        asset_name=archive.name,
        asset_platform=asset_platform,
        archive_executable=executable_name,
        activate=False,
    )


def _probe_manager(paths, platform_info):
    return BackendManager(
        paths,
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )


def _recovery_artifacts(paths):
    return (
        tuple(paths.runtimes.glob(".install-*"))
        + tuple(paths.runtimes.glob(".use-*"))
        + tuple(paths.runtimes.glob(".remove-*"))
        + tuple(paths.bin.glob(".*.use-*.candidate"))
        + tuple(paths.active.glob(".*.use-*.candidate.json"))
    )


def _recovery_failure(error):
    if isinstance(error, IntegrityError):
        return CheckResult.fail("%s: %s" % (error.__class__.__name__, _bounded_line(error)))
    return _error_result(error)


def _unsupported_recovery_platform(error):
    return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
