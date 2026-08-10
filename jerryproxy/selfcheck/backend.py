"""Backend inventory and isolated lifecycle checks."""

import tempfile
from pathlib import Path

from ..backend import BackendManager
from ..backend.platform import detect_platform
from ..errors import IntegrityError, JerryProxyError, UnsupportedPlatformError
from ..home import JerryProxyPaths
from .fixtures import (
    _install_probe_version,
    _probe_manager,
    _recovery_artifacts,
    _recovery_failure,
    _recovery_platform,
    _unsupported_recovery_platform,
)
from .result import CheckResult, _bounded_line, _error_result


def _check_backend_inventory(paths):
    try:
        inventory = BackendManager(paths, platform_info=detect_platform()).inventory()
    except UnsupportedPlatformError as error:
        # Inventory interpretation depends on the current backend platform contract.
        return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
    except IntegrityError as error:
        # Retained managed-state evidence is a failed integrity requirement.
        message = str(error).strip() or repr(error)
        return CheckResult.fail("%s: %s" % (error.__class__.__name__, message))
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Operational and unexpected inventory failures are diagnostic errors.
        return _error_result(error)
    return CheckResult.ok("%d installed; %d active" % (len(inventory.installed), len(inventory.active)))


def _check_isolated_backend_lifecycle():
    try:
        platform_info, spec, asset_platform = _recovery_platform()
        if asset_platform is None:
            return CheckResult.skip("no Mihomo fixture asset shape supports %s" % platform_info.key)
        with tempfile.TemporaryDirectory(prefix="jerryproxy-lifecycle-self-check-") as temporary:
            root = Path(temporary)
            paths = JerryProxyPaths(root / ".jerryproxy")
            manager = _probe_manager(paths, platform_info)
            installed = _install_probe_version(
                manager,
                root,
                spec,
                platform_info,
                asset_platform,
                "1.0.0",
                b"jerryproxy-lifecycle-self-check\n",
            )
            active = manager.use(spec.name, installed.version)
            manager.verify(spec.name, installed.version)
            manager.uninstall(spec.name, installed.version, deactivate=True)
            inventory = manager.inventory()
            if inventory.installed or inventory.active or _recovery_artifacts(paths):
                return CheckResult.fail("isolated backend lifecycle left managed state behind")
            if active.version != installed.version:
                return CheckResult.fail("isolated backend lifecycle activated the wrong version")
    except UnsupportedPlatformError as error:
        # The synthetic lifecycle has no meaningful backend asset shape on this host.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Local archive, installation, activation, verification, and removal failures are diagnostics.
        return _recovery_failure(error)
    return CheckResult.ok("install, use, verify, and uninstall succeeded in an isolated home")
