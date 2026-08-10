"""Crash-recovery checks driven by real hard-exiting child processes."""

import os
import tempfile
from pathlib import Path

from ..backend.installation import InstallTransaction
from ..backend.platform import detect_platform
from ..errors import JerryProxyError, UnsupportedPlatformError
from ..home import JerryProxyPaths
from ..lock import JerryProxyOperationLock
from .fixtures import (
    _install_probe_version,
    _probe_manager,
    _recovery_artifacts,
    _recovery_failure,
    _recovery_platform,
    _unsupported_recovery_platform,
)
from .processes import (
    _RECOVERY_CHILD_ERROR,
    _run_recovery_child,
    _write_recovery_child_error,
)
from .result import CheckResult

_RECOVERY_CHILD_INSTALL = 71
_RECOVERY_CHILD_ACTIVATION_ROLLBACK = 72
_RECOVERY_CHILD_ACTIVATION_ROLLFORWARD = 73
_RECOVERY_CHILD_REMOVAL_ROLLBACK = 74
_RECOVERY_CHILD_REMOVAL_ROLLFORWARD = 75


def _install_recovery_child(root, error_log):
    try:
        paths = JerryProxyPaths(Path(root))
        platform_info, spec, asset_platform = _recovery_platform()
        artifact = {
            "sha256": "0" * 64,
            "size": 1,
            "asset_name": "interrupted.zip",
            "platform": asset_platform,
        }
        with JerryProxyOperationLock(paths, platform_info=platform_info):
            transaction = InstallTransaction.prepare(paths, spec.name, "9.9.9", artifact)
            staging = transaction.begin_staging()
            (staging / "partial").write_bytes(b"interrupted")
        os._exit(_RECOVERY_CHILD_INSTALL)
    except (JerryProxyError, OSError, RuntimeError, ValueError):
        # Child setup failures are serialized for the parent self-check result.
        _write_recovery_child_error(error_log)
        os._exit(_RECOVERY_CHILD_ERROR)


def _activation_recovery_child(root, version, direction, error_log):
    try:
        from ..backend import activation as activation_module

        paths = JerryProxyPaths(Path(root))
        platform_info = detect_platform()
        manager = _probe_manager(paths, platform_info)
        if direction == "rollback":
            original_replace = activation_module.durable_replace

            def crash_after_first_publication(source, destination, *args, **kwargs):
                original_replace(source, destination, *args, **kwargs)
                os._exit(_RECOVERY_CHILD_ACTIVATION_ROLLBACK)

            activation_module.durable_replace = crash_after_first_publication
        else:

            def crash_after_commit(paths, platform_info):
                del paths, platform_info
                os._exit(_RECOVERY_CHILD_ACTIVATION_ROLLFORWARD)

            activation_module.recover_use_transactions = crash_after_commit
        manager.use("mihomo", version)
        os._exit(_RECOVERY_CHILD_ERROR)
    except (JerryProxyError, OSError, RuntimeError, ValueError):
        # Child activation failures are serialized for the parent self-check result.
        _write_recovery_child_error(error_log)
        os._exit(_RECOVERY_CHILD_ERROR)


def _removal_recovery_child(root, version, direction, error_log):
    try:
        from ..backend import removal as removal_module

        paths = JerryProxyPaths(Path(root))
        manager = _probe_manager(paths, detect_platform())
        if direction == "rollback":
            original_move = removal_module._move_no_replace

            def crash_after_first_move(*args, **kwargs):
                original_move(*args, **kwargs)
                os._exit(_RECOVERY_CHILD_REMOVAL_ROLLBACK)

            removal_module._move_no_replace = crash_after_first_move
        else:
            original_write = removal_module._write_removal_journal

            def crash_after_commit(*args, **kwargs):
                result = original_write(*args, **kwargs)
                if kwargs.get("phase", "staging") == "committed":
                    os._exit(_RECOVERY_CHILD_REMOVAL_ROLLFORWARD)
                return result

            removal_module._write_removal_journal = crash_after_commit
        manager.uninstall("mihomo", version, deactivate=True)
        os._exit(_RECOVERY_CHILD_ERROR)
    except (JerryProxyError, OSError, RuntimeError, ValueError):
        # Child removal failures are serialized for the parent self-check result.
        _write_recovery_child_error(error_log)
        os._exit(_RECOVERY_CHILD_ERROR)




def _check_install_recovery(supervision=None):
    try:
        platform_info, unused_spec, asset_platform = _recovery_platform()
        if asset_platform is None:
            return CheckResult.skip("no recovery fixture asset shape supports %s" % platform_info.key)
        with tempfile.TemporaryDirectory(prefix="jerryproxy-install-recovery-self-check-") as temporary:
            paths = JerryProxyPaths(Path(temporary) / ".jerryproxy")
            error_log = Path(temporary) / "child-error.log"
            result = _run_recovery_child(
                _install_recovery_child,
                (str(paths.root),),
                _RECOVERY_CHILD_INSTALL,
                error_log,
                supervision=supervision,
            )
            if result is not None:
                return result
            inventory = _probe_manager(paths, platform_info).inventory()
            if inventory.installed or inventory.active:
                return CheckResult.fail("hard-exit install rollback retained public backend state")
            if _recovery_artifacts(paths) or any(paths.backends.rglob(".*.install-*")):
                return CheckResult.fail("hard-exit install rollback retained recovery evidence")
    except UnsupportedPlatformError as error:
        # Install recovery requires a supported backend platform fixture.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Spawn coordination and isolated install recovery may fail operationally.
        return _recovery_failure(error)
    return CheckResult.ok("hard-exit install staging rolled back and converged")


def _prepare_activation_recovery(temporary):
    root = Path(temporary)
    platform_info, spec, asset_platform = _recovery_platform()
    if asset_platform is None:
        return platform_info, spec, None, None
    paths = JerryProxyPaths(root / ".jerryproxy")
    manager = _probe_manager(paths, platform_info)
    _install_probe_version(
        manager,
        root,
        spec,
        platform_info,
        asset_platform,
        "1.0.0",
        b"jerryproxy-recovery-previous\n",
    )
    target = _install_probe_version(
        manager,
        root,
        spec,
        platform_info,
        asset_platform,
        "2.0.0",
        b"jerryproxy-recovery-target\n",
    )
    manager.use(spec.name, "1.0.0")
    return platform_info, spec, manager, target


def _check_activation_recovery(direction, supervision=None):
    expected_exit = (
        _RECOVERY_CHILD_ACTIVATION_ROLLBACK if direction == "rollback" else _RECOVERY_CHILD_ACTIVATION_ROLLFORWARD
    )
    expected_version = "1.0.0" if direction == "rollback" else "2.0.0"
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-activation-recovery-self-check-") as temporary:
            platform_info, spec, manager, target = _prepare_activation_recovery(temporary)
            if manager is None:
                return CheckResult.skip("no recovery fixture asset shape supports %s" % platform_info.key)
            error_log = Path(temporary) / "child-error.log"
            result = _run_recovery_child(
                _activation_recovery_child,
                (str(manager.paths.root), target.version, direction),
                expected_exit,
                error_log,
                supervision=supervision,
            )
            if result is not None:
                return result
            active = manager.current(spec.name)
            if active is None or active.version != expected_version:
                return CheckResult.fail("activation %s recovery selected the wrong version" % direction)
            if active.link.read_bytes() != active.executable.read_bytes() or _recovery_artifacts(manager.paths):
                return CheckResult.fail("activation %s recovery did not converge cleanly" % direction)
    except UnsupportedPlatformError as error:
        # Activation recovery requires a supported backend platform fixture.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Isolated activation setup, hard exit, and lock-triggered recovery may fail operationally.
        return _recovery_failure(error)
    return CheckResult.ok("hard-exit activation %s converged to %s" % (direction, expected_version))


def _check_removal_recovery(direction, supervision=None):
    expected_exit = _RECOVERY_CHILD_REMOVAL_ROLLBACK if direction == "rollback" else _RECOVERY_CHILD_REMOVAL_ROLLFORWARD
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-removal-recovery-self-check-") as temporary:
            root = Path(temporary)
            platform_info, spec, asset_platform = _recovery_platform()
            if asset_platform is None:
                return CheckResult.skip("no recovery fixture asset shape supports %s" % platform_info.key)
            paths = JerryProxyPaths(root / ".jerryproxy")
            manager = _probe_manager(paths, platform_info)
            installed = _install_probe_version(
                manager,
                root,
                spec,
                platform_info,
                asset_platform,
                "1.0.0",
                b"jerryproxy-removal-recovery\n",
            )
            manager.use(spec.name, installed.version)
            error_log = root / "child-error.log"
            result = _run_recovery_child(
                _removal_recovery_child,
                (str(paths.root), installed.version, direction),
                expected_exit,
                error_log,
                supervision=supervision,
            )
            if result is not None:
                return result
            inventory = manager.inventory()
            if direction == "rollback":
                if len(inventory.installed) != 1 or len(inventory.active) != 1:
                    return CheckResult.fail("removal rollback did not restore installed and active state")
                if inventory.active[0].link.read_bytes() != inventory.active[0].executable.read_bytes():
                    return CheckResult.fail("removal rollback restored an unusable active command")
            elif inventory.installed or inventory.active:
                return CheckResult.fail("committed removal recovery did not dispose public state")
            if _recovery_artifacts(paths):
                return CheckResult.fail("removal %s recovery retained transaction evidence" % direction)
    except UnsupportedPlatformError as error:
        # Removal recovery requires a supported backend platform fixture.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Isolated removal setup, hard exit, and lock-triggered recovery may fail operationally.
        return _recovery_failure(error)
    return CheckResult.ok("hard-exit removal %s converged" % direction)
