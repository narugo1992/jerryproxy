"""Interpreter, platform, and JerryProxy home checks."""

import os
import platform
import sys
import tempfile

from ..backend.platform import detect_platform
from ..config.meta import __VERSION__
from ..errors import JerryProxyError, UnsupportedPlatformError
from ..lock import JerryProxyOperationLock
from .result import CheckResult, _bounded_line, _error_result


def _directory_paths(paths):
    return (
        paths.root,
        paths.backends,
        paths.bin,
        paths.downloads,
        paths.providers,
        paths.runtimes,
        paths.logs,
        paths.locks,
        paths.active,
        paths.subscriptions,
        paths.nodes,
        paths.leases,
        paths.config,
    )


def _check_runtime():
    if sys.version_info < (3, 7):
        return CheckResult.fail("Python 3.7 or newer is required")
    if not __VERSION__:
        return CheckResult.fail("package version is empty")
    frozen = bool(getattr(sys, "frozen", False))
    return CheckResult.ok(
        "Python %s; JerryProxy %s; frozen=%s" % (platform.python_version(), __VERSION__, str(frozen).lower())
    )


def _check_platform():
    try:
        platform_info = detect_platform()
    except UnsupportedPlatformError as error:
        # Platform-dependent checks have no applicable target on an unsupported host.
        return CheckResult.skip("%s: %s" % (error.__class__.__name__, _bounded_line(error)))
    except (OSError, RuntimeError) as error:
        # Host platform metadata may be temporarily unreadable.
        return _error_result(error)
    return CheckResult.ok(platform_info.key)


def _check_home_layout(paths):
    try:
        with JerryProxyOperationLock(paths):
            directory_paths = _directory_paths(paths)
            missing = [str(path) for path in directory_paths if not path.is_dir()]
    except (JerryProxyError, OSError) as error:
        # Home initialization can fail through lock contention or filesystem access.
        return _error_result(error)
    if missing:
        return CheckResult.fail("missing state directories: %s" % ", ".join(missing))
    return CheckResult.ok("%d private state directories" % len(directory_paths))


def _check_home_writable(paths):
    try:
        with JerryProxyOperationLock(paths):
            descriptor, temporary_name = tempfile.mkstemp(prefix=".self-check-", dir=str(paths.root))
            try:
                os.write(descriptor, b"jerryproxy-self-check\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)
    except (JerryProxyError, OSError) as error:
        # Lock contention and filesystem writes are expected operational failures.
        return _error_result(error)
    return CheckResult.ok("temporary write and cleanup succeeded")


def _check_private_permissions(paths):
    try:
        with JerryProxyOperationLock(paths):
            if os.name != "posix":
                return CheckResult.skip("POSIX mode checks do not apply on %s" % os.name)
            unexpected = []
            for path in _directory_paths(paths):
                mode = path.stat().st_mode & 0o777
                if mode != 0o700:
                    unexpected.append("%s=%03o" % (path, mode))
    except (JerryProxyError, OSError) as error:
        # Permission inspection can fail through lock or filesystem access.
        return _error_result(error)
    if unexpected:
        return CheckResult.fail("state directory modes are not 0700: %s" % ", ".join(unexpected))
    return CheckResult.ok("all state directories are 0700")
