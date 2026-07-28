"""Lightweight black-box checks for source and packaged JerryProxy CLIs."""

import os
import platform
import sys
import tempfile

from .backend import BackendManager, iter_backends
from .backend.platform import detect_platform
from .config.meta import __VERSION__


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
    )


def _check_runtime():
    if sys.version_info < (3, 7):
        raise RuntimeError("Python 3.7 or newer is required")
    if not __VERSION__:
        raise RuntimeError("package version is empty")
    frozen = bool(getattr(sys, "frozen", False))
    return "Python %s; JerryProxy %s; frozen=%s" % (
        platform.python_version(),
        __VERSION__,
        str(frozen).lower(),
    )


def _check_platform():
    platform_info = detect_platform()
    return platform_info.key


def _check_home_layout(paths):
    paths.ensure()
    missing = [str(path) for path in _directory_paths(paths) if not path.is_dir()]
    if missing:
        raise RuntimeError("missing state directories: %s" % ", ".join(missing))
    return "%d private state directories" % len(_directory_paths(paths))


def _check_home_writable(paths):
    paths.ensure()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".self-check-", dir=str(paths.root))
    try:
        os.write(descriptor, b"jerryproxy-self-check\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return "temporary write and cleanup succeeded"


def _check_private_permissions(paths):
    paths.ensure()
    if os.name != "posix":
        return "POSIX mode check not applicable"
    unexpected = []
    for path in _directory_paths(paths):
        mode = path.stat().st_mode & 0o777
        if mode != 0o700:
            unexpected.append("%s=%03o" % (path, mode))
    if unexpected:
        raise RuntimeError("state directory modes are not 0700: %s" % ", ".join(unexpected))
    return "all state directories are 0700"


def _check_backend_registry():
    platform_info = detect_platform()
    specs = list(iter_backends())
    names = [spec.name for spec in specs]
    if not names or len(names) != len(set(names)):
        raise RuntimeError("backend registry is empty or contains duplicate names")
    for spec in specs:
        spec.expected_asset_name(platform_info, "1.0.0")
    return "%d backends: %s" % (len(names), ", ".join(names))


def _check_backend_inventory(paths):
    manager = BackendManager(paths)
    installed = manager.list_installed()
    active = manager.list_active()
    for item in active:
        if not item.executable.is_file() or not os.path.lexists(str(item.link)):
            raise RuntimeError("active backend is incomplete: %s %s" % (item.name, item.version))
    return "%d installed; %d active" % (len(installed), len(active))


def build_checks(paths):
    return (
        ("Python runtime", _check_runtime),
        ("platform detection", _check_platform),
        ("home directory layout", lambda: _check_home_layout(paths)),
        ("home write access", lambda: _check_home_writable(paths)),
        ("private directory permissions", lambda: _check_private_permissions(paths)),
        ("backend registry", _check_backend_registry),
        ("backend inventory", lambda: _check_backend_inventory(paths)),
    )


def run_checks(checks, output):
    failures = []
    total = len(checks)
    for index, (name, check) in enumerate(checks, start=1):
        label = "[%d/%d] %s" % (index, total, name)
        try:
            detail = check()
        except Exception as error:
            message = str(error).strip() or repr(error)
            failures.append((name, error.__class__.__name__, message))
            output("%s: FAIL - %s: %s" % (label, error.__class__.__name__, message))
        else:
            output("%s: OK - %s" % (label, detail))

    output("Summary: %d OK, %d FAIL" % (total - len(failures), len(failures)))
    if failures:
        output("Self-check FAILED")
        return 1
    output("Self-check PASSED")
    return 0


def run_self_check(paths, output=print):
    output("JerryProxy self-check %s" % __VERSION__)
    output("Home: %s" % paths.root)
    return run_checks(build_checks(paths), output)
