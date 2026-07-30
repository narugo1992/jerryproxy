"""Home-wide process locking through the upstream filelock package."""

import re
import sys
from contextlib import ExitStack
from dataclasses import dataclass

import filelock
from filelock import FileLock, Timeout

from .errors import JerryProxyBusyError

_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:\.post\d+)?$")


@dataclass(frozen=True)
class FileLockStatus:
    """Installed filelock version and its JerryProxy compatibility level."""

    level: str
    version: str
    detail: str


def _minimum_filelock_version():
    # type: () -> tuple
    if sys.version_info < (3, 8):
        return (3, 12, 2)
    if sys.version_info < (3, 9):
        return (3, 16, 1)
    if sys.version_info < (3, 10):
        return (3, 19, 1)
    return (3, 30, 0)


def filelock_status():
    # type: () -> FileLockStatus
    """Describe the installed filelock line without altering its behavior."""

    version = str(filelock.__version__)
    match = _VERSION_PATTERN.match(version)
    if match is None:
        return FileLockStatus(
            "WARN",
            version,
            "filelock %s has unrecognized version metadata; reinstall JerryProxy dependencies" % version,
        )
    installed = tuple(int(value) for value in match.groups())
    minimum = _minimum_filelock_version()
    if installed < minimum:
        return FileLockStatus(
            "WARN",
            version,
            "filelock %s is older than the recommended %s.%s.%s floor"
            % ((version,) + minimum),
        )
    if sys.version_info < (3, 10):
        return FileLockStatus(
            "WARN",
            version,
            "filelock %s is the legacy Python compatibility line affected by CVE-2025-68146; "
            "upgrade to Python 3.10+ when possible" % version,
        )
    return FileLockStatus("OK", version, "filelock %s uses the supported native lock line" % version)


class JerryProxyOperationLock(object):
    """Serialize all managed-state access for one JerryProxy home."""

    def __init__(self, paths, timeout=0.0, initialize=True):
        self.paths = paths
        self.timeout = timeout
        self.initialize = initialize
        self._exit_stack = None

    def _validate_existing_lock(self):  # type: () -> None
        from .home import is_path_alias

        if (
            not self.paths.root.is_dir()
            or not self.paths.locks.is_dir()
            or is_path_alias(self.paths.locks)
            or not self.paths.lock_file.is_file()
            or is_path_alias(self.paths.lock_file)
        ):
            raise FileNotFoundError("JerryProxy home has no existing operation lock")

    def __enter__(self):
        if self.initialize:
            self.paths._ensure_lock_bootstrap()
        else:
            self._validate_existing_lock()
        lock = FileLock(str(self.paths.lock_file), timeout=self.timeout, mode=0o600)
        stack = ExitStack()
        try:
            stack.enter_context(lock.acquire())
        except Timeout as error:
            # filelock raises Timeout when another process owns the home lock.
            raise JerryProxyBusyError(
                "JerryProxy operation already in progress for home: %s" % self.paths.root
            ) from error
        with stack:
            if self.initialize:
                self.paths._ensure_layout_locked()
                from .backend.removal import _recover_removal_transactions

                _recover_removal_transactions(self.paths)
            else:
                self._validate_existing_lock()
            self._exit_stack = stack.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._exit_stack is not None:
            self._exit_stack.close()
            self._exit_stack = None
        return False
