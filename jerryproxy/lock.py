"""Home-wide process locking through the upstream filelock package."""

import os
import re
import sys
import time
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

    def __init__(self, paths, timeout=0.0, initialize=True, platform_info=None):
        self.paths = paths
        self.timeout = timeout
        self.initialize = initialize
        self.platform_info = platform_info
        self._exit_stack = None
        self._restore_lock_marker = False

    def _new_file_lock(self):  # type: () -> FileLock
        """Create the upstream lock, preserving its marker when supported."""

        try:
            lock = FileLock(
                str(self.paths.lock_file),
                timeout=self.timeout,
                mode=0o600,
                preserve_lock_file=True,
            )
        except TypeError:
            # Python 3.7-3.9 use the legacy filelock API without the public
            # marker-preservation option; restore its marker after release.
            self._restore_lock_marker = True
            lock = FileLock(str(self.paths.lock_file), timeout=self.timeout, mode=0o600)
        return lock

    def _restore_marker_after_release(self):  # type: () -> None
        """Recreate a legacy Windows marker without replacing an existing path."""

        if not self._restore_lock_marker or os.name != "nt":
            return
        from .home import is_path_alias

        if os.path.lexists(str(self.paths.lock_file)):
            if is_path_alias(self.paths.lock_file):
                raise OSError("managed JerryProxy lock file became an alias")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for _attempt in range(3):
            descriptor = -1
            try:
                descriptor = os.open(str(self.paths.lock_file), flags, 0o600)
                return
            except FileExistsError:
                # Another legacy waiter may have recreated the marker between
                # the existence check and O_EXCL. Recheck before retrying so a
                # release/acquire race cannot silently lose the marker.
                if os.path.lexists(str(self.paths.lock_file)):
                    from .home import is_path_alias

                    if is_path_alias(self.paths.lock_file):
                        raise OSError("managed JerryProxy lock file became an alias")
                time.sleep(0.001)
            finally:
                if descriptor != -1:
                    os.close(descriptor)
        if os.path.lexists(str(self.paths.lock_file)):
            from .home import is_path_alias

            if is_path_alias(self.paths.lock_file):
                raise OSError("managed JerryProxy lock file became an alias")
            return
        raise OSError("managed JerryProxy lock marker could not be restored")

    def _validate_existing_lock(self):  # type: () -> None
        from .home import is_path_alias

        if (
            not self.paths.root.is_dir()
            or not self.paths.locks.is_dir()
            or is_path_alias(self.paths.locks)
        ):
            raise FileNotFoundError("JerryProxy home has no existing operation lock")
        if os.path.lexists(str(self.paths.lock_file)) and (
            not self.paths.lock_file.is_file() or is_path_alias(self.paths.lock_file)
        ):
            raise FileNotFoundError("JerryProxy home has no safe operation lock path")

    def __enter__(self):
        if self.initialize:
            self.paths._ensure_lock_bootstrap()
        else:
            if not self.paths._validate_existing_layout():
                raise FileNotFoundError("JerryProxy home has no existing managed state")
            self._validate_existing_lock()
        lock = self._new_file_lock()
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
            else:
                self._validate_existing_lock()
                if not self.paths._validate_existing_layout():
                    raise FileNotFoundError("JerryProxy home has no existing managed state")
            from .backend.recovery import recover_backend_transactions

            recover_backend_transactions(self.paths, self.platform_info)
            if not self.paths._validate_existing_layout():
                raise FileNotFoundError("JerryProxy home changed during transaction recovery")
            self._exit_stack = stack.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._exit_stack is not None:
            try:
                self._exit_stack.close()
            finally:
                self._restore_marker_after_release()
            self._exit_stack = None
        return False
