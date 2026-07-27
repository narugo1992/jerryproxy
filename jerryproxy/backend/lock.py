"""Small cross-platform exclusive operation lock."""

import os
import uuid

from ..errors import BackendBusyError
from ..utils.fs import ensure_private_directory


class BackendOperationLock(object):
    def __init__(self, path):  # type: (Path) -> None
        self.path = path
        self.descriptor = -1
        self.owner = "%s %s" % (os.getpid(), uuid.uuid4().hex)

    def __enter__(self):
        ensure_private_directory(self.path.parent)
        for attempt in range(2):
            try:
                self.descriptor = os.open(
                    str(self.path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                break
            except FileExistsError:
                # A dead recorded PID identifies a crash-stale backend lock.
                if attempt == 0 and self._remove_stale_lock():
                    continue
                raise BackendBusyError("backend operation already in progress: %s" % self.path.name)
        os.write(self.descriptor, ("%s\n" % self.owner).encode("ascii"))
        os.fsync(self.descriptor)
        return self

    def __exit__(self, exception_type, exception, traceback):
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        if self._read_owner() == self.owner:
            try:
                self.path.unlink()
            except FileNotFoundError:
                # An operator may have already cleaned this exact lock.
                pass
        return False

    def _remove_stale_lock(self):  # type: () -> bool
        owner = self._read_owner()
        if owner is None:
            return False
        try:
            pid = int(owner.split(" ", 1)[0])
        except ValueError:
            # Invalid owner data is not enough evidence to delete a lock.
            return False
        if self._process_exists(pid):
            return False
        if self._read_owner() != owner:
            return False
        try:
            self.path.unlink()
        except FileNotFoundError:
            # Another recovery path already removed the stale lock.
            pass
        return True

    def _read_owner(self):  # type: () -> Optional[str]
        try:
            return self.path.read_text(encoding="ascii").strip() or None
        except (FileNotFoundError, UnicodeDecodeError, OSError):
            # Missing, partial, or invalid lock data cannot identify this owner.
            return None

    @staticmethod
    def _process_exists(pid):  # type: (int) -> bool
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            # Platform-specific errors are not enough evidence to delete a lock.
            return True
        return True
