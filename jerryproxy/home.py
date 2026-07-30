"""Cross-platform JerryProxy home-directory layout."""

import os
import stat
from pathlib import Path

from .errors import IntegrityError

HOME_ENVIRONMENT_VARIABLE = "JERRYPROXY_HOME"


def is_path_alias(path):  # type: (Path) -> bool
    """Return whether a managed path is a symlink or Windows reparse point."""

    path = Path(path)
    if path.is_symlink():
        return True
    if os.name != "nt":
        return False
    try:
        attributes = path.lstat().st_file_attributes
    except FileNotFoundError:
        # A missing managed path is created only after this alias check.
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def resolve_home(explicit_home=None):  # type: (Optional[str]) -> Path
    """Resolve the single JerryProxy state root.

    Precedence is an explicit CLI value, ``JERRYPROXY_HOME``, then
    ``~/.jerryproxy`` on every operating system.
    """

    configured = explicit_home or os.environ.get(HOME_ENVIRONMENT_VARIABLE)
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".jerryproxy"


class JerryProxyPaths(object):
    """All mutable JerryProxy paths rooted below one private directory."""

    def __init__(self, root):  # type: (Path) -> None
        self.root = Path(root)

    @classmethod
    def from_value(cls, explicit_home=None):  # type: (Optional[str]) -> "JerryProxyPaths"
        return cls(resolve_home(explicit_home))

    @property
    def backends(self):  # type: () -> Path
        return self.root / "backends"

    @property
    def bin(self):  # type: () -> Path
        return self.root / "bin"

    @property
    def downloads(self):  # type: () -> Path
        return self.root / "downloads"

    @property
    def providers(self):  # type: () -> Path
        return self.root / "providers"

    @property
    def runtimes(self):  # type: () -> Path
        return self.root / "runtimes"

    @property
    def logs(self):  # type: () -> Path
        return self.root / "logs"

    @property
    def locks(self):  # type: () -> Path
        return self.root / "locks"

    @property
    def active(self):  # type: () -> Path
        return self.root / "active"

    @property
    def lock_file(self):  # type: () -> Path
        return self.locks / "jerryproxy.lock"

    @staticmethod
    def _ensure_directory(path, reject_alias=False):  # type: (Path, bool) -> None
        if reject_alias and is_path_alias(path):
            raise IntegrityError(
                "managed JerryProxy home path must not be a symlink or Windows path alias: %s" % path
            )
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if reject_alias and is_path_alias(path):
            raise IntegrityError(
                "managed JerryProxy home path must not be a symlink or Windows path alias: %s" % path
            )
        if os.name == "posix":
            path.chmod(0o700)

    def _ensure_lock_bootstrap(self):  # type: () -> None
        self._ensure_directory(self.root)
        self._ensure_directory(self.locks, reject_alias=True)
        if is_path_alias(self.lock_file):
            raise IntegrityError(
                "managed JerryProxy lock file must not be a symlink or Windows path alias: %s"
                % self.lock_file
            )

    def _managed_directories(self):  # type: () -> tuple
        return (
            self.backends,
            self.bin,
            self.downloads,
            self.providers,
            self.runtimes,
            self.logs,
            self.active,
        )

    @staticmethod
    def _validate_private_mode(path, expected_mode):  # type: (Path, int) -> None
        if os.name != "posix":
            return
        actual_mode = stat.S_IMODE(path.stat().st_mode)
        if actual_mode != expected_mode:
            raise IntegrityError(
                "managed JerryProxy path has unsafe permissions %04o, expected %04o: %s"
                % (actual_mode, expected_mode, path)
            )

    def _validate_existing_layout(self):  # type: () -> bool
        """Validate a complete existing layout without creating or repairing it."""

        if not os.path.lexists(str(self.root)):
            return False
        if not self.root.is_dir():
            raise IntegrityError("JerryProxy home is not a directory: %s" % self.root)

        layout = (self.locks,) + self._managed_directories()
        present = tuple(os.path.lexists(str(path)) for path in layout)
        if not any(present):
            if any(self.root.iterdir()):
                raise IntegrityError("JerryProxy home is incomplete: %s" % self.root)
            return False
        if not all(present):
            raise IntegrityError("JerryProxy home is incomplete: %s" % self.root)

        self._validate_private_mode(self.root, 0o700)
        for path in layout:
            if not path.is_dir() or is_path_alias(path):
                raise IntegrityError(
                    "managed JerryProxy home path is invalid or aliased: %s" % path
                )
            self._validate_private_mode(path, 0o700)

        if os.path.lexists(str(self.lock_file)):
            if not self.lock_file.is_file() or is_path_alias(self.lock_file):
                raise IntegrityError(
                    "managed JerryProxy lock file is invalid or aliased: %s" % self.lock_file
                )
            self._validate_private_mode(self.lock_file, 0o600)
        elif os.name != "nt":
            raise IntegrityError("JerryProxy home is incomplete: %s" % self.root)
        return True

    def _ensure_layout_locked(self):  # type: () -> None
        for path in self._managed_directories():
            self._ensure_directory(path, reject_alias=True)

    def ensure(self):  # type: () -> None
        from .lock import JerryProxyOperationLock

        with JerryProxyOperationLock(self):
            pass
