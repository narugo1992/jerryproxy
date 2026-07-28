"""Cross-platform JerryProxy home-directory layout."""

import os
from pathlib import Path

from .errors import IntegrityError

HOME_ENVIRONMENT_VARIABLE = "JERRYPROXY_HOME"


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

    def ensure(self):  # type: () -> None
        for path in (
            self.root,
            self.backends,
            self.bin,
            self.downloads,
            self.providers,
            self.runtimes,
            self.logs,
            self.locks,
            self.active,
        ):
            if path != self.root and path.is_symlink():
                raise IntegrityError("managed JerryProxy home path must not be a symlink: %s" % path)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path != self.root and path.is_symlink():
                raise IntegrityError("managed JerryProxy home path must not be a symlink: %s" % path)
            if os.name == "posix":
                path.chmod(0o700)
