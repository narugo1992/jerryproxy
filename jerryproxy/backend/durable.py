"""Durable file publication primitives for backend transactions."""

import errno
import json
import os
import stat
from pathlib import Path

from ..errors import DurabilityError, IntegrityError
from ..home import is_path_alias

FLUSHED = "flushed"
UNSUPPORTED = "unsupported"

_UNSUPPORTED_FLUSH_ERRNOS = frozenset(
    value
    for value in (
        errno.EINVAL,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)


def flush_descriptor(descriptor, kind):
    # type: (int, str) -> str
    """Flush one validated descriptor and classify unsupported capability."""

    try:
        os.fsync(descriptor)
    except OSError as error:
        # fsync reports documented capability gaps and genuine storage failures as OSError.
        if os.name != "nt" and error.errno in _UNSUPPORTED_FLUSH_ERRNOS:
            return UNSUPPORTED
        raise DurabilityError("unable to flush %s" % kind) from error
    return FLUSHED


def flush_directory(path):
    # type: (Path) -> str
    """Flush one non-aliased directory where the platform documents support."""

    path = Path(path)
    if os.name == "nt":
        return UNSUPPORTED
    if is_path_alias(path):
        raise IntegrityError("managed directory flush path must not be an alias: %s" % path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        # Opening the directory may itself expose a filesystem capability gap.
        if error.errno in _UNSUPPORTED_FLUSH_ERRNOS:
            return UNSUPPORTED
        raise DurabilityError("unable to open directory for flush: %s" % path) from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISDIR(status.st_mode):
            raise IntegrityError("managed flush path is not a directory: %s" % path)
        return flush_descriptor(descriptor, "directory")
    finally:
        os.close(descriptor)


def durable_replace(source, destination, replace=os.replace, flush_directory=flush_directory):
    # type: (Path, Path, Callable, Callable) -> tuple
    """Atomically replace one path and flush every affected parent directory."""

    source = Path(source)
    destination = Path(destination)
    replace(str(source), str(destination))
    parents = [source.parent]
    if destination.parent != source.parent:
        parents.append(destination.parent)
    return tuple(flush_directory(parent) for parent in parents)


def durable_write_json(
    path,
    value,
    temporary,
    flush_file=None,
    replace=os.replace,
    flush_directory=flush_directory,
):
    # type: (Path, dict, Path, Optional[Callable], Callable, Callable) -> tuple
    """Publish canonical JSON through one exclusive adjacent writer temporary."""

    path = Path(path)
    temporary = Path(temporary)
    if temporary.parent != path.parent:
        raise ValueError("durable JSON temporary must be adjacent to its destination")
    payload = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(temporary), flags, 0o600)
    created = True
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            file_outcome = (flush_file or (lambda value: flush_descriptor(value, "regular file")))(stream.fileno())
        replace(str(temporary), str(path))
        created = False
        parent_outcome = flush_directory(path.parent)
        return file_outcome, parent_outcome
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created and os.path.lexists(str(temporary)):
            temporary.unlink()
