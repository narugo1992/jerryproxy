"""Crash-recoverable and alias-safe backend removal primitives."""

import ctypes
import os
import re
import stat
from pathlib import Path, PurePosixPath

from ..errors import CleanupScopeError, IntegrityError, RemovalCleanupError
from ..home import is_path_alias
from ..utils.fs import atomic_write_json, ensure_private_directory, read_json

_TRANSACTION_PATTERN = re.compile(r"^\.remove-[0-9a-f]{32}$")
_JOURNAL_NAME = "journal.json"
_MOVE_KINDS = {
    "download": ("downloads", "download-"),
    "installed": ("backends", "installed-"),
    "active-link": ("bin", "active-link"),
    "active-manifest": ("active", "active-manifest"),
}

_WINDOWS_DELETE = 0x00010000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_DISPOSITION_INFO_CLASS = 4
_WINDOWS_FILE_ID_INFO_CLASS = 18
_WINDOWS_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_WINDOWS_UNSUPPORTED_FILE_ID_ERRORS = (1, 50, 87)


class _WindowsFileTime(ctypes.Structure):
    _fields_ = (
        ("low_date_time", ctypes.c_uint32),
        ("high_date_time", ctypes.c_uint32),
    )


class _WindowsFileInformation(ctypes.Structure):
    _fields_ = (
        ("file_attributes", ctypes.c_uint32),
        ("creation_time", _WindowsFileTime),
        ("last_access_time", _WindowsFileTime),
        ("last_write_time", _WindowsFileTime),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    )


class _WindowsFileDispositionInformation(ctypes.Structure):
    _fields_ = (("delete_file", ctypes.c_ubyte),)


class _WindowsFileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _WindowsFileIdInformation(ctypes.Structure):
    _fields_ = (
        ("volume_serial_number", ctypes.c_uint64),
        ("file_id", _WindowsFileId128),
    )


if ctypes.sizeof(_WindowsFileDispositionInformation) != 1:  # pragma: no cover - ctypes ABI invariant
    raise RuntimeError("FILE_DISPOSITION_INFO must use the one-byte Windows BOOLEAN ABI")
if ctypes.sizeof(_WindowsFileInformation) != 52:  # pragma: no cover - ctypes ABI invariant
    raise RuntimeError("BY_HANDLE_FILE_INFORMATION must use the 52-byte Windows ABI")
if ctypes.sizeof(_WindowsFileIdInformation) != 24:  # pragma: no cover - ctypes ABI invariant
    raise RuntimeError("FILE_ID_INFO must use the 24-byte Windows ABI")


class _WindowsIdentityGuard(object):
    def __init__(self, path, handle, identities, status_identity, number_of_links, is_directory, size):
        self.path = Path(path)
        self.handle = handle
        self.identities = tuple(identities)
        self.status_identity = status_identity
        self.number_of_links = number_of_links
        self.is_directory = is_directory
        self.size = size


_WINDOWS_KERNEL32 = None
if os.name == "nt":
    _WINDOWS_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _WINDOWS_KERNEL32.CreateFileW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    _WINDOWS_KERNEL32.CreateFileW.restype = ctypes.c_void_p
    _WINDOWS_KERNEL32.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsFileInformation),
    )
    _WINDOWS_KERNEL32.GetFileInformationByHandle.restype = ctypes.c_int32
    _WINDOWS_KERNEL32.GetFileInformationByHandleEx.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    _WINDOWS_KERNEL32.GetFileInformationByHandleEx.restype = ctypes.c_int32
    _WINDOWS_KERNEL32.SetFileInformationByHandle.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    _WINDOWS_KERNEL32.SetFileInformationByHandle.restype = ctypes.c_int32
    _WINDOWS_KERNEL32.CloseHandle.argtypes = (ctypes.c_void_p,)
    _WINDOWS_KERNEL32.CloseHandle.restype = ctypes.c_int32


def _alias_error(error_type, path):
    raise error_type(
        "refusing removal through managed symlink or Windows path alias (managed path alias): %s" % path
    )


def _validate_chain(root, target, error_type):
    root = Path(root)
    current = Path(target)
    while True:
        if is_path_alias(current):
            _alias_error(error_type, current)
        if current == root:
            return
        if current.parent == current:  # pragma: no cover - callers constrain targets below managed roots
            raise error_type("managed removal target escapes its area: %s" % target)
        current = current.parent


def _identity(stat_result):
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat.S_IFMT(stat_result.st_mode)),
    )


def _snapshot_identity(stat_result):
    return _identity(stat_result) + (
        int(stat_result.st_size),
        int(stat_result.st_mtime_ns),
        int(stat_result.st_ctime_ns),
    )


def _windows_extended_path(path):
    value = os.path.abspath(str(path))
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_error():
    return ctypes.WinError(ctypes.get_last_error())


def _close_windows_guard(guard):
    if not _WINDOWS_KERNEL32.CloseHandle(guard.handle):
        raise _windows_error()


def _close_identity_guard(descriptor):
    if isinstance(descriptor, _WindowsIdentityGuard):
        _close_windows_guard(descriptor)
        return
    os.close(descriptor)


def _windows_status_matches_guard(status, guard):
    status_identity = (int(status.st_dev), int(status.st_ino))
    if (
        status_identity[1] == 0
        or status_identity != guard.status_identity
        or status_identity not in guard.identities
    ):
        return False
    is_directory = stat.S_ISDIR(status.st_mode)
    if is_directory != guard.is_directory:
        return False
    if not is_directory and int(status.st_nlink) != guard.number_of_links:
        return False
    return is_directory or int(status.st_size) == guard.size


def _open_windows_identity_guard(path, status, error_type):
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(path),
        _WINDOWS_DELETE | _WINDOWS_FILE_READ_ATTRIBUTES,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        cause = _windows_error()
        raise error_type("unable to pin managed removal path: %s" % path) from cause
    information = _WindowsFileInformation()
    if not _WINDOWS_KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        cause = _windows_error()
        guard = _WindowsIdentityGuard(path, handle, (), None, 0, False, 0)
        _close_windows_guard(guard)
        raise error_type("unable to identify pinned managed removal path: %s" % path) from cause
    file_index = (int(information.file_index_high) << 32) | int(information.file_index_low)
    size = (int(information.file_size_high) << 32) | int(information.file_size_low)
    identities = []
    if file_index:
        identities.append((int(information.volume_serial_number), file_index))
    extended_information = _WindowsFileIdInformation()
    if _WINDOWS_KERNEL32.GetFileInformationByHandleEx(
        handle,
        _WINDOWS_FILE_ID_INFO_CLASS,
        ctypes.byref(extended_information),
        ctypes.sizeof(extended_information),
    ):
        extended_file_index = int.from_bytes(bytes(extended_information.file_id.identifier), "little")
        if not extended_file_index:
            extended_file_index = file_index
        extended_identity = (int(extended_information.volume_serial_number), extended_file_index)
        if extended_file_index and extended_identity not in identities:
            identities.append(extended_identity)
    else:
        cause = _windows_error()
        if getattr(cause, "winerror", None) not in _WINDOWS_UNSUPPORTED_FILE_ID_ERRORS:
            guard = _WindowsIdentityGuard(path, handle, (), None, 0, False, 0)
            _close_windows_guard(guard)
            raise error_type("unable to identify extended managed removal path: %s" % path) from cause
    guard = _WindowsIdentityGuard(
        path,
        handle,
        identities,
        (int(status.st_dev), int(status.st_ino)),
        int(information.number_of_links),
        bool(information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY),
        size,
    )
    if not _windows_status_matches_guard(status, guard):
        _close_windows_guard(guard)
        raise error_type("managed removal path changed while pinning: %s" % path)
    guard.identities = (guard.status_identity,)
    return guard


def _open_identity_guard(path, status, error_type):
    if _WINDOWS_KERNEL32 is not None:
        return _open_windows_identity_guard(path, status, error_type)
    if os.name != "posix":
        return None
    flags = getattr(os, "O_PATH", os.O_RDONLY)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    if stat.S_ISDIR(status.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        # POSIX may deny or race an identity-preserving handle acquisition.
        raise error_type("unable to pin managed removal path: %s" % path) from error
    try:
        pinned = os.fstat(descriptor)
    except OSError:
        # The descriptor must not leak when the filesystem cannot identify it.
        _close_identity_guard(descriptor)
        raise
    if _snapshot_identity(pinned) != _snapshot_identity(status):
        _close_identity_guard(descriptor)
        raise error_type("managed removal path changed while pinning: %s" % path)
    return descriptor


def _matches_guard(status, original, descriptor):
    if descriptor is None:
        return _identity(status) == _identity(original)
    if isinstance(descriptor, _WindowsIdentityGuard):
        return _windows_status_matches_guard(status, descriptor)
    return _snapshot_identity(status) == _snapshot_identity(os.fstat(descriptor))


def _validate_windows_child_guard(parent_descriptor, target_descriptor, error_type, target):
    if not isinstance(parent_descriptor, _WindowsIdentityGuard):
        return
    if not isinstance(target_descriptor, _WindowsIdentityGuard):
        raise error_type("managed removal target was not pinned by a Windows handle: %s" % target)
    if parent_descriptor.status_identity[0] != target_descriptor.status_identity[0]:
        raise error_type("managed removal target changed volumes while pinning: %s" % target)


def _validate_parent_guard(root, target, original, descriptor, error_type, missing_ok=False):
    parent = target.parent
    _validate_chain(root, parent, error_type)
    current = _lstat(parent)
    if current is None and missing_ok:
        return
    if current is None or not stat.S_ISDIR(current.st_mode):
        raise error_type("managed removal parent disappeared: %s" % parent)
    if not _matches_guard(current, original, descriptor) or is_path_alias(parent):
        raise error_type("managed removal parent changed before deletion: %s" % parent)


def _open_parent_guard(root, target, error_type):
    parent = target.parent
    _validate_chain(root, parent, error_type)
    status = _lstat(parent)
    if status is None or not stat.S_ISDIR(status.st_mode):
        raise error_type("managed removal parent is not a directory: %s" % parent)
    if is_path_alias(parent):
        _alias_error(error_type, parent)
    descriptor = _open_identity_guard(parent, status, error_type)
    try:
        _validate_parent_guard(root, target, status, descriptor, error_type)
    except (OSError, CleanupScopeError, IntegrityError):
        # Guard acquisition failures must release the parent descriptor.
        if descriptor is not None:
            _close_identity_guard(descriptor)
        raise
    return status, descriptor


def _delete_windows_guard(descriptor, expect_directory):
    if descriptor.is_directory != expect_directory:  # pragma: no cover - caller uses the pinned status type
        raise IntegrityError("managed removal object type changed while pinned")
    disposition = _WindowsFileDispositionInformation(True)
    if not _WINDOWS_KERNEL32.SetFileInformationByHandle(
        descriptor.handle,
        _WINDOWS_FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise _windows_error()


def _anchored_unlink(target, parent_descriptor, target_descriptor=None):
    if isinstance(target_descriptor, _WindowsIdentityGuard):
        _delete_windows_guard(target_descriptor, False)
        return
    if parent_descriptor is None:
        target.unlink()
        return
    os.unlink(target.name, dir_fd=parent_descriptor)


def _anchored_rmdir(target, parent_descriptor, target_descriptor=None):
    if isinstance(target_descriptor, _WindowsIdentityGuard):
        _delete_windows_guard(target_descriptor, True)
        return
    if parent_descriptor is None:
        target.rmdir()
        return
    os.rmdir(target.name, dir_fd=parent_descriptor)


def _lstat(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        # Cleanup is idempotent when a selected path has already disappeared.
        return None


def _validate_removal_tree(root, target, error_type=CleanupScopeError, allowed_symlinks=()):
    # type: (Path, Path, type, tuple) -> None
    """Validate a complete removal tree without following path aliases."""

    root = Path(root)
    target = Path(target)
    allowed = set(Path(path) for path in allowed_symlinks)
    if target in allowed and target.is_symlink():
        _validate_chain(root, target.parent, error_type)
        return
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return
    if is_path_alias(target):
        _alias_error(error_type, target)
    if not stat.S_ISDIR(status.st_mode):
        return
    entries = list(target.iterdir())
    _validate_chain(root, target, error_type)
    current = _lstat(target)
    if current is None or _identity(current) != _identity(status):
        raise error_type("managed removal directory changed during validation: %s" % target)
    for child in entries:
        _validate_removal_tree(root, child, error_type, tuple(allowed))


def _secure_path_size(root, target, error_type=CleanupScopeError):
    # type: (Path, Path, type) -> int
    """Measure a managed tree without following aliases."""

    root = Path(root)
    target = Path(target)
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return 0
    if is_path_alias(target):
        _alias_error(error_type, target)
    if not stat.S_ISDIR(status.st_mode):
        return status.st_size
    entries = list(target.iterdir())
    _validate_chain(root, target, error_type)
    current = _lstat(target)
    if current is None or _identity(current) != _identity(status):
        raise error_type("managed removal directory changed during measurement: %s" % target)
    return sum(_secure_path_size(root, child, error_type) for child in entries)


def _remove_validated_tree(root, target, error_type, allowed, recursive=True):
    if target in allowed and target.is_symlink():
        parent_status, parent_descriptor = _open_parent_guard(root, target, error_type)
        target_descriptor = None
        try:
            if _WINDOWS_KERNEL32 is not None:
                status = _lstat(target)
                if status is None:
                    return False
                target_descriptor = _open_identity_guard(target, status, error_type)
                _validate_windows_child_guard(parent_descriptor, target_descriptor, error_type, target)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
            _anchored_unlink(target, parent_descriptor, target_descriptor)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type, missing_ok=True)
            return True
        finally:
            try:
                if target_descriptor is not None:
                    _close_identity_guard(target_descriptor)
            finally:
                if parent_descriptor is not None:
                    _close_identity_guard(parent_descriptor)
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return False
    if is_path_alias(target):
        _alias_error(error_type, target)
    parent_status, parent_descriptor = _open_parent_guard(root, target, error_type)
    descriptor = None
    try:
        descriptor = _open_identity_guard(target, status, error_type)
        _validate_windows_child_guard(parent_descriptor, descriptor, error_type, target)
        if not stat.S_ISDIR(status.st_mode):
            _validate_chain(root, target, error_type)
            current = _lstat(target)
            if current is None:
                return False
            if not _matches_guard(current, status, descriptor) or is_path_alias(target):
                raise error_type("managed removal path changed before deletion: %s" % target)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
            _anchored_unlink(target, parent_descriptor, descriptor)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type, missing_ok=True)
            return True
        _validate_chain(root, target, error_type)
        entries = list(target.iterdir())
        if entries and not recursive:
            raise error_type("managed removal directory is not empty: %s" % target)
        _validate_chain(root, target, error_type)
        current = _lstat(target)
        if current is None or not _matches_guard(current, status, descriptor) or is_path_alias(target):
            raise error_type("managed removal directory changed before deletion: %s" % target)
        for child in entries:
            _remove_validated_tree(root, child, error_type, allowed)
        _validate_chain(root, target, error_type)
        current = _lstat(target)
        if current is None:
            return True
        if not _matches_guard(current, status, descriptor) or is_path_alias(target):
            raise error_type("managed removal directory changed before final deletion: %s" % target)
        _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
        _anchored_rmdir(target, parent_descriptor, descriptor)
        _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type, missing_ok=True)
        return True
    finally:
        try:
            if descriptor is not None:
                _close_identity_guard(descriptor)
        finally:
            if parent_descriptor is not None:
                _close_identity_guard(parent_descriptor)


def _secure_remove_tree(root, target, error_type=CleanupScopeError, allowed_symlinks=()):
    # type: (Path, Path, type, tuple) -> bool
    """Delete a validated managed tree without traversing path aliases."""

    allowed = set(Path(path) for path in allowed_symlinks)
    _validate_removal_tree(root, target, error_type, tuple(allowed))
    return _remove_validated_tree(Path(root), Path(target), error_type, allowed)


def _secure_remove_empty_directory(root, target, error_type):
    root = Path(root)
    target = Path(target)
    _validate_removal_tree(root, target, error_type)
    return _remove_validated_tree(root, target, error_type, set(), recursive=False)


def _removal_move(paths, source, destination, kind):
    # type: (JerryProxyPaths, Path, Path, str) -> dict
    """Create one journal move record from an existing managed source."""

    source = Path(source)
    destination = Path(destination)
    status = source.lstat()
    source_relative = source.relative_to(paths.root)
    destination_relative = destination.relative_to(paths.root)
    return {
        "kind": kind,
        "source": str(PurePosixPath(*source_relative.parts)),
        "destination": str(PurePosixPath(*destination_relative.parts)),
        "device": int(status.st_dev),
        "inode": int(status.st_ino),
        "mode": int(stat.S_IFMT(status.st_mode)),
    }


def _write_removal_journal(transaction, moves, phase="staging"):
    # type: (Path, list, str) -> None
    """Persist the recovery record before or after public-state moves."""

    atomic_write_json(Path(transaction) / _JOURNAL_NAME, {"phase": phase, "moves": moves})


def _relative_path(paths, value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise IntegrityError("invalid removal journal path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise IntegrityError("invalid removal journal path: %s" % value)
    return paths.root.joinpath(*relative.parts), relative.parts


def _load_removal_journal(paths, transaction):
    journal = transaction / _JOURNAL_NAME
    if is_path_alias(journal):
        _alias_error(IntegrityError, journal)
    try:
        value = read_json(journal)
    except ValueError as error:
        # Invalid JSON or a non-object journal cannot define recovery actions.
        raise IntegrityError("invalid removal transaction journal: %s" % journal) from error
    if set(value) != {"phase", "moves"} or value.get("phase") not in ("staging", "committed"):
        raise IntegrityError("invalid removal transaction journal: %s" % journal)
    raw_moves = value.get("moves")
    if not isinstance(raw_moves, list) or not raw_moves:
        raise IntegrityError("invalid removal transaction moves: %s" % journal)
    moves = []
    sources = set()
    destinations = set()
    for raw_move in raw_moves:
        if not isinstance(raw_move, dict) or set(raw_move) != {
            "kind",
            "source",
            "destination",
            "device",
            "inode",
            "mode",
        }:
            raise IntegrityError("invalid removal transaction move: %s" % journal)
        kind = raw_move.get("kind")
        if kind not in _MOVE_KINDS:
            raise IntegrityError("invalid removal transaction move kind: %s" % journal)
        source, source_parts = _relative_path(paths, raw_move.get("source"))
        destination, destination_parts = _relative_path(paths, raw_move.get("destination"))
        source_area, destination_name = _MOVE_KINDS[kind]
        valid_source = source_parts and source_parts[0] == source_area
        if kind == "download":
            valid_source = valid_source and len(source_parts) in (2, 3)
        elif kind == "installed":
            valid_source = valid_source and len(source_parts) == 3
        elif kind == "active-link":
            valid_source = valid_source and len(source_parts) == 2
        else:
            valid_source = valid_source and len(source_parts) == 2 and source_parts[-1].endswith(".json")
        if not valid_source:
            raise IntegrityError("invalid removal transaction source: %s" % source)
        if len(destination_parts) != 3 or destination_parts[:2] != (
            paths.runtimes.name,
            transaction.name,
        ):
            raise IntegrityError("invalid removal transaction destination: %s" % destination)
        if destination_name.endswith("-"):
            suffix = destination_parts[-1][len(destination_name) :]
            if not destination_parts[-1].startswith(destination_name) or not suffix.isdigit():
                raise IntegrityError("invalid removal transaction destination: %s" % destination)
        elif destination_parts[-1] != destination_name:
            raise IntegrityError("invalid removal transaction destination: %s" % destination)
        identity = (raw_move.get("device"), raw_move.get("inode"), raw_move.get("mode"))
        if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in identity):
            raise IntegrityError("invalid removal transaction identity: %s" % journal)
        if source in sources or destination in destinations:
            raise IntegrityError("duplicate removal transaction path: %s" % journal)
        sources.add(source)
        destinations.add(destination)
        moves.append(
            {
                "kind": kind,
                "source": source,
                "destination": destination,
                "identity": identity,
            }
        )
    return value["phase"], moves


def _validate_staged_move(paths, transaction, move, error_type):
    # type: (JerryProxyPaths, Path, dict, type) -> None
    """Verify that one rename moved the exact object recorded in the journal."""

    destination = Path(transaction) / Path(move["destination"]).name
    _validate_chain(paths.runtimes, destination.parent, error_type)
    status = destination.lstat()
    expected = (move["device"], move["inode"], move["mode"])
    if _identity(status) != expected:
        raise error_type("managed removal source changed during staging: %s" % move["source"])
    allowed = (destination,) if move["kind"] == "active-link" and destination.is_symlink() else ()
    _validate_removal_tree(paths.runtimes, destination, error_type, allowed)


def _restore_moves(paths, transaction, moves, replace):
    for move in reversed(moves):
        source = move["source"]
        destination = move["destination"]
        source_exists = os.path.lexists(str(source))
        destination_exists = os.path.lexists(str(destination))
        if source_exists and destination_exists:
            raise IntegrityError("ambiguous removal recovery paths: %s and %s" % (source, destination))
        if not destination_exists:
            continue
        _validate_chain(paths.runtimes, destination.parent, IntegrityError)
        status = destination.lstat()
        if _identity(status) != move["identity"]:
            raise IntegrityError("removal transaction payload identity changed: %s" % destination)
        current = source.parent
        while current != paths.root:
            if is_path_alias(current):
                _alias_error(IntegrityError, current)
            current = current.parent
        if not source.parent.exists():
            source_area = getattr(paths, source.relative_to(paths.root).parts[0])
            _validate_chain(source_area, source.parent, IntegrityError)
            ensure_private_directory(source.parent)
            _validate_chain(source_area, source.parent, IntegrityError)
        replace(str(destination), str(source))
        restored = source.lstat()
        if _identity(restored) != _identity(status):
            raise IntegrityError("removal rollback restored a different filesystem object: %s" % source)


def _rollback_removal_transaction(paths, transaction, raw_moves, replace=os.replace):
    # type: (JerryProxyPaths, Path, list, Callable) -> None
    """Restore already staged moves and retain evidence if restoration fails."""

    phase, moves = _load_removal_journal(paths, Path(transaction))
    if phase != "staging":  # pragma: no cover - manager calls rollback only before commit
        raise IntegrityError("cannot roll back a committed removal transaction: %s" % transaction)
    moved_destinations = set(
        paths.root.joinpath(*PurePosixPath(move["destination"]).parts) for move in raw_moves
    )
    selected = [move for move in moves if move["destination"] in moved_destinations]
    _restore_moves(paths, Path(transaction), selected, replace)


def _dispose_transaction(paths, transaction, moves):
    _validate_chain(paths.runtimes, transaction, IntegrityError)
    expected = set([transaction / _JOURNAL_NAME])
    expected.update(move["destination"] for move in moves)
    entries = set(transaction.iterdir())
    journal_temporaries = set(
        path for path in entries if path.name.startswith(".%s." % _JOURNAL_NAME)
    )
    expected.update(journal_temporaries)
    unexpected = entries.difference(expected)
    if unexpected:
        raise IntegrityError(
            "unexpected removal transaction content: %s" % sorted(str(path) for path in unexpected)[0]
        )
    for move in moves:
        destination = move["destination"]
        allowed = ()
        if move["kind"] == "active-link" and destination.is_symlink():
            allowed = (destination,)
        _secure_remove_tree(paths.runtimes, destination, IntegrityError, allowed)
    for temporary in journal_temporaries:
        _secure_remove_tree(paths.runtimes, temporary, IntegrityError)
    journal = transaction / _JOURNAL_NAME
    if os.path.lexists(str(journal)):
        if is_path_alias(journal):
            _alias_error(IntegrityError, journal)
        _secure_remove_tree(paths.runtimes, journal, IntegrityError)
    if not _secure_remove_empty_directory(paths.runtimes, transaction, IntegrityError):
        raise IntegrityError("removal transaction disappeared before disposal: %s" % transaction)


def _dispose_removal_transaction(paths, transaction):
    # type: (JerryProxyPaths, Path) -> None
    """Finish physical deletion for a committed transaction."""

    phase, moves = _load_removal_journal(paths, Path(transaction))
    if phase != "committed":  # pragma: no cover - manager calls disposal only after commit
        raise IntegrityError("cannot dispose a staging removal transaction: %s" % transaction)
    _dispose_transaction(paths, Path(transaction), moves)


def _discard_rolled_back_transaction(paths, transaction):
    # type: (JerryProxyPaths, Path) -> None
    """Delete an empty staging transaction after successful rollback."""

    phase, moves = _load_removal_journal(paths, Path(transaction))
    if phase != "staging":  # pragma: no cover - rollback preserves the staging phase
        raise IntegrityError("cannot discard a committed removal transaction: %s" % transaction)
    if any(  # pragma: no cover - successful rollback removes every selected destination
        os.path.lexists(str(move["destination"])) for move in moves
    ):
        raise IntegrityError("removal transaction still contains staged state: %s" % transaction)
    _dispose_transaction(paths, Path(transaction), moves)


def _recover_removal_transactions(paths):
    # type: (JerryProxyPaths) -> None
    """Recover every journaled removal while the home-wide lock is held."""

    for transaction in sorted(paths.runtimes.iterdir()):
        if not _TRANSACTION_PATTERN.match(transaction.name) or not transaction.is_dir():
            continue
        if is_path_alias(transaction):
            _alias_error(IntegrityError, transaction)
        journal = transaction / _JOURNAL_NAME
        if not os.path.lexists(str(journal)):
            continue
        if not journal.is_file():
            raise IntegrityError("removal transaction journal is not a regular file: %s" % journal)
        phase, moves = _load_removal_journal(paths, transaction)
        if phase == "staging":
            _restore_moves(paths, transaction, moves, os.replace)
            _discard_rolled_back_transaction(paths, transaction)
        else:
            if any(os.path.lexists(str(move["source"])) for move in moves):
                raise IntegrityError("committed removal source unexpectedly exists: %s" % transaction)
            try:
                _dispose_transaction(paths, transaction, moves)
            except OSError as error:
                # Permission and filesystem failures leave the committed journal retryable.
                raise RemovalCleanupError(
                    "backend removal committed but quarantine cleanup failed at %s" % transaction
                ) from error
