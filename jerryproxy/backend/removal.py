"""Crash-recoverable and alias-safe backend removal primitives."""

import ctypes
import hashlib
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..errors import (
    ArchiveError,
    CleanupScopeError,
    IntegrityError,
    RemovalCleanupError,
    UnsupportedBackendError,
)
from ..home import is_path_alias
from ..utils.fs import MAXIMUM_JSON_BYTES
from .anchored import AnchoredDirectory, _isolate_posix_entry, _rename_posix_noreplace
from .durable import durable_write_json, flush_directory
from .identity import capture_identity, identity_matches, validate_identity
from .platform import detect_platform
from .registry import get_backend, iter_backends

_TRANSACTION_PATTERN = re.compile(r"^\.remove-[0-9a-f]{32}$")
_JOURNAL_NAME = "journal.json"
_REMOVAL_TEMPORARY_PREFIX = ".journal.json.tmp-"
_REMOVAL_TEMPORARY_PATTERN = re.compile(r"^\.journal\.json\.tmp-[0-9a-f]{32}$")
_CLEANUP_TOMBSTONE_PATTERN = re.compile(r"^\.jerryproxy-remove-(?:[0-9a-f]{64}-)?[0-9a-f]{32}$")
_MAXIMUM_REMOVAL_MOVES = 512
_MAXIMUM_REMOVAL_PATH_BYTES = 512
_CANONICAL_INDEX_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MOVE_ORDER = {
    "download": 0,
    "installed": 1,
    "active-link": 2,
    "active-manifest": 3,
}
_MOVE_KINDS = {
    "download": ("downloads", "download-"),
    "installed": ("backends", "installed-"),
    "active-link": ("bin", "active-link"),
    "active-manifest": ("active", "active-manifest"),
}


def _cleanup_tombstone_prefix(name):
    digest = hashlib.sha256(os.fsencode(name)).hexdigest()
    return ".jerryproxy-remove-%s-" % digest


def _is_cleanup_tombstone_name(name):
    return _CLEANUP_TOMBSTONE_PATTERN.fullmatch(name) is not None


def _is_cleanup_tombstone_for(name, target_name):
    prefix = _cleanup_tombstone_prefix(target_name)
    token = name[len(prefix) :] if name.startswith(prefix) else ""
    return len(token) == 32 and all(character in "0123456789abcdef" for character in token)

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
_DARWIN_O_SYMLINK = 0x00200000


def _symlink_open_flag():
    flag = getattr(os, "O_SYMLINK", None)
    if flag is not None:
        return flag
    if sys.platform == "darwin":
        # O_SYMLINK is a stable Darwin ABI flag that older CPython os modules omit.
        return _DARWIN_O_SYMLINK
    return None


@dataclass(frozen=True)
class RemovalRecoveryRecord:
    """One strictly parsed removal record and its normalized path sets."""

    kind: str
    operation: str
    transaction: Path
    phase: str
    moves: tuple
    read_paths: tuple
    write_paths: tuple
    transaction_identity: dict
    journal_identity: object
    journal_value: object
    temporary_evidence: tuple


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
        self.native_identities = tuple(identities)
        self.status_identity = status_identity
        self.number_of_links = number_of_links
        self.is_directory = is_directory
        self.size = size


_WINDOWS_KERNEL32 = None
if os.name == "nt":  # pragma: no cover - platform-only Win32 binding declarations
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
    raise error_type("refusing removal through managed symlink or Windows path alias (managed path alias): %s" % path)


def _validate_chain(root, target, error_type):
    root = Path(root)
    current = Path(target)
    while True:
        try:
            alias = is_path_alias(current)
        except OSError as error:
            # Every lexical ancestor must remain inspectable before removal.
            raise error_type("unable to inspect managed removal path: %s" % current) from error
        if alias:
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
    if status_identity[1] == 0 or status_identity != guard.status_identity or status_identity not in guard.identities:
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
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
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
        extended_volume_serial = int(extended_information.volume_serial_number)
        extended_file_index = int.from_bytes(bytes(extended_information.file_id.identifier), "little")
        if not extended_volume_serial or not extended_file_index:
            guard = _WindowsIdentityGuard(path, handle, (), None, 0, False, 0)
            _close_windows_guard(guard)
            raise error_type("managed removal path has no complete modern identity: %s" % path)
        extended_identity = (extended_volume_serial, extended_file_index)
        if extended_identity not in identities:
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
    symlink_flag = _symlink_open_flag()
    if stat.S_ISLNK(status.st_mode) and symlink_flag is not None:
        # Darwin's symlink-open contract uses O_SYMLINK alone; os.open returns a non-inheritable fd.
        flags = symlink_flag
    else:
        flags = getattr(os, "O_PATH", os.O_RDONLY)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
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


def _guard_matches_expected(original, descriptor, expected):
    expected = validate_identity(expected)
    expected_modes = {
        "directory": stat.S_IFDIR,
        "regular": stat.S_IFREG,
        "symlink": stat.S_IFLNK,
    }
    if stat.S_IFMT(original.st_mode) != expected_modes[expected["file_type"]]:
        return False
    if isinstance(descriptor, _WindowsIdentityGuard):
        if expected["kind"] not in ("windows-file-id", "windows-legacy-id"):
            return False
        pair = (int(expected["volume_serial"], 16), int(expected["file_id"], 16))
        return pair in descriptor.native_identities
    if descriptor is None or expected["kind"] != "posix":
        return False
    pinned = os.fstat(descriptor)
    return int(pinned.st_dev) == expected["device"] and int(pinned.st_ino) == expected["inode"]


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


def _delete_isolated_posix_entry(
    parent_descriptor,
    name,
    target_descriptor,
    error_type,
    directory,
    private_names=False,
):
    if private_names:
        current = _posix_child_status(parent_descriptor, name, error_type)
        if current is None or _snapshot_identity(current) != _snapshot_identity(os.fstat(target_descriptor)):
            raise error_type("private managed removal target changed before deletion: %s" % name)
        if directory:
            os.rmdir(name, dir_fd=parent_descriptor)
        else:
            os.unlink(name, dir_fd=parent_descriptor)
        return
    try:
        quarantine_name, unused_status = _isolate_posix_entry(
            parent_descriptor,
            name,
            _identity(os.fstat(target_descriptor)),
            _cleanup_tombstone_prefix(name),
            _rename_posix_noreplace,
        )
    except (ArchiveError, OSError) as error:
        raise error_type("managed removal target changed at the deletion boundary: %s" % name) from error
    try:
        if directory:
            os.rmdir(quarantine_name, dir_fd=parent_descriptor)
        else:
            os.unlink(quarantine_name, dir_fd=parent_descriptor)
    except OSError as error:
        try:
            _rename_posix_noreplace(
                parent_descriptor,
                quarantine_name,
                parent_descriptor,
                name,
            )
        except (ArchiveError, OSError) as restore_error:
            raise error_type(
                "unable to delete isolated managed entry; evidence retained in quarantine: %s" % name
            ) from restore_error
        raise error_type("unable to delete isolated managed entry: %s" % name) from error


def _anchored_unlink(
    target,
    parent_descriptor,
    target_descriptor=None,
    error_type=IntegrityError,
    private_names=False,
):
    if isinstance(target_descriptor, _WindowsIdentityGuard):
        _delete_windows_guard(target_descriptor, False)
        return
    if parent_descriptor is None:
        target.unlink()
        return
    _delete_isolated_posix_entry(
        parent_descriptor,
        target.name,
        target_descriptor,
        error_type,
        False,
        private_names=private_names,
    )


def _anchored_rmdir(
    target,
    parent_descriptor,
    target_descriptor=None,
    error_type=IntegrityError,
    private_names=False,
):
    if isinstance(target_descriptor, _WindowsIdentityGuard):
        _delete_windows_guard(target_descriptor, True)
        return
    if parent_descriptor is None:
        target.rmdir()
        return
    _delete_isolated_posix_entry(
        parent_descriptor,
        target.name,
        target_descriptor,
        error_type,
        True,
        private_names=private_names,
    )


def _posix_child_status(parent_descriptor, name, error_type):
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        # Descriptor-relative observation is the containment boundary for recursion.
        raise error_type("unable to inspect pinned managed removal child: %s" % name) from error


def _open_posix_child(parent_descriptor, name, status, error_type):
    flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if stat.S_ISDIR(status.st_mode):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
    except OSError as error:
        # Opening relative to the pinned parent must never fall back to a pathname.
        if descriptor is not None:
            os.close(descriptor)
        raise error_type("unable to pin managed removal child: %s" % name) from error
    if _snapshot_identity(opened) != _snapshot_identity(status):
        os.close(descriptor)
        raise error_type("managed removal child changed while pinning: %s" % name)
    return descriptor


def _remove_posix_entry(
    parent_descriptor,
    name,
    error_type,
    recursive=True,
    expected_identity=None,
    expected_snapshot=None,
    private_names=False,
):
    status = _posix_child_status(parent_descriptor, name, error_type)
    if status is None:
        return False
    if stat.S_ISLNK(status.st_mode):
        raise error_type("refusing removal through managed symlink or Windows path alias: %s" % name)
    descriptor = _open_posix_child(parent_descriptor, name, status, error_type)
    try:
        if expected_snapshot is not None and _snapshot_identity(os.fstat(descriptor)) != expected_snapshot:
            raise error_type("managed removal directory changed before traversal: %s" % name)
        if expected_identity is not None and not _guard_matches_expected(status, descriptor, expected_identity):
            raise error_type("managed removal target identity does not match recovery authority: %s" % name)
        if stat.S_ISDIR(status.st_mode):
            try:
                entries = sorted(os.listdir(descriptor))
            except OSError as error:
                # Directory enumeration stays relative to the identity-pinned object.
                raise error_type("unable to enumerate pinned managed removal directory: %s" % name) from error
            if entries and not recursive:
                raise error_type("managed removal directory is not empty: %s" % name)
            for child_name in entries:
                _remove_posix_entry(
                    descriptor,
                    child_name,
                    error_type,
                    private_names=private_names,
                )
            current = _posix_child_status(parent_descriptor, name, error_type)
            if current is None:
                return True
            if _snapshot_identity(current) != _snapshot_identity(os.fstat(descriptor)):
                raise error_type("managed removal directory changed before final deletion: %s" % name)
            _delete_isolated_posix_entry(
                parent_descriptor,
                name,
                descriptor,
                error_type,
                True,
                private_names=private_names,
            )
            return True
        current = _posix_child_status(parent_descriptor, name, error_type)
        if current is None:
            return False
        if _snapshot_identity(current) != _snapshot_identity(os.fstat(descriptor)):
            raise error_type("managed removal path changed before deletion: %s" % name)
        _delete_isolated_posix_entry(
            parent_descriptor,
            name,
            descriptor,
            error_type,
            False,
            private_names=private_names,
        )
        return True
    finally:
        os.close(descriptor)


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


def _remove_validated_tree(
    root,
    target,
    error_type,
    allowed,
    recursive=True,
    expected_identity=None,
    parent_status=None,
    parent_descriptor=None,
    private_names=False,
):
    owns_parent_descriptor = parent_descriptor is None
    if target in allowed and target.is_symlink():
        if owns_parent_descriptor:
            parent_status, parent_descriptor = _open_parent_guard(root, target, error_type)
        else:
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
        target_descriptor = None
        try:
            status = _lstat(target)
            if status is None:
                return False
            target_descriptor = _open_identity_guard(target, status, error_type)
            _validate_windows_child_guard(parent_descriptor, target_descriptor, error_type, target)
            if expected_identity is not None and not _guard_matches_expected(
                status, target_descriptor, expected_identity
            ):
                raise error_type("managed removal target identity does not match recovery authority: %s" % target)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
            _anchored_unlink(
                target,
                parent_descriptor,
                target_descriptor,
                error_type,
                private_names=private_names,
            )
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type, missing_ok=True)
            return True
        finally:
            try:
                if target_descriptor is not None:
                    _close_identity_guard(target_descriptor)
            finally:
                if owns_parent_descriptor and parent_descriptor is not None:
                    _close_identity_guard(parent_descriptor)
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return False
    if is_path_alias(target):
        _alias_error(error_type, target)
    if owns_parent_descriptor:
        parent_status, parent_descriptor = _open_parent_guard(root, target, error_type)
    else:
        _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
    descriptor = None
    try:
        descriptor = _open_identity_guard(target, status, error_type)
        _validate_windows_child_guard(parent_descriptor, descriptor, error_type, target)
        if expected_identity is not None and not _guard_matches_expected(status, descriptor, expected_identity):
            raise error_type("managed removal target identity does not match recovery authority: %s" % target)
        if not stat.S_ISDIR(status.st_mode):
            _validate_chain(root, target, error_type)
            current = _lstat(target)
            if current is None:
                return False
            if not _matches_guard(current, status, descriptor) or is_path_alias(target):
                raise error_type("managed removal path changed before deletion: %s" % target)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
            _anchored_unlink(
                target,
                parent_descriptor,
                descriptor,
                error_type,
                private_names=private_names,
            )
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type, missing_ok=True)
            return True
        if os.name == "posix" and isinstance(parent_descriptor, int):
            _validate_chain(root, target, error_type)
            current = _lstat(target)
            if current is None or not _matches_guard(current, status, descriptor) or is_path_alias(target):
                raise error_type("managed removal directory changed before deletion: %s" % target)
            _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
            removed = _remove_posix_entry(
                parent_descriptor,
                target.name,
                error_type,
                recursive=recursive,
                expected_identity=expected_identity,
                expected_snapshot=_snapshot_identity(os.fstat(descriptor)),
                private_names=private_names,
            )
            _validate_parent_guard(
                root,
                target,
                parent_status,
                parent_descriptor,
                error_type,
                missing_ok=True,
            )
            return removed
        _validate_chain(root, target, error_type)
        entries = list(target.iterdir())
        if entries and not recursive:
            raise error_type("managed removal directory is not empty: %s" % target)
        _validate_chain(root, target, error_type)
        current = _lstat(target)
        if current is None or not _matches_guard(current, status, descriptor) or is_path_alias(target):
            raise error_type("managed removal directory changed before deletion: %s" % target)
        for child in entries:
            _remove_validated_tree(
                root,
                child,
                error_type,
                allowed,
                parent_status=status,
                parent_descriptor=descriptor,
                private_names=private_names,
            )
        _validate_chain(root, target, error_type)
        current = _lstat(target)
        if current is None:
            return True
        if not _matches_guard(current, status, descriptor) or is_path_alias(target):
            raise error_type("managed removal directory changed before final deletion: %s" % target)
        _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type)
        _anchored_rmdir(
            target,
            parent_descriptor,
            descriptor,
            error_type,
            private_names=private_names,
        )
        _validate_parent_guard(root, target, parent_status, parent_descriptor, error_type, missing_ok=True)
        return True
    finally:
        try:
            if descriptor is not None:
                _close_identity_guard(descriptor)
        finally:
            if owns_parent_descriptor and parent_descriptor is not None:
                _close_identity_guard(parent_descriptor)


def _secure_remove_tree(
    root,
    target,
    error_type=CleanupScopeError,
    allowed_symlinks=(),
    expected_identity=None,
    private_names=False,
):
    # type: (Path, Path, type, tuple, Optional[dict]) -> bool
    """Delete a validated managed tree without traversing path aliases."""

    allowed = set(Path(path) for path in allowed_symlinks)
    _validate_removal_tree(root, target, error_type, tuple(allowed))
    return _remove_validated_tree(
        Path(root),
        Path(target),
        error_type,
        allowed,
        expected_identity=expected_identity,
        private_names=private_names,
    )


def _secure_remove_empty_directory(
    root,
    target,
    error_type,
    expected_identity=None,
    private_names=False,
):
    root = Path(root)
    target = Path(target)
    _validate_removal_tree(root, target, error_type)
    return _remove_validated_tree(
        root,
        target,
        error_type,
        set(),
        recursive=False,
        expected_identity=expected_identity,
        private_names=private_names,
    )


def _removal_move(paths, source, destination, kind):
    # type: (JerryProxyPaths, Path, Path, str) -> dict
    """Create one journal move record from an existing managed source."""

    source = Path(source)
    destination = Path(destination)
    source_relative = source.relative_to(paths.root)
    destination_relative = destination.relative_to(paths.root)
    return {
        "kind": kind,
        "source": str(PurePosixPath(*source_relative.parts)),
        "destination": str(PurePosixPath(*destination_relative.parts)),
        "identity": capture_identity(source),
    }


class _RemovalAuthorityError(IntegrityError):
    """A removal journal changed after its exact authority was captured."""


def _write_removal_journal(
    transaction,
    moves,
    phase="staging",
    write_id=None,
    expected_transaction_identity=None,
    expected_journal_identity=None,
):
    # type: (Path, list, str, Optional[Callable], Optional[dict], Optional[dict]) -> tuple
    """Persist the recovery record before or after public-state moves."""

    transaction = Path(transaction)
    selected_write_id = (write_id or (lambda: secrets.token_hex(16)))()
    if re.fullmatch(r"[0-9a-f]{32}", selected_write_id) is None:
        raise ValueError("removal journal write ID must be 32 lowercase hexadecimal characters")
    temporary = transaction / (_REMOVAL_TEMPORARY_PREFIX + selected_write_id)
    journal = transaction / _JOURNAL_NAME
    value = {"phase": phase, "moves": moves}
    if phase == "staging":
        if expected_transaction_identity is not None or expected_journal_identity is not None:
            raise ValueError("initial removal journal publication cannot replace authority")
        durable_write_json(journal, value, temporary)
        return value, _capture_removal_file_identity(journal, "transaction journal")
    if phase != "committed" or expected_transaction_identity is None or expected_journal_identity is None:
        raise ValueError("committed removal journal publication requires exact authority")
    try:
        with AnchoredDirectory(
            transaction,
            expected_identity=expected_transaction_identity,
        ) as anchored:
            unused_payload, identity = anchored.write_json(
                (_JOURNAL_NAME,),
                value,
                (temporary.name,),
                replace_existing=True,
                expected_destination_identity=expected_journal_identity,
            )
    except (ArchiveError, IntegrityError) as error:
        raise _RemovalAuthorityError(
            "removal journal authority changed before committed publication: %s" % journal
        ) from error
    return value, identity


def _relative_path(paths, value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise IntegrityError("invalid removal journal path")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        # A journal path must have one canonical byte representation on every platform.
        raise IntegrityError("invalid removal journal path") from error
    if encoded_length > _MAXIMUM_REMOVAL_PATH_BYTES:
        raise IntegrityError("removal journal path exceeds 512 UTF-8 bytes")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise IntegrityError("invalid removal journal path: %s" % value)
    return paths.root.joinpath(*relative.parts), relative.parts


def _removal_backend(value, journal):
    try:
        spec = get_backend(value)
    except UnsupportedBackendError as error:
        # Removal paths may refer only to identities compiled into the registry.
        raise IntegrityError("invalid removal backend in %s" % journal) from error
    if value != spec.name:
        raise IntegrityError("noncanonical removal backend in %s" % journal)
    return spec


def _removal_version(spec, value, journal):
    try:
        normalized = spec.normalize_version(value)
    except ValueError as error:
        # BackendSpec owns the canonical version grammar used by managed paths.
        raise IntegrityError("invalid removal version in %s" % journal) from error
    if value != normalized:
        raise IntegrityError("noncanonical removal version in %s" % journal)
    return normalized


def _active_link_backend(filename, platform_info, journal):
    selected_platform = platform_info or detect_platform()
    matches = [spec for spec in iter_backends() if spec.executable_filename(selected_platform) == filename]
    if len(matches) != 1:
        raise IntegrityError("invalid active-link command in %s" % journal)
    return matches[0].name


def _validate_move_source(kind, source, source_parts, platform_info, journal):
    source_area = _MOVE_KINDS[kind][0]
    if not source_parts or source_parts[0] != source_area:
        raise IntegrityError("invalid removal transaction source: %s" % source)
    if kind == "download":
        if len(source_parts) not in (2, 3):
            raise IntegrityError("invalid removal transaction source: %s" % source)
        spec = _removal_backend(source_parts[1], journal)
        if len(source_parts) == 3:
            _removal_version(spec, source_parts[2], journal)
        return spec.name
    if kind == "installed":
        if len(source_parts) != 3:
            raise IntegrityError("invalid removal transaction source: %s" % source)
        spec = _removal_backend(source_parts[1], journal)
        _removal_version(spec, source_parts[2], journal)
        return spec.name
    if kind == "active-link":
        if len(source_parts) != 2:
            raise IntegrityError("invalid removal transaction source: %s" % source)
        return _active_link_backend(source_parts[1], platform_info, journal)
    if len(source_parts) != 2 or not source_parts[1].endswith(".json"):
        raise IntegrityError("invalid removal transaction source: %s" % source)
    spec = _removal_backend(source_parts[1][:-5], journal)
    if source_parts[1] != "%s.json" % spec.name:
        raise IntegrityError("invalid removal transaction source: %s" % source)
    return spec.name


def _validate_move_destination(paths, transaction, kind, destination, destination_parts):
    if len(destination_parts) != 3 or destination_parts[:2] != (
        paths.runtimes.name,
        transaction.name,
    ):
        raise IntegrityError("invalid removal transaction destination: %s" % destination)
    expected = _MOVE_KINDS[kind][1]
    leaf = destination_parts[-1]
    if not expected.endswith("-"):
        if leaf != expected:
            raise IntegrityError("invalid removal transaction destination: %s" % destination)
        return None
    if not leaf.startswith(expected):
        raise IntegrityError("invalid removal transaction destination: %s" % destination)
    suffix = leaf[len(expected) :]
    if _CANONICAL_INDEX_PATTERN.fullmatch(suffix) is None:
        if suffix.isdigit():
            raise IntegrityError("noncanonical removal transaction index: %s" % destination)
        raise IntegrityError("invalid removal transaction destination: %s" % destination)
    index = int(suffix)
    if index > 511:
        raise IntegrityError("invalid removal transaction index: %s" % destination)
    return index


def _validate_move_identity(raw_move, kind, journal):
    try:
        identity = validate_identity(raw_move.get("identity"))
    except IntegrityError as error:
        # The shared stable-identity validator owns platform width and shape rules.
        raise IntegrityError("invalid removal transaction identity: %s" % journal) from error
    allowed_types = {
        "download": ("directory",),
        "installed": ("directory",),
        "active-link": ("symlink", "regular"),
        "active-manifest": ("regular",),
    }
    if identity["file_type"] not in allowed_types[kind]:
        expected = " or ".join(allowed_types[kind])
        raise IntegrityError("stable identity expected %s in %s" % (expected, journal))
    return identity


def _validate_move_sequence(moves, journal):
    previous_order = -1
    indices = {"download": [], "installed": []}
    active_backends = {}
    active_counts = {"active-link": 0, "active-manifest": 0}
    for move in moves:
        order = _MOVE_ORDER[move["kind"]]
        if order < previous_order:
            raise IntegrityError("invalid removal transaction move order: %s" % journal)
        previous_order = order
        if move["kind"] in indices:
            indices[move["kind"]].append(move["index"])
        else:
            active_counts[move["kind"]] += 1
            if active_counts[move["kind"]] > 1:
                raise IntegrityError("duplicate %s removal move: %s" % (move["kind"], journal))
            active_backends[move["kind"]] = move["backend"]
    for kind, actual in indices.items():
        if actual != list(range(len(actual))):
            raise IntegrityError("noncontiguous removal transaction indices: %s" % journal)
    if (
        "active-link" in active_backends
        and "active-manifest" in active_backends
        and active_backends["active-link"] != active_backends["active-manifest"]
    ):
        raise IntegrityError("active removal backend mismatch: %s" % journal)


def _load_removal_journal(
    paths,
    transaction,
    platform_info=None,
    transaction_identity=None,
    journal_identity=None,
):
    journal = transaction / _JOURNAL_NAME
    if is_path_alias(journal):
        _alias_error(IntegrityError, journal)
    try:
        with AnchoredDirectory(
            transaction,
            expected_identity=transaction_identity,
        ) as anchored:
            value, unused_identity = anchored.read_json(
                (_JOURNAL_NAME,),
                expected_identity=journal_identity,
            )
    except (ArchiveError, OSError, ValueError) as error:
        # Invalid JSON or a non-object journal cannot define recovery actions.
        raise IntegrityError("invalid removal transaction journal: %s" % journal) from error
    if set(value) != {"phase", "moves"} or value.get("phase") not in ("staging", "committed"):
        raise IntegrityError("invalid removal transaction journal: %s" % journal)
    raw_moves = value.get("moves")
    if not isinstance(raw_moves, list) or not raw_moves or len(raw_moves) > _MAXIMUM_REMOVAL_MOVES:
        raise IntegrityError("invalid removal transaction moves: %s" % journal)
    moves = []
    sources = set()
    destinations = set()
    for raw_move in raw_moves:
        if not isinstance(raw_move, dict) or set(raw_move) != {
            "kind",
            "source",
            "destination",
            "identity",
        }:
            raise IntegrityError("invalid removal transaction move: %s" % journal)
        kind = raw_move.get("kind")
        if kind not in _MOVE_KINDS:
            raise IntegrityError("invalid removal transaction move kind: %s" % journal)
        source, source_parts = _relative_path(paths, raw_move.get("source"))
        destination, destination_parts = _relative_path(paths, raw_move.get("destination"))
        backend = _validate_move_source(
            kind,
            source,
            source_parts,
            platform_info,
            journal,
        )
        index = _validate_move_destination(
            paths,
            transaction,
            kind,
            destination,
            destination_parts,
        )
        identity = _validate_move_identity(raw_move, kind, journal)
        sources.add(source)
        destinations.add(destination)
        moves.append(
            {
                "kind": kind,
                "source": source,
                "destination": destination,
                "identity": identity,
                "backend": backend,
                "index": index,
            }
        )
    _validate_move_sequence(moves, journal)
    if len(sources) != len(moves) or len(destinations) != len(moves):
        raise IntegrityError("duplicate removal transaction path: %s" % journal)
    return value["phase"], moves, value


def _validate_staged_move(paths, transaction, move, error_type):
    # type: (JerryProxyPaths, Path, dict, type) -> None
    """Verify that one rename moved the exact object recorded in the journal."""

    destination = Path(transaction) / Path(move["destination"]).name
    _validate_chain(paths.runtimes, destination.parent, error_type)
    destination.lstat()
    if not identity_matches(destination, move["identity"]):
        raise error_type("managed removal source changed during staging: %s" % move["source"])
    allowed = (destination,) if move["kind"] == "active-link" and destination.is_symlink() else ()
    _validate_removal_tree(paths.runtimes, destination, error_type, allowed)


def _validate_recorded_move_path(paths, move, path, missing_ok=False):
    root = (
        paths.runtimes
        if path == move["destination"]
        else getattr(
            paths,
            path.relative_to(paths.root).parts[0],
        )
    )
    allowed_symlink = move["kind"] == "active-link"
    _validate_chain(root, path.parent if allowed_symlink else path, IntegrityError)
    try:
        status = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise IntegrityError("removal recovery path disappeared: %s" % path)
    except OSError as error:
        # Recovery may trust only an observable object carrying the journaled identity.
        raise IntegrityError("unable to inspect removal recovery path: %s" % path) from error
    if not identity_matches(path, move["identity"]):
        raise IntegrityError("removal transaction payload identity changed: %s" % path)
    allowed = (path,) if allowed_symlink and stat.S_ISLNK(status.st_mode) else ()
    _validate_removal_tree(root, path, IntegrityError, allowed)
    return status


def _validate_transaction_contents(paths, transaction, moves):
    return _transaction_temporaries(paths, transaction, moves)


def _transaction_temporaries(paths, transaction, moves):
    _validate_chain(paths.runtimes, transaction, IntegrityError)
    journal = transaction / _JOURNAL_NAME
    if is_path_alias(journal):
        _alias_error(IntegrityError, journal)
    expected = {transaction / _JOURNAL_NAME}
    expected.update(move["destination"] for move in moves)
    try:
        entries = set(transaction.iterdir())
    except OSError as error:
        # A removal transaction must be enumerable in full before recovery mutates it.
        raise IntegrityError("unable to inspect removal transaction: %s" % transaction) from error
    malformed = {
        path
        for path in entries
        if path.name.startswith(_REMOVAL_TEMPORARY_PREFIX) and _REMOVAL_TEMPORARY_PATTERN.fullmatch(path.name) is None
    }
    if malformed:
        raise IntegrityError("invalid removal journal temporary: %s" % sorted(str(path) for path in malformed)[0])
    temporaries = {path for path in entries if _REMOVAL_TEMPORARY_PATTERN.fullmatch(path.name) is not None}
    unexpected = entries.difference(expected | temporaries)
    if unexpected:
        raise IntegrityError("unexpected removal transaction content: %s" % sorted(str(path) for path in unexpected)[0])
    for temporary in temporaries:
        _validate_removal_tree(paths.runtimes, temporary, IntegrityError)
    return temporaries


def _capture_removal_file_identity(path, description):
    try:
        if is_path_alias(path):
            _alias_error(IntegrityError, path)
        status = path.lstat()
    except OSError as error:
        # Alias inspection and lstat may fail for inaccessible removal evidence.
        raise IntegrityError("unable to inspect removal %s: %s" % (description, path)) from error
    if not stat.S_ISREG(status.st_mode) or status.st_size > MAXIMUM_JSON_BYTES:
        raise IntegrityError("invalid removal %s: %s" % (description, path))
    if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
        raise IntegrityError("removal %s has unsafe permissions: %s" % (description, path))
    identity = capture_identity(path)
    if not identity_matches(path, identity):
        raise IntegrityError("removal %s changed during preflight: %s" % (description, path))
    return identity


def _capture_transaction_identity(transaction):
    try:
        if is_path_alias(transaction):
            _alias_error(IntegrityError, transaction)
        status = transaction.lstat()
    except OSError as error:
        # Alias inspection and lstat may fail at the transaction containment boundary.
        raise IntegrityError("unable to inspect removal transaction: %s" % transaction) from error
    if not stat.S_ISDIR(status.st_mode):
        raise IntegrityError("invalid removal transaction entry: %s" % transaction)
    if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o700:
        raise IntegrityError("removal transaction has unsafe permissions: %s" % transaction)
    identity = capture_identity(transaction)
    if not identity_matches(transaction, identity):
        raise IntegrityError("removal transaction identity changed during preflight: %s" % transaction)
    return identity


def _require_removal_identity(path, expected, description):
    validate_identity(expected)
    if not os.path.lexists(str(path)) and description == "transaction":
        raise IntegrityError("removal transaction disappeared before disposal: %s" % path)
    if not identity_matches(path, expected):
        raise IntegrityError("removal %s identity changed before mutation: %s" % (description, path))


def _capture_deletion_identity(path):
    identity = capture_identity(path)
    if _WINDOWS_KERNEL32 is not None and identity["kind"] == "posix":
        # Native Windows tests may model kernel handles on a POSIX host; no real
        # filesystem can produce this mixed identity representation.
        return None
    return identity


def _require_removal_record_identities(
    record,
    include_journal=True,
    include_temporaries=True,
):
    _require_removal_identity(
        record.transaction,
        record.transaction_identity,
        "transaction",
    )
    if include_journal and record.journal_identity is not None:
        _require_removal_identity(
            record.transaction / _JOURNAL_NAME,
            record.journal_identity,
            "journal",
        )
    if include_temporaries:
        for temporary, identity in record.temporary_evidence:
            _require_removal_identity(temporary, identity, "journal temporary")


def _require_removal_authority(record, include_temporaries=True):
    journal = record.transaction / _JOURNAL_NAME
    if record.journal_identity is None or record.journal_value is None:
        raise _RemovalAuthorityError("removal record has no journal authority: %s" % record.transaction)
    try:
        _require_removal_record_identities(
            record,
            include_temporaries=include_temporaries,
        )
        with AnchoredDirectory(
            record.transaction,
            expected_identity=record.transaction_identity,
        ) as anchored:
            value, unused_identity = anchored.read_json(
                (_JOURNAL_NAME,),
                expected_identity=record.journal_identity,
            )
        if value != record.journal_value:
            raise _RemovalAuthorityError("removal journal content changed before mutation: %s" % journal)
        _require_removal_record_identities(
            record,
            include_temporaries=include_temporaries,
        )
    except _RemovalAuthorityError:
        raise
    except (ArchiveError, IntegrityError) as error:
        raise _RemovalAuthorityError(
            "removal journal authority changed before mutation: %s: %s" % (journal, error)
        ) from error
    except (OSError, ValueError) as error:
        # Journal reads may fail if recovery authority changes after preflight.
        raise _RemovalAuthorityError("removal journal authority changed before mutation: %s" % journal) from error


def preflight_removal_record(paths, record):
    # type: (JerryProxyPaths, RemovalRecoveryRecord) -> None
    """Validate every physical removal path without changing transaction state."""

    if not isinstance(record, RemovalRecoveryRecord) or record.kind != "remove":
        raise IntegrityError("invalid preflighted removal record")
    _require_removal_record_identities(record)
    if record.phase == "terminal":
        try:
            entries = tuple(record.transaction.iterdir())
        except OSError as error:
            # A terminal orphan is safe only when its complete directory is observable.
            raise IntegrityError("unable to inspect terminal removal transaction: %s" % record.transaction) from error
        if entries:
            raise IntegrityError("terminal removal transaction is not empty: %s" % record.transaction)
        _require_removal_record_identities(record, include_journal=False)
        return
    if record.phase == "initial-temporary":
        try:
            entries = tuple(record.transaction.iterdir())
        except OSError as error:
            # Initial writer debris is removable only after complete enumeration.
            raise IntegrityError("unable to inspect initial removal transaction: %s" % record.transaction) from error
        expected = tuple(path for path, _identity in record.temporary_evidence)
        if len(entries) != 1 or set(entries) != set(expected):
            raise IntegrityError("removal transaction has no authoritative journal: %s" % record.transaction)
        _require_removal_record_identities(record, include_journal=False)
        return
    _validate_transaction_contents(paths, record.transaction, record.moves)
    _require_removal_record_identities(record)
    for move in record.moves:
        source = move["source"]
        destination = move["destination"]
        source_exists = os.path.lexists(str(source))
        destination_exists = os.path.lexists(str(destination))
        if record.phase == "staging":
            if source_exists == destination_exists:
                raise IntegrityError("ambiguous removal recovery paths: %s and %s" % (source, destination))
            selected = source if source_exists else destination
            _validate_recorded_move_path(paths, move, selected)
            continue
        if source_exists:
            raise IntegrityError("committed removal source unexpectedly exists: %s" % record.transaction)
        if destination_exists:
            _validate_recorded_move_path(paths, move, destination, missing_ok=True)
    _require_removal_record_identities(record)


def _move_no_replace(
    paths,
    source,
    destination,
    expected_identity,
    error_type=IntegrityError,
    description="removal",
):
    source = Path(source)
    destination = Path(destination)
    try:
        source_parts = source.relative_to(paths.root).parts
        destination_parts = destination.relative_to(paths.root).parts
    except ValueError as error:
        raise error_type("%s path escapes the JerryProxy home" % description) from error
    try:
        with AnchoredDirectory(
            paths.root.resolve(),
            require_private_permissions=False,
        ) as anchored:
            return anchored.replace(
                source_parts,
                destination_parts,
                expected_identity=expected_identity,
                replace_existing=False,
            )
    except ArchiveError as error:
        if isinstance(error.__cause__, FileExistsError):
            raise error_type("%s destination already exists: %s" % (description, destination)) from error
        raise error_type("unable to perform anchored %s move: %s" % (description, source)) from error


def _restore_moves(paths, moves, record=None):
    for move in reversed(moves):
        source = move["source"]
        destination = move["destination"]
        source_exists = os.path.lexists(str(source))
        destination_exists = os.path.lexists(str(destination))
        if source_exists and destination_exists:
            raise IntegrityError("ambiguous removal recovery paths: %s and %s" % (source, destination))
        if not destination_exists:
            if not source_exists:
                raise IntegrityError("removal recovery lost both paths: %s and %s" % (source, destination))
            _validate_recorded_move_path(paths, move, source)
            if record is not None:
                _require_removal_authority(record)
            flush_directory(destination.parent)
            flush_directory(source.parent)
            if record is not None:
                _require_removal_authority(record)
            continue
        _validate_recorded_move_path(paths, move, destination)
        if record is not None:
            _require_removal_authority(record)
        current = source.parent
        while current != paths.root:
            if is_path_alias(current):
                _alias_error(IntegrityError, current)
            current = current.parent
        if not source.parent.exists():
            if record is not None:
                _require_removal_authority(record)
            source_area = getattr(paths, source.relative_to(paths.root).parts[0])
            _validate_chain(source_area, source.parent, IntegrityError)
            try:
                relative_parent = source.parent.relative_to(source_area).parts
                with AnchoredDirectory(source_area) as anchored_source:
                    if relative_parent:
                        anchored_source.ensure_directory(relative_parent)
            except (ArchiveError, ValueError) as error:
                raise IntegrityError("unable to recreate removal source parent: %s" % source.parent) from error
            _validate_chain(source_area, source.parent, IntegrityError)
        if record is not None:
            _require_removal_authority(record)
        _move_no_replace(
            paths,
            destination,
            source,
            move["identity"],
            description="removal recovery",
        )
        source.lstat()
        if not identity_matches(source, move["identity"]):
            raise IntegrityError("removal rollback restored a different filesystem object: %s" % source)
        if record is not None:
            _require_removal_authority(record)


def _dispose_transaction(paths, transaction, moves, record=None):
    journal_temporaries = _validate_transaction_contents(paths, transaction, moves)
    if record is not None:
        _require_removal_authority(record)
    absent_destination_parents = set()
    for move in moves:
        destination = move["destination"]
        if os.path.lexists(str(destination)):
            if _validate_recorded_move_path(paths, move, destination, missing_ok=True) is None:
                continue
            expected_identity = _capture_deletion_identity(destination)
            if expected_identity is not None and not identity_matches(destination, expected_identity):
                raise IntegrityError("removal transaction payload changed before disposal: %s" % destination)
        else:
            expected_identity = None
            absent_destination_parents.add(destination.parent)
            continue
        allowed = ()
        if move["kind"] == "active-link" and destination.is_symlink():
            allowed = (destination,)
        if record is not None:
            _require_removal_authority(record)
        removed = _secure_remove_tree(
            paths.runtimes,
            destination,
            IntegrityError,
            allowed,
            expected_identity=expected_identity,
            private_names=True,
        )
        if removed:
            flush_directory(destination.parent)
        if record is not None:
            _require_removal_authority(record)
    for parent in sorted(absent_destination_parents):
        flush_directory(parent)
    if absent_destination_parents and record is not None:
        _require_removal_authority(record)
    for temporary in journal_temporaries:
        expected_identity = None
        if record is not None:
            expected_identity = dict(record.temporary_evidence).get(temporary)
            _require_removal_authority(record, include_temporaries=False)
            _require_removal_identity(temporary, expected_identity, "journal temporary")
        else:
            expected_identity = _capture_deletion_identity(temporary)
        removed = _secure_remove_tree(
            paths.runtimes,
            temporary,
            IntegrityError,
            expected_identity=expected_identity,
            private_names=True,
        )
        if removed:
            flush_directory(temporary.parent)
    journal = transaction / _JOURNAL_NAME
    if os.path.lexists(str(journal)):
        if is_path_alias(journal):
            _alias_error(IntegrityError, journal)
        expected_identity = _capture_deletion_identity(journal)
        if record is not None:
            _require_removal_authority(record, include_temporaries=False)
        removed = _secure_remove_tree(
            paths.runtimes,
            journal,
            IntegrityError,
            expected_identity=expected_identity,
            private_names=True,
        )
        if removed:
            if record is not None:
                _require_removal_record_identities(
                    record,
                    include_journal=False,
                    include_temporaries=False,
                )
            flush_directory(journal.parent)
    if record is not None:
        _require_removal_record_identities(
            record,
            include_journal=False,
            include_temporaries=False,
        )
    expected_transaction_identity = _capture_deletion_identity(transaction)
    if not _secure_remove_empty_directory(
        paths.runtimes,
        transaction,
        IntegrityError,
        expected_identity=expected_transaction_identity,
        private_names=True,
    ):
        raise IntegrityError("removal transaction disappeared before disposal: %s" % transaction)
    flush_directory(transaction.parent)


def _dispose_removal_transaction(paths, transaction, platform_info=None, record=None):
    # type: (JerryProxyPaths, Path) -> None
    """Finish physical deletion for a committed transaction."""

    transaction = Path(transaction)
    if record is None:
        matching = tuple(
            candidate
            for candidate in preflight_removal_transactions(paths, platform_info)
            if candidate.transaction == transaction
        )
        if len(matching) != 1:
            raise IntegrityError("missing committed removal transaction: %s" % transaction)
        record = matching[0]
    preflight_removal_record(paths, record)
    if record.phase != "committed":  # pragma: no cover - manager calls disposal only after commit
        raise IntegrityError("cannot dispose a staging removal transaction: %s" % transaction)
    _dispose_transaction(paths, transaction, record.moves, record=record)


def preflight_removal_transactions(paths, platform_info=None):
    # type: (JerryProxyPaths, Optional[PlatformInfo]) -> tuple
    """Strictly parse every removal record without mutating managed state."""

    records = []
    for transaction in sorted(paths.runtimes.iterdir()):
        if not transaction.name.startswith(".remove-"):
            continue
        if _TRANSACTION_PATTERN.fullmatch(transaction.name) is None or not transaction.is_dir():
            raise IntegrityError("invalid removal transaction entry: %s" % transaction)
        transaction_identity = _capture_transaction_identity(transaction)
        journal = transaction / _JOURNAL_NAME
        if not os.path.lexists(str(journal)):
            try:
                entries = tuple(transaction.iterdir())
            except OSError as error:
                # A journal-free transaction can be adopted only as a proven empty tail state.
                raise IntegrityError("unable to inspect removal transaction: %s" % transaction) from error
            temporary_entries = tuple(entry for entry in entries if entry.name.startswith(_REMOVAL_TEMPORARY_PREFIX))
            invalid_temporaries = tuple(
                entry for entry in temporary_entries if _REMOVAL_TEMPORARY_PATTERN.fullmatch(entry.name) is None
            )
            if invalid_temporaries:
                raise IntegrityError(
                    "invalid removal journal temporary: %s" % sorted(str(path) for path in invalid_temporaries)[0]
                )
            if len(temporary_entries) > 1:
                raise IntegrityError("multiple removal journal temporaries: %s" % transaction)
            if entries and (len(entries) != 1 or not temporary_entries):
                raise IntegrityError("removal transaction has no authoritative journal: %s" % transaction)
            if not identity_matches(transaction, transaction_identity):
                raise IntegrityError("removal transaction identity changed during preflight: %s" % transaction)
            operation = transaction.name[len(".remove-") :]
            transaction_path = str(PurePosixPath(*transaction.relative_to(paths.root).parts))
            if temporary_entries:
                temporary = temporary_entries[0]
                temporary_identity = _capture_removal_file_identity(temporary, "journal temporary")
                if not identity_matches(transaction, transaction_identity):
                    raise IntegrityError("removal transaction identity changed during preflight: %s" % transaction)
                temporary_path = str(PurePosixPath(*temporary.relative_to(paths.root).parts))
                records.append(
                    RemovalRecoveryRecord(
                        kind="remove",
                        operation=operation,
                        transaction=transaction,
                        phase="initial-temporary",
                        moves=(),
                        read_paths=(temporary_path,),
                        write_paths=(transaction_path, temporary_path),
                        transaction_identity=transaction_identity,
                        journal_identity=None,
                        journal_value=None,
                        temporary_evidence=((temporary, temporary_identity),),
                    )
                )
                continue
            records.append(
                RemovalRecoveryRecord(
                    kind="remove",
                    operation=operation,
                    transaction=transaction,
                    phase="terminal",
                    moves=(),
                    read_paths=(),
                    write_paths=(transaction_path,),
                    transaction_identity=transaction_identity,
                    journal_identity=None,
                    journal_value=None,
                    temporary_evidence=(),
                )
            )
            continue
        if not journal.is_file():
            raise IntegrityError("removal transaction journal is not a regular file: %s" % journal)
        journal_identity = _capture_removal_file_identity(journal, "transaction journal")
        phase, moves, journal_value = _load_removal_journal(
            paths,
            transaction,
            platform_info=platform_info,
            transaction_identity=transaction_identity,
            journal_identity=journal_identity,
        )
        if not identity_matches(journal, journal_identity):
            raise IntegrityError("removal journal identity changed during preflight: %s" % journal)
        temporaries = _transaction_temporaries(paths, transaction, moves)
        temporary_evidence = tuple(
            sorted(
                (
                    (temporary, _capture_removal_file_identity(temporary, "journal temporary"))
                    for temporary in temporaries
                ),
                key=lambda item: item[0],
            )
        )
        if not identity_matches(transaction, transaction_identity):
            raise IntegrityError("removal transaction identity changed during preflight: %s" % transaction)
        if not identity_matches(journal, journal_identity):
            if is_path_alias(journal):
                _alias_error(IntegrityError, journal)
            raise IntegrityError("removal journal identity changed during preflight: %s" % journal)
        operation = transaction.name[len(".remove-") :]
        journal_path = str(PurePosixPath(*journal.relative_to(paths.root).parts))
        transaction_path = str(PurePosixPath(*transaction.relative_to(paths.root).parts))
        move_paths = tuple(
            str(PurePosixPath(*path.relative_to(paths.root).parts))
            for move in moves
            for path in (move["source"], move["destination"])
        )
        records.append(
            RemovalRecoveryRecord(
                kind="remove",
                operation=operation,
                transaction=transaction,
                phase=phase,
                moves=tuple(moves),
                read_paths=(journal_path,),
                write_paths=tuple(sorted(set((transaction_path, journal_path) + move_paths))),
                transaction_identity=transaction_identity,
                journal_identity=journal_identity,
                journal_value=journal_value,
                temporary_evidence=temporary_evidence,
            )
        )
    return tuple(records)


def _preflight_expected_removal_record(
    paths,
    transaction,
    journal_value,
    journal_identity,
    platform_info=None,
):
    """Bind normal removal work to the exact journal just published by its writer."""

    transaction = Path(transaction)
    matching = tuple(
        record for record in preflight_removal_transactions(paths, platform_info) if record.transaction == transaction
    )
    if len(matching) != 1:
        raise _RemovalAuthorityError("missing authoritative removal transaction: %s" % transaction)
    record = matching[0]
    if record.journal_identity != journal_identity:
        raise _RemovalAuthorityError("removal journal identity changed after publication: %s" % transaction)
    if record.journal_value != journal_value:
        raise _RemovalAuthorityError("removal journal content changed after publication: %s" % transaction)
    preflight_removal_record(paths, record)
    return record


def recover_removal_record(paths, record, platform_info=None):
    # type: (JerryProxyPaths, RemovalRecoveryRecord, Optional[PlatformInfo]) -> None
    """Recover one record that passed the coordinator's complete preflight."""

    if not isinstance(record, RemovalRecoveryRecord):
        raise IntegrityError("invalid preflighted removal record")
    preflight_removal_record(paths, record)
    if record.phase == "terminal":
        if not _secure_remove_empty_directory(
            paths.runtimes,
            record.transaction,
            IntegrityError,
            expected_identity=record.transaction_identity,
            private_names=True,
        ):
            raise IntegrityError("removal transaction disappeared before disposal: %s" % record.transaction)
        flush_directory(record.transaction.parent)
        return
    if record.phase == "initial-temporary":
        preflight_removal_record(paths, record)
        temporary, temporary_identity = record.temporary_evidence[0]
        removed = _secure_remove_tree(
            paths.runtimes,
            temporary,
            IntegrityError,
            expected_identity=temporary_identity,
            private_names=True,
        )
        if removed:
            flush_directory(temporary.parent)
        if not _secure_remove_empty_directory(
            paths.runtimes,
            record.transaction,
            IntegrityError,
            expected_identity=record.transaction_identity,
            private_names=True,
        ):
            raise IntegrityError("removal transaction disappeared before disposal: %s" % record.transaction)
        flush_directory(record.transaction.parent)
        return
    if record.phase == "staging":
        _restore_moves(paths, record.moves, record=record)
        _dispose_transaction(paths, record.transaction, record.moves, record=record)
        return
    try:
        _dispose_transaction(paths, record.transaction, record.moves, record=record)
    except OSError as error:
        # Permission and filesystem failures leave the committed journal retryable.
        raise RemovalCleanupError(
            "backend removal committed but quarantine cleanup failed at %s" % record.transaction
        ) from error


def _recover_removal_transactions(paths, platform_info=None):
    # type: (JerryProxyPaths, Optional[PlatformInfo]) -> None
    """Recover every preflighted removal while the home-wide lock is held."""

    selected_platform = platform_info or detect_platform()
    for record in preflight_removal_transactions(paths, selected_platform):
        recover_removal_record(paths, record, selected_platform)
