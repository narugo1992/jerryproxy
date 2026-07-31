"""Descriptor-anchored filesystem creation below one private directory."""

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from ..errors import ArchiveError, DurabilityError, IntegrityError
from ..home import is_path_alias
from ..utils.fs import read_json_stream
from .durable import flush_descriptor, flush_directory
from .identity import capture_identity, identity_matches, validate_identity

_WINDOWS_DELETE = 0x00010000
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_SYNCHRONIZE = 0x00100000
_WINDOWS_FILE_TRAVERSE = 0x00000020
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_CREATE_NEW = 1
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_NORMAL = 0x00000080
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_ID_INFO_CLASS = 18
_WINDOWS_FILE_RENAME_INFORMATION_CLASS = 10
_WINDOWS_FILE_RENAME_INFORMATION_EX_CLASS = 65
_WINDOWS_FILE_RENAME_REPLACE_IF_EXISTS = 0x00000001
_WINDOWS_FILE_RENAME_POSIX_SEMANTICS = 0x00000002
_WINDOWS_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_WINDOWS_UNSUPPORTED_FILE_ID_ERRORS = (1, 50, 87)
_WINDOWS_DESTINATION_EXISTS_ERRORS = (80, 183)
_LINUX_RENAMEAT2_SYSCALLS = {
    "aarch64": 276,
    "arm64": 276,
    "armv5l": 382,
    "armv6l": 382,
    "armv7l": 382,
    "i386": 353,
    "i686": 353,
    "loong64": 276,
    "loongarch64": 276,
    "ppc64": 357,
    "ppc64le": 357,
    "riscv64": 276,
    "s390x": 347,
    "x86_64": 316,
}
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_RENAME_EXCL = 0x00000004
_RENAME_SWAP = 0x00000002
_DARWIN_O_SYMLINK = 0x00200000


def _symlink_open_flag():
    flag = getattr(os, "O_SYMLINK", None)
    if flag is not None:
        return flag
    if sys.platform == "darwin":
        # O_SYMLINK is a stable Darwin ABI flag that older CPython os modules omit.
        return _DARWIN_O_SYMLINK
    return None


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


class _WindowsFileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _WindowsFileIdInformation(ctypes.Structure):
    _fields_ = (
        ("volume_serial_number", ctypes.c_uint64),
        ("file_id", _WindowsFileId128),
    )


class _WindowsIoStatusBlock(ctypes.Structure):
    _fields_ = (
        ("status_or_pointer", ctypes.c_void_p),
        ("information", ctypes.c_size_t),
    )


if ctypes.sizeof(_WindowsFileInformation) != 52:  # pragma: no cover - ctypes ABI invariant
    raise RuntimeError("BY_HANDLE_FILE_INFORMATION must use the 52-byte Windows ABI")
if ctypes.sizeof(_WindowsFileIdInformation) != 24:  # pragma: no cover - ctypes ABI invariant
    raise RuntimeError("FILE_ID_INFO must use the 24-byte Windows ABI")


_WINDOWS_KERNEL32 = None
_WINDOWS_NTDLL = None
_WINDOWS_OPEN_OSFHANDLE = None
if os.name == "nt":  # pragma: no cover - platform-only Win32 binding declarations
    import msvcrt

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
    _WINDOWS_NTDLL = ctypes.WinDLL("ntdll")
    _WINDOWS_NTDLL.NtSetInformationFile.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
    )
    _WINDOWS_NTDLL.NtSetInformationFile.restype = ctypes.c_int32
    _WINDOWS_NTDLL.RtlNtStatusToDosError.argtypes = (ctypes.c_int32,)
    _WINDOWS_NTDLL.RtlNtStatusToDosError.restype = ctypes.c_uint32
    _WINDOWS_KERNEL32.CloseHandle.argtypes = (ctypes.c_void_p,)
    _WINDOWS_KERNEL32.CloseHandle.restype = ctypes.c_int32
    _WINDOWS_OPEN_OSFHANDLE = msvcrt.open_osfhandle


def _identity(status):
    return status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode)


def _windows_extended_path(path):
    value = os.path.abspath(str(path))
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_error():
    return ctypes.WinError(ctypes.get_last_error())


def _windows_status_error(status):
    error_number = int(_WINDOWS_NTDLL.RtlNtStatusToDosError(status))
    return ctypes.WinError(error_number)


def _windows_information(handle, path):
    information = _WindowsFileInformation()
    if not _WINDOWS_KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise ArchiveError("unable to identify archive output handle: %s" % path) from _windows_error()
    return information


def _windows_directory_identities(handle, information, path):
    legacy_file_id = (int(information.file_index_high) << 32) | int(information.file_index_low)
    legacy = (int(information.volume_serial_number), legacy_file_id)
    if not legacy[0] or not legacy[1]:
        raise ArchiveError("archive output directory has no stable identity: %s" % path)

    get_extended = getattr(_WINDOWS_KERNEL32, "GetFileInformationByHandleEx", None)
    if get_extended is None:
        return None, legacy
    extended = _WindowsFileIdInformation()
    if get_extended(
        handle,
        _WINDOWS_FILE_ID_INFO_CLASS,
        ctypes.byref(extended),
        ctypes.sizeof(extended),
    ):
        modern = (
            int(extended.volume_serial_number),
            int.from_bytes(bytes(extended.file_id.identifier), "little"),
        )
        if not modern[0] or not modern[1]:
            raise ArchiveError("archive output directory has no stable modern identity: %s" % path)
        return modern, legacy
    error = _windows_error()
    if getattr(error, "winerror", None) not in _WINDOWS_UNSUPPORTED_FILE_ID_ERRORS:
        raise ArchiveError("unable to identify archive output directory: %s" % path) from error
    return None, legacy


def _close_windows_handle(handle, path):
    if not _WINDOWS_KERNEL32.CloseHandle(handle):
        raise ArchiveError("unable to close archive output handle: %s" % path) from _windows_error()


def _rename_windows_handle(source_handle, parent_handle, destination_name, replace_existing):
    payload = destination_name.encode("utf-16-le")
    file_name_type = ctypes.c_uint16 * (len(payload) // 2 + 2)

    class WindowsFileRenameInformation(ctypes.Structure):
        _fields_ = (
            ("replace_or_flags", ctypes.c_uint32),
            ("root_directory", ctypes.c_void_p),
            ("file_name_length", ctypes.c_uint32),
            ("file_name", file_name_type),
        )

    information = WindowsFileRenameInformation()
    if replace_existing:
        information.replace_or_flags = _WINDOWS_FILE_RENAME_REPLACE_IF_EXISTS | _WINDOWS_FILE_RENAME_POSIX_SEMANTICS
        information_class = _WINDOWS_FILE_RENAME_INFORMATION_EX_CLASS
    else:
        information.replace_or_flags = 0
        information_class = _WINDOWS_FILE_RENAME_INFORMATION_CLASS
    information.root_directory = int(parent_handle)
    information.file_name_length = len(payload)
    ctypes.memmove(
        ctypes.addressof(information) + WindowsFileRenameInformation.file_name.offset,
        payload,
        len(payload),
    )
    io_status = _WindowsIoStatusBlock()
    status = int(
        _WINDOWS_NTDLL.NtSetInformationFile(
            source_handle,
            ctypes.byref(io_status),
            ctypes.byref(information),
            ctypes.sizeof(information),
            information_class,
        )
    )
    if status != 0:
        error = _windows_status_error(status)
        if not replace_existing and getattr(error, "winerror", None) in _WINDOWS_DESTINATION_EXISTS_ERRORS:
            exists = FileExistsError("anchored replacement destination already exists")
            raise ArchiveError("anchored replacement destination already exists") from exists
        raise ArchiveError("unable to publish anchored Windows entry") from error


def _rename_posix_noreplace(
    source_parent_descriptor,
    source_name,
    destination_parent_descriptor,
    destination_name,
):
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    result = None
    if sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                source_parent_descriptor,
                source,
                destination_parent_descriptor,
                destination,
                _RENAME_NOREPLACE,
            )
        else:
            syscall_number = _LINUX_RENAMEAT2_SYSCALLS.get(os.uname().machine.lower())
            syscall = getattr(libc, "syscall", None)
            if syscall_number is None or syscall is None:
                raise ArchiveError("atomic no-replace publication is unsupported on this Linux architecture")
            syscall.restype = ctypes.c_long
            result = syscall(
                ctypes.c_long(syscall_number),
                ctypes.c_int(source_parent_descriptor),
                ctypes.c_char_p(source),
                ctypes.c_int(destination_parent_descriptor),
                ctypes.c_char_p(destination),
                ctypes.c_uint(_RENAME_NOREPLACE),
            )
    elif sys.platform == "darwin":
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is None:
            raise ArchiveError("atomic no-replace publication is unsupported on this macOS runtime")
        renameatx_np.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            source_parent_descriptor,
            source,
            destination_parent_descriptor,
            destination,
            _RENAME_EXCL,
        )
    else:
        raise ArchiveError("atomic no-replace publication is unsupported on this POSIX platform")

    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (errno.EEXIST, errno.ENOTEMPTY):
        raise FileExistsError(error_number, os.strerror(error_number), destination_name)
    if error_number in (
        errno.EINVAL,
        getattr(errno, "ENOSYS", -1),
        getattr(errno, "ENOTSUP", -1),
        getattr(errno, "EOPNOTSUPP", -1),
    ):
        raise ArchiveError("atomic no-replace publication is unsupported by this filesystem") from OSError(
            error_number, os.strerror(error_number)
        )
    raise OSError(error_number, os.strerror(error_number), destination_name)


def _rename_posix_exchange(
    source_parent_descriptor,
    source_name,
    destination_parent_descriptor,
    destination_name,
):
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    result = None
    if sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                source_parent_descriptor,
                source,
                destination_parent_descriptor,
                destination,
                _RENAME_EXCHANGE,
            )
        else:
            syscall_number = _LINUX_RENAMEAT2_SYSCALLS.get(os.uname().machine.lower())
            syscall = getattr(libc, "syscall", None)
            if syscall_number is None or syscall is None:
                raise ArchiveError("atomic exchange is unsupported on this Linux architecture")
            syscall.restype = ctypes.c_long
            result = syscall(
                ctypes.c_long(syscall_number),
                ctypes.c_int(source_parent_descriptor),
                ctypes.c_char_p(source),
                ctypes.c_int(destination_parent_descriptor),
                ctypes.c_char_p(destination),
                ctypes.c_uint(_RENAME_EXCHANGE),
            )
    elif sys.platform == "darwin":
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is None:
            raise ArchiveError("atomic exchange is unsupported on this macOS runtime")
        renameatx_np.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            source_parent_descriptor,
            source,
            destination_parent_descriptor,
            destination,
            _RENAME_SWAP,
        )
    else:
        raise ArchiveError("atomic exchange is unsupported on this POSIX platform")

    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (
        errno.EINVAL,
        getattr(errno, "ENOSYS", -1),
        getattr(errno, "ENOTSUP", -1),
        getattr(errno, "EOPNOTSUPP", -1),
    ):
        raise ArchiveError("atomic exchange is unsupported by this filesystem") from OSError(
            error_number, os.strerror(error_number)
        )
    raise OSError(error_number, os.strerror(error_number), destination_name)


def _isolate_posix_entry(parent_descriptor, name, expected_identity, prefix, rename_noreplace):
    quarantine_name = None
    for unused_attempt in range(4):
        candidate = "%s%s" % (prefix, secrets.token_hex(16))
        try:
            rename_noreplace(parent_descriptor, name, parent_descriptor, candidate)
        except FileExistsError:
            continue
        quarantine_name = candidate
        break
    if quarantine_name is None:
        raise ArchiveError("unable to allocate a private anchored quarantine name")
    try:
        moved = os.stat(quarantine_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise ArchiveError("unable to inspect the isolated anchored entry") from error
    if _identity(moved) == expected_identity:
        return quarantine_name, moved
    try:
        rename_noreplace(parent_descriptor, quarantine_name, parent_descriptor, name)
    except (ArchiveError, OSError) as error:
        raise ArchiveError(
            "anchored entry changed at the isolation boundary; substitute retained in quarantine"
        ) from error
    raise ArchiveError("anchored entry changed at the isolation boundary")


def _discard_posix_entry(parent_descriptor, name, expected_status):
    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if _identity(current) != _identity(expected_status):
        raise ArchiveError("anchored displaced entry changed before disposal")
    if stat.S_ISDIR(current.st_mode):
        os.rmdir(name, dir_fd=parent_descriptor)
    else:
        os.unlink(name, dir_fd=parent_descriptor)


def _open_windows_directory(path, expected_status):
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(path),
        _WINDOWS_FILE_TRAVERSE | _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        raise ArchiveError("unable to pin archive output directory: %s" % path) from _windows_error()
    try:
        information = _windows_information(handle, path)
        if not information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
            raise ArchiveError("archive output ancestor is not a directory: %s" % path)
        if information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise ArchiveError("archive output ancestor is a reparse point: %s" % path)
        modern_identity, legacy_identity = _windows_directory_identities(
            handle,
            information,
            path,
        )
        status = Path(path).lstat()
        if not stat.S_ISDIR(status.st_mode) or is_path_alias(path):
            raise ArchiveError("archive output ancestor is not a safe directory: %s" % path)
        expected_pair = (int(expected_status.st_dev), int(expected_status.st_ino))
        current_pair = (int(status.st_dev), int(status.st_ino))
        if _identity(status) != _identity(expected_status) or current_pair != expected_pair:
            raise ArchiveError("archive output directory changed while being pinned: %s" % path)
        if modern_identity is None:
            if expected_pair != legacy_identity:
                raise ArchiveError("archive output directory legacy identity does not exactly match: %s" % path)
        elif expected_pair not in (modern_identity, legacy_identity):
            raise ArchiveError("archive output directory handle identity does not match: %s" % path)
        return handle
    except (ArchiveError, OSError):
        # Failed Win32 directory validation retains no live guard handle.
        _close_windows_handle(handle, path)
        raise


def _open_windows_file(path):
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(path),
        _WINDOWS_GENERIC_WRITE,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        None,
        _WINDOWS_CREATE_NEW,
        _WINDOWS_FILE_ATTRIBUTE_NORMAL | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        raise ArchiveError("unable to exclusively create archive output file: %s" % path) from _windows_error()
    descriptor = None
    try:
        information = _windows_information(handle, path)
        size = (int(information.file_size_high) << 32) | int(information.file_size_low)
        if information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
            raise ArchiveError("archive output handle is a directory: %s" % path)
        if information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise ArchiveError("archive output handle is a reparse point: %s" % path)
        if int(information.number_of_links) != 1 or size != 0:
            raise ArchiveError("archive output handle is not a private empty file: %s" % path)
        descriptor = _WINDOWS_OPEN_OSFHANDLE(handle, os.O_WRONLY | getattr(os, "O_BINARY", 0))
        handle = None
        descriptor_status = os.fstat(descriptor)
        path_status = Path(path).lstat()
        if (
            is_path_alias(path)
            or not stat.S_ISREG(descriptor_status.st_mode)
            or int(descriptor_status.st_nlink) != 1
            or _identity(descriptor_status) != _identity(path_status)
        ):
            raise ArchiveError("archive output file changed while being created: %s" % path)
        identity = capture_identity(path)
        if not identity_matches(path, identity):
            raise ArchiveError("archive output file changed while being identified: %s" % path)
        stream = os.fdopen(descriptor, "wb")
        descriptor = None
        return stream, identity
    except (ArchiveError, IntegrityError, OSError):
        # The CRT descriptor owns the native handle only after open_osfhandle succeeds.
        if descriptor is not None:
            os.close(descriptor)
        elif handle is not None:
            _close_windows_handle(handle, path)
        raise


def _open_windows_existing_file(path, writable=False):
    access = _WINDOWS_GENERIC_READ
    descriptor_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    stream_mode = "rb"
    if writable:
        access |= _WINDOWS_GENERIC_WRITE
        descriptor_flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        stream_mode = "r+b"
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(path),
        access,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_ATTRIBUTE_NORMAL | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        raise ArchiveError("unable to open anchored regular file: %s" % path) from _windows_error()
    descriptor = None
    try:
        information = _windows_information(handle, path)
        if information.file_attributes & (_WINDOWS_FILE_ATTRIBUTE_DIRECTORY | _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT):
            raise ArchiveError("anchored input is not a regular file: %s" % path)
        if int(information.number_of_links) != 1:
            raise ArchiveError("anchored input is not a private regular file: %s" % path)
        descriptor = _WINDOWS_OPEN_OSFHANDLE(handle, descriptor_flags)
        handle = None
        descriptor_status = os.fstat(descriptor)
        path_status = Path(path).lstat()
        if (
            is_path_alias(path)
            or not stat.S_ISREG(descriptor_status.st_mode)
            or int(descriptor_status.st_nlink) != 1
            or _identity(descriptor_status) != _identity(path_status)
        ):
            raise ArchiveError("anchored input changed while being opened: %s" % path)
        identity = capture_identity(path)
        if not identity_matches(path, identity):
            raise ArchiveError("anchored input changed while being identified: %s" % path)
        stream = os.fdopen(descriptor, stream_mode)
        descriptor = None
        return stream, identity
    except (ArchiveError, IntegrityError, OSError):
        # The CRT descriptor owns the native handle only after open_osfhandle succeeds.
        if descriptor is not None:
            os.close(descriptor)
        elif handle is not None:
            _close_windows_handle(handle, path)
        raise


def _open_windows_entry(path, expected_identity=None):
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(path),
        _WINDOWS_DELETE | _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        raise ArchiveError("unable to pin archive output entry: %s" % path) from _windows_error()
    try:
        information = _windows_information(handle, path)
        status = Path(path).lstat()
        native_directory = bool(information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
        if native_directory != stat.S_ISDIR(status.st_mode):
            raise ArchiveError("archive output entry type changed while being pinned: %s" % path)
        if not native_directory and not (stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode)):
            raise ArchiveError("archive output entry has an unsupported type: %s" % path)
        expected_pair = (int(status.st_dev), int(status.st_ino))
        modern_identity, legacy_identity = _windows_directory_identities(
            handle,
            information,
            path,
        )
        if modern_identity is None:
            if expected_pair != legacy_identity:
                raise ArchiveError("archive output entry legacy identity does not exactly match: %s" % path)
        elif expected_pair not in (modern_identity, legacy_identity):
            raise ArchiveError("archive output entry handle identity does not match: %s" % path)
        if expected_identity is not None and not identity_matches(path, expected_identity):
            raise ArchiveError("archive output entry does not match its expected identity: %s" % path)
        return handle
    except (ArchiveError, IntegrityError, OSError):
        # Failed entry pinning retains no native guard handle.
        _close_windows_handle(handle, path)
        raise


class AnchoredDirectory(object):
    """Create and validate private descendants without following aliases."""

    def __init__(self, root, expected_identity=None, require_private_permissions=True):
        self.root = Path(root)
        self._expected_identity = expected_identity
        self._require_private_permissions = require_private_permissions
        self._descriptor = None
        self._root_identity = None
        self._windows = _WINDOWS_KERNEL32 is not None
        self._windows_directories = {}
        self._windows_directory_identities = {}
        self._tracked_identities = {}
        self._posix = (
            not self._windows
            and os.name == "posix"
            and os.open in os.supports_dir_fd
            and os.mkdir in os.supports_dir_fd
        )

    def __enter__(self):
        if self._expected_identity is not None:
            try:
                validate_identity(self._expected_identity, expected_file_type="directory")
            except IntegrityError as error:
                raise ArchiveError("invalid expected archive output root identity") from error
        if os.path.lexists(str(self.root)):
            if is_path_alias(self.root):
                raise ArchiveError("archive output root is a path alias: %s" % self.root)
        else:
            try:
                self.root.mkdir(mode=0o700)
            except OSError as error:
                # The transaction-owned staging parent may reject exclusive root creation.
                raise ArchiveError("unable to create archive output root: %s" % self.root) from error
        try:
            status = self.root.lstat()
        except OSError as error:
            # The staging root must remain observable while its descriptor is acquired.
            raise ArchiveError("unable to inspect archive output root: %s" % self.root) from error
        if not stat.S_ISDIR(status.st_mode) or is_path_alias(self.root):
            raise ArchiveError("archive output root is not a safe directory: %s" % self.root)
        if self._expected_identity is not None:
            try:
                matches_expected = identity_matches(self.root, self._expected_identity)
            except IntegrityError as error:
                raise ArchiveError("unable to verify archive output root identity: %s" % self.root) from error
            if not matches_expected:
                raise ArchiveError("archive output root identity does not match: %s" % self.root)
        self._root_identity = _identity(status)
        if self._windows:
            self._windows_directories[self.root] = _open_windows_directory(
                self.root,
                status,
            )
            self._windows_directory_identities[self.root] = _identity(status)
        elif self._posix:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            try:
                self._descriptor = os.open(str(self.root), flags)
                opened = os.fstat(self._descriptor)
            except OSError as error:
                # POSIX descriptor pinning rejects an output root changed during acquisition.
                self.close()
                raise ArchiveError("unable to pin archive output root: %s" % self.root) from error
            if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != self._root_identity:
                self.close()
                raise ArchiveError("archive output root changed while being pinned: %s" % self.root)
            if self._require_private_permissions:
                os.fchmod(self._descriptor, 0o700)
        elif os.name == "posix" and self._require_private_permissions:
            self.root.chmod(0o700)
        if self._expected_identity is not None:
            try:
                matches_expected = identity_matches(self.root, self._expected_identity)
            except IntegrityError as error:
                self.close()
                raise ArchiveError("archive output root changed while being pinned: %s" % self.root) from error
            if not matches_expected:
                self.close()
                raise ArchiveError("archive output root changed while being pinned: %s" % self.root)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def close(self):
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        failure = None
        for path, handle in reversed(tuple(self._windows_directories.items())):
            try:
                _close_windows_handle(handle, path)
            except ArchiveError as error:
                # Every Windows guard is released even when one CloseHandle call fails.
                if failure is None:
                    failure = error
        self._windows_directories.clear()
        self._windows_directory_identities.clear()
        self._tracked_identities.clear()
        if failure is not None:
            raise failure

    def _release_windows_directory_tree(self, root):
        root = Path(root)
        selected = sorted(
            (path for path in self._windows_directories if path == root or root in path.parents),
            key=lambda path: len(path.parts),
            reverse=True,
        )
        failure = None
        for path in selected:
            handle = self._windows_directories.pop(path)
            self._windows_directory_identities.pop(path, None)
            try:
                _close_windows_handle(handle, path)
            except ArchiveError as error:
                # Release every descendant guard before reporting a close failure.
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure

    def _verify_root(self):
        if self._windows:
            if self.root not in self._windows_directories:
                raise ArchiveError("archive output root is not pinned")
            for path, handle in tuple(self._windows_directories.items()):
                information = _windows_information(handle, path)
                try:
                    current = path.lstat()
                except OSError as error:
                    # Every guarded Win32 directory must retain one visible binding.
                    label = "root" if path == self.root else "ancestor"
                    raise ArchiveError("archive output %s became unavailable" % label) from error
                expected = self._windows_directory_identities[path]
                current_pair = (int(current.st_dev), int(current.st_ino))
                modern_identity, legacy_identity = _windows_directory_identities(
                    handle,
                    information,
                    path,
                )
                handle_matches = current_pair == legacy_identity or (
                    modern_identity is not None and current_pair == modern_identity
                )
                if (
                    information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
                    or not information.file_attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                    or is_path_alias(path)
                    or not stat.S_ISDIR(current.st_mode)
                    or _identity(current) != expected
                    or not handle_matches
                ):
                    label = "root" if path == self.root else "ancestor"
                    raise ArchiveError("archive output %s changed during extraction" % label)
            return
        if self._posix:
            try:
                current = os.fstat(self._descriptor)
                lexical = self.root.lstat()
            except OSError as error:
                # The pinned root descriptor is required for every descendant operation.
                raise ArchiveError("archive output root became unavailable") from error
            if (
                is_path_alias(self.root)
                or not stat.S_ISDIR(current.st_mode)
                or not stat.S_ISDIR(lexical.st_mode)
                or _identity(current) != self._root_identity
                or _identity(lexical) != self._root_identity
            ):
                raise ArchiveError("archive output root changed during extraction")
            return
        try:
            current = self.root.lstat()
        except OSError as error:
            # Non-POSIX platforms revalidate the lexical root around each exclusive operation.
            raise ArchiveError("archive output root became unavailable") from error
        if is_path_alias(self.root) or not stat.S_ISDIR(current.st_mode) or _identity(current) != self._root_identity:
            raise ArchiveError("archive output root changed during extraction")

    def assert_bound(self, expected_identity=None):
        """Require the visible root name to remain bound to the pinned directory."""

        if expected_identity is not None:
            try:
                validate_identity(expected_identity, expected_file_type="directory")
            except IntegrityError as error:
                raise ArchiveError("invalid expected archive output root identity") from error
            if self._expected_identity != expected_identity:
                raise ArchiveError("archive output anchor does not own the expected root identity")
        self._verify_root()

    def flush(self):
        """Flush the pinned root directory where the platform supports it."""

        self._verify_root()
        if self._posix:
            return flush_descriptor(self._descriptor, "anchored directory")
        return flush_directory(self.root)

    def flush_tree(self):
        """Validate and flush every directory below the anchor bottom-up."""

        self._verify_root()
        directories = []
        if self._posix:
            self._collect_posix_flush_directories(
                self._descriptor,
                (),
                directories,
            )
        else:
            self._collect_path_flush_directories(self.root, (), directories)
        directories.sort(key=lambda parts: (-len(parts), parts))
        outcomes = []
        if self._posix:
            for parts in directories:
                descriptor = self._open_existing_posix_directory(parts)
                try:
                    outcomes.append(flush_descriptor(descriptor, "anchored tree directory"))
                    self._verify_posix_directory(parts, descriptor)
                finally:
                    os.close(descriptor)
            outcomes.append(flush_descriptor(self._descriptor, "anchored tree root"))
        else:
            for parts in directories:
                path = self._existing_path_directory(parts)
                outcomes.append(flush_directory(path))
            outcomes.append(flush_directory(self.root))
        self._verify_root()
        return tuple(outcomes)

    def _collect_posix_flush_directories(self, descriptor, prefix, result):
        for name in os.listdir(descriptor):
            try:
                status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise ArchiveError("unable to inspect anchored tree object: %s" % name) from error
            parts = prefix + (name,)
            if stat.S_ISDIR(status.st_mode):
                if self._require_private_permissions and stat.S_IMODE(status.st_mode) != 0o700:
                    raise ArchiveError("anchored tree directory has unsafe permissions: %s" % "/".join(parts))
                child = os.open(name, self._directory_flags(), dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if _identity(opened) != _identity(status):
                        raise ArchiveError("anchored tree directory changed: %s" % "/".join(parts))
                    result.append(parts)
                    self._collect_posix_flush_directories(child, parts, result)
                finally:
                    os.close(child)
            elif not stat.S_ISREG(status.st_mode) or int(status.st_nlink) != 1:
                raise ArchiveError("anchored tree contains an alias or special object: %s" % "/".join(parts))

    def _collect_path_flush_directories(self, path, prefix, result):
        try:
            entries = list(path.iterdir())
        except OSError as error:
            raise ArchiveError("unable to inspect anchored tree directory: %s" % path) from error
        for entry in entries:
            parts = prefix + (entry.name,)
            try:
                status = entry.lstat()
            except OSError as error:
                raise ArchiveError("unable to inspect anchored tree object: %s" % entry) from error
            if is_path_alias(entry):
                raise ArchiveError("anchored tree contains a path alias: %s" % entry)
            if stat.S_ISDIR(status.st_mode):
                if os.name == "posix" and self._require_private_permissions and stat.S_IMODE(status.st_mode) != 0o700:
                    raise ArchiveError("anchored tree directory has unsafe permissions: %s" % entry)
                result.append(parts)
                self._collect_path_flush_directories(entry, parts, result)
            elif not stat.S_ISREG(status.st_mode) or int(status.st_nlink) != 1:
                raise ArchiveError("anchored tree contains a special object: %s" % entry)

    @staticmethod
    def _directory_flags():
        return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)

    def _open_posix_directory(self, parts):
        self._verify_root()
        descriptor = os.dup(self._descriptor)
        child = None
        prefix = ()
        try:
            for component in parts:
                created = False
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    # Existing archive ancestors are opened and validated immediately below.
                    pass
                try:
                    child = os.open(component, self._directory_flags(), dir_fd=descriptor)
                except OSError as error:
                    # O_NOFOLLOW and O_DIRECTORY reject symlink and non-directory ancestors.
                    raise ArchiveError("archive output ancestor is not a safe directory: %s" % component) from error
                status = os.fstat(child)
                if not stat.S_ISDIR(status.st_mode):
                    raise ArchiveError("archive output ancestor is not a directory: %s" % component)
                visible = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if _identity(visible) != _identity(status):
                    raise ArchiveError("archive output ancestor changed while being opened: %s" % component)
                prefix += (component,)
                self._track_identity(prefix, self._posix_identity(status, "directory"))
                if created:
                    os.fchmod(child, 0o700)
                    flush_descriptor(child, "anchored created directory")
                    flush_descriptor(descriptor, "anchored created directory parent")
                elif self._require_private_permissions and stat.S_IMODE(status.st_mode) != 0o700:
                    raise ArchiveError("archive output ancestor has unsafe permissions: %s" % component)
                os.close(descriptor)
                descriptor = child
                child = None
            return descriptor
        except (OSError, ArchiveError, DurabilityError):
            # Descriptor-relative traversal owns and closes its current directory handle.
            if child is not None:
                os.close(child)
            os.close(descriptor)
            raise

    def _open_existing_posix_directory(self, parts):
        self._verify_root()
        descriptor = os.dup(self._descriptor)
        child = None
        prefix = ()
        try:
            for component in parts:
                child = os.open(component, self._directory_flags(), dir_fd=descriptor)
                opened = os.fstat(child)
                visible = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _identity(opened) != _identity(visible)
                    or (self._require_private_permissions and stat.S_IMODE(opened.st_mode) != 0o700)
                ):
                    raise ArchiveError("archive output ancestor changed while being opened: %s" % component)
                prefix += (component,)
                self._track_identity(prefix, self._posix_identity(opened, "directory"))
                os.close(descriptor)
                descriptor = child
                child = None
            return descriptor
        except (OSError, ArchiveError):
            if child is not None:
                os.close(child)
            os.close(descriptor)
            raise

    def _verify_posix_directory(self, parts, descriptor):
        self._verify_root()
        path = self.root.joinpath(*parts)
        try:
            opened = os.fstat(descriptor)
            visible = path.lstat()
        except OSError as error:
            # A descriptor-relative mutation is valid only while its visible parent remains bound.
            raise ArchiveError("archive output ancestor became unavailable") from error
        if (
            is_path_alias(path)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(visible.st_mode)
            or _identity(opened) != _identity(visible)
        ):
            raise ArchiveError("archive output ancestor changed during anchored mutation")

    def _path_directory(self, parts):
        self._verify_root()
        current = self.root
        for component in parts:
            current = current / component
            created = False
            try:
                current.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            try:
                status = current.lstat()
            except OSError as error:
                # Fallback platforms still reject disappearance and aliases around creation.
                raise ArchiveError("unable to inspect archive output directory: %s" % current) from error
            if is_path_alias(current) or not stat.S_ISDIR(status.st_mode):
                raise ArchiveError("archive output ancestor is an alias or non-directory: %s" % current)
            if created and os.name == "posix":
                current.chmod(0o700)
            elif os.name == "posix" and self._require_private_permissions and stat.S_IMODE(status.st_mode) != 0o700:
                raise ArchiveError("archive output ancestor has unsafe permissions: %s" % current)
            if self._windows and current not in self._windows_directories:
                self._windows_directories[current] = _open_windows_directory(
                    current,
                    status,
                )
                self._windows_directory_identities[current] = _identity(status)
            self._track_identity(tuple(current.relative_to(self.root).parts), capture_identity(current))
            self._verify_root()
            if created:
                flush_directory(current)
                flush_directory(current.parent)
        return current

    def _existing_path_directory(self, parts):
        self._verify_root()
        current = self.root
        for component in parts:
            current = current / component
            try:
                status = current.lstat()
            except OSError as error:
                raise ArchiveError("unable to inspect archive output directory: %s" % current) from error
            if is_path_alias(current) or not stat.S_ISDIR(status.st_mode):
                raise ArchiveError("archive output ancestor is an alias or non-directory: %s" % current)
            if os.name == "posix" and self._require_private_permissions and stat.S_IMODE(status.st_mode) != 0o700:
                raise ArchiveError("archive output ancestor has unsafe permissions: %s" % current)
            if self._windows and current not in self._windows_directories:
                self._windows_directories[current] = _open_windows_directory(current, status)
                self._windows_directory_identities[current] = _identity(status)
            self._track_identity(tuple(current.relative_to(self.root).parts), capture_identity(current))
            self._verify_root()
        return current

    @staticmethod
    def _parts(parts):
        selected = tuple(parts)
        if not selected or any(
            not isinstance(part, str) or not part or part in (".", "..") or "/" in part or "\\" in part
            for part in selected
        ):
            raise ArchiveError("invalid anchored relative path")
        return selected

    @staticmethod
    def _posix_identity(status, file_type):
        return {
            "kind": "posix",
            "device": int(status.st_dev),
            "inode": int(status.st_ino),
            "file_type": file_type,
        }

    def _track_identity(self, parts, identity):
        selected = tuple(parts)
        previous = self._tracked_identities.get(selected)
        if previous is not None and previous != identity:
            raise ArchiveError("archive output identity changed: %s" % "/".join(selected))
        self._tracked_identities[selected] = identity
        return identity

    def _transfer_tracked_identity(self, source_parts, destination_parts, identity=None):
        source_parts = tuple(source_parts)
        destination_parts = tuple(destination_parts)
        tracked = self._tracked_identities.pop(source_parts, None)
        selected = identity or tracked
        self._tracked_identities.pop(destination_parts, None)
        if selected is not None:
            self._tracked_identities[destination_parts] = selected

    def identity(self, parts):
        """Return the stable identity of one non-followed relative entry."""

        selected = self._parts(parts)
        if self._posix:
            parent = self._open_posix_directory(selected[:-1])
            try:
                status = os.stat(selected[-1], dir_fd=parent, follow_symlinks=False)
                return {
                    "kind": "posix",
                    "device": int(status.st_dev),
                    "inode": int(status.st_ino),
                    "file_type": (
                        "directory"
                        if stat.S_ISDIR(status.st_mode)
                        else "regular"
                        if stat.S_ISREG(status.st_mode)
                        else "symlink"
                        if stat.S_ISLNK(status.st_mode)
                        else "unsupported"
                    ),
                }
            except OSError as error:
                # Descriptor-relative identity capture must not fall back to a pathname.
                raise ArchiveError("unable to identify anchored entry: %s" % "/".join(selected)) from error
            finally:
                os.close(parent)
        self._path_directory(selected[:-1])
        path = self.root.joinpath(*selected)
        try:
            identity = capture_identity(path)
        except (OSError, IntegrityError) as error:
            raise ArchiveError("unable to identify anchored entry: %s" % path) from error
        self._verify_root()
        return identity

    def read_symlink(self, parts):
        """Read one symbolic link while binding the observed object to its parent."""

        selected = self._parts(parts)
        if self._posix:
            parent = self._open_posix_directory(selected[:-1])
            try:
                before = os.stat(selected[-1], dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISLNK(before.st_mode):
                    raise ArchiveError("anchored entry is not a symbolic link: %s" % "/".join(selected))
                identity = self._posix_identity(before, "symlink")
                target = os.readlink(selected[-1], dir_fd=parent)
                after = os.stat(selected[-1], dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISLNK(after.st_mode) or self._posix_identity(after, "symlink") != identity:
                    raise ArchiveError("anchored symbolic link changed while being read: %s" % "/".join(selected))
                if os.readlink(selected[-1], dir_fd=parent) != target:
                    raise ArchiveError(
                        "anchored symbolic link target changed while being read: %s" % "/".join(selected)
                    )
            except OSError as error:
                raise ArchiveError("unable to read anchored symbolic link: %s" % "/".join(selected)) from error
            finally:
                os.close(parent)
            self._verify_root()
            return target, identity

        parent = self._path_directory(selected[:-1])
        path = parent / selected[-1]
        try:
            before = path.lstat()
            if is_path_alias(path) or not stat.S_ISLNK(before.st_mode):
                raise ArchiveError("anchored entry is not a symbolic link: %s" % path)
            identity = capture_identity(path)
            target = os.readlink(str(path))
            after = path.lstat()
            if (
                is_path_alias(path)
                or not stat.S_ISLNK(after.st_mode)
                or capture_identity(path) != identity
            ):
                raise ArchiveError("anchored symbolic link changed while being read: %s" % path)
            if os.readlink(str(path)) != target:
                raise ArchiveError("anchored symbolic link target changed while being read: %s" % path)
        except (OSError, IntegrityError) as error:
            raise ArchiveError("unable to read anchored symbolic link: %s" % path) from error
        self._verify_root()
        return target, identity

    def create_symlink(self, parts, target):
        """Exclusively create and verify one relative symbolic link."""

        selected = self._parts(parts)
        if not isinstance(target, str) or not target:
            raise ArchiveError("invalid anchored symlink target")
        if self._posix:
            parent = self._open_posix_directory(selected[:-1])
            try:
                os.symlink(target, selected[-1], target_is_directory=False, dir_fd=parent)
                status = os.stat(selected[-1], dir_fd=parent, follow_symlinks=False)
                actual = os.readlink(selected[-1], dir_fd=parent)
                if not stat.S_ISLNK(status.st_mode) or actual != target:
                    raise ArchiveError("anchored symlink changed while being created")
                outcome = {
                    "kind": "posix",
                    "device": int(status.st_dev),
                    "inode": int(status.st_ino),
                    "file_type": "symlink",
                }
                self._track_identity(selected, outcome)
                flush_descriptor(parent, "anchored symlink parent")
            except OSError as error:
                # Relative symlink creation is confined to the pinned parent directory.
                raise ArchiveError("unable to create anchored symlink") from error
            finally:
                os.close(parent)
            self._verify_root()
            return outcome
        parent = self._path_directory(selected[:-1])
        path = parent / selected[-1]
        try:
            os.symlink(target, str(path), target_is_directory=False)
            if not path.is_symlink() or os.readlink(str(path)) != target:
                raise ArchiveError("anchored symlink changed while being created")
            identity = capture_identity(path)
            self._track_identity(selected, identity)
        except (OSError, IntegrityError) as error:
            raise ArchiveError("unable to create anchored symlink") from error
        self._verify_root()
        flush_directory(parent)
        return identity

    def replace(
        self,
        source_parts,
        destination_parts,
        expected_identity=None,
        replace_existing=True,
        expected_destination_identity=None,
    ):
        """Publish one exact relative entry beneath this pinned root."""

        source_parts = self._parts(source_parts)
        destination_parts = self._parts(destination_parts)
        tracked_identity = self._tracked_identities.get(source_parts)
        if expected_identity is None:
            expected_identity = tracked_identity
        elif tracked_identity is not None and tracked_identity != expected_identity:
            raise ArchiveError("anchored replacement source identity disagrees with tracked creation")
        if expected_identity is not None:
            try:
                validate_identity(expected_identity)
            except IntegrityError as error:
                raise ArchiveError("invalid anchored replacement identity") from error
        if expected_destination_identity is not None:
            try:
                validate_identity(expected_destination_identity)
            except IntegrityError as error:
                raise ArchiveError("invalid anchored replacement destination identity") from error
            if not replace_existing:
                raise ArchiveError("anchored no-replace publication cannot expect a destination identity")
        if self._posix:
            source_parent = self._open_posix_directory(source_parts[:-1])
            destination_parent = None
            descriptor = None
            destination_descriptor = None
            destination_opened = None
            try:
                if source_parts[:-1] == destination_parts[:-1]:
                    destination_parent = source_parent
                else:
                    destination_parent = self._open_posix_directory(destination_parts[:-1])
                status = os.stat(source_parts[-1], dir_fd=source_parent, follow_symlinks=False)
                symlink_flag = _symlink_open_flag()
                if stat.S_ISLNK(status.st_mode) and symlink_flag is not None:
                    flags = symlink_flag
                else:
                    flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
                    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
                descriptor = os.open(source_parts[-1], flags, dir_fd=source_parent)
                opened = os.fstat(descriptor)
                source_identity = {
                    "kind": "posix",
                    "device": int(opened.st_dev),
                    "inode": int(opened.st_ino),
                    "file_type": (
                        "regular"
                        if stat.S_ISREG(opened.st_mode)
                        else "symlink"
                        if stat.S_ISLNK(opened.st_mode)
                        else "directory"
                    ),
                }
                if _identity(status) != _identity(opened) or (
                    expected_identity is not None and source_identity != expected_identity
                ):
                    raise ArchiveError("anchored replacement source identity changed")
                if replace_existing:
                    try:
                        destination_status = os.stat(
                            destination_parts[-1],
                            dir_fd=destination_parent,
                            follow_symlinks=False,
                        )
                        if stat.S_ISLNK(destination_status.st_mode) and symlink_flag is not None:
                            destination_flags = symlink_flag
                        else:
                            destination_flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
                            destination_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
                        destination_descriptor = os.open(
                            destination_parts[-1],
                            destination_flags,
                            dir_fd=destination_parent,
                        )
                        destination_opened = os.fstat(destination_descriptor)
                    except FileNotFoundError as error:
                        if expected_destination_identity is not None:
                            raise ArchiveError("anchored replacement destination identity changed") from error
                    if destination_opened is not None:
                        destination_identity = {
                            "kind": "posix",
                            "device": int(destination_opened.st_dev),
                            "inode": int(destination_opened.st_ino),
                            "file_type": (
                                "regular"
                                if stat.S_ISREG(destination_opened.st_mode)
                                else "symlink"
                                if stat.S_ISLNK(destination_opened.st_mode)
                                else "directory"
                            ),
                        }
                        if _identity(destination_status) != _identity(destination_opened) or (
                            expected_destination_identity is not None
                            and destination_identity != expected_destination_identity
                        ):
                            raise ArchiveError("anchored replacement destination identity changed")
                if destination_opened is not None:
                    _rename_posix_exchange(
                        source_parent,
                        source_parts[-1],
                        destination_parent,
                        destination_parts[-1],
                    )
                    published = os.stat(
                        destination_parts[-1],
                        dir_fd=destination_parent,
                        follow_symlinks=False,
                    )
                    displaced = os.stat(
                        source_parts[-1],
                        dir_fd=source_parent,
                        follow_symlinks=False,
                    )
                    if _identity(published) != _identity(opened) or _identity(displaced) != _identity(
                        destination_opened
                    ):
                        _rename_posix_exchange(
                            source_parent,
                            source_parts[-1],
                            destination_parent,
                            destination_parts[-1],
                        )
                        raise ArchiveError("anchored replacement changed at the publication boundary")
                    _discard_posix_entry(source_parent, source_parts[-1], destination_opened)
                else:
                    _rename_posix_noreplace(
                        source_parent,
                        source_parts[-1],
                        destination_parent,
                        destination_parts[-1],
                    )
                    published = os.stat(
                        destination_parts[-1],
                        dir_fd=destination_parent,
                        follow_symlinks=False,
                    )
                    if _identity(published) != _identity(opened):
                        try:
                            _rename_posix_noreplace(
                                destination_parent,
                                destination_parts[-1],
                                source_parent,
                                source_parts[-1],
                            )
                        except (ArchiveError, OSError) as error:
                            raise ArchiveError(
                                "anchored source changed at the publication boundary; "
                                "substitute retained at the destination"
                            ) from error
                        raise ArchiveError("anchored source changed at the publication boundary")
                if _identity(published) != _identity(opened):
                    raise ArchiveError("anchored replacement published a different entry")
                source_outcome = flush_descriptor(source_parent, "anchored publication source directory")
                if destination_parent == source_parent:
                    outcome = source_outcome
                else:
                    outcome = (
                        source_outcome,
                        flush_descriptor(
                            destination_parent,
                            "anchored publication destination directory",
                        ),
                    )
            except FileExistsError as error:
                raise ArchiveError("anchored replacement destination already exists") from error
            except OSError as error:
                raise ArchiveError("unable to publish anchored entry") from error
            finally:
                if destination_descriptor is not None:
                    os.close(destination_descriptor)
                if descriptor is not None:
                    os.close(descriptor)
                if destination_parent is not None and destination_parent != source_parent:
                    os.close(destination_parent)
                os.close(source_parent)
            self._verify_root()
            self._transfer_tracked_identity(source_parts, destination_parts, source_identity)
            return outcome
        source_parent = self._path_directory(source_parts[:-1])
        destination_parent = self._path_directory(destination_parts[:-1])
        source = source_parent / source_parts[-1]
        destination = destination_parent / destination_parts[-1]
        if expected_identity is not None:
            try:
                if not identity_matches(source, expected_identity):
                    raise ArchiveError("anchored replacement source identity changed")
            except IntegrityError as error:
                raise ArchiveError("unable to verify anchored replacement source") from error
        if self._windows:
            if source in self._windows_directories:
                self._release_windows_directory_tree(source)
            if destination in self._windows_directories:
                self._release_windows_directory_tree(destination)
            source_handle = _open_windows_entry(source, expected_identity=expected_identity)
            destination_handle = None
            try:
                if expected_destination_identity is not None:
                    destination_handle = _open_windows_entry(
                        destination,
                        expected_identity=expected_destination_identity,
                    )
                parent_handle = self._windows_directories[destination_parent]
                _rename_windows_handle(source_handle, parent_handle, destination.name, replace_existing)
                published_handles = ((destination_handle, destination), (source_handle, source))
                destination_handle = None
                source_handle = None
                close_failure = None
                for handle, path in published_handles:
                    if handle is None:
                        continue
                    try:
                        _close_windows_handle(handle, path)
                    except ArchiveError as error:
                        # A published entry must not retain either native rename guard.
                        if close_failure is None:
                            close_failure = error
                if close_failure is not None:
                    raise close_failure
                self._verify_root()
                if expected_identity is not None and not identity_matches(destination, expected_identity):
                    raise ArchiveError("anchored replacement published a different entry")
                if expected_identity is not None and expected_identity.get("file_type") == "directory":
                    self._existing_path_directory(destination_parts)
            finally:
                if destination_handle is not None:
                    _close_windows_handle(destination_handle, destination)
                if source_handle is not None:
                    _close_windows_handle(source_handle, source)
            source_outcome = flush_directory(source_parent)
            self._transfer_tracked_identity(source_parts, destination_parts, expected_identity)
            if destination_parent == source_parent:
                return source_outcome
            return source_outcome, flush_directory(destination_parent)
        if not replace_existing:
            raise ArchiveError("atomic no-replace publication is unsupported on this platform")
        if expected_destination_identity is not None:
            try:
                if not identity_matches(destination, expected_destination_identity):
                    raise ArchiveError("anchored replacement destination identity changed")
            except IntegrityError as error:
                raise ArchiveError("unable to verify anchored replacement destination") from error
        try:
            os.replace(str(source), str(destination))
        except OSError as error:
            raise ArchiveError("unable to publish anchored entry") from error
        self._verify_root()
        if expected_identity is not None and not identity_matches(destination, expected_identity):
            raise ArchiveError("anchored replacement published a different entry")
        source_outcome = flush_directory(source_parent)
        self._transfer_tracked_identity(source_parts, destination_parts, expected_identity)
        if destination_parent == source_parent:
            return source_outcome
        return source_outcome, flush_directory(destination_parent)

    def ensure_directory(self, parts):
        if self._posix:
            descriptor = self._open_posix_directory(parts)
            os.close(descriptor)
        else:
            self._path_directory(parts)

    def create_directory(self, parts):
        """Exclusively create, pin, and identify one private directory."""

        selected = self._parts(parts)
        if self._posix:
            parent = self._open_posix_directory(selected[:-1])
            child = None
            try:
                os.mkdir(selected[-1], 0o700, dir_fd=parent)
                child = os.open(selected[-1], self._directory_flags(), dir_fd=parent)
                status = os.fstat(child)
                if not stat.S_ISDIR(status.st_mode):
                    raise ArchiveError("anchored directory creation returned a non-directory")
                os.fchmod(child, 0o700)
                identity = {
                    "kind": "posix",
                    "device": int(status.st_dev),
                    "inode": int(status.st_ino),
                    "file_type": "directory",
                }
                self._track_identity(selected, identity)
                flush_descriptor(child, "anchored created directory")
                flush_descriptor(parent, "anchored directory parent")
                self._verify_posix_directory(selected[:-1], parent)
            except FileExistsError as error:
                raise ArchiveError("anchored directory already exists: %s" % "/".join(selected)) from error
            except OSError as error:
                raise ArchiveError("unable to create anchored directory: %s" % "/".join(selected)) from error
            finally:
                if child is not None:
                    os.close(child)
                os.close(parent)
            self._verify_root()
            return identity
        parent = self._path_directory(selected[:-1])
        path = parent / selected[-1]
        try:
            path.mkdir(mode=0o700)
            status = path.lstat()
            if is_path_alias(path) or not stat.S_ISDIR(status.st_mode):
                raise ArchiveError("anchored directory changed while being created")
            if os.name == "posix":
                path.chmod(0o700)
            if self._windows:
                handle = _open_windows_directory(path, status)
                self._windows_directories[path] = handle
                self._windows_directory_identities[path] = _identity(status)
            identity = capture_identity(path)
            self._track_identity(selected, identity)
        except FileExistsError as error:
            raise ArchiveError("anchored directory already exists: %s" % path) from error
        except (OSError, IntegrityError) as error:
            raise ArchiveError("unable to create anchored directory: %s" % path) from error
        self._verify_root()
        flush_directory(path)
        flush_directory(parent)
        return identity

    def create_file(self, parts):
        """Exclusively create a regular file and return its stream and identity."""

        if not parts:
            raise ArchiveError("archive output file has an empty path")
        selected = self._parts(parts)
        if self._posix:
            parent = self._open_posix_directory(selected[:-1])
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            descriptor = None
            try:
                try:
                    descriptor = os.open(selected[-1], flags, 0o600, dir_fd=parent)
                except FileExistsError as error:
                    raise ArchiveError("archive output file already exists: %s" % "/".join(selected)) from error
                except OSError as error:
                    # Exclusive no-follow creation rejects replaced or inaccessible output leaves.
                    raise ArchiveError("unable to create archive output file: %s" % "/".join(selected)) from error
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise ArchiveError("archive output leaf is not a private regular file: %s" % "/".join(selected))
                os.fchmod(descriptor, 0o600)
                visible = os.stat(selected[-1], dir_fd=parent, follow_symlinks=False)
                if _identity(visible) != _identity(status):
                    raise ArchiveError("archive output file changed while being created: %s" % "/".join(selected))
                identity = {
                    "kind": "posix",
                    "device": int(status.st_dev),
                    "inode": int(status.st_ino),
                    "file_type": "regular",
                }
                self._track_identity(selected, identity)
                stream = os.fdopen(descriptor, "wb")
                descriptor = None
                return stream, identity
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(parent)

        parent = self._path_directory(selected[:-1])
        target = parent / selected[-1]
        if self._windows:
            stream, identity = _open_windows_file(target)
            try:
                self._verify_root()
                self._track_identity(selected, identity)
                return stream, identity
            except ArchiveError:
                # A failed post-create root check must release the returned file handle.
                stream.close()
                raise
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(str(target), flags, 0o600)
        except FileExistsError as error:
            raise ArchiveError("archive output file already exists: %s" % "/".join(parts)) from error
        except OSError as error:
            # Exclusive creation is the portable fallback for non-POSIX output leaves.
            raise ArchiveError("unable to create archive output file: %s" % "/".join(parts)) from error
        try:
            descriptor_status = os.fstat(descriptor)
            path_status = target.lstat()
            if (
                is_path_alias(target)
                or not stat.S_ISREG(descriptor_status.st_mode)
                or _identity(descriptor_status) != _identity(path_status)
            ):
                raise ArchiveError("archive output file changed while being created: %s" % target)
            identity = capture_identity(target)
            if not identity_matches(target, identity):
                raise ArchiveError("archive output file changed while being identified: %s" % target)
            self._track_identity(selected, identity)
            stream = os.fdopen(descriptor, "wb")
            descriptor = None
            return stream, identity
        except (OSError, ArchiveError, IntegrityError):
            # A failed portable identity comparison must not leak the new descriptor.
            if descriptor is not None:
                os.close(descriptor)
            raise

    def open_file(self, parts):
        """Exclusively create a regular output stream under this anchor."""

        stream, unused_identity = self.create_file(parts)
        return stream

    def open_existing_file(self, parts, writable=False, expected_identity=None):
        """Open one existing private regular file and return its stream and identity."""

        selected = self._parts(parts)
        path = self.root.joinpath(*selected)
        if expected_identity is not None and not identity_matches(path, expected_identity):
            raise ArchiveError("anchored input identity changed before opening")
        if self._posix:
            parent = self._open_posix_directory(selected[:-1])
            descriptor = None
            try:
                flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_CLOEXEC", 0)
                descriptor = os.open(selected[-1], flags, dir_fd=parent)
                opened = os.fstat(descriptor)
                visible = os.stat(selected[-1], dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or int(opened.st_nlink) != 1
                    or _identity(opened) != _identity(visible)
                ):
                    raise ArchiveError("anchored input is not a stable private regular file: %s" % "/".join(selected))
                identity = {
                    "kind": "posix",
                    "device": int(opened.st_dev),
                    "inode": int(opened.st_ino),
                    "file_type": "regular",
                }
                if expected_identity is not None and not identity_matches(path, expected_identity):
                    raise ArchiveError("anchored input identity changed while opening")
                stream = os.fdopen(descriptor, "r+b" if writable else "rb")
                descriptor = None
                return stream, identity
            except OSError as error:
                raise ArchiveError("unable to open anchored regular file: %s" % "/".join(selected)) from error
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(parent)

        parent = self._path_directory(selected[:-1])
        target = parent / selected[-1]
        if self._windows:
            stream, identity = _open_windows_existing_file(target, writable=writable)
            try:
                self._verify_root()
                if expected_identity is not None and not identity_matches(target, expected_identity):
                    raise ArchiveError("anchored input identity changed while opening")
                return stream, identity
            except ArchiveError:
                stream.close()
                raise
        flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = None
        try:
            descriptor = os.open(str(target), flags)
            opened = os.fstat(descriptor)
            visible = target.lstat()
            if (
                is_path_alias(target)
                or not stat.S_ISREG(opened.st_mode)
                or int(opened.st_nlink) != 1
                or _identity(opened) != _identity(visible)
            ):
                raise ArchiveError("anchored input is not a stable private regular file: %s" % target)
            identity = capture_identity(target)
            if not identity_matches(target, identity):
                raise ArchiveError("anchored input changed while being identified: %s" % target)
            if expected_identity is not None and not identity_matches(target, expected_identity):
                raise ArchiveError("anchored input identity changed while opening")
            stream = os.fdopen(descriptor, "r+b" if writable else "rb")
            descriptor = None
            return stream, identity
        except (ArchiveError, IntegrityError, OSError):
            if descriptor is not None:
                os.close(descriptor)
            raise

    def file_evidence(self, parts, flush=False, expected_identity=None):
        """Return stable size and SHA-256 evidence from one anchored file handle."""

        stream, identity = self.open_existing_file(
            parts,
            writable=flush,
            expected_identity=expected_identity,
        )
        digest = hashlib.sha256()
        with stream:
            before = os.fstat(stream.fileno())
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(stream.fileno())
            before_snapshot = (
                int(before.st_dev),
                int(before.st_ino),
                stat.S_IFMT(before.st_mode),
                int(before.st_size),
                int(before.st_mtime_ns),
                int(before.st_ctime_ns),
            )
            after_snapshot = (
                int(after.st_dev),
                int(after.st_ino),
                stat.S_IFMT(after.st_mode),
                int(after.st_size),
                int(after.st_mtime_ns),
                int(after.st_ctime_ns),
            )
            if before_snapshot != after_snapshot:
                raise ArchiveError("anchored regular file changed while being read")
            if flush:
                flush_descriptor(stream.fileno(), "anchored regular file")
        self._verify_root()
        path = self.root.joinpath(*parts)
        if not identity_matches(path, identity):
            raise ArchiveError("anchored regular file binding changed while being read")
        if expected_identity is not None and identity != expected_identity:
            raise ArchiveError("anchored regular file identity changed while being read")
        return int(after.st_size), digest.hexdigest(), identity

    def read_json(self, parts, expected_identity=None):
        """Read strict JSON from one fixed handle and verify its visible binding."""

        selected = self._parts(parts)
        path = self.root.joinpath(*selected)
        if expected_identity is not None and not identity_matches(path, expected_identity):
            raise ArchiveError("anchored JSON identity changed before reading")
        stream, identity = self.open_existing_file(selected)
        with stream:
            before = os.fstat(stream.fileno())
            if os.name == "posix" and stat.S_IMODE(before.st_mode) != 0o600:
                raise ArchiveError("anchored JSON file has unsafe permissions")
            value = read_json_stream(stream, path)
            after = os.fstat(stream.fileno())
            before_snapshot = (
                int(before.st_dev),
                int(before.st_ino),
                stat.S_IFMT(before.st_mode),
                int(before.st_size),
                int(before.st_mtime_ns),
                int(before.st_ctime_ns),
            )
            after_snapshot = (
                int(after.st_dev),
                int(after.st_ino),
                stat.S_IFMT(after.st_mode),
                int(after.st_size),
                int(after.st_mtime_ns),
                int(after.st_ctime_ns),
            )
            if before_snapshot != after_snapshot:
                raise ArchiveError("anchored JSON file changed while being read")
        self._verify_root()
        if not identity_matches(path, identity):
            raise ArchiveError("anchored JSON binding changed while being read")
        if expected_identity is not None and not identity_matches(path, expected_identity):
            raise ArchiveError("anchored JSON authority changed while being read")
        return value, identity

    def write_json(
        self,
        parts,
        value,
        temporary_parts,
        replace_existing=False,
        expected_destination_identity=None,
    ):
        """Durably publish canonical JSON without leaving the pinned directory tree."""

        selected = self._parts(parts)
        temporary = self._parts(temporary_parts)
        if selected[:-1] != temporary[:-1]:
            raise ArchiveError("anchored JSON temporary must be adjacent to its destination")
        if replace_existing != (expected_destination_identity is not None):
            raise ArchiveError("anchored JSON replacement requires the exact destination identity")
        payload = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
        output, identity = self.create_file(temporary)
        with output:
            output.write(payload)
            output.flush()
            flush_descriptor(output.fileno(), "anchored JSON file")
        self.replace(
            temporary,
            selected,
            expected_identity=identity,
            replace_existing=replace_existing,
            expected_destination_identity=expected_destination_identity,
        )
        self._verify_root()
        return payload, identity

    def _scan_posix(self, descriptor, prefix, result):
        for name in os.listdir(descriptor):
            try:
                status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                # Final validation requires every created object to remain observable.
                raise ArchiveError("unable to inspect extracted archive object: %s" % name) from error
            parts = prefix + (name,)
            if stat.S_ISDIR(status.st_mode):
                if stat.S_IMODE(status.st_mode) != 0o700:
                    raise ArchiveError("extracted archive directory has unsafe permissions: %s" % "/".join(parts))
                child = os.open(name, self._directory_flags(), dir_fd=descriptor)
                try:
                    result[parts] = ("directory", 0)
                    self._scan_posix(child, parts, result)
                finally:
                    os.close(child)
            elif stat.S_ISREG(status.st_mode) and status.st_nlink == 1:
                if stat.S_IMODE(status.st_mode) != 0o600:
                    raise ArchiveError("extracted archive file has unsafe permissions: %s" % "/".join(parts))
                result[parts] = ("file", status.st_size)
            else:
                raise ArchiveError("extracted archive contains an alias or special object: %s" % "/".join(parts))

    def _scan_path(self, path, prefix, result):
        try:
            entries = list(path.iterdir())
        except OSError as error:
            # Final fallback validation requires a complete directory listing.
            raise ArchiveError("unable to inspect extracted archive directory: %s" % path) from error
        for entry in entries:
            parts = prefix + (entry.name,)
            try:
                status = entry.lstat()
            except OSError as error:
                # A fallback scan must reject entries replaced after the directory listing.
                raise ArchiveError("unable to inspect extracted archive object: %s" % entry) from error
            if is_path_alias(entry):
                raise ArchiveError("extracted archive contains a path alias: %s" % entry)
            if stat.S_ISDIR(status.st_mode):
                result[parts] = ("directory", 0)
                self._scan_path(entry, parts, result)
            elif stat.S_ISREG(status.st_mode) and int(status.st_nlink) == 1:
                result[parts] = ("file", status.st_size)
            else:
                raise ArchiveError("extracted archive contains a special object: %s" % entry)

    def prepare_executable(self, executable_name, normalized_name=None):
        """Select, optionally rename, and normalize one executable under the anchor."""

        self._verify_root()
        actual = {}
        if self._posix:
            self._scan_posix(self._descriptor, (), actual)
        else:
            self._scan_path(self.root, (), actual)
        candidates = [parts for parts, value in actual.items() if value[0] == "file" and parts[-1] == executable_name]
        if len(candidates) != 1:
            raise ArchiveError("expected exactly one %s executable, found %d" % (executable_name, len(candidates)))
        source_parts = candidates[0]
        expected_identity = self._tracked_identities.get(source_parts)
        selected_name = normalized_name or executable_name
        target_parts = source_parts[:-1] + (selected_name,)
        if self._posix:
            self._prepare_posix_executable(source_parts, target_parts, expected_identity)
        else:
            self._prepare_path_executable(source_parts, target_parts, expected_identity)
        self._verify_root()
        return target_parts

    def _prepare_posix_executable(self, source_parts, target_parts, expected_identity=None):
        parent = self._open_posix_directory(source_parts[:-1])
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(source_parts[-1], flags, dir_fd=parent)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or int(opened.st_nlink) != 1:
                raise ArchiveError("selected executable is not a private regular file")
            opened_identity = self._posix_identity(opened, "regular")
            if expected_identity is not None and opened_identity != expected_identity:
                raise ArchiveError("selected executable identity changed before normalization")
            if source_parts != target_parts:
                try:
                    os.stat(target_parts[-1], dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ArchiveError("normalized executable destination already exists")
                os.rename(
                    source_parts[-1],
                    target_parts[-1],
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                )
            os.fchmod(descriptor, 0o755)
            selected = os.stat(target_parts[-1], dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(selected.st_mode)
                or int(selected.st_nlink) != 1
                or _identity(selected) != _identity(opened)
                or stat.S_IMODE(selected.st_mode) != 0o755
            ):
                raise ArchiveError("selected executable changed during mode normalization")
            self._transfer_tracked_identity(source_parts, target_parts, opened_identity)
        except OSError as error:
            # Descriptor-relative selection and normalization expose filesystem races as archive errors.
            raise ArchiveError("unable to prepare extracted backend executable") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def _prepare_path_executable(self, source_parts, target_parts, expected_identity=None):
        parent = self._path_directory(source_parts[:-1])
        source = parent / source_parts[-1]
        target = parent / target_parts[-1]
        try:
            original = source.lstat()
        except OSError as error:
            # Fallback selection requires the approved source to remain visible.
            raise ArchiveError("unable to inspect extracted backend executable") from error
        if is_path_alias(source) or not stat.S_ISREG(original.st_mode) or int(original.st_nlink) != 1:
            raise ArchiveError("selected executable is not a private regular file")
        if expected_identity is not None:
            try:
                if not identity_matches(source, expected_identity):
                    raise ArchiveError("selected executable identity changed before normalization")
            except IntegrityError as error:
                raise ArchiveError("unable to verify selected executable identity") from error
        if source != target:
            if os.path.lexists(str(target)):
                raise ArchiveError("normalized executable destination already exists")
            if self._windows:
                source_handle = _open_windows_entry(source, expected_identity=expected_identity)
                try:
                    _rename_windows_handle(
                        source_handle,
                        self._windows_directories[parent],
                        target.name,
                        False,
                    )
                finally:
                    _close_windows_handle(source_handle, source)
            else:
                try:
                    os.rename(str(source), str(target))
                except OSError as error:
                    # The guarded parent contains both normalization names.
                    raise ArchiveError("unable to normalize extracted backend executable") from error
        if not self._windows and os.name == "posix":
            target.chmod(0o755)
        selected = target.lstat()
        if (
            is_path_alias(target)
            or not stat.S_ISREG(selected.st_mode)
            or int(selected.st_nlink) != 1
            or _identity(selected) != _identity(original)
        ):
            raise ArchiveError("selected executable changed during normalization")
        selected_identity = expected_identity or capture_identity(target)
        self._transfer_tracked_identity(source_parts, target_parts, selected_identity)

    def validate(self, expected):
        """Require the final private tree to equal an exact path/type/size plan."""

        self._verify_root()
        actual = {}
        if self._posix:
            self._scan_posix(self._descriptor, (), actual)
        else:
            self._scan_path(self.root, (), actual)
        self._verify_root()
        if actual != expected:
            raise ArchiveError("extracted archive tree does not match its approved member plan")
        for parts in sorted(expected):
            tracked = self._tracked_identities.get(parts)
            if tracked is None:
                continue
            if self.identity(parts) != tracked:
                raise ArchiveError("extracted archive object identity changed: %s" % "/".join(parts))
        self._verify_root()
