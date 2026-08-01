"""Stable cross-platform filesystem identities for backend recovery."""

import ctypes
import os
import stat
from pathlib import Path

from ..errors import IntegrityError

_FILE_TYPES = frozenset(("directory", "regular", "symlink"))
_MAXIMUM_NATIVE_INTEGER = (1 << 64) - 1

_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
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


class _WindowsFileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _WindowsFileIdInformation(ctypes.Structure):
    _fields_ = (
        ("volume_serial_number", ctypes.c_uint64),
        ("file_id", _WindowsFileId128),
    )


if ctypes.sizeof(_WindowsFileInformation) != 52:
    raise RuntimeError("BY_HANDLE_FILE_INFORMATION must use the 52-byte Windows ABI")
if ctypes.sizeof(_WindowsFileIdInformation) != 24:
    raise RuntimeError("FILE_ID_INFO must use the 24-byte Windows ABI")


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
    _WINDOWS_KERNEL32.CloseHandle.argtypes = (ctypes.c_void_p,)
    _WINDOWS_KERNEL32.CloseHandle.restype = ctypes.c_int32


def _file_type(status):
    if stat.S_ISDIR(status.st_mode):
        return "directory"
    if stat.S_ISREG(status.st_mode):
        return "regular"
    if stat.S_ISLNK(status.st_mode):
        return "symlink"
    raise IntegrityError("managed recovery object has an unsupported file type")


def _bounded_integer(value, field):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > _MAXIMUM_NATIVE_INTEGER:
        raise IntegrityError("invalid stable identity %s" % field)
    return value


def _fixed_hex(value, width, field):
    if (
        not isinstance(value, str)
        or len(value) != width
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise IntegrityError("invalid stable identity %s" % field)
    return value


def validate_identity(value, expected_file_type=None):
    # type: (dict, Optional[str]) -> dict
    """Validate and return one normative stable identity object."""

    if not isinstance(value, dict) or "kind" not in value:
        raise IntegrityError("invalid stable identity object")
    kind = value["kind"]
    if kind == "posix":
        if set(value) != {"kind", "device", "inode", "file_type"}:
            raise IntegrityError("invalid stable identity keys")
        _bounded_integer(value["device"], "device")
        _bounded_integer(value["inode"], "inode")
    elif kind == "windows-file-id":
        if set(value) != {"kind", "volume_serial", "file_id", "file_type"}:
            raise IntegrityError("invalid stable identity keys")
        _fixed_hex(value["volume_serial"], 16, "volume serial")
        _fixed_hex(value["file_id"], 32, "file id")
    elif kind == "windows-legacy-id":
        if set(value) != {"kind", "volume_serial", "file_id", "file_type"}:
            raise IntegrityError("invalid stable identity keys")
        _fixed_hex(value["volume_serial"], 8, "volume serial")
        _fixed_hex(value["file_id"], 16, "file id")
    else:
        raise IntegrityError("invalid stable identity kind")
    file_type = value.get("file_type")
    if file_type not in _FILE_TYPES:
        raise IntegrityError("invalid stable identity file type")
    if expected_file_type is not None and file_type != expected_file_type:
        raise IntegrityError("stable identity expected %s" % expected_file_type)
    return value


def _windows_extended_path(path):
    value = os.path.abspath(str(path))
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_error():
    return ctypes.WinError(ctypes.get_last_error())


def _capture_windows_identities(path, status, file_type):
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(path),
        _WINDOWS_FILE_READ_ATTRIBUTES,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        raise IntegrityError("unable to pin managed recovery object: %s" % path) from _windows_error()
    try:
        information = _WindowsFileInformation()
        if not _WINDOWS_KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise IntegrityError("unable to identify managed recovery object: %s" % path) from _windows_error()
        attributes = int(information.file_attributes)
        if (file_type == "directory") != bool(attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY):
            raise IntegrityError("managed recovery object changed type while identifying: %s" % path)
        if (file_type == "symlink") != bool(attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT):
            raise IntegrityError("managed recovery reparse state changed while identifying: %s" % path)
        legacy_file_id = (int(information.file_index_high) << 32) | int(information.file_index_low)
        legacy_pair = (int(information.volume_serial_number), legacy_file_id)
        if not legacy_pair[0] or not legacy_pair[1]:
            raise IntegrityError("managed recovery object has no stable legacy identity: %s" % path)
        legacy = {
            "kind": "windows-legacy-id",
            "volume_serial": "%08x" % legacy_pair[0],
            "file_id": "%016x" % legacy_pair[1],
            "file_type": file_type,
        }
        extended = _WindowsFileIdInformation()
        modern = None
        if _WINDOWS_KERNEL32.GetFileInformationByHandleEx(
            handle,
            _WINDOWS_FILE_ID_INFO_CLASS,
            ctypes.byref(extended),
            ctypes.sizeof(extended),
        ):
            modern_pair = (
                int(extended.volume_serial_number),
                int.from_bytes(bytes(extended.file_id.identifier), "little"),
            )
            if not modern_pair[0] or not modern_pair[1]:
                raise IntegrityError("managed recovery object has no stable modern identity: %s" % path)
            modern = {
                "kind": "windows-file-id",
                "volume_serial": "%016x" % modern_pair[0],
                "file_id": "%032x" % modern_pair[1],
                "file_type": file_type,
            }
        else:
            error = _windows_error()
            if getattr(error, "winerror", None) not in _WINDOWS_UNSUPPORTED_FILE_ID_ERRORS:
                raise IntegrityError("unable to identify extended managed recovery object: %s" % path) from error
        status_pair = (int(status.st_dev), int(status.st_ino))
        accepted_pairs = {legacy_pair}
        if modern is not None:
            accepted_pairs.add((int(modern["volume_serial"], 16), int(modern["file_id"], 16)))
        if status_pair not in accepted_pairs:
            raise IntegrityError("managed recovery object changed while identifying: %s" % path)
        return modern, legacy
    finally:
        if not _WINDOWS_KERNEL32.CloseHandle(handle):
            raise IntegrityError("unable to close managed recovery identity handle: %s" % path) from _windows_error()


def capture_identity(path):
    # type: (Path) -> dict
    """Capture one path without following its final component."""

    path = Path(path)
    try:
        status = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as error:
        # Managed recovery paths may become inaccessible between enumeration and capture.
        raise IntegrityError("unable to inspect managed recovery object: %s" % path) from error
    file_type = _file_type(status)
    if _WINDOWS_KERNEL32 is not None:
        modern, legacy = _capture_windows_identities(path, status, file_type)
        return modern or legacy
    if os.name != "posix":
        raise IntegrityError("stable filesystem identity is unsupported on this platform")
    return {
        "kind": "posix",
        "device": int(status.st_dev),
        "inode": int(status.st_ino),
        "file_type": file_type,
    }


def identity_matches(path, identity):
    # type: (Path, dict) -> bool
    """Return whether a current path still has an exact recorded identity."""

    expected = validate_identity(identity)
    path = Path(path)
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        # Permission and filesystem failures cannot be treated as a missing object.
        raise IntegrityError("unable to inspect managed recovery object: %s" % path) from error
    file_type = _file_type(status)
    if file_type != expected["file_type"]:
        return False
    if _WINDOWS_KERNEL32 is not None:
        modern, legacy = _capture_windows_identities(path, status, file_type)
        if expected["kind"] == "windows-file-id":
            return modern == expected
        if expected["kind"] == "windows-legacy-id":
            return legacy == expected
        return False
    if expected["kind"] != "posix":
        return False
    current = {
        "kind": "posix",
        "device": int(status.st_dev),
        "inode": int(status.st_ino),
        "file_type": file_type,
    }
    return current == expected
