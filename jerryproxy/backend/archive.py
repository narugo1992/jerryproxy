"""Safe, bounded extraction for supported backend release archives."""

import ctypes
import gzip
import hashlib
import os
import stat
import tarfile
import unicodedata
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath

from ..errors import ArchiveError
from ..home import is_path_alias
from .anchored import AnchoredDirectory
from .archive_preflight import preflight_gzip, preflight_tar_gzip, preflight_zip
from .durable import flush_descriptor

DEFAULT_MAXIMUM_EXTRACTED_BYTES = 768 * 1024 * 1024
BAD_GZIP_FILE = getattr(gzip, "BadGzipFile", OSError)
_WINDOWS_FORBIDDEN = set('<>:"|?*')
_WINDOWS_DEVICES = set(["CON", "PRN", "AUX", "NUL"])
_WINDOWS_DEVICES.update("COM%d" % value for value in range(1, 10))
_WINDOWS_DEVICES.update("LPT%d" % value for value in range(1, 10))
_WINDOWS_DEVICES.update("COM%s" % value for value in ("\u00b9", "\u00b2", "\u00b3"))
_WINDOWS_DEVICES.update("LPT%s" % value for value in ("\u00b9", "\u00b2", "\u00b3"))

_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_NORMAL = 0x00000080
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
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
_WINDOWS_OPEN_OSFHANDLE = None
if os.name == "nt":
    import msvcrt

    _WINDOWS_OPEN_OSFHANDLE = msvcrt.open_osfhandle
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


@dataclass(frozen=True)
class ArchiveLimits:
    """Finite resource ceilings applied before archive publication."""

    maximum_compressed_bytes: int = 256 * 1024 * 1024
    maximum_members: int = 4096
    maximum_files: int = 4096
    maximum_directories: int = 4096
    maximum_path_depth: int = 32
    maximum_component_bytes: int = 255
    maximum_path_bytes: int = 1024
    maximum_total_path_bytes: int = 4 * 1024 * 1024
    maximum_file_bytes: int = 512 * 1024 * 1024
    maximum_extracted_bytes: int = DEFAULT_MAXIMUM_EXTRACTED_BYTES
    maximum_zip_central_directory_bytes: int = 32 * 1024 * 1024
    maximum_tar_stream_bytes: int = 1024 * 1024 * 1024
    maximum_extension_bytes: int = 64 * 1024
    maximum_total_extension_bytes: int = 1024 * 1024


def _effective_limits(limits, maximum_bytes):
    # type: (Optional[ArchiveLimits], Optional[int]) -> ArchiveLimits
    selected = limits or ArchiveLimits()
    if maximum_bytes is None:
        return selected
    return replace(
        selected,
        maximum_file_bytes=maximum_bytes,
        maximum_extracted_bytes=maximum_bytes,
    )


def _validate_limits(limits):
    # type: (ArchiveLimits) -> None
    for name, value in limits.__dict__.items():
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError("%s must be a positive integer" % name)


def _windows_extended_path(path):
    value = os.path.abspath(str(path))
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _windows_error():
    return ctypes.WinError(ctypes.get_last_error())


def _close_windows_archive_handle(handle, archive):
    if not _WINDOWS_KERNEL32.CloseHandle(handle):
        raise ArchiveError("unable to close backend archive handle: %s" % archive) from _windows_error()


def _create_windows_archive_handle(archive):
    handle = _WINDOWS_KERNEL32.CreateFileW(
        _windows_extended_path(archive),
        _WINDOWS_GENERIC_READ | _WINDOWS_FILE_READ_ATTRIBUTES,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_ATTRIBUTE_NORMAL | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _WINDOWS_INVALID_HANDLE_VALUE:
        raise ArchiveError("unable to open backend archive: %s" % archive) from _windows_error()
    return handle


def _inspect_windows_archive_handle(handle, archive, limits):
    information = _WindowsFileInformation()
    if not _WINDOWS_KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise ArchiveError("unable to inspect backend archive handle: %s" % archive) from _windows_error()
    attributes = int(information.file_attributes)
    if attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
        raise ArchiveError("backend archive is not a regular file: %s" % archive)
    if attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        raise ArchiveError("backend archive handle is a reparse point: %s" % archive)
    native_size = (int(information.file_size_high) << 32) | int(information.file_size_low)
    if native_size > limits.maximum_compressed_bytes:
        raise ArchiveError("compressed input exceeds the safety limit")
    legacy_identity = (
        "legacy",
        int(information.volume_serial_number),
        (int(information.file_index_high) << 32) | int(information.file_index_low),
    )
    if int(information.number_of_links) < 1:
        raise ArchiveError("backend archive handle has no stable file identity: %s" % archive)

    extended = _WindowsFileIdInformation()
    if _WINDOWS_KERNEL32.GetFileInformationByHandleEx(
        handle,
        _WINDOWS_FILE_ID_INFO_CLASS,
        ctypes.byref(extended),
        ctypes.sizeof(extended),
    ):
        identity = (
            "modern",
            int(extended.volume_serial_number),
            int.from_bytes(bytes(extended.file_id.identifier), "little"),
        )
        if not identity[1] or not identity[2]:
            raise ArchiveError("backend archive handle has no stable modern file identity: %s" % archive)
        return native_size, identity

    error = _windows_error()
    if getattr(error, "winerror", None) not in _WINDOWS_UNSUPPORTED_FILE_ID_ERRORS:
        raise ArchiveError("unable to identify extended backend archive handle: %s" % archive) from error
    if not legacy_identity[1] or not legacy_identity[2]:
        raise ArchiveError("backend archive handle has no stable legacy file identity: %s" % archive)
    return native_size, legacy_identity


def _open_windows_archive(archive, limits):
    handle = _create_windows_archive_handle(archive)
    descriptor = None
    try:
        native_size, trusted_identity = _inspect_windows_archive_handle(handle, archive, limits)
        visible_handle = _create_windows_archive_handle(archive)
        try:
            visible_size, visible_identity = _inspect_windows_archive_handle(
                visible_handle,
                archive,
                limits,
            )
        finally:
            _close_windows_archive_handle(visible_handle, archive)
        if visible_identity != trusted_identity or visible_size != native_size:
            raise ArchiveError("backend archive changed while being opened: %s" % archive)
        descriptor = _WINDOWS_OPEN_OSFHANDLE(
            handle,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        handle = None
        status = os.fstat(descriptor)
        visible = Path(archive).lstat()
        if (
            is_path_alias(archive)
            or not stat.S_ISREG(status.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or int(status.st_size) != native_size
            or int(visible.st_size) != native_size
        ):
            raise ArchiveError("backend archive changed while being opened: %s" % archive)
        stream = os.fdopen(descriptor, "rb", buffering=0)
        descriptor = None
        identity = (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode), status.st_size)
        return stream, identity
    except (ArchiveError, OSError):
        # The CRT descriptor owns the native handle only after open_osfhandle succeeds.
        if descriptor is not None:
            os.close(descriptor)
        elif handle is not None:
            _close_windows_archive_handle(handle, archive)
        raise


def _open_archive(archive, limits):
    # type: (Path, ArchiveLimits) -> tuple
    if is_path_alias(archive):
        raise ArchiveError("backend archive must not be a path alias: %s" % archive)
    if _WINDOWS_KERNEL32 is not None:
        return _open_windows_archive(archive, limits)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(archive), flags)
    except OSError as error:
        # Caller-supplied archives may disappear, become aliases, or become inaccessible before opening.
        raise ArchiveError("unable to open backend archive: %s" % archive) from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ArchiveError("backend archive is not a regular file: %s" % archive)
        if status.st_size > limits.maximum_compressed_bytes:
            raise ArchiveError("compressed input exceeds the safety limit")
        handle = os.fdopen(descriptor, "rb", buffering=0)
    except (OSError, ArchiveError):
        # Descriptor validation failures must not leak the pinned archive handle.
        os.close(descriptor)
        raise
    identity = (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode), status.st_size)
    return handle, identity


class _BoundedArchiveView(object):
    """Expose only the archive extent captured when its handle was opened."""

    def __init__(self, handle, size):
        self._handle = handle
        self._size = size

    @property
    def closed(self):
        return self._handle.closed

    def close(self):
        self._handle.close()

    def fileno(self):
        return self._handle.fileno()

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        try:
            position = self._handle.tell()
        except (OSError, ValueError) as error:
            # Parser access must remain on the caller-owned pinned descriptor.
            raise ArchiveError("backend archive changed while being processed") from error
        if position < 0 or position > self._size:
            raise ArchiveError("backend archive position is outside its opened extent")
        return position

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self.tell() + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ArchiveError("backend archive seek mode is invalid")
        if not isinstance(position, int) or isinstance(position, bool) or position < 0 or position > self._size:
            raise ArchiveError("backend archive seek is outside its opened extent")
        try:
            selected = self._handle.seek(position, os.SEEK_SET)
        except (OSError, ValueError) as error:
            # A regular pinned archive must support deterministic absolute seeks.
            raise ArchiveError("backend archive changed while being processed") from error
        if selected != position:
            raise ArchiveError("backend archive changed while being processed")
        return selected

    def read(self, size=-1):
        position = self.tell()
        remaining = self._size - position
        if size is None or size < 0:
            requested = remaining
        else:
            requested = min(size, remaining)
        if requested == 0:
            return b""

        chunks = []
        unread = requested
        while unread:
            try:
                block = self._handle.read(unread)
            except (OSError, ValueError) as error:
                # In-place truncation or descriptor failure invalidates the fixed view.
                raise ArchiveError("backend archive changed while being processed") from error
            if not block:
                raise ArchiveError("backend archive changed while being processed")
            if len(block) > unread:
                raise ArchiveError("backend archive read exceeded its opened extent")
            chunks.append(block)
            unread -= len(block)
        return b"".join(chunks)


def _hash_handle(handle):
    digest = hashlib.sha256()
    handle.seek(0)
    while True:
        block = handle.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
    handle.seek(0)
    return digest.hexdigest()


def _verify_archive_identity(handle, identity):
    try:
        status = os.fstat(handle.fileno())
    except (OSError, ValueError) as error:
        # The caller-owned archive descriptor must remain valid through extraction.
        raise ArchiveError("backend archive changed while being processed") from error
    current = (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode), status.st_size)
    if current != identity:
        raise ArchiveError("backend archive changed while being processed")


def _verify_archive_handle(handle, identity, digest):
    _verify_archive_identity(handle, identity)
    current_digest = _hash_handle(handle)
    _verify_archive_identity(handle, identity)
    if current_digest != digest:
        raise ArchiveError("backend archive changed while being processed")


def _safe_parts(member_name, is_directory, limits):
    # type: (str, bool, ArchiveLimits) -> tuple
    if not isinstance(member_name, str) or not member_name:
        raise ArchiveError("empty archive member path")
    if "\\" in member_name:
        raise ArchiveError("backslash is not allowed in archive member paths")
    if any(unicodedata.category(character) in ("Cc", "Cs") for character in member_name):
        raise ArchiveError("control character is not allowed in archive member path")
    if unicodedata.normalize("NFC", member_name) != member_name:
        raise ArchiveError("archive member path must use Unicode NFC")

    raw_parts = member_name.split("/")
    if is_directory and raw_parts[-1:] == [""]:
        raw_parts = raw_parts[:-1]
    if not raw_parts:
        raise ArchiveError("empty archive member path")
    if raw_parts == ["."]:
        raise ArchiveError("empty archive member path")
    if "" in raw_parts:
        raise ArchiveError("empty archive member path component")
    if any(part in (".", "..") for part in raw_parts):
        raise ArchiveError("dot archive member path component is not allowed")
    member = PurePosixPath(*raw_parts)
    windows_member = PureWindowsPath(member_name)
    if member.is_absolute() or windows_member.is_absolute() or windows_member.drive:
        raise ArchiveError("unsafe archive member path: %s" % member_name)
    if len(raw_parts) > limits.maximum_path_depth:
        raise ArchiveError("archive member path depth exceeds the safety limit")

    for component in raw_parts:
        encoded = component.encode("utf-8")
        if len(encoded) > limits.maximum_component_bytes:
            raise ArchiveError("archive member component exceeds the safety limit")
        if component.endswith((".", " ")):
            raise ArchiveError("archive member component has a trailing dot or space")
        if any(character in _WINDOWS_FORBIDDEN for character in component):
            raise ArchiveError("archive member contains Windows-forbidden punctuation")
        device = component.split(".", 1)[0].upper()
        if device in _WINDOWS_DEVICES:
            raise ArchiveError("archive member uses a Windows device name")

    normalized = "/".join(raw_parts)
    if len(normalized.encode("utf-8")) > limits.maximum_path_bytes:
        raise ArchiveError("archive member path exceeds the safety limit")
    return tuple(raw_parts)


class _MemberPlan(object):
    def __init__(self, limits):
        # type: (ArchiveLimits) -> None
        self.limits = limits
        self.members = 0
        self.files = 0
        self.total_bytes = 0
        self.total_path_bytes = 0
        self._files = set()
        self._directories = set()
        self._collision_names = {}
        self._objects = {}

    def add(self, member_name, is_directory, size):
        # type: (str, bool, int) -> tuple
        self.members += 1
        if self.members > self.limits.maximum_members:
            raise ArchiveError("archive members exceeds the safety limit")
        parts = _safe_parts(member_name, is_directory, self.limits)
        normalized = "/".join(parts)
        self.total_path_bytes += len(normalized.encode("utf-8"))
        if self.total_path_bytes > self.limits.maximum_total_path_bytes:
            raise ArchiveError("aggregate archive member paths exceed the safety limit")

        keys = tuple("/".join(parts[:index]).casefold() for index in range(1, len(parts) + 1))
        key = keys[-1]
        existing = self._collision_names.get(key)
        if existing is not None:
            raise ArchiveError("duplicate backend archive member: %s" % normalized)
        for prefix in keys[:-1]:
            if prefix in self._files:
                raise ArchiveError("archive file/directory prefix conflict: %s" % normalized)
        for index, directory_key in enumerate(keys[:-1] if not is_directory else keys):
            if directory_key not in self._directories:
                self._directories.add(directory_key)
                if len(self._directories) > self.limits.maximum_directories:
                    raise ArchiveError("archive directories exceeds the safety limit")
            self._collision_names.setdefault(directory_key, "/".join(parts[: index + 1]))
            self._objects.setdefault(parts[: index + 1], ("directory", 0))

        self._collision_names[key] = normalized
        if is_directory:
            self._directories.add(key)
            self._objects[parts] = ("directory", 0)
            return parts

        self.files += 1
        if self.files > self.limits.maximum_files:
            raise ArchiveError("archive files exceeds the safety limit")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ArchiveError("invalid backend archive member size")
        if size > self.limits.maximum_file_bytes:
            raise ArchiveError("archive member exceeds the safety limit")
        self.total_bytes += size
        if self.total_bytes > self.limits.maximum_extracted_bytes:
            raise ArchiveError("extracted backend content exceeds the safety limit")
        self._files.add(key)
        self._objects[parts] = ("file", size)
        return parts

    @property
    def objects(self):
        return dict(self._objects)


def _copy_bounded(source, destination, maximum_bytes):
    total = 0
    try:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum_bytes:
                raise ArchiveError("extracted backend content exceeds the safety limit")
            written = 0
            while written < len(block):
                progress = destination.write(block[written:])
                if (
                    not isinstance(progress, int)
                    or isinstance(progress, bool)
                    or progress <= 0
                    or progress > len(block) - written
                ):
                    raise ArchiveError("archive output write made no valid progress")
                written += progress
        destination.flush()
        flush_descriptor(destination.fileno(), "extracted archive file")
    except OSError as error:
        # Stream or output filesystem failures leave only unpublished staging content.
        raise ArchiveError("unable to stream backend archive content") from error
    return total


@contextmanager
def _anchored_output(destination, output_tree=None):
    destination = Path(destination)
    if output_tree is None:
        with AnchoredDirectory(destination) as owned:
            yield owned
        return
    if not isinstance(output_tree, AnchoredDirectory) or output_tree.root != destination:
        raise ArchiveError("archive output anchor does not match its destination")
    output_tree.assert_bound()
    yield output_tree
    output_tree.assert_bound()


class PinnedArchive(object):
    """Keep one verified archive handle fixed across hashing and extraction."""

    def __init__(self, archive, maximum_bytes=None, limits=None):
        self.path = archive
        self.limits = _effective_limits(limits, maximum_bytes)
        _validate_limits(self.limits)
        self.lower_name = archive.name.lower()
        if not (
            self.lower_name.endswith(".zip")
            or self.lower_name.endswith(".tar.gz")
            or self.lower_name.endswith(".tgz")
            or self.lower_name.endswith(".gz")
        ):
            raise ArchiveError("unsupported backend archive: %s" % archive.name)
        self.handle = None
        self.identity = None
        self.sha256 = None
        self.size = None

    def __enter__(self):
        raw_handle, self.identity = _open_archive(self.path, self.limits)
        self.size = self.identity[3]
        self.handle = _BoundedArchiveView(raw_handle, self.size)
        try:
            self.sha256 = _hash_handle(self.handle)
            _verify_archive_identity(self.handle, self.identity)
        except (ArchiveError, OSError, ValueError):
            # Opening the context owns and closes the descriptor on validation failure.
            self.handle.close()
            self.handle = None
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.handle is not None:
            self.handle.close()
            self.handle = None
        return False

    def extract(self, destination, standalone_name, output_tree=None):
        """Extract through the pinned handle and reject any in-place mutation."""

        if self.handle is None or self.identity is None or self.sha256 is None:
            raise RuntimeError("pinned archive context is not open")
        _verify_archive_identity(self.handle, self.identity)
        if self.lower_name.endswith(".zip"):
            try:
                plan = preflight_zip(self.handle, self.limits)
            except ArchiveError as error:
                raise ArchiveError("invalid ZIP backend archive: %s" % error) from error
            _verify_archive_identity(self.handle, self.identity)
            self.handle.seek(0)
            if output_tree is None:
                _extract_zip(self.handle, destination, self.limits, plan)
            else:
                _extract_zip(self.handle, destination, self.limits, plan, output_tree=output_tree)
        elif self.lower_name.endswith(".tar.gz") or self.lower_name.endswith(".tgz"):
            try:
                plan = preflight_tar_gzip(self.handle, self.limits)
            except ArchiveError as error:
                raise ArchiveError("invalid TAR backend archive: %s" % error) from error
            _verify_archive_identity(self.handle, self.identity)
            self.handle.seek(0)
            if output_tree is None:
                _extract_tar(self.handle, destination, self.limits, plan)
            else:
                _extract_tar(self.handle, destination, self.limits, plan, output_tree=output_tree)
        else:
            try:
                plan = preflight_gzip(self.handle, self.limits)
            except ArchiveError as error:
                raise ArchiveError("invalid GZip backend archive: %s" % error) from error
            _verify_archive_identity(self.handle, self.identity)
            self.handle.seek(0)
            if output_tree is None:
                _extract_gzip(self.handle, destination, standalone_name, self.limits, plan)
            else:
                _extract_gzip(
                    self.handle,
                    destination,
                    standalone_name,
                    self.limits,
                    plan,
                    output_tree=output_tree,
                )
        _verify_archive_handle(self.handle, self.identity, self.sha256)


def extract_archive(archive, destination, standalone_name, maximum_bytes=None, limits=None):
    # type: (Path, Path, str, Optional[int], Optional[ArchiveLimits]) -> None
    """Extract one supported archive into a private unpublished directory."""

    with PinnedArchive(archive, maximum_bytes=maximum_bytes, limits=limits) as source:
        source.extract(destination, standalone_name)


def _extract_gzip(handle, destination, standalone_name, limits, plan, output_tree=None):
    member_plan = _MemberPlan(limits)
    parts = member_plan.add(standalone_name, False, plan.expanded_size)
    try:
        with _anchored_output(destination, output_tree) as selected_tree:
            with gzip.GzipFile(fileobj=handle, mode="rb") as source:
                with selected_tree.open_file(parts) as output:
                    written = _copy_bounded(
                        source,
                        output,
                        min(limits.maximum_file_bytes, limits.maximum_extracted_bytes),
                    )
            selected_tree.validate(member_plan.objects)
        if written != plan.expanded_size:
            raise ArchiveError("GZip content size did not match its preflight metadata")
    except (BAD_GZIP_FILE, EOFError, zlib.error, OSError) as error:
        # GZip parser construction and validation may fail while using the pinned stream.
        raise ArchiveError("invalid GZip backend archive: %s" % error) from error


def _extract_zip(handle, destination, limits, preflight, output_tree=None):
    # type: (object, Path, ArchiveLimits, ZipPreflightPlan) -> None
    try:
        source = zipfile.ZipFile(handle, "r")
    except (zipfile.BadZipFile, OSError) as error:
        # ZIP parser construction may reject a corrupt stream or report pinned-stream I/O failure.
        raise ArchiveError("invalid ZIP backend archive: %s" % error)

    try:
        with source:
            plan = _MemberPlan(limits)
            members = []
            infos = source.infolist()
            if len(infos) != preflight.entry_count:
                raise ArchiveError("ZIP member plan changed after preflight")
            for member, approved in zip(infos, preflight.entries):
                if (
                    member.filename != approved.name
                    or member.header_offset != approved.local_header_offset
                    or member.compress_size != approved.compressed_size
                    or member.file_size != approved.uncompressed_size
                    or member.compress_type != approved.method
                    or member.flag_bits != approved.flags
                    or member.CRC != approved.crc32
                ):
                    raise ArchiveError("ZIP member plan changed after preflight")
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ArchiveError("symbolic links are not allowed in backend archives")
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ArchiveError("special files are not allowed in backend archives")
                is_directory = member.is_dir()
                if file_type == stat.S_IFDIR and not is_directory or file_type == stat.S_IFREG and is_directory:
                    raise ArchiveError("ZIP entry type does not match its name")
                if member.flag_bits & 0x1:
                    raise ArchiveError("encrypted ZIP entries are not allowed")
                if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ArchiveError("unsupported ZIP compression method")
                parts = plan.add(member.filename, is_directory, 0 if is_directory else member.file_size)
                members.append((member, parts, is_directory))

            with _anchored_output(destination, output_tree) as selected_tree:
                for member, parts, is_directory in members:
                    if is_directory:
                        selected_tree.ensure_directory(parts)
                        continue
                    with source.open(member, "r") as input_stream:
                        with selected_tree.open_file(parts) as output:
                            written = _copy_bounded(input_stream, output, member.file_size)
                    if written != member.file_size:
                        raise ArchiveError("ZIP member size did not match its metadata")
                selected_tree.validate(plan.objects)
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, RuntimeError, zlib.error) as error:
        # CRC, encryption, and member corruption can surface only while reading.
        raise ArchiveError("invalid ZIP backend archive: %s" % error)


def _extract_tar(handle, destination, limits, preflight, output_tree=None):
    # type: (object, Path, ArchiveLimits, TarPreflightPlan) -> None
    member_plan = _MemberPlan(limits)
    planned = []
    for approved in preflight.entries:
        parts = member_plan.add(
            approved.name,
            approved.is_directory,
            0 if approved.is_directory else approved.size,
        )
        planned.append((approved, parts))
    try:
        source = tarfile.open(fileobj=handle, mode="r|gz")
    except (tarfile.TarError, OSError) as error:
        # TAR parser construction may reject a corrupt stream or report pinned-stream I/O failure.
        raise ArchiveError("invalid TAR backend archive: %s" % error)
    try:
        with source, _anchored_output(destination, output_tree) as selected_tree:
            index = 0
            for member in source:
                if index >= preflight.entry_count:
                    raise ArchiveError("TAR member plan changed during extraction")
                approved, parts = planned[index]
                index += 1
                approved_parts = _safe_parts(approved.name, approved.is_directory, limits)
                member_parts = _safe_parts(member.name, member.isdir(), limits)
                expected_type = b"5" if approved.is_directory else (b"0", b"\0")
                type_matches = (
                    member.type == expected_type if isinstance(expected_type, bytes) else member.type in expected_type
                )
                if (
                    member_parts != approved_parts
                    or member.isdir() != approved.is_directory
                    or member.size != approved.size
                    or not type_matches
                ):
                    raise ArchiveError("TAR member plan changed during extraction")
                if member.isdir():
                    selected_tree.ensure_directory(parts)
                    continue
                input_stream = source.extractfile(member)
                if input_stream is None:
                    raise ArchiveError("unable to read backend archive member: %s" % member.name)
                with input_stream:
                    with selected_tree.open_file(parts) as output:
                        written = _copy_bounded(input_stream, output, member.size)
                if written != member.size:
                    raise ArchiveError("TAR member size did not match its metadata")
            if index != preflight.entry_count:
                raise ArchiveError("TAR member plan changed during extraction")
            selected_tree.validate(member_plan.objects)
    except tarfile.TarError as error:
        raise ArchiveError("invalid TAR backend archive: %s" % error)


def find_executable(root, executable_name, normalized_name=None):
    # type: (Path, str, Optional[str]) -> Path
    """Select and normalize one executable without leaving its anchored tree."""

    with AnchoredDirectory(root) as output_tree:
        parts = output_tree.prepare_executable(executable_name, normalized_name)
    return root.joinpath(*parts)
