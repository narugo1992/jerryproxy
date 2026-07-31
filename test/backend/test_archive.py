import errno
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

import jerryproxy.backend.anchored as anchored_module
import jerryproxy.backend.archive as archive_module
from jerryproxy.backend.archive import (
    ArchiveLimits,
    PinnedArchive,
    extract_archive,
    find_executable,
)
from jerryproxy.errors import ArchiveError, DurabilityError, IntegrityError


class SimulatedArchiveWindowsKernel(object):
    """Exercise Win32 archive creation calls on a POSIX test filesystem."""

    def __init__(self, reparse_names=(), modern_failure=None):
        self.reparse_names = set(reparse_names)
        self.modern_failure = modern_failure
        self.last_error = None
        self.calls = []
        self.handles = {}
        self.opened_handles = []
        self.closed_handles = []
        self.rename_roots = []
        self.rename_classes = []
        self.rename_flags = []

    def CreateFileW(self, path, access, share, security, creation, flags, template):
        del security, template
        native = Path(path)
        self.calls.append((native, access, share, creation, flags))
        try:
            if creation == anchored_module._WINDOWS_CREATE_NEW:
                descriptor = os.open(str(native), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            else:
                open_flags = os.O_RDWR if access & anchored_module._WINDOWS_GENERIC_WRITE else os.O_RDONLY
                if native.is_dir():
                    open_flags |= getattr(os, "O_DIRECTORY", 0)
                descriptor = os.open(str(native), open_flags)
        except OSError:
            return anchored_module._WINDOWS_INVALID_HANDLE_VALUE
        self.handles[descriptor] = native
        self.opened_handles.append((descriptor, creation))
        return descriptor

    def GetFileInformationByHandle(self, handle, information_pointer):
        path = self.handles[handle]
        status = os.fstat(handle)
        information = information_pointer._obj
        information.file_attributes = 0
        if stat.S_ISDIR(status.st_mode):
            information.file_attributes |= anchored_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        if path.name in self.reparse_names:
            information.file_attributes |= anchored_module._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        information.number_of_links = int(status.st_nlink)
        information.file_size_high = (int(status.st_size) >> 32) & 0xFFFFFFFF
        information.file_size_low = int(status.st_size) & 0xFFFFFFFF
        information.volume_serial_number = int(status.st_dev) & 0xFFFFFFFF
        information.file_index_high = (int(status.st_ino) >> 32) & 0xFFFFFFFF
        information.file_index_low = int(status.st_ino) & 0xFFFFFFFF
        return True

    def GetFileInformationByHandleEx(self, handle, information_class, information_pointer, size):
        del information_class, size
        if self.modern_failure in ("unsupported", "denied"):
            return False
        status = os.fstat(handle)
        information = information_pointer._obj
        information.volume_serial_number = int(status.st_dev)
        file_id = 0 if self.modern_failure == "zero" else int(status.st_ino)
        raw = file_id.to_bytes(16, "little")
        for index, value in enumerate(raw):
            information.file_id.identifier[index] = value
        return True

    def NtSetInformationFile(self, handle, io_status, information_pointer, size, information_class):
        del io_status
        assert information_class in (
            anchored_module._WINDOWS_FILE_RENAME_INFORMATION_CLASS,
            anchored_module._WINDOWS_FILE_RENAME_INFORMATION_EX_CLASS,
        )
        information = information_pointer._obj
        replace_existing = bool(
            information.replace_or_flags & anchored_module._WINDOWS_FILE_RENAME_REPLACE_IF_EXISTS
        )
        parent_handle = information.root_directory
        self.rename_roots.append(parent_handle)
        self.rename_classes.append(information_class)
        self.rename_flags.append(int(information.replace_or_flags))
        name_length = information.file_name_length
        assert size == anchored_module.ctypes.sizeof(information)
        payload = anchored_module.ctypes.string_at(
            anchored_module.ctypes.addressof(information) + information.__class__.file_name.offset,
            name_length,
        )
        source = self.handles[handle]
        destination_parent = self.handles[parent_handle]
        destination = destination_parent / payload.decode("utf-16-le")
        try:
            if replace_existing:
                os.replace(str(source), str(destination))
            else:
                os.rename(str(source), str(destination))
        except OSError as error:
            if not replace_existing and error.errno in (errno.EEXIST, errno.ENOTEMPTY):
                self.last_error = 183
                return anchored_module.ctypes.c_int32(0xC0000035).value
            raise
        self.handles[handle] = destination
        self.last_error = None
        return 0

    def RtlNtStatusToDosError(self, status):
        del status
        return self.last_error if self.last_error is not None else 5

    def CloseHandle(self, handle):
        os.close(handle)
        self.handles.pop(handle, None)
        self.closed_handles.append(handle)
        return True


def configure_simulated_windows_archive_creation(monkeypatch, kernel):
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(anchored_module, "_WINDOWS_NTDLL", kernel)
    monkeypatch.setattr(anchored_module, "_WINDOWS_OPEN_OSFHANDLE", lambda handle, flags: handle)
    monkeypatch.setattr(anchored_module, "_windows_extended_path", lambda path: str(path))

    def windows_error():
        error = OSError("simulated Windows API failure")
        error.winerror = (
            kernel.last_error if kernel.last_error is not None else 50 if kernel.modern_failure == "unsupported" else 5
        )
        return error

    monkeypatch.setattr(anchored_module, "_windows_error", windows_error)
    monkeypatch.setattr(anchored_module, "_windows_status_error", lambda status: windows_error())


def configure_simulated_windows_archive_input(monkeypatch, kernel):
    monkeypatch.setattr(archive_module, "_WINDOWS_KERNEL32", kernel, raising=False)
    monkeypatch.setattr(archive_module, "_windows_extended_path", lambda path: str(path), raising=False)

    def transfer_handle(handle, flags):
        del flags
        kernel.handles.pop(handle, None)
        return handle

    monkeypatch.setattr(archive_module, "_WINDOWS_OPEN_OSFHANDLE", transfer_handle, raising=False)

    def windows_error():
        error = OSError("simulated Windows API failure")
        error.winerror = 50 if kernel.modern_failure == "unsupported" else 5
        return error

    monkeypatch.setattr(archive_module, "_windows_error", windows_error)


def _write_limit_archive(tmp_path, archive_type):
    members = (("aa/bb/cc", b"abc"), ("dd/ee", b"de"))
    if archive_type == "zip":
        archive = tmp_path / "backend.zip"
        with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
            for name, payload in members:
                stream.writestr(name, payload)
        return archive, "backend", members
    if archive_type == "tar":
        archive = tmp_path / "backend.tar.gz"
        with tarfile.open(str(archive), "w:gz") as stream:
            for name, payload in members:
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                stream.addfile(member, io.BytesIO(payload))
        return archive, "backend", members
    archive = tmp_path / "backend.gz"
    payload = b"abc"
    archive.write_bytes(gzip.compress(payload))
    return archive, "aa/bb/cc", (("aa/bb/cc", payload),)


def _archive_limit_value(archive, archive_type, dimension):
    if dimension == "maximum_compressed_bytes":
        return archive.stat().st_size
    if archive_type == "gzip":
        return {
            "maximum_members": 1,
            "maximum_files": 1,
            "maximum_directories": 2,
            "maximum_path_depth": 3,
            "maximum_component_bytes": 2,
            "maximum_path_bytes": 8,
            "maximum_total_path_bytes": 8,
            "maximum_file_bytes": 3,
            "maximum_extracted_bytes": 3,
        }[dimension]
    return {
        "maximum_members": 2,
        "maximum_files": 2,
        "maximum_directories": 3,
        "maximum_path_depth": 3,
        "maximum_component_bytes": 2,
        "maximum_path_bytes": 8,
        "maximum_total_path_bytes": 13,
        "maximum_file_bytes": 3,
        "maximum_extracted_bytes": 5,
    }[dimension]


_GENERAL_ARCHIVE_LIMITS = (
    "maximum_compressed_bytes",
    "maximum_members",
    "maximum_files",
    "maximum_directories",
    "maximum_path_depth",
    "maximum_component_bytes",
    "maximum_path_bytes",
    "maximum_total_path_bytes",
    "maximum_file_bytes",
    "maximum_extracted_bytes",
)


@pytest.mark.parametrize("archive_type", ("zip", "tar", "gzip"))
@pytest.mark.parametrize("dimension", _GENERAL_ARCHIVE_LIMITS)
def test_archive_extraction_accepts_each_exact_general_limit(tmp_path, archive_type, dimension):
    archive, standalone_name, members = _write_limit_archive(tmp_path, archive_type)
    exact = _archive_limit_value(archive, archive_type, dimension)
    destination = tmp_path / "output"

    extract_archive(
        archive,
        destination,
        standalone_name,
        limits=ArchiveLimits(**{dimension: exact}),
    )

    for name, payload in members:
        assert destination.joinpath(*name.split("/")).read_bytes() == payload


@pytest.mark.parametrize("archive_type", ("zip", "tar", "gzip"))
@pytest.mark.parametrize("dimension", _GENERAL_ARCHIVE_LIMITS)
def test_archive_extraction_rejects_each_general_limit_plus_one_before_output(
    tmp_path,
    archive_type,
    dimension,
):
    archive, standalone_name, unused_members = _write_limit_archive(tmp_path, archive_type)
    exact = _archive_limit_value(archive, archive_type, dimension)
    if archive_type == "gzip" and dimension in ("maximum_members", "maximum_files"):
        pytest.skip("a standalone GZip structurally contains exactly one regular member")
    destination = tmp_path / "output"

    with pytest.raises(ArchiveError, match="exceed"):
        extract_archive(
            archive,
            destination,
            standalone_name,
            limits=ArchiveLimits(**{dimension: exact - 1}),
        )

    assert not destination.exists()


def test_standalone_gzip_extraction(tmp_path):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"fake executable")
    destination = tmp_path / "output"
    extract_archive(archive, destination, "mihomo")
    executable = find_executable(destination, "mihomo")
    assert executable.read_bytes() == b"fake executable"
    if os.name == "posix":
        assert executable.stat().st_mode & stat.S_IXUSR


def test_archive_extraction_retries_short_output_writes(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"short-output-write"))
    original_open = anchored_module.AnchoredDirectory.open_file

    class ShortWriter(object):
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback):
            return self.stream.__exit__(exception_type, exception, traceback)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, block):
            return self.stream.write(block[:1])

    def short_open(anchored, parts):
        return ShortWriter(original_open(anchored, parts))

    monkeypatch.setattr(anchored_module.AnchoredDirectory, "open_file", short_open)

    extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b"short-output-write"


@pytest.mark.parametrize("progress", (None, 0, -1, True, 19))
def test_archive_extraction_rejects_invalid_output_write_progress(
    tmp_path,
    monkeypatch,
    progress,
):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"invalid-output-write"))
    original_open = anchored_module.AnchoredDirectory.open_file

    class InvalidWriter(object):
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback):
            return self.stream.__exit__(exception_type, exception, traceback)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, block):
            del block
            return progress

    def invalid_open(anchored, parts):
        return InvalidWriter(original_open(anchored, parts))

    monkeypatch.setattr(anchored_module.AnchoredDirectory, "open_file", invalid_open)

    with pytest.raises(ArchiveError, match="write made no valid progress"):
        extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b""


def test_archive_extraction_maps_output_write_failure_to_archive_error(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"write-failure"))
    original_open = anchored_module.AnchoredDirectory.open_file

    class FailingWriter(object):
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback):
            return self.stream.__exit__(exception_type, exception, traceback)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, block):
            del block
            raise OSError("simulated archive output failure")

    def failing_open(anchored, parts):
        return FailingWriter(original_open(anchored, parts))

    monkeypatch.setattr(anchored_module.AnchoredDirectory, "open_file", failing_open)

    with pytest.raises(ArchiveError, match="unable to stream backend archive content"):
        extract_archive(archive, tmp_path / "output", "mihomo")


def test_gzip_extraction_rejects_late_size_drift(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    original_copy = archive_module._copy_bounded

    def report_short_copy(source, destination, maximum_bytes):
        return original_copy(source, destination, maximum_bytes) - 1

    monkeypatch.setattr(archive_module, "_copy_bounded", report_short_copy)

    with pytest.raises(ArchiveError, match="GZip content size did not match"):
        extract_archive(archive, tmp_path / "output", "mihomo")


def test_gzip_parser_open_failure_after_preflight_is_a_domain_error(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))

    def fail_parser(*args, **kwargs):
        del args, kwargs
        raise OSError("simulated GZip parser open failure")

    monkeypatch.setattr(archive_module.gzip, "GzipFile", fail_parser)

    with pytest.raises(ArchiveError, match="invalid GZip backend archive"):
        extract_archive(archive, tmp_path / "output", "mihomo")


def test_corrupt_standalone_gzip_is_a_domain_error(tmp_path):
    archive = tmp_path / "corrupt.gz"
    archive.write_bytes(b"not a gzip stream")
    with pytest.raises(ArchiveError, match="invalid GZip backend archive"):
        extract_archive(archive, tmp_path / "output", "mihomo")


def test_archive_output_flush_continues_only_for_a_documented_unsupported_result(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"backend")

    def unsupported(descriptor):
        del descriptor
        raise OSError(errno.EINVAL, "simulated unsupported flush")

    monkeypatch.setattr(archive_module.os, "fsync", unsupported)

    extract_archive(archive, tmp_path / "output", "mihomo")
    assert (tmp_path / "output" / "mihomo").read_bytes() == b"backend"


def test_archive_output_flush_preserves_a_genuine_durability_failure(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"backend")

    def failed(descriptor):
        del descriptor
        raise OSError(errno.EIO, "simulated storage failure")

    monkeypatch.setattr(archive_module.os, "fsync", failed)

    with pytest.raises(DurabilityError, match="unable to flush extracted archive file"):
        extract_archive(archive, tmp_path / "output", "mihomo")


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_anchored_directory_creation_flushes_each_child_before_its_parent(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "output"
    root.mkdir(mode=0o700)
    flushed = []

    def record_flush(descriptor, kind):
        del kind
        flushed.append((os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino))
        return "flushed"

    monkeypatch.setattr(anchored_module, "flush_descriptor", record_flush)

    with anchored_module.AnchoredDirectory(root) as output_tree:
        output_tree.ensure_directory(("one", "two"))

    assert flushed == [
        (root.joinpath("one").stat().st_dev, root.joinpath("one").stat().st_ino),
        (root.stat().st_dev, root.stat().st_ino),
        (root.joinpath("one", "two").stat().st_dev, root.joinpath("one", "two").stat().st_ino),
        (root.joinpath("one").stat().st_dev, root.joinpath("one").stat().st_ino),
    ]


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_exclusive_anchored_directory_creation_flushes_child_then_parent(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "backends"
    backend = root / "mihomo"
    backend.mkdir(mode=0o700, parents=True)
    flushed = []

    def record_flush(descriptor, kind):
        del kind
        flushed.append((os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino))
        return "flushed"

    monkeypatch.setattr(anchored_module, "flush_descriptor", record_flush)

    with anchored_module.AnchoredDirectory(root) as output_tree:
        output_tree.create_directory(("mihomo", ".1.0.0.install-operation"))

    staging = backend / ".1.0.0.install-operation"
    assert flushed == [
        (staging.stat().st_dev, staging.stat().st_ino),
        (backend.stat().st_dev, backend.stat().st_ino),
    ]


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_anchored_flush_tree_flushes_directories_bottom_up(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "staging"
    leaf = root / "one" / "two"
    leaf.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    (root / "one").chmod(0o700)
    payload = leaf / "backend"
    payload.write_bytes(b"payload")
    payload.chmod(0o600)
    flushed = []

    def record_flush(descriptor, kind):
        del kind
        flushed.append((os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino))
        return "flushed"

    monkeypatch.setattr(anchored_module, "flush_descriptor", record_flush)

    with anchored_module.AnchoredDirectory(root) as output_tree:
        outcomes = output_tree.flush_tree()

    assert outcomes == ("flushed", "flushed", "flushed")
    assert flushed == [
        (leaf.stat().st_dev, leaf.stat().st_ino),
        ((root / "one").stat().st_dev, (root / "one").stat().st_ino),
        (root.stat().st_dev, root.stat().st_ino),
    ]


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link identity is required")
def test_anchored_flush_tree_rejects_a_hard_linked_file(tmp_path):
    root = tmp_path / "staging"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.write_bytes(b"payload")
    outside.chmod(0o600)
    os.link(str(outside), str(root / "backend"))

    with anchored_module.AnchoredDirectory(root) as output_tree:
        with pytest.raises(ArchiveError, match="alias or special object"):
            output_tree.flush_tree()

    assert outside.read_bytes() == b"payload"


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory permissions are required")
def test_anchored_flush_tree_rejects_an_unsafe_descendant_directory(tmp_path):
    root = tmp_path / "staging"
    child = root / "unsafe"
    child.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    child.chmod(0o755)

    with anchored_module.AnchoredDirectory(root) as output_tree:
        with pytest.raises(ArchiveError, match="directory has unsafe permissions"):
            output_tree.flush_tree()


def test_portable_anchored_directory_creation_and_tree_flush_preserve_order(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    root = tmp_path / "portable"
    root.mkdir(mode=0o700)
    flushed = []
    monkeypatch.setattr(
        anchored_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)) or "unsupported",
    )

    with anchored_module.AnchoredDirectory(root) as output_tree:
        output_tree.ensure_directory(("one", "two"))
        assert flushed == [root / "one", root, root / "one" / "two", root / "one"]
        flushed[:] = []
        outcomes = output_tree.flush_tree()

    assert outcomes == ("unsupported", "unsupported", "unsupported")
    assert flushed == [root / "one" / "two", root / "one", root]


def test_unsupported_archive_type_is_rejected(tmp_path):
    archive = tmp_path / "backend.xz"
    archive.write_bytes(b"unsupported")
    with pytest.raises(ArchiveError, match="unsupported backend archive"):
        extract_archive(archive, tmp_path / "output", "backend")


@pytest.mark.parametrize("value", (0, -1, True, "1"))
def test_archive_limits_require_positive_non_boolean_integers(tmp_path, value):
    archive = tmp_path / "backend.gz"
    archive.write_bytes(b"unused")

    with pytest.raises(ValueError, match="positive integer"):
        extract_archive(
            archive,
            tmp_path / "output",
            "backend",
            limits=ArchiveLimits(maximum_members=value),
        )


def test_archive_input_must_be_an_openable_private_regular_file(tmp_path):
    missing = tmp_path / "missing.zip"
    with pytest.raises(ArchiveError, match="unable to open"):
        extract_archive(missing, tmp_path / "missing-output", "xray")

    directory = tmp_path / "directory.zip"
    directory.mkdir()
    with pytest.raises(ArchiveError, match="not a regular file"):
        extract_archive(directory, tmp_path / "directory-output", "xray")


def test_archive_input_alias_is_rejected_without_reading_its_target(tmp_path):
    target = tmp_path / "target.zip"
    target.write_bytes(b"sentinel")
    alias = tmp_path / "alias.zip"
    alias.symlink_to(target.name)

    with pytest.raises(ArchiveError, match="must not be a path alias"):
        extract_archive(alias, tmp_path / "output", "xray")

    assert target.read_bytes() == b"sentinel"


def test_gzip_extraction_enforces_size_limit(tmp_path):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"12345")
    with pytest.raises(ArchiveError, match="safety limit"):
        extract_archive(archive, tmp_path / "output", "mihomo", maximum_bytes=4)


def test_zip_extraction_rejects_parent_traversal(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("../escape", b"bad")
    with pytest.raises(ArchiveError):
        extract_archive(archive, tmp_path / "output", "xray")
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize(
    "member_name, message",
    [
        ("bin\\xray", "backslash"),
        ("bin/./xray", "dot archive member"),
        ("bin//xray", "empty archive member"),
        ("CON.txt", "Windows device name"),
        ("COM\u00b9.txt", "Windows device name"),
        ("COM\u00b2.txt", "Windows device name"),
        ("COM\u00b3.txt", "Windows device name"),
        ("LPT\u00b9.txt", "Windows device name"),
        ("LPT\u00b2.txt", "Windows device name"),
        ("LPT\u00b3.txt", "Windows device name"),
        ("name. ", "trailing dot or space"),
        ("e\u0301/xray", "Unicode NFC"),
    ],
)
def test_zip_extraction_rejects_noncanonical_cross_platform_names(tmp_path, member_name, message):
    archive = tmp_path / "noncanonical.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(member_name, b"bad")

    with pytest.raises(ArchiveError, match=message):
        extract_archive(archive, tmp_path / "output", "xray")


def test_gzip_extraction_maps_surrogate_standalone_name_to_archive_error(tmp_path):
    archive = tmp_path / "backend.gz"
    archive.write_bytes(gzip.compress(b"backend"))

    with pytest.raises(ArchiveError, match="control character"):
        extract_archive(archive, tmp_path / "output", "bad\ud800name")


@pytest.mark.parametrize(
    ("member_name", "limits", "message"),
    (
        ("/absolute", ArchiveLimits(), "empty archive member path component"),
        ("bad:name", ArchiveLimits(), "Windows-forbidden punctuation"),
        ("four", ArchiveLimits(maximum_component_bytes=3), "component exceeds"),
        ("four", ArchiveLimits(maximum_path_bytes=3), "path exceeds"),
        ("four", ArchiveLimits(maximum_total_path_bytes=3), "aggregate archive member paths"),
        ("a/b/c", ArchiveLimits(maximum_directories=1), "directories exceeds"),
    ),
)
def test_zip_member_plan_enforces_every_path_resource_boundary(
    tmp_path,
    member_name,
    limits,
    message,
):
    archive = tmp_path / "bounded-path.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(member_name, b"payload")

    with pytest.raises(ArchiveError, match=message):
        extract_archive(archive, tmp_path / "output", "xray", limits=limits)


def test_zip_member_plan_enforces_file_count(tmp_path):
    archive = tmp_path / "files.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("one", b"1")
        stream.writestr("two", b"2")

    with pytest.raises(ArchiveError, match="files exceeds"):
        extract_archive(
            archive,
            tmp_path / "output",
            "xray",
            limits=ArchiveLimits(maximum_files=1),
        )


@pytest.mark.parametrize("member_name", ("bad\x85name", "bad\ud800name"))
def test_archive_member_unicode_controls_are_domain_errors(tmp_path, member_name):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"backend")

    with pytest.raises(ArchiveError, match="control character"):
        extract_archive(archive, tmp_path / "output", member_name)


@pytest.mark.parametrize(
    ("member_name", "file_type"),
    (
        ("typed-directory", stat.S_IFDIR),
        ("typed-file/", stat.S_IFREG),
    ),
)
def test_zip_explicit_type_must_match_trailing_slash_before_output(
    tmp_path,
    member_name,
    file_type,
):
    archive = tmp_path / "typed.zip"
    member = zipfile.ZipInfo(member_name)
    member.create_system = 3
    member.external_attr = (file_type | 0o600) << 16
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(member, b"")
    destination = tmp_path / "output"

    with pytest.raises(ArchiveError, match="ZIP entry type does not match its name"):
        extract_archive(archive, destination, "typed-file")

    assert not destination.exists()


def test_zip_extraction_rejects_file_directory_prefix_conflict(tmp_path):
    archive = tmp_path / "prefix.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin", b"file")
        stream.writestr("bin/xray", b"executable")

    with pytest.raises(ArchiveError, match="file/directory prefix conflict"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_windows_drive_path(tmp_path):
    archive = tmp_path / "windows-drive.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("C:/escape", b"bad")
    with pytest.raises(ArchiveError, match="unsafe archive member path"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_duplicate_casefolded_paths(tmp_path):
    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/Xray", b"one")
        stream.writestr("bin/xray", b"two")
    with pytest.raises(ArchiveError, match="duplicate backend archive member"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_symlink(tmp_path):
    archive = tmp_path / "evil-link.zip"
    info = zipfile.ZipInfo("xray")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(info, "target")
    with pytest.raises(ArchiveError):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_special_file(tmp_path):
    archive = tmp_path / "device.zip"
    info = zipfile.ZipInfo("device")
    info.create_system = 3
    info.external_attr = stat.S_IFCHR << 16
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(info, b"")

    with pytest.raises(ArchiveError, match="special files"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_preserves_nested_executable(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/", b"")
        stream.writestr("bin/xray", b"xray executable")

    destination = tmp_path / "output"
    extract_archive(archive, destination, "xray")
    assert find_executable(destination, "xray").read_bytes() == b"xray executable"


def test_zip_extraction_rejects_empty_member_path(tmp_path):
    archive = tmp_path / "empty-member.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(".", b"empty")
    with pytest.raises(ArchiveError, match="empty archive member path"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_enforces_total_size_limit(tmp_path):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"12345")
    with pytest.raises(ArchiveError, match="safety limit"):
        extract_archive(archive, tmp_path / "output", "xray", maximum_bytes=4)


def test_zip_extraction_enforces_member_and_depth_limits(tmp_path):
    archive = tmp_path / "bounded.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("a/b", b"one")
        stream.writestr("second", b"two")

    with pytest.raises(ArchiveError, match="members exceeds"):
        extract_archive(
            archive,
            tmp_path / "members",
            "xray",
            limits=ArchiveLimits(maximum_members=1),
        )
    with pytest.raises(ArchiveError, match="path depth exceeds"):
        extract_archive(
            archive,
            tmp_path / "depth",
            "xray",
            limits=ArchiveLimits(maximum_path_depth=1),
        )


def test_archive_enforces_compressed_input_limit_before_parsing(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")

    with pytest.raises(ArchiveError, match="compressed input exceeds"):
        extract_archive(
            archive,
            tmp_path / "output",
            "xray",
            limits=ArchiveLimits(maximum_compressed_bytes=archive.stat().st_size - 1),
        )


def test_corrupt_zip_is_a_domain_error(tmp_path):
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"not-zip")
    with pytest.raises(ArchiveError, match="invalid ZIP"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_parser_open_failure_after_preflight_is_a_domain_error(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")

    def fail_parser(*args, **kwargs):
        del args, kwargs
        raise OSError("simulated ZIP parser open failure")

    monkeypatch.setattr(archive_module.zipfile, "ZipFile", fail_parser)

    with pytest.raises(ArchiveError, match="invalid ZIP backend archive"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_late_member_size_drift(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    original_copy = archive_module._copy_bounded

    def report_short_copy(source, destination, maximum_bytes):
        return original_copy(source, destination, maximum_bytes) - 1

    monkeypatch.setattr(archive_module, "_copy_bounded", report_short_copy)

    with pytest.raises(ArchiveError, match="ZIP member size did not match"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_member_crc_failure_is_a_domain_error(tmp_path):
    archive = tmp_path / "bad-crc.zip"
    with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("xray", b"backend")
    with zipfile.ZipFile(str(archive), "r") as stream:
        member = stream.getinfo("xray")
    with archive.open("r+b") as stream:
        stream.seek(member.header_offset)
        header = stream.read(30)
        filename_length, extra_length = struct.unpack("<HH", header[26:30])
        stream.seek(member.header_offset + 30 + filename_length + extra_length)
        first = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((first[0] ^ 0xFF,)))

    with pytest.raises(ArchiveError, match="invalid ZIP backend archive"):
        extract_archive(archive, tmp_path / "output", "xray")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("filename", "other"),
        ("header_offset", 1),
        ("compress_size", 8),
        ("file_size", 8),
        ("compress_type", zipfile.ZIP_BZIP2),
        ("flag_bits", 0x800),
        ("CRC", 0),
    ],
)
def test_zip_extraction_rejects_library_plan_field_divergence_before_output(
    tmp_path,
    monkeypatch,
    field,
    replacement,
):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("xray", b"backend")
    destination = tmp_path / "output"
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    original_infolist = zipfile.ZipFile.infolist

    def divergent_infolist(source):
        members = original_infolist(source)
        setattr(members[0], field, replacement)
        return members

    monkeypatch.setattr(zipfile.ZipFile, "infolist", divergent_infolist)

    with pytest.raises(ArchiveError, match="ZIP member plan changed after preflight"):
        extract_archive(archive, destination, "xray")

    assert not destination.exists()
    assert outside.read_bytes() == b"sentinel"


def test_zip_extraction_rejects_library_entry_count_divergence_before_output(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    destination = tmp_path / "output"
    original_infolist = zipfile.ZipFile.infolist

    def missing_infolist_member(source):
        return original_infolist(source)[:-1]

    monkeypatch.setattr(zipfile.ZipFile, "infolist", missing_infolist_member)

    with pytest.raises(ArchiveError, match="ZIP member plan changed after preflight"):
        extract_archive(archive, destination, "xray")

    assert not destination.exists()


def test_zip_extraction_rejects_library_member_order_divergence_before_output(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("first", b"one")
        stream.writestr("xray", b"two")
    destination = tmp_path / "output"
    original_infolist = zipfile.ZipFile.infolist

    def reversed_infolist(source):
        return list(reversed(original_infolist(source)))

    monkeypatch.setattr(zipfile.ZipFile, "infolist", reversed_infolist)

    with pytest.raises(ArchiveError, match="ZIP member plan changed after preflight"):
        extract_archive(archive, destination, "xray")

    assert not destination.exists()


def test_duplicate_executable_is_rejected(tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir(parents=True)
    (root / "a" / "xray").write_bytes(b"one")
    (root / "b" / "xray").write_bytes(b"two")
    with pytest.raises(ArchiveError):
        find_executable(root, "xray")


def test_tar_gzip_extraction_preserves_nested_executable(tmp_path):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"fake sing-box executable"
    with tarfile.open(str(archive), "w:gz") as stream:
        directory = tarfile.TarInfo("sing-box-1.0.0")
        directory.type = tarfile.DIRTYPE
        stream.addfile(directory)
        executable = tarfile.TarInfo("sing-box-1.0.0/sing-box")
        executable.size = len(payload)
        stream.addfile(executable, io.BytesIO(payload))

    destination = tmp_path / "output"
    extract_archive(archive, destination, "sing-box")
    executable_path = find_executable(destination, "sing-box")
    assert executable_path.read_bytes() == payload


def test_tar_extraction_never_materializes_all_members(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"fake sing-box executable"
    with tarfile.open(str(archive), "w:gz") as stream:
        executable = tarfile.TarInfo("sing-box")
        executable.size = len(payload)
        stream.addfile(executable, io.BytesIO(payload))

    def reject_getmembers(self):
        raise AssertionError("getmembers must not be used")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", reject_getmembers)
    destination = tmp_path / "output"
    extract_archive(archive, destination, "sing-box")
    assert (destination / "sing-box").read_bytes() == payload


def test_tar_gzip_extraction_rejects_links(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(str(archive), "w:gz") as stream:
        link = tarfile.TarInfo("xray")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        stream.addfile(link)

    with pytest.raises(ArchiveError, match="links and special files"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_tar_gzip_extraction_enforces_total_size_limit(tmp_path):
    archive = tmp_path / "large.tar.gz"
    payload = b"12345"
    with tarfile.open(str(archive), "w:gz") as stream:
        executable = tarfile.TarInfo("sing-box")
        executable.size = len(payload)
        stream.addfile(executable, io.BytesIO(payload))
    with pytest.raises(ArchiveError, match="safety limit"):
        extract_archive(archive, tmp_path / "output", "sing-box", maximum_bytes=4)


def test_corrupt_tar_gzip_is_a_domain_error(tmp_path):
    archive = tmp_path / "corrupt.tar.gz"
    archive.write_bytes(b"not-tar")
    with pytest.raises(ArchiveError, match="invalid TAR"):
        extract_archive(archive, tmp_path / "output", "sing-box")


def test_tar_parser_open_failure_after_preflight_is_a_domain_error(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"backend"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))

    def fail_parser(*args, **kwargs):
        del args, kwargs
        raise OSError("simulated TAR parser open failure")

    monkeypatch.setattr(archive_module.tarfile, "open", fail_parser)

    with pytest.raises(ArchiveError, match="invalid TAR backend archive"):
        extract_archive(archive, tmp_path / "output", "sing-box")


def test_tar_extraction_rejects_late_member_size_drift(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"backend"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))
    original_copy = archive_module._copy_bounded

    def report_short_copy(source, destination, maximum_bytes):
        return original_copy(source, destination, maximum_bytes) - 1

    monkeypatch.setattr(archive_module, "_copy_bounded", report_short_copy)

    with pytest.raises(ArchiveError, match="TAR member size did not match"):
        extract_archive(archive, tmp_path / "output", "sing-box")


def test_tar_extraction_rejects_an_extra_streamed_member_after_preflight(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"backend"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))
    original_next = tarfile.TarFile.next
    injected = []

    def add_extra_member(source):
        member = original_next(source)
        if member is None and not injected:
            injected.append(True)
            extra = tarfile.TarInfo("extra")
            extra.type = tarfile.DIRTYPE
            return extra
        return member

    monkeypatch.setattr(tarfile.TarFile, "next", add_extra_member)

    with pytest.raises(ArchiveError, match="TAR member plan changed during extraction"):
        extract_archive(archive, tmp_path / "output", "sing-box")


def test_tar_regular_member_without_a_content_stream_is_rejected(tmp_path, monkeypatch):
    archive = tmp_path / "missing-stream.tar.gz"
    payload = b"x"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))

    monkeypatch.setattr(tarfile.TarFile, "extractfile", lambda self, selected: None)

    with pytest.raises(ArchiveError, match="unable to read backend archive member"):
        extract_archive(archive, tmp_path / "output", "sing-box")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("name", "other"),
        ("type", tarfile.DIRTYPE),
        ("size", 8),
    ],
)
def test_tar_extraction_rejects_library_plan_field_divergence_before_output(
    tmp_path,
    monkeypatch,
    field,
    replacement,
):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"backend"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))
    destination = tmp_path / "output"
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    original_next = tarfile.TarFile.next
    changed = []

    def divergent_next(source):
        member = original_next(source)
        if member is not None and not changed:
            setattr(member, field, replacement)
            changed.append(True)
        return member

    monkeypatch.setattr(tarfile.TarFile, "next", divergent_next)

    with pytest.raises(ArchiveError, match="TAR member plan changed during extraction"):
        extract_archive(archive, destination, "sing-box")

    assert destination.is_dir()
    assert list(destination.iterdir()) == []
    assert outside.read_bytes() == b"sentinel"


def test_tar_extraction_rejects_library_entry_count_divergence_before_output(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"backend"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))
    destination = tmp_path / "output"

    monkeypatch.setattr(tarfile.TarFile, "next", lambda source: None)

    with pytest.raises(ArchiveError, match="TAR member plan changed during extraction"):
        extract_archive(archive, destination, "sing-box")

    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_tar_extraction_rejects_library_member_order_divergence_before_output(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    with tarfile.open(str(archive), "w:gz") as stream:
        for name in ("first", "sing-box"):
            member = tarfile.TarInfo(name)
            member.size = 1
            stream.addfile(member, io.BytesIO(b"x"))
    destination = tmp_path / "output"
    first = tarfile.TarInfo("first")
    first.size = 1
    second = tarfile.TarInfo("sing-box")
    second.size = 1

    monkeypatch.setattr(tarfile.TarFile, "__iter__", lambda source: iter((second, first)))

    with pytest.raises(ArchiveError, match="TAR member plan changed during extraction"):
        extract_archive(archive, destination, "sing-box")

    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_zip_extraction_keeps_using_the_opened_archive_after_path_replacement(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"original")
    replacement = tmp_path / "replacement.zip"
    with zipfile.ZipFile(str(replacement), "w") as stream:
        stream.writestr("xray", b"replacement")
    displaced = tmp_path / "displaced.zip"
    original_preflight = archive_module.preflight_zip

    def replace_path_after_open(handle, limits):
        archive.rename(displaced)
        replacement.rename(archive)
        return original_preflight(handle, limits)

    monkeypatch.setattr(archive_module, "preflight_zip", replace_path_after_open)
    destination = tmp_path / "output"
    extract_archive(archive, destination, "xray")

    assert (destination / "xray").read_bytes() == b"original"
    with zipfile.ZipFile(str(archive), "r") as stream:
        assert stream.read("xray") == b"replacement"


def test_archive_view_never_exposes_bytes_appended_after_open(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    opened_size = archive.stat().st_size
    original_preflight = archive_module.preflight_zip

    def grow_after_open(handle, limits):
        with archive.open("ab") as stream:
            stream.write(b"untrusted appended bytes")
            stream.flush()
            os.fsync(stream.fileno())
        handle.seek(0)
        assert len(handle.read()) == opened_size
        handle.seek(0)
        return original_preflight(handle, limits)

    monkeypatch.setattr(archive_module, "preflight_zip", grow_after_open)

    with pytest.raises(ArchiveError, match="changed while being processed"):
        extract_archive(archive, tmp_path / "output", "xray")


@pytest.mark.parametrize(
    "offset,whence",
    [
        (-1, os.SEEK_SET),
        (1, os.SEEK_END),
    ],
)
def test_archive_view_rejects_seek_outside_opened_extent(tmp_path, monkeypatch, offset, whence):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")

    def seek_outside_view(handle, limits):
        handle.seek(offset, whence)

    monkeypatch.setattr(archive_module, "preflight_zip", seek_outside_view)

    with pytest.raises(ArchiveError, match="outside its opened extent"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_archive_view_rejects_an_invalid_seek_mode(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")

    def invalid_seek(handle, limits):
        del limits
        handle.seek(0, 999)

    monkeypatch.setattr(archive_module, "preflight_zip", invalid_seek)

    with pytest.raises(ArchiveError, match="seek mode is invalid"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_pinned_archive_exposes_open_state_and_rejects_extract_outside_context(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    source = PinnedArchive(archive)

    with pytest.raises(RuntimeError, match="context is not open"):
        source.extract(tmp_path / "outside-context", "xray")

    with source:
        view = source.handle
        assert view.readable()
        assert view.seekable()
        assert not view.closed
    assert view.closed


@pytest.mark.parametrize("archive_type", ("zip", "tar", "gzip"))
def test_pinned_archive_extracts_through_the_callers_matching_output_anchor(
    tmp_path,
    archive_type,
):
    archive, standalone_name, members = _write_limit_archive(tmp_path, archive_type)
    destination = tmp_path / "anchored-output"

    with anchored_module.AnchoredDirectory(destination) as output_tree:
        with PinnedArchive(archive) as source:
            source.extract(
                destination,
                standalone_name,
                output_tree=output_tree,
            )

    for name, payload in members:
        assert destination.joinpath(*name.split("/")).read_bytes() == payload


def test_pinned_archive_rejects_an_output_anchor_bound_to_another_destination(tmp_path):
    archive, standalone_name, unused_members = _write_limit_archive(tmp_path, "zip")
    destination = tmp_path / "expected-output"
    other_destination = tmp_path / "other-output"

    with anchored_module.AnchoredDirectory(other_destination) as output_tree:
        with PinnedArchive(archive) as source:
            with pytest.raises(ArchiveError, match="anchor does not match"):
                source.extract(
                    destination,
                    standalone_name,
                    output_tree=output_tree,
                )

    assert not destination.exists()
    assert list(other_destination.iterdir()) == []


def test_anchored_directory_assert_bound_rejects_invalid_identity_authority(tmp_path):
    destination = tmp_path / "output"

    with anchored_module.AnchoredDirectory(destination) as output_tree:
        with pytest.raises(ArchiveError, match="invalid expected archive output root identity"):
            output_tree.assert_bound({"kind": "invalid"})


def test_anchored_directory_assert_bound_rejects_another_directory_authority(tmp_path):
    destination = tmp_path / "output"
    other = tmp_path / "other"
    destination.mkdir(mode=0o700)
    other.mkdir(mode=0o700)
    destination_identity = anchored_module.capture_identity(destination)
    other_identity = anchored_module.capture_identity(other)

    with anchored_module.AnchoredDirectory(
        destination,
        expected_identity=destination_identity,
    ) as output_tree:
        with pytest.raises(ArchiveError, match="does not own the expected root identity"):
            output_tree.assert_bound(other_identity)


def test_windows_archive_input_uses_a_nonfollowing_native_handle(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b"backend"
    opened = [call for call in kernel.calls if call[0] == archive]
    assert len(opened) == 2
    for _path, access, share, creation, flags in opened:
        assert access & 0x80000000
        assert share & 0x00000004
        assert creation == 3
        assert flags & 0x00200000
    assert kernel.handles == {}


@pytest.mark.parametrize("modern_failure", (None, "unsupported"))
def test_windows_archive_input_compares_native_handles_not_crt_inode_values(
    tmp_path,
    monkeypatch,
    modern_failure,
):
    class DifferentCrtIdentityKernel(SimulatedArchiveWindowsKernel):
        def GetFileInformationByHandle(self, handle, information_pointer):
            result = super(DifferentCrtIdentityKernel, self).GetFileInformationByHandle(
                handle,
                information_pointer,
            )
            information = information_pointer._obj
            information.volume_serial_number ^= 0x1234
            information.file_index_low ^= 0x5678
            return result

        def GetFileInformationByHandleEx(self, handle, information_class, information_pointer, size):
            result = super(DifferentCrtIdentityKernel, self).GetFileInformationByHandleEx(
                handle,
                information_class,
                information_pointer,
                size,
            )
            if result:
                information = information_pointer._obj
                information.volume_serial_number ^= 0x12345678
                information.file_id.identifier[15] ^= 0x5A
            return result

    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    kernel = DifferentCrtIdentityKernel(modern_failure=modern_failure)
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b"backend"
    assert kernel.handles == {}


def test_windows_archive_input_rejects_path_replacement_between_native_opens(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "mihomo.gz"
    replacement = tmp_path / "replacement.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    replacement.write_bytes(gzip.compress(b"changed"))

    class ReplacingInputKernel(SimulatedArchiveWindowsKernel):
        def CreateFileW(self, path, access, share, security, creation, flags, template):
            if len(self.calls) == 1:
                os.replace(str(replacement), str(archive))
            return super(ReplacingInputKernel, self).CreateFileW(
                path,
                access,
                share,
                security,
                creation,
                flags,
                template,
            )

    kernel = ReplacingInputKernel()
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match="changed while being opened"):
        extract_archive(archive, tmp_path / "output", "mihomo")

    assert not (tmp_path / "output").exists()
    assert kernel.handles == {}


def test_windows_archive_input_prefers_modern_identity_over_truncated_legacy(
    tmp_path,
    monkeypatch,
):
    class TruncatedLegacyKernel(SimulatedArchiveWindowsKernel):
        def GetFileInformationByHandle(self, handle, information_pointer):
            result = super(TruncatedLegacyKernel, self).GetFileInformationByHandle(handle, information_pointer)
            information = information_pointer._obj
            information.volume_serial_number ^= 1
            information.file_index_low ^= 1
            return result

    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    kernel = TruncatedLegacyKernel()
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b"backend"
    assert kernel.handles == {}


def test_windows_archive_input_accepts_exact_legacy_identity_when_modern_is_unsupported(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    kernel = SimulatedArchiveWindowsKernel(modern_failure="unsupported")
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b"backend"
    assert kernel.handles == {}


@pytest.mark.parametrize(
    "modern_failure,message",
    (
        ("denied", "unable to identify extended backend archive handle"),
        ("zero", "no stable modern file identity"),
    ),
)
def test_windows_archive_input_rejects_untrusted_modern_identity(
    tmp_path,
    monkeypatch,
    modern_failure,
    message,
):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    kernel = SimulatedArchiveWindowsKernel(modern_failure=modern_failure)
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match=message):
        extract_archive(archive, tmp_path / "output", "mihomo")

    assert len(kernel.closed_handles) == 1
    with pytest.raises(OSError):
        os.fstat(kernel.closed_handles[0])
    assert not (tmp_path / "output").exists()


def test_windows_archive_input_rejects_a_reparse_handle(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))
    kernel = SimulatedArchiveWindowsKernel(reparse_names=(archive.name,))
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match="reparse point"):
        extract_archive(archive, tmp_path / "output", "mihomo")

    assert len(kernel.closed_handles) == 1
    with pytest.raises(OSError):
        os.fstat(kernel.closed_handles[0])
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("open", "unable to open backend archive"),
        ("information", "unable to inspect backend archive handle"),
        ("directory", "not a regular file"),
        ("oversized", "compressed input exceeds"),
        ("links", "no stable file identity"),
        ("legacy-zero", "no stable legacy file identity"),
        ("visible-size", "changed while being opened"),
        ("descriptor", "simulated descriptor inspection failure"),
    ),
)
def test_windows_archive_input_rejects_untrusted_handle_evidence_and_closes_it(
    tmp_path,
    monkeypatch,
    failure,
    message,
):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))

    class FailingArchiveKernel(SimulatedArchiveWindowsKernel):
        def CreateFileW(self, path, access, share, security, creation, flags, template):
            if failure == "open":
                return anchored_module._WINDOWS_INVALID_HANDLE_VALUE
            return super(FailingArchiveKernel, self).CreateFileW(
                path,
                access,
                share,
                security,
                creation,
                flags,
                template,
            )

        def GetFileInformationByHandle(self, handle, information_pointer):
            if failure == "information":
                return False
            result = super(FailingArchiveKernel, self).GetFileInformationByHandle(
                handle,
                information_pointer,
            )
            information = information_pointer._obj
            if failure == "directory":
                information.file_attributes |= archive_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY
            elif failure == "oversized":
                information.file_size_high = 1
            elif failure == "links":
                information.number_of_links = 0
            elif failure == "legacy-zero":
                information.volume_serial_number = 0
                information.file_index_high = 0
                information.file_index_low = 0
            return result

    kernel = FailingArchiveKernel(modern_failure="unsupported" if failure == "legacy-zero" else None)
    configure_simulated_windows_archive_input(monkeypatch, kernel)
    if failure == "visible-size":
        original_lstat = Path.lstat

        def changed_lstat(path):
            status = original_lstat(path)
            if path != archive:
                return status
            values = list(status)
            values[6] += 1
            return os.stat_result(values)

        monkeypatch.setattr(Path, "lstat", changed_lstat)
    elif failure == "descriptor":
        original_fstat = archive_module.os.fstat

        def denied_fstat(descriptor):
            if descriptor not in kernel.handles and any(
                descriptor == handle for handle, unused_creation in kernel.opened_handles
            ):
                raise OSError("simulated descriptor inspection failure")
            return original_fstat(descriptor)

        monkeypatch.setattr(archive_module.os, "fstat", denied_fstat)

    with pytest.raises((ArchiveError, OSError), match=message):
        extract_archive(archive, tmp_path / "output", "mihomo")

    assert not (tmp_path / "output").exists()
    if failure != "open":
        handle = kernel.opened_handles[0][0]
        with pytest.raises(OSError):
            os.fstat(handle)


def test_windows_archive_input_reports_close_failure_without_leaking_the_handle(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))

    class CloseFailureKernel(SimulatedArchiveWindowsKernel):
        def CloseHandle(self, handle):
            super(CloseFailureKernel, self).CloseHandle(handle)
            return False

    kernel = CloseFailureKernel(reparse_names=(archive.name,))
    configure_simulated_windows_archive_input(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match="unable to close backend archive handle"):
        extract_archive(archive, tmp_path / "output", "mihomo")

    assert len(kernel.closed_handles) == 1


@pytest.mark.parametrize(
    ("failure", "operation", "message"),
    (
        ("tell-error", "tell", "changed while being processed"),
        ("tell-outside", "tell", "outside its opened extent"),
        ("seek-error", "seek", "changed while being processed"),
        ("seek-mismatch", "seek", "changed while being processed"),
        ("read-error", "read", "changed while being processed"),
        ("read-overflow", "read", "exceeded its opened extent"),
    ),
)
def test_pinned_archive_view_rejects_untrusted_underlying_handle_results(
    tmp_path,
    failure,
    operation,
    message,
):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))

    with PinnedArchive(archive) as source:
        raw = source.handle._handle

        class FaultyHandle(object):
            def __getattr__(self, name):
                return getattr(raw, name)

            def tell(self):
                if failure == "tell-error":
                    raise OSError("simulated tell failure")
                if failure == "tell-outside":
                    return source.size + 1
                return raw.tell()

            def seek(self, offset, whence=os.SEEK_SET):
                if failure == "seek-error":
                    raise OSError("simulated seek failure")
                selected = raw.seek(offset, whence)
                return selected + 1 if failure == "seek-mismatch" else selected

            def read(self, size=-1):
                if failure == "read-error":
                    raise OSError("simulated read failure")
                block = raw.read(size)
                if failure == "read-overflow" and size > 0:
                    return block + b"x"
                return block

        source.handle._handle = FaultyHandle()
        with pytest.raises(ArchiveError, match=message):
            if operation == "tell":
                source.handle.tell()
            elif operation == "seek":
                source.handle.seek(0)
            else:
                source.handle.read(1)


def test_anchored_json_replaces_only_the_expected_destination_identity(tmp_path):
    root = tmp_path / "runtimes"
    root.mkdir()
    with anchored_module.AnchoredDirectory(root) as anchored:
        first_payload, first_identity = anchored.write_json(
            ("journal.json",),
            {"phase": "prepared"},
            (".journal.json.tmp-first",),
        )
        second_payload, second_identity = anchored.write_json(
            ("journal.json",),
            {"phase": "committed"},
            (".journal.json.tmp-second",),
            replace_existing=True,
            expected_destination_identity=first_identity,
        )

    assert json.loads(first_payload.decode("utf-8")) == {"phase": "prepared"}
    assert json.loads(second_payload.decode("utf-8")) == {"phase": "committed"}
    assert second_identity != first_identity
    assert json.loads((root / "journal.json").read_text(encoding="utf-8")) == {"phase": "committed"}

    wrong_identity = dict(second_identity)
    if wrong_identity["kind"] == "posix":
        wrong_identity["inode"] += 1
    else:
        wrong_identity["file_id"] = "f" * len(wrong_identity["file_id"])
    with anchored_module.AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="destination identity"):
            anchored.write_json(
                ("journal.json",),
                {"phase": "wrong"},
                (".journal.json.tmp-wrong",),
                replace_existing=True,
                expected_destination_identity=wrong_identity,
            )

    assert json.loads((root / "journal.json").read_text(encoding="utf-8")) == {"phase": "committed"}


def test_anchored_json_read_rejects_same_content_path_replacement(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    journal = root / "journal.json"
    payload = b'{"phase":"prepared"}\n'
    journal.write_bytes(payload)
    if os.name == "posix":
        journal.chmod(0o600)
    displaced = root / "journal.displaced"

    with anchored_module.AnchoredDirectory(root) as anchored:
        original_open = anchored.open_existing_file

        def open_then_replace(parts):
            stream, identity = original_open(parts)
            journal.rename(displaced)
            journal.write_bytes(payload)
            if os.name == "posix":
                journal.chmod(0o600)
            return stream, identity

        monkeypatch.setattr(anchored, "open_existing_file", open_then_replace)

        with pytest.raises(ArchiveError, match="binding changed"):
            anchored.read_json((journal.name,))

    assert displaced.read_bytes() == payload
    assert journal.read_bytes() == payload


def test_anchored_file_evidence_rejects_metadata_change_while_reading(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    target = root / "backend"
    target.write_bytes(b"backend")
    if os.name == "posix":
        target.chmod(0o600)
    original_fstat = os.fstat
    regular_calls = {}

    class ChangedStatus(object):
        def __init__(self, status):
            self._status = status
            self.st_mtime_ns = status.st_mtime_ns + 1

        def __getattr__(self, name):
            return getattr(self._status, name)

    def changed_fstat(descriptor):
        status = original_fstat(descriptor)
        if stat.S_ISREG(status.st_mode):
            regular_calls[descriptor] = regular_calls.get(descriptor, 0) + 1
            if regular_calls[descriptor] >= 3:
                return ChangedStatus(status)
        return status

    monkeypatch.setattr(os, "fstat", changed_fstat)

    with anchored_module.AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="changed while being read"):
            anchored.file_evidence((target.name,))


def test_archive_view_rejects_shrink_before_the_opened_extent_is_read(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    opened_size = archive.stat().st_size

    def shrink_after_open(handle, limits):
        with archive.open("r+b") as stream:
            stream.truncate(opened_size - 1)
            stream.flush()
            os.fsync(stream.fileno())
        handle.seek(opened_size - 1)
        handle.read(1)

    monkeypatch.setattr(archive_module, "preflight_zip", shrink_after_open)

    with pytest.raises(ArchiveError, match="changed while being processed"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_archive_growth_during_initial_hash_is_rejected_before_use(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    original_hash = archive_module._hash_handle

    def grow_after_hash(handle):
        digest = original_hash(handle)
        with archive.open("ab") as stream:
            stream.write(b"late growth")
            stream.flush()
            os.fsync(stream.fileno())
        return digest

    monkeypatch.setattr(archive_module, "_hash_handle", grow_after_hash)

    with pytest.raises(ArchiveError, match="changed while being processed"):
        with archive_module.PinnedArchive(archive):
            pass


def test_zip_parser_receives_the_preflighted_handle_instead_of_a_path(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    original_zipfile = zipfile.ZipFile
    inputs = []

    def record_input(source, *args, **kwargs):
        inputs.append(source)
        assert not isinstance(source, (str, os.PathLike))
        return original_zipfile(source, *args, **kwargs)

    monkeypatch.setattr(archive_module.zipfile, "ZipFile", record_input)
    extract_archive(archive, tmp_path / "output", "xray")

    assert len(inputs) == 1


def test_tar_parser_receives_the_preflighted_handle_instead_of_a_path(tmp_path, monkeypatch):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"backend"
    with tarfile.open(str(archive), "w:gz") as stream:
        member = tarfile.TarInfo("sing-box")
        member.size = len(payload)
        stream.addfile(member, io.BytesIO(payload))
    original_open = tarfile.open
    calls = []

    def record_open(*args, **kwargs):
        calls.append((args, kwargs))
        assert not args or args[0] is None
        assert kwargs.get("fileobj") is not None
        return original_open(*args, **kwargs)

    monkeypatch.setattr(archive_module.tarfile, "open", record_open)
    extract_archive(archive, tmp_path / "output", "sing-box")

    assert len(calls) == 1


def test_archive_mutation_during_extraction_is_rejected_before_success(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("xray", b"backend")
    original_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    original_extract = archive_module._extract_zip

    def mutate_after_extraction(source, destination, limits, plan):
        original_extract(source, destination, limits, plan)
        with archive.open("r+b") as stream:
            stream.seek(0)
            first = stream.read(1)
            stream.seek(0)
            stream.write(bytes((first[0] ^ 0x01,)))

    monkeypatch.setattr(archive_module, "_extract_zip", mutate_after_extraction)
    with pytest.raises(ArchiveError, match="changed while being processed"):
        extract_archive(archive, tmp_path / "output", "xray")

    assert hashlib.sha256(archive.read_bytes()).hexdigest() != original_digest


def test_zip_extraction_rejects_existing_output_ancestor_symlink(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/xray", b"backend")
    destination = tmp_path / "output"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "bin").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ArchiveError, match="alias|directory"):
        extract_archive(archive, destination, "xray")

    assert not (outside / "xray").exists()
    assert (destination / "bin").is_symlink()


def test_zip_extraction_rejects_existing_output_leaf_symlink(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    destination = tmp_path / "output"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    (destination / "xray").symlink_to(outside)

    with pytest.raises(ArchiveError, match="exists|alias"):
        extract_archive(archive, destination, "xray")

    assert outside.read_bytes() == b"sentinel"
    assert (destination / "xray").is_symlink()


def test_zip_extraction_rejects_existing_output_file(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    destination = tmp_path / "output"
    destination.mkdir()
    existing = destination / "xray"
    existing.write_bytes(b"sentinel")

    with pytest.raises(ArchiveError, match="exists"):
        extract_archive(archive, destination, "xray")

    assert existing.read_bytes() == b"sentinel"


def test_windows_archive_output_uses_native_exclusive_creation(tmp_path, monkeypatch):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    destination = tmp_path / "output"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        with output_tree.open_file(("bin", "xray")) as stream:
            stream.write(b"backend")

    file_calls = [call for call in kernel.calls if call[0].name == "xray"]
    assert len(file_calls) == 1
    unused_path, access, share, creation, flags = file_calls[0]
    assert access == anchored_module._WINDOWS_GENERIC_WRITE
    assert not share & anchored_module._WINDOWS_FILE_SHARE_DELETE
    assert creation == anchored_module._WINDOWS_CREATE_NEW
    assert flags & anchored_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    assert (destination / "bin" / "xray").read_bytes() == b"backend"


def test_windows_archive_output_directory_guards_do_not_share_delete(tmp_path, monkeypatch):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with archive_module.AnchoredDirectory(tmp_path / "output") as output_tree:
        output_tree.ensure_directory(("bin",))

    directory_calls = [
        call
        for call in kernel.calls
        if call[3] == anchored_module._WINDOWS_OPEN_EXISTING
        and call[4] & anchored_module._WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
    ]
    assert len(directory_calls) == 2
    assert all(not share & anchored_module._WINDOWS_FILE_SHARE_DELETE for _, _, share, _, _ in directory_calls)
    assert all(
        access & anchored_module._WINDOWS_FILE_TRAVERSE
        and access & anchored_module._WINDOWS_FILE_READ_ATTRIBUTES
        and access & anchored_module._WINDOWS_SYNCHRONIZE
        for _, access, _, _, _ in directory_calls
    )


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows archive input identity semantics")
def test_windows_native_archive_input_accepts_real_file_identity(tmp_path):
    archive = tmp_path / "mihomo.gz"
    archive.write_bytes(gzip.compress(b"backend"))

    extract_archive(archive, tmp_path / "output", "mihomo")

    assert (tmp_path / "output" / "mihomo").read_bytes() == b"backend"


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows directory sharing semantics")
@pytest.mark.parametrize("scope", ("root", "nested"))
def test_windows_archive_output_directory_guards_block_native_rename(tmp_path, scope):
    destination = tmp_path / "output"
    displaced = tmp_path / "displaced"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        output_tree.ensure_directory(("bin",))
        selected = destination if scope == "root" else destination / "bin"
        with pytest.raises(OSError):
            selected.rename(displaced)
        assert selected.is_dir()
        assert not displaced.exists()
        output_tree.assert_bound()


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows directory publication guards")
def test_windows_native_directory_publication_reacquires_the_final_guard(tmp_path):
    root = tmp_path / "backends"
    displaced = tmp_path / "displaced"

    with archive_module.AnchoredDirectory(root) as output_tree:
        output_tree.ensure_directory(("mihomo",))
        identity = output_tree.create_directory(("mihomo", ".1.0.0.install-operation"))
        outcome = output_tree.replace(
            ("mihomo", ".1.0.0.install-operation"),
            ("mihomo", "1.0.0"),
            expected_identity=identity,
            replace_existing=False,
        )
        final = root / "mihomo" / "1.0.0"
        with pytest.raises(OSError):
            final.rename(displaced)

    assert outcome == "unsupported"
    assert final.is_dir()
    assert not displaced.exists()


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows handle-relative replacement")
def test_windows_native_handle_relative_replace_preserves_destination_guard(tmp_path):
    root = tmp_path / "state"

    with archive_module.AnchoredDirectory(root) as output_tree:
        candidate_stream, candidate_identity = output_tree.create_file((".candidate",))
        with candidate_stream:
            candidate_stream.write(b"candidate")
        current_stream, current_identity = output_tree.create_file(("current",))
        with current_stream:
            current_stream.write(b"current")

        outcome = output_tree.replace(
            (".candidate",),
            ("current",),
            expected_identity=candidate_identity,
            expected_destination_identity=current_identity,
        )

    assert outcome == "unsupported"
    assert not (root / ".candidate").exists()
    assert (root / "current").read_bytes() == b"candidate"


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows handle-relative no-replace")
def test_windows_native_handle_relative_no_replace_preserves_both_entries(tmp_path):
    root = tmp_path / "state"

    with archive_module.AnchoredDirectory(root) as output_tree:
        candidate_stream, candidate_identity = output_tree.create_file((".candidate",))
        with candidate_stream:
            candidate_stream.write(b"candidate")
        current_stream, _ = output_tree.create_file(("current",))
        with current_stream:
            current_stream.write(b"current")

        with pytest.raises(ArchiveError, match="destination already exists"):
            output_tree.replace(
                (".candidate",),
                ("current",),
                expected_identity=candidate_identity,
                replace_existing=False,
            )

    assert (root / ".candidate").read_bytes() == b"candidate"
    assert (root / "current").read_bytes() == b"current"


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows directory publication replacement race")
def test_windows_native_directory_publication_rejects_source_replacement_during_rebind(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "backends"
    staging = root / "mihomo" / ".1.0.0.install-operation"
    displaced = root / "mihomo" / ".displaced"
    original_open = anchored_module._open_windows_entry
    replaced = []

    with archive_module.AnchoredDirectory(root) as output_tree:
        output_tree.ensure_directory(("mihomo",))
        identity = output_tree.create_directory(("mihomo", staging.name))
        (staging / "payload").write_bytes(b"original")

        def replace_before_pin(path, expected_identity=None):
            if Path(path) == staging and not replaced:
                staging.rename(displaced)
                staging.mkdir()
                (staging / "payload").write_bytes(b"replacement")
                replaced.append(True)
            return original_open(path, expected_identity=expected_identity)

        monkeypatch.setattr(anchored_module, "_open_windows_entry", replace_before_pin)
        with pytest.raises(ArchiveError, match="expected identity"):
            output_tree.replace(
                ("mihomo", staging.name),
                ("mihomo", "1.0.0"),
                expected_identity=identity,
                replace_existing=False,
            )

    assert replaced == [True]
    assert (displaced / "payload").read_bytes() == b"original"
    assert (staging / "payload").read_bytes() == b"replacement"
    assert not (root / "mihomo" / "1.0.0").exists()


def test_anchored_directory_creates_and_verifies_a_relative_symlink(tmp_path):
    destination = tmp_path / "output"
    target = "../backends/mihomo/1.0.0/mihomo"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        identity = output_tree.create_symlink(("mihomo",), target)

    link = destination / "mihomo"
    assert link.is_symlink()
    assert os.readlink(str(link)) == target
    assert identity["file_type"] == "symlink"


def test_anchored_directory_closes_its_root_when_expected_identity_recheck_fails(
    tmp_path,
    monkeypatch,
):
    destination = tmp_path / "output"
    destination.mkdir(mode=0o700)
    identity = anchored_module.capture_identity(destination)
    original_matches = anchored_module.identity_matches
    original_open = anchored_module.os.open
    original_close = anchored_module.os.close
    calls = []
    root_descriptors = []
    closed = []

    def record_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == destination:
            root_descriptors.append(descriptor)
        return descriptor

    def record_close(descriptor):
        closed.append(descriptor)
        return original_close(descriptor)

    def fail_after_root_is_pinned(path, expected):
        calls.append(Path(path))
        if len(calls) == 2:
            raise IntegrityError("simulated expected identity failure")
        return original_matches(path, expected)

    output_tree = archive_module.AnchoredDirectory(destination, expected_identity=identity)
    monkeypatch.setattr(anchored_module, "identity_matches", fail_after_root_is_pinned)
    monkeypatch.setattr(anchored_module.os, "open", record_open)
    monkeypatch.setattr(anchored_module.os, "close", record_close)

    with pytest.raises(ArchiveError, match="changed while being pinned"):
        output_tree.__enter__()

    assert calls == [destination, destination]
    assert len(root_descriptors) == 1
    assert root_descriptors[0] in closed


def test_anchored_directory_replaces_one_verified_relative_entry(tmp_path):
    destination = tmp_path / "output"
    candidate = destination / ".candidate"
    public = destination / "mihomo.json"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        with output_tree.open_file((candidate.name,)) as stream:
            stream.write(b"candidate")
        identity = output_tree.identity((candidate.name,))
        public.write_bytes(b"previous")
        outcome = output_tree.replace(
            (candidate.name,),
            (public.name,),
            expected_identity=identity,
        )
        published_identity = output_tree.identity((public.name,))

    assert outcome in ("flushed", "unsupported")
    assert not candidate.exists()
    assert public.read_bytes() == b"candidate"
    assert published_identity == identity


def test_simulated_windows_anchored_replace_stays_on_the_pinned_parent(
    tmp_path,
    monkeypatch,
):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    destination = tmp_path / "output"
    displaced = tmp_path / "displaced-output"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    sentinel = outside / "mihomo.json"
    sentinel.write_bytes(b"outside")
    replaced = []

    def rename_by_handle(source_handle, parent_handle, destination_name, replace_existing):
        del source_handle, replace_existing
        destination.rename(displaced)
        destination.symlink_to(outside, target_is_directory=True)
        replaced.append(True)
        os.replace(
            ".candidate",
            destination_name,
            src_dir_fd=parent_handle,
            dst_dir_fd=parent_handle,
        )

    monkeypatch.setattr(anchored_module, "_rename_windows_handle", rename_by_handle)

    with pytest.raises(ArchiveError, match="root changed"):
        with archive_module.AnchoredDirectory(destination) as output_tree:
            with output_tree.open_file((".candidate",)) as stream:
                stream.write(b"candidate")
            identity = output_tree.identity((".candidate",))
            output_tree.replace(
                (".candidate",),
                ("mihomo.json",),
                expected_identity=identity,
            )

    assert replaced == [True]
    assert sentinel.read_bytes() == b"outside"
    assert (displaced / "mihomo.json").read_bytes() == b"candidate"


def test_simulated_windows_anchored_replace_publishes_a_verified_directory_without_overwrite(
    tmp_path,
    monkeypatch,
):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    root = tmp_path / "backends"

    with archive_module.AnchoredDirectory(root) as output_tree:
        output_tree.ensure_directory(("mihomo",))
        identity = output_tree.create_directory(("mihomo", ".1.0.0.install-operation"))

    def rename_by_handle(source_handle, parent_handle, destination_name, replace_existing):
        del source_handle
        assert replace_existing is False
        os.rename(
            ".1.0.0.install-operation",
            destination_name,
            src_dir_fd=parent_handle,
            dst_dir_fd=parent_handle,
        )

    monkeypatch.setattr(anchored_module, "_rename_windows_handle", rename_by_handle)

    with archive_module.AnchoredDirectory(root) as output_tree:
        outcome = output_tree.replace(
            ("mihomo", ".1.0.0.install-operation"),
            ("mihomo", "1.0.0"),
            expected_identity=identity,
            replace_existing=False,
        )

    assert outcome in ("flushed", "unsupported")
    assert not (root / "mihomo" / ".1.0.0.install-operation").exists()
    assert (root / "mihomo" / "1.0.0").is_dir()


def test_simulated_windows_existing_file_handles_preserve_read_and_write_identity(
    tmp_path,
    monkeypatch,
):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    state = root / "state.json"
    state.write_bytes(b"initial")
    state.chmod(0o600)

    with archive_module.AnchoredDirectory(root) as anchored:
        stream, read_identity = anchored.open_existing_file((state.name,))
        with stream:
            assert stream.read() == b"initial"

        stream, write_identity = anchored.open_existing_file((state.name,), writable=True)
        with stream:
            stream.seek(0, os.SEEK_END)
            stream.write(b" updated")

    assert read_identity == write_identity
    assert state.read_bytes() == b"initial updated"


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("open", "unable to open anchored regular file"),
        ("information", "unable to identify archive output handle"),
        ("directory", "not a regular file"),
        ("links", "not a private regular file"),
        ("identity", "changed while being opened"),
    ),
)
def test_simulated_windows_existing_file_handles_reject_untrusted_evidence(
    tmp_path,
    monkeypatch,
    failure,
    message,
):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    state = root / "state.json"
    state.write_bytes(b"initial")
    state.chmod(0o600)

    class FailingExistingFileKernel(SimulatedArchiveWindowsKernel):
        def CreateFileW(self, path, access, share, security, creation, flags, template):
            if failure == "open" and Path(path) == state:
                return anchored_module._WINDOWS_INVALID_HANDLE_VALUE
            return super(FailingExistingFileKernel, self).CreateFileW(
                path,
                access,
                share,
                security,
                creation,
                flags,
                template,
            )

        def GetFileInformationByHandle(self, handle, information_pointer):
            if failure == "information" and self.handles[handle] == state:
                return False
            result = super(FailingExistingFileKernel, self).GetFileInformationByHandle(
                handle,
                information_pointer,
            )
            if self.handles[handle] == state:
                information = information_pointer._obj
                if failure == "directory":
                    information.file_attributes |= anchored_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                elif failure == "links":
                    information.number_of_links = 2
            return result

    kernel = FailingExistingFileKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    if failure == "identity":
        original_lstat = Path.lstat

        def changed_lstat(path):
            status = original_lstat(path)
            if path != state:
                return status
            values = list(status)
            values[1] += 1
            return os.stat_result(values)

        monkeypatch.setattr(Path, "lstat", changed_lstat)

    with archive_module.AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match=message):
            anchored.open_existing_file((state.name,))


def test_simulated_windows_file_evidence_flush_opens_a_writable_native_handle(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    state = root / "state.json"
    state.write_bytes(b"state")
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with archive_module.AnchoredDirectory(root) as anchored:
        size, digest, identity = anchored.file_evidence((state.name,), flush=True)

    file_calls = [call for call in kernel.calls if call[0] == state]
    assert len(file_calls) == 1
    assert file_calls[0][1] & anchored_module._WINDOWS_GENERIC_WRITE
    assert size == 5
    assert digest == hashlib.sha256(b"state").hexdigest()
    assert identity["file_type"] == "regular"


def test_simulated_windows_handle_rename_replaces_only_the_pinned_destination(
    tmp_path,
    monkeypatch,
):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    root = tmp_path / "root"

    with archive_module.AnchoredDirectory(root) as anchored:
        candidate_stream, candidate_identity = anchored.create_file((".candidate",))
        with candidate_stream:
            candidate_stream.write(b"candidate")
        public_stream, public_identity = anchored.create_file(("public",))
        with public_stream:
            public_stream.write(b"previous")

        outcome = anchored.replace(
            (".candidate",),
            ("public",),
            expected_identity=candidate_identity,
            replace_existing=True,
            expected_destination_identity=public_identity,
        )

    assert outcome in ("flushed", "unsupported")
    assert len(kernel.rename_roots) == 1
    assert kernel.rename_roots[0] is not None
    assert kernel.rename_classes == [anchored_module._WINDOWS_FILE_RENAME_INFORMATION_EX_CLASS]
    assert kernel.rename_flags == [
        anchored_module._WINDOWS_FILE_RENAME_REPLACE_IF_EXISTS
        | anchored_module._WINDOWS_FILE_RENAME_POSIX_SEMANTICS
    ]
    assert not (root / ".candidate").exists()
    assert (root / "public").read_bytes() == b"candidate"


def test_simulated_windows_cross_directory_rename_uses_the_destination_guard(
    tmp_path,
    monkeypatch,
):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    root = tmp_path / "root"

    with archive_module.AnchoredDirectory(root) as anchored:
        anchored.ensure_directory(("source",))
        anchored.ensure_directory(("destination",))
        candidate_stream, candidate_identity = anchored.create_file(("source", "candidate"))
        with candidate_stream:
            candidate_stream.write(b"candidate")

        anchored.replace(
            ("source", "candidate"),
            ("destination", "published"),
            expected_identity=candidate_identity,
        )

    assert len(kernel.rename_roots) == 1
    assert kernel.rename_roots[0] is not None
    assert kernel.rename_classes == [anchored_module._WINDOWS_FILE_RENAME_INFORMATION_EX_CLASS]
    assert kernel.rename_flags == [
        anchored_module._WINDOWS_FILE_RENAME_REPLACE_IF_EXISTS
        | anchored_module._WINDOWS_FILE_RENAME_POSIX_SEMANTICS
    ]
    assert not (root / "source" / "candidate").exists()
    assert (root / "destination" / "published").read_bytes() == b"candidate"


def test_simulated_windows_handle_rename_releases_directory_guards_and_never_overwrites(
    tmp_path,
    monkeypatch,
):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    root = tmp_path / "root"

    with archive_module.AnchoredDirectory(root) as anchored:
        anchored.ensure_directory(("backend",))
        identity = anchored.create_directory(("backend", ".staging"))
        anchored.ensure_directory(("backend", ".staging", "nested"))
        source_root = root / "backend" / ".staging"
        source_guards = {
            handle for handle, path in kernel.handles.items() if path == source_root or source_root in path.parents
        }

        anchored.replace(
            ("backend", ".staging"),
            ("backend", "1.0.0"),
            expected_identity=identity,
            replace_existing=False,
        )
        assert source_guards.issubset(set(kernel.closed_handles))

        second_identity = anchored.create_directory(("backend", ".second"))
        with pytest.raises(ArchiveError, match="destination already exists"):
            anchored.replace(
                ("backend", ".second"),
                ("backend", "1.0.0"),
                expected_identity=second_identity,
                replace_existing=False,
            )

    assert (root / "backend" / "1.0.0").is_dir()
    assert (root / "backend" / ".second").is_dir()
    assert kernel.rename_classes == [
        anchored_module._WINDOWS_FILE_RENAME_INFORMATION_CLASS,
        anchored_module._WINDOWS_FILE_RENAME_INFORMATION_CLASS,
    ]
    assert kernel.rename_flags == [0, 0]


def test_windows_archive_output_rejects_reparse_returned_handle(tmp_path, monkeypatch):
    kernel = SimulatedArchiveWindowsKernel(reparse_names=("xray",))
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    destination = tmp_path / "output"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        with pytest.raises(ArchiveError, match="reparse"):
            output_tree.open_file(("xray",))


def test_windows_directory_identity_uses_exact_legacy_fallback(tmp_path, monkeypatch):
    kernel = SimulatedArchiveWindowsKernel(modern_failure="unsupported")
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with archive_module.AnchoredDirectory(tmp_path / "output") as output_tree:
        output_tree.ensure_directory(("bin",))

    assert kernel.handles == {}
    assert set(kernel.closed_handles) == {
        handle for handle, creation in kernel.opened_handles if creation == anchored_module._WINDOWS_OPEN_EXISTING
    }


@pytest.mark.parametrize(
    ("modern_failure", "message"),
    (
        ("denied", "unable to identify archive output directory"),
        ("zero", "no stable modern identity"),
    ),
)
def test_windows_directory_identity_failures_close_the_guard(
    tmp_path,
    monkeypatch,
    modern_failure,
    message,
):
    kernel = SimulatedArchiveWindowsKernel(modern_failure=modern_failure)
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match=message):
        with archive_module.AnchoredDirectory(tmp_path / "output"):
            pass

    assert set(kernel.closed_handles) == {
        handle for handle, creation in kernel.opened_handles if creation == anchored_module._WINDOWS_OPEN_EXISTING
    }


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("open", "unable to pin archive output directory"),
        ("information", "unable to identify archive output handle"),
        ("not-directory", "not a directory"),
        ("reparse", "reparse point"),
        ("legacy-zero", "no stable identity"),
        ("identity-mismatch", "handle identity does not match"),
    ),
)
def test_windows_directory_guard_rejects_untrusted_native_evidence(
    tmp_path,
    monkeypatch,
    failure,
    message,
):
    class FailingDirectoryKernel(SimulatedArchiveWindowsKernel):
        def CreateFileW(self, path, access, share, security, creation, flags, template):
            if failure == "open" and creation == anchored_module._WINDOWS_OPEN_EXISTING:
                return anchored_module._WINDOWS_INVALID_HANDLE_VALUE
            return super(FailingDirectoryKernel, self).CreateFileW(
                path, access, share, security, creation, flags, template
            )

        def GetFileInformationByHandle(self, handle, information_pointer):
            if failure == "information":
                return False
            result = super(FailingDirectoryKernel, self).GetFileInformationByHandle(handle, information_pointer)
            information = information_pointer._obj
            if failure == "not-directory":
                information.file_attributes &= ~anchored_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY
            elif failure == "reparse":
                information.file_attributes |= anchored_module._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            elif failure == "legacy-zero":
                information.volume_serial_number = 0
            elif failure == "identity-mismatch":
                information.volume_serial_number += 1
                information.file_index_low += 1
            return result

        def GetFileInformationByHandleEx(self, handle, information_class, information_pointer, size):
            result = super(FailingDirectoryKernel, self).GetFileInformationByHandleEx(
                handle, information_class, information_pointer, size
            )
            if failure == "identity-mismatch":
                information_pointer._obj.volume_serial_number += 1
                information_pointer._obj.file_id.identifier[0] ^= 1
            return result

    kernel = FailingDirectoryKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match=message):
        with archive_module.AnchoredDirectory(tmp_path / "output"):
            pass

    assert set(kernel.closed_handles) == {
        handle for handle, creation in kernel.opened_handles if creation == anchored_module._WINDOWS_OPEN_EXISTING
    }


def test_windows_directory_guard_accepts_exact_legacy_api_without_extended_binding(tmp_path, monkeypatch):
    kernel = SimulatedArchiveWindowsKernel()
    kernel.GetFileInformationByHandleEx = None
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with archive_module.AnchoredDirectory(tmp_path / "output") as output_tree:
        output_tree.ensure_directory(("bin",))


def test_windows_directory_guard_reports_close_failure_after_releasing_all_handles(tmp_path, monkeypatch):
    class CloseFailureKernel(SimulatedArchiveWindowsKernel):
        def CloseHandle(self, handle):
            super(CloseFailureKernel, self).CloseHandle(handle)
            return False

    kernel = CloseFailureKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match="unable to close archive output handle"):
        with archive_module.AnchoredDirectory(tmp_path / "output") as output_tree:
            output_tree.ensure_directory(("bin",))

    assert len(kernel.closed_handles) == 2


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("open", "unable to exclusively create"),
        ("directory", "handle is a directory"),
        ("nonprivate", "not a private empty file"),
        ("identity", "changed while being created"),
    ),
)
def test_windows_file_guard_rejects_untrusted_native_evidence(
    tmp_path,
    monkeypatch,
    failure,
    message,
):
    class FailingFileKernel(SimulatedArchiveWindowsKernel):
        def CreateFileW(self, path, access, share, security, creation, flags, template):
            if failure == "open" and creation == anchored_module._WINDOWS_CREATE_NEW:
                return anchored_module._WINDOWS_INVALID_HANDLE_VALUE
            return super(FailingFileKernel, self).CreateFileW(path, access, share, security, creation, flags, template)

        def GetFileInformationByHandle(self, handle, information_pointer):
            result = super(FailingFileKernel, self).GetFileInformationByHandle(handle, information_pointer)
            if self.handles[handle].name == "xray":
                information = information_pointer._obj
                if failure == "directory":
                    information.file_attributes |= anchored_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                elif failure == "nonprivate":
                    information.number_of_links = 2
            return result

    kernel = FailingFileKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    if failure == "identity":
        original_lstat = Path.lstat

        def changed_lstat(path):
            status = original_lstat(path)
            if path.name != "xray":
                return status
            values = list(status)
            values[1] += 1
            return os.stat_result(values)

        monkeypatch.setattr(Path, "lstat", changed_lstat)

    with archive_module.AnchoredDirectory(tmp_path / "output") as output_tree:
        with pytest.raises(ArchiveError, match=message):
            output_tree.open_file(("xray",))


def test_windows_root_guard_detects_disappearance_after_pinning(tmp_path, monkeypatch):
    kernel = SimulatedArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)
    destination = tmp_path / "output"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        original_lstat = Path.lstat

        def missing_root(path):
            if path == destination:
                raise FileNotFoundError("simulated disappearance")
            return original_lstat(path)

        monkeypatch.setattr(Path, "lstat", missing_root)
        with pytest.raises(ArchiveError, match="root became unavailable"):
            output_tree.ensure_directory(("bin",))


@pytest.mark.parametrize("replacement_scope", ("root", "nested"))
def test_windows_directory_pin_rejects_plain_directory_replacement_between_lstat_and_open(
    tmp_path,
    monkeypatch,
    replacement_scope,
):
    destination = tmp_path / "output"
    displaced = tmp_path / ("displaced-" + replacement_scope)
    replacement = tmp_path / ("replacement-" + replacement_scope)
    replacement.mkdir(mode=0o700)

    class ReplacingArchiveWindowsKernel(SimulatedArchiveWindowsKernel):
        def __init__(self):
            super(ReplacingArchiveWindowsKernel, self).__init__()
            self.replaced = False

        def CreateFileW(self, path, access, share, security, creation, flags, template):
            native = Path(path)
            selected = destination if replacement_scope == "root" else destination / "bin"
            if creation == anchored_module._WINDOWS_OPEN_EXISTING and native == selected and not self.replaced:
                native.rename(displaced)
                replacement.rename(native)
                self.replaced = True
            return super(ReplacingArchiveWindowsKernel, self).CreateFileW(
                path,
                access,
                share,
                security,
                creation,
                flags,
                template,
            )

    kernel = ReplacingArchiveWindowsKernel()
    configure_simulated_windows_archive_creation(monkeypatch, kernel)

    with pytest.raises(ArchiveError, match="changed while being pinned"):
        with archive_module.AnchoredDirectory(destination) as output_tree:
            output_tree.ensure_directory(("bin",))

    assert kernel.replaced
    assert set(kernel.closed_handles) == {
        handle for handle, creation in kernel.opened_handles if creation == anchored_module._WINDOWS_OPEN_EXISTING
    }


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes are not portable")
def test_zip_extraction_ignores_archive_permissions_and_creates_private_objects(tmp_path):
    archive = tmp_path / "xray.zip"
    directory = zipfile.ZipInfo("bin/")
    directory.create_system = 3
    directory.external_attr = (stat.S_IFDIR | 0o777) << 16
    executable = zipfile.ZipInfo("bin/xray")
    executable.create_system = 3
    executable.external_attr = (stat.S_IFREG | 0o777) << 16
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(directory, b"")
        stream.writestr(executable, b"backend")

    destination = tmp_path / "output"
    extract_archive(archive, destination, "xray")

    assert stat.S_IMODE((destination / "bin").stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "bin" / "xray").stat().st_mode) == 0o600


def test_portable_archive_output_fallback_creates_validates_and_normalizes(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    destination = tmp_path / "portable-output"

    with archive_module.AnchoredDirectory(destination) as output_tree:
        output_tree.ensure_directory(("bin",))
        with output_tree.open_file(("bin", "upstream-name")) as stream:
            stream.write(b"backend")
        output_tree.validate(
            {
                ("bin",): ("directory", 0),
                ("bin", "upstream-name"): ("file", len(b"backend")),
            }
        )
        selected = output_tree.prepare_executable("upstream-name", "jerryproxy-core")

    executable = destination.joinpath(*selected)
    assert executable.read_bytes() == b"backend"
    assert not (destination / "bin" / "upstream-name").exists()
    if os.name == "posix":
        assert stat.S_IMODE(executable.stat().st_mode) == 0o755


def test_anchored_output_rejects_empty_file_path_and_wrong_final_plan(tmp_path):
    destination = tmp_path / "output"
    with archive_module.AnchoredDirectory(destination) as output_tree:
        with pytest.raises(ArchiveError, match="empty path"):
            output_tree.open_file(())
        with output_tree.open_file(("xray",)) as stream:
            stream.write(b"backend")
        with pytest.raises(ArchiveError, match="does not match"):
            output_tree.validate({("xray",): ("file", 1)})


def test_anchored_output_rejects_an_existing_regular_root(tmp_path):
    destination = tmp_path / "output"
    destination.write_bytes(b"sentinel")

    with pytest.raises(ArchiveError, match="not a safe directory"):
        with archive_module.AnchoredDirectory(destination):
            pass

    assert destination.read_bytes() == b"sentinel"


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics require POSIX")
def test_anchored_output_rejects_an_existing_root_alias(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    destination = tmp_path / "output"
    destination.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ArchiveError, match="root is a path alias"):
        with archive_module.AnchoredDirectory(destination):
            pass


@pytest.mark.parametrize("failure", ("mkdir", "lstat"))
def test_anchored_output_maps_root_acquisition_failures(tmp_path, monkeypatch, failure):
    destination = tmp_path / "output"
    original_mkdir = Path.mkdir
    original_lstat = Path.lstat

    def guarded_mkdir(path, *args, **kwargs):
        if failure == "mkdir" and path == destination:
            raise PermissionError("simulated root creation denial")
        return original_mkdir(path, *args, **kwargs)

    def guarded_lstat(path):
        if failure == "lstat" and path == destination:
            raise PermissionError("simulated root observation denial")
        return original_lstat(path)

    monkeypatch.setattr(Path, "mkdir", guarded_mkdir)
    monkeypatch.setattr(Path, "lstat", guarded_lstat)

    with pytest.raises(ArchiveError, match="unable to (create|inspect) archive output root"):
        with archive_module.AnchoredDirectory(destination):
            pass


@pytest.mark.skipif(os.name != "posix", reason="descriptor pinning requires POSIX")
@pytest.mark.parametrize("failure", ("open", "identity"))
def test_anchored_output_rejects_root_descriptor_acquisition_races(tmp_path, monkeypatch, failure):
    destination = tmp_path / "output"
    destination.mkdir(mode=0o700)
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    output_tree = archive_module.AnchoredDirectory(destination)
    original_open = anchored_module.os.open
    original_fstat = anchored_module.os.fstat

    def guarded_open(path, *args, **kwargs):
        if failure == "open" and Path(path) == destination:
            raise PermissionError("simulated descriptor denial")
        return original_open(path, *args, **kwargs)

    def guarded_fstat(descriptor):
        if failure == "identity":
            return replacement.stat()
        return original_fstat(descriptor)

    monkeypatch.setattr(anchored_module.os, "open", guarded_open)
    monkeypatch.setattr(anchored_module.os, "fstat", guarded_fstat)

    with pytest.raises(ArchiveError, match="unable to pin|changed while being pinned"):
        with output_tree:
            pass


@pytest.mark.parametrize("failure", ("missing", "identity"))
def test_portable_output_revalidates_its_root_before_each_operation(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    destination = tmp_path / "portable-output"
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)

    with archive_module.AnchoredDirectory(destination) as output_tree:
        original_lstat = Path.lstat

        def changed_lstat(path):
            if path == destination:
                if failure == "missing":
                    raise FileNotFoundError("simulated root disappearance")
                return replacement.stat()
            return original_lstat(path)

        monkeypatch.setattr(Path, "lstat", changed_lstat)
        with pytest.raises(ArchiveError, match="root (became unavailable|changed during extraction)"):
            output_tree.ensure_directory(("bin",))


@pytest.mark.parametrize("failure", ("inspect", "non-directory", "permissions"))
def test_portable_output_rejects_unsafe_existing_ancestors(tmp_path, monkeypatch, failure):
    if failure == "permissions" and os.name != "posix":
        pytest.skip("portable fallback permission enforcement is POSIX-specific")
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    destination = tmp_path / "portable-output"
    destination.mkdir(mode=0o700)
    ancestor = destination / "bin"
    if failure == "non-directory":
        ancestor.write_bytes(b"sentinel")
    else:
        ancestor.mkdir(mode=0o755 if failure == "permissions" else 0o700)

    with archive_module.AnchoredDirectory(destination) as output_tree:
        if failure == "inspect":
            original_lstat = Path.lstat

            def denied_lstat(path):
                if path == ancestor:
                    raise PermissionError("simulated ancestor observation denial")
                return original_lstat(path)

            monkeypatch.setattr(Path, "lstat", denied_lstat)
        message = "unable to inspect|alias or non-directory|unsafe permissions"
        with pytest.raises(ArchiveError, match=message):
            output_tree.ensure_directory(("bin",))


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative creation requires POSIX")
@pytest.mark.parametrize("failure", ("open", "type"))
def test_posix_output_rejects_leaf_creation_failures(tmp_path, monkeypatch, failure):
    destination = tmp_path / "output"
    output_tree = archive_module.AnchoredDirectory(destination)
    captured = []
    original_open = anchored_module.os.open
    original_fstat = anchored_module.os.fstat

    def guarded_open(path, *args, **kwargs):
        if path == "xray" and kwargs.get("dir_fd") is not None:
            if failure == "open":
                raise PermissionError("simulated leaf creation denial")
            descriptor = original_open(path, *args, **kwargs)
            captured.append(descriptor)
            return descriptor
        return original_open(path, *args, **kwargs)

    def guarded_fstat(descriptor):
        status = original_fstat(descriptor)
        if failure == "type" and captured and descriptor == captured[0]:
            values = list(status)
            values[0] = stat.S_IFDIR | 0o700
            return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.os, "open", guarded_open)
    monkeypatch.setattr(anchored_module.os, "fstat", guarded_fstat)
    with output_tree:
        with pytest.raises(ArchiveError, match="unable to create|not a private regular file"):
            output_tree.open_file(("xray",))


@pytest.mark.parametrize("failure", ("exists", "identity"))
def test_portable_output_rejects_leaf_conflicts_and_identity_races(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    destination = tmp_path / "portable-output"
    destination.mkdir(mode=0o700)
    target = destination / "xray"
    if failure == "exists":
        target.write_bytes(b"sentinel")

    with archive_module.AnchoredDirectory(destination) as output_tree:
        if failure == "identity":
            original_lstat = Path.lstat

            def changed_lstat(path):
                status = original_lstat(path)
                if path == target:
                    values = list(status)
                    values[1] += 1
                    return os.stat_result(values)
                return status

            monkeypatch.setattr(Path, "lstat", changed_lstat)
        with pytest.raises(ArchiveError, match="already exists|changed while being created"):
            output_tree.open_file(("xray",))


def test_executable_selection_requires_exactly_one_matching_leaf(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir(mode=0o700)
    with pytest.raises(ArchiveError, match="found 0"):
        find_executable(empty, "xray")

    duplicate = tmp_path / "duplicate"
    for directory in (duplicate / "one", duplicate / "two"):
        directory.mkdir(parents=True, mode=0o700)
        executable = directory / "xray"
        executable.write_bytes(b"backend")
        executable.chmod(0o600)
    with pytest.raises(ArchiveError, match="found 2"):
        find_executable(duplicate, "xray")


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative normalization requires POSIX")
@pytest.mark.parametrize("failure", ("destination", "chmod"))
def test_posix_executable_normalization_fails_closed(tmp_path, monkeypatch, failure):
    root = tmp_path / "output"
    root.mkdir(mode=0o700)
    source = root / "upstream"
    source.write_bytes(b"backend")
    source.chmod(0o600)
    if failure == "destination":
        destination = root / "normalized"
        destination.write_bytes(b"existing")
        destination.chmod(0o600)
    else:
        original_fchmod = anchored_module.os.fchmod

        def denied_fchmod(descriptor, mode):
            if mode == 0o755:
                raise PermissionError("simulated mode normalization denial")
            return original_fchmod(descriptor, mode)

        monkeypatch.setattr(anchored_module.os, "fchmod", denied_fchmod)

    with pytest.raises(ArchiveError, match="destination already exists|unable to prepare"):
        find_executable(root, "upstream", "normalized")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions are required")
def test_anchored_output_rejects_unsafe_existing_directory_and_file_modes(tmp_path):
    directory_root = tmp_path / "directory-output"
    directory_root.mkdir(mode=0o700)
    (directory_root / "bin").mkdir(mode=0o755)
    with archive_module.AnchoredDirectory(directory_root) as output_tree:
        with pytest.raises(ArchiveError, match="unsafe permissions"):
            output_tree.ensure_directory(("bin",))

    file_root = tmp_path / "file-output"
    file_root.mkdir(mode=0o700)
    executable = file_root / "xray"
    executable.write_bytes(b"backend")
    executable.chmod(0o644)
    with archive_module.AnchoredDirectory(file_root) as output_tree:
        with pytest.raises(ArchiveError, match="unsafe permissions"):
            output_tree.validate({("xray",): ("file", len(b"backend"))})


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative validation requires POSIX")
def test_anchored_output_maps_root_and_final_scan_observation_failures(tmp_path, monkeypatch):
    destination = tmp_path / "output"
    destination.mkdir(mode=0o700)
    executable = destination / "xray"
    executable.write_bytes(b"backend")
    executable.chmod(0o600)

    with archive_module.AnchoredDirectory(destination) as output_tree:
        original_fstat = anchored_module.os.fstat

        def denied_fstat(descriptor):
            if descriptor == output_tree._descriptor:
                raise PermissionError("simulated root inspection denial")
            return original_fstat(descriptor)

        monkeypatch.setattr(anchored_module.os, "fstat", denied_fstat)
        with pytest.raises(ArchiveError, match="root became unavailable"):
            output_tree.validate({("xray",): ("file", len(b"backend"))})

    monkeypatch.undo()
    with archive_module.AnchoredDirectory(destination) as output_tree:
        original_stat = anchored_module.os.stat

        def denied_stat(path, *args, **kwargs):
            if path == "xray" and kwargs.get("dir_fd") is not None:
                raise PermissionError("simulated member inspection denial")
            return original_stat(path, *args, **kwargs)

        monkeypatch.setattr(anchored_module.os, "stat", denied_stat)
        with pytest.raises(ArchiveError, match="unable to inspect extracted archive object"):
            output_tree.validate({("xray",): ("file", len(b"backend"))})


def test_portable_output_maps_listing_and_leaf_creation_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    destination = tmp_path / "portable-output"
    with archive_module.AnchoredDirectory(destination) as output_tree:
        original_open = anchored_module.os.open

        def denied_open(path, *args, **kwargs):
            if Path(path).name == "xray":
                raise PermissionError("simulated leaf creation denial")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(anchored_module.os, "open", denied_open)
        with pytest.raises(ArchiveError, match="unable to create archive output file"):
            output_tree.open_file(("xray",))

    monkeypatch.undo()
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    destination.mkdir(mode=0o700, exist_ok=True)
    with archive_module.AnchoredDirectory(destination) as output_tree:
        original_iterdir = Path.iterdir

        def denied_iterdir(path):
            if path == destination:
                raise PermissionError("simulated listing denial")
            return original_iterdir(path)

        monkeypatch.setattr(Path, "iterdir", denied_iterdir)
        with pytest.raises(ArchiveError, match="unable to inspect extracted archive directory"):
            output_tree.validate({})


def test_portable_executable_normalization_rejects_conflict_and_rename_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(anchored_module, "_WINDOWS_KERNEL32", None)
    monkeypatch.setattr(anchored_module.os, "supports_dir_fd", set())
    conflict_root = tmp_path / "conflict-output"
    conflict_root.mkdir(mode=0o700)
    (conflict_root / "upstream").write_bytes(b"backend")
    (conflict_root / "normalized").write_bytes(b"existing")
    with pytest.raises(ArchiveError, match="destination already exists"):
        find_executable(conflict_root, "upstream", "normalized")

    rename_root = tmp_path / "rename-output"
    rename_root.mkdir(mode=0o700)
    (rename_root / "upstream").write_bytes(b"backend")
    original_rename = anchored_module.os.rename

    def denied_rename(source, target, *args, **kwargs):
        if Path(source).name == "upstream":
            raise PermissionError("simulated rename denial")
        return original_rename(source, target, *args, **kwargs)

    monkeypatch.setattr(anchored_module.os, "rename", denied_rename)
    with pytest.raises(ArchiveError, match="unable to normalize"):
        find_executable(rename_root, "upstream", "normalized")


def test_zip_metadata_failure_does_not_write_earlier_members(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("good", b"first")
        stream.writestr("../escape", b"second")
    destination = tmp_path / "output"

    with pytest.raises(ArchiveError):
        extract_archive(archive, destination, "xray")

    assert not (destination / "good").exists()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative race fixture requires POSIX")
def test_archive_output_root_replacement_is_rejected(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    destination = tmp_path / "output"
    displaced = tmp_path / "displaced"
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    original_open = archive_module.AnchoredDirectory.open_file
    replaced = []

    def replace_root(output_tree, parts):
        if not replaced:
            destination.rename(displaced)
            replacement.rename(destination)
            replaced.append(True)
        return original_open(output_tree, parts)

    monkeypatch.setattr(archive_module.AnchoredDirectory, "open_file", replace_root)
    with pytest.raises(ArchiveError, match="root changed"):
        extract_archive(archive, destination, "xray")

    assert not (destination / "xray").exists()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative race fixture requires POSIX")
def test_archive_output_ancestor_replacement_is_rejected(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/xray", b"backend")
    destination = tmp_path / "output"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    original_open = archive_module.AnchoredDirectory.open_file

    def replace_ancestor(output_tree, parts):
        ancestor = output_tree.root / "bin"
        ancestor.mkdir(mode=0o700)
        ancestor.rmdir()
        ancestor.symlink_to(outside, target_is_directory=True)
        return original_open(output_tree, parts)

    monkeypatch.setattr(archive_module.AnchoredDirectory, "open_file", replace_ancestor)
    with pytest.raises(ArchiveError, match="safe directory"):
        extract_archive(archive, destination, "xray")

    assert not (outside / "xray").exists()


@pytest.mark.skipif(os.name != "posix", reason="hardlink semantics require POSIX")
def test_archive_final_validation_rejects_output_hardlink(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"backend")
    destination = tmp_path / "output"
    hardlink = tmp_path / "hardlink"
    original_copy = archive_module._copy_bounded

    def add_hardlink(source, output, maximum_bytes):
        written = original_copy(source, output, maximum_bytes)
        output.flush()
        os.link(destination / "xray", hardlink)
        return written

    monkeypatch.setattr(archive_module, "_copy_bounded", add_hardlink)
    with pytest.raises(ArchiveError, match="alias or special object"):
        extract_archive(archive, destination, "xray")

    assert hardlink.read_bytes() == b"backend"


@pytest.mark.skipif(os.name != "posix", reason="open-file replacement semantics require POSIX")
def test_archive_final_validation_rejects_same_size_output_replacement(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"trusted!")
    destination = tmp_path / "output"
    displaced = tmp_path / "displaced"
    original_copy = archive_module._copy_bounded

    def replace_completed_output(source, output, maximum_bytes):
        written = original_copy(source, output, maximum_bytes)
        output.flush()
        (destination / "xray").rename(displaced)
        (destination / "xray").write_bytes(b"hostile!")
        (destination / "xray").chmod(0o600)
        return written

    monkeypatch.setattr(archive_module, "_copy_bounded", replace_completed_output)
    with pytest.raises(ArchiveError, match="identity|changed"):
        extract_archive(archive, destination, "xray")

    assert displaced.read_bytes() == b"trusted!"
    assert (destination / "xray").read_bytes() == b"hostile!"


@pytest.mark.skipif(os.name != "posix", reason="open-directory replacement semantics require POSIX")
def test_archive_final_validation_rejects_same_shape_directory_replacement(tmp_path, monkeypatch):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/xray", b"trusted!")
    destination = tmp_path / "output"
    displaced = tmp_path / "displaced-bin"
    original_copy = archive_module._copy_bounded

    def replace_completed_directory(source, output, maximum_bytes):
        written = original_copy(source, output, maximum_bytes)
        output.flush()
        (destination / "bin").rename(displaced)
        (destination / "bin").mkdir(mode=0o700)
        (destination / "bin" / "xray").write_bytes(b"hostile!")
        (destination / "bin" / "xray").chmod(0o600)
        return written

    monkeypatch.setattr(archive_module, "_copy_bounded", replace_completed_directory)
    with pytest.raises(ArchiveError, match="identity|changed"):
        extract_archive(archive, destination, "xray")

    assert (displaced / "xray").read_bytes() == b"trusted!"
    assert (destination / "bin" / "xray").read_bytes() == b"hostile!"


@pytest.mark.skipif(os.name != "posix", reason="open-file replacement semantics require POSIX")
def test_executable_preparation_rejects_replacement_after_tree_validation(tmp_path):
    root = tmp_path / "output"
    displaced = tmp_path / "displaced"
    with anchored_module.AnchoredDirectory(root) as output_tree:
        with output_tree.open_file(("xray",)) as stream:
            stream.write(b"trusted!")
        output_tree.validate({("xray",): ("file", 8)})
        (root / "xray").rename(displaced)
        (root / "xray").write_bytes(b"hostile!")
        (root / "xray").chmod(0o600)

        with pytest.raises(ArchiveError, match="identity|changed"):
            output_tree.prepare_executable("xray")

    assert displaced.read_bytes() == b"trusted!"
    assert (root / "xray").read_bytes() == b"hostile!"


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics require POSIX")
def test_executable_selection_rejects_a_symlink_substitution(tmp_path):
    root = tmp_path / "output"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    outside.chmod(0o600)
    (root / "xray").symlink_to(outside)

    with pytest.raises(ArchiveError, match="alias|executable"):
        find_executable(root, "xray")

    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    assert outside.read_bytes() == b"sentinel"


@pytest.mark.skipif(os.name != "posix", reason="hardlink semantics require POSIX")
def test_executable_selection_rejects_a_hardlink_substitution(tmp_path):
    root = tmp_path / "output"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    outside.chmod(0o600)
    os.link(str(outside), str(root / "xray"))

    with pytest.raises(ArchiveError, match="alias|special object|private regular file|executable"):
        find_executable(root, "xray")

    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    assert outside.read_bytes() == b"sentinel"
