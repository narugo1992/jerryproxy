import ctypes
import os
import stat
from pathlib import Path

import pytest

import jerryproxy.backend.identity as identity_module
from jerryproxy.backend.identity import capture_identity, identity_matches, validate_identity
from jerryproxy.errors import IntegrityError


class SimulatedIdentityWindowsKernel(object):
    def __init__(self, failure=None):
        self.failure = failure
        self.handles = {}
        self.closed = []

    def CreateFileW(self, path, access, share, security, creation, flags, template):
        del access, share, security, creation, flags, template
        if self.failure == "open":
            return identity_module._WINDOWS_INVALID_HANDLE_VALUE
        descriptor = os.open(str(Path(path)), os.O_RDONLY)
        self.handles[descriptor] = Path(path)
        return descriptor

    def GetFileInformationByHandle(self, handle, information_pointer):
        if self.failure == "information":
            return False
        status = os.fstat(handle)
        information = information_pointer._obj
        is_directory = stat.S_ISDIR(status.st_mode)
        if self.failure == "type":
            is_directory = not is_directory
        information.file_attributes = identity_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY if is_directory else 0
        if self.failure == "reparse":
            information.file_attributes |= identity_module._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        information.volume_serial_number = int(status.st_dev) & 0xFFFFFFFF
        file_id = 0 if self.failure == "legacy-zero" else int(status.st_ino)
        if self.failure == "all-mismatch":
            file_id += 1
        information.file_index_high = (file_id >> 32) & 0xFFFFFFFF
        information.file_index_low = file_id & 0xFFFFFFFF
        return True

    def GetFileInformationByHandleEx(self, handle, information_class, information_pointer, size):
        del information_class, size
        if self.failure in ("modern-unsupported", "modern-denied"):
            return False
        status = os.fstat(handle)
        information = information_pointer._obj
        information.volume_serial_number = int(status.st_dev)
        file_id = 0 if self.failure == "modern-zero" else int(status.st_ino)
        if self.failure == "all-mismatch":
            file_id += 1
        raw = file_id.to_bytes(16, "little")
        for index, value in enumerate(raw):
            information.file_id.identifier[index] = value
        return True

    def CloseHandle(self, handle):
        os.close(handle)
        self.handles.pop(handle, None)
        self.closed.append(handle)
        return self.failure != "close"


def configure_simulated_windows_identity(monkeypatch, kernel):
    monkeypatch.setattr(identity_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(identity_module, "_windows_extended_path", lambda path: str(path))

    def windows_error():
        error = OSError("simulated Windows identity failure")
        error.winerror = 50 if kernel.failure == "modern-unsupported" else 5
        return error

    monkeypatch.setattr(identity_module, "_windows_error", windows_error)


class RecordingNativeWindowsIdentityKernel(object):
    def __init__(self, kernel, modern_error=None, corrupt_legacy=False):
        self.kernel = kernel
        self.modern_error = modern_error
        self.corrupt_legacy = corrupt_legacy
        self.opened = []
        self.closed = []

    def CreateFileW(self, *args):
        handle = self.kernel.CreateFileW(*args)
        self.opened.append(handle)
        return handle

    def GetFileInformationByHandle(self, handle, information_pointer):
        result = self.kernel.GetFileInformationByHandle(handle, information_pointer)
        if result and self.corrupt_legacy:
            information_pointer._obj.file_index_low ^= 1
        return result

    def GetFileInformationByHandleEx(self, *args):
        if self.modern_error is not None:
            ctypes.set_last_error(self.modern_error)
            return 0
        return self.kernel.GetFileInformationByHandleEx(*args)

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return self.kernel.CloseHandle(handle)


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity shape")
def test_capture_identity_records_stable_posix_directory_and_regular_file_ids(tmp_path):
    directory_identity = capture_identity(tmp_path)
    regular = tmp_path / "payload"
    regular.write_bytes(b"payload")
    regular_identity = capture_identity(regular)

    assert directory_identity == {
        "kind": "posix",
        "device": tmp_path.lstat().st_dev,
        "inode": tmp_path.lstat().st_ino,
        "file_type": "directory",
    }
    assert regular_identity == {
        "kind": "posix",
        "device": regular.lstat().st_dev,
        "inode": regular.lstat().st_ino,
        "file_type": "regular",
    }
    assert identity_matches(tmp_path, directory_identity)
    assert identity_matches(regular, regular_identity)


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "symlink"), reason="POSIX symlink identity")
def test_capture_identity_never_follows_a_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"target")
    link = tmp_path / "link"
    link.symlink_to(target.name)

    identity = capture_identity(link)

    assert identity["file_type"] == "symlink"
    assert identity["inode"] == link.lstat().st_ino
    assert identity["inode"] != target.stat().st_ino


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_capture_identity_rejects_special_files(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(str(fifo))

    with pytest.raises(IntegrityError, match="unsupported file type"):
        capture_identity(fifo)


def test_windows_identity_capture_and_matching_use_modern_and_legacy_ids(tmp_path, monkeypatch):
    kernel = SimulatedIdentityWindowsKernel()
    configure_simulated_windows_identity(monkeypatch, kernel)
    regular = tmp_path / "payload"
    regular.write_bytes(b"payload")

    modern = capture_identity(regular)
    legacy = {
        "kind": "windows-legacy-id",
        "volume_serial": "%08x" % (int(regular.stat().st_dev) & 0xFFFFFFFF),
        "file_id": "%016x" % int(regular.stat().st_ino),
        "file_type": "regular",
    }

    assert modern == {
        "kind": "windows-file-id",
        "volume_serial": "%016x" % int(regular.stat().st_dev),
        "file_id": "%032x" % int(regular.stat().st_ino),
        "file_type": "regular",
    }
    assert identity_matches(regular, modern)
    assert identity_matches(regular, legacy)
    assert not identity_matches(regular, {**modern, "file_id": "f" * 32})
    assert not identity_matches(regular, {**modern, "file_type": "directory"})
    assert kernel.handles == {}
    assert len(kernel.closed) == 4


def test_windows_identity_uses_exact_legacy_fallback(tmp_path, monkeypatch):
    kernel = SimulatedIdentityWindowsKernel("modern-unsupported")
    configure_simulated_windows_identity(monkeypatch, kernel)
    path = tmp_path / "payload"
    path.write_bytes(b"payload")

    identity = capture_identity(path)

    assert identity["kind"] == "windows-legacy-id"
    assert identity_matches(path, identity)
    assert kernel.handles == {}


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows FILE_ID_INFO evidence")
def test_windows_native_identity_uses_file_id_info_and_rejects_same_content_replacement(tmp_path):
    path = tmp_path / "payload"
    path.write_bytes(b"same")

    identity = capture_identity(path)

    assert identity["kind"] == "windows-file-id"
    assert len(identity["volume_serial"]) == 16
    assert len(identity["file_id"]) == 32
    assert identity_matches(path, identity)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"same")
    os.replace(str(replacement), str(path))
    assert not identity_matches(path, identity)


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows legacy identity evidence")
def test_windows_native_exact_legacy_fallback_does_not_downgrade_a_modern_identity(tmp_path, monkeypatch):
    path = tmp_path / "payload"
    path.write_bytes(b"payload")
    modern = capture_identity(path)
    assert modern["kind"] == "windows-file-id"
    kernel = RecordingNativeWindowsIdentityKernel(identity_module._WINDOWS_KERNEL32, modern_error=50)
    monkeypatch.setattr(identity_module, "_WINDOWS_KERNEL32", kernel)

    legacy = capture_identity(path)

    assert legacy["kind"] == "windows-legacy-id"
    assert identity_matches(path, legacy)
    assert not identity_matches(path, modern)
    assert len(kernel.opened) == len(kernel.closed) == 3


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows legacy mismatch evidence")
@pytest.mark.parametrize(
    "modern_error,corrupt_legacy,message",
    (
        (50, True, "changed while identifying"),
        (5, False, "extended managed recovery"),
    ),
)
def test_windows_native_identity_uncertainty_fails_closed_and_closes_handle(
    tmp_path,
    monkeypatch,
    modern_error,
    corrupt_legacy,
    message,
):
    path = tmp_path / "payload"
    path.write_bytes(b"payload")
    kernel = RecordingNativeWindowsIdentityKernel(
        identity_module._WINDOWS_KERNEL32,
        modern_error=modern_error,
        corrupt_legacy=corrupt_legacy,
    )
    monkeypatch.setattr(identity_module, "_WINDOWS_KERNEL32", kernel)

    with pytest.raises(IntegrityError, match=message):
        capture_identity(path)

    assert len(kernel.opened) == len(kernel.closed) == 1


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("open", "unable to pin"),
        ("information", "unable to identify"),
        ("type", "changed type"),
        ("reparse", "reparse state changed"),
        ("legacy-zero", "no stable legacy"),
        ("modern-zero", "no stable modern"),
        ("all-mismatch", "changed while identifying"),
        ("modern-denied", "extended managed recovery"),
        ("close", "unable to close"),
    ),
)
def test_windows_identity_failures_close_handles_and_fail_closed(
    tmp_path,
    monkeypatch,
    failure,
    message,
):
    kernel = SimulatedIdentityWindowsKernel(failure)
    configure_simulated_windows_identity(monkeypatch, kernel)
    path = tmp_path / "payload"
    path.write_bytes(b"payload")

    with pytest.raises(IntegrityError, match=message):
        capture_identity(path)

    assert kernel.handles == {}


def test_identity_capture_rejects_platforms_without_stable_identity(tmp_path, monkeypatch):
    host_os = identity_module.os

    class UnsupportedOsProxy(object):
        name = "unsupported"

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(identity_module, "os", UnsupportedOsProxy())
    monkeypatch.setattr(identity_module, "_WINDOWS_KERNEL32", None)

    with pytest.raises(IntegrityError, match="unsupported on this platform"):
        capture_identity(tmp_path)


def test_identity_capture_preserves_absence_and_maps_inspection_failures(tmp_path, monkeypatch):
    missing = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        capture_identity(missing)

    path = tmp_path / "payload"
    path.write_bytes(b"payload")
    original_lstat = Path.lstat

    def deny_selected(selected):
        if selected == path:
            raise PermissionError("simulated identity inspection denial")
        return original_lstat(selected)

    monkeypatch.setattr(Path, "lstat", deny_selected)
    with pytest.raises(IntegrityError, match="unable to inspect managed recovery object"):
        capture_identity(path)


def test_identity_match_maps_inspection_failures_and_rejects_foreign_shapes(tmp_path, monkeypatch):
    path = tmp_path / "payload"
    path.write_bytes(b"payload")
    posix_identity = capture_identity(path)
    windows_identity = {
        "kind": "windows-file-id",
        "volume_serial": "0" * 16,
        "file_id": "0" * 32,
        "file_type": "regular",
    }
    assert not identity_matches(path, windows_identity)

    kernel = SimulatedIdentityWindowsKernel()
    configure_simulated_windows_identity(monkeypatch, kernel)
    assert not identity_matches(path, posix_identity)

    monkeypatch.setattr(identity_module, "_WINDOWS_KERNEL32", None)
    original_lstat = Path.lstat

    def deny_selected(selected):
        if selected == path:
            raise PermissionError("simulated identity match denial")
        return original_lstat(selected)

    monkeypatch.setattr(Path, "lstat", deny_selected)
    with pytest.raises(IntegrityError, match="unable to inspect managed recovery object"):
        identity_matches(path, posix_identity)


@pytest.mark.skipif(os.name != "posix", reason="POSIX replacement identity")
def test_identity_match_rejects_a_same_content_replacement(tmp_path):
    path = tmp_path / "payload"
    path.write_bytes(b"same")
    identity = capture_identity(path)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"same")
    os.replace(str(replacement), str(path))

    assert not identity_matches(path, identity)
    assert not identity_matches(tmp_path / "missing", identity)


@pytest.mark.parametrize(
    "value,message",
    [
        (None, "object"),
        ({}, "object"),
        ({"kind": "unknown", "file_type": "regular"}, "kind"),
        ({"kind": "posix", "device": 1, "inode": 2}, "keys"),
        ({"kind": "posix", "device": 1, "inode": 2, "file_type": "regular", "extra": 3}, "keys"),
        ({"kind": "posix", "device": True, "inode": 2, "file_type": "regular"}, "device"),
        ({"kind": "posix", "device": -1, "inode": 2, "file_type": "regular"}, "device"),
        (
            {
                "kind": "posix",
                "device": 1 << 64,
                "inode": 2,
                "file_type": "regular",
            },
            "device",
        ),
        ({"kind": "posix", "device": 1, "inode": 2, "file_type": "socket"}, "file type"),
        (
            {
                "kind": "windows-file-id",
                "volume_serial": "1",
                "file_id": "0" * 32,
                "file_type": "regular",
            },
            "volume serial",
        ),
        (
            {
                "kind": "windows-file-id",
                "volume_serial": "0" * 16,
                "file_id": "A" * 32,
                "file_type": "regular",
            },
            "file id",
        ),
        (
            {
                "kind": "windows-file-id",
                "volume_serial": "0" * 16,
                "file_id": "0" * 32,
                "file_type": "regular",
                "extra": True,
            },
            "keys",
        ),
        (
            {
                "kind": "windows-legacy-id",
                "volume_serial": "0" * 8,
                "file_id": "0" * 15,
                "file_type": "regular",
            },
            "file id",
        ),
        (
            {
                "kind": "windows-legacy-id",
                "volume_serial": "0" * 8,
                "file_id": "0" * 16,
                "file_type": "regular",
                "extra": True,
            },
            "keys",
        ),
    ],
)
def test_validate_identity_rejects_noncanonical_or_ambiguous_objects(value, message):
    with pytest.raises(IntegrityError, match=message):
        validate_identity(value)


@pytest.mark.parametrize(
    "value",
    [
        {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"},
        {
            "kind": "windows-file-id",
            "volume_serial": "0000000000000001",
            "file_id": "00000000000000000000000000000002",
            "file_type": "regular",
        },
        {
            "kind": "windows-legacy-id",
            "volume_serial": "00000001",
            "file_id": "0000000000000002",
            "file_type": "symlink",
        },
    ],
)
def test_validate_identity_accepts_each_normative_shape(value):
    assert validate_identity(value) == value


def test_validate_identity_enforces_expected_file_type():
    value = {"kind": "posix", "device": 1, "inode": 2, "file_type": "regular"}
    with pytest.raises(IntegrityError, match="expected directory"):
        validate_identity(value, expected_file_type="directory")
