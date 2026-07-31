import gzip
import hashlib
import io
import multiprocessing
import os
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import jerryproxy.backend.activation as activation_module
import jerryproxy.backend.anchored as anchored_module
import jerryproxy.backend.archive as archive_module
import jerryproxy.backend.durable as durable_module
import jerryproxy.backend.installation as installation_module
import jerryproxy.backend.manager as manager_module
import jerryproxy.backend.removal as removal_module
from jerryproxy.backend.identity import capture_identity
from jerryproxy.backend.manager import BackendManager
from jerryproxy.backend.model import CatalogArtifact, PlatformInfo
from jerryproxy.backend.recovery import recover_backend_transactions
from jerryproxy.errors import (
    ArchiveError,
    BackendActiveError,
    BackendAlreadyInstalledError,
    BackendNotInstalledError,
    CleanupScopeError,
    DurabilityError,
    IntegrityError,
    JerryProxyBusyError,
    RemovalCleanupError,
    UnsupportedPlatformError,
)
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock
from jerryproxy.utils.fs import MAXIMUM_JSON_BYTES, atomic_write_json, read_json


def make_gzip_archive(path, payload):
    with gzip.open(str(path), "wb") as stream:
        stream.write(payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_backend_archive(path, archive_type, payload):
    if archive_type == "gzip":
        return make_gzip_archive(path, payload)
    if archive_type == "zip":
        with zipfile.ZipFile(str(path), "w", compression=zipfile.ZIP_STORED) as stream:
            stream.writestr("mihomo", payload)
    else:
        with tarfile.open(str(path), "w:gz") as stream:
            member = tarfile.TarInfo("mihomo")
            member.size = len(payload)
            stream.addfile(member, io.BytesIO(payload))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_windows_mihomo_zip(path, payload):
    with zipfile.ZipFile(str(path), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("license-before.txt", b"first")
        stream.writestr("mihomo.exe", payload)
        stream.writestr("license-after.txt", b"last")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manager_for(tmp_path):
    return BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )


def removal_journal_move(
    manager,
    transaction,
    source,
    destination_name="download-0",
    kind="download",
    mode=None,
):
    status = source.lstat() if os.path.lexists(str(source)) else None
    default_types = {
        "download": "directory",
        "installed": "directory",
        "active-link": "symlink",
        "active-manifest": "regular",
    }
    if status is not None:
        identity = capture_identity(source)
    else:
        identity = capture_identity(transaction)
        identity = dict(identity)
        identity["file_type"] = default_types[kind]
    if mode is not None:
        identity = dict(identity)
        identity["file_type"] = {
            stat.S_IFDIR: "directory",
            stat.S_IFREG: "regular",
            stat.S_IFLNK: "symlink",
        }.get(mode, "invalid")
    return {
        "kind": kind,
        "source": str(source.relative_to(manager.paths.root)).replace(os.sep, "/"),
        "destination": "runtimes/%s/%s" % (transaction.name, destination_name),
        "identity": identity,
    }


def create_windows_junction(link, target):
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
        text=True,
    )


def unlink_windows_identity_guard_path(guard):
    ctypes = removal_module.ctypes
    file_disposition_info_ex = 21
    file_disposition_delete = 0x00000001
    file_disposition_posix_semantics = 0x00000002
    kernel = removal_module._WINDOWS_KERNEL32
    handle = kernel.CreateFileW(
        removal_module._windows_extended_path(guard.path),
        removal_module._WINDOWS_DELETE | removal_module._WINDOWS_FILE_READ_ATTRIBUTES,
        (
            removal_module._WINDOWS_FILE_SHARE_READ
            | removal_module._WINDOWS_FILE_SHARE_WRITE
            | removal_module._WINDOWS_FILE_SHARE_DELETE
        ),
        None,
        removal_module._WINDOWS_OPEN_EXISTING,
        (removal_module._WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | removal_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT),
        None,
    )
    if handle == removal_module._WINDOWS_INVALID_HANDLE_VALUE:
        raise removal_module._windows_error()
    disposition = ctypes.c_uint32(file_disposition_delete | file_disposition_posix_semantics)
    if not removal_module._WINDOWS_KERNEL32.SetFileInformationByHandle(
        handle,
        file_disposition_info_ex,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        cause = removal_module._windows_error()
        kernel.CloseHandle(handle)
        raise cause
    if not kernel.CloseHandle(handle):
        raise removal_module._windows_error()
    assert not os.path.lexists(str(guard.path))


def record_windows_identity_guards(monkeypatch):
    opened = []
    closed = []
    original_open = removal_module._open_windows_identity_guard
    original_close = removal_module._close_windows_guard

    def record_open(*args, **kwargs):
        guard = original_open(*args, **kwargs)
        opened.append(guard)
        return guard

    def record_close(guard):
        try:
            return original_close(guard)
        finally:
            closed.append(guard)

    monkeypatch.setattr(removal_module, "_open_windows_identity_guard", record_open)
    monkeypatch.setattr(removal_module, "_close_windows_guard", record_close)
    return opened, closed


def assert_windows_identity_guards_closed(opened, closed):
    assert opened
    assert len(closed) == len(opened)
    assert set(id(guard) for guard in closed) == set(id(guard) for guard in opened)


class SimulatedWindowsKernel(object):
    """Exercise the Windows handle boundary on non-Windows CI hosts."""

    def __init__(self, failure=None, before_delete=None):
        self.failure = failure
        self.before_delete = before_delete
        self.handles = {}
        self.delete_calls = []
        self.next_handle = 1000

    @staticmethod
    def _native_path(value):
        if value.startswith("\\\\?\\UNC\\"):
            return "//" + value[8:]
        if value.startswith("\\\\?\\"):
            return value[4:]
        return value

    def CreateFileW(self, path, access, share, security, creation, flags, template):
        del access, share, security, creation, flags, template
        if self.failure == "create":
            return removal_module._WINDOWS_INVALID_HANDLE_VALUE
        native_path = self._native_path(path)
        native = Path(native_path)
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = native
        return handle

    def GetFileInformationByHandle(self, handle, information_pointer):
        if self.failure == "information":
            return False
        status = self.handles[handle].lstat()
        information = information_pointer._obj
        file_index = int(status.st_ino)
        if self.failure == "identity":
            file_index = 0
        elif self.failure == "modern-only":
            file_index += 1
        information.file_index_high = (file_index >> 32) & 0xFFFFFFFF
        information.file_index_low = file_index & 0xFFFFFFFF
        volume_serial = int(status.st_dev)
        if self.failure == "modern-only":
            volume_serial += 1
        if self.failure == "parent-volume" and self.handles[handle].is_dir():
            volume_serial += 1
        if self.failure == "target-volume" and not self.handles[handle].is_dir():
            volume_serial += 1
        information.volume_serial_number = volume_serial
        information.number_of_links = int(status.st_nlink) + (1 if self.failure == "links" else 0)
        size = int(status.st_size)
        if self.failure == "size":
            size += 1
        information.file_size_high = (size >> 32) & 0xFFFFFFFF
        information.file_size_low = size & 0xFFFFFFFF
        is_directory = Path(self.handles[handle]).is_dir()
        if self.failure == "type":
            is_directory = not is_directory
        information.file_attributes = removal_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY if is_directory else 0
        return True

    def GetFileInformationByHandleEx(self, handle, information_class, information_pointer, size):
        assert information_class == removal_module._WINDOWS_FILE_ID_INFO_CLASS
        assert size == 24
        if self.failure == "modern-unavailable" or self.failure == "modern-denied":
            return False
        status = self.handles[handle].lstat()
        information = information_pointer._obj
        volume_serial = int(status.st_dev)
        if self.failure == "parent-volume" and self.handles[handle].is_dir():
            volume_serial += 1
        if self.failure == "target-volume" and not self.handles[handle].is_dir():
            volume_serial += 1
        information.volume_serial_number = 0 if self.failure == "modern-zero-volume" else volume_serial
        file_index = 0 if self.failure in ("identity", "modern-zero-id") else int(status.st_ino)
        encoded = file_index.to_bytes(16, "little")
        for index, value in enumerate(encoded):
            information.file_id.identifier[index] = value
        return True

    def SetFileInformationByHandle(self, handle, information_class, disposition_pointer, size):
        assert information_class == removal_module._WINDOWS_FILE_DISPOSITION_INFO_CLASS
        assert size == 1
        assert removal_module.ctypes.sizeof(disposition_pointer._obj) == 1
        assert disposition_pointer._obj.delete_file
        self.delete_calls.append(handle)
        if self.failure == "delete":
            return False
        original_path = self.handles[handle]
        pinned_path = original_path
        if self.before_delete is not None:
            relocated_path = self.before_delete(original_path)
            if relocated_path is not None:
                pinned_path = Path(relocated_path)
        if pinned_path.is_dir():
            pinned_path.rmdir()
        else:
            pinned_path.unlink()
        return True

    def CloseHandle(self, handle):
        self.handles.pop(handle, None)
        return self.failure != "close"


def _crash_after_removal_move(home, move_number):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_move = removal_module._move_no_replace
    moves = []

    def crash_after_move(paths, source, destination, expected_identity, *args, **kwargs):
        result = original_move(paths, source, destination, expected_identity, *args, **kwargs)
        moves.append((source, destination))
        if len(moves) == move_number:
            os._exit(20 + move_number)
        return result

    removal_module._move_no_replace = crash_after_move
    manager.uninstall("mihomo", "1.0.0", deactivate=True)


def _crash_before_removal_commit(home):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os
    write_journal = removal_module._write_removal_journal

    def crash_before_commit(transaction, moves, phase="staging", **kwargs):
        if phase == "committed":
            host_os._exit(27)
        return write_journal(transaction, moves, phase=phase, **kwargs)

    removal_module._write_removal_journal = crash_before_commit
    manager.uninstall("mihomo", "1.0.0", deactivate=True)


def _crash_during_removal_commit_write(home):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os
    write_journal = removal_module._write_removal_journal

    def crash_with_temporary_journal(transaction, moves, phase="staging", **kwargs):
        if phase == "committed":
            temporary = transaction / (".journal.json.tmp-" + "f" * 32)
            temporary.write_bytes(b"partial")
            if os.name == "posix":
                temporary.chmod(0o600)
            host_os._exit(29)
        return write_journal(transaction, moves, phase=phase, **kwargs)

    removal_module._write_removal_journal = crash_with_temporary_journal
    manager.uninstall("mihomo", "1.0.0", deactivate=True)


def _crash_after_removal_commit(home):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os

    def crash_before_disposal(paths, transaction, platform_info=None, record=None):
        host_os._exit(28)

    removal_module._dispose_removal_transaction = crash_before_disposal
    manager.uninstall("mihomo", "1.0.0", deactivate=True)


def _crash_removal_committed_journal(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_flush = anchored_module.flush_descriptor
    original_path_replace = anchored_module.os.replace
    original_replace = anchored_module.AnchoredDirectory.replace

    def crash_after_file_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "file-flushed" and kind == "anchored JSON file":
            os._exit(105)
        return result

    def crash_after_path_replace(source, destination, *args, **kwargs):
        result = original_path_replace(source, destination, *args, **kwargs)
        if crash_point == "replaced-before-parent-flush" and Path(destination).name == "journal.json":
            os._exit(106)
        return result

    def crash_after_parent_flush(anchored, source_parts, destination_parts, *args, **kwargs):
        result = original_replace(
            anchored,
            source_parts,
            destination_parts,
            *args,
            **kwargs,
        )
        if crash_point == "parent-flushed" and tuple(destination_parts) == ("journal.json",):
            os._exit(107)
        return result

    anchored_module.flush_descriptor = crash_after_file_flush
    anchored_module.os.replace = crash_after_path_replace
    anchored_module.AnchoredDirectory.replace = crash_after_parent_flush
    manager.uninstall("mihomo", "1.0.0", deactivate=True)


def _crash_initial_removal_journal(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_write = removal_module._write_removal_journal
    original_durable_write = removal_module.durable_write_json

    if crash_point == "before-temporary":

        def crash_before_temporary(transaction, moves, phase="staging", write_id=None):
            os._exit(101)

        removal_module._write_removal_journal = crash_before_temporary
    else:

        def crash_durable_publication(path, value, temporary):
            if value["phase"] != "staging":
                return original_durable_write(path, value, temporary)
            if crash_point == "writer-file-flushed":

                def flush_file_and_exit(descriptor):
                    durable_module.flush_descriptor(descriptor, "regular file")
                    os._exit(102)

                return original_durable_write(
                    path,
                    value,
                    temporary,
                    flush_file=flush_file_and_exit,
                )
            if crash_point == "journal-replaced":

                def replace_and_exit(source, destination):
                    os.replace(source, destination)
                    os._exit(103)

                return original_durable_write(
                    path,
                    value,
                    temporary,
                    replace=replace_and_exit,
                )

            def flush_parent_and_exit(parent):
                durable_module.flush_directory(parent)
                os._exit(104)

            return original_durable_write(
                path,
                value,
                temporary,
                flush_directory=flush_parent_and_exit,
            )

        removal_module.durable_write_json = crash_durable_publication
        removal_module._write_removal_journal = original_write

    manager.uninstall("mihomo", "1.0.0", deactivate=True)


def _crash_removal_recovery(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_move = removal_module._move_no_replace
    original_remove = removal_module._secure_remove_tree
    original_remove_empty = removal_module._secure_remove_empty_directory
    original_anchored_flush = anchored_module.flush_descriptor
    restoring = []

    def crash_after_restore(paths, source, destination, expected_identity, *args, **kwargs):
        restoring.append(True)
        try:
            result = original_move(paths, source, destination, expected_identity, *args, **kwargs)
        finally:
            restoring.pop()
        if crash_point == "rollback-move" and kwargs.get("description") == "removal recovery":
            os._exit(111)
        return result

    def crash_during_restore_flush(descriptor, kind):
        if (
            restoring
            and crash_point == "rollback-replaced-before-flush"
            and kind == "anchored publication source directory"
        ):
            os._exit(115)
        if (
            restoring
            and crash_point == "rollback-destination-before-flush"
            and kind == "anchored publication destination directory"
        ):
            os._exit(116)
        return original_anchored_flush(descriptor, kind)

    def crash_after_remove(root, target, *args, **kwargs):
        result = original_remove(root, target, *args, **kwargs)
        target = Path(target)
        if crash_point == "payload-deleted" and target.name.startswith("installed-"):
            os._exit(112)
        if crash_point == "journal-deleted" and target.name == "journal.json":
            os._exit(113)
        return result

    def crash_after_transaction_remove(root, target, *args, **kwargs):
        result = original_remove_empty(root, target, *args, **kwargs)
        if crash_point == "transaction-deleted" and Path(target).name.startswith(".remove-"):
            os._exit(114)
        return result

    removal_module._move_no_replace = crash_after_restore
    removal_module._secure_remove_tree = crash_after_remove
    removal_module._secure_remove_empty_directory = crash_after_transaction_remove
    anchored_module.flush_descriptor = crash_during_restore_flush
    manager.current("mihomo")


def _crash_removal_transaction_creation(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_flush = anchored_module.flush_descriptor

    def crash_after_creation_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "transaction-child-flushed" and kind == "anchored created directory":
            os._exit(131)
        if crash_point == "transaction-parent-flushed" and kind == "anchored directory parent":
            os._exit(132)
        return result

    anchored_module.flush_descriptor = crash_after_creation_flush
    manager.uninstall("mihomo", "1.0.0")


def _crash_runtime_clean_after_recovery(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_remove = removal_module._secure_remove_tree

    def crash_around_runtime_delete(root, target, *args, **kwargs):
        target = Path(target)
        if target.name == "runtime.json" and crash_point == "before-runtime-delete":
            os._exit(121)
        result = original_remove(root, target, *args, **kwargs)
        if target.name == "runtime.json" and crash_point == "after-runtime-delete":
            os._exit(122)
        return result

    removal_module._secure_remove_tree = crash_around_runtime_delete
    manager.clean(areas=("runtimes",))


def _crash_activation(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_write = activation_module._write_activation_record
    original_replace = activation_module.durable_replace
    original_symlink = activation_module.os.symlink
    original_open_candidate = activation_module._open_regular_candidate
    original_flush = activation_module.flush_descriptor
    original_anchored_flush = anchored_module.flush_descriptor
    original_path_replace = anchored_module.os.replace
    original_classify = activation_module.classify_activation
    replacements = []
    manifest_bytes = {"written": 0, "expected": None}
    phase_exit_codes = {
        "prepared": 41,
        "link-ready": 45,
        "manifest-building": 46,
        "candidates-ready": 47,
        "link-published": 48,
        "manifest-published": 49,
        "committed": 43,
    }

    def crash_after_journal(paths, journal, value, write_id, *args, **kwargs):
        result = original_write(paths, journal, value, write_id, *args, **kwargs)
        manifest = value["candidates"]["manifest"]
        if (
            crash_point == "manifest-identity"
            and value["phase"] == "manifest-building"
            and manifest["state"] == "building"
            and manifest["identity"] is not None
        ):
            os._exit(78)
        if crash_point == value["phase"]:
            os._exit(phase_exit_codes[crash_point])
        return result

    def crash_after_replace(source, destination, *args, **kwargs):
        result = original_replace(source, destination, *args, **kwargs)
        replacements.append(destination)
        if crash_point == "link-replaced" and len(replacements) == 1:
            os._exit(42)
        if crash_point == "manifest-replaced" and len(replacements) == 2:
            os._exit(50)
        return result

    def crash_after_symlink(*args, **kwargs):
        result = original_symlink(*args, **kwargs)
        if crash_point == "symlink-created":
            os._exit(55)
        return result

    def crash_after_empty_candidate(path):
        stream, identity = original_open_candidate(path)
        if crash_point == "manifest-empty":
            os._exit(56)
        journal = read_json(next(manager.paths.runtimes.glob(".use-*.json")))
        expected = activation_module._canonical_bytes(journal["target"]["manifest_payload"])
        manifest_bytes["expected"] = len(expected)

        class CrashAfterWrite(object):
            def __getattr__(self, name):
                return getattr(stream, name)

            def __enter__(self):
                stream.__enter__()
                return self

            def __exit__(self, exception_type, exception, traceback):
                return stream.__exit__(exception_type, exception, traceback)

            def write(self, payload):
                written = stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
                previous = manifest_bytes["written"]
                manifest_bytes["written"] += written
                current = manifest_bytes["written"]
                expected_size = manifest_bytes["expected"]
                if crash_point == "manifest-first-chunk" and previous == 0:
                    os._exit(75)
                if crash_point == "manifest-middle-chunk" and previous < expected_size // 2 <= current < expected_size:
                    os._exit(76)
                if crash_point == "manifest-last-chunk" and current == expected_size:
                    os._exit(77)
                return written

        return CrashAfterWrite(), identity

    def crash_after_candidate_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "manifest-empty-file-flushed" and kind == "empty activation candidate":
            os._exit(65)
        if crash_point == "manifest-written" and kind == "activation candidate":
            os._exit(57)
        return result

    def crash_after_anchored_flush(descriptor, kind):
        result = original_anchored_flush(descriptor, kind)
        if crash_point == "symlink-parent-flushed" and kind == "anchored symlink parent":
            os._exit(64)
        if crash_point == "manifest-empty-parent-flushed" and kind == "anchored directory":
            os._exit(66)
        return result

    def crash_after_path_replace(source, destination, *args, **kwargs):
        result = original_path_replace(source, destination, *args, **kwargs)
        source_name = Path(source).name
        destination_name = Path(destination).name
        if ".candidate" in source_name:
            if crash_point == "link-replaced-before-parent-flush" and destination_name == "mihomo":
                os._exit(80)
            if crash_point == "manifest-replaced-before-parent-flush" and destination_name == "mihomo.json":
                os._exit(91)
        return result

    def crash_after_pair_validation(paths, value):
        result = original_classify(paths, value)
        if crash_point == "pair-validated" and value["phase"] == "manifest-published":
            os._exit(79)
        return result

    activation_module._COPY_CHUNK_SIZE = 2
    activation_module._write_activation_record = crash_after_journal
    activation_module.durable_replace = crash_after_replace
    activation_module.os.symlink = crash_after_symlink
    activation_module._open_regular_candidate = crash_after_empty_candidate
    activation_module.flush_descriptor = crash_after_candidate_flush
    anchored_module.flush_descriptor = crash_after_anchored_flush
    anchored_module.os.replace = crash_after_path_replace
    activation_module.classify_activation = crash_after_pair_validation
    manager.use("mihomo", "2.0.0")


def _crash_initial_activation_journal(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_create_file = anchored_module.AnchoredDirectory.create_file
    original_flush = anchored_module.flush_descriptor
    original_replace = anchored_module.os.replace
    original_write_record = activation_module._write_activation_record

    def crash_after_temporary_create(anchored, parts):
        result = original_create_file(anchored, parts)
        if (
            crash_point == "writer-temporary-created"
            and anchored.root == manager.paths.runtimes
            and parts[-1].startswith(".use-")
            and ".json.tmp-" in parts[-1]
        ):
            os._exit(71)
        return result

    def crash_after_file_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "writer-file-flushed" and kind == "anchored JSON file":
            os._exit(72)
        return result

    def crash_after_authority_replace(source, destination, *args, **kwargs):
        result = original_replace(source, destination, *args, **kwargs)
        destination_name = Path(destination).name
        if (
            crash_point == "authority-replaced-before-parent-flush"
            and destination_name.startswith(".use-")
            and destination_name.endswith(".json")
            and ".tmp-" not in destination_name
        ):
            os._exit(73)
        return result

    def crash_after_parent_flush(paths, journal, value, write_id, *args, **kwargs):
        result = original_write_record(paths, journal, value, write_id, *args, **kwargs)
        if crash_point == "authority-parent-flushed" and value["phase"] == "prepared":
            os._exit(74)
        return result

    anchored_module.AnchoredDirectory.create_file = crash_after_temporary_create
    anchored_module.flush_descriptor = crash_after_file_flush
    anchored_module.os.replace = crash_after_authority_replace
    activation_module._write_activation_record = crash_after_parent_flush
    manager.use("mihomo", "2.0.0")


def _crash_windows_copy_activation(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    paths = manager.paths
    original_write = activation_module._write_activation_record
    original_create_file = anchored_module.AnchoredDirectory.create_file
    original_open_candidate = activation_module._open_regular_candidate
    original_flush = activation_module.flush_descriptor
    original_anchored_directory_flush = anchored_module.AnchoredDirectory.flush
    original_rename = anchored_module._rename_windows_handle
    original_replace = activation_module.durable_replace
    write_counts = {"link": 0, "manifest": 0}
    bytes_written = {"link": 0, "manifest": 0}
    expected_sizes = {
        "link": (paths.backends / "mihomo" / "2.0.0" / "mihomo.exe").stat().st_size,
        "manifest": None,
    }
    flush_counts = []
    empty_flush_counts = []

    class CrashAfterWrite(object):
        def __init__(self, stream, name):
            self.stream = stream
            self.name = name

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback):
            return self.stream.__exit__(exception_type, exception, traceback)

        def write(self, payload):
            written = self.stream.write(payload)
            write_counts[self.name] += 1
            self.stream.flush()
            os.fsync(self.stream.fileno())
            previous = bytes_written[self.name]
            bytes_written[self.name] += written
            expected = expected_sizes[self.name]
            selected = []
            if previous == 0:
                selected.append(("%s-first-chunk" % self.name, 134 if self.name == "link" else 142))
            if previous < expected // 2 <= bytes_written[self.name] < expected:
                selected.append(("%s-middle-chunk" % self.name, 135 if self.name == "link" else 152))
            if bytes_written[self.name] == expected:
                selected.append(("%s-last-chunk" % self.name, 136 if self.name == "link" else 153))
            for selected_point, exit_code in selected:
                if crash_point == selected_point:
                    os._exit(exit_code)
            return written

    def unavailable_symlink(*args, **kwargs):
        del args, kwargs
        raise OSError("forced Windows copy fallback")

    def crash_after_journal(paths_value, journal, value, write_id, *args, **kwargs):
        result = original_write(paths_value, journal, value, write_id, *args, **kwargs)
        phase = value["phase"]
        link_identity = value["candidates"]["link"]["identity"]
        manifest_identity = value["candidates"]["manifest"]["identity"]
        if value["target"]["manifest_payload"] is not None:
            expected_sizes["manifest"] = len(activation_module._canonical_bytes(value["target"]["manifest_payload"]))
        selected = None
        if crash_point == "prepared" and phase == "prepared":
            selected = 130
        elif crash_point == "link-building" and phase == "link-building" and link_identity is None:
            selected = 131
        elif crash_point == "link-identity" and phase == "link-building" and link_identity is not None:
            selected = 133
        elif crash_point == "link-ready" and phase == "link-ready":
            selected = 138
        elif crash_point == "manifest-building" and phase == "manifest-building" and manifest_identity is None:
            selected = 139
        elif crash_point == "manifest-identity" and phase == "manifest-building" and manifest_identity is not None:
            selected = 141
        elif crash_point == "candidates-ready" and phase == "candidates-ready":
            selected = 144
        elif crash_point == "link-published" and phase == "link-published":
            selected = 147
        elif crash_point == "manifest-published" and phase == "manifest-published":
            selected = 150
        elif crash_point == "committed" and phase == "committed":
            selected = 151
        if selected is not None:
            os._exit(selected)
        return result

    def crash_after_empty_create(anchored, parts):
        result = original_create_file(anchored, parts)
        if anchored.root == paths.bin and crash_point == "link-empty-created":
            os._exit(132)
        if anchored.root == paths.active and crash_point == "manifest-empty-created":
            os._exit(140)
        return result

    def wrap_candidate(path):
        stream, identity = original_open_candidate(path)
        name = "link" if Path(path).parent == paths.bin else "manifest"
        return CrashAfterWrite(stream, name), identity

    def crash_after_candidate_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if kind == "empty activation candidate":
            empty_flush_counts.append(kind)
            if crash_point == "link-empty-file-flushed" and len(empty_flush_counts) == 1:
                os._exit(157)
            if crash_point == "manifest-empty-file-flushed" and len(empty_flush_counts) == 2:
                os._exit(159)
        if kind == "activation candidate":
            flush_counts.append(kind)
            if crash_point == "link-flushed" and len(flush_counts) == 1:
                os._exit(137)
            if crash_point == "manifest-flushed" and len(flush_counts) == 2:
                os._exit(143)
        return result

    def crash_after_empty_parent_flush(anchored):
        result = original_anchored_directory_flush(anchored)
        if anchored.root == paths.bin and crash_point == "link-empty-parent-flushed":
            os._exit(158)
        if anchored.root == paths.active and crash_point == "manifest-empty-parent-flushed":
            os._exit(160)
        return result

    def crash_after_native_rename(source_handle, parent_handle, destination_name, replace_existing):
        result = original_rename(source_handle, parent_handle, destination_name, replace_existing)
        if crash_point == "link-replaced-before-parent-flush" and destination_name == "mihomo.exe":
            os._exit(145)
        if crash_point == "manifest-replaced-before-parent-flush" and destination_name == "mihomo.json":
            os._exit(148)
        return result

    def crash_after_parent_flush(source, destination, *args, **kwargs):
        result = original_replace(source, destination, *args, **kwargs)
        destination_name = Path(destination).name
        if crash_point == "link-parent-flushed" and destination_name == "mihomo.exe":
            os._exit(146)
        if crash_point == "manifest-parent-flushed" and destination_name == "mihomo.json":
            os._exit(149)
        return result

    activation_module._COPY_CHUNK_SIZE = 2
    activation_module._create_symlink_candidate = unavailable_symlink
    activation_module._write_activation_record = crash_after_journal
    anchored_module.AnchoredDirectory.create_file = crash_after_empty_create
    activation_module._open_regular_candidate = wrap_candidate
    activation_module.flush_descriptor = crash_after_candidate_flush
    anchored_module.AnchoredDirectory.flush = crash_after_empty_parent_flush
    anchored_module._rename_windows_handle = crash_after_native_rename
    activation_module.durable_replace = crash_after_parent_flush
    manager.use("mihomo", "2.0.0")


def _assert_windows_partial_candidate(paths, crash_point):
    name = "link" if crash_point.startswith("link-") else "manifest"
    journal = read_json(next(paths.runtimes.glob(".use-*.json")))
    candidate = paths.root / journal["candidates"][name]["path"]
    expected_identity = journal["candidates"][name]["identity"]
    assert expected_identity is not None
    assert capture_identity(candidate) == expected_identity
    if name == "link":
        expected = (paths.backends / "mihomo" / "2.0.0" / "mihomo.exe").read_bytes()
    else:
        expected = activation_module._canonical_bytes(journal["target"]["manifest_payload"])
    actual = candidate.read_bytes()
    assert actual == expected[: len(actual)]
    if crash_point.endswith("first-chunk"):
        assert 0 < len(actual) < len(expected) // 2
    elif crash_point.endswith("middle-chunk"):
        assert len(expected) // 2 <= len(actual) < len(expected)
    else:
        assert actual == expected


def _crash_activation_recovery_after_step(home, selected_step, platform_name="linux"):
    platform_info = (
        PlatformInfo("windows", "amd64", None)
        if platform_name == "windows"
        else PlatformInfo("linux", "amd64", "glibc")
    )
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )
    original_execute = activation_module._execute_recovery_plan
    steps = []

    def crash_after_step(paths, record, plan, platform_info, write_id):
        original_execute(paths, record, plan, platform_info, write_id)
        steps.append((plan.action, plan.object_name))
        if len(steps) == selected_step:
            os._exit(60 + selected_step)

    activation_module._execute_recovery_plan = crash_after_step
    manager.current("mihomo")


def _crash_inside_activation_recovery(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    original_symlink = activation_module.os.symlink
    original_replace = activation_module.durable_replace
    original_remove = activation_module._secure_remove_tree
    original_create_file = anchored_module.AnchoredDirectory.create_file
    original_open_candidate = activation_module._open_regular_candidate
    original_candidate_flush = activation_module.flush_descriptor
    original_anchored_directory_flush = anchored_module.AnchoredDirectory.flush
    original_write_record = activation_module._write_activation_record
    original_anchored_replace = anchored_module.AnchoredDirectory.replace
    original_flush = anchored_module.flush_descriptor
    original_path_replace = anchored_module.os.replace
    original_flush_directory = activation_module.flush_directory
    expected_payload = {"value": None}
    bytes_written = {"value": 0}
    active_candidate = {"name": None}
    removed = {"kind": None, "name": None}

    class CrashAfterRecoveryWrite(object):
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback):
            return self.stream.__exit__(exception_type, exception, traceback)

        def write(self, payload):
            written = self.stream.write(payload)
            self.stream.flush()
            os.fsync(self.stream.fileno())
            previous = bytes_written["value"]
            bytes_written["value"] += written
            current = bytes_written["value"]
            expected_size = len(expected_payload["value"])
            if crash_point == "manifest-first-chunk" and previous == 0:
                os._exit(96)
            if crash_point == "manifest-middle-chunk" and previous < expected_size // 2 <= current < expected_size:
                os._exit(97)
            if crash_point == "manifest-last-chunk" and current == expected_size:
                os._exit(98)
            return written

    def crash_after_symlink(*args, **kwargs):
        result = original_symlink(*args, **kwargs)
        if crash_point == "symlink-created":
            os._exit(81)
        return result

    def crash_after_replace(source, destination, *args, **kwargs):
        result = original_replace(source, destination, *args, **kwargs)
        if crash_point == "manifest-repair-parent-flushed" and Path(destination).name == "mihomo.json":
            os._exit(103)
        if crash_point == "repair-replaced":
            os._exit(82)
        return result

    def crash_after_empty_create(anchored, parts):
        result = original_create_file(anchored, parts)
        if anchored.root == manager.paths.active:
            active_candidate["name"] = "manifest"
            if crash_point == "manifest-empty-created":
                os._exit(92)
        return result

    def wrap_candidate(path):
        stream, identity = original_open_candidate(path)
        journal = read_json(next(manager.paths.runtimes.glob(".use-*.json")))
        direction = journal["recovery"]["direction"]
        logical = journal["previous"] if direction == "rollback-previous" else journal["target"]
        expected_payload["value"] = activation_module._canonical_bytes(logical["manifest_payload"])
        active_candidate["name"] = "manifest"
        return CrashAfterRecoveryWrite(stream), identity

    def crash_after_candidate_flush(descriptor, kind):
        result = original_candidate_flush(descriptor, kind)
        if active_candidate["name"] == "manifest":
            if crash_point == "manifest-empty-file-flushed" and kind == "empty activation candidate":
                os._exit(93)
            if crash_point == "manifest-file-flushed" and kind == "activation candidate":
                os._exit(100)
        return result

    def crash_after_empty_parent_flush(anchored):
        result = original_anchored_directory_flush(anchored)
        if anchored.root == manager.paths.active and crash_point == "manifest-empty-parent-flushed":
            os._exit(94)
        return result

    def crash_after_journal(paths, journal, value, write_id, *args, **kwargs):
        result = original_write_record(paths, journal, value, write_id, *args, **kwargs)
        candidate = value["candidates"]["manifest"]
        if candidate["purpose"] in ("recovery-previous", "recovery-target"):
            if (
                crash_point == "manifest-identity-recorded"
                and candidate["state"] == "building"
                and candidate["identity"] is not None
            ):
                os._exit(95)
            if crash_point == "manifest-ready-recorded" and candidate["state"] == "ready":
                os._exit(101)
        return result

    def crash_after_remove(root, target, *args, **kwargs):
        result = original_remove(root, target, *args, **kwargs)
        target = Path(target)
        if ".candidate" in target.name:
            removed.update({"kind": "candidate", "name": target.name})
            if crash_point == "candidate-deleted":
                os._exit(83)
        if target.parent in (manager.paths.bin, manager.paths.active) and ".candidate" not in target.name:
            removed.update({"kind": "public", "name": target.name})
            if crash_point == "public-deleted":
                os._exit(88)
            if crash_point == "manifest-public-deleted" and target.name == "mihomo.json":
                os._exit(106)
        if target.parent == manager.paths.runtimes and target.name.startswith(".use-") and ".tmp-" not in target.name:
            removed.update({"kind": "journal", "name": target.name})
            if crash_point == "journal-deleted":
                os._exit(84)
        return result

    def crash_after_remove_parent_flush(path):
        result = original_flush_directory(path)
        if crash_point == "candidate-delete-parent-flushed" and removed["kind"] == "candidate":
            os._exit(104)
        if crash_point == "journal-delete-parent-flushed" and removed["kind"] == "journal":
            os._exit(105)
        if crash_point == "public-delete-parent-flushed" and removed["kind"] == "public":
            os._exit(90)
        if (
            crash_point == "manifest-public-delete-parent-flushed"
            and removed["kind"] == "public"
            and removed["name"] == "mihomo.json"
        ):
            os._exit(107)
        return result

    def crash_after_file_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "journal-file-flushed" and kind == "anchored JSON file":
            os._exit(85)
        return result

    def crash_after_path_replace(source, destination, *args, **kwargs):
        result = original_path_replace(source, destination, *args, **kwargs)
        source_name = Path(source).name
        destination_name = Path(destination).name
        if (
            crash_point == "journal-replaced-before-parent-flush"
            and destination_name.startswith(".use-")
            and ".tmp-" not in destination_name
        ):
            os._exit(86)
        if (
            crash_point == "repair-replaced-before-parent-flush"
            and ".candidate" in source_name
            and destination_name in ("mihomo", "mihomo.json")
        ):
            os._exit(89)
        if (
            crash_point == "manifest-repair-replaced-before-parent-flush"
            and ".candidate" in source_name
            and destination_name == "mihomo.json"
        ):
            os._exit(102)
        return result

    def crash_after_anchored_replace(anchored, source_parts, destination_parts, *args, **kwargs):
        result = original_anchored_replace(
            anchored,
            source_parts,
            destination_parts,
            *args,
            **kwargs,
        )
        if (
            crash_point == "journal-parent-flushed"
            and destination_parts[-1].startswith(".use-")
            and ".tmp-" not in destination_parts[-1]
        ):
            os._exit(87)
        return result

    activation_module._COPY_CHUNK_SIZE = 2
    activation_module.os.symlink = crash_after_symlink
    activation_module.durable_replace = crash_after_replace
    activation_module._secure_remove_tree = crash_after_remove
    anchored_module.AnchoredDirectory.create_file = crash_after_empty_create
    activation_module._open_regular_candidate = wrap_candidate
    activation_module.flush_descriptor = crash_after_candidate_flush
    anchored_module.AnchoredDirectory.flush = crash_after_empty_parent_flush
    activation_module._write_activation_record = crash_after_journal
    anchored_module.flush_descriptor = crash_after_file_flush
    anchored_module.os.replace = crash_after_path_replace
    anchored_module.AnchoredDirectory.replace = crash_after_anchored_replace
    activation_module.flush_directory = crash_after_remove_parent_flush
    manager.current("mihomo")


def _crash_inside_windows_activation_recovery(home, crash_point):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    paths = manager.paths
    original_create_file = anchored_module.AnchoredDirectory.create_file
    original_open_candidate = activation_module._open_regular_candidate
    original_candidate_flush = activation_module.flush_descriptor
    original_anchored_flush = anchored_module.AnchoredDirectory.flush
    original_write_record = activation_module._write_activation_record
    original_native_rename = anchored_module._rename_windows_handle
    original_anchored_replace = anchored_module.AnchoredDirectory.replace
    original_replace = activation_module.durable_replace
    original_remove = activation_module._secure_remove_tree
    original_flush_directory = activation_module.flush_directory
    expected_payloads = {}
    bytes_written = {"link": 0, "manifest": 0}
    active_candidate = {"name": None}
    removed_kind = {"value": None}

    class CrashAfterRecoveryWrite(object):
        def __init__(self, stream, name):
            self.stream = stream
            self.name = name

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback):
            return self.stream.__exit__(exception_type, exception, traceback)

        def write(self, payload):
            written = self.stream.write(payload)
            self.stream.flush()
            os.fsync(self.stream.fileno())
            previous = bytes_written[self.name]
            bytes_written[self.name] += written
            expected = expected_payloads[self.name]
            selected = []
            if previous == 0:
                selected.append(("%s-first-chunk" % self.name, 171 if self.name == "link" else 181))
            if previous < len(expected) // 2 <= bytes_written[self.name] < len(expected):
                selected.append(("%s-middle-chunk" % self.name, 172 if self.name == "link" else 182))
            if bytes_written[self.name] == len(expected):
                selected.append(("%s-last-chunk" % self.name, 173 if self.name == "link" else 183))
            for selected_point, exit_code in selected:
                if crash_point == selected_point:
                    os._exit(exit_code)
            return written

    def crash_after_empty_create(anchored, parts):
        result = original_create_file(anchored, parts)
        if anchored.root == paths.bin:
            active_candidate["name"] = "link"
            if crash_point == "link-empty-created":
                os._exit(167)
        if anchored.root == paths.active:
            active_candidate["name"] = "manifest"
            if crash_point == "manifest-empty-created":
                os._exit(177)
        return result

    def wrap_candidate(path):
        stream, identity = original_open_candidate(path)
        name = "link" if Path(path).parent == paths.bin else "manifest"
        active_candidate["name"] = name
        journal = read_json(next(paths.runtimes.glob(".use-*.json")))
        direction = journal["recovery"]["direction"]
        logical = journal["previous"] if direction == "rollback-previous" else journal["target"]
        if name == "link":
            expected_payloads[name] = (paths.root / logical["executable"]).read_bytes()
        else:
            expected_payloads[name] = activation_module._canonical_bytes(logical["manifest_payload"])
        return CrashAfterRecoveryWrite(stream, name), identity

    def crash_after_candidate_flush(descriptor, kind):
        result = original_candidate_flush(descriptor, kind)
        if kind == "empty activation candidate":
            name = active_candidate["name"]
            if crash_point == "%s-empty-file-flushed" % name:
                os._exit(168 if name == "link" else 178)
        if kind == "activation candidate":
            name = active_candidate["name"]
            if crash_point == "%s-flushed" % name:
                os._exit(174 if name == "link" else 184)
        return result

    def crash_after_empty_parent_flush(anchored):
        result = original_anchored_flush(anchored)
        if anchored.root == paths.bin and crash_point == "link-empty-parent-flushed":
            os._exit(169)
        if anchored.root == paths.active and crash_point == "manifest-empty-parent-flushed":
            os._exit(179)
        return result

    def crash_after_journal(paths_value, journal, value, write_id, *args, **kwargs):
        result = original_write_record(paths_value, journal, value, write_id, *args, **kwargs)
        direction = value["recovery"]["direction"] if value["recovery"] is not None else None
        purpose = "recovery-target" if direction == "rollforward-target" else "recovery-previous"
        for name, exit_code in (("link", 170), ("manifest", 180)):
            candidate = value["candidates"][name]
            if (
                crash_point == "%s-identity-recorded" % name
                and candidate["purpose"] == purpose
                and candidate["state"] == "building"
                and candidate["identity"] is not None
            ):
                os._exit(exit_code)
        return result

    def crash_after_native_rename(source_handle, parent_handle, destination_name, replace_existing):
        result = original_native_rename(source_handle, parent_handle, destination_name, replace_existing)
        if crash_point == "repair-replaced-before-parent-flush" and destination_name == "mihomo.exe":
            os._exit(185)
        if (
            crash_point == "journal-replaced-before-parent-flush"
            and destination_name.startswith(".use-")
            and ".tmp-" not in destination_name
        ):
            os._exit(191)
        return result

    def crash_after_repair_parent_flush(source, destination, *args, **kwargs):
        result = original_replace(source, destination, *args, **kwargs)
        if crash_point == "repair-parent-flushed" and Path(destination).name == "mihomo.exe":
            os._exit(186)
        return result

    def crash_after_journal_parent_flush(anchored, source_parts, destination_parts, *args, **kwargs):
        result = original_anchored_replace(
            anchored,
            source_parts,
            destination_parts,
            *args,
            **kwargs,
        )
        destination_name = destination_parts[-1]
        if (
            crash_point == "journal-parent-flushed"
            and anchored.root == paths.runtimes
            and destination_name.startswith(".use-")
            and ".tmp-" not in destination_name
        ):
            os._exit(192)
        return result

    def crash_after_remove(root, target, *args, **kwargs):
        result = original_remove(root, target, *args, **kwargs)
        target = Path(target)
        if ".candidate" in target.name:
            removed_kind["value"] = "candidate"
            if crash_point == "candidate-deleted":
                os._exit(187)
        elif target.parent in (paths.bin, paths.active):
            removed_kind["value"] = "public"
            if crash_point == "public-deleted":
                os._exit(194)
        elif target.parent == paths.runtimes and target.name.startswith(".use-") and ".tmp-" not in target.name:
            removed_kind["value"] = "journal"
            if crash_point == "journal-deleted":
                os._exit(189)
        return result

    def crash_after_remove_parent_flush(path):
        result = original_flush_directory(path)
        if crash_point == "candidate-delete-parent-flushed" and removed_kind["value"] == "candidate":
            os._exit(188)
        if crash_point == "journal-delete-parent-flushed" and removed_kind["value"] == "journal":
            os._exit(190)
        if crash_point == "public-delete-parent-flushed" and removed_kind["value"] == "public":
            os._exit(195)
        return result

    def crash_after_journal_file_flush(descriptor, kind):
        result = original_candidate_flush(descriptor, kind)
        if crash_point == "journal-file-flushed" and kind == "anchored JSON file":
            os._exit(193)
        return result

    activation_module._COPY_CHUNK_SIZE = 2
    anchored_module.AnchoredDirectory.create_file = crash_after_empty_create
    activation_module._open_regular_candidate = wrap_candidate
    activation_module.flush_descriptor = crash_after_candidate_flush
    anchored_module.AnchoredDirectory.flush = crash_after_empty_parent_flush
    activation_module._write_activation_record = crash_after_journal
    anchored_module._rename_windows_handle = crash_after_native_rename
    activation_module.durable_replace = crash_after_repair_parent_flush
    anchored_module.AnchoredDirectory.replace = crash_after_journal_parent_flush
    activation_module._secure_remove_tree = crash_after_remove
    activation_module.flush_directory = crash_after_remove_parent_flush
    anchored_module.flush_descriptor = crash_after_journal_file_flush
    manager.current("mihomo")


def _crash_initial_install_journal(home, archive, digest, crash_point, platform_name="linux"):
    platform_info = (
        PlatformInfo("windows", "amd64", None)
        if platform_name == "windows"
        else PlatformInfo("linux", "amd64", "glibc")
    )
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )
    original_create_file = anchored_module.AnchoredDirectory.create_file
    original_flush = anchored_module.flush_descriptor
    original_path_replace = anchored_module.os.replace
    original_native_rename = anchored_module._rename_windows_handle
    original_write_record = installation_module._write_record

    def crash_after_temporary_create(anchored, parts):
        result = original_create_file(anchored, parts)
        if (
            crash_point == "writer-temporary-created"
            and anchored.root == manager.paths.runtimes
            and parts[-1].startswith(".install-")
            and ".json.tmp-" in parts[-1]
        ):
            os._exit(201)
        return result

    def crash_after_file_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "writer-file-flushed" and kind == "anchored JSON file":
            os._exit(202)
        return result

    def crash_after_path_replace(source, destination, *args, **kwargs):
        result = original_path_replace(source, destination, *args, **kwargs)
        destination_name = Path(destination).name
        if (
            crash_point == "authority-replaced-before-parent-flush"
            and destination_name.startswith(".install-")
            and destination_name.endswith(".json")
            and ".tmp-" not in destination_name
        ):
            os._exit(203)
        return result

    def crash_after_native_rename(source_handle, parent_handle, destination_name, replace_existing):
        result = original_native_rename(source_handle, parent_handle, destination_name, replace_existing)
        if (
            crash_point == "authority-replaced-before-parent-flush"
            and destination_name.startswith(".install-")
            and destination_name.endswith(".json")
            and ".tmp-" not in destination_name
        ):
            os._exit(203)
        return result

    def crash_after_parent_flush(transaction):
        result = original_write_record(transaction)
        if crash_point == "authority-parent-flushed" and transaction.phase == "prepared":
            os._exit(204)
        return result

    anchored_module.AnchoredDirectory.create_file = crash_after_temporary_create
    anchored_module.flush_descriptor = crash_after_file_flush
    anchored_module.os.replace = crash_after_path_replace
    anchored_module._rename_windows_handle = crash_after_native_rename
    installation_module._write_record = crash_after_parent_flush
    manager.install_from_archive(
        "mihomo",
        "1.0.0",
        Path(archive),
        expected_sha256=digest,
        asset_name=(
            "mihomo-windows-amd64-compatible-v1.0.0.zip"
            if platform_name == "windows"
            else "mihomo-linux-amd64-v1.0.0.gz"
        ),
        source_url=(
            "https://example.test/mihomo.zip" if platform_name == "windows" else "https://example.test/mihomo.gz"
        ),
        activate=False,
    )


def _crash_install(home, archive, digest, crash_point, platform_name="linux"):
    platform_info = (
        PlatformInfo("windows", "amd64", None)
        if platform_name == "windows"
        else PlatformInfo("linux", "amd64", "glibc")
    )
    executable_name = "mihomo.exe" if platform_name == "windows" else "mihomo"
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )
    original_write = installation_module._write_record
    original_replace = installation_module.AnchoredDirectory.replace
    original_create_directory = installation_module.AnchoredDirectory.create_directory
    original_create_file = anchored_module.AnchoredDirectory.create_file
    original_manifest_write = anchored_module.AnchoredDirectory.write_json
    original_file_evidence = anchored_module.AnchoredDirectory.file_evidence
    original_anchored_flush = anchored_module.flush_descriptor
    original_path_replace = anchored_module.os.replace
    original_noreplace = anchored_module._rename_posix_noreplace
    original_native_rename = anchored_module._rename_windows_handle
    original_copy = archive_module._copy_bounded
    original_validate_staged = manager_module.validate_staged_installed_manifest_value
    original_mark_validated = installation_module.InstallTransaction.mark_validated
    original_verify_final = installation_module._verify_final
    creating_staging = []
    publishing_final = []
    writing_manifest = []
    extracted_objects = []
    probe_sentinel = Path(home).parent / "probe-called"
    phase_exit_codes = {
        "prepared": 51,
        "extracting-phase": 58,
        "validated": 59,
        "committed": 54,
    }

    def crash_after_journal(transaction):
        original_write(transaction)
        if crash_point in phase_exit_codes and crash_point == transaction.phase:
            os._exit(phase_exit_codes[crash_point])
        if crash_point == "extracting-phase" and transaction.phase == "extracting":
            os._exit(phase_exit_codes[crash_point])

    def crash_after_staging_creation(anchored, parts):
        creating_staging.append(True)
        try:
            identity = original_create_directory(anchored, parts)
        finally:
            creating_staging.pop()
        if crash_point == "staging-created" and ".install-" in parts[-1]:
            os._exit(61)
        return identity

    def crash_after_manifest(anchored, parts, value, temporary_parts, *args, **kwargs):
        is_manifest = parts == ("manifest.json",) and ".install-" in anchored.root.name
        if is_manifest:
            writing_manifest.append(True)
        try:
            result = original_manifest_write(anchored, parts, value, temporary_parts, *args, **kwargs)
        finally:
            if is_manifest:
                writing_manifest.pop()
        if crash_point == "manifest-parent-flushed" and is_manifest:
            os._exit(208)
        if crash_point == "manifest-written" and parts == ("manifest.json",):
            os._exit(62)
        return result

    def crash_after_manifest_temporary_create(anchored, parts):
        result = original_create_file(anchored, parts)
        if (
            crash_point == "manifest-temporary-created"
            and ".install-" in anchored.root.name
            and parts[-1].startswith(".manifest.json.tmp-")
        ):
            os._exit(205)
        return result

    def crash_after_executable_flush(anchored, parts, flush=False, **kwargs):
        result = original_file_evidence(anchored, parts, flush=flush, **kwargs)
        if crash_point == "executable-flushed" and flush and parts[-1] == executable_name:
            os._exit(63)
        return result

    def crash_during_extract(source, destination, maximum_bytes):
        block = source.read(1)
        destination.write(block)
        destination.flush()
        os.fsync(destination.fileno())
        os._exit(52)

    def crash_after_extracted_object(source, destination, maximum_bytes):
        result = original_copy(source, destination, maximum_bytes)
        extracted_objects.append(True)
        selected = {
            "first-extracted-object": (1, 154),
            "middle-extracted-object": (2, 155),
            "last-extracted-object": (3, 156),
        }.get(crash_point)
        if selected is not None and len(extracted_objects) == selected[0]:
            os._exit(selected[1])
        return result

    def crash_after_final_replace(anchored, source_parts, destination_parts, *args, **kwargs):
        if (
            crash_point == "journal-temporary"
            and source_parts[-1].startswith(".install-")
            and ".json.tmp-" in source_parts[-1]
        ):
            os._exit(60)
        is_final = ".install-" in source_parts[-1] and ".json.tmp-" not in source_parts[-1]
        if is_final:
            publishing_final.append(True)
        try:
            result = original_replace(anchored, source_parts, destination_parts, *args, **kwargs)
        finally:
            if is_final:
                publishing_final.pop()
        if ".install-" in source_parts[-1] and ".json.tmp-" not in source_parts[-1]:
            if crash_point == "final-replaced":
                os._exit(53)
            if platform_name == "windows" and crash_point == "final-parent-flushed":
                os._exit(68)
        return result

    def crash_after_native_rename(source_handle, parent_handle, destination_name, replace_existing):
        result = original_native_rename(source_handle, parent_handle, destination_name, replace_existing)
        if (
            writing_manifest
            and crash_point == "manifest-replaced-before-parent-flush"
            and destination_name == "manifest.json"
        ):
            os._exit(207)
        if publishing_final and crash_point == "final-replaced-before-parent-flush":
            os._exit(67)
        return result

    def crash_after_path_replace(source, destination, *args, **kwargs):
        result = original_path_replace(source, destination, *args, **kwargs)
        if (
            writing_manifest
            and crash_point == "manifest-replaced-before-parent-flush"
            and Path(source).name.startswith(".manifest.json.tmp-")
            and Path(destination).name == "manifest.json"
        ):
            os._exit(207)
        return result

    def crash_after_posix_noreplace(source_parent, source_name, destination_parent, destination_name):
        result = original_noreplace(source_parent, source_name, destination_parent, destination_name)
        if (
            writing_manifest
            and crash_point == "manifest-replaced-before-parent-flush"
            and destination_name == "manifest.json"
        ):
            os._exit(207)
        return result

    def crash_at_directory_flush(descriptor, kind):
        if (
            publishing_final
            and crash_point == "final-replaced-before-parent-flush"
            and kind == "anchored publication source directory"
        ):
            os._exit(67)
        result = original_anchored_flush(descriptor, kind)
        if writing_manifest and crash_point == "manifest-file-flushed" and kind == "anchored JSON file":
            os._exit(206)
        if creating_staging and crash_point == "staging-child-flushed" and kind == "anchored created directory":
            os._exit(64)
        if creating_staging and crash_point == "staging-parent-flushed" and kind == "anchored directory parent":
            os._exit(65)
        if crash_point == "tree-root-flushed" and kind == "anchored tree root":
            os._exit(66)
        if (
            publishing_final
            and crash_point == "final-parent-flushed"
            and kind == "anchored publication source directory"
        ):
            os._exit(68)
        return result

    def crash_after_staged_validation(*args, **kwargs):
        result = original_validate_staged(*args, **kwargs)
        if crash_point == "staged-static-validated":
            os._exit(209)
        return result

    def crash_after_probe(installed):
        del installed
        probe_sentinel.write_text("called", encoding="utf-8")
        if crash_point == "probe-returned":
            os._exit(210)

    def crash_before_validated_publication(transaction, publication, staging_anchor=None):
        if crash_point == "post-probe-validated":
            os._exit(211)
        return original_mark_validated(transaction, publication, staging_anchor=staging_anchor)

    def crash_after_final_validation(record):
        result = original_verify_final(record)
        if crash_point == "final-static-validated" and result == "identity":
            os._exit(212)
        return result

    installation_module._write_record = crash_after_journal
    installation_module.AnchoredDirectory.replace = crash_after_final_replace
    installation_module.AnchoredDirectory.create_directory = crash_after_staging_creation
    anchored_module.AnchoredDirectory.create_file = crash_after_manifest_temporary_create
    anchored_module.AnchoredDirectory.write_json = crash_after_manifest
    anchored_module.AnchoredDirectory.file_evidence = crash_after_executable_flush
    anchored_module.flush_descriptor = crash_at_directory_flush
    anchored_module.os.replace = crash_after_path_replace
    anchored_module._rename_posix_noreplace = crash_after_posix_noreplace
    anchored_module._rename_windows_handle = crash_after_native_rename
    manager_module.validate_staged_installed_manifest_value = crash_after_staged_validation
    installation_module.InstallTransaction.mark_validated = crash_before_validated_publication
    installation_module._verify_final = crash_after_final_validation
    manager.probe_runner = crash_after_probe
    if crash_point == "extracting":
        archive_module._copy_bounded = crash_during_extract
    elif crash_point.endswith("-extracted-object"):
        archive_module._copy_bounded = crash_after_extracted_object
    manager.install_from_archive(
        "mihomo",
        "1.0.0",
        Path(archive),
        expected_sha256=digest,
        asset_name=(
            "mihomo-windows-amd64-compatible-v1.0.0.zip"
            if platform_name == "windows"
            else "mihomo-linux-amd64-v1.0.0.gz"
        ),
        source_url=(
            "https://example.test/mihomo.zip" if platform_name == "windows" else "https://example.test/mihomo.gz"
        ),
        activate=False,
    )


def _crash_install_recovery(home, crash_point, platform_name="linux"):
    platform_info = (
        PlatformInfo("windows", "amd64", None)
        if platform_name == "windows"
        else PlatformInfo("linux", "amd64", "glibc")
    )
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )
    original_remove_staging = installation_module._remove_staging
    original_advance = installation_module._advance_committed
    original_dispose = installation_module._dispose_file
    original_secure_remove = installation_module._secure_remove_tree
    original_flush = anchored_module.flush_descriptor
    original_path_replace = anchored_module.os.replace
    original_native_rename = anchored_module._rename_windows_handle

    def crash_during_staging_delete(record, expected_identity):
        if crash_point == "staging-child-deleted":
            children = [path for path in record.staging.rglob("*") if path.is_file()]
            if children:
                children[0].unlink()
            os._exit(91)
        result = original_remove_staging(record, expected_identity)
        if crash_point == "staging-tree-deleted":
            os._exit(92)
        return result

    def crash_after_committed(record):
        result = original_advance(record)
        if crash_point == "committed-persisted":
            os._exit(94)
        return result

    def crash_after_dispose(paths, path, expected_identity):
        result = original_dispose(paths, path, expected_identity)
        if crash_point == "journal-deleted" and Path(path).name.startswith(".install-"):
            os._exit(93)
        return result

    def crash_after_secure_remove(root, target, *args, **kwargs):
        result = original_secure_remove(root, target, *args, **kwargs)
        target = Path(target)
        if (
            crash_point == "staging-root-deleted-before-parent-flush"
            and ".install-" in target.name
            and not target.name.endswith(".json")
        ):
            os._exit(95)
        if (
            crash_point == "journal-unlinked-before-parent-flush"
            and target.name.startswith(".install-")
            and target.name.endswith(".json")
        ):
            os._exit(98)
        return result

    def crash_after_file_flush(descriptor, kind):
        result = original_flush(descriptor, kind)
        if crash_point == "committed-journal-file-flushed" and kind == "anchored JSON file":
            os._exit(96)
        return result

    def crash_after_path_replace(source, destination, *args, **kwargs):
        result = original_path_replace(source, destination, *args, **kwargs)
        destination_name = Path(destination).name
        if (
            crash_point == "committed-journal-replaced-before-parent-flush"
            and destination_name.startswith(".install-")
            and destination_name.endswith(".json")
        ):
            os._exit(97)
        return result

    def crash_after_native_rename(source_handle, parent_handle, destination_name, replace_existing):
        result = original_native_rename(source_handle, parent_handle, destination_name, replace_existing)
        if (
            crash_point == "committed-journal-replaced-before-parent-flush"
            and destination_name.startswith(".install-")
            and destination_name.endswith(".json")
        ):
            os._exit(97)
        return result

    installation_module._remove_staging = crash_during_staging_delete
    installation_module._advance_committed = crash_after_committed
    installation_module._dispose_file = crash_after_dispose
    installation_module._secure_remove_tree = crash_after_secure_remove
    anchored_module.flush_descriptor = crash_after_file_flush
    anchored_module.os.replace = crash_after_path_replace
    anchored_module._rename_windows_handle = crash_after_native_rename
    manager.list_installed("mihomo")


def test_manager_public_construction_and_supported_catalog(tmp_path):
    manager = BackendManager.from_home(str(tmp_path / ".jerryproxy"))
    assert manager.paths.root == tmp_path / ".jerryproxy"
    assert not manager.paths.root.exists()
    assert [spec.name for spec in manager.supported()] == ["mihomo", "sing-box", "v2ray", "xray"]


def install_fake_mihomo(manager, tmp_path, version, payload, activate):
    archive = tmp_path / ("mihomo-%s.gz" % version)
    digest = make_gzip_archive(archive, payload)
    return manager.install_from_archive(
        "mihomo",
        version,
        archive,
        expected_sha256=digest,
        asset_name="mihomo-linux-amd64-v%s.gz" % version,
        source_url="https://example.test/%s" % archive.name,
        activate=activate,
    )


def test_install_and_switch_versions(tmp_path):
    manager = manager_for(tmp_path)
    first = install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    second = install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    active = manager.current("mihomo")
    assert active.version == "1.0.0"
    assert active.executable == first.executable
    assert active.link.read_bytes() == b"version one"
    if os.name == "posix":
        assert active.link.is_symlink()
        assert os.readlink(str(active.link)).startswith("../backends/mihomo/1.0.0/")

    switched = manager.use("mihomo", "2.0.0")
    assert switched.version == "2.0.0"
    assert switched.executable == second.executable
    assert switched.link.read_bytes() == b"version two"
    value = read_json(manager.paths.active / "mihomo.json")
    assert value["version"] == "2.0.0"
    assert value["link_mode"] in ("symlink", "copy")
    assert set(value) == {"activated_at", "executable", "link", "link_mode", "name", "version"}
    installed_value = read_json(second.manifest)
    assert set(installed_value) == {
        "asset_name",
        "catalog_generated_at",
        "executable",
        "executable_sha256",
        "installed_at",
        "name",
        "platform",
        "sha256",
        "source_url",
        "version",
    }

    rolled_back = manager.use("mihomo", "1.0.0")
    assert rolled_back.link.read_bytes() == b"version one"


@pytest.mark.skipif(os.name != "posix", reason="POSIX initial activation journal hard exits")
@pytest.mark.parametrize(
    "crash_point,exit_code",
    (
        ("writer-temporary-created", 71),
        ("writer-file-flushed", 72),
        ("authority-replaced-before-parent-flush", 73),
        ("authority-parent-flushed", 74),
    ),
)
@pytest.mark.parametrize("with_previous", (False, True))
def test_hard_exit_during_initial_activation_journal_publication_recovers(
    tmp_path,
    crash_point,
    exit_code,
    with_previous,
):
    manager = manager_for(tmp_path)
    if with_previous:
        install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    installed = install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_initial_activation_journal,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    active = manager.current("mihomo")
    if with_previous:
        assert active.version == "1.0.0"
        assert active.link.read_bytes() == b"previous"
    else:
        assert active is None
        assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
        assert not (manager.paths.active / "mihomo.json").exists()
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".use-*"))
    assert not list(manager.paths.bin.glob(".*.use-*.candidate"))
    assert not list(manager.paths.active.glob(".*.use-*.candidate.json"))


def _assert_partial_manifest_candidate(paths, crash_point):
    journal = read_json(next(paths.runtimes.glob(".use-*.json")))
    candidate_value = journal["candidates"]["manifest"]
    candidate = paths.root / candidate_value["path"]
    expected = activation_module._canonical_bytes(journal["target"]["manifest_payload"])
    actual = candidate.read_bytes()
    assert candidate_value["state"] == "building"
    assert candidate_value["identity"] is not None
    assert capture_identity(candidate) == candidate_value["identity"]
    assert actual == expected[: len(actual)]
    if crash_point == "manifest-first-chunk":
        assert 0 < len(actual) < len(expected) // 2
    elif crash_point == "manifest-middle-chunk":
        assert len(expected) // 2 <= len(actual) < len(expected)
    else:
        assert actual == expected


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit activation matrix")
@pytest.mark.parametrize(
    "crash_point,exit_code,expected_version",
    [
        ("prepared", 41, "1.0.0"),
        ("symlink-created", 55, "1.0.0"),
        ("symlink-parent-flushed", 64, "1.0.0"),
        ("link-ready", 45, "1.0.0"),
        ("manifest-building", 46, "1.0.0"),
        ("manifest-empty-file-flushed", 65, "1.0.0"),
        ("manifest-empty-parent-flushed", 66, "1.0.0"),
        ("manifest-empty", 56, "1.0.0"),
        ("manifest-identity", 78, "1.0.0"),
        ("manifest-first-chunk", 75, "1.0.0"),
        ("manifest-middle-chunk", 76, "1.0.0"),
        ("manifest-last-chunk", 77, "1.0.0"),
        ("manifest-written", 57, "1.0.0"),
        ("candidates-ready", 47, "1.0.0"),
        ("link-replaced-before-parent-flush", 80, "1.0.0"),
        ("link-replaced", 42, "1.0.0"),
        ("link-published", 48, "1.0.0"),
        ("manifest-replaced-before-parent-flush", 91, "1.0.0"),
        ("manifest-replaced", 50, "1.0.0"),
        ("manifest-published", 49, "1.0.0"),
        ("pair-validated", 79, "1.0.0"),
        ("committed", 43, "2.0.0"),
    ],
)
def test_hard_exit_activation_recovers_on_next_public_lock(
    tmp_path,
    crash_point,
    exit_code,
    expected_version,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    if crash_point.endswith("-chunk"):
        _assert_partial_manifest_candidate(manager.paths, crash_point)
    active = manager.current("mihomo")
    assert active.version == expected_version
    assert active.link.read_bytes() == (b"target" if expected_version == "2.0.0" else b"previous")
    assert not list(manager.paths.runtimes.glob(".use-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit activation matrix")
@pytest.mark.parametrize(
    "crash_point,exit_code,committed",
    [
        ("prepared", 41, False),
        ("symlink-created", 55, False),
        ("symlink-parent-flushed", 64, False),
        ("link-ready", 45, False),
        ("manifest-building", 46, False),
        ("manifest-empty-file-flushed", 65, False),
        ("manifest-empty-parent-flushed", 66, False),
        ("manifest-empty", 56, False),
        ("manifest-identity", 78, False),
        ("manifest-first-chunk", 75, False),
        ("manifest-middle-chunk", 76, False),
        ("manifest-last-chunk", 77, False),
        ("manifest-written", 57, False),
        ("candidates-ready", 47, False),
        ("link-replaced-before-parent-flush", 80, False),
        ("link-replaced", 42, False),
        ("link-published", 48, False),
        ("manifest-replaced-before-parent-flush", 91, False),
        ("manifest-replaced", 50, False),
        ("manifest-published", 49, False),
        ("pair-validated", 79, False),
        ("committed", 43, True),
    ],
)
def test_hard_exit_activation_without_previous_recovers_to_absent_or_committed_target(
    tmp_path,
    crash_point,
    exit_code,
    committed,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    if crash_point.endswith("-chunk"):
        _assert_partial_manifest_candidate(manager.paths, crash_point)
    active = manager.current("mihomo")
    if committed:
        assert active.version == "2.0.0"
        assert active.link.read_bytes() == b"target"
    else:
        assert active is None
        assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
        assert not (manager.paths.active / "mihomo.json").exists()
    assert not list(manager.paths.runtimes.glob(".use-*"))


_WINDOWS_COPY_HARD_EXIT_CASES = (
    ("prepared", 130, False),
    ("link-building", 131, False),
    ("link-empty-created", 132, False),
    ("link-empty-file-flushed", 157, False),
    ("link-empty-parent-flushed", 158, False),
    ("link-identity", 133, False),
    ("link-first-chunk", 134, False),
    ("link-middle-chunk", 135, False),
    ("link-last-chunk", 136, False),
    ("link-flushed", 137, False),
    ("link-ready", 138, False),
    ("manifest-building", 139, False),
    ("manifest-empty-created", 140, False),
    ("manifest-empty-file-flushed", 159, False),
    ("manifest-empty-parent-flushed", 160, False),
    ("manifest-identity", 141, False),
    ("manifest-first-chunk", 142, False),
    ("manifest-middle-chunk", 152, False),
    ("manifest-last-chunk", 153, False),
    ("manifest-flushed", 143, False),
    ("candidates-ready", 144, False),
    ("link-replaced-before-parent-flush", 145, False),
    ("link-parent-flushed", 146, False),
    ("link-published", 147, False),
    ("manifest-replaced-before-parent-flush", 148, False),
    ("manifest-parent-flushed", 149, False),
    ("manifest-published", 150, False),
    ("committed", 151, True),
)


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows copy-mode hard-exit matrix")
@pytest.mark.parametrize("crash_point,exit_code,committed", _WINDOWS_COPY_HARD_EXIT_CASES)
def test_windows_copy_mode_hard_exit_recovers_on_next_public_lock(
    tmp_path,
    monkeypatch,
    crash_point,
    exit_code,
    committed,
):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"prior!", activate=False)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)

    def unavailable_symlink(*args, **kwargs):
        del args, kwargs
        raise OSError("forced Windows copy fallback")

    with monkeypatch.context() as selected:
        selected.setattr(activation_module, "_create_symlink_candidate", unavailable_symlink)
        previous = manager.use("mihomo", "1.0.0")
    assert previous.link_mode == "copy"
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_windows_copy_activation,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(20)

    assert process.exitcode == exit_code
    if crash_point.endswith("-chunk"):
        _assert_windows_partial_candidate(manager.paths, crash_point)
    active = manager.current("mihomo")
    expected_version = "2.0.0" if committed else "1.0.0"
    assert active.version == expected_version
    assert active.link_mode == "copy"
    assert active.link.read_bytes() == (b"target" if expected_version == "2.0.0" else b"prior!")
    assert not list(manager.paths.runtimes.glob(".use-*"))


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows no-previous copy-mode hard-exit matrix")
@pytest.mark.parametrize("crash_point,exit_code,committed", _WINDOWS_COPY_HARD_EXIT_CASES)
def test_windows_copy_mode_hard_exit_without_previous_recovers_to_absent_or_target(
    tmp_path,
    crash_point,
    exit_code,
    committed,
):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_windows_copy_activation,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(20)

    assert process.exitcode == exit_code
    if crash_point.endswith("-chunk"):
        _assert_windows_partial_candidate(manager.paths, crash_point)
    active = manager.current("mihomo")
    if committed:
        assert active.version == "2.0.0"
        assert active.link_mode == "copy"
        assert active.link.read_bytes() == b"target"
    else:
        assert active is None
        assert not os.path.lexists(str(manager.paths.bin / "mihomo.exe"))
        assert not (manager.paths.active / "mihomo.json").exists()
    assert not list(manager.paths.runtimes.glob(".use-*"))


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows equal-byte copy recovery")
@pytest.mark.parametrize(
    ("crash_point", "exit_code", "expected_version"),
    (("link-parent-flushed", 146, "1.0.0"), ("committed", 151, "2.0.0")),
)
def test_windows_equal_byte_copy_recovery_uses_manifest_and_commit_phase(
    tmp_path,
    monkeypatch,
    crash_point,
    exit_code,
    expected_version,
):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"same!!", activate=False)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"same!!", activate=False)

    def unavailable_symlink(*args, **kwargs):
        del args, kwargs
        raise OSError("forced Windows copy fallback")

    with monkeypatch.context() as selected:
        selected.setattr(activation_module, "_create_symlink_candidate", unavailable_symlink)
        manager.use("mihomo", "1.0.0")
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_windows_copy_activation,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(20)

    assert process.exitcode == exit_code
    active = manager.current("mihomo")
    assert active.version == expected_version
    assert active.link_mode == "copy"
    assert active.link.read_bytes() == b"same!!"
    assert not list(manager.paths.runtimes.glob(".use-*"))


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows activation recovery hard-exit matrix")
@pytest.mark.parametrize(
    "direction,with_previous,operation_crash,operation_exit,expected_version",
    (
        ("rollback-previous", True, "manifest-published", 150, "1.0.0"),
        ("rollback-absent", False, "manifest-published", 150, None),
        ("rollforward-target", True, "committed", 151, "2.0.0"),
    ),
)
def test_windows_hard_exit_after_each_activation_recovery_action_converges(
    tmp_path,
    monkeypatch,
    direction,
    with_previous,
    operation_crash,
    operation_exit,
    expected_version,
):
    context = multiprocessing.get_context("spawn")
    completed_step = None
    for selected_step in range(1, 24):
        case_root = tmp_path / ("%s-%d" % (direction, selected_step))
        case_root.mkdir()
        manager = BackendManager(
            JerryProxyPaths(case_root / ".jerryproxy"),
            platform_info=PlatformInfo("windows", "amd64", None),
            probe_runner=lambda installed: None,
        )
        if with_previous:
            install_fake_mihomo(manager, case_root, "1.0.0", b"previous", activate=False)
        install_fake_mihomo(manager, case_root, "2.0.0", b"target", activate=False)

        if with_previous:

            def unavailable_symlink(*args, **kwargs):
                del args, kwargs
                raise OSError("forced Windows copy fallback")

            with monkeypatch.context() as selected:
                selected.setattr(activation_module, "_create_symlink_candidate", unavailable_symlink)
                manager.use("mihomo", "1.0.0")

        operation = context.Process(
            target=_crash_windows_copy_activation,
            args=(str(manager.paths.root), operation_crash),
        )
        operation.start()
        operation.join(20)
        assert operation.exitcode == operation_exit

        recovery = context.Process(
            target=_crash_activation_recovery_after_step,
            args=(str(manager.paths.root), selected_step, "windows"),
        )
        recovery.start()
        recovery.join(20)
        if recovery.exitcode == 0:
            completed_step = selected_step
        else:
            assert recovery.exitcode == 60 + selected_step

        active = manager.current("mihomo")
        if expected_version is None:
            assert active is None
            assert not os.path.lexists(str(manager.paths.bin / "mihomo.exe"))
            assert not (manager.paths.active / "mihomo.json").exists()
        else:
            assert active.version == expected_version
            assert active.link_mode == "copy"
            expected_payload = b"target" if expected_version == "2.0.0" else b"previous"
            assert active.link.read_bytes() == expected_payload
        assert not list(manager.paths.runtimes.glob(".use-*"))
        if completed_step is not None:
            break

    assert completed_step is not None
    assert completed_step > 1


def _assert_windows_recovery_partial_candidate(paths, crash_point, direction):
    name = "link" if crash_point.startswith("link-") else "manifest"
    journal = read_json(next(paths.runtimes.glob(".use-*.json")))
    candidate_value = journal["candidates"][name]
    candidate = paths.root / candidate_value["path"]
    expected_purpose = "recovery-target" if direction == "rollforward-target" else "recovery-previous"
    assert journal["recovery"] == {"direction": direction}
    assert candidate_value["purpose"] == expected_purpose
    assert candidate_value["state"] == "building"
    assert candidate_value["identity"] is not None
    assert capture_identity(candidate) == candidate_value["identity"]
    logical = journal["target"] if direction == "rollforward-target" else journal["previous"]
    if name == "link":
        expected = (paths.root / logical["executable"]).read_bytes()
    else:
        expected = activation_module._canonical_bytes(logical["manifest_payload"])
    actual = candidate.read_bytes()
    assert actual == expected[: len(actual)]
    if crash_point.endswith("first-chunk"):
        assert 0 < len(actual) < len(expected) // 2
    elif crash_point.endswith("middle-chunk"):
        assert len(expected) // 2 <= len(actual) < len(expected)
    else:
        assert actual == expected


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows activation recovery action internals")
@pytest.mark.parametrize(
    (
        "direction",
        "with_previous",
        "operation_crash",
        "operation_exit",
        "remove_public",
        "crash_point",
        "exit_code",
        "expected_version",
    ),
    (
        ("rollback-previous", True, "manifest-published", 150, False, "link-empty-created", 167, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-empty-file-flushed", 168, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-empty-parent-flushed", 169, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-identity-recorded", 170, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-first-chunk", 171, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-middle-chunk", 172, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-last-chunk", 173, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "link-flushed", 174, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-empty-created", 177, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-empty-file-flushed", 178, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-empty-parent-flushed", 179, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-identity-recorded", 180, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-first-chunk", 181, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-middle-chunk", 182, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-last-chunk", 183, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "manifest-flushed", 184, "1.0.0"),
        (
            "rollback-previous",
            True,
            "manifest-published",
            150,
            False,
            "repair-replaced-before-parent-flush",
            185,
            "1.0.0",
        ),
        ("rollback-previous", True, "manifest-published", 150, False, "repair-parent-flushed", 186, "1.0.0"),
        ("rollback-previous", True, "candidates-ready", 144, False, "candidate-deleted", 187, "1.0.0"),
        ("rollback-previous", True, "candidates-ready", 144, False, "candidate-delete-parent-flushed", 188, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "journal-deleted", 189, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "journal-delete-parent-flushed", 190, "1.0.0"),
        (
            "rollback-previous",
            True,
            "manifest-published",
            150,
            False,
            "journal-replaced-before-parent-flush",
            191,
            "1.0.0",
        ),
        ("rollback-previous", True, "manifest-published", 150, False, "journal-parent-flushed", 192, "1.0.0"),
        ("rollback-previous", True, "manifest-published", 150, False, "journal-file-flushed", 193, "1.0.0"),
        ("rollback-absent", False, "manifest-published", 150, False, "public-deleted", 194, None),
        ("rollback-absent", False, "manifest-published", 150, False, "public-delete-parent-flushed", 195, None),
        ("rollforward-target", True, "committed", 151, True, "link-first-chunk", 171, "2.0.0"),
        ("rollforward-target", True, "committed", 151, True, "link-middle-chunk", 172, "2.0.0"),
        ("rollforward-target", True, "committed", 151, True, "link-last-chunk", 173, "2.0.0"),
        ("rollforward-target", True, "committed", 151, True, "manifest-first-chunk", 181, "2.0.0"),
        ("rollforward-target", True, "committed", 151, True, "manifest-middle-chunk", 182, "2.0.0"),
        ("rollforward-target", True, "committed", 151, True, "manifest-last-chunk", 183, "2.0.0"),
    ),
)
def test_windows_hard_exit_inside_activation_recovery_action_converges(
    tmp_path,
    monkeypatch,
    direction,
    with_previous,
    operation_crash,
    operation_exit,
    remove_public,
    crash_point,
    exit_code,
    expected_version,
):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    if with_previous:
        install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=False)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)

    def unavailable_symlink(*args, **kwargs):
        del args, kwargs
        raise OSError("forced Windows copy fallback")

    if with_previous:
        with monkeypatch.context() as selected:
            selected.setattr(activation_module, "_create_symlink_candidate", unavailable_symlink)
            previous = manager.use("mihomo", "1.0.0")
        assert previous.link_mode == "copy"

    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_windows_copy_activation,
        args=(str(manager.paths.root), operation_crash),
    )
    operation.start()
    operation.join(20)
    assert operation.exitcode == operation_exit

    if remove_public:
        (manager.paths.bin / "mihomo.exe").unlink()
        (manager.paths.active / "mihomo.json").unlink()

    recovery = context.Process(
        target=_crash_inside_windows_activation_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(20)
    assert recovery.exitcode == exit_code
    if crash_point.endswith("-chunk"):
        _assert_windows_recovery_partial_candidate(manager.paths, crash_point, direction)

    active = manager.current("mihomo")
    if expected_version is None:
        assert active is None
        assert not os.path.lexists(str(manager.paths.bin / "mihomo.exe"))
        assert not (manager.paths.active / "mihomo.json").exists()
    else:
        assert active.version == expected_version
        assert active.link_mode == "copy"
        expected_payload = b"target" if expected_version == "2.0.0" else b"previous"
        assert active.link.read_bytes() == expected_payload
    assert not list(manager.paths.runtimes.glob(".use-*"))
    assert not list(manager.paths.bin.glob(".*.use-*.candidate"))
    assert not list(manager.paths.active.glob(".*.use-*.candidate.json"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit activation recovery")
@pytest.mark.parametrize("selected_step", range(1, 13))
def test_hard_exit_after_each_activation_recovery_action_keeps_direction_and_converges(
    tmp_path,
    selected_step,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), "link-replaced"),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == 42

    recovery = context.Process(
        target=_crash_activation_recovery_after_step,
        args=(str(manager.paths.root), selected_step),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == 60 + selected_step
    journal = next(manager.paths.runtimes.glob(".use-*.json"))
    assert read_json(journal)["recovery"] == {"direction": "rollback-previous"}

    active = manager.current("mihomo")
    assert active.version == "1.0.0"
    assert active.link.read_bytes() == b"previous"
    assert not list(manager.paths.runtimes.glob(".use-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit activation recovery directions")
@pytest.mark.parametrize(
    ("direction", "with_previous", "operation_crash", "operation_exit", "expected_version", "remove_public"),
    (
        ("rollback-absent", False, "manifest-published", 49, None, False),
        ("rollforward-target", True, "committed", 43, "2.0.0", True),
    ),
)
def test_hard_exit_after_each_activation_recovery_action_converges_for_every_direction(
    tmp_path,
    direction,
    with_previous,
    operation_crash,
    operation_exit,
    expected_version,
    remove_public,
):
    context = multiprocessing.get_context("spawn")
    completed_step = None
    for selected_step in range(1, 24):
        case_root = tmp_path / ("%s-%d" % (direction, selected_step))
        case_root.mkdir()
        manager = manager_for(case_root)
        if with_previous:
            install_fake_mihomo(manager, case_root, "1.0.0", b"previous", activate=True)
        install_fake_mihomo(manager, case_root, "2.0.0", b"target", activate=False)

        operation = context.Process(
            target=_crash_activation,
            args=(str(manager.paths.root), operation_crash),
        )
        operation.start()
        operation.join(10)
        assert operation.exitcode == operation_exit

        if remove_public:
            (manager.paths.bin / "mihomo").unlink()
            (manager.paths.active / "mihomo.json").unlink()

        recovery = context.Process(
            target=_crash_activation_recovery_after_step,
            args=(str(manager.paths.root), selected_step),
        )
        recovery.start()
        recovery.join(10)
        if recovery.exitcode == 0:
            completed_step = selected_step
        else:
            assert recovery.exitcode == 60 + selected_step
            journals = list(manager.paths.runtimes.glob(".use-*.json"))
            if journals:
                assert read_json(journals[0])["recovery"] == {"direction": direction}
            else:
                completed_step = selected_step

        active = manager.current("mihomo")
        if expected_version is None:
            assert active is None
            assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
            assert not (manager.paths.active / "mihomo.json").exists()
        else:
            assert active.version == expected_version
            assert active.link.read_bytes() == b"target"
        assert not list(manager.paths.runtimes.glob(".use-*"))
        if completed_step is not None:
            break

    assert completed_step is not None
    assert completed_step > 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit activation recovery")
@pytest.mark.parametrize(
    "crash_point,exit_code",
    [
        ("symlink-created", 81),
        ("repair-replaced", 82),
        ("candidate-deleted", 83),
        ("journal-deleted", 84),
        ("journal-file-flushed", 85),
        ("journal-replaced-before-parent-flush", 86),
        ("journal-parent-flushed", 87),
        ("repair-replaced-before-parent-flush", 89),
        ("candidate-delete-parent-flushed", 104),
        ("journal-delete-parent-flushed", 105),
    ],
)
def test_hard_exit_inside_activation_recovery_action_converges(
    tmp_path,
    crash_point,
    exit_code,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), "link-replaced"),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == 42

    recovery = context.Process(
        target=_crash_inside_activation_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == exit_code

    active = manager.current("mihomo")
    assert active.version == "1.0.0"
    assert active.link.read_bytes() == b"previous"
    assert not list(manager.paths.runtimes.glob(".use-*"))
    assert not list(manager.paths.bin.glob(".*.use-*.candidate"))
    assert not list(manager.paths.active.glob(".*.use-*.candidate.json"))


def _assert_partial_recovery_manifest_candidate(paths, crash_point, direction):
    journal = read_json(next(paths.runtimes.glob(".use-*.json")))
    assert journal["recovery"] == {"direction": direction}
    candidate_value = journal["candidates"]["manifest"]
    candidate = paths.root / candidate_value["path"]
    logical = journal["previous"] if direction == "rollback-previous" else journal["target"]
    expected = activation_module._canonical_bytes(logical["manifest_payload"])
    actual = candidate.read_bytes()
    assert candidate_value["purpose"] == (
        "recovery-previous" if direction == "rollback-previous" else "recovery-target"
    )
    assert candidate_value["state"] == "building"
    assert candidate_value["identity"] is not None
    assert capture_identity(candidate) == candidate_value["identity"]
    assert actual == expected[: len(actual)]
    if crash_point == "manifest-first-chunk":
        assert 0 < len(actual) < len(expected) // 2
    elif crash_point == "manifest-middle-chunk":
        assert len(expected) // 2 <= len(actual) < len(expected)
    else:
        assert actual == expected


@pytest.mark.skipif(os.name != "posix", reason="POSIX manifest recovery action internals")
@pytest.mark.parametrize(
    "crash_point,exit_code",
    (
        ("manifest-empty-created", 92),
        ("manifest-empty-file-flushed", 93),
        ("manifest-empty-parent-flushed", 94),
        ("manifest-identity-recorded", 95),
        ("manifest-first-chunk", 96),
        ("manifest-middle-chunk", 97),
        ("manifest-last-chunk", 98),
        ("manifest-file-flushed", 100),
        ("manifest-ready-recorded", 101),
        ("manifest-repair-replaced-before-parent-flush", 102),
        ("manifest-repair-parent-flushed", 103),
    ),
)
@pytest.mark.parametrize(
    "direction,operation_crash,operation_exit,remove_manifest,expected_version",
    (
        ("rollback-previous", "manifest-published", 49, False, "1.0.0"),
        ("rollforward-target", "committed", 43, True, "2.0.0"),
    ),
)
def test_hard_exit_inside_manifest_recovery_converges_for_both_repair_directions(
    tmp_path,
    crash_point,
    exit_code,
    direction,
    operation_crash,
    operation_exit,
    remove_manifest,
    expected_version,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), operation_crash),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == operation_exit
    if remove_manifest:
        (manager.paths.active / "mihomo.json").unlink()

    recovery = context.Process(
        target=_crash_inside_activation_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == exit_code
    if crash_point.endswith("-chunk"):
        _assert_partial_recovery_manifest_candidate(manager.paths, crash_point, direction)

    active = manager.current("mihomo")
    assert active.version == expected_version
    assert active.link.read_bytes() == (b"previous" if expected_version == "1.0.0" else b"target")
    assert not list(manager.paths.runtimes.glob(".use-*"))
    assert not list(manager.paths.bin.glob(".*.use-*.candidate"))
    assert not list(manager.paths.active.glob(".*.use-*.candidate.json"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX rollback-to-absent manifest deletion")
@pytest.mark.parametrize(
    "crash_point,exit_code",
    (
        ("manifest-public-deleted", 106),
        ("manifest-public-delete-parent-flushed", 107),
    ),
)
def test_hard_exit_inside_rollback_absent_manifest_deletion_converges(
    tmp_path,
    crash_point,
    exit_code,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), "manifest-published"),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == 49
    (manager.paths.bin / "mihomo").unlink()

    recovery = context.Process(
        target=_crash_inside_activation_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == exit_code

    assert manager.current("mihomo") is None
    assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
    assert not (manager.paths.active / "mihomo.json").exists()
    assert not list(manager.paths.runtimes.glob(".use-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit activation recovery directions")
@pytest.mark.parametrize(
    (
        "direction",
        "with_previous",
        "operation_crash",
        "operation_exit",
        "remove_public",
        "crash_point",
        "recovery_exit",
        "expected_version",
    ),
    (
        ("rollback-absent", False, "manifest-published", 49, False, "public-deleted", 88, None),
        (
            "rollback-absent",
            False,
            "manifest-published",
            49,
            False,
            "public-delete-parent-flushed",
            90,
            None,
        ),
        ("rollforward-target", True, "committed", 43, True, "journal-file-flushed", 85, "2.0.0"),
        ("rollforward-target", True, "committed", 43, True, "symlink-created", 81, "2.0.0"),
        (
            "rollforward-target",
            True,
            "committed",
            43,
            True,
            "repair-replaced-before-parent-flush",
            89,
            "2.0.0",
        ),
        ("rollforward-target", True, "committed", 43, True, "repair-replaced", 82, "2.0.0"),
        ("rollforward-target", True, "committed", 43, True, "journal-deleted", 84, "2.0.0"),
    ),
)
def test_hard_exit_inside_activation_recovery_converges_for_every_direction(
    tmp_path,
    direction,
    with_previous,
    operation_crash,
    operation_exit,
    remove_public,
    crash_point,
    recovery_exit,
    expected_version,
):
    manager = manager_for(tmp_path)
    if with_previous:
        install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_activation,
        args=(str(manager.paths.root), operation_crash),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == operation_exit

    if remove_public:
        (manager.paths.bin / "mihomo").unlink()
        (manager.paths.active / "mihomo.json").unlink()

    recovery = context.Process(
        target=_crash_inside_activation_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == recovery_exit
    journals = list(manager.paths.runtimes.glob(".use-*.json"))
    if journals:
        expected_recovery = None if crash_point == "journal-file-flushed" else {"direction": direction}
        assert read_json(journals[0])["recovery"] == expected_recovery

    active = manager.current("mihomo")
    if expected_version is None:
        assert active is None
        assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
        assert not (manager.paths.active / "mihomo.json").exists()
    else:
        assert active.version == expected_version
        assert active.link.read_bytes() == b"target"
    assert not list(manager.paths.runtimes.glob(".use-*"))
    assert not list(manager.paths.bin.glob(".*.use-*.candidate"))
    assert not list(manager.paths.active.glob(".*.use-*.candidate.json"))


@pytest.mark.parametrize(
    "platform_name",
    (
        pytest.param(
            "linux",
            marks=pytest.mark.skipif(os.name != "posix", reason="POSIX initial install journal hard exits"),
        ),
        pytest.param(
            "windows",
            marks=(
                pytest.mark.windows_native,
                pytest.mark.skipif(os.name != "nt", reason="native Windows initial install journal hard exits"),
            ),
        ),
    ),
)
@pytest.mark.parametrize(
    "crash_point,exit_code",
    (
        ("writer-temporary-created", 201),
        ("writer-file-flushed", 202),
        ("authority-replaced-before-parent-flush", 203),
        ("authority-parent-flushed", 204),
    ),
)
def test_hard_exit_during_initial_install_journal_publication_recovers(
    tmp_path,
    platform_name,
    crash_point,
    exit_code,
):
    platform_info = (
        PlatformInfo("windows", "amd64", None)
        if platform_name == "windows"
        else PlatformInfo("linux", "amd64", "glibc")
    )
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )
    manager.paths.ensure()
    archive = tmp_path / ("mihomo.zip" if platform_name == "windows" else "mihomo.gz")
    digest = (
        make_windows_mihomo_zip(archive, b"backend payload")
        if platform_name == "windows"
        else make_gzip_archive(archive, b"backend payload")
    )
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_initial_install_journal,
        args=(str(manager.paths.root), str(archive), digest, crash_point, platform_name),
    )

    process.start()
    process.join(20 if platform_name == "windows" else 10)

    assert process.exitcode == exit_code
    assert manager.list_installed("mihomo") == []
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))
    assert not (manager.paths.backends / "mihomo" / "1.0.0").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit install matrix")
@pytest.mark.parametrize(
    "crash_point,exit_code,expected_installed",
    [
        ("journal-temporary", 60, False),
        ("prepared", 51, False),
        ("staging-child-flushed", 64, False),
        ("staging-parent-flushed", 65, False),
        ("staging-created", 61, False),
        ("extracting-phase", 58, False),
        ("extracting", 52, False),
        ("manifest-temporary-created", 205, False),
        ("manifest-file-flushed", 206, False),
        ("manifest-replaced-before-parent-flush", 207, False),
        ("manifest-parent-flushed", 208, False),
        ("manifest-written", 62, False),
        ("executable-flushed", 63, False),
        ("tree-root-flushed", 66, False),
        ("staged-static-validated", 209, False),
        ("probe-returned", 210, False),
        ("post-probe-validated", 211, False),
        ("validated", 59, False),
        ("final-replaced-before-parent-flush", 67, True),
        ("final-parent-flushed", 68, True),
        ("final-replaced", 53, True),
        ("final-static-validated", 212, True),
        ("committed", 54, True),
    ],
)
def test_hard_exit_install_recovers_on_next_public_lock(
    tmp_path,
    crash_point,
    exit_code,
    expected_installed,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = make_gzip_archive(archive, b"backend payload")
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_install,
        args=(str(manager.paths.root), str(archive), digest, crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    if crash_point == "staged-static-validated":
        assert not (tmp_path / "probe-called").exists()
    if crash_point in ("probe-returned", "post-probe-validated", "final-static-validated"):
        assert (tmp_path / "probe-called").read_text(encoding="utf-8") == "called"
    installed = manager.list_installed("mihomo")
    assert bool(installed) is expected_installed
    if expected_installed:
        assert installed[0].version == "1.0.0"
        assert installed[0].executable.read_bytes() == b"backend payload"
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows ZIP install hard-exit matrix")
@pytest.mark.parametrize(
    "crash_point,exit_code,expected_installed",
    (
        ("journal-temporary", 60, False),
        ("prepared", 51, False),
        ("staging-created", 61, False),
        ("extracting-phase", 58, False),
        ("extracting", 52, False),
        ("first-extracted-object", 154, False),
        ("middle-extracted-object", 155, False),
        ("last-extracted-object", 156, False),
        ("manifest-temporary-created", 205, False),
        ("manifest-file-flushed", 206, False),
        ("manifest-replaced-before-parent-flush", 207, False),
        ("manifest-parent-flushed", 208, False),
        ("manifest-written", 62, False),
        ("executable-flushed", 63, False),
        ("staged-static-validated", 209, False),
        ("probe-returned", 210, False),
        ("post-probe-validated", 211, False),
        ("validated", 59, False),
        ("final-replaced-before-parent-flush", 67, True),
        ("final-parent-flushed", 68, True),
        ("final-replaced", 53, True),
        ("final-static-validated", 212, True),
        ("committed", 54, True),
    ),
)
def test_windows_zip_install_hard_exit_recovers_on_next_public_lock(
    tmp_path,
    crash_point,
    exit_code,
    expected_installed,
):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    manager.paths.ensure()
    archive = tmp_path / "mihomo-1.0.0.zip"
    digest = make_windows_mihomo_zip(archive, b"backend payload")
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_install,
        args=(str(manager.paths.root), str(archive), digest, crash_point, "windows"),
    )

    process.start()
    process.join(20)

    assert process.exitcode == exit_code
    if crash_point == "staged-static-validated":
        assert not (tmp_path / "probe-called").exists()
    if crash_point in ("probe-returned", "post-probe-validated", "final-static-validated"):
        assert (tmp_path / "probe-called").read_text(encoding="utf-8") == "called"
    installed = manager.list_installed("mihomo")
    assert bool(installed) is expected_installed
    if expected_installed:
        assert installed[0].version == "1.0.0"
        assert installed[0].executable.name == "mihomo.exe"
        assert installed[0].executable.read_bytes() == b"backend payload"
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit install recovery")
@pytest.mark.parametrize(
    "operation_point,recovery_point,exit_code,expected_installed",
    [
        ("extracting", "staging-child-deleted", 91, False),
        ("extracting", "staging-root-deleted-before-parent-flush", 95, False),
        ("extracting", "staging-tree-deleted", 92, False),
        ("extracting", "journal-deleted", 93, False),
        ("final-replaced", "committed-journal-file-flushed", 96, True),
        ("final-replaced", "committed-journal-replaced-before-parent-flush", 97, True),
        ("final-replaced", "committed-persisted", 94, True),
        ("final-replaced", "journal-unlinked-before-parent-flush", 98, True),
        ("final-replaced", "journal-deleted", 93, True),
    ],
)
def test_hard_exit_during_install_recovery_converges(
    tmp_path,
    operation_point,
    recovery_point,
    exit_code,
    expected_installed,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = make_gzip_archive(archive, b"backend payload")
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_install,
        args=(str(manager.paths.root), str(archive), digest, operation_point),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode in (52, 53)

    recovery = context.Process(
        target=_crash_install_recovery,
        args=(str(manager.paths.root), recovery_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == exit_code

    installed = manager.list_installed("mihomo")
    assert bool(installed) is expected_installed
    if expected_installed:
        assert installed[0].executable.read_bytes() == b"backend payload"
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows ZIP install recovery hard-exit matrix")
@pytest.mark.parametrize(
    "operation_point,recovery_point,exit_code,expected_installed",
    (
        ("extracting", "staging-child-deleted", 91, False),
        ("extracting", "staging-root-deleted-before-parent-flush", 95, False),
        ("extracting", "staging-tree-deleted", 92, False),
        ("extracting", "journal-deleted", 93, False),
        ("final-replaced", "committed-journal-file-flushed", 96, True),
        ("final-replaced", "committed-journal-replaced-before-parent-flush", 97, True),
        ("final-replaced", "committed-persisted", 94, True),
        ("final-replaced", "journal-unlinked-before-parent-flush", 98, True),
        ("final-replaced", "journal-deleted", 93, True),
    ),
)
def test_windows_hard_exit_during_zip_install_recovery_converges(
    tmp_path,
    operation_point,
    recovery_point,
    exit_code,
    expected_installed,
):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("windows", "amd64", None),
        probe_runner=lambda installed: None,
    )
    manager.paths.ensure()
    archive = tmp_path / "mihomo-1.0.0.zip"
    digest = make_windows_mihomo_zip(archive, b"backend payload")
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_install,
        args=(str(manager.paths.root), str(archive), digest, operation_point, "windows"),
    )
    operation.start()
    operation.join(20)
    assert operation.exitcode in (52, 53)

    recovery = context.Process(
        target=_crash_install_recovery,
        args=(str(manager.paths.root), recovery_point, "windows"),
    )
    recovery.start()
    recovery.join(20)
    assert recovery.exitcode == exit_code

    installed = manager.list_installed("mihomo")
    assert bool(installed) is expected_installed
    if expected_installed:
        assert installed[0].executable.name == "mihomo.exe"
        assert installed[0].executable.read_bytes() == b"backend payload"
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))


def test_public_use_runs_the_activation_transaction(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)
    prepared = []
    original_prepare = activation_module.ActivationTransaction.prepare

    def record_prepare(*args, **kwargs):
        prepared.append((args, kwargs))
        return original_prepare(*args, **kwargs)

    monkeypatch.setattr(
        activation_module.ActivationTransaction,
        "prepare",
        record_prepare,
    )

    active = manager.use("mihomo", "1.0.0")

    assert active.version == "1.0.0"
    assert len(prepared) == 1
    assert not list(manager.paths.runtimes.glob(".use-*.json"))
    assert not list(manager.paths.bin.glob("*.rollback"))
    assert not list(manager.paths.active.glob("*.rollback"))


def test_same_version_use_is_a_verified_zero_write_noop(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    manifest = manager.paths.active / "mihomo.json"
    link = manager.paths.bin / "mihomo"
    before_manifest = manifest.read_bytes()
    before_manifest_status = manifest.stat()
    before_link_status = link.lstat()

    def unexpected_prepare(*args, **kwargs):
        raise AssertionError("same-version use must not prepare a transaction")

    monkeypatch.setattr(
        activation_module.ActivationTransaction,
        "prepare",
        unexpected_prepare,
    )

    active = manager.use("mihomo", "1.0.0")

    assert active.version == "1.0.0"
    assert manifest.read_bytes() == before_manifest
    assert manifest.stat().st_mtime_ns == before_manifest_status.st_mtime_ns
    assert link.lstat().st_ino == before_link_status.st_ino
    assert not list(manager.paths.runtimes.glob(".use-*"))


def test_next_public_read_recovers_an_interrupted_activation(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)
    original_replace = activation_module.durable_replace
    publications = []

    def interrupt_after_link_publication(source, destination, *args, **kwargs):
        result = original_replace(source, destination, *args, **kwargs)
        publications.append(Path(destination))
        if len(publications) == 1:
            raise OSError("simulated hard interruption")
        return result

    monkeypatch.setattr(
        activation_module,
        "durable_replace",
        interrupt_after_link_publication,
    )
    transaction = activation_module.ActivationTransaction.prepare(
        manager.paths,
        manager.platform_info,
        "mihomo",
        "2.0.0",
    )
    with pytest.raises(OSError, match="hard interruption"):
        transaction.execute()
    monkeypatch.setattr(activation_module, "durable_replace", original_replace)

    active = manager.current("mihomo")

    assert active.version == "1.0.0"
    assert active.link.read_bytes() == b"version one"
    assert not list(manager.paths.runtimes.glob(".use-*"))


def test_active_version_removal_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    with pytest.raises(BackendActiveError):
        manager.uninstall("mihomo", "1.0.0")
    assert manager.current("mihomo").version == "1.0.0"


def test_force_remove_deactivates_exact_version(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    manager.uninstall("mihomo", "1.0.0", deactivate=True)
    assert not installed.manifest.parent.exists()
    assert manager.current("mihomo") is None


def test_install_rejects_wrong_digest_without_creating_version(tmp_path):
    manager = manager_for(tmp_path)
    archive = tmp_path / "mihomo.gz"
    make_gzip_archive(archive, b"tampered")
    with pytest.raises(IntegrityError):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256="0" * 64)
    assert manager.list_installed() == []


def test_same_version_same_digest_is_idempotent(tmp_path):
    manager = manager_for(tmp_path)
    first = install_fake_mihomo(manager, tmp_path, "1.0.0", b"same", activate=False)
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    second = manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)
    assert first == second


def test_same_version_different_digest_is_rejected(tmp_path):
    manager = manager_for(tmp_path)
    first = install_fake_mihomo(manager, tmp_path, "1.0.0", b"original", activate=False)
    replacement = tmp_path / "replacement.gz"
    replacement_digest = make_gzip_archive(replacement, b"replacement")

    with pytest.raises(BackendAlreadyInstalledError, match="different digest"):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            replacement,
            expected_sha256=replacement_digest,
        )

    assert manager.get_installed("mihomo", "1.0.0") == first


def test_failed_archive_install_cleans_staging_directory(tmp_path):
    manager = manager_for(tmp_path)
    archive = tmp_path / "broken.gz"
    archive.write_bytes(b"not-gzip")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    with pytest.raises(ArchiveError, match="invalid GZip"):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)

    backend_root = manager.paths.backends / "mihomo"
    assert not (backend_root / "1.0.0").exists()
    assert not list(backend_root.glob(".1.0.0.install-*"))
    assert not list(manager.paths.runtimes.glob(".install-*"))


def test_manager_archive_limits_reject_streamed_expansion_without_publication(tmp_path):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
        archive_limits=archive_module.ArchiveLimits(
            maximum_file_bytes=4,
            maximum_extracted_bytes=4,
        ),
    )
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"backend")

    with pytest.raises(ArchiveError, match="expanded content exceeds"):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
        )

    assert manager.list_installed("mihomo") == []
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))


@pytest.mark.parametrize(
    ("archive_type", "filename"),
    (("gzip", "mihomo.gz"), ("zip", "mihomo.zip"), ("tar", "mihomo.tar.gz")),
)
def test_manager_install_accepts_each_archive_family_at_exact_expansion_limits(
    tmp_path,
    archive_type,
    filename,
):
    payload = b"backend"
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
        archive_limits=archive_module.ArchiveLimits(
            maximum_file_bytes=len(payload),
            maximum_extracted_bytes=len(payload),
        ),
    )
    archive = tmp_path / filename
    digest = make_backend_archive(archive, archive_type, payload)

    installed = manager.install_from_archive(
        "mihomo",
        "1.0.0",
        archive,
        expected_sha256=digest,
    )

    assert installed.executable.read_bytes() == payload
    assert manager.get_installed("mihomo", "1.0.0") == installed
    assert not list(manager.paths.runtimes.glob(".install-*"))


@pytest.mark.parametrize(
    ("archive_type", "filename"),
    (("gzip", "mihomo.gz"), ("zip", "mihomo.zip"), ("tar", "mihomo.tar.gz")),
)
def test_manager_install_rejects_each_archive_family_limit_plus_one_without_publication(
    tmp_path,
    archive_type,
    filename,
):
    payload = b"backend"
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
        archive_limits=archive_module.ArchiveLimits(
            maximum_file_bytes=len(payload) - 1,
            maximum_extracted_bytes=len(payload) - 1,
        ),
    )
    archive = tmp_path / filename
    digest = make_backend_archive(archive, archive_type, payload)

    with pytest.raises(ArchiveError, match="exceed"):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
        )

    assert manager.list_installed("mihomo") == []
    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".*.install-*"))


def test_manager_archive_limits_cannot_relax_the_builtin_safety_budget(tmp_path):
    with pytest.raises(ValueError, match="cannot exceed the built-in safety budget"):
        BackendManager(
            JerryProxyPaths(tmp_path / ".jerryproxy"),
            platform_info=PlatformInfo("linux", "amd64", "glibc"),
            probe_runner=lambda installed: None,
            archive_limits=archive_module.ArchiveLimits(
                maximum_compressed_bytes=archive_module.ArchiveLimits().maximum_compressed_bytes + 1,
            ),
        )


@pytest.mark.parametrize("archive_limits", (object(), archive_module.ArchiveLimits(maximum_members=0)))
def test_manager_rejects_invalid_archive_limit_objects(tmp_path, archive_limits):
    expected = TypeError if not isinstance(archive_limits, archive_module.ArchiveLimits) else ValueError

    with pytest.raises(expected):
        BackendManager(
            JerryProxyPaths(tmp_path / ".jerryproxy"),
            platform_info=PlatformInfo("linux", "amd64", "glibc"),
            probe_runner=lambda installed: None,
            archive_limits=archive_limits,
        )


def test_install_rejects_an_exact_archive_size_mismatch_before_publication(tmp_path):
    manager = manager_for(tmp_path)
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"backend")

    with pytest.raises(IntegrityError, match="asset size mismatch"):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
            expected_size=archive.stat().st_size + 1,
        )

    assert manager.list_installed("mihomo") == []
    assert not list(manager.paths.runtimes.glob(".install-*"))


def test_idempotent_install_rejects_an_incompatible_recorded_platform(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    value = read_json(installed.manifest)
    value["platform"] = "windows-amd64"
    atomic_write_json(installed.manifest, value)
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    with pytest.raises(IntegrityError, match="targets windows-amd64"):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)


@pytest.mark.skipif(os.name != "posix", reason="POSIX post-manifest executable replacement")
@pytest.mark.parametrize("replacement", ("tampered", "directory"))
def test_idempotent_install_rechecks_executable_after_manifest_load(tmp_path, monkeypatch, replacement):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    original_load = manager_module.load_installed_manifest

    def replace_after_load(paths, manifest):
        result = original_load(paths, manifest)
        installed.executable.unlink()
        if replacement == "tampered":
            installed.executable.write_bytes(b"changed")
            installed.executable.chmod(0o755)
        else:
            installed.executable.mkdir()
        return result

    monkeypatch.setattr(manager_module, "load_installed_manifest", replace_after_load)

    message = "SHA-256 mismatch" if replacement == "tampered" else "missing or unsafe"
    with pytest.raises(IntegrityError, match=message):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)


def test_install_pins_archive_before_publishing_journal(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    archive = tmp_path / "mihomo.gz"
    original_digest = make_gzip_archive(archive, b"original")
    replacement = tmp_path / "replacement.gz"
    make_gzip_archive(replacement, b"replacement")
    displaced = tmp_path / "displaced.gz"
    original_prepare = installation_module.InstallTransaction.prepare
    observed = []

    def replace_after_pin(cls, paths, backend, version, artifact, operation=None, write_id=None):
        assert artifact["sha256"] == original_digest
        archive.rename(displaced)
        replacement.rename(archive)
        observed.append(artifact["size"])
        return original_prepare(
            paths,
            backend,
            version,
            artifact,
            operation=operation,
            write_id=write_id,
        )

    monkeypatch.setattr(
        installation_module.InstallTransaction,
        "prepare",
        classmethod(replace_after_pin),
    )
    installed = manager.install_from_archive(
        "mihomo",
        "1.0.0",
        archive,
        expected_sha256=original_digest,
    )

    assert observed == [displaced.stat().st_size]
    assert installed.executable.read_bytes() == b"original"
    assert gzip.decompress(archive.read_bytes()) == b"replacement"


def test_install_failure_after_journal_publication_recovers_under_same_lock(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"backend")
    original_extract = manager_module.PinnedArchive.extract

    def fail_after_staging(source, destination, standalone_name, output_tree=None):
        journals = list(manager.paths.runtimes.glob(".install-*.json"))
        assert len(journals) == 1
        assert ".install-" in destination.name
        assert destination.is_dir()
        assert output_tree is not None
        raise ArchiveError("injected extraction failure")

    monkeypatch.setattr(manager_module.PinnedArchive, "extract", fail_after_staging)
    with pytest.raises(ArchiveError, match="injected extraction failure"):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)

    assert not list(manager.paths.runtimes.glob(".install-*"))
    assert not list((manager.paths.backends / "mihomo").glob(".1.0.0.install-*"))
    monkeypatch.setattr(manager_module.PinnedArchive, "extract", original_extract)


def test_missing_install_and_missing_executable_fail_through_public_lookup(tmp_path):
    manager = manager_for(tmp_path)
    with pytest.raises(BackendNotInstalledError, match="is not installed"):
        manager.get_installed("mihomo", "1.0.0")

    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    installed.executable.unlink()
    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.get_installed("mihomo", "1.0.0")


def test_install_resolves_downloads_and_activates_exact_release(tmp_path):
    source = tmp_path / "upstream.gz"
    payload = b"#!/bin/sh\nprintf 'Mihomo Meta v1.19.29\\n'\n"
    digest = make_gzip_archive(source, payload)
    asset_name = "mihomo-linux-amd64-v1.19.29.gz"
    asset = CatalogArtifact(
        backend="mihomo",
        version="1.19.29",
        platform="linux-amd64",
        asset_id=1,
        name=asset_name,
        url=("https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/%s" % asset_name),
        sha256=digest,
        size=source.stat().st_size,
        updated_at="2026-01-01T00:00:00Z",
        verification="github-release-digest",
        archive_format="gz",
        executable="mihomo",
    )

    class Catalog(object):
        generated_at = "2026-01-01T00:00:00Z"

        def resolve(self, name, version, platform_info):
            assert name == "mihomo"
            assert version == "v1.19.29"
            assert platform_info.asset_key == "linux-amd64-glibc"
            return asset

    class Downloader(object):
        def download_sources(self, sources, destination, expected_sha256, expected_size=None):
            assert [source.label for source in sources] == [
                "direct",
                "gh-proxy.com",
                "cdn.akaere.online",
                "gh.geekertao.top",
            ]
            assert sources[0].url == asset.url
            assert expected_sha256 == digest
            assert expected_size == source.stat().st_size
            with pytest.raises(JerryProxyBusyError):
                with JerryProxyOperationLock(paths):
                    pass
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(source), str(destination))
            return destination

    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    probe_calls = []

    def probe(installed):
        probe_calls.append(installed.version)
        with pytest.raises(JerryProxyBusyError):
            with JerryProxyOperationLock(paths):
                pass

    cached_archive = paths.downloads / "mihomo" / "1.19.29" / asset_name
    cached_archive.parent.mkdir(parents=True)
    cached_archive.write_bytes(b"corrupt cached archive")
    manager = BackendManager(
        paths,
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        catalog=Catalog(),
        downloader=Downloader(),
        probe_runner=probe,
    )
    installed = manager.install("mihomo", "v1.19.29", relay="auto")

    assert installed.version == "1.19.29"
    assert installed.executable.read_bytes() == payload
    assert installed.asset_name == asset_name
    assert manager.current("mihomo").version == "1.19.29"
    assert cached_archive.read_bytes() == source.read_bytes()
    assert probe_calls == ["1.19.29", "1.19.29"]


def test_verify_detects_installed_executable_tampering(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"original", activate=False)

    assert manager.verify("mihomo") == [installed]
    installed.executable.write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="executable SHA-256 mismatch"):
        manager.verify("mihomo")
    with pytest.raises(IntegrityError, match="executable SHA-256 mismatch"):
        manager.use("mihomo", "1.0.0")
    assert manager.current("mihomo") is None


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative verification requires POSIX")
def test_verify_does_not_reopen_installed_executable_by_path(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"original", activate=False)
    original_open = Path.open

    def deny_executable_path_open(path, *args, **kwargs):
        if path == installed.executable:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_executable_path_open)

    assert manager.verify("mihomo") == [installed]


@pytest.mark.skipif(os.name == "nt", reason="POSIX active-link validation")
def test_which_validates_current_and_exact_installed_executables(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"original", activate=True)

    current = manager.which("mihomo")
    exact = manager.which("mihomo", "1.0.0")

    assert current.version == installed.version
    assert current.executable == installed.executable
    assert current.link.is_symlink()
    assert exact == installed

    installed.executable.write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="executable SHA-256 mismatch"):
        manager.which("mihomo")
    with pytest.raises(IntegrityError, match="executable SHA-256 mismatch"):
        manager.which("mihomo", "1.0.0")


def test_which_rejects_missing_current_missing_version_and_malformed_version(tmp_path):
    manager = manager_for(tmp_path)

    with pytest.raises(BackendNotInstalledError, match="has no current version"):
        manager.which("mihomo")
    with pytest.raises(BackendNotInstalledError, match="is not installed"):
        manager.which("mihomo", "1.0.0")
    with pytest.raises(ValueError, match="invalid backend version"):
        manager.which("mihomo", "../outside")
    assert not manager.paths.root.exists()


def test_install_probes_the_staged_executable_before_publication(tmp_path, monkeypatch):
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return manager_module.subprocess.CompletedProcess(arguments, 0, stdout="Mihomo Meta v1.0.0\n")

    monkeypatch.setattr(manager_module.subprocess, "run", run)
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
    )
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)

    assert installed.manifest.is_file()
    assert calls[0][0][-1] == "-v"
    assert calls[0][1]["timeout"] == 20
    manager.use("mihomo", "1.0.0")
    assert len(calls) == 2


def test_failed_staging_probe_leaves_no_installed_version(tmp_path):
    def reject(installed):
        raise IntegrityError("probe rejected")

    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=reject,
    )

    with pytest.raises(IntegrityError, match="probe rejected"):
        install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    assert manager.list_installed("mihomo") == []


def test_copied_home_cannot_activate_another_platform_binary(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"linux", activate=False)
    value = read_json(installed.manifest)
    value["platform"] = "windows-amd64"
    atomic_write_json(installed.manifest, value)

    with pytest.raises(BackendNotInstalledError, match="was installed for windows-amd64"):
        manager.use("mihomo", "1.0.0")


def test_installed_manifest_identity_must_match_its_directory(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    value = read_json(installed.manifest)
    value["version"] = "2.0.0"
    atomic_write_json(installed.manifest, value)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.list_installed("mihomo")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_installed_manifest_rejects_an_executable_symlink_escape(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    installed.executable.unlink()
    installed.executable.symlink_to(outside)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.get_installed("mihomo", "1.0.0")


@pytest.mark.skipif(os.name != "nt", reason="Windows junction containment behavior")
def test_installed_manifest_rejects_an_executable_junction_escape(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside = tmp_path / "outside-executable"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    installed.executable.unlink()
    create_windows_junction(installed.executable, outside)

    try:
        with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
            manager.get_installed("mihomo", "1.0.0")
        assert marker.read_bytes() == b"outside"
    finally:
        if removal_module.is_path_alias(installed.executable):
            os.rmdir(str(installed.executable))


def test_active_manifest_rejects_paths_outside_the_home(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["executable"] = "../outside"
    atomic_write_json(manifest, value)

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


def test_install_sing_box_from_nested_release_archive(tmp_path):
    manager = manager_for(tmp_path)
    archive = tmp_path / "sing-box-1.13.14-linux-amd64.tar.gz"
    payload = b"sing-box executable"
    member = tarfile.TarInfo("sing-box-1.13.14-linux-amd64/sing-box")
    member.size = len(payload)
    with tarfile.open(str(archive), "w:gz") as stream:
        stream.addfile(member, io.BytesIO(payload))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    installed = manager.install_from_archive(
        "sing-box",
        "1.13.14",
        archive,
        expected_sha256=digest,
        activate=True,
    )

    assert installed.executable.name == "sing-box"
    assert installed.executable.read_bytes() == payload
    assert manager.current("sing-box").version == "1.13.14"


def test_switch_rolls_back_link_and_manifest_on_write_failure(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)
    original_manifest = read_json(manager.paths.active / "mihomo.json")

    def fail_manifest_write(*args, **kwargs):
        raise OSError("simulated manifest failure")

    monkeypatch.setattr(activation_module, "_write_manifest_candidate", fail_manifest_write)
    with pytest.raises(OSError, match="simulated manifest failure"):
        manager.use("mihomo", "2.0.0")

    assert manager.current("mihomo").version == "1.0.0"
    assert (manager.paths.bin / "mihomo").read_bytes() == b"version one"
    assert read_json(manager.paths.active / "mihomo.json") == original_manifest


def test_switch_retains_journal_and_chains_error_when_recovery_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    def fail_manifest_write(*args, **kwargs):
        raise OSError("simulated publication failure")

    def fail_recovery(*args, **kwargs):
        raise IntegrityError("simulated recovery failure")

    monkeypatch.setattr(activation_module, "_write_manifest_candidate", fail_manifest_write)
    monkeypatch.setattr(manager_module, "recover_use_transactions", fail_recovery)

    with pytest.raises(IntegrityError, match="simulated recovery failure") as captured:
        manager.use("mihomo", "2.0.0")

    assert isinstance(captured.value.__cause__, OSError)
    assert list(manager.paths.runtimes.glob(".use-*.json"))
    assert not list(manager.paths.bin.glob("*.rollback"))
    assert not list(manager.paths.active.glob("*.rollback"))


def test_first_switch_removes_new_link_when_manifest_write_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)

    def fail_manifest_write(*args, **kwargs):
        raise OSError("simulated first manifest failure")

    monkeypatch.setattr(activation_module, "_write_manifest_candidate", fail_manifest_write)
    with pytest.raises(OSError, match="simulated first manifest failure"):
        manager.use("mihomo", "1.0.0")

    assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
    assert not (manager.paths.active / "mihomo.json").exists()


def test_current_rejects_an_active_backend_with_missing_executable(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    installed.executable.unlink()

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


def test_switch_does_not_delete_an_unowned_legacy_temporary(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)
    temporary = manager.paths.bin / (".mihomo.%s.tmp" % os.getpid())
    temporary.write_bytes(b"stale")

    active = manager.use("mihomo", "1.0.0")

    assert active.link.read_bytes() == b"version one"
    assert temporary.read_bytes() == b"stale"


def test_switch_cleans_temporary_link_when_atomic_replace_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)

    def fail_replace(source, destination, *args, **kwargs):
        del source, destination, args, kwargs
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(activation_module, "durable_replace", fail_replace)
    with pytest.raises(OSError, match="simulated atomic replace failure"):
        manager.use("mihomo", "1.0.0")

    assert manager.current("mihomo") is None
    assert not list(manager.paths.bin.glob(".mihomo.*.tmp"))


def test_backend_operations_share_one_home_wide_lock(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    with JerryProxyOperationLock(manager.paths):
        with pytest.raises(JerryProxyBusyError):
            manager.use("mihomo", "2.0.0")
        with pytest.raises(JerryProxyBusyError):
            manager.uninstall("mihomo", "2.0.0")
        with pytest.raises(JerryProxyBusyError):
            manager.uninstall_all("mihomo")
        with pytest.raises(JerryProxyBusyError):
            manager.clean("mihomo")
        with pytest.raises(JerryProxyBusyError):
            manager.list_installed()
        with pytest.raises(JerryProxyBusyError):
            manager.inventory()
        with pytest.raises(JerryProxyBusyError):
            manager.get_installed("mihomo", "1.0.0")
        with pytest.raises(JerryProxyBusyError):
            manager.verify("mihomo")
        with pytest.raises(JerryProxyBusyError):
            manager.current("mihomo")
        with pytest.raises(JerryProxyBusyError):
            manager.list_active()
        with pytest.raises(JerryProxyBusyError):
            manager.list_cached_versions()
        with pytest.raises(JerryProxyBusyError):
            manager.which("mihomo")
        archive = tmp_path / "mihomo-1.0.0.gz"
        with pytest.raises(JerryProxyBusyError):
            manager.install_from_archive(
                "mihomo",
                "1.0.0",
                archive,
                expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            )


def test_inventory_returns_one_installed_and_active_snapshot(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)

    inventory = manager.inventory("mihomo")

    assert inventory.installed == (installed,)
    assert len(inventory.active) == 1
    assert inventory.active[0].version == installed.version


def test_inventory_does_not_initialize_an_empty_home(tmp_path):
    manager = manager_for(tmp_path)

    inventory = manager.inventory()

    assert inventory.installed == ()
    assert inventory.active == ()
    assert manager.list_installed() == []
    assert manager.list_active() == []
    assert manager.current("mihomo") is None
    assert manager.verify() == []
    assert manager.list_cached_versions() == {
        "mihomo": (),
        "sing-box": (),
        "v2ray": (),
        "xray": (),
    }
    assert not manager.paths.root.exists()


def test_exact_reads_on_an_empty_home_fail_without_initializing_it(tmp_path):
    manager = manager_for(tmp_path)

    with pytest.raises(ValueError, match="requires a backend name"):
        manager.verify(version="1.0.0")
    with pytest.raises(BackendNotInstalledError, match="mihomo 1.0.0 is not installed"):
        manager.verify("mihomo", "1.0.0")

    assert not manager.paths.root.exists()


@pytest.mark.parametrize("existing", ["file", "foreign-content"])
def test_inventory_rejects_an_existing_non_managed_home(tmp_path, existing):
    manager = manager_for(tmp_path)
    if existing == "file":
        manager.paths.root.write_bytes(b"not a directory")
    else:
        manager.paths.root.mkdir()
        (manager.paths.root / "foreign.txt").write_bytes(b"not managed state")

    with pytest.raises(IntegrityError, match="home is not a directory|home is incomplete"):
        manager.inventory()


def test_exact_reads_reject_missing_targets_in_a_complete_home(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()

    with pytest.raises(BackendNotInstalledError, match="mihomo 1.0.0 is not installed"):
        manager.get_installed("mihomo", "1.0.0")
    with pytest.raises(BackendNotInstalledError, match="mihomo has no current version"):
        manager.which("mihomo")


@pytest.mark.parametrize("areas", [("backends",), ("locks",), ("locks", "backends")])
def test_inventory_rejects_partial_managed_state_without_repair(tmp_path, areas):
    manager = manager_for(tmp_path)
    for area in areas:
        getattr(manager.paths, area).mkdir(parents=True, exist_ok=True)

    with pytest.raises(IntegrityError, match="home is incomplete"):
        manager.inventory()

    assert not manager.paths.lock_file.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission validation")
@pytest.mark.parametrize("area", ["root", "locks", "backends", "lock_file"])
def test_inventory_rejects_unsafe_existing_layout_permissions_without_repair(tmp_path, area):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = getattr(manager.paths, area)
    target.chmod(0o777 if area != "lock_file" else 0o666)

    with pytest.raises(IntegrityError, match="unsafe permissions"):
        manager.inventory()

    expected = 0o777 if area != "lock_file" else 0o666
    assert target.stat().st_mode & 0o777 == expected


@pytest.mark.skipif(os.name != "posix", reason="POSIX filelock retains its lock file")
def test_inventory_rejects_a_missing_existing_lock_file_without_recreating_it(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    manager.paths.lock_file.unlink()

    with pytest.raises(IntegrityError, match="home is incomplete"):
        manager.inventory()

    assert not manager.paths.lock_file.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows filelock removes its lock file")
def test_inventory_accepts_a_complete_windows_layout_without_a_persistent_lock_file(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    if manager.paths.lock_file.exists():
        manager.paths.lock_file.unlink()

    inventory = manager.inventory()

    assert inventory.installed == ()
    assert inventory.active == ()


def test_clean_download_cache_by_version_backend_and_all(tmp_path):
    manager = manager_for(tmp_path)
    paths = manager.paths
    first = paths.downloads / "mihomo" / "1.0.0" / "first.gz"
    second = paths.downloads / "mihomo" / "2.0.0" / "second.gz"
    other = paths.downloads / "xray" / "1.0.0" / "other.zip"
    for path, payload in ((first, b"one"), (second, b"two"), (other, b"other")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    exact = manager.clean("mihomo", "1.0.0")
    assert exact.targets_removed == 1
    assert exact.bytes_reclaimed == 3
    assert not first.exists()
    assert second.is_file()
    assert other.is_file()

    backend = manager.clean("mihomo")
    assert backend.targets_removed == 1
    assert backend.bytes_reclaimed == 3
    assert not second.exists()
    assert other.is_file()

    everything = manager.clean()
    assert everything.areas == ("downloads",)
    assert everything.targets_removed == 1
    assert everything.bytes_reclaimed == 5
    assert list(paths.downloads.iterdir()) == []


def test_clean_global_areas_preserves_installs_active_links_and_locks(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    for root, filename in (
        (manager.paths.downloads, "archive"),
        (manager.paths.logs, "backend.log"),
        (manager.paths.providers, "provider.yaml"),
        (manager.paths.runtimes, "runtime.json"),
    ):
        (root / filename).write_bytes(b"data")

    result = manager.clean(areas=("downloads", "logs", "providers", "runtimes"))

    assert result.targets_removed == 4
    assert result.bytes_reclaimed == 16
    assert installed.manifest.is_file()
    assert manager.current("mihomo").version == "1.0.0"
    assert manager.paths.locks.is_dir()


def test_clean_is_idempotent_and_lists_cached_versions(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    cache = manager.paths.downloads / "mihomo" / "2.0.0" / "asset.gz"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"asset")

    assert manager.list_cached_versions("mihomo")["mihomo"] == ("2.0.0",)
    assert manager.clean("mihomo", "2.0.0").targets_removed == 1
    assert manager.clean("mihomo", "2.0.0").targets_removed == 0
    assert manager.list_cached_versions("mihomo")["mihomo"] == ()


def test_clean_tolerates_a_target_disappearing_after_collection(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    (target / "asset.gz").write_bytes(b"asset")
    original_lexists = os.path.lexists
    target_checks = []

    def remove_before_cleanup(path):
        if path == str(target):
            target_checks.append(path)
            if len(target_checks) == 2:
                shutil.rmtree(path)
                return False
        return original_lexists(path)

    monkeypatch.setattr(manager_module.os.path, "lexists", remove_before_cleanup)

    result = manager.clean("mihomo", "1.0.0")

    assert result.targets_removed == 0
    assert result.bytes_reclaimed == 0
    assert len(target_checks) == 2


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_clean_revalidates_ancestors_immediately_before_removal(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    backend_root = manager.paths.downloads / "mihomo"
    target = backend_root / "1.0.0"
    target.mkdir(parents=True)
    (target / "cached.gz").write_bytes(b"managed")
    outside = tmp_path / "outside"
    outside_target = outside / "1.0.0"
    outside_target.mkdir(parents=True)
    outside_asset = outside_target / "must-survive.gz"
    outside_asset.write_bytes(b"outside")
    saved_root = manager.paths.downloads / "mihomo-original"
    original_lexists = os.path.lexists
    swapped = []

    def swap_ancestor_before_removal(path):
        if path == str(target) and not swapped:
            backend_root.rename(saved_root)
            backend_root.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_lexists(path)

    monkeypatch.setattr(manager_module.os.path, "lexists", swap_ancestor_before_removal)

    with pytest.raises(manager_module.CleanupScopeError, match="managed symlink"):
        manager.clean("mihomo", "1.0.0")

    assert swapped == [str(target)]
    assert outside_asset.read_bytes() == b"outside"
    assert (saved_root / "1.0.0" / "cached.gz").read_bytes() == b"managed"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_clean_revalidates_ancestors_after_size_measurement(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    backend_root = manager.paths.downloads / "mihomo"
    target = backend_root / "1.0.0"
    target.mkdir(parents=True)
    (target / "cached.gz").write_bytes(b"managed")
    outside = tmp_path / "outside"
    outside_target = outside / "1.0.0"
    outside_target.mkdir(parents=True)
    outside_asset = outside_target / "must-survive.gz"
    outside_asset.write_bytes(b"outside")
    saved_root = manager.paths.downloads / "mihomo-original"
    original_iterdir = Path.iterdir
    swapped = []

    def swap_ancestor_during_measurement(path):
        if path == target and not swapped:
            backend_root.rename(saved_root)
            backend_root.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", swap_ancestor_during_measurement)

    with pytest.raises(manager_module.CleanupScopeError, match="managed symlink"):
        manager.clean("mihomo", "1.0.0")

    assert swapped == [target]
    assert outside_asset.read_bytes() == b"outside"
    assert (saved_root / "1.0.0" / "cached.gz").read_bytes() == b"managed"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_clean_rejects_a_nested_alias_swapped_in_after_measurement(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    nested = target / "nested"
    nested.mkdir(parents=True)
    (nested / "managed.gz").write_bytes(b"managed")
    outside = tmp_path / "outside-after-measurement"
    outside.mkdir()
    marker = outside / "must-survive.gz"
    marker.write_bytes(b"outside")
    saved_nested = target / "nested-original"
    original_iterdir = Path.iterdir
    target_reads = []

    def swap_nested_during_removal(path):
        if path == target:
            target_reads.append(path)
            if len(target_reads) == 2:
                nested.rename(saved_nested)
                nested.symlink_to(outside, target_is_directory=True)
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", swap_nested_during_removal)

    with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
        manager.clean("mihomo", "1.0.0")

    assert marker.read_bytes() == b"outside"
    assert (saved_nested / "managed.gz").read_bytes() == b"managed"


@pytest.mark.parametrize(
    ("target_read", "message"),
    [
        (1, "changed during measurement"),
        (2, "changed during validation"),
    ],
)
def test_clean_rejects_a_directory_replaced_in_each_deletion_window(
    tmp_path,
    monkeypatch,
    target_read,
    message,
):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    (target / "managed.gz").write_bytes(b"managed")
    saved = manager.paths.downloads / ("saved-%d" % target_read)
    original_iterdir = Path.iterdir
    reads = []

    def replace_directory_during_iteration(path):
        entries = list(original_iterdir(path))
        if path == target:
            reads.append(path)
            if len(reads) == target_read:
                target.rename(saved)
                target.mkdir()
        return iter(entries)

    monkeypatch.setattr(Path, "iterdir", replace_directory_during_iteration)

    with pytest.raises(manager_module.CleanupScopeError, match=message):
        manager.clean("mihomo", "1.0.0")

    assert (saved / "managed.gz").read_bytes() == b"managed"
    assert target.is_dir()


@pytest.mark.parametrize("replace_parent", (False, True))
def test_clean_handles_a_directory_removed_or_replaced_after_its_last_child(
    tmp_path,
    monkeypatch,
    replace_parent,
):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    child = target / "managed.gz"
    child.write_bytes(b"managed")
    if os.name == "posix":
        original_unlink = removal_module.os.unlink

        def remove_parent_after_last_child(path, *args, **kwargs):
            result = original_unlink(path, *args, **kwargs)
            if Path(path).name == child.name:
                target.rmdir()
                if replace_parent:
                    target.mkdir()
            return result

        monkeypatch.setattr(removal_module.os, "unlink", remove_parent_after_last_child)
    elif replace_parent:
        original_delete = removal_module._delete_windows_guard
        original_lstat = removal_module._lstat
        changed = []

        def delete_child_then_change_parent_identity(descriptor, expect_directory):
            result = original_delete(descriptor, expect_directory)
            if descriptor.path == child:
                changed.append(target)
            return result

        def changed_parent_status(path):
            status = original_lstat(path)
            if path != target or not changed or status is None:
                return status

            class ChangedStatus(object):
                def __getattr__(self, name):
                    if name == "st_ino":
                        return status.st_ino + 1
                    return getattr(status, name)

            return ChangedStatus()

        monkeypatch.setattr(removal_module, "_delete_windows_guard", delete_child_then_change_parent_identity)
        monkeypatch.setattr(removal_module, "_lstat", changed_parent_status)

    if replace_parent:
        with pytest.raises(manager_module.CleanupScopeError, match="directory changed before final deletion"):
            manager.clean("mihomo", "1.0.0")
        assert target.is_dir()
    else:
        assert manager.clean("mihomo", "1.0.0").targets_removed == 1
        assert not target.exists()


@pytest.mark.parametrize("alias_check", (2, 4, 6))
def test_clean_rejects_a_file_becoming_an_alias_between_identity_checks(
    tmp_path,
    monkeypatch,
    alias_check,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    original_is_alias = removal_module.is_path_alias
    checks = []

    def report_alias_at_selected_check(path):
        if path == target:
            checks.append(path)
            if len(checks) == alias_check:
                return True
        return original_is_alias(path)

    monkeypatch.setattr(removal_module, "is_path_alias", report_alias_at_selected_check)

    with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
        manager.clean(areas=("logs",))

    assert target.read_bytes() == b"managed"


@pytest.mark.parametrize("replace_file", (False, True))
def test_clean_handles_a_file_removed_or_replaced_before_unlink(
    tmp_path,
    monkeypatch,
    replace_file,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    original_lstat = removal_module._lstat
    checks = []

    def change_file_before_final_lstat(path):
        if path == target:
            checks.append(path)
            if len(checks) == 4:
                path.unlink()
                if replace_file:
                    path.write_bytes(b"replacement")
                else:
                    return None
        return original_lstat(path)

    monkeypatch.setattr(removal_module, "_lstat", change_file_before_final_lstat)

    if replace_file:
        with pytest.raises(manager_module.CleanupScopeError, match="changed before deletion"):
            manager.clean(areas=("logs",))
        assert target.read_bytes() == b"replacement"
    else:
        assert manager.clean(areas=("logs",)).targets_removed == 1
        assert not target.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity guard behavior")
def test_clean_fails_closed_when_a_target_cannot_be_pinned(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    original_open = removal_module.os.open

    def deny_target_open(path, flags, *args, **kwargs):
        if Path(path) == target:
            raise PermissionError("identity handle denied")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(removal_module.os, "open", deny_target_open)

    with pytest.raises(manager_module.CleanupScopeError, match="unable to pin managed removal path"):
        manager.clean(areas=("logs",))

    assert target.read_bytes() == b"managed"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_clean_revalidates_ancestors_after_identity_guard_acquisition(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    outside = tmp_path / "outside-logs"
    original_open = removal_module.os.open
    swapped = []

    def swap_parent_before_target_open(path, flags, *args, **kwargs):
        if Path(path) == target and not swapped:
            manager.paths.logs.rename(outside)
            manager.paths.logs.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(removal_module.os, "open", swap_parent_before_target_open)

    with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
        manager.clean(areas=("logs",))

    assert (outside / target.name).read_bytes() == b"managed"
    assert manager.paths.logs.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity guard behavior")
@pytest.mark.parametrize("replacement", ("file", "alias", "missing-after-open"))
def test_clean_fails_closed_when_parent_guard_cannot_be_established(
    tmp_path,
    monkeypatch,
    replacement,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    saved = tmp_path / ("saved-logs-" + replacement)
    original_lstat = removal_module._lstat
    parent_reads = []

    def replace_parent_during_guard(path):
        if path != manager.paths.logs:
            return original_lstat(path)
        parent_reads.append(path)
        if replacement == "missing-after-open" and len(parent_reads) == 2:
            manager.paths.logs.rename(saved)
            return None
        if len(parent_reads) == 1 and replacement in ("file", "alias"):
            status = original_lstat(path)
            manager.paths.logs.rename(saved)
            if replacement == "file":
                manager.paths.logs.write_bytes(b"replacement")
                return original_lstat(path)
            manager.paths.logs.symlink_to(saved, target_is_directory=True)
            return status
        return original_lstat(path)

    monkeypatch.setattr(removal_module, "_lstat", replace_parent_during_guard)

    expected = {
        "file": "parent is not a directory",
        "alias": "managed symlink",
        "missing-after-open": "parent disappeared",
    }[replacement]
    with pytest.raises(manager_module.CleanupScopeError, match=expected):
        manager.clean(areas=("logs",))

    assert (saved / target.name).read_bytes() == b"managed"


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity guard behavior")
def test_clean_releases_parent_guard_when_post_open_validation_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    saved = tmp_path / "saved-logs-after-open"
    original_open = removal_module.os.open
    original_fstat = removal_module.os.fstat
    original_close = removal_module.os.close
    parent_descriptors = []
    swapped = []
    closed = []

    def record_parent_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == manager.paths.logs and not parent_descriptors:
            parent_descriptors.append(descriptor)
        return descriptor

    def swap_parent_after_fstat(descriptor):
        status = original_fstat(descriptor)
        if descriptor in parent_descriptors and not swapped:
            manager.paths.logs.rename(saved)
            manager.paths.logs.symlink_to(saved, target_is_directory=True)
            swapped.append(descriptor)
        return status

    def record_parent_close(descriptor):
        if descriptor in parent_descriptors:
            closed.append(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(removal_module.os, "open", record_parent_open)
    monkeypatch.setattr(removal_module.os, "fstat", swap_parent_after_fstat)
    monkeypatch.setattr(removal_module.os, "close", record_parent_close)

    with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
        manager.clean(areas=("logs",))

    assert closed == parent_descriptors
    assert (saved / target.name).read_bytes() == b"managed"


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd deletion behavior")
def test_clean_final_unlink_cannot_be_redirected_by_an_ancestor_swap(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    saved = manager.paths.root / "saved-logs"
    outside = tmp_path / "outside-logs"
    outside.mkdir()
    victim = outside / target.name
    victim.write_bytes(b"outside")
    original_unlink = removal_module.os.unlink
    swapped = []

    def swap_parent_at_unlink(path, *args, **kwargs):
        if Path(path).name == target.name and kwargs.get("dir_fd") is not None and not swapped:
            manager.paths.logs.rename(saved)
            manager.paths.logs.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(removal_module.os, "unlink", swap_parent_at_unlink)

    with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
        manager.clean(areas=("logs",))

    assert victim.read_bytes() == b"outside"
    assert not (saved / target.name).exists()
    assert manager.paths.logs.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd deletion behavior")
def test_clean_final_rmdir_cannot_be_redirected_by_an_ancestor_swap(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime"
    target.mkdir()
    saved = tmp_path / "saved-logs"
    outside = tmp_path / "outside-logs"
    victim = outside / target.name
    victim.mkdir(parents=True)
    original_rmdir = removal_module.os.rmdir
    swapped = []

    def swap_parent_at_rmdir(path, *args, **kwargs):
        if Path(path).name == target.name and kwargs.get("dir_fd") is not None and not swapped:
            manager.paths.logs.rename(saved)
            manager.paths.logs.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(removal_module.os, "rmdir", swap_parent_at_rmdir)

    with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
        manager.clean(areas=("logs",))

    assert victim.is_dir()
    assert not (saved / target.name).exists()
    assert manager.paths.logs.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity guard behavior")
def test_macos_symlink_identity_guard_uses_o_symlink_when_o_path_is_unavailable(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "target"
    target.write_bytes(b"target")
    link = tmp_path / "link"
    link.symlink_to(target)
    status = link.lstat()
    opened = []
    closed = []
    o_symlink = 0x200000

    def fake_open(path, flags):
        opened.append((Path(path), flags))
        return 91

    fake_os = SimpleNamespace(
        name="posix",
        O_RDONLY=os.O_RDONLY,
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
        O_NONBLOCK=getattr(os, "O_NONBLOCK", 0),
        O_DIRECTORY=getattr(os, "O_DIRECTORY", 0),
        O_SYMLINK=o_symlink,
        open=fake_open,
        fstat=lambda descriptor: status,
        close=lambda descriptor: closed.append(descriptor),
    )
    monkeypatch.setattr(removal_module, "os", fake_os)

    descriptor = removal_module._open_identity_guard(link, status, CleanupScopeError)
    removal_module._close_identity_guard(descriptor)

    assert opened == [(link, o_symlink | fake_os.O_CLOEXEC | fake_os.O_NOFOLLOW | fake_os.O_NONBLOCK)]
    assert closed == [91]


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity guard behavior")
def test_clean_rejects_directory_replacement_before_final_anchored_rmdir(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    target = manager.paths.logs / "runtime"
    target.mkdir(parents=True)
    saved = manager.paths.logs / "saved-runtime"
    original_status = removal_module._posix_child_status
    checks = []

    def replace_before_final_status(parent_descriptor, name, error_type):
        if name == target.name:
            checks.append(name)
            if len(checks) == 2:
                target.rename(saved)
                target.mkdir()
        return original_status(parent_descriptor, name, error_type)

    monkeypatch.setattr(removal_module, "_posix_child_status", replace_before_final_status)

    with pytest.raises(manager_module.CleanupScopeError, match="before final deletion"):
        manager.clean(areas=("logs",))

    assert saved.is_dir()
    assert target.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative recursion")
def test_clean_never_recurses_into_a_directory_replacement_after_pin(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    target = manager.paths.logs / "runtime"
    target.mkdir(parents=True)
    original_child = target / "same-name"
    original_child.write_bytes(b"managed")
    displaced = manager.paths.logs / "runtime-displaced"
    replacement_child = target / "same-name"
    original_open_guard = removal_module._open_identity_guard
    original_matches_guard = removal_module._matches_guard
    pinned_target = []
    swapped = []

    def record_target_guard(path, status, error_type):
        descriptor = original_open_guard(path, status, error_type)
        if path == target:
            pinned_target.append(descriptor)
        return descriptor

    def swap_after_target_validation(status, original, descriptor):
        matches = original_matches_guard(status, original, descriptor)
        if descriptor in pinned_target and matches and not swapped:
            target.rename(displaced)
            target.mkdir()
            replacement_child.write_bytes(b"replacement-must-survive")
            swapped.append(target)
        return matches

    monkeypatch.setattr(removal_module, "_open_identity_guard", record_target_guard)
    monkeypatch.setattr(removal_module, "_matches_guard", swap_after_target_validation)

    with pytest.raises(manager_module.CleanupScopeError):
        manager.clean(areas=("logs",))

    assert (displaced / original_child.name).read_bytes() == b"managed"
    assert replacement_child.read_bytes() == b"replacement-must-survive"


@pytest.mark.skipif(os.name != "posix", reason="POSIX identity guard behavior")
@pytest.mark.parametrize("failure", ("fstat", "mismatch"))
def test_clean_fails_closed_when_a_pinned_target_cannot_be_identified(
    tmp_path,
    monkeypatch,
    failure,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    original_open = removal_module.os.open
    original_fstat = removal_module.os.fstat
    original_close = removal_module.os.close
    target_descriptors = set()
    closed = []

    def record_target_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == target:
            target_descriptors.add(descriptor)
        return descriptor

    def fail_or_change_target_fstat(descriptor):
        status = original_fstat(descriptor)
        if descriptor not in target_descriptors:
            return status
        if failure == "fstat":
            raise OSError("identity unavailable")

        class ChangedStatus(object):
            def __getattr__(self, name):
                if name == "st_ino":
                    return status.st_ino + 1
                return getattr(status, name)

        return ChangedStatus()

    def record_target_close(descriptor):
        if descriptor in target_descriptors:
            closed.append(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(removal_module.os, "open", record_target_open)
    monkeypatch.setattr(removal_module.os, "fstat", fail_or_change_target_fstat)
    monkeypatch.setattr(removal_module.os, "close", record_target_close)

    expected_error = OSError if failure == "fstat" else manager_module.CleanupScopeError
    with pytest.raises(expected_error):
        manager.clean(areas=("logs",))

    assert closed == list(target_descriptors)
    assert target.read_bytes() == b"managed"


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative recursion")
def test_clean_closes_a_child_descriptor_when_descriptor_relative_fstat_fails(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    directory = manager.paths.logs / "runtime"
    directory.mkdir()
    target = directory / "runtime.log"
    target.write_bytes(b"managed")
    original_open = removal_module.os.open
    original_fstat = removal_module.os.fstat
    original_close = removal_module.os.close
    child_descriptors = []
    closed = []

    def record_child_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == Path(target.name) and kwargs.get("dir_fd") is not None:
            child_descriptors.append(descriptor)
        return descriptor

    def fail_child_fstat(descriptor):
        if descriptor in child_descriptors:
            raise OSError("simulated child identity failure")
        return original_fstat(descriptor)

    def record_child_close(descriptor):
        if descriptor in child_descriptors:
            closed.append(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(removal_module.os, "open", record_child_open)
    monkeypatch.setattr(removal_module.os, "fstat", fail_child_fstat)
    monkeypatch.setattr(removal_module.os, "close", record_child_close)

    with pytest.raises(manager_module.CleanupScopeError, match="unable to pin managed removal child"):
        manager.clean(areas=("logs",))

    assert len(child_descriptors) == 1
    assert closed == child_descriptors
    assert target.read_bytes() == b"managed"


@pytest.mark.parametrize("directory", (False, True))
def test_clean_uses_stat_identity_fallback_off_posix(tmp_path, monkeypatch, directory):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / ("runtime" if directory else "runtime.log")
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"managed")
    host_os = removal_module.os

    class NonPosixOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(removal_module, "os", NonPosixOsProxy())
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", None)

    result = manager.clean(areas=("logs",))

    assert result.targets_removed == 1
    assert not target.exists()


def test_clean_simulated_windows_guard_rejects_parent_disappearing_after_pin(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel()
    original_lstat = removal_module._lstat

    def hide_open_parent(path):
        if path == manager.paths.logs and path in kernel.handles.values():
            return None
        return original_lstat(path)

    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_lstat", hide_open_parent)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    with pytest.raises(manager_module.CleanupScopeError, match="parent disappeared"):
        manager.clean(areas=("logs",))

    assert target.read_bytes() == b"managed"
    assert kernel.handles == {}


@pytest.mark.parametrize("directory", (False, True))
def test_clean_deletes_through_a_simulated_windows_identity_handle(tmp_path, monkeypatch, directory):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / ("runtime" if directory else "runtime.log")
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel()
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    result = manager.clean(areas=("logs",))

    assert result.targets_removed == 1
    assert not target.exists()
    assert len(kernel.delete_calls) == 1
    assert kernel.handles == {}


@pytest.mark.parametrize("identity_mode", ("modern-only", "modern-unavailable"))
def test_clean_supports_modern_and_legacy_windows_stat_identities(tmp_path, monkeypatch, identity_mode):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel(failure=identity_mode)
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)

    def unsupported_file_id_error():
        error = OSError("Windows API failure")
        error.winerror = 50
        return error

    monkeypatch.setattr(removal_module, "_windows_error", unsupported_file_id_error)

    status = target.lstat()
    legacy_identity = (
        int(status.st_dev) & 0xFFFFFFFF,
        int(status.st_ino) & 0xFFFFFFFFFFFFFFFF,
    )
    if identity_mode == "modern-unavailable" and legacy_identity != (
        int(status.st_dev),
        int(status.st_ino),
    ):
        with pytest.raises(manager_module.CleanupScopeError, match="changed while pinning"):
            manager.clean(areas=("logs",))

        assert target.read_bytes() == b"managed"
        assert kernel.handles == {}
        return

    result = manager.clean(areas=("logs",))

    assert result.targets_removed == 1
    assert not target.exists()
    assert kernel.handles == {}


@pytest.mark.parametrize("failure", ("modern-zero-id", "modern-zero-volume"))
def test_clean_rejects_incomplete_successful_windows_modern_identity(
    tmp_path,
    monkeypatch,
    failure,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel(failure=failure)
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)

    with pytest.raises(manager_module.CleanupScopeError, match="modern identity"):
        manager.clean(areas=("logs",))

    assert target.read_bytes() == b"managed"
    assert kernel.handles == {}


def test_clean_rejects_switching_between_windows_identity_representations(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel(failure="modern-only")
    original_lstat = removal_module._lstat

    def switch_to_legacy_identity_after_pin(path):
        status = original_lstat(path)
        if path != target or target not in kernel.handles.values():
            return status

        class LegacyIdentityStatus(object):
            def __getattr__(self, name):
                if name == "st_dev" or name == "st_ino":
                    return getattr(status, name) + 1
                return getattr(status, name)

        return LegacyIdentityStatus()

    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_lstat", switch_to_legacy_identity_after_pin)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    with pytest.raises(manager_module.CleanupScopeError, match="changed before deletion"):
        manager.clean(areas=("logs",))

    assert target.read_bytes() == b"managed"
    assert kernel.handles == {}


@pytest.mark.skipif(os.name != "posix", reason="active symbolic-link simulation requires POSIX")
def test_force_remove_deletes_the_allowed_active_symlink_through_a_windows_handle(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    active_link = manager.paths.bin / "mihomo"
    assert active_link.is_symlink()
    kernel = SimulatedWindowsKernel()
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    result = manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert result.versions == ("1.0.0",)
    assert not active_link.exists()
    assert kernel.handles == {}


@pytest.mark.skipif(os.name != "posix", reason="active symbolic-link simulation requires POSIX")
def test_force_remove_tolerates_allowed_active_symlink_disappearing_before_windows_pin(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    kernel = SimulatedWindowsKernel()
    original_lstat = removal_module._lstat
    disappeared = []

    def remove_active_link_before_pin(path):
        if path.name == "active-link" and path.is_symlink() and not disappeared:
            path.unlink()
            disappeared.append(path)
            return None
        return original_lstat(path)

    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))
    monkeypatch.setattr(removal_module, "_lstat", remove_active_link_before_pin)

    result = manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert result.versions == ("1.0.0",)
    assert len(disappeared) == 1
    assert kernel.handles == {}


@pytest.mark.skipif(os.name != "posix", reason="Windows handle API is simulated on POSIX")
@pytest.mark.parametrize("directory", (False, True))
def test_clean_simulated_windows_handle_cannot_be_redirected_by_parent_swap(
    tmp_path,
    monkeypatch,
    directory,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    parent = manager.paths.logs / "runtime"
    parent.mkdir()
    target = parent / ("victim" if directory else "victim.log")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_victim = outside / target.name
    if directory:
        target.mkdir()
        outside_victim.mkdir()
    else:
        target.write_bytes(b"managed")
        outside_victim.write_bytes(b"outside")
    saved = manager.paths.logs / "saved-runtime"

    def redirect_parent(original_path):
        relative_path = original_path.relative_to(parent)
        parent.rename(saved)
        parent.symlink_to(outside, target_is_directory=True)
        return saved / relative_path

    kernel = SimulatedWindowsKernel(before_delete=redirect_parent)
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    try:
        with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
            manager.clean(areas=("logs",))

        assert outside_victim.exists()
        assert not (saved / target.name).exists()
        assert parent.is_symlink()
    finally:
        if parent.is_symlink():
            parent.unlink()
        if saved.exists():
            saved.rename(parent)


@pytest.mark.parametrize(
    "failure",
    (
        "create",
        "information",
        "identity",
        "links",
        "type",
        "size",
        "parent-volume",
        "target-volume",
        "modern-denied",
        "delete",
    ),
)
def test_clean_simulated_windows_handle_failures_preserve_the_target(tmp_path, monkeypatch, failure):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel(failure=failure)
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    expected_error = OSError if failure == "delete" else manager_module.CleanupScopeError
    with pytest.raises(expected_error):
        manager.clean(areas=("logs",))

    assert target.read_bytes() == b"managed"
    assert kernel.handles == {}


def test_clean_simulated_windows_close_failure_releases_both_handles(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    kernel = SimulatedWindowsKernel(failure="close")
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows close failure"))

    with pytest.raises(OSError, match="Windows close failure"):
        manager.clean(areas=("logs",))

    assert not target.exists()
    assert kernel.handles == {}


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-bound deletion behavior")
@pytest.mark.parametrize("directory", (False, True))
def test_clean_windows_handle_fails_closed_after_final_path_replacement(
    tmp_path,
    monkeypatch,
    directory,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    root = manager.paths.logs
    target = root / ("victim" if directory else "victim.log")
    outside = tmp_path / "outside-logs"
    outside.mkdir()
    outside_marker = outside / "must-survive"
    outside_marker.write_bytes(b"outside")
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"managed")
    original_delete = removal_module._delete_windows_guard
    swaps = []
    opened, closed = record_windows_identity_guards(monkeypatch)

    def replace_path_then_delete_pinned_object(descriptor, expect_directory):
        if descriptor.path == target and not swaps:
            unlink_windows_identity_guard_path(descriptor)
            if directory:
                create_windows_junction(target, outside)
            else:
                target.write_bytes(b"replacement")
            swaps.append(target)
            return original_delete(descriptor, expect_directory)
        return original_delete(descriptor, expect_directory)

    monkeypatch.setattr(removal_module, "_delete_windows_guard", replace_path_then_delete_pinned_object)

    try:
        with pytest.raises(PermissionError) as error:
            manager.clean(areas=("logs",))

        assert error.value.winerror == 5
        assert swaps == [target]
        if directory:
            assert removal_module.is_path_alias(target)
            assert outside.is_dir()
            assert outside_marker.read_bytes() == b"outside"
        else:
            assert target.read_bytes() == b"replacement"
        assert_windows_identity_guards_closed(opened, closed)
    finally:
        if directory and removal_module.is_path_alias(target):
            os.rmdir(str(target))


def test_clean_tolerates_a_file_disappearing_before_measurement(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"managed")
    original_lstat = removal_module._lstat
    disappeared = []

    def remove_before_measurement(path):
        if path == target and not disappeared:
            path.unlink()
            disappeared.append(path)
            return None
        return original_lstat(path)

    monkeypatch.setattr(removal_module, "_lstat", remove_before_measurement)

    result = manager.clean(areas=("logs",))

    assert result.targets_removed == 1
    assert result.bytes_reclaimed == 0
    assert disappeared == [target]


def test_remove_cleans_the_empty_backend_parent(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    backend_root = installed.manifest.parent.parent

    result = manager.uninstall("mihomo", "1.0.0")

    assert result.versions == ("1.0.0",)
    assert not backend_root.exists()


def test_remove_propagates_unexpected_backend_parent_removal_errors(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    backend_root = installed.manifest.parent.parent
    original_rmdir = type(backend_root).rmdir

    def deny_backend_parent_removal(path):
        if path == backend_root:
            raise PermissionError("backend parent removal denied")
        return original_rmdir(path)

    monkeypatch.setattr(type(backend_root), "rmdir", deny_backend_parent_removal)

    with pytest.raises(PermissionError, match="backend parent removal denied"):
        manager.uninstall("mihomo", "1.0.0")

    assert backend_root.is_dir()
    assert installed.manifest.is_file()


def test_forced_remove_failure_restores_the_active_backend(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_move = removal_module._move_no_replace

    def fail_active_link_move(paths, source, destination, expected_identity, *args, **kwargs):
        if Path(source) == manager.paths.bin / "mihomo":
            raise PermissionError("active link move denied")
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", fail_active_link_move)

    with pytest.raises(PermissionError, match="active link move denied"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert installed.manifest.is_file()
    assert manager.current("mihomo").version == "1.0.0"


def test_forced_remove_preserves_recovery_backups_when_restore_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_move = removal_module._move_no_replace

    def fail_stage_and_restore(paths, source, destination, expected_identity, *args, **kwargs):
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path == manager.paths.bin / "mihomo":
            raise PermissionError("active link move denied")
        if destination_path == installed.manifest.parent and ".remove-" in source_path.parent.name:
            raise OSError("installed rollback denied")
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", fail_stage_and_restore)

    with pytest.raises(OSError, match="installed rollback denied"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    quarantines = [path for path in manager.paths.runtimes.glob(".remove-*") if path.is_dir()]
    assert len(quarantines) == 1
    assert (quarantines[0] / "installed-0").is_dir()


def test_forced_remove_detects_a_restored_path_replaced_during_rollback(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_move = removal_module._move_no_replace
    preserved = tmp_path / "preserved-restored-install"

    def replace_restored_install(paths, source, destination, expected_identity, *args, **kwargs):
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path == manager.paths.bin / "mihomo":
            raise PermissionError("active link move denied")
        result = original_move(paths, source, destination, expected_identity, *args, **kwargs)
        if destination_path == installed.manifest.parent and ".remove-" in source_path.parent.name:
            destination_path.rename(preserved)
            destination_path.mkdir()
        return result

    monkeypatch.setattr(removal_module, "_move_no_replace", replace_restored_install)

    with pytest.raises(IntegrityError, match="restored a different filesystem object"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert (preserved / "manifest.json").is_file()
    assert installed.manifest.parent.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="POSIX atomic rename race fixture")
def test_removal_recovery_never_overwrites_a_source_appearing_before_restore(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "6" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.active / "mihomo.json"
    source.write_bytes(b"original managed state")
    if os.name == "posix":
        source.chmod(0o600)
    move = removal_module._removal_move(
        manager.paths,
        source,
        transaction / "active-manifest",
        "active-manifest",
    )
    destination = transaction / "active-manifest"
    os.replace(str(source), str(destination))
    atomic_write_json(transaction / "journal.json", {"phase": "staging", "moves": [move]})
    original_noreplace = anchored_module._rename_posix_noreplace
    inserted = []

    def insert_source_before_restore(
        source_parent_descriptor,
        source_name,
        destination_parent_descriptor,
        destination_name,
    ):
        if destination_name == source.name and not inserted:
            source.write_bytes(b"new user state")
            if os.name == "posix":
                source.chmod(0o600)
            inserted.append(source)
        return original_noreplace(
            source_parent_descriptor,
            source_name,
            destination_parent_descriptor,
            destination_name,
        )

    monkeypatch.setattr(
        anchored_module,
        "_rename_posix_noreplace",
        insert_source_before_restore,
    )

    with pytest.raises(IntegrityError, match="removal recovery destination already exists"):
        recover_backend_transactions(manager.paths, manager.platform_info)

    assert inserted == [source]
    assert source.read_bytes() == b"new user state"
    assert destination.read_bytes() == b"original managed state"
    assert (transaction / "journal.json").is_file()


def test_remove_all_failure_keeps_the_active_backend_usable(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    first = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    second = install_fake_mihomo(manager, tmp_path, "2.0.0", b"two", activate=False)
    original_move = removal_module._move_no_replace

    def fail_active_version_move(paths, source, destination, expected_identity, *args, **kwargs):
        if Path(source) == first.manifest.parent:
            raise PermissionError("active version move denied")
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", fail_active_version_move)

    with pytest.raises(PermissionError, match="active version move denied"):
        manager.uninstall_all("mihomo")

    assert first.manifest.is_file()
    assert second.manifest.is_file()
    assert manager.current("mihomo").version == "1.0.0"


def test_uninstall_accepts_a_canonical_windows_128_bit_file_identity(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=False)
    installed_root = installed.manifest.parent
    modern_identity = {
        "kind": "windows-file-id",
        "volume_serial": "0000000000000001",
        "file_id": "%032x" % (1 << 96),
        "file_type": "directory",
    }
    original_capture = removal_module.capture_identity
    original_matches = removal_module.identity_matches
    original_guard_matches = removal_module._guard_matches_expected
    original_write_journal = removal_module._write_removal_journal
    original_anchored_replace = anchored_module.AnchoredDirectory.replace
    observed_identities = []

    def capture_modern_install(path):
        if Path(path) == installed_root:
            return modern_identity
        return original_capture(path)

    def match_modern_quarantine(path, identity):
        if identity == modern_identity and (Path(path) == installed_root or Path(path).name == "installed-0"):
            return True
        return original_matches(path, identity)

    def match_modern_guard(status, descriptor, identity):
        if identity == modern_identity:
            return True
        return original_guard_matches(status, descriptor, identity)

    def record_journal_identity(transaction, moves, phase="staging", **kwargs):
        observed_identities.extend(move.get("identity") for move in moves)
        return original_write_journal(transaction, moves, phase=phase, **kwargs)

    def replace_synthetic_identity(anchored, source_parts, destination_parts, **kwargs):
        if kwargs.get("expected_identity") == modern_identity:
            kwargs["expected_identity"] = anchored.identity(source_parts)
        return original_anchored_replace(anchored, source_parts, destination_parts, **kwargs)

    monkeypatch.setattr(removal_module, "capture_identity", capture_modern_install)
    monkeypatch.setattr(removal_module, "identity_matches", match_modern_quarantine)
    monkeypatch.setattr(removal_module, "_guard_matches_expected", match_modern_guard)
    monkeypatch.setattr(removal_module, "_write_removal_journal", record_journal_identity)
    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "replace",
        replace_synthetic_identity,
    )

    removed = manager.uninstall("mihomo", "1.0.0")

    assert removed.versions == ("1.0.0",)
    assert observed_identities and all(identity == modern_identity for identity in observed_identities)
    assert not installed_root.exists()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_remove_download_cleanup_failure_does_not_change_installed_state(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    cached = manager.paths.downloads / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cache")

    original_move = removal_module._move_no_replace

    def fail_download_move(paths, source, destination, expected_identity, *args, **kwargs):
        if Path(source) == cached.parent:
            raise PermissionError("download move denied")
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", fail_download_move)

    with pytest.raises(PermissionError, match="download move denied"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True, cache=True)

    assert installed.manifest.is_file()
    assert cached.is_file()
    assert manager.current("mihomo").version == "1.0.0"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_remove_fails_closed_when_a_download_parent_is_swapped_during_rename(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=False)
    backend_root = manager.paths.downloads / "mihomo"
    cached = backend_root / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"managed")
    outside = tmp_path / "outside-download-parent"
    outside_target = outside / "1.0.0"
    outside_target.mkdir(parents=True)
    marker = outside_target / "must-survive.gz"
    marker.write_bytes(b"outside")
    saved_root = manager.paths.downloads / "mihomo-original"
    original_move = removal_module._move_no_replace
    swapped = []

    def swap_parent(paths, source, destination, expected_identity, *args, **kwargs):
        if Path(source) == cached.parent and not swapped:
            backend_root.rename(saved_root)
            backend_root.symlink_to(outside, target_is_directory=True)
            swapped.append(source)
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", swap_parent)

    with pytest.raises(IntegrityError, match="managed path alias"):
        manager.uninstall("mihomo", "1.0.0", cache=True)

    assert len(list(manager.paths.runtimes.glob(".remove-*"))) == 1
    assert marker.read_bytes() == b"outside"
    assert not cached.exists()
    assert (saved_root / "1.0.0" / "archive.gz").read_bytes() == b"managed"
    assert installed.manifest.is_file()


def test_remove_fails_closed_when_source_identity_changes_before_rename(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=False)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    (target / "archive.gz").write_bytes(b"managed")
    saved = manager.paths.downloads / "saved-original"
    original_move = removal_module._move_no_replace
    swapped = []

    def swap_source(paths, source, destination, expected_identity, *args, **kwargs):
        if Path(source) == target and not swapped:
            target.rename(saved)
            target.mkdir()
            (target / "replacement.gz").write_bytes(b"replacement")
            swapped.append(source)
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", swap_source)

    with pytest.raises(IntegrityError, match="payload identity changed"):
        manager.uninstall("mihomo", "1.0.0", cache=True)

    assert (saved / "archive.gz").read_bytes() == b"managed"
    assert len(list(manager.paths.runtimes.glob(".remove-*"))) == 1
    assert (target / "replacement.gz").read_bytes() == b"replacement"
    assert installed.manifest.is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_remove_rolls_back_a_download_junction_swapped_during_rename(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=False)
    backend_root = manager.paths.downloads / "mihomo"
    cached = backend_root / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"managed")
    outside = tmp_path / "outside-download-parent"
    outside_target = outside / "1.0.0"
    outside_target.mkdir(parents=True)
    marker = outside_target / "must-survive.gz"
    marker.write_bytes(b"outside")
    saved_root = manager.paths.downloads / "mihomo-original"
    original_move = removal_module._move_no_replace
    swapped = []

    def swap_parent(paths, source, destination, expected_identity, *args, **kwargs):
        if Path(source) == cached.parent and not swapped:
            backend_root.rename(saved_root)
            subprocess.check_call(
                ["cmd", "/c", "mklink", "/J", str(backend_root), str(outside)],
                stdout=subprocess.DEVNULL,
            )
            swapped.append(source)
        return original_move(paths, source, destination, expected_identity, *args, **kwargs)

    monkeypatch.setattr(removal_module, "_move_no_replace", swap_parent)

    try:
        with pytest.raises(CleanupScopeError, match="anchored removal staging"):
            manager.uninstall("mihomo", "1.0.0", cache=True)
        assert not list(manager.paths.runtimes.glob(".remove-*"))
        assert marker.read_bytes() == b"outside"
        assert not cached.exists()
        assert (saved_root / "1.0.0" / "archive.gz").read_bytes() == b"managed"
        assert installed.manifest.is_file()
    finally:
        if os.path.lexists(str(backend_root)):
            os.rmdir(str(backend_root))


def test_remove_tolerates_a_download_target_disappearing_after_collection(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=False)
    cached = manager.paths.downloads / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cache")
    original_lexists = manager_module.os.path.lexists
    checks = []

    def remove_download_before_staging(path):
        if path == str(cached.parent):
            checks.append(path)
            if len(checks) == 2:
                shutil.rmtree(path)
                return False
        return original_lexists(path)

    monkeypatch.setattr(manager_module.os.path, "lexists", remove_download_before_staging)

    result = manager.uninstall("mihomo", "1.0.0", cache=True)

    assert result.cleanup.targets_removed == 0
    assert result.cleanup.bytes_reclaimed == 0
    assert not installed.manifest.parent.exists()
    assert len(checks) == 2


def test_removal_reports_committed_quarantine_cleanup_failure(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)

    def fail_quarantine_cleanup(paths, path, platform_info=None, record=None):
        raise PermissionError("quarantine cleanup denied")

    with monkeypatch.context() as context:
        context.setattr(removal_module, "_dispose_removal_transaction", fail_quarantine_cleanup)
        with pytest.raises(RemovalCleanupError, match="removal committed.*clean --runtimes"):
            manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert not installed.manifest.parent.exists()
    assert manager.current("mihomo") is None
    assert manager.clean(areas=("runtimes",)).targets_removed in (0, 1)
    assert list(manager.paths.runtimes.iterdir()) == []


@pytest.mark.parametrize("move_number", (1, 2, 3))
def test_crashed_removal_move_is_recovered_before_the_next_state_read(tmp_path, move_number):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_after_removal_move,
        args=(str(manager.paths.root), move_number),
    )

    process.start()
    process.join(10)

    assert process.exitcode == 20 + move_number
    inventory = manager.inventory("mihomo")
    assert [item.version for item in inventory.installed] == ["1.0.0"]
    assert [item.version for item in inventory.active] == ["1.0.0"]
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_removal_transaction_directory_is_durably_created_before_its_journal(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    events = []
    original_create = manager_module.AnchoredDirectory.create_directory
    original_write = removal_module._write_removal_journal

    def record_create(anchored, parts):
        result = original_create(anchored, parts)
        if anchored.root == manager.paths.runtimes and parts[-1].startswith(".remove-"):
            events.append("transaction-created")
        return result

    def record_write(transaction, moves, phase="staging", write_id=None, **kwargs):
        events.append("journal-%s" % phase)
        return original_write(
            transaction,
            moves,
            phase=phase,
            write_id=write_id,
            **kwargs,
        )

    monkeypatch.setattr(
        manager_module.AnchoredDirectory,
        "create_directory",
        record_create,
    )
    monkeypatch.setattr(removal_module, "_write_removal_journal", record_write)

    manager.uninstall("mihomo", "1.0.0")

    assert events[:2] == ["transaction-created", "journal-staging"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory flush failure injection")
def test_removal_transaction_parent_flush_failure_precedes_journal_and_public_mutation(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(
        manager,
        tmp_path,
        "1.0.0",
        b"backend",
        activate=False,
    )
    original_flush = anchored_module.flush_descriptor

    def fail_transaction_parent(descriptor, kind):
        if kind == "anchored directory parent":
            raise DurabilityError("simulated removal transaction parent flush failure")
        return original_flush(descriptor, kind)

    monkeypatch.setattr(anchored_module, "flush_descriptor", fail_transaction_parent)

    with pytest.raises(DurabilityError, match="transaction parent flush failure"):
        manager.uninstall("mihomo", "1.0.0")

    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*/journal.json"))

    monkeypatch.undo()
    assert manager.list_installed("mihomo")[0].version == "1.0.0"
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_crash_before_commit_restores_a_removed_backend_parent(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_crash_before_removal_commit, args=(str(manager.paths.root),))

    process.start()
    process.join(10)

    assert process.exitcode == 27
    assert not installed.manifest.parent.parent.exists()
    assert manager.current("mihomo").version == "1.0.0"
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_crash_during_commit_write_discards_the_durable_journal_temporary(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_during_removal_commit_write,
        args=(str(manager.paths.root),),
    )

    process.start()
    process.join(10)

    assert process.exitcode == 29
    assert manager.current("mihomo").version == "1.0.0"
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_crash_after_commit_finishes_quarantine_disposal(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_crash_after_removal_commit, args=(str(manager.paths.root),))

    process.start()
    process.join(10)

    assert process.exitcode == 28
    assert not installed.manifest.is_file()
    inventory = manager.inventory("mihomo")
    assert inventory.installed == ()
    assert inventory.active == ()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit removal journal matrix")
@pytest.mark.parametrize(
    ("crash_point", "exit_code", "committed"),
    (
        ("file-flushed", 105, False),
        ("replaced-before-parent-flush", 106, True),
        ("parent-flushed", 107, True),
    ),
)
def test_hard_exit_during_committed_removal_journal_publication_uses_visible_authority(
    tmp_path,
    crash_point,
    exit_code,
    committed,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_removal_committed_journal,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    active = manager.current("mihomo")
    assert (active is None) is committed
    assert installed.manifest.is_file() is not committed
    assert not list(manager.paths.runtimes.glob(".remove-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit removal journal matrix")
@pytest.mark.parametrize(
    ("crash_point", "exit_code"),
    (
        ("before-temporary", 101),
        ("writer-file-flushed", 102),
        ("journal-replaced", 103),
        ("parent-flushed", 104),
    ),
)
def test_hard_exit_during_initial_removal_journal_publication_recovers(
    tmp_path,
    crash_point,
    exit_code,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_initial_removal_journal,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    assert manager.current("mihomo").version == "1.0.0"
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))
    assert manager.current("mihomo").version == "1.0.0"


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit removal directory creation")
@pytest.mark.parametrize(
    ("crash_point", "exit_code"),
    (
        ("transaction-child-flushed", 131),
        ("transaction-parent-flushed", 132),
    ),
)
def test_hard_exit_during_removal_transaction_directory_creation_recovers(
    tmp_path,
    crash_point,
    exit_code,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(
        manager,
        tmp_path,
        "1.0.0",
        b"backend",
        activate=False,
    )
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_removal_transaction_creation,
        args=(str(manager.paths.root), crash_point),
    )

    process.start()
    process.join(10)

    assert process.exitcode == exit_code
    assert manager.list_installed("mihomo")[0].manifest == installed.manifest
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit removal recovery")
@pytest.mark.parametrize(
    ("crash_point", "exit_code"),
    (
        ("rollback-replaced-before-flush", 115),
        ("rollback-destination-before-flush", 116),
        ("rollback-move", 111),
    ),
)
def test_hard_exit_during_removal_rollback_recovery_converges(
    tmp_path,
    crash_point,
    exit_code,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_after_removal_move,
        args=(str(manager.paths.root), 2),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == 22

    recovery = context.Process(
        target=_crash_removal_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == exit_code

    assert manager.current("mihomo").version == "1.0.0"
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))
    assert manager.current("mihomo").version == "1.0.0"


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit removal recovery")
@pytest.mark.parametrize(
    ("crash_point", "exit_code"),
    (
        ("payload-deleted", 112),
        ("journal-deleted", 113),
        ("transaction-deleted", 114),
    ),
)
def test_hard_exit_during_committed_removal_recovery_converges(
    tmp_path,
    crash_point,
    exit_code,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_after_removal_commit,
        args=(str(manager.paths.root),),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == 28

    recovery = context.Process(
        target=_crash_removal_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    recovery.start()
    recovery.join(10)
    assert recovery.exitcode == exit_code

    assert manager.current("mihomo") is None
    assert not installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))
    assert manager.current("mihomo") is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-exit runtime cleanup")
@pytest.mark.parametrize(
    ("crash_point", "exit_code", "runtime_survives"),
    (
        ("before-runtime-delete", 121, True),
        ("after-runtime-delete", 122, False),
    ),
)
def test_hard_exit_during_runtime_cleanup_after_recovery_is_safe(
    tmp_path,
    crash_point,
    exit_code,
    runtime_survives,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    runtime = manager.paths.runtimes / "runtime.json"
    runtime.write_bytes(b"runtime")
    context = multiprocessing.get_context("spawn")
    operation = context.Process(
        target=_crash_after_removal_move,
        args=(str(manager.paths.root), 1),
    )
    operation.start()
    operation.join(10)
    assert operation.exitcode == 21

    cleanup = context.Process(
        target=_crash_runtime_clean_after_recovery,
        args=(str(manager.paths.root), crash_point),
    )
    cleanup.start()
    cleanup.join(10)
    assert cleanup.exitcode == exit_code

    assert runtime.exists() is runtime_survives
    assert manager.current("mihomo").version == "1.0.0"
    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))
    manager.clean(areas=("runtimes",))
    assert not runtime.exists()


@pytest.mark.parametrize(
    ("failed_phase", "installed_after_failure"),
    (("staging", True), ("committed", False)),
)
def test_removal_durability_failure_recovers_under_the_held_lock(
    tmp_path,
    monkeypatch,
    failed_phase,
    installed_after_failure,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_write = removal_module._write_removal_journal

    def fail_after_visible_journal(transaction, moves, phase="staging", write_id=None, **kwargs):
        result = original_write(
            transaction,
            moves,
            phase=phase,
            write_id=write_id,
            **kwargs,
        )
        if phase == failed_phase:
            raise DurabilityError("simulated removal journal parent flush failure")
        return result

    monkeypatch.setattr(
        removal_module,
        "_write_removal_journal",
        fail_after_visible_journal,
    )

    with pytest.raises(DurabilityError, match="simulated removal journal parent flush failure"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert installed.manifest.is_file() is installed_after_failure
    assert not list(manager.paths.runtimes.glob(".remove-*"))
    active = manager.current("mihomo")
    assert (active is not None) is installed_after_failure


def test_removal_move_flush_failure_recovers_the_visible_rename_under_the_held_lock(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_flush = anchored_module.flush_descriptor
    failed = []

    def fail_first_move_parent_flush(descriptor, kind):
        if kind == "anchored publication source directory" and not failed:
            failed.append(kind)
            raise DurabilityError("simulated removal move parent flush failure")
        return original_flush(descriptor, kind)

    monkeypatch.setattr(
        anchored_module,
        "flush_descriptor",
        fail_first_move_parent_flush,
    )

    with pytest.raises(DurabilityError, match="removal move parent flush failure"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert failed == ["anchored publication source directory"]
    assert installed.manifest.is_file()
    assert manager.current("mihomo").version == "1.0.0"
    assert not list(manager.paths.runtimes.glob(".remove-*"))


@pytest.mark.parametrize("tampered_phase", ("staging", "committed"))
def test_normal_removal_rejects_journal_content_changed_after_publication(
    tmp_path,
    monkeypatch,
    tampered_phase,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_write = removal_module._write_removal_journal

    def tamper_after_publication(transaction, moves, phase="staging", write_id=None, **kwargs):
        result = original_write(
            transaction,
            moves,
            phase=phase,
            write_id=write_id,
            **kwargs,
        )
        if phase == tampered_phase:
            journal = transaction / "journal.json"
            replacement_phase = "committed" if phase == "staging" else "staging"
            payload = journal.read_text(encoding="utf-8").replace(
                '"phase": "%s"' % phase,
                '"phase": "%s"' % replacement_phase,
            )
            journal.write_text(payload, encoding="utf-8")
            if os.name == "posix":
                journal.chmod(0o600)
        return result

    monkeypatch.setattr(
        removal_module,
        "_write_removal_journal",
        tamper_after_publication,
    )

    with pytest.raises(IntegrityError):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert len(list(manager.paths.runtimes.glob(".remove-*"))) == 1
    if tampered_phase == "staging":
        assert installed.manifest.is_file()
    else:
        assert not installed.manifest.is_file()


def test_removal_commit_rejects_journal_identity_swap_before_replace(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_replace = anchored_module.AnchoredDirectory.replace
    displaced = tmp_path / "displaced-removal-journal.json"
    substituted = []

    def swap_committed_authority(anchored, source_parts, destination_parts, *args, **kwargs):
        expected = kwargs.get("expected_destination_identity")
        if tuple(destination_parts) == ("journal.json",) and expected is not None and not substituted:
            journal = anchored.root / "journal.json"
            payload = journal.read_bytes()
            journal.rename(displaced)
            journal.write_bytes(payload)
            if os.name == "posix":
                journal.chmod(0o600)
            substituted.append(journal)
        return original_replace(
            anchored,
            source_parts,
            destination_parts,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "replace",
        swap_committed_authority,
    )

    with pytest.raises(IntegrityError, match="journal authority"):
        manager.uninstall("mihomo", "1.0.0", deactivate=True)

    assert substituted
    transaction = substituted[0].parent
    assert substituted[0].read_bytes() == displaced.read_bytes()
    assert (transaction / "installed-0" / "manifest.json").is_file()
    assert not installed.manifest.exists()
    assert transaction.is_dir()


def test_empty_remove_all_is_idempotent_and_leaves_no_transaction(tmp_path):
    manager = manager_for(tmp_path)

    result = manager.uninstall_all("mihomo", cache=True)

    assert result.versions == ()
    assert result.cleanup.targets_removed == 0
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_empty_remove_all_maps_transaction_creation_failure(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    original_create = anchored_module.AnchoredDirectory.create_directory

    def fail_removal_transaction(anchored, parts):
        if parts[-1].startswith(".remove-"):
            raise ArchiveError("simulated transaction creation failure")
        return original_create(anchored, parts)

    monkeypatch.setattr(anchored_module.AnchoredDirectory, "create_directory", fail_removal_transaction)

    with pytest.raises(IntegrityError, match="unable to create removal transaction directory"):
        manager.uninstall_all("mihomo")


def test_empty_remove_all_rejects_transaction_disappearance_before_disposal(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)

    monkeypatch.setattr(removal_module, "_secure_remove_empty_directory", lambda *args, **kwargs: False)

    with pytest.raises(IntegrityError, match="removal transaction disappeared before disposal"):
        manager.uninstall_all("mihomo")


def test_remove_all_tolerates_a_cache_target_disappearing_after_measurement(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo"
    version = target / "1.0.0"
    version.mkdir(parents=True)
    (version / "archive.gz").write_bytes(b"cache")
    original_size = removal_module._secure_path_size

    def remove_after_measurement(root, selected, error_type):
        result = original_size(root, selected, error_type)
        if selected == target:
            shutil.rmtree(str(selected))
        return result

    monkeypatch.setattr(removal_module, "_secure_path_size", remove_after_measurement)

    result = manager.uninstall_all("mihomo", cache=True)

    assert result.cleanup.targets_removed == 0
    assert not target.exists()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("path-type", "invalid removal journal path"),
        ("path-traversal", "invalid removal journal path"),
        ("path-surrogate", "invalid removal journal path"),
        ("phase", "invalid removal transaction journal"),
        ("moves", "invalid removal transaction moves"),
        ("move-shape", "invalid removal transaction move"),
        ("kind", "move kind"),
        ("source", "transaction source"),
        ("destination-parent", "transaction destination"),
        ("destination-prefix", "transaction destination"),
        ("destination-exact", "transaction destination"),
        ("identity", "transaction identity"),
        ("duplicate", "duplicate removal transaction path"),
    ],
)
def test_invalid_removal_journal_fails_closed_before_a_state_read(tmp_path, case, message):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "a" * 32)
    transaction.mkdir()
    outside = tmp_path / "outside-journal"
    outside.write_bytes(b"must survive")
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    move = removal_journal_move(manager, transaction, source)
    journal = {"phase": "committed", "moves": [move]}
    if case == "path-type":
        move["source"] = None
    elif case == "path-traversal":
        move["source"] = "../outside-journal"
    elif case == "path-surrogate":
        move["source"] = "downloads/mihomo/bad\ud800version"
    elif case == "phase":
        journal["phase"] = "unknown"
    elif case == "moves":
        journal["moves"] = []
    elif case == "move-shape":
        move.pop("identity")
    elif case == "kind":
        move["kind"] = "unknown"
    elif case == "source":
        move["source"] = "logs/mihomo/1.0.0"
    elif case == "destination-parent":
        move["destination"] = "runtimes/other/download-0"
    elif case == "destination-prefix":
        move["destination"] = "runtimes/%s/wrong-0" % transaction.name
    elif case == "destination-exact":
        move["kind"] = "active-link"
        move["source"] = "bin/mihomo"
        move["destination"] = "runtimes/%s/wrong-link" % transaction.name
    elif case == "identity":
        move["identity"] = True
    else:
        duplicate = dict(move)
        duplicate["destination"] = "runtimes/%s/download-1" % transaction.name
        journal["moves"].append(duplicate)
    atomic_write_json(transaction / "journal.json", journal)

    with pytest.raises(IntegrityError, match=message):
        manager.inventory("mihomo")

    assert outside.read_bytes() == b"must survive"


def test_non_json_removal_journal_fails_closed_before_a_state_read(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "b" * 32)
    transaction.mkdir(mode=0o700)
    journal = transaction / "journal.json"
    journal.write_text("not json", encoding="utf-8")
    if os.name == "posix":
        journal.chmod(0o600)

    with pytest.raises(IntegrityError, match="invalid removal transaction journal"):
        manager.current("mihomo")


def test_removal_journal_preflight_does_not_reopen_authority_by_path(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(mode=0o700, parents=True)
    transaction = manager.paths.runtimes / (".remove-" + "1" * 32)
    transaction.mkdir(mode=0o700)
    move = removal_journal_move(manager, transaction, source)
    removal_module._write_removal_journal(
        transaction,
        [move],
        write_id=lambda: "2" * 32,
    )
    journal = transaction / "journal.json"
    original_open = Path.open

    def deny_journal_path_open(path, *args, **kwargs):
        if path == journal:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_journal_path_open)

    records = removal_module.preflight_removal_transactions(manager.paths, manager.platform_info)

    assert len(records) == 1
    assert records[0].transaction == transaction


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("backend-case", "noncanonical removal backend"),
        ("backend-unknown", "invalid removal backend"),
        ("version-prefix", "noncanonical removal version"),
        ("version-invalid", "invalid removal version"),
        ("download-depth", "invalid removal transaction source"),
        ("installed-depth", "invalid removal transaction source"),
        ("active-link-depth", "invalid removal transaction source"),
        ("active-manifest-shape", "invalid removal transaction source"),
        ("active-command", "invalid active-link command"),
        ("active-manifest", "noncanonical removal backend"),
        ("mode", "stable identity expected"),
        ("identity-overflow", "invalid removal transaction identity"),
        ("leading-zero", "noncanonical removal transaction index"),
        ("index-overflow", "invalid removal transaction index"),
        ("invalid-index", "invalid removal transaction destination"),
        ("path-overflow", "removal journal path exceeds"),
    ],
)
def test_removal_journal_rejects_noncanonical_relationships(tmp_path, case, message):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "9" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    move = removal_journal_move(manager, transaction, source)
    if case == "backend-case":
        move["source"] = "downloads/Mihomo/1.0.0"
    elif case == "backend-unknown":
        move["source"] = "downloads/unknown/1.0.0"
    elif case == "version-prefix":
        move["source"] = "downloads/mihomo/v1.0.0"
    elif case == "version-invalid":
        move["source"] = "downloads/mihomo/bad version"
    elif case == "download-depth":
        move["source"] = "downloads/mihomo/1.0.0/extra"
    elif case == "installed-depth":
        move.update(
            {
                "kind": "installed",
                "source": "backends/mihomo",
                "destination": "runtimes/%s/installed-0" % transaction.name,
                "identity": dict(move["identity"], file_type="directory"),
            }
        )
    elif case == "active-link-depth":
        move.update(
            {
                "kind": "active-link",
                "source": "bin/mihomo/extra",
                "destination": "runtimes/%s/active-link" % transaction.name,
                "identity": dict(move["identity"], file_type="symlink"),
            }
        )
    elif case == "active-manifest-shape":
        move.update(
            {
                "kind": "active-manifest",
                "source": "active/mihomo",
                "destination": "runtimes/%s/active-manifest" % transaction.name,
                "identity": dict(move["identity"], file_type="regular"),
            }
        )
    elif case == "active-command":
        move.update(
            {
                "kind": "active-link",
                "source": "bin/mihomo.exe",
                "destination": "runtimes/%s/active-link" % transaction.name,
                "identity": dict(move["identity"], file_type="symlink"),
            }
        )
    elif case == "active-manifest":
        move.update(
            {
                "kind": "active-manifest",
                "source": "active/Mihomo.json",
                "destination": "runtimes/%s/active-manifest" % transaction.name,
                "identity": dict(move["identity"], file_type="regular"),
            }
        )
    elif case == "mode":
        move["identity"] = dict(move["identity"], file_type="regular")
    elif case == "identity-overflow":
        move["identity"] = {
            "kind": "windows-file-id",
            "volume_serial": "0" * 16,
            "file_id": "1" * 33,
            "file_type": "directory",
        }
    elif case == "leading-zero":
        move["destination"] = "runtimes/%s/download-00" % transaction.name
    elif case == "index-overflow":
        move["destination"] = "runtimes/%s/download-512" % transaction.name
    elif case == "invalid-index":
        move["destination"] = "runtimes/%s/download-invalid" % transaction.name
    else:
        move["source"] = "downloads/mihomo/%s" % ("a" * 496)
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match=message):
        manager.current("mihomo")

    assert (transaction / "journal.json").is_file()


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("gap", "noncontiguous removal transaction indices"),
        ("kind-order", "invalid removal transaction move order"),
        ("active-order", "invalid removal transaction move order"),
        ("duplicate-active-link", "duplicate active-link removal move"),
        ("duplicate-active-manifest", "duplicate active-manifest removal move"),
        ("active-backend-mismatch", "active removal backend mismatch"),
    ],
)
def test_removal_journal_rejects_ambiguous_move_sequences(tmp_path, case, message):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "8" * 32)
    transaction.mkdir(mode=0o700)
    download = removal_journal_move(
        manager,
        transaction,
        manager.paths.downloads / "mihomo" / "1.0.0",
    )
    installed = removal_journal_move(
        manager,
        transaction,
        manager.paths.backends / "mihomo" / "1.0.0",
        destination_name="installed-0",
        kind="installed",
    )
    active_link = removal_journal_move(
        manager,
        transaction,
        manager.paths.bin / "mihomo",
        destination_name="active-link",
        kind="active-link",
    )
    active_manifest = removal_journal_move(
        manager,
        transaction,
        manager.paths.active / "mihomo.json",
        destination_name="active-manifest",
        kind="active-manifest",
    )
    if case == "gap":
        second = dict(download)
        second["source"] = "downloads/mihomo/2.0.0"
        second["destination"] = "runtimes/%s/download-2" % transaction.name
        moves = [download, second]
    elif case == "kind-order":
        moves = [installed, download]
    elif case == "active-order":
        moves = [active_manifest, active_link]
    elif case == "duplicate-active-link":
        duplicate = dict(active_link)
        duplicate["source"] = "bin/xray"
        moves = [active_link, duplicate]
    elif case == "duplicate-active-manifest":
        duplicate = dict(active_manifest)
        duplicate["source"] = "active/xray.json"
        moves = [active_manifest, duplicate]
    else:
        active_manifest["source"] = "active/xray.json"
        moves = [active_link, active_manifest]
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": moves},
    )

    with pytest.raises(IntegrityError, match=message):
        manager.current("mihomo")

    assert (transaction / "journal.json").is_file()


@pytest.mark.parametrize("active_mode", (stat.S_IFLNK, stat.S_IFREG))
def test_removal_journal_accepts_exact_path_and_active_mode_boundaries(tmp_path, active_mode):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "7" * 32)
    transaction.mkdir(mode=0o700)
    exact_version = "a" * 495
    exact_source = "downloads/mihomo/%s" % exact_version
    assert len(exact_source.encode("utf-8")) == 512
    download = removal_journal_move(
        manager,
        transaction,
        manager.paths.downloads / "mihomo" / exact_version,
    )
    active_link = removal_journal_move(
        manager,
        transaction,
        manager.paths.bin / "mihomo",
        destination_name="active-link",
        kind="active-link",
        mode=active_mode,
    )
    active_manifest = removal_journal_move(
        manager,
        transaction,
        manager.paths.active / "mihomo.json",
        destination_name="active-manifest",
        kind="active-manifest",
    )
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "committed", "moves": [download, active_link, active_manifest]},
    )

    assert manager.current("mihomo") is None
    assert not transaction.exists()


def test_removal_journal_accepts_512_moves_and_rejects_513(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()

    def build_moves(transaction, count):
        moves = []
        for index in range(min(count, 256)):
            moves.append(
                removal_journal_move(
                    manager,
                    transaction,
                    manager.paths.downloads / "mihomo" / ("1.0.%d" % index),
                    destination_name="download-%d" % index,
                )
            )
        for index in range(max(0, count - 256)):
            moves.append(
                removal_journal_move(
                    manager,
                    transaction,
                    manager.paths.backends / "mihomo" / ("2.0.%d" % index),
                    destination_name="installed-%d" % index,
                    kind="installed",
                )
            )
        return moves

    accepted = manager.paths.runtimes / (".remove-" + "6" * 32)
    accepted.mkdir()
    accepted_moves = build_moves(accepted, 512)
    assert len(accepted_moves) == 512
    atomic_write_json(
        accepted / "journal.json",
        {"phase": "committed", "moves": accepted_moves},
    )
    assert manager.current("mihomo") is None
    assert not accepted.exists()

    rejected = manager.paths.runtimes / (".remove-" + "5" * 32)
    rejected.mkdir()
    rejected_moves = build_moves(rejected, 513)
    assert len(rejected_moves) == 513
    atomic_write_json(
        rejected / "journal.json",
        {"phase": "staging", "moves": rejected_moves},
    )
    with pytest.raises(IntegrityError, match="invalid removal transaction moves"):
        manager.current("mihomo")
    assert (rejected / "journal.json").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_removal_transaction_alias_fails_closed_without_touching_its_target(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    outside = tmp_path / "outside-transaction"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    transaction = manager.paths.runtimes / (".remove-" + "c" * 32)
    transaction.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert marker.read_bytes() == b"outside"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_removal_journal_alias_fails_closed_without_reading_its_target(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    outside = tmp_path / "outside-journal.json"
    outside.write_text("{}", encoding="utf-8")
    (transaction / "journal.json").symlink_to(outside)

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert outside.read_text(encoding="utf-8") == "{}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_committed_recovery_rechecks_a_journal_swapped_before_unlink(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "6" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    saved_journal = transaction / "journal-original.json"
    outside = tmp_path / "outside-swapped-journal.json"
    outside.write_text("outside", encoding="utf-8")
    original_iterdir = Path.iterdir
    swapped = []

    def swap_journal_after_transaction_listing(path):
        entries = list(original_iterdir(path))
        if path == transaction and not swapped:
            journal.rename(saved_journal)
            journal.symlink_to(outside)
            swapped.append(path)
        return iter(entries)

    monkeypatch.setattr(Path, "iterdir", swap_journal_after_transaction_listing)

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert outside.read_text(encoding="utf-8") == "outside"
    assert saved_journal.is_file()


def test_committed_recovery_preserves_a_regular_journal_replacement(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "e" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    saved = tmp_path / "saved-removal-journal.json"
    original_validate = removal_module._validate_transaction_contents
    calls = []

    def replace_after_final_transaction_validation(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        calls.append(True)
        if len(calls) == 3:
            payload = journal.read_bytes()
            journal.rename(saved)
            journal.write_bytes(payload)
            if os.name == "posix":
                journal.chmod(0o600)
        return result

    monkeypatch.setattr(
        removal_module,
        "_validate_transaction_contents",
        replace_after_final_transaction_validation,
    )

    with pytest.raises(IntegrityError, match="journal identity"):
        manager.current("mihomo")

    assert journal.is_file()
    assert saved.is_file()
    assert destination.is_dir()


@pytest.mark.parametrize("phase", ("staging", "committed"))
def test_removal_recovery_rechecks_journal_content_before_public_mutation(
    tmp_path,
    monkeypatch,
    phase,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "7" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": phase, "moves": [move]})
    original_validate = removal_module._validate_recorded_move_path
    observations = []

    def change_content_after_action_validation(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        observations.append(True)
        if len(observations) == 3:
            replacement_phase = "committed" if phase == "staging" else "staging"
            payload = journal.read_text(encoding="utf-8").replace(
                '"phase": "%s"' % phase,
                '"phase": "%s"' % replacement_phase,
            )
            journal.write_text(payload, encoding="utf-8")
            if os.name == "posix":
                journal.chmod(0o600)
        return result

    monkeypatch.setattr(
        removal_module,
        "_validate_recorded_move_path",
        change_content_after_action_validation,
    )

    with pytest.raises(IntegrityError, match="journal content changed"):
        manager.current("mihomo")

    assert not source.exists()
    assert destination.is_dir()
    assert journal.is_file()


@pytest.mark.parametrize(
    ("failure_point", "journal_survives", "transaction_survives"),
    (
        ("payload-parent", True, True),
        ("journal-parent", False, True),
        ("transaction-parent", False, False),
    ),
)
def test_committed_removal_delete_flush_failure_remains_recoverable(
    tmp_path,
    monkeypatch,
    failure_point,
    journal_survives,
    transaction_survives,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "a" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    flushes = []

    def fail_selected_parent(path):
        path = Path(path)
        flushes.append(path)
        if failure_point == "payload-parent" and path == transaction and flushes.count(transaction) == 1:
            raise DurabilityError("payload parent flush failed")
        if failure_point == "journal-parent" and path == transaction and flushes.count(transaction) == 2:
            raise DurabilityError("journal parent flush failed")
        if failure_point == "transaction-parent" and path == manager.paths.runtimes:
            raise DurabilityError("transaction parent flush failed")
        return durable_module.FLUSHED

    monkeypatch.setattr(removal_module, "flush_directory", fail_selected_parent, raising=False)

    with pytest.raises(DurabilityError, match="parent flush failed"):
        manager.current("mihomo")

    assert not destination.exists()
    assert journal.exists() is journal_survives
    assert transaction.exists() is transaction_survives

    monkeypatch.undo()
    assert manager.current("mihomo") is None
    assert not transaction.exists()


def test_staging_recovery_flushes_both_completed_move_parents_before_disposal(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "b" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "staging", "moves": [move]})
    flushed = []
    monkeypatch.setattr(
        removal_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)) or durable_module.FLUSHED,
        raising=False,
    )

    assert manager.current("mihomo") is None

    assert flushed[:2] == [transaction, source.parent]
    assert not transaction.exists()
    assert source.is_dir()


def test_staging_recovery_retains_authority_when_completed_move_parent_flush_fails(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "c" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "staging", "moves": [move]})

    def fail_original_parent(path):
        if Path(path) == source.parent:
            raise DurabilityError("simulated restored parent flush failure")
        return durable_module.FLUSHED

    monkeypatch.setattr(
        removal_module,
        "flush_directory",
        fail_original_parent,
        raising=False,
    )

    with pytest.raises(DurabilityError, match="restored parent flush failure"):
        manager.current("mihomo")

    assert journal.is_file()
    assert source.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="POSIX anchored directory flush ordering")
def test_staging_recovery_durably_recreates_a_missing_source_parent(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "e" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    source.parent.rmdir()
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "staging", "moves": [move]})
    flush_kinds = []
    original_flush = anchored_module.flush_descriptor

    def record_flush(descriptor, kind):
        flush_kinds.append(kind)
        return original_flush(descriptor, kind)

    monkeypatch.setattr(anchored_module, "flush_descriptor", record_flush)

    assert manager.current("mihomo") is None

    assert "anchored created directory" in flush_kinds
    assert "anchored created directory parent" in flush_kinds
    assert source.is_dir()
    assert not journal.exists()


def test_clean_flushes_the_parent_of_each_removed_disposable_target(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"log")
    flushed = []
    monkeypatch.setattr(
        manager_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)) or durable_module.FLUSHED,
        raising=False,
    )

    result = manager.clean(areas=("logs",))

    assert result.targets_removed == 1
    assert flushed == [manager.paths.logs]


def test_clean_reports_parent_flush_failure_after_visible_disposable_deletion(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    target = manager.paths.logs / "runtime.log"
    target.write_bytes(b"log")

    def fail_logs_parent(path):
        if Path(path) == manager.paths.logs:
            raise DurabilityError("simulated clean parent flush failure")
        return durable_module.FLUSHED

    monkeypatch.setattr(
        manager_module,
        "flush_directory",
        fail_logs_parent,
        raising=False,
    )

    with pytest.raises(DurabilityError, match="clean parent flush failure"):
        manager.clean(areas=("logs",))

    assert not target.exists()


def test_uninstall_flushes_the_parent_after_removing_an_empty_backend_directory(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    flushed = []
    monkeypatch.setattr(
        manager_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)) or durable_module.FLUSHED,
        raising=False,
    )

    manager.uninstall("mihomo", "1.0.0")

    assert manager.paths.backends in flushed


def test_uninstall_recovers_when_empty_backend_parent_flush_fails(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(
        manager,
        tmp_path,
        "1.0.0",
        b"backend",
        activate=False,
    )

    def fail_backends_parent(path):
        if Path(path) == manager.paths.backends:
            raise DurabilityError("simulated empty backend parent flush failure")
        return durable_module.FLUSHED

    monkeypatch.setattr(
        manager_module,
        "flush_directory",
        fail_backends_parent,
        raising=False,
    )

    with pytest.raises(DurabilityError, match="empty backend parent flush failure"):
        manager.uninstall("mihomo", "1.0.0")

    assert installed.manifest.is_file()
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_committed_recovery_flushes_an_already_absent_payload_before_journal_deletion(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    source.rmdir()
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    attempts = []

    def fail_first_transaction_flush(path):
        path = Path(path)
        attempts.append(path)
        if path == transaction and attempts.count(transaction) == 1:
            raise DurabilityError("simulated absent payload parent flush failure")
        return durable_module.FLUSHED

    monkeypatch.setattr(
        removal_module,
        "flush_directory",
        fail_first_transaction_flush,
        raising=False,
    )

    with pytest.raises(DurabilityError, match="absent payload parent flush failure"):
        manager.current("mihomo")

    assert journal.is_file()
    assert transaction.is_dir()


def test_committed_recovery_preserves_a_transaction_replacement(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "f" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    source.rmdir()
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    saved = tmp_path / "saved-removal-transaction"
    original_validate = removal_module._validate_transaction_contents
    calls = []

    def replace_before_final_transaction_validation(*args, **kwargs):
        calls.append(True)
        if len(calls) == 3:
            payload = journal.read_bytes()
            transaction.rename(saved)
            transaction.mkdir()
            replacement = transaction / "journal.json"
            replacement.write_bytes(payload)
            if os.name == "posix":
                replacement.chmod(0o600)
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(
        removal_module,
        "_validate_transaction_contents",
        replace_before_final_transaction_validation,
    )

    with pytest.raises(IntegrityError, match="transaction identity"):
        manager.current("mihomo")

    assert transaction.is_dir()
    assert (transaction / "journal.json").is_file()
    assert (saved / "journal.json").is_file()


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd deletion behavior")
def test_committed_recovery_final_journal_unlink_cannot_escape_transaction(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "7" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    saved = tmp_path / "saved-transaction"
    outside = tmp_path / "outside-transaction"
    outside.mkdir()
    victim = outside / journal.name
    victim.write_text("outside", encoding="utf-8")
    original_unlink = removal_module.os.unlink
    swapped = []

    def swap_transaction_at_journal_unlink(path, *args, **kwargs):
        if Path(path).name == journal.name and kwargs.get("dir_fd") is not None and not swapped:
            transaction.rename(saved)
            transaction.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(removal_module.os, "unlink", swap_transaction_at_journal_unlink)

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert victim.read_text(encoding="utf-8") == "outside"
    assert transaction.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd deletion behavior")
def test_committed_recovery_final_transaction_rmdir_cannot_escape_runtimes(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "8" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "committed", "moves": [move]},
    )
    saved = tmp_path / "saved-runtimes"
    outside = tmp_path / "outside-runtimes"
    victim = outside / transaction.name
    victim.mkdir(parents=True)
    original_rmdir = removal_module.os.rmdir
    swapped = []

    def swap_runtimes_at_transaction_rmdir(path, *args, **kwargs):
        if Path(path).name == transaction.name and kwargs.get("dir_fd") is not None and not swapped:
            manager.paths.runtimes.rename(saved)
            manager.paths.runtimes.symlink_to(outside, target_is_directory=True)
            swapped.append(path)
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(removal_module.os, "rmdir", swap_runtimes_at_transaction_rmdir)

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert victim.is_dir()
    assert manager.paths.runtimes.is_symlink()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_committed_recovery_windows_journal_replacement_preserves_substitute(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "a" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    original_delete = removal_module._delete_windows_guard
    opened, closed = record_windows_identity_guards(monkeypatch)
    swapped = []

    def replace_journal_before_native_delete(guard, expect_directory):
        if guard.path == journal and not swapped:
            unlink_windows_identity_guard_path(guard)
            journal.write_bytes(b"replacement")
            swapped.append(journal)
            return original_delete(guard, expect_directory)
        return original_delete(guard, expect_directory)

    monkeypatch.setattr(
        removal_module,
        "_delete_windows_guard",
        replace_journal_before_native_delete,
    )

    with pytest.raises(RemovalCleanupError, match="quarantine cleanup failed") as error:
        manager.current("mihomo")

    assert isinstance(error.value.__cause__, PermissionError)
    assert error.value.__cause__.winerror == 5
    assert swapped == [journal]
    assert journal.read_bytes() == b"replacement"
    assert_windows_identity_guards_closed(opened, closed)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_committed_recovery_windows_transaction_replacement_preserves_external_data(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "b" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "committed", "moves": [move]},
    )
    outside = tmp_path / "outside-transaction"
    outside.mkdir()
    outside_marker = outside / "must-survive"
    outside_marker.write_bytes(b"outside")
    original_delete = removal_module._delete_windows_guard
    opened, closed = record_windows_identity_guards(monkeypatch)
    swapped = []

    def replace_transaction_before_native_delete(guard, expect_directory):
        if guard.path == transaction and not swapped:
            unlink_windows_identity_guard_path(guard)
            create_windows_junction(transaction, outside)
            swapped.append(transaction)
            return original_delete(guard, expect_directory)
        return original_delete(guard, expect_directory)

    monkeypatch.setattr(
        removal_module,
        "_delete_windows_guard",
        replace_transaction_before_native_delete,
    )

    try:
        with pytest.raises(RemovalCleanupError, match="quarantine cleanup failed") as error:
            manager.current("mihomo")

        assert isinstance(error.value.__cause__, PermissionError)
        assert error.value.__cause__.winerror == 5
        assert swapped == [transaction]
        assert removal_module.is_path_alias(transaction)
        assert outside.is_dir()
        assert outside_marker.read_bytes() == b"outside"
        assert_windows_identity_guards_closed(opened, closed)
    finally:
        if removal_module.is_path_alias(transaction):
            os.rmdir(str(transaction))


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd deletion behavior")
@pytest.mark.parametrize("change", ("insert", "remove"))
def test_committed_recovery_rechecks_transaction_after_journal_unlink(
    tmp_path,
    monkeypatch,
    change,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "9" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    marker = transaction / "unexpected"
    original_unlink = removal_module.os.unlink
    changed = []

    def change_transaction_after_journal_unlink(path, *args, **kwargs):
        result = original_unlink(path, *args, **kwargs)
        if Path(path).name == journal.name and not changed:
            if change == "insert":
                marker.write_bytes(b"preserve")
            else:
                transaction.rmdir()
            changed.append(path)
        return result

    monkeypatch.setattr(removal_module.os, "unlink", change_transaction_after_journal_unlink)

    expected = "not empty" if change == "insert" else "disappeared before disposal"
    with pytest.raises(IntegrityError, match=expected):
        manager.current("mihomo")

    if change == "insert":
        assert marker.read_bytes() == b"preserve"
    else:
        assert not transaction.exists()


def test_unjournaled_removal_artifact_blocks_state_reads_without_mutation(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "e" * 32)
    transaction.mkdir(mode=0o700)
    marker = transaction / "unknown"
    marker.write_bytes(b"preserve")

    with pytest.raises(IntegrityError, match="no authoritative journal"):
        manager.current("mihomo")
    assert marker.read_bytes() == b"preserve"


def test_initial_removal_journal_temporary_without_payload_is_disposed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    temporary = transaction / (".journal.json.tmp-" + "1" * 32)
    temporary.write_bytes(b"partial journal bytes")
    if os.name == "posix":
        temporary.chmod(0o600)

    assert manager.current("mihomo") is None
    assert not transaction.exists()


def test_initial_removal_journal_temporary_with_payload_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    temporary = transaction / (".journal.json.tmp-" + "1" * 32)
    temporary.write_bytes(b"partial journal bytes")
    payload = transaction / "download-0"
    payload.write_bytes(b"preserve")
    if os.name == "posix":
        temporary.chmod(0o600)

    with pytest.raises(IntegrityError, match="no authoritative journal"):
        manager.current("mihomo")

    assert temporary.read_bytes() == b"partial journal bytes"
    assert payload.read_bytes() == b"preserve"


def test_multiple_initial_removal_journal_temporaries_fail_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    temporaries = [transaction / (".journal.json.tmp-" + character * 32) for character in ("1", "2")]
    for temporary in temporaries:
        temporary.write_bytes(b"partial journal bytes")
        if os.name == "posix":
            temporary.chmod(0o600)

    with pytest.raises(IntegrityError, match="multiple removal journal temporaries"):
        manager.current("mihomo")

    assert all(temporary.read_bytes() == b"partial journal bytes" for temporary in temporaries)


def test_invalid_initial_removal_journal_temporary_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    temporary = transaction / ".journal.json.tmp-not-a-write-id"
    temporary.write_bytes(b"preserve")
    if os.name == "posix":
        temporary.chmod(0o600)

    with pytest.raises(IntegrityError, match="invalid removal journal temporary"):
        manager.current("mihomo")

    assert temporary.read_bytes() == b"preserve"


@pytest.mark.parametrize("unsafe_kind", ("directory", "oversized"))
def test_unsafe_initial_removal_journal_temporary_fails_closed(tmp_path, unsafe_kind):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    temporary = transaction / (".journal.json.tmp-" + "1" * 32)
    if unsafe_kind == "directory":
        temporary.mkdir()
    else:
        temporary.write_bytes(b"x" * (MAXIMUM_JSON_BYTES + 1))
        if os.name == "posix":
            temporary.chmod(0o600)

    with pytest.raises(IntegrityError, match="invalid removal journal temporary"):
        manager.current("mihomo")

    assert os.path.lexists(str(temporary))


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-mode invariant")
def test_nonprivate_initial_removal_journal_temporary_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    temporary = transaction / (".journal.json.tmp-" + "1" * 32)
    temporary.write_bytes(b"preserve")
    temporary.chmod(0o644)

    with pytest.raises(IntegrityError, match="unsafe permissions"):
        manager.current("mihomo")

    assert temporary.read_bytes() == b"preserve"


def test_aliased_initial_removal_journal_temporary_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(mode=0o700)
    outside = tmp_path / "outside-removal-temporary"
    outside.write_bytes(b"preserve")
    temporary = transaction / (".journal.json.tmp-" + "1" * 32)
    try:
        temporary.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(IntegrityError, match="alias"):
        manager.current("mihomo")

    assert temporary.is_symlink()
    assert outside.read_bytes() == b"preserve"


def test_empty_terminal_removal_orphan_is_disposed_on_the_next_lock(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "0" * 32)
    transaction.mkdir(mode=0o700)

    assert manager.current("mihomo") is None
    assert not transaction.exists()


def test_non_file_removal_journal_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "f" * 32)
    transaction.mkdir(mode=0o700)
    (transaction / "journal.json").mkdir()

    with pytest.raises(IntegrityError, match="not a regular file"):
        manager.current("mihomo")


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("journal-inspect", "unable to inspect removal transaction journal"),
        ("journal-size", "invalid removal transaction journal"),
        ("journal-permissions", "unsafe permissions"),
        ("journal-identity", "changed during preflight"),
        ("transaction-inspect", "unable to inspect removal transaction"),
        ("transaction-permissions", "unsafe permissions"),
        ("transaction-identity", "identity changed during preflight"),
    ),
)
def test_removal_evidence_security_failures_preserve_authority(tmp_path, monkeypatch, case, message):
    if case.endswith("permissions") and os.name != "posix":
        pytest.skip("managed permission contract is POSIX-specific")
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "2" * 32)
    transaction.mkdir(mode=0o700)
    move = removal_journal_move(
        manager,
        transaction,
        manager.paths.downloads / "mihomo" / "1.0.0",
    )
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})

    if case == "journal-size":
        journal.write_bytes(b"x" * (1024 * 1024 + 1))
        journal.chmod(0o600)
    elif case == "journal-permissions":
        journal.chmod(0o644)
    elif case == "transaction-permissions":
        transaction.chmod(0o755)
    elif case.endswith("identity"):
        original_matches = removal_module.identity_matches
        selected = journal if case == "journal-identity" else transaction

        def changed_identity(path, expected):
            if path == selected:
                return False
            return original_matches(path, expected)

        monkeypatch.setattr(removal_module, "identity_matches", changed_identity)
    elif case.endswith("inspect"):
        original_lstat = Path.lstat
        selected = journal if case == "journal-inspect" else transaction

        def denied_lstat(path):
            if path == selected:
                raise PermissionError("simulated evidence observation denial")
            return original_lstat(path)

        monkeypatch.setattr(Path, "lstat", denied_lstat)

    with pytest.raises(IntegrityError, match=message):
        manager.current("mihomo")

    assert transaction.exists()
    assert journal.exists()


def test_invalid_removal_namespace_entry_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    invalid = manager.paths.runtimes / ".remove-invalid"
    invalid.mkdir(mode=0o700)

    with pytest.raises(IntegrityError, match="invalid removal transaction entry"):
        manager.current("mihomo")

    assert invalid.is_dir()


def test_journaled_removal_requires_complete_transaction_enumeration(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "3" * 32)
    transaction.mkdir(mode=0o700)
    move = removal_journal_move(
        manager,
        transaction,
        manager.paths.downloads / "mihomo" / "1.0.0",
    )
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "committed", "moves": [move]})
    original_iterdir = Path.iterdir

    def denied_iterdir(path):
        if path == transaction:
            raise PermissionError("simulated transaction enumeration denial")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied_iterdir)

    with pytest.raises(IntegrityError, match="unable to inspect removal transaction"):
        manager.current("mihomo")

    assert journal.is_file()


@pytest.mark.parametrize("race", ("error", "content"))
def test_terminal_removal_orphan_is_revalidated_before_disposal(tmp_path, monkeypatch, race):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "4" * 32)
    transaction.mkdir(mode=0o700)
    marker = transaction / "replacement"
    original_iterdir = Path.iterdir
    observations = []

    def changed_iterdir(path):
        if path == transaction:
            observations.append(path)
            if len(observations) == 2:
                if race == "error":
                    raise PermissionError("simulated terminal observation denial")
                marker.write_bytes(b"preserve")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", changed_iterdir)
    message = "unable to inspect terminal removal transaction|terminal removal transaction is not empty"
    with pytest.raises(IntegrityError, match=message):
        manager.current("mihomo")

    assert transaction.is_dir()
    if race == "content":
        assert marker.read_bytes() == b"preserve"


def test_staging_recovery_rejects_ambiguous_source_and_destination(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "1" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    destination = transaction / "download-0"
    destination.mkdir()
    move = removal_journal_move(manager, transaction, source)
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match="ambiguous removal recovery paths"):
        manager.current("mihomo")

    assert source.is_dir()
    assert destination.is_dir()


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("alias-permission", "unable to inspect managed removal path"),
        ("missing", "removal recovery path disappeared"),
        ("permission", "unable to inspect removal recovery path"),
    ),
)
def test_staging_recovery_rejects_source_observation_races(tmp_path, monkeypatch, failure, message):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "5" * 32)
    transaction.mkdir(mode=0o700)
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    marker = source / "managed.gz"
    marker.write_bytes(b"managed")
    move = removal_journal_move(manager, transaction, source)
    journal = transaction / "journal.json"
    atomic_write_json(journal, {"phase": "staging", "moves": [move]})
    original_lstat = Path.lstat
    original_validate_chain = removal_module._validate_chain
    validated = []

    def mark_validated(root, target, error_type):
        result = original_validate_chain(root, target, error_type)
        if target == source:
            validated.append(source)
        return result

    def failed_lstat(path):
        if path == source and failure == "alias-permission":
            raise PermissionError("simulated alias observation denial")
        if path == source and validated:
            if failure == "missing":
                raise FileNotFoundError("simulated recovery source disappearance")
            raise PermissionError("simulated recovery source observation denial")
        return original_lstat(path)

    monkeypatch.setattr(removal_module, "_validate_chain", mark_validated)
    monkeypatch.setattr(Path, "lstat", failed_lstat)
    with pytest.raises(IntegrityError, match=message):
        manager.current("mihomo")

    assert marker.read_bytes() == b"managed"
    assert journal.is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_staging_recovery_never_restores_through_a_swapped_source_alias(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "7" * 32)
    transaction.mkdir()
    backend_root = manager.paths.downloads / "mihomo"
    source = backend_root / "1.0.0"
    source.mkdir(parents=True)
    (source / "managed.gz").write_bytes(b"managed")
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    backend_root.rmdir()
    outside = tmp_path / "outside-recovery"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    backend_root.symlink_to(outside, target_is_directory=True)
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert marker.read_bytes() == b"outside"
    assert not (outside / "1.0.0").exists()
    assert (destination / "managed.gz").read_bytes() == b"managed"
    assert (transaction / "journal.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_staging_recovery_never_restores_through_a_swapped_source_junction(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "8" * 32)
    transaction.mkdir()
    backend_root = manager.paths.downloads / "mihomo"
    source = backend_root / "1.0.0"
    source.mkdir(parents=True)
    (source / "managed.gz").write_bytes(b"managed")
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    backend_root.rmdir()
    outside = tmp_path / "outside-recovery"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    subprocess.check_call(
        ["cmd", "/c", "mklink", "/J", str(backend_root), str(outside)],
        stdout=subprocess.DEVNULL,
    )
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )

    try:
        with pytest.raises(IntegrityError, match="Windows path alias"):
            manager.current("mihomo")
        assert marker.read_bytes() == b"outside"
        assert not (outside / "1.0.0").exists()
        assert (destination / "managed.gz").read_bytes() == b"managed"
        assert (transaction / "journal.json").is_file()
    finally:
        if os.path.lexists(str(backend_root)):
            os.rmdir(str(backend_root))


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_staging_recovery_rechecks_a_new_source_parent_before_restore(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "9" * 32)
    transaction.mkdir()
    backend_root = manager.paths.downloads / "mihomo"
    source = backend_root / "1.0.0"
    source.mkdir(parents=True)
    (source / "managed.gz").write_bytes(b"managed")
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    backend_root.rmdir()
    outside = tmp_path / "outside-new-parent"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )
    original_ensure = removal_module.AnchoredDirectory.ensure_directory

    def replace_new_parent_with_alias(anchored, parts):
        original_ensure(anchored, parts)
        path = anchored.root.joinpath(*parts)
        if path == backend_root:
            path.rmdir()
            path.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(
        removal_module.AnchoredDirectory,
        "ensure_directory",
        replace_new_parent_with_alias,
    )

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.current("mihomo")

    assert marker.read_bytes() == b"outside"
    assert not (outside / "1.0.0").exists()
    assert (destination / "managed.gz").read_bytes() == b"managed"
    assert (transaction / "journal.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_staging_recovery_rechecks_a_new_source_parent_junction(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "0" * 32)
    transaction.mkdir()
    backend_root = manager.paths.downloads / "mihomo"
    source = backend_root / "1.0.0"
    source.mkdir(parents=True)
    (source / "managed.gz").write_bytes(b"managed")
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    backend_root.rmdir()
    outside = tmp_path / "outside-new-parent"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )
    original_ensure = removal_module.AnchoredDirectory.ensure_directory

    def replace_new_parent_with_junction(anchored, parts):
        original_ensure(anchored, parts)
        path = anchored.root.joinpath(*parts)
        if path == backend_root:
            path.rmdir()
            subprocess.check_call(
                ["cmd", "/c", "mklink", "/J", str(path), str(outside)],
                stdout=subprocess.DEVNULL,
            )

    monkeypatch.setattr(
        removal_module.AnchoredDirectory,
        "ensure_directory",
        replace_new_parent_with_junction,
    )

    try:
        with pytest.raises(IntegrityError, match="Windows path alias"):
            manager.current("mihomo")
        assert marker.read_bytes() == b"outside"
        assert not (outside / "1.0.0").exists()
        assert (destination / "managed.gz").read_bytes() == b"managed"
        assert (transaction / "journal.json").is_file()
    finally:
        if os.path.lexists(str(backend_root)):
            os.rmdir(str(backend_root))


def test_staging_recovery_restores_then_reports_an_identity_mismatch(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "2" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    if move["identity"]["kind"] == "posix":
        move["identity"]["inode"] += 1
    else:
        move["identity"]["file_id"] = "%032x" % (int(move["identity"]["file_id"], 16) + 1)
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match="payload identity changed"):
        manager.current("mihomo")

    assert not source.exists()
    assert destination.is_dir()
    with pytest.raises(IntegrityError, match="payload identity changed"):
        manager.current("mihomo")


def test_committed_recovery_rejects_a_reappeared_public_source(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "3" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "committed", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match="source unexpectedly exists"):
        manager.current("mihomo")

    assert source.is_dir()


def test_committed_recovery_rejects_unexpected_quarantine_content(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "4" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    (transaction / "unexpected").write_bytes(b"unknown")
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "committed", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match="unexpected removal transaction content"):
        manager.current("mihomo")

    assert destination.is_dir()


def test_committed_recovery_keeps_a_retryable_journal_on_permission_failure(
    tmp_path,
    monkeypatch,
):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "5" * 32)
    transaction.mkdir()
    source = manager.paths.downloads / "mihomo" / "1.0.0"
    source.mkdir(parents=True)
    marker = source / "asset.gz"
    marker.write_bytes(b"cache")
    move = removal_journal_move(manager, transaction, source)
    destination = transaction / "download-0"
    os.replace(str(source), str(destination))
    atomic_write_json(
        transaction / "journal.json",
        {"phase": "committed", "moves": [move]},
    )
    if os.name == "posix":
        original_unlink = removal_module.os.unlink

        def deny_payload_unlink(path, *args, **kwargs):
            if Path(path).name == "asset.gz":
                raise PermissionError("payload cleanup denied")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(removal_module.os, "unlink", deny_payload_unlink)
    else:
        original_delete = removal_module._delete_windows_guard

        def deny_payload_unlink(descriptor, expect_directory):
            if descriptor.path.name == "asset.gz":
                raise PermissionError("payload cleanup denied")
            return original_delete(descriptor, expect_directory)

        monkeypatch.setattr(removal_module, "_delete_windows_guard", deny_payload_unlink)

    with pytest.raises(RemovalCleanupError, match="quarantine cleanup failed"):
        manager.current("mihomo")

    assert (transaction / "journal.json").is_file()
    assert (destination / "asset.gz").is_file()


@pytest.mark.parametrize(
    ("name", "version", "areas", "message"),
    [
        (None, None, (), "cleanup areas"),
        (None, None, ("downloads", "downloads"), "duplicates"),
        (None, "1.0.0", ("downloads",), "requires a backend"),
        ("mihomo", None, ("logs",), "only target downloads"),
        (None, None, ("unknown",), "cleanup areas"),
    ],
)
def test_clean_rejects_invalid_public_scopes(tmp_path, name, version, areas, message):
    manager = manager_for(tmp_path)
    with pytest.raises(manager_module.CleanupScopeError, match=message):
        manager.clean(name=name, version=version, areas=areas)


def test_cached_version_inventory_omits_unrecognized_entries(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    backend_cache = manager.paths.downloads / "mihomo"
    (backend_cache / "not-a-release").mkdir(parents=True)
    (backend_cache / "1.0.0").mkdir()

    assert manager.list_cached_versions("mihomo")["mihomo"] == ("1.0.0",)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_clean_rejects_managed_symlink_without_touching_external_data(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    outside = tmp_path / "outside"
    target = outside / "1.0.0"
    target.mkdir(parents=True)
    (target / "asset.gz").write_bytes(b"outside")
    backend_cache = manager.paths.downloads / "mihomo"
    backend_cache.symlink_to(outside, target_is_directory=True)

    with pytest.raises(manager_module.CleanupScopeError, match="managed symlink"):
        manager.clean("mihomo", "1.0.0")
    assert (target / "asset.gz").is_file()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_clean_rejects_nested_managed_symlink_without_touching_external_data(tmp_path):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    outside = tmp_path / "outside-nested"
    outside.mkdir()
    marker = outside / "must-survive.gz"
    marker.write_bytes(b"outside")
    (target / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(manager_module.CleanupScopeError, match="managed symlink"):
        manager.clean("mihomo", "1.0.0")

    assert marker.read_bytes() == b"outside"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_remove_rejects_nested_managed_symlink_without_touching_external_data(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside = tmp_path / "outside-install"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    (installed.manifest.parent / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="managed symlink"):
        manager.uninstall("mihomo", "1.0.0")

    assert marker.read_bytes() == b"outside"
    assert installed.manifest.is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_clean_rejects_windows_junction_without_touching_external_data(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    outside = tmp_path / "outside"
    target = outside / "1.0.0"
    target.mkdir(parents=True)
    marker = target / "must-survive.gz"
    marker.write_bytes(b"outside")
    backend_cache = manager.paths.downloads / "mihomo"
    subprocess.check_call(
        ["cmd", "/c", "mklink", "/J", str(backend_cache), str(outside)],
        stdout=subprocess.DEVNULL,
    )

    try:
        with pytest.raises((IntegrityError, manager_module.CleanupScopeError), match="path alias"):
            manager.clean("mihomo", "1.0.0")
        assert marker.read_bytes() == b"outside"
    finally:
        if os.path.lexists(str(backend_cache)):
            os.rmdir(str(backend_cache))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_clean_rejects_nested_windows_junction_without_touching_external_data(tmp_path):
    manager = manager_for(tmp_path)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    outside = tmp_path / "outside-nested"
    outside.mkdir()
    marker = outside / "must-survive.gz"
    marker.write_bytes(b"outside")
    junction = target / "nested"
    subprocess.check_call(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        stdout=subprocess.DEVNULL,
    )

    try:
        with pytest.raises(manager_module.CleanupScopeError, match="path alias"):
            manager.clean("mihomo", "1.0.0")
        assert marker.read_bytes() == b"outside"
    finally:
        if os.path.lexists(str(junction)):
            os.rmdir(str(junction))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_remove_rejects_nested_windows_junction_without_touching_external_data(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside = tmp_path / "outside-install"
    outside.mkdir()
    marker = outside / "must-survive"
    marker.write_bytes(b"outside")
    junction = installed.manifest.parent / "nested"
    subprocess.check_call(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        stdout=subprocess.DEVNULL,
    )

    try:
        with pytest.raises(IntegrityError, match="path alias"):
            manager.uninstall("mihomo", "1.0.0")
        assert marker.read_bytes() == b"outside"
        assert installed.manifest.is_file()
    finally:
        if os.path.lexists(str(junction)):
            os.rmdir(str(junction))


def test_remove_all_and_download_cleanup_share_one_result(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"two", activate=False)
    cached = manager.paths.downloads / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cache")

    result = manager.uninstall_all("mihomo", cache=True)

    assert result.name == "mihomo"
    assert set(result.versions) == {"1.0.0", "2.0.0"}
    assert result.cleanup.targets_removed == 1
    assert manager.list_installed("mihomo") == []
    assert manager.current("mihomo") is None
    assert not cached.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink failure behavior")
def test_posix_symlink_failure_does_not_downgrade_to_copy(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)

    def fail_symlink(source, target, target_is_directory=False, **kwargs):
        raise OSError("simulated symlink failure")

    monkeypatch.setattr(manager_module.os, "symlink", fail_symlink)
    with pytest.raises(OSError, match="simulated symlink failure"):
        manager.use("mihomo", "1.0.0")
    assert manager.current("mihomo") is None
    assert not (manager.paths.bin / "mihomo").exists()


def test_windows_symlink_failure_uses_and_replaces_a_verified_copy(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def symlink(source, target, target_is_directory=False, **kwargs):
            raise OSError("simulated Windows symlink privilege failure")

    monkeypatch.setattr(activation_module, "os", WindowsOsProxy())
    monkeypatch.setattr(anchored_module.os, "symlink", WindowsOsProxy.symlink)

    first = manager.use("mihomo", "1.0.0")
    second = manager.use("mihomo", "2.0.0")
    selected = manager.which("mihomo")
    exact = manager.which("mihomo", "2.0.0")

    assert first.link_mode == "copy"
    assert second.link_mode == "copy"
    assert selected.link_mode == "copy"
    assert selected.executable == exact.executable
    assert not second.link.is_symlink()
    assert second.link.read_bytes() == b"version two"

    second.link.write_bytes(b"tampered active copy")
    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.which("mihomo")
    assert manager.which("mihomo", "2.0.0") == exact


def test_windows_copy_activation_streams_the_immutable_executable(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    payload = b"x" * (2 * 1024 * 1024 + 3)
    installed = install_fake_mihomo(
        manager,
        tmp_path,
        "1.0.0",
        payload,
        activate=False,
    )

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def symlink(source, target, target_is_directory=False, **kwargs):
            raise OSError("simulated Windows symlink privilege failure")

    original_open = anchored_module.AnchoredDirectory.open_existing_file
    reads = []

    class GuardedReader(object):
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.stream.close()
            return False

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def read(self, size=-1):
            reads.append(size)
            if size < 0 or size > 1024 * 1024:
                raise AssertionError("activation copy attempted an unbounded read")
            return self.stream.read(size)

    def guarded_open(anchored, parts, **kwargs):
        stream, identity = original_open(anchored, parts, **kwargs)
        if anchored.root.joinpath(*parts) == installed.executable:
            return GuardedReader(stream), identity
        return stream, identity

    monkeypatch.setattr(activation_module, "os", WindowsOsProxy())
    monkeypatch.setattr(anchored_module.os, "symlink", WindowsOsProxy.symlink)
    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "open_existing_file",
        guarded_open,
    )

    active = manager.use("mihomo", "1.0.0")

    assert active.link_mode == "copy"
    assert active.link.read_bytes() == payload
    assert reads
    assert max(reads) <= 1024 * 1024


def test_windows_copy_activation_writes_candidates_in_bounded_chunks(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    payload = b"candidate-chunks"
    install_fake_mihomo(manager, tmp_path, "1.0.0", payload, activate=False)

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def symlink(source, target, target_is_directory=False, **kwargs):
            raise OSError("simulated Windows symlink privilege failure")

    original_open = activation_module._open_regular_candidate
    writes = {"link": [], "manifest": []}

    class GuardedWriter(object):
        def __init__(self, stream, name):
            self.stream = stream
            self.name = name

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return self.stream.__exit__(exc_type, exc_value, traceback)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, block):
            writes[self.name].append(len(block))
            return self.stream.write(block)

    def guarded_open(path):
        stream, identity = original_open(path)
        name = "link" if Path(path).parent == manager.paths.bin else "manifest"
        return GuardedWriter(stream, name), identity

    monkeypatch.setattr(activation_module, "os", WindowsOsProxy())
    monkeypatch.setattr(anchored_module.os, "symlink", WindowsOsProxy.symlink)
    monkeypatch.setattr(activation_module, "_COPY_CHUNK_SIZE", 4)
    monkeypatch.setattr(activation_module, "_open_regular_candidate", guarded_open)

    active = manager.use("mihomo", "1.0.0")

    assert active.link_mode == "copy"
    assert active.link.read_bytes() == payload
    assert writes["link"]
    assert writes["manifest"]
    assert max(writes["link"]) <= 4
    assert max(writes["manifest"]) <= 4
    assert len(writes["link"]) > 1
    assert len(writes["manifest"]) > 1


def test_windows_copy_activation_retries_short_candidate_writes(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    payload = b"short-write-copy"
    install_fake_mihomo(manager, tmp_path, "1.0.0", payload, activate=False)

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def symlink(source, target, target_is_directory=False, **kwargs):
            raise OSError("simulated Windows symlink privilege failure")

    original_open = activation_module._open_regular_candidate

    class ShortWriter(object):
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return self.stream.__exit__(exc_type, exc_value, traceback)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, block):
            return self.stream.write(block[:1])

    def short_open(path):
        stream, identity = original_open(path)
        return ShortWriter(stream), identity

    monkeypatch.setattr(activation_module, "os", WindowsOsProxy())
    monkeypatch.setattr(anchored_module.os, "symlink", WindowsOsProxy.symlink)
    monkeypatch.setattr(activation_module, "_COPY_CHUNK_SIZE", 4)
    monkeypatch.setattr(activation_module, "_open_regular_candidate", short_open)

    active = manager.use("mihomo", "1.0.0")

    assert active.link_mode == "copy"
    assert active.link.read_bytes() == payload


@pytest.mark.parametrize("progress", (None, 0, -1, True, 5))
def test_windows_copy_activation_rejects_invalid_candidate_write_progress(
    tmp_path,
    monkeypatch,
    progress,
):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"invalid-write", activate=False)

    class WindowsOsProxy(object):
        name = "nt"

        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def symlink(source, target, target_is_directory=False, **kwargs):
            raise OSError("simulated Windows symlink privilege failure")

    original_open = activation_module._open_regular_candidate

    class InvalidWriter(object):
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return self.stream.__exit__(exc_type, exc_value, traceback)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, block):
            del block
            return progress

    def invalid_open(path):
        stream, identity = original_open(path)
        return InvalidWriter(stream), identity

    monkeypatch.setattr(activation_module, "os", WindowsOsProxy())
    monkeypatch.setattr(anchored_module.os, "symlink", WindowsOsProxy.symlink)
    monkeypatch.setattr(activation_module, "_COPY_CHUNK_SIZE", 4)
    monkeypatch.setattr(activation_module, "_open_regular_candidate", invalid_open)

    with pytest.raises(IntegrityError, match="write made no valid progress"):
        manager.use("mihomo", "1.0.0")

    assert manager.current("mihomo") is None
    assert not list(manager.paths.runtimes.glob(".use-*"))
    assert not list(manager.paths.bin.glob(".*.use-*.candidate"))


@pytest.mark.parametrize("failure", ["launch", "exit", "output"])
def test_default_probe_rejects_unusable_executables_during_switch(tmp_path, monkeypatch, failure):
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        if len(calls) == 1:
            return manager_module.subprocess.CompletedProcess(arguments, 0, stdout="Mihomo Meta v1.0.0\n")
        if failure == "launch":
            raise OSError("cannot execute")
        if failure == "exit":
            return manager_module.subprocess.CompletedProcess(arguments, 2, stdout="failed\n")
        return manager_module.subprocess.CompletedProcess(arguments, 0, stdout="unexpected version\n")

    monkeypatch.setattr(manager_module.subprocess, "run", run)
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
    )
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)

    with pytest.raises(IntegrityError, match="probe"):
        manager.use("mihomo", "1.0.0")
    assert manager.current("mihomo") is None


def test_install_normalizes_a_different_archive_executable_name(tmp_path):
    manager = manager_for(tmp_path)
    archive = tmp_path / "mihomo-core.gz"
    digest = make_gzip_archive(archive, b"backend")

    installed = manager.install_from_archive(
        "mihomo",
        "1.0.0",
        archive,
        expected_sha256=digest,
        archive_executable="mihomo-core",
    )

    assert installed.executable.name == "mihomo"
    assert installed.executable.read_bytes() == b"backend"


@pytest.mark.skipif(os.name != "posix", reason="POSIX staging binding replacement fixture")
def test_install_never_writes_manifest_through_a_replaced_staging_binding(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = make_gzip_archive(archive, b"backend")
    outside = tmp_path / "outside-staging"
    outside.mkdir(mode=0o700)
    outside_executable = outside / "mihomo"
    outside_executable.write_bytes(b"backend")
    outside_executable.chmod(0o755)
    displaced = tmp_path / "displaced-staging"
    original_prepare = anchored_module.AnchoredDirectory.prepare_executable
    replaced = []

    def replace_staging_after_executable_selection(anchored, executable_name, normalized_name=None):
        selected = original_prepare(anchored, executable_name, normalized_name)
        if ".install-" in anchored.root.name and not replaced:
            anchored.root.rename(displaced)
            anchored.root.symlink_to(outside, target_is_directory=True)
            replaced.append(True)
        return selected

    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "prepare_executable",
        replace_staging_after_executable_selection,
    )

    with pytest.raises(IntegrityError):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
            asset_name=archive.name,
            source_url="https://example.test/mihomo.gz",
        )

    assert replaced == [True]
    assert outside_executable.read_bytes() == b"backend"
    assert not (outside / "manifest.json").exists()
    assert list(manager.paths.runtimes.glob(".install-*.json"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable replacement fixture")
def test_install_rejects_replaced_staging_executable_before_probe(tmp_path, monkeypatch):
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = make_gzip_archive(archive, b"trusted!")
    displaced = tmp_path / "displaced-executable"
    observed = []
    original_assert_bound = anchored_module.AnchoredDirectory.assert_bound
    replaced = []

    def replace_validated_executable(anchored, expected_identity=None):
        result = original_assert_bound(anchored, expected_identity)
        executable = anchored.root / "mihomo"
        manifest = anchored.root / "manifest.json"
        if (
            ".install-" in anchored.root.name
            and executable.is_file()
            and manifest.is_file()
            and executable.stat().st_mode & stat.S_IXUSR
            and not replaced
        ):
            executable.rename(displaced)
            executable.write_bytes(b"hostile!")
            executable.chmod(0o755)
            replaced.append(True)
        return result

    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "assert_bound",
        replace_validated_executable,
    )
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: observed.append(installed.executable.read_bytes()),
    )

    with pytest.raises(ArchiveError, match="identity changed"):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
            asset_name=archive.name,
        )

    assert replaced == [True]
    assert observed == []
    assert displaced.read_bytes() == b"trusted!"
    assert not (manager.paths.backends / "mihomo" / "1.0.0").exists()


def test_new_install_rejects_an_incompatible_recorded_asset_platform(tmp_path):
    manager = manager_for(tmp_path)
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"backend")

    with pytest.raises(IntegrityError, match="targets windows-amd64"):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
            asset_platform="windows-amd64",
        )

    assert not (manager.paths.backends / "mihomo" / "1.0.0").exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("executable", "staged backend executable changed during validation"),
        ("manifest", "staged backend manifest changed during validation"),
    ),
)
def test_install_rejects_staged_state_mutated_by_the_probe(tmp_path, mutation, message):
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"trusted!")

    def mutate_staged_state(installed):
        if mutation == "executable":
            installed.executable.write_bytes(b"tampered")
        else:
            installed.manifest.write_bytes(b"{}")

    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=mutate_staged_state,
    )

    with pytest.raises(IntegrityError, match=message):
        manager.install_from_archive(
            "mihomo",
            "1.0.0",
            archive,
            expected_sha256=digest,
        )

    assert not (manager.paths.backends / "mihomo" / "1.0.0").exists()


def test_switch_never_creates_legacy_recovery_backups(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"two", activate=False)

    manager.use("mihomo", "2.0.0")

    assert manager.current("mihomo").version == "2.0.0"
    assert not list(manager.paths.bin.glob("*.rollback"))
    assert not list(manager.paths.active.glob("*.rollback"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "unknown"),
        ("platform", "unknown-platform"),
        ("executable", "../outside"),
        ("sha256", "bad"),
    ],
)
def test_installed_manifest_rejects_invalid_security_fields(tmp_path, field, value):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    manifest = read_json(installed.manifest)
    manifest[field] = value
    atomic_write_json(installed.manifest, manifest)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.list_installed("mihomo")


def test_installed_manifest_requires_all_identity_fields(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    manifest = read_json(installed.manifest)
    manifest.pop("executable_sha256")
    atomic_write_json(installed.manifest, manifest)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.list_installed("mihomo")


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory symlink behavior")
def test_installed_manifest_rejects_a_version_directory_alias_outside_backends(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside = tmp_path / "outside-version"
    installed.manifest.parent.rename(outside)
    installed.manifest.parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="managed backend path must not be a symlink"):
        manager.get_installed("mihomo", "1.0.0")


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_idempotent_install_rejects_a_version_alias_before_reading_external_state(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    archive = tmp_path / "mihomo-1.0.0.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    outside = tmp_path / "outside-version"
    installed.manifest.parent.rename(outside)
    installed.manifest.parent.symlink_to(outside, target_is_directory=True)
    original_manifest = (outside / "manifest.json").read_bytes()

    with pytest.raises(IntegrityError, match="managed backend path must not be a symlink"):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)

    assert (outside / "manifest.json").read_bytes() == original_manifest


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_backend_inventory_reads_reject_an_internal_version_alias(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    stored = manager.paths.backends / "mihomo" / "holder" / "stored"
    stored.parent.mkdir()
    installed.manifest.parent.rename(stored)
    installed.manifest.parent.symlink_to(stored, target_is_directory=True)

    operations = (
        lambda: manager.list_installed("mihomo"),
        lambda: manager.inventory("mihomo"),
        lambda: manager.verify("mihomo"),
    )
    for operation in operations:
        with pytest.raises(IntegrityError, match="managed backend path must not be a symlink"):
            operation()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_installed_manifest_rejects_a_file_alias_outside_backends(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside_manifest = tmp_path / "outside-manifest.json"
    installed.manifest.replace(outside_manifest)
    installed.manifest.symlink_to(outside_manifest)

    with pytest.raises(IntegrityError, match="installed backend manifest"):
        manager.get_installed("mihomo", "1.0.0")

    assert outside_manifest.is_file()


def test_verify_rejects_wrong_platform_and_missing_executable(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    manifest = read_json(installed.manifest)
    manifest["platform"] = "windows-amd64"
    atomic_write_json(installed.manifest, manifest)
    with pytest.raises(IntegrityError, match="targets windows-amd64"):
        manager.verify("mihomo")

    manifest["platform"] = "linux-amd64"
    atomic_write_json(installed.manifest, manifest)
    installed.executable.unlink()
    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.verify("mihomo")


def test_install_from_archive_rejects_an_unregistered_host_platform(tmp_path):
    manager = BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("plan9", "amd64"),
        probe_runner=lambda installed: None,
    )
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"backend")

    with pytest.raises(UnsupportedPlatformError, match="no catalog platform"):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)


def test_active_manifest_rejects_corrupt_identity_and_paths(tmp_path):
    cases = (
        ("missing", None),
        ("name", "xray"),
        ("version", "../bad"),
        ("link_mode", "unknown"),
        ("link", "bin/xray"),
    )
    for index, (field, value) in enumerate(cases):
        home = tmp_path / ("home-%d" % index)
        manager = BackendManager(
            JerryProxyPaths(home),
            platform_info=PlatformInfo("linux", "amd64", "glibc"),
            probe_runner=lambda installed: None,
        )
        install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
        path = manager.paths.active / "mihomo.json"
        manifest = read_json(path)
        if field == "missing":
            manifest.pop("link_mode")
        else:
            manifest[field] = value
        atomic_write_json(path, manifest)
        with pytest.raises(IntegrityError, match="invalid active backend manifest"):
            manager.current("mihomo")


def test_active_manifest_rejects_missing_invalid_and_tampered_links(tmp_path):
    for mode in ("missing", "invalid-symlink", "invalid-copy", "tampered-copy"):
        home = tmp_path / mode
        manager = BackendManager(
            JerryProxyPaths(home),
            platform_info=PlatformInfo("linux", "amd64", "glibc"),
            probe_runner=lambda installed: None,
        )
        installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
        active_path = manager.paths.active / "mihomo.json"
        manifest = read_json(active_path)
        link = manager.paths.bin / "mihomo"
        link.unlink()
        if mode == "invalid-symlink":
            outside = home / "outside"
            outside.write_bytes(b"outside")
            link.symlink_to(outside)
        elif mode == "invalid-copy":
            link.mkdir()
            manifest["link_mode"] = "copy"
        elif mode == "tampered-copy":
            link.write_bytes(b"tampered")
            manifest["link_mode"] = "copy"
        atomic_write_json(active_path, manifest)

        with pytest.raises(IntegrityError, match="incomplete|invalid active backend manifest"):
            manager.current("mihomo")
        assert installed.manifest.is_file()


def test_list_active_uses_the_public_locked_read(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)

    assert [item.version for item in manager.list_active()] == ["1.0.0"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory symlink behavior")
def test_install_rejects_backend_alias_before_writing_outside_home(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    outside = tmp_path / "outside-backends"
    outside.mkdir()
    (manager.paths.backends / "mihomo").symlink_to(outside, target_is_directory=True)
    archive = tmp_path / "mihomo.gz"
    digest = make_gzip_archive(archive, b"backend")

    with pytest.raises(IntegrityError, match="managed backend path must not be a symlink"):
        manager.install_from_archive("mihomo", "1.0.0", archive, expected_sha256=digest)

    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory symlink behavior")
def test_download_rejects_backend_alias_before_transport_or_external_write(tmp_path):
    source = tmp_path / "source.gz"
    digest = make_gzip_archive(source, b"backend")
    asset = CatalogArtifact(
        backend="mihomo",
        version="1.0.0",
        platform="linux-amd64",
        asset_id=1,
        name="mihomo-linux-amd64-v1.0.0.gz",
        url="https://example.test/mihomo.gz",
        sha256=digest,
        size=source.stat().st_size,
        updated_at="2026-01-01T00:00:00Z",
        verification="github-release-digest",
        archive_format="gz",
        executable="mihomo",
    )

    class Catalog(object):
        generated_at = "2026-01-01T00:00:00Z"

        def resolve(self, name, version, platform_info):
            return asset

    class Downloader(object):
        def download(self, *args, **kwargs):
            raise AssertionError("transport must not run through a managed alias")

    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    outside = tmp_path / "outside-downloads"
    outside.mkdir()
    (paths.downloads / "mihomo").symlink_to(outside, target_is_directory=True)
    manager = BackendManager(
        paths,
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        catalog=Catalog(),
        downloader=Downloader(),
        probe_runner=lambda installed: None,
    )

    with pytest.raises(IntegrityError, match="managed backend path must not be a symlink"):
        manager.install("mihomo", "1.0.0")

    assert list(outside.iterdir()) == []


def test_inventory_maps_layout_disappearance_during_lock_acquisition(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    manager.paths.ensure()

    class DisappearingOperationLock(object):
        def __init__(self, *args, **kwargs):
            del args, kwargs

        def __enter__(self):
            raise FileNotFoundError("simulated lock path disappearance")

        def __exit__(self, exception_type, exception, traceback):
            del exception_type, exception, traceback

    monkeypatch.setattr(manager_module, "JerryProxyOperationLock", DisappearingOperationLock)

    with pytest.raises(IntegrityError, match="JerryProxy home changed during read"):
        manager.inventory()


def test_uninstall_tolerates_empty_backend_parent_disappearing_at_rmdir(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    backend_root = manager.paths.backends / "mihomo"
    original_rmdir = Path.rmdir

    def disappear_at_rmdir(path):
        if path == backend_root:
            original_rmdir(path)
            raise FileNotFoundError("simulated concurrent parent cleanup")
        return original_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", disappear_at_rmdir)

    result = manager.uninstall("mihomo", "1.0.0")

    assert result.versions == ("1.0.0",)
    assert not backend_root.exists()
