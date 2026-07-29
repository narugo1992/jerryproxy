import gzip
import hashlib
import io
import multiprocessing
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

import jerryproxy.backend.manager as manager_module
import jerryproxy.backend.removal as removal_module
from jerryproxy.backend.manager import BackendManager
from jerryproxy.backend.model import CatalogArtifact, PlatformInfo
from jerryproxy.errors import (
    ArchiveError,
    BackendActiveError,
    BackendAlreadyInstalledError,
    BackendNotInstalledError,
    IntegrityError,
    JerryProxyBusyError,
    RemovalCleanupError,
    UnsupportedPlatformError,
)
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import JerryProxyOperationLock
from jerryproxy.utils.fs import read_json


def make_gzip_archive(path, payload):
    with gzip.open(str(path), "wb") as stream:
        stream.write(payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manager_for(tmp_path):
    return BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )


def removal_journal_move(manager, transaction, source, destination_name="download-0", kind="download"):
    status = source.lstat() if os.path.lexists(str(source)) else None
    return {
        "kind": kind,
        "source": str(source.relative_to(manager.paths.root)).replace(os.sep, "/"),
        "destination": "runtimes/%s/%s" % (transaction.name, destination_name),
        "device": int(status.st_dev) if status is not None else 0,
        "inode": int(status.st_ino) if status is not None else 0,
        "mode": int(status.st_mode & 0o170000) if status is not None else 0,
    }


class SimulatedWindowsKernel(object):
    """Exercise the Windows handle boundary on non-Windows CI hosts."""

    def __init__(self, failure=None, before_delete=None):
        self.failure = failure
        self.before_delete = before_delete
        self.handles = {}
        self.delete_calls = []

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
        if native.is_symlink():
            flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
        else:
            flags = os.O_RDONLY
        if native.is_dir():
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(native_path, flags)
        self.handles[descriptor] = native
        return descriptor

    def GetFileInformationByHandle(self, handle, information_pointer):
        if self.failure == "information":
            return False
        status = os.fstat(handle)
        information = information_pointer._obj
        file_index = int(status.st_ino)
        if self.failure == "identity":
            file_index = 0
        information.file_index_high = (file_index >> 32) & 0xFFFFFFFF
        information.file_index_low = file_index & 0xFFFFFFFF
        information.volume_serial_number = (
            2 if self.failure == "volume" and not self.handles[handle].is_dir() else 1
        )
        information.number_of_links = int(status.st_nlink) + (1 if self.failure == "links" else 0)
        size = int(status.st_size)
        if self.failure == "size":
            size += 1
        information.file_size_high = (size >> 32) & 0xFFFFFFFF
        information.file_size_low = size & 0xFFFFFFFF
        is_directory = Path(self.handles[handle]).is_dir()
        if self.failure == "type":
            is_directory = not is_directory
        information.file_attributes = (
            removal_module._WINDOWS_FILE_ATTRIBUTE_DIRECTORY if is_directory else 0
        )
        return True

    def SetFileInformationByHandle(self, handle, information_class, disposition_pointer, size):
        assert information_class == removal_module._WINDOWS_FILE_DISPOSITION_INFO_CLASS
        assert size == 1
        assert removal_module.ctypes.sizeof(disposition_pointer._obj) == 1
        assert disposition_pointer._obj.delete_file
        self.delete_calls.append(handle)
        if self.failure == "delete":
            return False
        if self.before_delete is not None:
            self.before_delete()
        original_path = self.handles[handle]
        pinned_path = (
            original_path if original_path.is_symlink() else Path(os.readlink("/proc/self/fd/%d" % handle))
        )
        if pinned_path.is_dir():
            pinned_path.rmdir()
        else:
            pinned_path.unlink()
        return True

    def CloseHandle(self, handle):
        self.handles.pop(handle, None)
        os.close(handle)
        return self.failure != "close"


def _crash_after_removal_move(home, move_number):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os

    class CrashOsProxy(object):
        def __init__(self):
            self.moves = 0

        def replace(self, source, destination):
            host_os.replace(source, destination)
            self.moves += 1
            if self.moves == move_number:
                host_os._exit(20 + move_number)

        def __getattr__(self, name):
            return getattr(host_os, name)

    manager_module.os = CrashOsProxy()
    manager.remove("mihomo", "1.0.0", force=True)


def _crash_before_removal_commit(home):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os
    write_journal = removal_module._write_removal_journal

    def crash_before_commit(transaction, moves, phase="staging"):
        if phase == "committed":
            host_os._exit(27)
        write_journal(transaction, moves, phase)

    removal_module._write_removal_journal = crash_before_commit
    manager.remove("mihomo", "1.0.0", force=True)


def _crash_during_removal_commit_write(home):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os
    write_journal = removal_module._write_removal_journal

    def crash_with_temporary_journal(transaction, moves, phase="staging"):
        if phase == "committed":
            (transaction / ".journal.json.interrupted").write_bytes(b"partial")
            host_os._exit(29)
        write_journal(transaction, moves, phase)

    removal_module._write_removal_journal = crash_with_temporary_journal
    manager.remove("mihomo", "1.0.0", force=True)


def _crash_after_removal_commit(home):
    manager = BackendManager(
        JerryProxyPaths(home),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )
    host_os = manager_module.os

    def crash_before_disposal(paths, transaction):
        host_os._exit(28)

    removal_module._dispose_removal_transaction = crash_before_disposal
    manager.remove("mihomo", "1.0.0", force=True)


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

    switched = manager.switch("mihomo", "2.0.0")
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

    rolled_back = manager.switch("mihomo", "1.0.0")
    assert rolled_back.link.read_bytes() == b"version one"


def test_active_version_removal_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    with pytest.raises(BackendActiveError):
        manager.remove("mihomo", "1.0.0")
    assert manager.current("mihomo").version == "1.0.0"


def test_force_remove_deactivates_exact_version(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    manager.remove("mihomo", "1.0.0", force=True)
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
    assert not list(backend_root.glob(".1.0.0.tmp-*"))


def test_missing_install_and_missing_executable_fail_through_public_lookup(tmp_path):
    manager = manager_for(tmp_path)
    with pytest.raises(BackendNotInstalledError, match="is not installed"):
        manager.get_installed("mihomo", "1.0.0")

    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    installed.executable.unlink()
    with pytest.raises(BackendNotInstalledError, match="executable is missing"):
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
        url="https://example.test/%s" % asset_name,
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
        def download(self, url, destination, expected_sha256, expected_size=None):
            assert url == asset.url
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
    installed = manager.install("mihomo", "v1.19.29")

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
        manager.switch("mihomo", "1.0.0")
    assert manager.current("mihomo") is None


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
    manager.switch("mihomo", "1.0.0")
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
    manager_module.atomic_write_json(installed.manifest, value)

    with pytest.raises(BackendNotInstalledError, match="was installed for windows-amd64"):
        manager.switch("mihomo", "1.0.0")


def test_installed_manifest_identity_must_match_its_directory(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    value = read_json(installed.manifest)
    value["version"] = "2.0.0"
    manager_module.atomic_write_json(installed.manifest, value)

    with pytest.raises(BackendNotInstalledError, match="does not match its directory"):
        manager.list_installed("mihomo")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink containment behavior")
def test_installed_manifest_rejects_an_executable_symlink_escape(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    installed.executable.unlink()
    installed.executable.symlink_to(outside)

    with pytest.raises(BackendNotInstalledError, match="escapes its version directory"):
        manager.get_installed("mihomo", "1.0.0")


def test_active_manifest_rejects_paths_outside_the_home(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["executable"] = "../outside"
    manager_module.atomic_write_json(manifest, value)

    with pytest.raises(BackendNotInstalledError, match="unsafe executable path"):
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

    def fail_manifest_write(path, value):
        raise OSError("simulated manifest failure")

    monkeypatch.setattr(manager_module, "atomic_write_json", fail_manifest_write)
    with pytest.raises(OSError, match="simulated manifest failure"):
        manager.switch("mihomo", "2.0.0")

    assert manager.current("mihomo").version == "1.0.0"
    assert (manager.paths.bin / "mihomo").read_bytes() == b"version one"
    assert read_json(manager.paths.active / "mihomo.json") == original_manifest


def test_switch_preserves_recovery_backups_when_rollback_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    def fail_manifest_write(path, value):
        raise OSError("simulated publication failure")

    def fail_restore(path, backup, existed):
        raise OSError("simulated rollback failure")

    monkeypatch.setattr(manager_module, "atomic_write_json", fail_manifest_write)
    monkeypatch.setattr(manager, "_restore_path", fail_restore)

    with pytest.raises(OSError, match="simulated rollback failure"):
        manager.switch("mihomo", "2.0.0")

    assert len(list(manager.paths.bin.glob("*.rollback"))) == 1
    assert len(list(manager.paths.active.glob("*.rollback"))) == 1


def test_first_switch_removes_new_link_when_manifest_write_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)

    def fail_manifest_write(path, value):
        raise OSError("simulated first manifest failure")

    monkeypatch.setattr(manager_module, "atomic_write_json", fail_manifest_write)
    with pytest.raises(OSError, match="simulated first manifest failure"):
        manager.switch("mihomo", "1.0.0")

    assert not os.path.lexists(str(manager.paths.bin / "mihomo"))
    assert not (manager.paths.active / "mihomo.json").exists()


def test_current_rejects_an_active_backend_with_missing_executable(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    installed.executable.unlink()

    with pytest.raises(BackendNotInstalledError, match="active mihomo backend is incomplete"):
        manager.current("mihomo")


def test_switch_replaces_stale_temporary_link_through_public_api(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)
    temporary = manager.paths.bin / (".mihomo.%s.tmp" % os.getpid())
    temporary.write_bytes(b"stale")

    active = manager.switch("mihomo", "1.0.0")

    assert active.link.read_bytes() == b"version one"
    assert not temporary.exists()


def test_switch_cleans_temporary_link_when_atomic_replace_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=False)

    def fail_replace(source, destination):
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(manager_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated atomic replace failure"):
        manager.switch("mihomo", "1.0.0")

    assert manager.current("mihomo") is None
    assert not list(manager.paths.bin.glob(".mihomo.*.tmp"))


def test_backend_operations_share_one_home_wide_lock(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    with JerryProxyOperationLock(manager.paths):
        with pytest.raises(JerryProxyBusyError):
            manager.switch("mihomo", "2.0.0")
        with pytest.raises(JerryProxyBusyError):
            manager.remove("mihomo", "2.0.0")
        with pytest.raises(JerryProxyBusyError):
            manager.remove_all("mihomo")
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
        (3, "changed before deletion"),
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
    else:
        original_unlink = Path.unlink

        def remove_parent_after_last_child(path, *args, **kwargs):
            result = original_unlink(path, *args, **kwargs)
            if path == child:
                target.rmdir()
                if replace_parent:
                    target.mkdir()
            return result

        monkeypatch.setattr(Path, "unlink", remove_parent_after_last_child)

    if replace_parent:
        with pytest.raises(manager_module.CleanupScopeError, match="parent changed before deletion"):
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
    saved = tmp_path / "saved-logs"
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
def test_clean_rejects_directory_replacement_before_final_anchored_rmdir(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    target = manager.paths.logs / "runtime"
    target.mkdir(parents=True)
    saved = manager.paths.logs / "saved-runtime"
    original_iterdir = Path.iterdir
    original_lstat = removal_module._lstat
    iterations = []
    final_checks = []

    def arm_during_removal_iteration(path):
        entries = list(original_iterdir(path))
        if path == target:
            iterations.append(path)
        return iter(entries)

    def replace_before_final_lstat(path):
        if path == target and len(iterations) == 3:
            final_checks.append(path)
            if len(final_checks) == 2:
                target.rename(saved)
                target.mkdir()
        return original_lstat(path)

    monkeypatch.setattr(Path, "iterdir", arm_during_removal_iteration)
    monkeypatch.setattr(removal_module, "_lstat", replace_before_final_lstat)

    with pytest.raises(manager_module.CleanupScopeError, match="before final deletion"):
        manager.clean(areas=("logs",))

    assert saved.is_dir()
    assert target.is_dir()


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


@pytest.mark.skipif(os.name != "posix", reason="non-POSIX fallback is simulated on POSIX")
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

    result = manager.clean(areas=("logs",))

    assert result.targets_removed == 1
    assert not target.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Windows handle API simulation uses Linux procfs")
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


@pytest.mark.skipif(sys.platform != "linux", reason="Windows handle API simulation uses Linux procfs")
def test_force_remove_deletes_the_allowed_active_symlink_through_a_windows_handle(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    active_link = manager.paths.bin / "mihomo"
    assert active_link.is_symlink()
    kernel = SimulatedWindowsKernel()
    monkeypatch.setattr(removal_module, "_WINDOWS_KERNEL32", kernel)
    monkeypatch.setattr(removal_module, "_windows_error", lambda: OSError("Windows API failure"))

    result = manager.remove("mihomo", "1.0.0", force=True)

    assert result.versions == ("1.0.0",)
    assert not active_link.exists()
    assert kernel.handles == {}


@pytest.mark.skipif(sys.platform != "linux", reason="Windows handle API simulation uses Linux procfs")
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

    result = manager.remove("mihomo", "1.0.0", force=True)

    assert result.versions == ("1.0.0",)
    assert len(disappeared) == 1
    assert kernel.handles == {}


@pytest.mark.skipif(sys.platform != "linux", reason="Windows handle API simulation uses Linux procfs")
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

    def redirect_parent():
        parent.rename(saved)
        parent.symlink_to(outside, target_is_directory=True)

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


@pytest.mark.skipif(sys.platform != "linux", reason="Windows handle API simulation uses Linux procfs")
@pytest.mark.parametrize(
    "failure",
    ("create", "information", "identity", "links", "type", "size", "volume", "delete"),
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


@pytest.mark.skipif(sys.platform != "linux", reason="Windows handle API simulation uses Linux procfs")
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
def test_clean_windows_handle_cannot_be_redirected_by_final_junction_swap(
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
    original_delete = removal_module._delete_windows_guard
    swaps = []

    def swap_parent_then_delete(descriptor, expect_directory):
        if not swaps:
            parent.rename(saved)
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
                check=True,
                capture_output=True,
                text=True,
            )
            swaps.append(parent)
        return original_delete(descriptor, expect_directory)

    monkeypatch.setattr(removal_module, "_delete_windows_guard", swap_parent_then_delete)

    try:
        with pytest.raises(manager_module.CleanupScopeError, match="managed path alias"):
            manager.clean(areas=("logs",))

        assert swaps == [parent]
        assert outside_victim.exists()
        assert not (saved / target.name).exists()
    finally:
        if os.path.lexists(str(parent)):
            os.rmdir(str(parent))
        if saved.exists():
            saved.rename(parent)


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

    result = manager.remove("mihomo", "1.0.0")

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
        manager.remove("mihomo", "1.0.0")

    assert backend_root.is_dir()
    assert installed.manifest.is_file()


def test_forced_remove_failure_restores_the_active_backend(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_replace = manager_module.os.replace

    def fail_active_link_move(source, destination):
        if Path(source) == manager.paths.bin / "mihomo":
            raise PermissionError("active link move denied")
        return original_replace(source, destination)

    monkeypatch.setattr(manager_module.os, "replace", fail_active_link_move)

    with pytest.raises(PermissionError, match="active link move denied"):
        manager.remove("mihomo", "1.0.0", force=True)

    assert installed.manifest.is_file()
    assert manager.current("mihomo").version == "1.0.0"


def test_forced_remove_preserves_recovery_backups_when_restore_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_replace = manager_module.os.replace

    def fail_stage_and_restore(source, destination):
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path == manager.paths.bin / "mihomo":
            raise PermissionError("active link move denied")
        if destination_path == installed.manifest.parent and ".remove-" in source_path.parent.name:
            raise OSError("installed rollback denied")
        return original_replace(source, destination)

    monkeypatch.setattr(manager_module.os, "replace", fail_stage_and_restore)

    with pytest.raises(OSError, match="installed rollback denied"):
        manager.remove("mihomo", "1.0.0", force=True)

    quarantines = [path for path in manager.paths.runtimes.glob(".remove-*") if path.is_dir()]
    assert len(quarantines) == 1
    assert (quarantines[0] / "installed-0").is_dir()


def test_forced_remove_detects_a_restored_path_replaced_during_rollback(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)
    original_replace = manager_module.os.replace
    preserved = tmp_path / "preserved-restored-install"

    def replace_restored_install(source, destination):
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path == manager.paths.bin / "mihomo":
            raise PermissionError("active link move denied")
        result = original_replace(source, destination)
        if destination_path == installed.manifest.parent and ".remove-" in source_path.parent.name:
            destination_path.rename(preserved)
            destination_path.mkdir()
        return result

    monkeypatch.setattr(manager_module.os, "replace", replace_restored_install)

    with pytest.raises(IntegrityError, match="restored a different filesystem object"):
        manager.remove("mihomo", "1.0.0", force=True)

    assert (preserved / "manifest.json").is_file()
    assert installed.manifest.parent.is_dir()


def test_remove_all_failure_keeps_the_active_backend_usable(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    first = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    second = install_fake_mihomo(manager, tmp_path, "2.0.0", b"two", activate=False)
    original_replace = manager_module.os.replace

    def fail_active_version_move(source, destination):
        if Path(source) == first.manifest.parent:
            raise PermissionError("active version move denied")
        return original_replace(source, destination)

    monkeypatch.setattr(manager_module.os, "replace", fail_active_version_move)

    with pytest.raises(PermissionError, match="active version move denied"):
        manager.remove_all("mihomo")

    assert first.manifest.is_file()
    assert second.manifest.is_file()
    assert manager.current("mihomo").version == "1.0.0"


def test_remove_download_cleanup_failure_does_not_change_installed_state(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    cached = manager.paths.downloads / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cache")

    original_replace = manager_module.os.replace

    def fail_download_move(source, destination):
        if Path(source) == cached.parent:
            raise PermissionError("download move denied")
        return original_replace(source, destination)

    monkeypatch.setattr(manager_module.os, "replace", fail_download_move)

    with pytest.raises(PermissionError, match="download move denied"):
        manager.remove("mihomo", "1.0.0", force=True, downloads=True)

    assert installed.manifest.is_file()
    assert cached.is_file()
    assert manager.current("mihomo").version == "1.0.0"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation may require elevated privileges")
def test_remove_rolls_back_a_download_parent_swapped_during_rename(tmp_path, monkeypatch):
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
    host_os = manager_module.os
    swapped = []

    class SwapOsProxy(object):
        def replace(self, source, destination):
            if Path(source) == cached.parent and not swapped:
                backend_root.rename(saved_root)
                backend_root.symlink_to(outside, target_is_directory=True)
                swapped.append(source)
            return host_os.replace(source, destination)

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(manager_module, "os", SwapOsProxy())

    with pytest.raises(IntegrityError, match="payload identity changed"):
        manager.remove("mihomo", "1.0.0", downloads=True)

    quarantine = next(path for path in manager.paths.runtimes.glob(".remove-*") if path.is_dir())
    assert (quarantine / "download-0" / marker.name).read_bytes() == b"outside"
    assert not cached.exists()
    assert (saved_root / "1.0.0" / "archive.gz").read_bytes() == b"managed"
    assert installed.manifest.is_file()


def test_remove_rolls_back_when_rename_moves_a_different_source_object(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=False)
    target = manager.paths.downloads / "mihomo" / "1.0.0"
    target.mkdir(parents=True)
    (target / "archive.gz").write_bytes(b"managed")
    saved = manager.paths.downloads / "saved-original"
    host_os = manager_module.os
    swapped = []

    class SwapOsProxy(object):
        def replace(self, source, destination):
            if Path(source) == target and not swapped:
                target.rename(saved)
                target.mkdir()
                (target / "replacement.gz").write_bytes(b"replacement")
                swapped.append(source)
            return host_os.replace(source, destination)

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(manager_module, "os", SwapOsProxy())

    with pytest.raises(IntegrityError, match="payload identity changed"):
        manager.remove("mihomo", "1.0.0", downloads=True)

    quarantine = next(path for path in manager.paths.runtimes.glob(".remove-*") if path.is_dir())
    assert (saved / "archive.gz").read_bytes() == b"managed"
    assert (quarantine / "download-0" / "replacement.gz").read_bytes() == b"replacement"
    assert not target.exists()
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
    host_os = manager_module.os
    swapped = []

    class SwapOsProxy(object):
        def replace(self, source, destination):
            if Path(source) == cached.parent and not swapped:
                backend_root.rename(saved_root)
                subprocess.check_call(
                    ["cmd", "/c", "mklink", "/J", str(backend_root), str(outside)],
                    stdout=subprocess.DEVNULL,
                )
                swapped.append(source)
            return host_os.replace(source, destination)

        def __getattr__(self, name):
            return getattr(host_os, name)

    monkeypatch.setattr(manager_module, "os", SwapOsProxy())

    try:
        with pytest.raises(IntegrityError, match="payload identity changed"):
            manager.remove("mihomo", "1.0.0", downloads=True)
        quarantine = next(path for path in manager.paths.runtimes.glob(".remove-*") if path.is_dir())
        assert (quarantine / "download-0" / marker.name).read_bytes() == b"outside"
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

    result = manager.remove("mihomo", "1.0.0", downloads=True)

    assert result.cleanup.targets_removed == 0
    assert result.cleanup.bytes_reclaimed == 0
    assert not installed.manifest.parent.exists()
    assert len(checks) == 2


def test_removal_reports_committed_quarantine_cleanup_failure(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)

    def fail_quarantine_cleanup(paths, path):
        raise PermissionError("quarantine cleanup denied")

    with monkeypatch.context() as context:
        context.setattr(removal_module, "_dispose_removal_transaction", fail_quarantine_cleanup)
        with pytest.raises(RemovalCleanupError, match="removal committed.*clean --runtimes"):
            manager.remove("mihomo", "1.0.0", force=True)

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
    assert manager.current("mihomo").version == "1.0.0"
    assert installed.manifest.is_file()
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


def test_crash_during_commit_write_discards_the_atomic_journal_temporary(tmp_path):
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
    assert manager.current("mihomo") is None
    assert not list(manager.paths.runtimes.glob(".remove-*"))


def test_empty_remove_all_is_idempotent_and_leaves_no_transaction(tmp_path):
    manager = manager_for(tmp_path)

    result = manager.remove_all("mihomo", downloads=True)

    assert result.versions == ()
    assert result.cleanup.targets_removed == 0
    assert not list(manager.paths.runtimes.glob(".remove-*"))


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("path-type", "invalid removal journal path"),
        ("path-traversal", "invalid removal journal path"),
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
    elif case == "phase":
        journal["phase"] = "unknown"
    elif case == "moves":
        journal["moves"] = []
    elif case == "move-shape":
        move.pop("mode")
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
        move["inode"] = True
    else:
        duplicate = dict(move)
        duplicate["destination"] = "runtimes/%s/download-1" % transaction.name
        journal["moves"].append(duplicate)
    manager_module.atomic_write_json(transaction / "journal.json", journal)

    with pytest.raises(IntegrityError, match=message):
        manager.current("mihomo")

    assert outside.read_bytes() == b"must survive"


def test_non_json_removal_journal_fails_closed_before_a_state_read(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "b" * 32)
    transaction.mkdir()
    (transaction / "journal.json").write_text("not json", encoding="utf-8")

    with pytest.raises(IntegrityError, match="invalid removal transaction journal"):
        manager.current("mihomo")


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
    transaction.mkdir()
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
    manager_module.atomic_write_json(journal, {"phase": "committed", "moves": [move]})
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
    manager_module.atomic_write_json(journal, {"phase": "committed", "moves": [move]})
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
    manager_module.atomic_write_json(
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
    manager_module.atomic_write_json(journal, {"phase": "committed", "moves": [move]})
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


def test_unjournaled_removal_artifact_is_left_for_explicit_cleanup(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "e" * 32)
    transaction.mkdir()
    marker = transaction / "unknown"
    marker.write_bytes(b"preserve")

    assert manager.current("mihomo") is None
    assert marker.read_bytes() == b"preserve"


def test_non_file_removal_journal_fails_closed(tmp_path):
    manager = manager_for(tmp_path)
    manager.paths.ensure()
    transaction = manager.paths.runtimes / (".remove-" + "f" * 32)
    transaction.mkdir()
    (transaction / "journal.json").mkdir()

    with pytest.raises(IntegrityError, match="not a regular file"):
        manager.current("mihomo")


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
    manager_module.atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )

    with pytest.raises(IntegrityError, match="ambiguous removal recovery paths"):
        manager.current("mihomo")

    assert source.is_dir()
    assert destination.is_dir()


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
    manager_module.atomic_write_json(
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
    manager_module.atomic_write_json(
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
    manager_module.atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )
    original_ensure = removal_module.ensure_private_directory

    def replace_new_parent_with_alias(path):
        original_ensure(path)
        if path == backend_root:
            path.rmdir()
            path.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(removal_module, "ensure_private_directory", replace_new_parent_with_alias)

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
    manager_module.atomic_write_json(
        transaction / "journal.json",
        {"phase": "staging", "moves": [move]},
    )
    original_ensure = removal_module.ensure_private_directory

    def replace_new_parent_with_junction(path):
        original_ensure(path)
        if path == backend_root:
            path.rmdir()
            subprocess.check_call(
                ["cmd", "/c", "mklink", "/J", str(path), str(outside)],
                stdout=subprocess.DEVNULL,
            )

    monkeypatch.setattr(removal_module, "ensure_private_directory", replace_new_parent_with_junction)

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
    move["inode"] = move["inode"] + 1
    manager_module.atomic_write_json(
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
    manager_module.atomic_write_json(
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
    manager_module.atomic_write_json(
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
    manager_module.atomic_write_json(
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
        original_unlink = Path.unlink

        def deny_payload_unlink(path, *args, **kwargs):
            if path.name == "asset.gz":
                raise PermissionError("payload cleanup denied")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", deny_payload_unlink)

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
        manager.remove("mihomo", "1.0.0")

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
            manager.remove("mihomo", "1.0.0")
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

    result = manager.remove_all("mihomo", downloads=True)

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

    def fail_symlink(source, target, target_is_directory=False):
        raise OSError("simulated symlink failure")

    monkeypatch.setattr(manager_module.os, "symlink", fail_symlink)
    with pytest.raises(OSError, match="simulated symlink failure"):
        manager.switch("mihomo", "1.0.0")
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
        def symlink(source, target, target_is_directory=False):
            raise OSError("simulated Windows symlink privilege failure")

    monkeypatch.setattr(manager_module, "os", WindowsOsProxy())

    first = manager.switch("mihomo", "1.0.0")
    second = manager.switch("mihomo", "2.0.0")

    assert first.link_mode == "copy"
    assert second.link_mode == "copy"
    assert not second.link.is_symlink()
    assert second.link.read_bytes() == b"version two"


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
        manager.switch("mihomo", "1.0.0")
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


def test_switch_cleans_partial_backups_when_manifest_backup_fails(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"two", activate=False)

    def fail_copy(source, destination):
        raise OSError("backup unavailable")

    monkeypatch.setattr(manager_module.shutil, "copy2", fail_copy)
    with pytest.raises(OSError, match="backup unavailable"):
        manager.switch("mihomo", "2.0.0")

    assert manager.current("mihomo").version == "1.0.0"
    assert not list(manager.paths.bin.glob("*.rollback"))
    assert not list(manager.paths.active.glob("*.rollback"))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "unknown", "invalid installed backend identity"),
        ("platform", "unknown-platform", "invalid platform"),
        ("executable", "../outside", "unsafe executable path"),
        ("sha256", "bad", "invalid sha256"),
    ],
)
def test_installed_manifest_rejects_invalid_security_fields(tmp_path, field, value, message):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    manifest = read_json(installed.manifest)
    manifest[field] = value
    manager_module.atomic_write_json(installed.manifest, manifest)

    with pytest.raises(BackendNotInstalledError, match=message):
        manager.list_installed("mihomo")


def test_installed_manifest_requires_all_identity_fields(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    manifest = read_json(installed.manifest)
    manifest.pop("executable_sha256")
    manager_module.atomic_write_json(installed.manifest, manifest)

    with pytest.raises(BackendNotInstalledError, match="invalid installed backend manifest"):
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

    with pytest.raises(BackendNotInstalledError, match="manifest escapes the backend home"):
        manager.get_installed("mihomo", "1.0.0")

    assert outside_manifest.is_file()


def test_verify_rejects_wrong_platform_and_missing_executable(tmp_path):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=False)
    manifest = read_json(installed.manifest)
    manifest["platform"] = "windows-amd64"
    manager_module.atomic_write_json(installed.manifest, manifest)
    with pytest.raises(IntegrityError, match="targets windows-amd64"):
        manager.verify("mihomo")

    manifest["platform"] = "linux-amd64"
    manager_module.atomic_write_json(installed.manifest, manifest)
    installed.executable.unlink()
    with pytest.raises(IntegrityError, match="executable is missing"):
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
        ("missing", None, "invalid active backend manifest"),
        ("name", "xray", "wrong backend name"),
        ("version", "../bad", "invalid version"),
        ("link_mode", "unknown", "invalid active backend manifest"),
        ("link", "bin/xray", "paths do not match"),
    )
    for index, (field, value, message) in enumerate(cases):
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
        manager_module.atomic_write_json(path, manifest)
        with pytest.raises(BackendNotInstalledError, match=message):
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
        manager_module.atomic_write_json(active_path, manifest)

        with pytest.raises(BackendNotInstalledError, match="incomplete|invalid|integrity"):
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
