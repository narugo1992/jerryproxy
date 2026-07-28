import gzip
import hashlib
import io
import os
import shutil
import tarfile

import pytest

import jerryproxy.backend.manager as manager_module
from jerryproxy.backend.lock import BackendOperationLock
from jerryproxy.backend.manager import BackendManager
from jerryproxy.backend.model import CatalogArtifact, PlatformInfo
from jerryproxy.errors import (
    ArchiveError,
    BackendActiveError,
    BackendAlreadyInstalledError,
    BackendBusyError,
    BackendNotInstalledError,
    IntegrityError,
)
from jerryproxy.home import JerryProxyPaths
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


def test_manager_public_construction_and_supported_catalog(tmp_path):
    manager = BackendManager.from_home(str(tmp_path / ".jerryproxy"))
    assert manager.paths.root == tmp_path / ".jerryproxy"
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
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(source), str(destination))
            return destination

    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    cached_archive = paths.downloads / "mihomo" / "1.19.29" / asset_name
    cached_archive.parent.mkdir(parents=True)
    cached_archive.write_bytes(b"corrupt cached archive")
    manager = BackendManager(
        paths,
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        catalog=Catalog(),
        downloader=Downloader(),
        probe_runner=lambda installed: None,
    )
    installed = manager.install("mihomo", "v1.19.29")

    assert installed.version == "1.19.29"
    assert installed.executable.read_bytes() == payload
    assert installed.asset_name == asset_name
    assert manager.current("mihomo").version == "1.19.29"
    assert cached_archive.read_bytes() == source.read_bytes()


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


def test_mutating_operations_share_one_backend_lock(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"version one", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"version two", activate=False)

    with BackendOperationLock(manager.paths.locks / "backend-mihomo.lock"):
        with pytest.raises(BackendBusyError):
            manager.switch("mihomo", "2.0.0")
        with pytest.raises(BackendBusyError):
            manager.remove("mihomo", "2.0.0")


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
