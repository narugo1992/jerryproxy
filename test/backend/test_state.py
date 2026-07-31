import gzip
import hashlib
import os
from pathlib import Path

import pytest

import jerryproxy.backend.activation as activation_module
import jerryproxy.backend.anchored as anchored_module
import jerryproxy.backend.state as state_module
from jerryproxy.backend.manager import BackendManager
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.backend.state import (
    load_active_state,
    load_installed_manifest,
    load_staged_installed_manifest,
    validate_staged_installed_manifest_value,
)
from jerryproxy.errors import IntegrityError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.utils.fs import atomic_write_json, read_json


def _manager(tmp_path):
    return BackendManager(
        JerryProxyPaths(tmp_path / ".jerryproxy"),
        platform_info=PlatformInfo("linux", "amd64", "glibc"),
        probe_runner=lambda installed: None,
    )


def _install(manager, tmp_path, activate=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"backend")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return manager.install_from_archive(
        "mihomo",
        "1.0.0",
        archive,
        expected_sha256=digest,
        asset_name="mihomo-linux-amd64-v1.0.0.gz",
        source_url="https://example.test/mihomo.gz",
        activate=activate,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"extra": "unexpected"}),
        lambda value: value.update({"source_url": "https://example.test/archive?credential=secret"}),
        lambda value: value.update({"source_url": "http://example.test/archive"}),
        lambda value: value.update({"installed_at": "not-a-timestamp"}),
        lambda value: value.update({"installed_at": "2026-02-30T00:00:00Z"}),
        lambda value: value.update({"asset_name": "../archive.gz"}),
        lambda value: value.update({"name": "unknown"}),
        lambda value: value.update({"version": "../bad"}),
        lambda value: value.update({"platform": "unknown-platform"}),
        lambda value: value.update({"executable": "/absolute"}),
    ],
)
def test_installed_state_rejects_unknown_or_noncanonical_fields_as_integrity_errors(tmp_path, mutation):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path)
    value = read_json(installed.manifest)
    mutation(value)
    atomic_write_json(installed.manifest, value)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.list_installed("mihomo")


@pytest.mark.parametrize(
    "payload",
    [
        b'{"name":"mihomo","name":"xray"}',
        b'{"name":"\xff"}',
        b'{"name":1.5}',
    ],
)
def test_installed_state_maps_strict_json_failures_to_integrity_errors(tmp_path, payload):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path)
    installed.manifest.write_bytes(payload)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.get_installed("mihomo", "1.0.0")


def test_active_state_rejects_manifest_only_and_link_only_orphans(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    link = manager.paths.bin / "mihomo"

    link.unlink()
    with pytest.raises(IntegrityError, match="active backend state is incomplete"):
        manager.current("mihomo")

    manager = _manager(tmp_path / "second")
    installed = _install(manager, tmp_path / "second", activate=False)
    link = manager.paths.bin / "mihomo"
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        link.write_bytes(installed.executable.read_bytes())
    else:
        link.symlink_to(os.path.relpath(str(installed.executable), str(link.parent)))
    with pytest.raises(IntegrityError, match="active backend state is incomplete"):
        manager.current("mihomo")


def test_active_state_rejects_unknown_keys_and_bad_timestamps(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["extra"] = "unexpected"
    atomic_write_json(manifest, value)
    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")

    value.pop("extra")
    value["activated_at"] = "not-a-timestamp"
    atomic_write_json(manifest, value)
    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


def test_genuine_active_pair_absence_remains_inactive(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=False)
    assert manager.current("mihomo") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows copy-mode state validation")
def test_active_copy_rejects_wrong_digest_on_windows(tmp_path, monkeypatch):
    manager = _manager(tmp_path)

    def force_copy_fallback(*args, **kwargs):
        del args, kwargs
        error = OSError("simulated Windows symlink privilege failure")
        error.winerror = 1314
        raise error

    monkeypatch.setattr(activation_module, "_create_symlink_candidate", force_copy_fallback)
    installed = _install(manager, tmp_path, activate=True)
    link = manager.paths.bin / "mihomo"
    assert manager.current("mihomo").link_mode == "copy"
    link.write_bytes(b"changed")
    assert len(b"changed") == installed.executable.stat().st_size

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


@pytest.mark.skipif(os.name != "nt", reason="Windows simulation of POSIX state permissions")
def test_installed_state_rejects_simulated_unsafe_posix_permissions(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    real_os = state_module.os

    class PosixStateOS(object):
        name = "posix"
        path = real_os.path

        def __getattr__(self, attribute):
            return getattr(real_os, attribute)

    monkeypatch.setattr(state_module, "os", PosixStateOS())
    monkeypatch.setattr(state_module.stat, "S_IMODE", lambda unused_mode: 0o644)

    with pytest.raises(IntegrityError, match="unsafe permissions"):
        manager.get_installed("mihomo", installed.version)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission boundary")
def test_managed_state_rejects_unsafe_manifest_permissions(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    installed.manifest.chmod(0o644)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        manager.list_installed("mihomo")

    manager = _manager(tmp_path / "active")
    _install(manager, tmp_path / "active", activate=True)
    active_manifest = manager.paths.active / "mihomo.json"
    active_manifest.chmod(0o644)
    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink activation fixture")
@pytest.mark.parametrize("failure", ("size", "digest"))
def test_active_copy_rejects_wrong_size_and_digest(tmp_path, failure):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["link_mode"] = "copy"
    atomic_write_json(manifest, value)
    link = manager.paths.bin / "mihomo"
    link.unlink()
    if failure == "size":
        link.write_bytes(b"short")
    else:
        link.write_bytes(b"changed")
        assert len(b"changed") == installed.executable.stat().st_size

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative active copy read requires POSIX")
def test_active_copy_does_not_reopen_the_command_by_path(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["link_mode"] = "copy"
    atomic_write_json(manifest, value)
    link = manager.paths.bin / "mihomo"
    link.unlink()
    link.write_bytes(installed.executable.read_bytes())
    original_open = Path.open

    def deny_command_path_open(path, *args, **kwargs):
        if path == link:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_command_path_open)

    assert manager.current("mihomo").version == "1.0.0"


def test_installed_state_accepts_absent_optional_source_url(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    value = read_json(installed.manifest)
    value["source_url"] = None
    atomic_write_json(installed.manifest, value)

    assert manager.get_installed("mihomo", "1.0.0").version == "1.0.0"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="managed state alias fixture")
def test_installed_state_rejects_alias_and_nonregular_manifest_paths(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    value = installed.manifest.read_bytes()
    outside = tmp_path / "outside-manifest.json"
    outside.write_bytes(value)
    installed.manifest.unlink()
    installed.manifest.symlink_to(outside)

    with pytest.raises(IntegrityError, match="managed path is aliased"):
        load_installed_manifest(manager.paths, installed.manifest)

    installed.manifest.unlink()
    installed.manifest.mkdir()
    with pytest.raises(IntegrityError, match="not a regular file"):
        load_installed_manifest(manager.paths, installed.manifest)


def test_installed_state_maps_manifest_inspection_race(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    original_lstat = Path.lstat

    def deny_manifest(path):
        if path == installed.manifest:
            raise PermissionError("simulated state inspection denial")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", deny_manifest)
    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_installed_manifest(manager.paths, installed.manifest)


def test_installed_state_maps_disappearance_after_chain_validation(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    original_lstat = Path.lstat

    monkeypatch.setattr(state_module, "is_path_alias", lambda path: False)

    def disappear_after_chain_validation(path):
        if path == installed.manifest:
            raise FileNotFoundError("simulated manifest disappearance")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", disappear_after_chain_validation)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_installed_manifest(manager.paths, installed.manifest)


def test_managed_state_rejects_path_replacement_after_descriptor_open(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    manifest = installed.manifest
    displaced = manifest.parent / "manifest.displaced.json"
    replacement = manifest.parent / "manifest.replacement.json"
    replacement.write_bytes(manifest.read_bytes())
    if os.name == "posix":
        replacement.chmod(0o600)
    original_open = anchored_module.AnchoredDirectory.open_existing_file
    replaced = []

    def replace_after_open(anchored, parts):
        stream, identity = original_open(anchored, parts)
        if anchored.root == manifest.parent and parts == (manifest.name,) and not replaced:
            manifest.rename(displaced)
            replacement.rename(manifest)
            replaced.append(manifest)
        return stream, identity

    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "open_existing_file",
        replace_after_open,
    )

    with pytest.raises(IntegrityError, match="invalid installed backend manifest") as error:
        manager.get_installed("mihomo", "1.0.0")

    if os.name == "nt":
        assert isinstance(error.value.__cause__, PermissionError)
        assert error.value.__cause__.winerror == 32
        assert replaced == []
        assert manifest.is_file()
    else:
        assert "changed while being read" in str(error.value.__cause__)
        assert replaced == [manifest]
        assert manifest.read_bytes() == displaced.read_bytes()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("asset_name", ""),
        ("asset_name", "e\u0301.gz"),
        ("version", "v1.0.0"),
    ),
)
def test_installed_state_rejects_empty_non_nfc_and_noncanonical_values(tmp_path, field, value):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    manifest = read_json(installed.manifest)
    manifest[field] = value
    atomic_write_json(installed.manifest, manifest)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_installed_manifest(manager.paths, installed.manifest)


def test_staged_state_requires_the_exact_canonical_final_manifest(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    wrong_final = manager.paths.backends / "mihomo" / "9.9.9" / "manifest.json"

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_staged_installed_manifest(manager.paths, installed.manifest, wrong_final)


def test_installed_state_rejects_a_manifest_outside_backends_before_reading_it(tmp_path):
    manager = _manager(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(IntegrityError, match="managed path escapes its root"):
        load_installed_manifest(manager.paths, outside)


@pytest.mark.parametrize("replacement", ("directory", "symlink"))
def test_installed_state_rejects_nonregular_executable_objects(tmp_path, replacement):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    installed.executable.unlink()
    if replacement == "directory":
        installed.executable.mkdir()
    else:
        outside = tmp_path / "outside-executable"
        outside.write_bytes(b"backend")
        installed.executable.symlink_to(outside)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_installed_manifest(manager.paths, installed.manifest)


def test_active_state_rejects_a_noncanonical_version_before_installed_lookup(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["version"] = "v1.0.0"
    atomic_write_json(manifest, value)

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="active manifest alias fixture")
def test_active_state_rejects_an_aliased_manifest_before_reading_target(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    outside = tmp_path / "outside-active.json"
    manifest.replace(outside)
    manifest.symlink_to(outside)

    with pytest.raises(IntegrityError, match="managed state path is aliased"):
        manager.current("mihomo")


def test_active_state_maps_alias_inspection_failures_to_integrity(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    original_lstat = Path.lstat

    def deny_manifest(path):
        if path == manifest:
            raise PermissionError("simulated active manifest inspection denial")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", deny_manifest)
    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


def test_active_state_maps_resource_alias_api_failures_to_integrity(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    original_alias_check = state_module.is_path_alias

    def deny_manifest(path):
        if Path(path) == manifest:
            raise PermissionError("simulated active resource alias denial")
        return original_alias_check(path)

    monkeypatch.setattr(state_module, "is_path_alias", deny_manifest)

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


def test_installed_state_maps_ancestor_alias_api_failures_to_integrity(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path)
    denied = installed.manifest.parent
    original_alias_check = state_module.is_path_alias

    def deny_version_directory(path):
        if Path(path) == denied:
            raise PermissionError("simulated installed ancestor alias denial")
        return original_alias_check(path)

    monkeypatch.setattr(state_module, "is_path_alias", deny_version_directory)

    with pytest.raises(IntegrityError, match="unable to inspect managed path"):
        manager.get_installed("mihomo", "1.0.0")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sha256", "bad"),
        ("executable", "C:escape"),
    ),
)
def test_installed_state_rejects_digest_and_windows_drive_values(tmp_path, field, value):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    manifest = read_json(installed.manifest)
    manifest[field] = value
    atomic_write_json(installed.manifest, manifest)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_installed_manifest(manager.paths, installed.manifest)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("link_mode", "unknown"),
        ("link", "bin/other"),
    ),
)
def test_active_state_rejects_invalid_mode_and_recorded_paths(tmp_path, field, value):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    payload = read_json(manifest)
    payload[field] = value
    atomic_write_json(manifest, payload)

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink target fixture")
def test_active_state_rejects_a_wrong_public_symlink_target(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    link = manager.paths.bin / "mihomo"
    link.unlink()
    link.symlink_to("../backends/mihomo/9.9.9/mihomo")

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        manager.current("mihomo")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink observation boundary")
def test_active_state_rejects_symlink_replacement_after_read(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    link = manager.paths.bin / "mihomo"
    outside = tmp_path / "outside"
    outside.write_bytes(b"attacker")
    replacement_target = os.path.relpath(str(outside), str(link.parent))
    original_readlink = anchored_module.os.readlink
    replaced = {"value": False}

    def replace_after_read(path, *args, **kwargs):
        target = original_readlink(path, *args, **kwargs)
        if path == link.name and not replaced["value"]:
            replaced["value"] = True
            link.unlink()
            link.symlink_to(replacement_target)
        return target

    monkeypatch.setattr(anchored_module.os, "readlink", replace_after_read)
    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        load_active_state(manager.paths, "mihomo", manager.platform_info)
    assert os.readlink(str(link)) == replacement_target


def test_active_state_maps_manifest_disappearance_after_alias_check(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    original_lstat = Path.lstat

    monkeypatch.setattr(state_module, "is_path_alias", lambda path: False)

    def disappear_after_alias_check(path):
        if path == manifest:
            raise FileNotFoundError("simulated manifest disappearance")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", disappear_after_alias_check)

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        load_active_state(manager.paths, "mihomo", manager.platform_info)


def test_active_state_rejects_nonregular_manifest_object(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    manifest.unlink()
    manifest.mkdir()

    with pytest.raises(IntegrityError, match="managed state is not a regular file"):
        load_active_state(manager.paths, "mihomo", manager.platform_info)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor permission boundary")
def test_active_state_rejects_permissions_changed_after_descriptor_open(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    original_open = anchored_module.AnchoredDirectory.open_existing_file

    def make_unsafe_after_open(anchored, parts):
        stream, identity = original_open(anchored, parts)
        if anchored.root == manifest.parent and parts == (manifest.name,):
            manifest.chmod(0o644)
        return stream, identity

    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "open_existing_file",
        make_unsafe_after_open,
    )

    with pytest.raises(IntegrityError, match="invalid active backend manifest") as error:
        load_active_state(manager.paths, "mihomo", manager.platform_info)

    assert "unsafe permissions" in str(error.value.__cause__)


def test_active_state_rejects_path_replacement_after_descriptor_open(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    displaced = manifest.with_name("mihomo.displaced.json")
    replacement = manifest.with_name("mihomo.replacement.json")
    replacement.write_bytes(manifest.read_bytes())
    if os.name == "posix":
        replacement.chmod(0o600)
    original_open = anchored_module.AnchoredDirectory.open_existing_file

    def replace_after_open(anchored, parts):
        stream, identity = original_open(anchored, parts)
        if anchored.root == manifest.parent and parts == (manifest.name,):
            manifest.rename(displaced)
            replacement.rename(manifest)
        return stream, identity

    monkeypatch.setattr(
        anchored_module.AnchoredDirectory,
        "open_existing_file",
        replace_after_open,
    )

    with pytest.raises(IntegrityError, match="invalid active backend manifest") as error:
        load_active_state(manager.paths, "mihomo", manager.platform_info)

    if os.name == "nt":
        assert isinstance(error.value.__cause__, PermissionError)
        assert error.value.__cause__.winerror == 32
    else:
        assert "changed while being read" in str(error.value.__cause__)


def test_installed_state_rejects_manifest_at_noncanonical_backend_location(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    unexpected = manager.paths.backends / "mihomo" / "unexpected" / "manifest.json"
    unexpected.parent.mkdir()
    unexpected.write_bytes(installed.manifest.read_bytes())
    if os.name == "posix":
        unexpected.chmod(0o600)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        load_installed_manifest(manager.paths, unexpected)


def test_staged_state_rejects_manifest_path_outside_backend_root(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    outside = tmp_path / "staged-manifest.json"

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        validate_staged_installed_manifest_value(
            manager.paths,
            outside,
            installed.manifest,
            read_json(installed.manifest),
        )


def test_installed_state_rejects_executable_digest_mismatch(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)
    installed.executable.write_bytes(b"changed")

    with pytest.raises(IntegrityError, match="executable SHA-256 mismatch"):
        load_installed_manifest(manager.paths, installed.manifest)


def test_staged_state_loads_exact_canonical_manifest(tmp_path):
    manager = _manager(tmp_path)
    installed = _install(manager, tmp_path, activate=False)

    loaded = load_staged_installed_manifest(
        manager.paths,
        installed.manifest,
        installed.manifest,
    )

    assert loaded == installed


def test_active_state_rejects_backend_name_mismatch(tmp_path):
    manager = _manager(tmp_path)
    _install(manager, tmp_path, activate=True)
    manifest = manager.paths.active / "mihomo.json"
    value = read_json(manifest)
    value["name"] = "xray"
    atomic_write_json(manifest, value)

    with pytest.raises(IntegrityError, match="invalid active backend manifest"):
        load_active_state(manager.paths, "mihomo", manager.platform_info)
