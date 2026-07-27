"""Backend download, immutable installation, activation, and rollback."""

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..errors import (
    BackendActiveError,
    BackendAlreadyInstalledError,
    BackendNotInstalledError,
    IntegrityError,
)
from ..home import JerryProxyPaths
from ..utils.fs import atomic_write_json, ensure_private_directory, read_json, sha256_file
from .archive import extract_archive, find_executable
from .download import AssetDownloader
from .github import GitHubReleaseClient, select_release_asset
from .lock import BackendOperationLock
from .model import ActiveBackend, InstalledBackend
from .platform import detect_platform
from .registry import get_backend, iter_backends


class BackendManager(object):
    """Manage external backend binaries below a JerryProxy home directory."""

    def __init__(
        self,
        paths,
        platform_info=None,
        release_client=None,
        downloader=None,
    ):
        # type: (JerryProxyPaths, Optional[PlatformInfo], GitHubReleaseClient, AssetDownloader) -> None
        self.paths = paths
        self.platform_info = platform_info or detect_platform()
        self.release_client = release_client or GitHubReleaseClient()
        self.downloader = downloader or AssetDownloader()
        self.paths.ensure()

    @classmethod
    def from_home(cls, home=None):  # type: (Optional[str]) -> "BackendManager"
        return cls(JerryProxyPaths.from_value(home))

    def supported(self):  # type: () -> Iterable[BackendSpec]
        return iter_backends()

    def install(self, name, version, activate=True):  # type: (str, str, bool) -> InstalledBackend
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        tag = spec.tag_for(normalized_version)
        assets = self.release_client.release_assets(spec.repository, tag)
        asset = select_release_asset(spec, normalized_version, self.platform_info, assets)
        download_directory = self.paths.downloads / spec.name / normalized_version
        ensure_private_directory(download_directory)
        archive = download_directory / asset.name
        if archive.exists() and sha256_file(archive) != asset.sha256:
            archive.unlink()
        if not archive.exists():
            self.downloader.download(
                asset.url,
                archive,
                asset.sha256,
                expected_size=asset.size,
            )
        installed = self.install_from_archive(
            spec.name,
            normalized_version,
            archive,
            expected_sha256=asset.sha256,
            asset_name=asset.name,
            source_url=asset.url,
            activate=False,
        )
        if activate:
            self.switch(spec.name, normalized_version)
        return installed

    def install_from_archive(
        self,
        name,
        version,
        archive,
        expected_sha256,
        asset_name=None,
        source_url=None,
        activate=False,
    ):
        # type: (str, str, Path, str, Optional[str], Optional[str], bool) -> InstalledBackend
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        archive = Path(archive)
        actual_sha256 = sha256_file(archive)
        if actual_sha256.lower() != expected_sha256.lower():
            raise IntegrityError(
                "backend asset SHA-256 mismatch: expected %s, got %s" % (expected_sha256.lower(), actual_sha256.lower())
            )

        target = self.paths.backends / spec.name / normalized_version
        lock_path = self._lock_path(spec.name)
        with BackendOperationLock(lock_path):
            if target.exists():
                installed = self._load_installed_manifest(target / "manifest.json")
                if installed.sha256 != actual_sha256:
                    raise BackendAlreadyInstalledError(
                        "%s %s already exists with a different digest" % (spec.name, normalized_version)
                    )
            else:
                installed = self._install_new_version(
                    spec,
                    normalized_version,
                    archive,
                    actual_sha256,
                    asset_name or archive.name,
                    source_url,
                    target,
                )
        if activate:
            self.switch(spec.name, normalized_version)
        return installed

    def _install_new_version(
        self,
        spec,
        version,
        archive,
        sha256,
        asset_name,
        source_url,
        target,
    ):
        # type: (BackendSpec, str, Path, str, str, Optional[str], Path) -> InstalledBackend
        ensure_private_directory(target.parent)
        staging = target.parent / (".%s.tmp-%s" % (version, uuid.uuid4().hex))
        ensure_private_directory(staging)
        try:
            executable_name = spec.executable_filename(self.platform_info)
            extract_archive(archive, staging, executable_name)
            executable = find_executable(staging, executable_name)
            relative_executable = executable.relative_to(staging)
            manifest_value = {
                "schema": "jerryproxy/installed-backend/v1",
                "name": spec.name,
                "version": version,
                "platform": self.platform_info.key,
                "asset_name": asset_name,
                "sha256": sha256,
                "source_url": source_url,
                "executable": str(relative_executable).replace(os.sep, "/"),
                "installed_at": datetime.now(timezone.utc).isoformat(),
            }
            atomic_write_json(staging / "manifest.json", manifest_value)
            os.replace(str(staging), str(target))
        finally:
            if staging.exists():
                shutil.rmtree(str(staging))
        return self._load_installed_manifest(target / "manifest.json")

    def list_installed(self, name=None):  # type: (Optional[str]) -> List[InstalledBackend]
        manifests = []
        if name is not None:
            spec = get_backend(name)
            roots = [self.paths.backends / spec.name]
        else:
            roots = [self.paths.backends / spec.name for spec in iter_backends()]
        for root in roots:
            if not root.exists():
                continue
            manifests.extend(sorted(root.glob("*/manifest.json")))
        installed = [self._load_installed_manifest(manifest) for manifest in manifests]
        return sorted(installed, key=lambda item: (item.name, item.version))

    def get_installed(self, name, version):  # type: (str, str) -> InstalledBackend
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        manifest = self.paths.backends / spec.name / normalized_version / "manifest.json"
        if not manifest.is_file():
            raise BackendNotInstalledError("%s %s is not installed" % (spec.name, normalized_version))
        installed = self._load_installed_manifest(manifest)
        if not installed.executable.is_file():
            raise BackendNotInstalledError("%s %s executable is missing" % (spec.name, normalized_version))
        return installed

    def switch(self, name, version):  # type: (str, str) -> ActiveBackend
        spec = get_backend(name)
        link = self.paths.bin / spec.executable_filename(self.platform_info)
        active_manifest = self.paths.active / ("%s.json" % spec.name)
        with BackendOperationLock(self._lock_path(spec.name)):
            installed = self.get_installed(spec.name, version)
            link_backup = link.with_name(".%s.%s.rollback" % (link.name, uuid.uuid4().hex))
            manifest_backup = active_manifest.with_name(".%s.%s.rollback" % (active_manifest.name, uuid.uuid4().hex))
            had_link = os.path.lexists(str(link))
            had_manifest = active_manifest.is_file()
            if had_link:
                self._backup_path(link, link_backup)
            if had_manifest:
                shutil.copy2(str(active_manifest), str(manifest_backup))
            value = {
                "schema": "jerryproxy/active-backend/v1",
                "name": spec.name,
                "version": installed.version,
                "executable": str(installed.executable.relative_to(self.paths.root)).replace(os.sep, "/"),
                "link": str(link.relative_to(self.paths.root)).replace(os.sep, "/"),
                "activated_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                link_mode = self._replace_active_link(installed.executable, link)
                value["link_mode"] = link_mode
                atomic_write_json(active_manifest, value)
            except OSError:
                # Filesystem failures must restore the previously active command and manifest.
                self._restore_path(link, link_backup, had_link)
                self._restore_path(active_manifest, manifest_backup, had_manifest)
                raise
            finally:
                self._remove_path(link_backup)
                self._remove_path(manifest_backup)
        return ActiveBackend(
            name=spec.name,
            version=installed.version,
            executable=installed.executable,
            link=link,
            link_mode=link_mode,
        )

    def _replace_active_link(self, executable, link):  # type: (Path, Path) -> str
        ensure_private_directory(link.parent)
        temporary = link.with_name(".%s.%s.tmp" % (link.name, os.getpid()))
        if os.path.lexists(str(temporary)):
            temporary.unlink()
        relative_target = os.path.relpath(str(executable), str(link.parent))
        link_mode = "symlink"
        try:
            try:
                os.symlink(relative_target, str(temporary), target_is_directory=False)
            except (OSError, NotImplementedError):
                if os.name != "nt":
                    raise
                # Windows commonly lacks symlink privilege; record an explicit copy fallback.
                link_mode = "copy"
                shutil.copy2(str(executable), str(temporary))
            os.replace(str(temporary), str(link))
        finally:
            if os.path.lexists(str(temporary)):
                temporary.unlink()
        if os.name == "posix" and link_mode == "copy":
            link.chmod(0o755)
        return link_mode

    def current(self, name):  # type: (str) -> Optional[ActiveBackend]
        spec = get_backend(name)
        manifest = self.paths.active / ("%s.json" % spec.name)
        if not manifest.is_file():
            return None
        value = read_json(manifest)
        executable = self.paths.root / str(value["executable"])
        link = self.paths.root / str(value["link"])
        if not executable.is_file() or not os.path.lexists(str(link)):
            raise BackendNotInstalledError("active %s backend is incomplete" % spec.name)
        return ActiveBackend(
            name=spec.name,
            version=str(value["version"]),
            executable=executable,
            link=link,
            link_mode=str(value["link_mode"]),
        )

    def list_active(self):  # type: () -> List[ActiveBackend]
        active = []
        for spec in iter_backends():
            item = self.current(spec.name)
            if item is not None:
                active.append(item)
        return active

    def remove(self, name, version, force=False):  # type: (str, str, bool) -> None
        spec = get_backend(name)
        with BackendOperationLock(self._lock_path(spec.name)):
            installed = self.get_installed(spec.name, version)
            active = self.current(spec.name)
            if active is not None and active.version == installed.version:
                if not force:
                    raise BackendActiveError(
                        "%s %s is active; switch versions or use --force" % (spec.name, installed.version)
                    )
                if os.path.lexists(str(active.link)):
                    active.link.unlink()
                active_manifest = self.paths.active / ("%s.json" % spec.name)
                if active_manifest.exists():
                    active_manifest.unlink()
            shutil.rmtree(str(installed.manifest.parent))

    def _lock_path(self, name):  # type: (str) -> Path
        return self.paths.locks / ("backend-%s.lock" % name)

    @staticmethod
    def _backup_path(source, backup):  # type: (Path, Path) -> None
        if source.is_symlink():
            os.symlink(os.readlink(str(source)), str(backup), target_is_directory=False)
        else:
            shutil.copy2(str(source), str(backup))

    @staticmethod
    def _restore_path(path, backup, existed):  # type: (Path, Path, bool) -> None
        if existed:
            os.replace(str(backup), str(path))
        elif os.path.lexists(str(path)):
            path.unlink()

    @staticmethod
    def _remove_path(path):  # type: (Path) -> None
        if os.path.lexists(str(path)):
            path.unlink()

    @staticmethod
    def _load_installed_manifest(manifest):  # type: (Path) -> InstalledBackend
        return InstalledBackend.from_manifest(manifest, read_json(manifest))
