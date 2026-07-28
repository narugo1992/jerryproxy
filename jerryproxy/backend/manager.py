"""Backend download, immutable installation, activation, and rollback."""

import errno
import os
import shutil
import subprocess
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from ..errors import (
    BackendActiveError,
    BackendAlreadyInstalledError,
    BackendNotInstalledError,
    CleanupScopeError,
    IntegrityError,
    UnsupportedBackendError,
    UnsupportedPlatformError,
)
from ..home import JerryProxyPaths
from ..utils.fs import atomic_write_json, ensure_private_directory, read_json, sha256_file
from .archive import extract_archive, find_executable
from .catalog import BackendCatalog
from .download import AssetDownloader
from .lock import BackendOperationLock
from .model import ActiveBackend, CleanupResult, InstalledBackend, RemovalResult
from .platform import detect_platform
from .registry import get_backend, iter_backend_platforms, iter_backends, version_sort_key


class BackendManager(object):
    """Manage external backend binaries below a JerryProxy home directory."""

    def __init__(
        self,
        paths,
        platform_info=None,
        catalog=None,
        downloader=None,
        probe_runner=None,
    ):
        # type: (JerryProxyPaths, Optional[PlatformInfo], BackendCatalog, AssetDownloader, Callable) -> None
        self.paths = paths
        self.platform_info = platform_info or detect_platform()
        self.catalog = catalog or BackendCatalog.load()
        self.downloader = downloader or AssetDownloader()
        self.probe_runner = probe_runner or self._probe_installed
        self.paths.ensure()

    @classmethod
    def from_home(cls, home=None):  # type: (Optional[str]) -> "BackendManager"
        return cls(JerryProxyPaths.from_value(home))

    def supported(self):  # type: () -> Iterable[BackendSpec]
        return iter_backends()

    def available(self, name):  # type: (str) -> tuple
        return self.catalog.available_versions(name, self.platform_info)

    def resolve_artifact(self, name, version=None):
        # type: (str, Optional[str]) -> CatalogArtifact
        return self.catalog.resolve(name, version, self.platform_info)

    def install(self, name, version=None, activate=True):
        # type: (str, Optional[str], bool) -> InstalledBackend
        spec = get_backend(name)
        asset = self.resolve_artifact(spec.name, version)
        normalized_version = asset.version
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
            asset_platform=asset.platform,
            archive_executable=asset.executable,
            activate=False,
        )
        if activate:
            self.switch(spec.name, normalized_version)
        return installed

    def _probe_installed(self, installed):  # type: (InstalledBackend) -> None
        spec = get_backend(installed.name)
        arguments = [str(installed.executable)] + list(spec.version_arguments)
        try:
            completed = subprocess.run(
                arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            # Launch failures and bounded timeouts mean the selected binary is unusable.
            raise IntegrityError("%s %s executable probe failed: %s" % (installed.name, installed.version, error))
        if completed.returncode != 0:
            raise IntegrityError(
                "%s %s executable probe exited with status %d"
                % (installed.name, installed.version, completed.returncode)
            )
        if installed.version not in (completed.stdout or ""):
            raise IntegrityError(
                "%s executable probe did not report expected version %s" % (installed.name, installed.version)
            )

    def install_from_archive(
        self,
        name,
        version,
        archive,
        expected_sha256,
        asset_name=None,
        source_url=None,
        asset_platform=None,
        archive_executable=None,
        activate=False,
    ):
        # type: (str, str, Path, str, Optional[str], Optional[str], Optional[str], Optional[str], bool) -> InstalledBackend
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        selected_platform = asset_platform or self._default_asset_platform(spec.name)
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
                self._verify_installed_executable(installed)
                self.probe_runner(installed)
            else:
                installed = self._install_new_version(
                    spec,
                    normalized_version,
                    archive,
                    actual_sha256,
                    asset_name or archive.name,
                    source_url,
                    selected_platform,
                    archive_executable,
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
        asset_platform,
        archive_executable,
        target,
    ):
        # type: (BackendSpec, str, Path, str, str, Optional[str], str, Optional[str], Path) -> InstalledBackend
        ensure_private_directory(target.parent)
        staging = target.parent / (".%s.tmp-%s" % (version, uuid.uuid4().hex))
        ensure_private_directory(staging)
        try:
            executable_name = spec.executable_filename(self.platform_info)
            source_executable_name = archive_executable or executable_name
            extract_archive(archive, staging, source_executable_name)
            executable = find_executable(staging, source_executable_name)
            if executable.name != executable_name:
                normalized_executable = executable.with_name(executable_name)
                os.replace(str(executable), str(normalized_executable))
                executable = normalized_executable
            relative_executable = executable.relative_to(staging)
            manifest_value = {
                "name": spec.name,
                "version": version,
                "platform": asset_platform,
                "asset_name": asset_name,
                "sha256": sha256,
                "executable_sha256": sha256_file(executable),
                "source_url": source_url,
                "catalog_generated_at": self.catalog.generated_at,
                "executable": str(relative_executable).replace(os.sep, "/"),
                "installed_at": datetime.now(timezone.utc).isoformat(),
            }
            staging_manifest = staging / "manifest.json"
            atomic_write_json(staging_manifest, manifest_value)
            staged = InstalledBackend.from_manifest(staging_manifest, manifest_value)
            self._verify_installed_executable(staged)
            self.probe_runner(staged)
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
        grouped = []
        for spec in iter_backends():
            versions = [item for item in installed if item.name == spec.name]
            grouped.extend(sorted(versions, key=lambda item: version_sort_key(item.version), reverse=True))
        return grouped

    def get_installed(self, name, version):  # type: (str, str) -> InstalledBackend
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        manifest = self.paths.backends / spec.name / normalized_version / "manifest.json"
        if not manifest.is_file():
            raise BackendNotInstalledError("%s %s is not installed" % (spec.name, normalized_version))
        installed = self._load_installed_manifest(manifest)
        if installed.platform not in self.platform_info.compatible_asset_keys:
            raise BackendNotInstalledError(
                "%s %s was installed for %s, not %s"
                % (spec.name, normalized_version, installed.platform, self.platform_info.asset_key)
            )
        if not installed.executable.is_file():
            raise BackendNotInstalledError("%s %s executable is missing" % (spec.name, normalized_version))
        return installed

    def verify(self, name=None):  # type: (Optional[str]) -> List[InstalledBackend]
        """Re-hash installed executables and return every verified version."""
        installed = self.list_installed(name=name)
        for item in installed:
            self._verify_installed_executable(item)
        return installed

    def update(self, name):  # type: (str) -> InstalledBackend
        """Install and activate the newest compatible catalog release."""
        return self.install(name, version=None, activate=True)

    def switch(self, name, version):  # type: (str, str) -> ActiveBackend
        spec = get_backend(name)
        link = self.paths.bin / spec.executable_filename(self.platform_info)
        active_manifest = self.paths.active / ("%s.json" % spec.name)
        with BackendOperationLock(self._lock_path(spec.name)):
            installed = self.get_installed(spec.name, version)
            self._verify_installed_executable(installed)
            self.probe_runner(installed)
            link_backup = link.with_name(".%s.%s.rollback" % (link.name, uuid.uuid4().hex))
            manifest_backup = active_manifest.with_name(".%s.%s.rollback" % (active_manifest.name, uuid.uuid4().hex))
            had_link = os.path.lexists(str(link))
            had_manifest = active_manifest.is_file()
            if had_link:
                self._backup_path(link, link_backup)
            if had_manifest:
                shutil.copy2(str(active_manifest), str(manifest_backup))
            value = {
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
        required = ("name", "version", "executable", "link", "link_mode")
        if any(not isinstance(value.get(key), str) or not value[key] for key in required):
            raise BackendNotInstalledError("invalid active backend manifest: %s" % manifest)
        if value["name"] != spec.name:
            raise BackendNotInstalledError("active backend manifest has the wrong backend name: %s" % manifest)
        try:
            version = spec.normalize_version(value["version"])
        except ValueError:
            raise BackendNotInstalledError("active backend manifest has an invalid version: %s" % manifest)
        if version != value["version"] or value["link_mode"] not in ("symlink", "copy"):
            raise BackendNotInstalledError("invalid active backend manifest: %s" % manifest)
        executable_path = self._safe_relative_path(value["executable"], manifest, "executable")
        link_path = self._safe_relative_path(value["link"], manifest, "link")
        try:
            installed = self.get_installed(spec.name, version)
        except BackendNotInstalledError:
            raise BackendNotInstalledError("active %s backend is incomplete" % spec.name)
        expected_link = self.paths.bin / spec.executable_filename(self.platform_info)
        if executable_path != installed.executable or link_path != expected_link:
            raise BackendNotInstalledError("active backend manifest paths do not match %s %s" % (spec.name, version))
        if not os.path.lexists(str(link_path)):
            raise BackendNotInstalledError("active %s backend is incomplete" % spec.name)
        if value["link_mode"] == "symlink":
            if not link_path.is_symlink() or link_path.resolve() != installed.executable.resolve():
                raise BackendNotInstalledError("active %s backend link is invalid" % spec.name)
        elif link_path.is_symlink() or not link_path.is_file():
            raise BackendNotInstalledError("active %s backend copy is invalid" % spec.name)
        elif sha256_file(link_path) != installed.executable_sha256:
            raise BackendNotInstalledError("active %s backend copy failed integrity verification" % spec.name)
        return ActiveBackend(
            name=spec.name,
            version=version,
            executable=installed.executable,
            link=link_path,
            link_mode=str(value["link_mode"]),
        )

    def list_active(self):  # type: () -> List[ActiveBackend]
        active = []
        for spec in iter_backends():
            item = self.current(spec.name)
            if item is not None:
                active.append(item)
        return active

    def remove(self, name, version, force=False, downloads=False):
        # type: (str, str, bool, bool) -> RemovalResult
        """Remove one installed version and optionally its cached downloads."""

        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        with BackendOperationLock(self._lock_path(spec.name)):
            cleanup_targets = self._download_cleanup_targets(spec.name, normalized_version) if downloads else []
            installed = self.get_installed(spec.name, normalized_version)
            active = self.current(spec.name)
            if active is not None and active.version == installed.version:
                if not force:
                    raise BackendActiveError(
                        "%s %s is active; switch versions or use --force" % (spec.name, installed.version)
                    )
                self._deactivate(active)
            shutil.rmtree(str(installed.manifest.parent))
            self._remove_empty_directory(installed.manifest.parent.parent)
            cleanup = (
                self._remove_cleanup_targets(("downloads",), cleanup_targets)
                if downloads
                else CleanupResult((), 0, 0)
            )
        return RemovalResult(spec.name, (installed.version,), cleanup)

    def remove_all(self, name, downloads=False):  # type: (str, bool) -> RemovalResult
        """Remove every installed version of one backend and deactivate it."""

        spec = get_backend(name)
        with BackendOperationLock(self._lock_path(spec.name)):
            cleanup_targets = self._download_cleanup_targets(spec.name, None) if downloads else []
            installed = self.list_installed(spec.name)
            active = self.current(spec.name)
            if active is not None:
                self._deactivate(active)
            for item in installed:
                shutil.rmtree(str(item.manifest.parent))
            self._remove_empty_directory(self.paths.backends / spec.name)
            cleanup = (
                self._remove_cleanup_targets(("downloads",), cleanup_targets)
                if downloads
                else CleanupResult((), 0, 0)
            )
        return RemovalResult(spec.name, tuple(item.version for item in installed), cleanup)

    def clean(self, name=None, version=None, areas=None):
        # type: (Optional[str], Optional[str], Optional[Iterable[str]]) -> CleanupResult
        """Remove selected disposable data without touching installed backends."""

        selected_areas = tuple(("downloads",) if areas is None else areas)
        allowed_areas = ("downloads", "logs", "providers", "runtimes")
        if not selected_areas or any(area not in allowed_areas for area in selected_areas):
            raise CleanupScopeError("cleanup areas must be selected from: %s" % ", ".join(allowed_areas))
        if len(set(selected_areas)) != len(selected_areas):
            raise CleanupScopeError("cleanup areas must not contain duplicates")
        if version is not None and name is None:
            raise CleanupScopeError("a cleanup version requires a backend name")
        if name is not None and selected_areas != ("downloads",):
            raise CleanupScopeError("backend-scoped cleanup can only target downloads")

        normalized_name = None
        normalized_version = None
        if name is not None:
            spec = get_backend(name)
            normalized_name = spec.name
            if version is not None:
                normalized_version = spec.normalize_version(version)

        lock_names = []
        if "downloads" in selected_areas:
            lock_names = [normalized_name] if normalized_name else [spec.name for spec in iter_backends()]
        with ExitStack() as stack:
            for lock_name in lock_names:
                stack.enter_context(BackendOperationLock(self._lock_path(lock_name)))
            targets = []
            for area in selected_areas:
                if area == "downloads":
                    targets.extend(self._download_cleanup_targets(normalized_name, normalized_version))
                else:
                    targets.extend(self._area_cleanup_targets(area))
            return self._remove_cleanup_targets(selected_areas, targets)

    def list_cached_versions(self, name=None):  # type: (Optional[str]) -> dict
        """Return exact cached release versions grouped by backend name."""

        names = [get_backend(name).name] if name is not None else [spec.name for spec in iter_backends()]
        cached = {}
        for backend_name in names:
            backend_root = self.paths.downloads / backend_name
            self._validate_cleanup_chain(self.paths.downloads, backend_root)
            versions = []
            if backend_root.exists():
                for candidate in backend_root.iterdir():
                    self._validate_cleanup_chain(self.paths.downloads, candidate)
                    try:
                        normalized = get_backend(backend_name).normalize_version(candidate.name)
                        version_sort_key(normalized)
                    except ValueError:
                        # Non-release cache entries are omitted from exact-version selection.
                        continue
                    if normalized == candidate.name:
                        versions.append(normalized)
            cached[backend_name] = tuple(sorted(versions, key=version_sort_key, reverse=True))
        return cached

    def _deactivate(self, active):  # type: (ActiveBackend) -> None
        if os.path.lexists(str(active.link)):
            active.link.unlink()
        active_manifest = self.paths.active / ("%s.json" % active.name)
        if active_manifest.exists():
            active_manifest.unlink()

    def _download_cleanup_targets(self, name, version):
        # type: (Optional[str], Optional[str]) -> List[Path]
        root = self.paths.downloads
        if name is None:
            return self._area_cleanup_targets("downloads")
        backend_root = root / name
        self._validate_cleanup_chain(root, backend_root)
        if version is None:
            return [backend_root] if os.path.lexists(str(backend_root)) else []
        target = backend_root / version
        self._validate_cleanup_chain(root, target)
        return [target] if os.path.lexists(str(target)) else []

    def _area_cleanup_targets(self, area):  # type: (str) -> List[Path]
        root = getattr(self.paths, area)
        self._validate_cleanup_chain(root, root)
        return list(root.iterdir())

    def _validate_cleanup_chain(self, root, target):  # type: (Path, Path) -> None
        current = target
        while True:
            if current.is_symlink():
                raise CleanupScopeError("refusing cleanup through managed symlink: %s" % current)
            if current == root:
                return
            if current == self.paths.root or current.parent == current:
                raise CleanupScopeError("cleanup target escapes managed area: %s" % target)
            current = current.parent

    def _remove_cleanup_targets(self, areas, targets):
        # type: (Iterable[str], Iterable[Path]) -> CleanupResult
        removed = 0
        reclaimed = 0
        for target in targets:
            if not os.path.lexists(str(target)):
                continue
            reclaimed += self._path_size(target)
            if target.is_symlink() or not target.is_dir():
                target.unlink()
            else:
                shutil.rmtree(str(target))
            removed += 1
        return CleanupResult(tuple(areas), removed, reclaimed)

    @classmethod
    def _path_size(cls, path):  # type: (Path) -> int
        if path.is_symlink() or not path.is_dir():
            return path.lstat().st_size
        return sum(cls._path_size(child) for child in path.iterdir())

    @staticmethod
    def _remove_empty_directory(path):  # type: (Path) -> None
        try:
            path.rmdir()
        except FileNotFoundError:
            # Another cleanup path may already have removed this empty parent.
            return
        except OSError as error:
            # A non-empty parent is intentionally preserved; other filesystem errors remain fatal.
            if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise

    def _lock_path(self, name):  # type: (str) -> Path
        return self.paths.locks / ("backend-%s.lock" % name)

    def _default_asset_platform(self, name):  # type: (str) -> str
        supported = {item.asset_key for item in iter_backend_platforms(name)}
        for key in self.platform_info.compatible_asset_keys:
            if key in supported:
                return key
        raise UnsupportedPlatformError("%s has no catalog platform for %s" % (name, self.platform_info.key))

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

    def _load_installed_manifest(self, manifest):  # type: (Path) -> InstalledBackend
        manifest = Path(manifest)
        value = read_json(manifest)
        required = (
            "name",
            "version",
            "platform",
            "asset_name",
            "sha256",
            "executable_sha256",
            "executable",
        )
        if any(not isinstance(value.get(key), str) or not value[key] for key in required):
            raise BackendNotInstalledError("invalid installed backend manifest: %s" % manifest)
        try:
            spec = get_backend(value["name"])
            normalized_version = spec.normalize_version(value["version"])
        except (UnsupportedBackendError, ValueError):
            raise BackendNotInstalledError("invalid installed backend identity: %s" % manifest)
        expected_manifest = self.paths.backends / spec.name / normalized_version / "manifest.json"
        if value["version"] != normalized_version or manifest.absolute() != expected_manifest.absolute():
            raise BackendNotInstalledError("installed backend manifest does not match its directory: %s" % manifest)
        try:
            manifest.resolve().relative_to(self.paths.backends.resolve())
        except ValueError:
            raise BackendNotInstalledError("installed backend manifest escapes the backend home: %s" % manifest)
        supported_platforms = {item.asset_key for item in iter_backend_platforms(spec.name)}
        if value["platform"] not in supported_platforms:
            raise BackendNotInstalledError("invalid platform in installed backend manifest: %s" % manifest)
        executable = Path(str(value["executable"]))
        if executable.is_absolute() or ".." in executable.parts:
            raise BackendNotInstalledError("unsafe executable path in installed backend manifest: %s" % manifest)
        try:
            (manifest.parent / executable).resolve().relative_to(manifest.parent.resolve())
        except ValueError:
            raise BackendNotInstalledError("installed backend executable escapes its version directory: %s" % manifest)
        for digest_key in ("sha256", "executable_sha256"):
            digest = str(value[digest_key]).lower()
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise BackendNotInstalledError("invalid %s in installed backend manifest: %s" % (digest_key, manifest))
        return InstalledBackend.from_manifest(manifest, value)

    def _verify_installed_executable(self, installed):  # type: (InstalledBackend) -> None
        if installed.platform not in self.platform_info.compatible_asset_keys:
            raise IntegrityError(
                "%s %s targets %s, not %s"
                % (installed.name, installed.version, installed.platform, self.platform_info.asset_key)
            )
        if not installed.executable.is_file():
            raise IntegrityError("%s %s executable is missing" % (installed.name, installed.version))
        actual = sha256_file(installed.executable)
        if actual != installed.executable_sha256:
            raise IntegrityError(
                "%s %s executable SHA-256 mismatch: expected %s, got %s"
                % (installed.name, installed.version, installed.executable_sha256, actual)
            )

    def _safe_relative_path(self, value, manifest, field):
        # type: (str, Path, str) -> Path
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise BackendNotInstalledError("unsafe %s path in active backend manifest: %s" % (field, manifest))
        path = self.paths.root / relative
        try:
            path.absolute().relative_to(self.paths.root.absolute())
        except ValueError:
            raise BackendNotInstalledError("unsafe %s path in active backend manifest: %s" % (field, manifest))
        return path
