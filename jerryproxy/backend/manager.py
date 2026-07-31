"""Backend download, immutable installation, activation, and rollback."""

import errno
import hashlib
import os
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..errors import (
    ArchiveError,
    BackendActiveError,
    BackendAlreadyInstalledError,
    BackendNotInstalledError,
    CleanupScopeError,
    DurabilityError,
    IntegrityError,
    RemovalCleanupError,
    UnsupportedPlatformError,
)
from ..home import JerryProxyPaths, is_path_alias
from ..lock import JerryProxyOperationLock
from ..utils.fs import ensure_private_directory, sha256_file
from . import removal as removal_module
from .activation import ActivationTransaction, recover_use_transactions
from .anchored import AnchoredDirectory
from .archive import ArchiveLimits, PinnedArchive
from .catalog import BackendCatalog
from .download import AssetDownloader
from .durable import flush_directory
from .installation import InstallTransaction, recover_install_transactions
from .model import BackendInventory, CleanupResult, RemovalResult
from .platform import detect_platform
from .registry import get_backend, iter_backend_platforms, iter_backends, version_sort_key
from .relay import build_download_sources
from .state import (
    load_active_state,
    load_installed_manifest,
    validate_staged_installed_manifest_value,
)


class BackendManager(object):
    """Manage external backend binaries below a JerryProxy home directory."""

    def __init__(
        self,
        paths,
        platform_info=None,
        catalog=None,
        downloader=None,
        probe_runner=None,
        archive_limits=None,
    ):
        # type: (JerryProxyPaths, Optional[PlatformInfo], BackendCatalog, AssetDownloader, Callable, Optional[ArchiveLimits]) -> None
        self.paths = paths
        self.platform_info = platform_info or detect_platform()
        self._catalog = catalog
        self.downloader = downloader or AssetDownloader()
        self.probe_runner = probe_runner or self._probe_installed
        default_archive_limits = ArchiveLimits()
        selected_archive_limits = archive_limits or default_archive_limits
        if not isinstance(selected_archive_limits, ArchiveLimits):
            raise TypeError("archive_limits must be an ArchiveLimits value")
        for name, ceiling in default_archive_limits.__dict__.items():
            value = getattr(selected_archive_limits, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError("%s must be a positive integer" % name)
            if value > ceiling:
                raise ValueError("archive limit %s cannot exceed the built-in safety budget" % name)
        self.archive_limits = selected_archive_limits

    @property
    def catalog(self):  # type: () -> BackendCatalog
        """Load the packaged catalog only when an operation requires it."""

        if self._catalog is None:
            self._catalog = BackendCatalog.load()
        return self._catalog

    @contextmanager
    def _read_operation(self):
        """Lock complete existing state without initializing an absent home."""

        if not self.paths._validate_existing_layout():
            yield False
            return
        try:
            with JerryProxyOperationLock(
                self.paths,
                initialize=False,
                platform_info=self.platform_info,
            ):
                yield True
        except FileNotFoundError as error:
            # A concurrent external layout change can invalidate the pre-lock snapshot.
            raise IntegrityError("JerryProxy home changed during read: %s" % self.paths.root) from error

    @classmethod
    def from_home(cls, home=None):  # type: (Optional[str]) -> "BackendManager"
        return cls(JerryProxyPaths.from_value(home))

    def supported(self):  # type: () -> Iterable[BackendSpec]
        return iter_backends()

    def compatible_versions(self, name):  # type: (str) -> tuple
        return self.catalog.compatible_versions(name, self.platform_info)

    def resolve_artifact(self, name, version=None):
        # type: (str, Optional[str]) -> CatalogArtifact
        return self.catalog.resolve(name, version, self.platform_info)

    def install(
        self,
        name,
        version=None,
        activate=True,
        relay=None,
        relay_url=None,
        relay_pattern=None,
    ):
        # type: (str, Optional[str], bool, Optional[str], Optional[str], Optional[str]) -> InstalledBackend
        spec = get_backend(name)
        asset = self.resolve_artifact(spec.name, version)
        sources = build_download_sources(
            asset.url,
            relay=relay,
            relay_url=relay_url,
            relay_pattern=relay_pattern,
        )
        normalized_version = asset.version
        with JerryProxyOperationLock(self.paths, platform_info=self.platform_info):
            download_directory = self.paths.downloads / spec.name / normalized_version
            self._reject_backend_alias(self.paths.downloads, spec.name, download_directory)
            ensure_private_directory(download_directory)
            archive = download_directory / asset.name
            if archive.exists() and sha256_file(archive) != asset.sha256:
                archive.unlink()
            if not archive.exists():
                self.downloader.download_sources(
                    sources,
                    archive,
                    asset.sha256,
                    expected_size=asset.size,
                )
            installed = self._install_from_archive_locked(
                spec.name,
                normalized_version,
                archive,
                expected_sha256=asset.sha256,
                expected_size=asset.size,
                asset_name=asset.name,
                source_url=asset.url,
                asset_platform=asset.platform,
                archive_executable=asset.executable,
            )
            if activate:
                self._switch_locked(spec.name, normalized_version)
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
        expected_size=None,
        asset_name=None,
        source_url=None,
        asset_platform=None,
        archive_executable=None,
        activate=False,
    ):
        # type: (str, str, Path, str, Optional[int], Optional[str], Optional[str], Optional[str], Optional[str], bool) -> InstalledBackend
        with JerryProxyOperationLock(self.paths, platform_info=self.platform_info):
            installed = self._install_from_archive_locked(
                name,
                version,
                archive,
                expected_sha256,
                expected_size=expected_size,
                asset_name=asset_name,
                source_url=source_url,
                asset_platform=asset_platform,
                archive_executable=archive_executable,
            )
            if activate:
                self._switch_locked(name, version)
            return installed

    def _install_from_archive_locked(
        self,
        name,
        version,
        archive,
        expected_sha256,
        expected_size=None,
        asset_name=None,
        source_url=None,
        asset_platform=None,
        archive_executable=None,
    ):
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        selected_platform = asset_platform or self._default_asset_platform(spec.name)
        archive = Path(archive)
        target = self.paths.backends / spec.name / normalized_version
        self._reject_backend_alias(self.paths.backends, spec.name, target)
        with PinnedArchive(archive, limits=self.archive_limits) as source:
            actual_sha256 = source.sha256
            if actual_sha256.lower() != expected_sha256.lower():
                raise IntegrityError(
                    "backend asset SHA-256 mismatch: expected %s, got %s"
                    % (expected_sha256.lower(), actual_sha256.lower())
                )
            if expected_size is not None and source.size != expected_size:
                raise IntegrityError("backend asset size mismatch: expected %d, got %d" % (expected_size, source.size))
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
                    source,
                    actual_sha256,
                    asset_name or archive.name,
                    source_url,
                    selected_platform,
                    archive_executable,
                    target,
                )
        return installed

    def _install_new_version(
        self,
        spec,
        version,
        source,
        sha256,
        asset_name,
        source_url,
        asset_platform,
        archive_executable,
        target,
    ):
        # type: (BackendSpec, str, PinnedArchive, str, str, Optional[str], str, Optional[str], Path) -> InstalledBackend
        artifact = {
            "sha256": sha256,
            "size": source.size,
            "asset_name": asset_name,
            "platform": asset_platform,
        }
        transaction = InstallTransaction.prepare(self.paths, spec.name, version, artifact)
        try:
            staging = transaction.begin_staging()
            executable_name = spec.executable_filename(self.platform_info)
            source_executable_name = archive_executable or executable_name
            with AnchoredDirectory(
                staging,
                expected_identity=transaction.value["tree_identity"],
            ) as staging_anchor:
                source.extract(
                    staging,
                    source_executable_name,
                    output_tree=staging_anchor,
                )
                executable_parts = staging_anchor.prepare_executable(
                    source_executable_name,
                    executable_name,
                )
                executable = staging.joinpath(*executable_parts)
                executable_size, executable_digest, executable_identity = staging_anchor.file_evidence(
                    executable_parts,
                    flush=True,
                )
                executable_value = "/".join(executable_parts)
                manifest_value = {
                    "name": spec.name,
                    "version": version,
                    "platform": asset_platform,
                    "asset_name": asset_name,
                    "sha256": sha256,
                    "executable_sha256": executable_digest,
                    "source_url": source_url,
                    "catalog_generated_at": self.catalog.generated_at,
                    "executable": executable_value,
                    "installed_at": datetime.now(timezone.utc).isoformat(),
                }
                manifest_parts = ("manifest.json",)
                manifest_temporary_parts = (".manifest.json.tmp-%s" % uuid.uuid4().hex,)
                manifest_payload, manifest_identity = staging_anchor.write_json(
                    manifest_parts,
                    manifest_value,
                    manifest_temporary_parts,
                )
                staged = validate_staged_installed_manifest_value(
                    self.paths,
                    staging / "manifest.json",
                    target / "manifest.json",
                    manifest_value,
                )
                if staged.platform not in self.platform_info.compatible_asset_keys:
                    raise IntegrityError(
                        "%s %s targets %s, not %s"
                        % (staged.name, staged.version, staged.platform, self.platform_info.asset_key)
                    )
                if staged.executable != executable or staged.executable_sha256 != executable_digest:
                    raise IntegrityError("staged backend executable evidence does not match its manifest")
                staging_anchor.assert_bound(transaction.value["tree_identity"])
                probe_size, probe_digest, probe_identity = staging_anchor.file_evidence(
                    executable_parts,
                    expected_identity=executable_identity,
                )
                if (
                    probe_identity != executable_identity
                    or probe_size != executable_size
                    or probe_digest != executable_digest
                ):
                    raise IntegrityError("staged backend executable changed before probe")
                self.probe_runner(staged)
                staging_anchor.assert_bound(transaction.value["tree_identity"])
                final_size, final_digest, final_identity = staging_anchor.file_evidence(
                    executable_parts,
                    flush=True,
                )
                if (
                    final_identity != executable_identity
                    or final_size != executable_size
                    or final_digest != executable_digest
                ):
                    raise IntegrityError("staged backend executable changed during validation")
                _manifest_size, manifest_digest, final_manifest_identity = staging_anchor.file_evidence(
                    manifest_parts,
                    flush=True,
                )
                if (
                    final_manifest_identity != manifest_identity
                    or manifest_digest != hashlib.sha256(manifest_payload).hexdigest()
                ):
                    raise IntegrityError("staged backend manifest changed during validation")
                publication = {
                    "manifest_sha256": manifest_digest,
                    "executable": executable_value,
                    "executable_sha256": executable_digest,
                    "executable_size": executable_size,
                }
                transaction.mark_validated(publication, staging_anchor=staging_anchor)
            transaction.commit()
        except (ArchiveError, DurabilityError, IntegrityError, OSError) as error:
            # Any ordinary failure after journal publication uses the restart recovery protocol immediately.
            try:
                recover_install_transactions(self.paths)
            except (DurabilityError, IntegrityError, OSError) as recovery_error:
                # Unprovable recovery retains its authoritative evidence and supersedes the operation failure.
                raise recovery_error from error
            raise
        return self._load_installed_manifest(target / "manifest.json")

    def list_installed(self, name=None):  # type: (Optional[str]) -> List[InstalledBackend]
        if name is not None:
            get_backend(name)
        with self._read_operation() as has_state:
            if not has_state:
                return []
            return self._list_installed_locked(name)

    def _list_installed_locked(self, name=None):
        manifests = []
        if name is not None:
            spec = get_backend(name)
            roots = [self.paths.backends / spec.name]
        else:
            roots = [self.paths.backends / spec.name for spec in iter_backends()]
        for root in roots:
            self._reject_backend_alias(self.paths.backends, root.name, root)
            if not root.exists():
                continue
            manifests.extend(sorted(root.glob("*/manifest.json")))
        installed = []
        for manifest in manifests:
            self._reject_backend_alias(self.paths.backends, manifest.parent.parent.name, manifest.parent)
            installed.append(self._load_installed_manifest(manifest))
        grouped = []
        for spec in iter_backends():
            versions = [item for item in installed if item.name == spec.name]
            grouped.extend(sorted(versions, key=lambda item: version_sort_key(item.version), reverse=True))
        return grouped

    def get_installed(self, name, version):  # type: (str, str) -> InstalledBackend
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        with self._read_operation() as has_state:
            if not has_state:
                raise BackendNotInstalledError("%s %s is not installed" % (spec.name, normalized_version))
            return self._get_installed_locked(spec.name, normalized_version)

    def _get_installed_locked(self, name, version):
        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        manifest = self.paths.backends / spec.name / normalized_version / "manifest.json"
        self._reject_backend_alias(self.paths.backends, spec.name, manifest.parent)
        if not manifest.is_file():
            raise BackendNotInstalledError("%s %s is not installed" % (spec.name, normalized_version))
        installed = self._load_installed_manifest(manifest)
        if installed.platform not in self.platform_info.compatible_asset_keys:
            raise BackendNotInstalledError(
                "%s %s was installed for %s, not %s"
                % (spec.name, normalized_version, installed.platform, self.platform_info.asset_key)
            )
        return installed

    def verify(self, name=None, version=None):
        # type: (Optional[str], Optional[str]) -> List[InstalledBackend]
        """Re-hash installed executables and return every verified version."""

        if version is not None and name is None:
            raise ValueError("a verification version requires a backend name")
        spec = get_backend(name) if name is not None else None
        normalized_version = spec.normalize_version(version) if version is not None else None
        with self._read_operation() as has_state:
            if not has_state:
                if normalized_version is not None:
                    raise BackendNotInstalledError("%s %s is not installed" % (spec.name, normalized_version))
                return []
            if version is None:
                installed = self._list_installed_locked(name=name)
            else:
                installed = [self._get_installed_locked(spec.name, normalized_version)]
            for item in installed:
                self._verify_installed_executable(item)
            return installed

    def which(self, name, version=None):
        # type: (str, Optional[str]) -> Union[ActiveBackend, InstalledBackend]
        """Return one integrity-verified executable selection without running it."""

        spec = get_backend(name)
        normalized_version = spec.normalize_version(version) if version is not None else None
        with self._read_operation() as has_state:
            if not has_state:
                if normalized_version is None:
                    raise BackendNotInstalledError("%s has no current version" % spec.name)
                raise BackendNotInstalledError("%s %s is not installed" % (spec.name, normalized_version))
            if version is None:
                current = self._current_locked(spec.name)
                if current is None:
                    raise BackendNotInstalledError("%s has no current version" % spec.name)
                installed = self._get_installed_locked(current.name, current.version)
                self._verify_installed_executable(installed)
                return current
            installed = self._get_installed_locked(spec.name, normalized_version)
            self._verify_installed_executable(installed)
            return installed

    def use(self, name, version):  # type: (str, str) -> ActiveBackend
        """Activate one exact already installed backend version."""

        with JerryProxyOperationLock(self.paths, platform_info=self.platform_info):
            return self._switch_locked(name, version)

    def _switch_locked(self, name, version):
        spec = get_backend(name)
        installed = self._get_installed_locked(spec.name, version)
        self._verify_installed_executable(installed)
        self.probe_runner(installed)
        current = self._current_locked(spec.name)
        if current is not None and current.version == installed.version:
            return current
        try:
            transaction = ActivationTransaction.prepare(
                self.paths,
                self.platform_info,
                spec.name,
                installed.version,
            )
            return transaction.execute()
        except (DurabilityError, IntegrityError, OSError) as error:
            # Activation failures use the persisted restart protocol while the lock is still held.
            try:
                recover_use_transactions(self.paths, self.platform_info)
            except (DurabilityError, IntegrityError, OSError) as recovery_error:
                # Unprovable recovery retains its journal and supersedes the operation failure.
                raise recovery_error from error
            raise

    def current(self, name):  # type: (str) -> Optional[ActiveBackend]
        spec = get_backend(name)
        with self._read_operation() as has_state:
            if not has_state:
                return None
            return self._current_locked(spec.name)

    def _current_locked(self, name):
        state = load_active_state(self.paths, name, self.platform_info)
        return None if state is None else state[0]

    def list_active(self):  # type: () -> List[ActiveBackend]
        with self._read_operation() as has_state:
            if not has_state:
                return []
            return self._list_active_locked()

    def _list_active_locked(self, name=None):
        active = []
        specs = (get_backend(name),) if name is not None else iter_backends()
        for spec in specs:
            item = self._current_locked(spec.name)
            if item is not None:
                active.append(item)
        return active

    def inventory(self, name=None):  # type: (Optional[str]) -> BackendInventory
        """Return a non-initializing, lock-consistent backend snapshot.

        Acquiring an existing home lock may recover a journaled interrupted
        uninstall before the snapshot is constructed.
        """

        if name is not None:
            get_backend(name)
        with self._read_operation() as has_state:
            if not has_state:
                return BackendInventory(installed=(), active=())
            return BackendInventory(
                installed=tuple(self._list_installed_locked(name)),
                active=tuple(self._list_active_locked(name)),
            )

    def uninstall(self, name, version, deactivate=False, cache=False):
        # type: (str, str, bool, bool) -> RemovalResult
        """Uninstall one version and optionally its matching release cache."""

        spec = get_backend(name)
        normalized_version = spec.normalize_version(version)
        with JerryProxyOperationLock(self.paths, platform_info=self.platform_info):
            cleanup_targets = self._download_cleanup_targets(spec.name, normalized_version) if cache else []
            installed = self._get_installed_locked(spec.name, normalized_version)
            active = self._current_locked(spec.name)
            if active is not None and active.version == installed.version:
                if not deactivate:
                    raise BackendActiveError(
                        "%s %s is current; use another version or pass --deactivate" % (spec.name, installed.version)
                    )
            cleanup = self._remove_transaction_locked(
                (installed,),
                active if active and active.version == installed.version else None,
                cleanup_targets,
                cache,
            )
        return RemovalResult(spec.name, (installed.version,), cleanup)

    def uninstall_all(self, name, cache=False):  # type: (str, bool) -> RemovalResult
        """Uninstall every version of one backend and deactivate it."""

        spec = get_backend(name)
        with JerryProxyOperationLock(self.paths, platform_info=self.platform_info):
            cleanup_targets = self._download_cleanup_targets(spec.name, None) if cache else []
            installed = self._list_installed_locked(spec.name)
            active = self._current_locked(spec.name)
            cleanup = self._remove_transaction_locked(installed, active, cleanup_targets, cache)
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

        with JerryProxyOperationLock(self.paths, platform_info=self.platform_info):
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
        with self._read_operation() as has_state:
            if not has_state:
                return {backend_name: () for backend_name in names}
            return self._list_cached_versions_locked(name)

    def _list_cached_versions_locked(self, name=None):
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

    def _remove_transaction_locked(self, installed, active, cleanup_targets, downloads):
        # type: (Iterable[InstalledBackend], Optional[ActiveBackend], Iterable[Path], bool) -> CleanupResult
        installed = tuple(installed)
        cleanup_targets = tuple(cleanup_targets)
        measured_cleanup_targets = []
        for target in cleanup_targets:
            self._validate_cleanup_chain(self.paths.downloads, target)
            if not os.path.lexists(str(target)):
                continue
            measured_cleanup_targets.append(
                (
                    target,
                    removal_module._secure_path_size(
                        self.paths.downloads,
                        target,
                        CleanupScopeError,
                    ),
                )
            )
        for item in installed:
            self._reject_backend_alias(self.paths.backends, item.name, item.manifest.parent)
            removal_module._validate_removal_tree(
                self.paths.backends,
                item.manifest.parent,
                IntegrityError,
            )

        existing_cleanup_targets = []
        cleanup_size = 0
        for target, measured_size in measured_cleanup_targets:
            self._validate_cleanup_chain(self.paths.downloads, target)
            if not os.path.lexists(str(target)):
                continue
            removal_module._validate_removal_tree(
                self.paths.downloads,
                target,
                CleanupScopeError,
            )
            existing_cleanup_targets.append(target)
            cleanup_size += measured_size

        transaction = self.paths.runtimes / (".remove-%s" % uuid.uuid4().hex)
        try:
            with AnchoredDirectory(self.paths.runtimes) as runtimes:
                transaction_identity = runtimes.create_directory((transaction.name,))
        except ArchiveError as error:
            raise IntegrityError("unable to create removal transaction directory") from error
        removal_module._validate_removal_tree(
            self.paths.runtimes,
            transaction,
            IntegrityError,
        )
        sources = []
        for index, target in enumerate(existing_cleanup_targets):
            sources.append((target, transaction / ("download-%d" % index), "download"))
        for index, item in enumerate(installed):
            sources.append((item.manifest.parent, transaction / ("installed-%d" % index), "installed"))
        if active is not None:
            sources.append((active.link, transaction / "active-link", "active-link"))
            sources.append(
                (
                    self.paths.active / ("%s.json" % active.name),
                    transaction / "active-manifest",
                    "active-manifest",
                )
            )

        if not sources:
            if not removal_module._secure_remove_empty_directory(
                self.paths.runtimes,
                transaction,
                IntegrityError,
                expected_identity=transaction_identity,
                private_names=True,
            ):
                raise IntegrityError("removal transaction disappeared before disposal: %s" % transaction)
            flush_directory(transaction.parent)
            return CleanupResult(
                ("downloads",) if downloads else (),
                0,
                0,
            )

        try:
            moves = [
                removal_module._removal_move(self.paths, source, destination, kind)
                for source, destination, kind in sources
            ]
            journal_value, journal_identity = removal_module._write_removal_journal(
                transaction,
                moves,
            )
            removal_record = removal_module._preflight_expected_removal_record(
                self.paths,
                transaction,
                journal_value,
                journal_identity,
                platform_info=self.platform_info,
            )
            backend_root = installed[0].manifest.parent.parent if installed else None
            for (source, destination, kind), move in zip(sources, moves):
                removal_module._require_removal_authority(removal_record)
                removal_module._validate_chain(
                    self.paths.runtimes,
                    destination.parent,
                    IntegrityError,
                )
                if kind == "download":
                    self._validate_cleanup_chain(self.paths.downloads, source)
                    removal_module._validate_removal_tree(
                        self.paths.downloads,
                        source,
                        CleanupScopeError,
                    )
                    error_type = CleanupScopeError
                elif kind == "installed":
                    self._reject_backend_alias(self.paths.backends, source.parent.name, source)
                    removal_module._validate_removal_tree(
                        self.paths.backends,
                        source,
                        IntegrityError,
                    )
                    error_type = IntegrityError
                elif kind == "active-link":
                    self._validate_cleanup_chain(self.paths.bin, source.parent)
                    error_type = IntegrityError
                else:
                    self._validate_cleanup_chain(self.paths.active, source)
                    removal_module._validate_removal_tree(
                        self.paths.active,
                        source,
                        IntegrityError,
                    )
                    error_type = IntegrityError
                removal_module._move_no_replace(
                    self.paths,
                    source,
                    destination,
                    move["identity"],
                    error_type=error_type,
                    description="removal staging",
                )
                removal_module._require_removal_authority(removal_record)
                if kind == "download":
                    self._validate_cleanup_chain(self.paths.downloads, source)
                elif kind == "installed":
                    self._reject_backend_alias(self.paths.backends, source.parent.name, source)
                else:
                    self._validate_cleanup_chain(getattr(self.paths, move["source"].split("/", 1)[0]), source.parent)
                removal_module._validate_staged_move(
                    self.paths,
                    transaction,
                    move,
                    error_type,
                )
            if backend_root is not None:
                removal_module._require_removal_authority(removal_record)
                self._remove_empty_directory(backend_root)
            removal_module._require_removal_authority(removal_record)
            journal_value, journal_identity = removal_module._write_removal_journal(
                transaction,
                moves,
                phase="committed",
                expected_transaction_identity=removal_record.transaction_identity,
                expected_journal_identity=removal_record.journal_identity,
            )
            removal_record = removal_module._preflight_expected_removal_record(
                self.paths,
                transaction,
                journal_value,
                journal_identity,
                platform_info=self.platform_info,
            )
        except (DurabilityError, OSError, CleanupScopeError, IntegrityError) as error:
            # Disk-visible authority, rather than in-memory progress, chooses recovery direction.
            if isinstance(error, removal_module._RemovalAuthorityError):
                raise
            try:
                removal_module._recover_removal_transactions(
                    self.paths,
                    platform_info=self.platform_info,
                )
            except (DurabilityError, OSError, CleanupScopeError, IntegrityError, RemovalCleanupError) as recovery_error:
                # Unprovable recovery retains its journal and supersedes the operation failure.
                raise recovery_error from error
            raise

        try:
            removal_module._dispose_removal_transaction(
                self.paths,
                transaction,
                platform_info=self.platform_info,
                record=removal_record,
            )
        except OSError as error:
            # Public state is already atomically absent; retain private evidence for explicit cleanup.
            raise RemovalCleanupError(
                "backend removal committed but quarantine cleanup failed at %s; "
                "run 'jerryproxy backend clean --runtimes -y'" % transaction
            ) from error
        return CleanupResult(
            ("downloads",) if downloads else (),
            len(existing_cleanup_targets),
            cleanup_size,
        )

    def _download_cleanup_targets(self, name, version):
        # type: (Optional[str], Optional[str]) -> List[Path]
        root = self.paths.downloads
        if name is None:
            return self._area_cleanup_targets("downloads")
        backend_root = root / name
        self._validate_cleanup_chain(root, backend_root)
        if version is None:
            target = backend_root
            parent = root
        else:
            target = backend_root / version
            parent = backend_root
        self._validate_cleanup_chain(root, target)
        targets = [target] if os.path.lexists(str(target)) else []
        if not parent.is_dir():
            return targets
        for candidate in parent.iterdir():
            self._validate_cleanup_chain(root, candidate)
            if removal_module._is_cleanup_tombstone_for(candidate.name, target.name):
                targets.append(candidate)
        return targets

    def _area_cleanup_targets(self, area):  # type: (str) -> List[Path]
        root = getattr(self.paths, area)
        self._validate_cleanup_chain(root, root)
        return list(root.iterdir())

    def _validate_cleanup_chain(self, root, target):  # type: (Path, Path) -> None
        current = target
        while True:
            if is_path_alias(current):
                raise CleanupScopeError("refusing cleanup through managed symlink or Windows path alias: %s" % current)
            if current == root:
                return
            if current == self.paths.root or current.parent == current:
                raise CleanupScopeError("cleanup target escapes managed area: %s" % target)
            current = current.parent

    def _remove_cleanup_targets(self, areas, targets):
        # type: (Iterable[str], Iterable[Path]) -> CleanupResult
        selected_areas = tuple(areas)
        removed = 0
        reclaimed = 0
        for target in targets:
            for area in selected_areas:
                root = getattr(self.paths, area)
                try:
                    target.relative_to(root)
                except ValueError:
                    # Path.relative_to rejects targets outside this candidate cleanup area.
                    continue
                self._validate_cleanup_chain(root, target)
                break
            else:
                raise CleanupScopeError("cleanup target escapes managed areas: %s" % target)
            if not os.path.lexists(str(target)):
                continue
            reclaimed += removal_module._secure_path_size(root, target, CleanupScopeError)
            self._validate_cleanup_chain(root, target)
            removal_module._secure_remove_tree(
                root,
                target,
                CleanupScopeError,
                private_names=removal_module._is_cleanup_tombstone_name(target.name),
            )
            flush_directory(target.parent)
            removed += 1
        return CleanupResult(selected_areas, removed, reclaimed)

    @staticmethod
    def _remove_empty_directory(path):  # type: (Path) -> bool
        try:
            path.rmdir()
            flush_directory(path.parent)
            return True
        except FileNotFoundError:
            # Another cleanup path may already have removed this empty parent.
            return False
        except OSError as error:
            # A non-empty parent is intentionally preserved; other filesystem errors remain fatal.
            if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise
            return False

    def _default_asset_platform(self, name):  # type: (str) -> str
        supported = {item.asset_key for item in iter_backend_platforms(name)}
        for key in self.platform_info.compatible_asset_keys:
            if key in supported:
                return key
        raise UnsupportedPlatformError("%s has no catalog platform for %s" % (name, self.platform_info.key))

    @staticmethod
    def _reject_backend_alias(area, name, target):  # type: (Path, str, Path) -> None
        backend_root = area / name
        if is_path_alias(backend_root) or is_path_alias(target):
            raise IntegrityError("managed backend path must not be a symlink or Windows path alias: %s" % target)

    def _load_installed_manifest(self, manifest):  # type: (Path) -> InstalledBackend
        return load_installed_manifest(self.paths, manifest)

    def _verify_installed_executable(self, installed):  # type: (InstalledBackend) -> None
        if installed.platform not in self.platform_info.compatible_asset_keys:
            raise IntegrityError(
                "%s %s targets %s, not %s"
                % (installed.name, installed.version, installed.platform, self.platform_info.asset_key)
            )
        try:
            executable_parts = installed.executable.relative_to(self.paths.backends).parts
            with AnchoredDirectory(self.paths.backends) as backends:
                unused_size, actual, unused_identity = backends.file_evidence(executable_parts)
        except (ArchiveError, OSError, ValueError) as error:
            # Verification must not follow a replaced executable or managed ancestor.
            raise IntegrityError(
                "%s %s executable is missing or unsafe" % (installed.name, installed.version)
            ) from error
        if actual != installed.executable_sha256:
            raise IntegrityError(
                "%s %s executable SHA-256 mismatch: expected %s, got %s"
                % (installed.name, installed.version, installed.executable_sha256, actual)
            )
