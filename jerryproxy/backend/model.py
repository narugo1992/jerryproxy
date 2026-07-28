"""Backend manager value objects."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class PlatformInfo:
    os_name: str
    architecture: str
    libc: Optional[str] = None

    @property
    def key(self):  # type: () -> str
        parts = [self.os_name, self.architecture]
        if self.libc:
            parts.append(self.libc)
        return "-".join(parts)

    @property
    def asset_key(self):  # type: () -> str
        """Return the most specific catalog key for this platform."""
        return self.key

    @property
    def portable_asset_key(self):  # type: () -> str
        """Return the OS/architecture key for libc-independent assets."""
        return "%s-%s" % (self.os_name, self.architecture)

    @property
    def compatible_asset_keys(self):  # type: () -> tuple
        """Return exact then portable catalog keys for deterministic fallback."""
        if self.asset_key == self.portable_asset_key:
            return (self.asset_key,)
        return self.asset_key, self.portable_asset_key


@dataclass(frozen=True)
class CatalogArtifact:
    """One exact upstream asset recorded in the packaged catalog."""

    backend: str
    version: str
    platform: str
    asset_id: int
    name: str
    url: str
    sha256: Optional[str]
    size: int
    updated_at: str
    verification: str
    archive_format: str
    executable: str

    @property
    def verified(self):  # type: () -> bool
        return self.sha256 is not None


@dataclass(frozen=True)
class CatalogVersion:
    """One upstream release and its selected cross-platform assets."""

    backend: str
    version: str
    tag: str
    release_id: int
    release_url: str
    published_at: str
    artifacts: dict

    def artifact_for(self, platform_info):  # type: (PlatformInfo) -> Optional[CatalogArtifact]
        for key in platform_info.compatible_asset_keys:
            artifact = self.artifacts.get(key)
            if artifact is not None:
                return artifact
        return None


@dataclass(frozen=True)
class InstalledBackend:
    name: str
    version: str
    executable: Path
    manifest: Path
    asset_name: str
    sha256: str
    platform: str
    executable_sha256: str

    @classmethod
    def from_manifest(cls, manifest, value):  # type: (Path, Dict[str, Any]) -> "InstalledBackend"
        root = manifest.parent
        return cls(
            name=str(value["name"]),
            version=str(value["version"]),
            executable=root / str(value["executable"]),
            manifest=manifest,
            asset_name=str(value["asset_name"]),
            sha256=str(value["sha256"]),
            platform=str(value["platform"]),
            executable_sha256=str(value["executable_sha256"]),
        )


@dataclass(frozen=True)
class ActiveBackend:
    name: str
    version: str
    executable: Path
    link: Path
    link_mode: str


@dataclass(frozen=True)
class CleanupResult:
    """Summary of targets removed from managed disposable storage."""

    areas: tuple
    targets_removed: int
    bytes_reclaimed: int


@dataclass(frozen=True)
class RemovalResult:
    """Summary of installed versions and cached downloads removed together."""

    name: str
    versions: tuple
    cleanup: CleanupResult
