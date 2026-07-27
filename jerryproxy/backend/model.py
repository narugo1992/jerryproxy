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


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    sha256: str
    size: int


@dataclass(frozen=True)
class InstalledBackend:
    name: str
    version: str
    executable: Path
    manifest: Path
    asset_name: str
    sha256: str

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
        )


@dataclass(frozen=True)
class ActiveBackend:
    name: str
    version: str
    executable: Path
    link: Path
    link_mode: str
