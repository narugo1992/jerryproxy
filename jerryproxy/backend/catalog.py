"""Strict reader and selector for the packaged offline backend catalog."""

from functools import lru_cache
from types import MappingProxyType
from urllib.parse import quote, urlparse

from jerryproxy.data import backend_catalog_resource_names, read_backend_catalog_json

from ..errors import BackendCatalogError, UnsupportedPlatformError
from .model import CatalogArtifact, CatalogVersion, PlatformInfo
from .platform import detect_platform
from .registry import get_backend, is_stable_version, iter_backend_platforms, iter_backends, version_sort_key

MAXIMUM_ASSET_BYTES = 256 * 1024 * 1024
_HEX_DIGITS = frozenset("0123456789abcdef")


def _catalog_error(message):  # type: (str) -> BackendCatalogError
    return BackendCatalogError("invalid packaged backend catalog: %s" % message)


def _required(value, key, expected_type, context):
    if key not in value or not isinstance(value[key], expected_type):
        raise _catalog_error("%s.%s must be %s" % (context, key, expected_type.__name__))
    return value[key]


def _validate_sha256(value, context):
    if value is None:
        return None
    if not isinstance(value, str):
        raise _catalog_error("%s.sha256 must be a string or null" % context)
    normalized = value.lower()
    if len(normalized) != 64 or any(character not in _HEX_DIGITS for character in normalized):
        raise _catalog_error("%s.sha256 is not a SHA-256 digest" % context)
    return normalized


def _platform_pairs(name):
    return {(item.asset_key, item.os_name, item.architecture, item.libc) for item in iter_backend_platforms(name)}


class BackendCatalog(object):
    """Validated immutable view of upstream backend release metadata."""

    def __init__(self, generated_at_by_backend, versions):
        self.generated_at_by_backend = MappingProxyType(dict(generated_at_by_backend))
        self.generated_at = max(generated_at_by_backend.values())
        self._versions = MappingProxyType(dict(versions))

    @classmethod
    def load(cls):  # type: () -> "BackendCatalog"
        return _load_packaged_catalog()

    @classmethod
    def from_values(cls, values):  # type: (dict) -> "BackendCatalog"
        expected_names = [spec.name for spec in iter_backends()]
        if not isinstance(values, dict) or sorted(values) != expected_names:
            raise _catalog_error("backend set must be %s" % ", ".join(expected_names))
        generated_at = {}
        parsed = {}
        for name in expected_names:
            value = values[name]
            if not isinstance(value, dict):
                raise _catalog_error("%s catalog must be an object" % name)
            if value.get("backend") != name:
                raise _catalog_error("%s catalog has the wrong backend id" % name)
            generated_at[name] = _required(value, "generated_at", str, "%s catalog" % name)
            parsed[name] = cls._parse_backend(name, value)
        return cls(generated_at_by_backend=generated_at, versions=parsed)

    @staticmethod
    def _parse_backend(name, value):
        spec = get_backend(name)
        context = "%s catalog" % name
        if _required(value, "repository", str, context) != spec.repository:
            raise _catalog_error("%s.repository does not match the registry" % context)
        raw_versions = _required(value, "versions", list, context)
        versions = []
        seen = set()
        supported = _platform_pairs(name)
        supported_keys = {item[0] for item in supported}
        supported_details = {item[0]: item[1:] for item in supported}
        for index, raw_version in enumerate(raw_versions):
            item_context = "%s.versions[%d]" % (context, index)
            version = BackendCatalog._parse_version(spec, raw_version, item_context, supported_keys, supported_details)
            if version.version in seen:
                raise _catalog_error("duplicate %s version %s" % (name, version.version))
            seen.add(version.version)
            versions.append(version)
        ordered = sorted(versions, key=lambda item: version_sort_key(item.version), reverse=True)
        if [item.version for item in versions] != [item.version for item in ordered]:
            raise _catalog_error("%s versions are not sorted newest to oldest" % name)
        return tuple(versions)

    @staticmethod
    def _parse_version(spec, value, context, supported_keys, supported_details):
        if not isinstance(value, dict):
            raise _catalog_error("%s must be an object" % context)
        version = _required(value, "version", str, context)
        try:
            normalized = spec.normalize_version(version)
            version_sort_key(normalized)
        except ValueError as error:
            # Registry normalization rejects malformed catalog release versions.
            raise _catalog_error("%s.version is invalid: %s" % (context, error))
        if version != normalized:
            raise _catalog_error("%s.version must be normalized" % context)
        if not is_stable_version(version):
            raise _catalog_error("%s.version must be a stable release" % context)
        tag = _required(value, "tag", str, context)
        if tag != spec.tag_for(version):
            raise _catalog_error("%s.tag does not match its version" % context)
        release_id = _required(value, "release_id", int, context)
        if isinstance(release_id, bool) or release_id <= 0:
            raise _catalog_error("%s.release_id must be a positive integer" % context)
        release_url = _required(value, "release_url", str, context)
        parsed_release_url = urlparse(release_url)
        expected_release_path = "/%s/releases/tag/%s" % (spec.repository, quote(tag, safe=""))
        if (
            parsed_release_url.scheme != "https"
            or parsed_release_url.netloc != "github.com"
            or parsed_release_url.path != expected_release_path
        ):
            raise _catalog_error("%s.release_url is not the exact official GitHub release URL" % context)
        published_at = _required(value, "published_at", str, context)
        raw_artifacts = _required(value, "artifacts", dict, context)
        unexpected = sorted(set(raw_artifacts) - supported_keys)
        if unexpected:
            raise _catalog_error("%s contains unsupported platforms: %s" % (context, ", ".join(unexpected)))
        artifacts = {}
        for platform_key in sorted(raw_artifacts):
            os_name, architecture, libc = supported_details[platform_key]
            artifacts[platform_key] = BackendCatalog._parse_artifact(
                spec,
                version,
                tag,
                platform_key,
                os_name,
                architecture,
                libc,
                raw_artifacts[platform_key],
                "%s.artifacts.%s" % (context, platform_key),
            )
        return CatalogVersion(
            backend=spec.name,
            version=version,
            tag=tag,
            release_id=release_id,
            release_url=release_url,
            published_at=published_at,
            artifacts=MappingProxyType(artifacts),
        )

    @staticmethod
    def _parse_artifact(spec, version, tag, platform_key, os_name, architecture, libc, value, context):
        if not isinstance(value, dict):
            raise _catalog_error("%s must be an object" % context)
        name = _required(value, "name", str, context)
        if not name or "/" in name or "\\" in name:
            raise _catalog_error("%s.name is not a safe release asset name" % context)
        platform_info = PlatformInfo(os_name=os_name, architecture=architecture, libc=libc)
        if name != spec.expected_asset_name(platform_info, version):
            raise _catalog_error("%s.name does not match the registered platform asset" % context)
        asset_id = _required(value, "asset_id", int, context)
        if isinstance(asset_id, bool) or asset_id <= 0:
            raise _catalog_error("%s.asset_id must be a positive integer" % context)
        url = _required(value, "url", str, context)
        parsed_url = urlparse(url)
        expected_path = "/%s/releases/download/%s/%s" % (
            spec.repository,
            quote(tag, safe=""),
            quote(name, safe=""),
        )
        if parsed_url.scheme != "https" or parsed_url.netloc != "github.com" or parsed_url.path != expected_path:
            raise _catalog_error("%s.url is not the exact official GitHub release URL" % context)
        size = _required(value, "size", int, context)
        if isinstance(size, bool) or size <= 0 or size > MAXIMUM_ASSET_BYTES:
            raise _catalog_error("%s.size is outside the safety limit" % context)
        sha256 = _validate_sha256(value.get("sha256"), context)
        updated_at = _required(value, "updated_at", str, context)
        verification = _required(value, "verification", str, context)
        unverified_sources = ("missing-upstream-sha256", "conflicting-upstream-sha256")
        verified_sources = (
            "github-release-digest",
            "upstream-dgst",
            "upstream-release-manifest",
            "cross-checked-upstream-sha256",
        )
        if sha256 is None and verification not in unverified_sources:
            raise _catalog_error("%s has no digest but is not marked unverified" % context)
        if sha256 is not None and verification not in verified_sources:
            raise _catalog_error("%s digest has an unsupported verification source" % context)
        archive_format = _required(value, "archive_format", str, context)
        expected_archive_format = "tar.gz" if name.lower().endswith(".tar.gz") else name.rsplit(".", 1)[-1].lower()
        if archive_format != expected_archive_format or archive_format not in ("gz", "tar.gz", "zip"):
            raise _catalog_error("%s.archive_format does not match its asset" % context)
        executable = _required(value, "executable", str, context)
        if not executable or "/" in executable or "\\" in executable or executable in (".", ".."):
            raise _catalog_error("%s.executable is not a safe member name" % context)
        return CatalogArtifact(
            backend=spec.name,
            version=version,
            platform=platform_key,
            asset_id=asset_id,
            name=name,
            url=url,
            sha256=sha256,
            size=size,
            updated_at=updated_at,
            verification=verification,
            archive_format=archive_format,
            executable=executable,
        )

    @property
    def backend_names(self):  # type: () -> tuple
        return tuple(sorted(self._versions))

    def versions(self, name):  # type: (str) -> tuple
        spec = get_backend(name)
        return self._versions[spec.name]

    def compatible_versions(self, name, platform_info=None):
        # type: (str, PlatformInfo) -> tuple
        platform_info = platform_info or detect_platform()
        compatible = []
        for version in self.versions(name):
            artifact = version.artifact_for(platform_info)
            if artifact is not None and artifact.verified:
                compatible.append(version)
        return tuple(compatible)

    def resolve(self, name, version=None, platform_info=None):
        # type: (str, Optional[str], PlatformInfo) -> CatalogArtifact
        spec = get_backend(name)
        platform_info = platform_info or detect_platform()
        if version is None:
            compatible = self.compatible_versions(spec.name, platform_info)
            if not compatible:
                raise UnsupportedPlatformError(
                    "%s has no verified catalog asset for %s" % (spec.name, platform_info.key)
                )
            selected = compatible[0]
        else:
            normalized = spec.normalize_version(version)
            selected = next((item for item in self.versions(spec.name) if item.version == normalized), None)
            if selected is None:
                raise BackendCatalogError("%s %s is not recorded in the packaged catalog" % (spec.name, normalized))
        artifact = selected.artifact_for(platform_info)
        if artifact is None:
            raise UnsupportedPlatformError(
                "%s %s has no catalog asset for %s" % (spec.name, selected.version, platform_info.key)
            )
        if not artifact.verified:
            if artifact.verification == "conflicting-upstream-sha256":
                raise BackendCatalogError(
                    "%s %s asset for %s has conflicting upstream SHA-256 evidence"
                    % (spec.name, selected.version, platform_info.key)
                )
            raise BackendCatalogError(
                "%s %s asset for %s has no upstream SHA-256 fingerprint"
                % (spec.name, selected.version, platform_info.key)
            )
        return artifact

    def summary(self, platform_info=None):
        # type: (PlatformInfo) -> dict
        platform_info = platform_info or detect_platform()
        result = {}
        for name in self.backend_names:
            versions = self.versions(name)
            compatible = self.compatible_versions(name, platform_info)
            result[name] = {
                "releases": len(versions),
                "compatible": len(compatible),
                "latest": compatible[0].version if compatible else None,
            }
        return result


@lru_cache(maxsize=1)
def _load_packaged_catalog():  # type: () -> BackendCatalog
    values = {}
    for name in backend_catalog_resource_names():
        try:
            values[name] = read_backend_catalog_json(name)
        except (FileNotFoundError, ValueError) as error:
            raise BackendCatalogError(str(error))
    return BackendCatalog.from_values(values)
