"""Build the packaged backend catalog from official GitHub release metadata."""

import argparse
import json
import os
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from jerryproxy.backend.catalog import BackendCatalog
from jerryproxy.backend.registry import is_stable_version, iter_backend_platforms, iter_backends, version_sort_key
from jerryproxy.data import read_backend_catalog_json

DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "jerryproxy" / "data"
GITHUB_API_ROOT = "https://api.github.com"
MAXIMUM_PAGE_BYTES = 64 * 1024 * 1024
MAXIMUM_RELEASES_PER_BACKEND = 2000
PAGE_SIZE = 100
RETRYABLE_HTTP_CODES = frozenset((502, 503, 504))
_MANIFEST_DIGEST = re.compile(r"^SHA256 \(([^)]+)\) = ([0-9a-fA-F]{64})$", re.MULTILINE)
_DGST_DIGEST = re.compile(r"^(?:SHA256|SHA2-256)=\s*([0-9a-fA-F]{64})\s*$", re.MULTILINE)


class CatalogMaintenanceError(RuntimeError):
    """Raised when repository catalog maintenance cannot complete safely."""


class GitHubReleaseSource(object):
    """Bounded paginated reader for public GitHub releases."""

    def __init__(self, token=None, timeout=30.0, opener=None, retries=3):
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.timeout = timeout
        self.opener = opener or urlopen
        self.retries = retries

    def releases(self, repository):  # type: (str) -> list
        owner_and_name = repository.split("/")
        if len(owner_and_name) != 2 or not all(owner_and_name):
            raise ValueError("GitHub repository must be OWNER/REPO: %r" % repository)
        releases = []
        page = 1
        while True:
            url = "%s/repos/%s/releases?per_page=%d&page=%d" % (
                GITHUB_API_ROOT,
                "/".join(quote(part, safe="") for part in owner_and_name),
                PAGE_SIZE,
                page,
            )
            payload = self._request(url, repository)
            try:
                value = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise CatalogMaintenanceError("invalid GitHub releases metadata for %s: %s" % (repository, error))
            if not isinstance(value, list):
                raise CatalogMaintenanceError("GitHub releases metadata for %s is not a list" % repository)
            releases.extend(value)
            if len(releases) > MAXIMUM_RELEASES_PER_BACKEND:
                raise CatalogMaintenanceError("GitHub releases metadata for %s exceeds the entry limit" % repository)
            if len(value) < PAGE_SIZE:
                return releases
            page += 1

    def _request(self, url, repository):
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "JerryProxy-catalog-updater",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer %s" % self.token
        for attempt in range(self.retries + 1):
            request = Request(url, headers=headers)
            try:
                response = self.opener(request, timeout=self.timeout)
                with response:
                    payload = response.read(MAXIMUM_PAGE_BYTES + 1)
            except HTTPError as error:
                # Transient GitHub gateway errors are retried; other API errors fail closed.
                if error.code in RETRYABLE_HTTP_CODES and attempt < self.retries:
                    time.sleep(2**attempt)
                    continue
                raise CatalogMaintenanceError(
                    "GitHub releases lookup failed for %s: HTTP %s" % (repository, error.code)
                )
            except URLError as error:
                # DNS, TLS, proxy, and connection failures may be transient in the maintenance lane.
                if attempt < self.retries:
                    time.sleep(2**attempt)
                    continue
                raise CatalogMaintenanceError("GitHub releases lookup failed for %s: %s" % (repository, error.reason))
            if len(payload) > MAXIMUM_PAGE_BYTES:
                raise CatalogMaintenanceError("GitHub releases page for %s exceeds the safety limit" % repository)
            return payload
        raise CatalogMaintenanceError("GitHub releases lookup exhausted retries for %s" % repository)

    def asset_text(self, url, repository):  # type: (str, str) -> str
        payload = self._request(url, repository)
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CatalogMaintenanceError("invalid UTF-8 checksum metadata for %s: %s" % (repository, error))


def _release_digest(raw_asset):
    digest = raw_asset.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        return None
    sha256 = digest.split(":", 1)[1].lower()
    if len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256):
        return None
    return sha256


def _asset_record(raw_asset):
    asset_id = raw_asset.get("id")
    name = raw_asset.get("name")
    url = raw_asset.get("browser_download_url")
    size = raw_asset.get("size")
    updated_at = raw_asset.get("updated_at")
    if (
        not isinstance(asset_id, int)
        or isinstance(asset_id, bool)
        or asset_id <= 0
        or not isinstance(name, str)
        or not isinstance(url, str)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(updated_at, str)
    ):
        return None
    verification = raw_asset.get("_catalog_verification")
    if verification is None:
        sha256 = _release_digest(raw_asset)
        verification = "github-release-digest" if sha256 is not None else "missing-upstream-sha256"
    else:
        sha256 = raw_asset.get("_catalog_sha256")
    return {
        "asset_id": asset_id,
        "name": name,
        "url": url,
        "size": size,
        "updated_at": updated_at,
        "sha256": sha256,
        "verification": verification,
    }


def _archive_format(name):  # type: (str) -> str
    if name.lower().endswith(".tar.gz"):
        return "tar.gz"
    return name.rsplit(".", 1)[-1].lower()


def _executable_name(spec, platform_info, asset_name, version):
    suffix = ".exe" if platform_info.os_name == "windows" else ""
    if spec.name == "mihomo" and platform_info.os_name == "windows":
        marker = "-v%s" % version
        stem = asset_name[: -len(".zip")]
        marker_index = stem.find(marker)
        if marker_index > 0:
            stem = stem[:marker_index]
        return "%s.exe" % stem
    return "%s%s" % (spec.executable, suffix)


def _version_record(spec, raw_release):
    if (
        not isinstance(raw_release, dict)
        or raw_release.get("draft") is not False
        or raw_release.get("prerelease") is not False
    ):
        return None
    tag = raw_release.get("tag_name")
    release_id = raw_release.get("id")
    release_url = raw_release.get("html_url")
    published_at = raw_release.get("published_at")
    raw_assets = raw_release.get("assets")
    if (
        not isinstance(tag, str)
        or not isinstance(release_id, int)
        or isinstance(release_id, bool)
        or release_id <= 0
        or not isinstance(release_url, str)
        or not isinstance(published_at, str)
    ):
        return None
    if not isinstance(raw_assets, list):
        return None
    try:
        version = spec.normalize_version(tag)
        version_sort_key(version)
    except ValueError:
        return None
    if not is_stable_version(version):
        return None
    if tag != spec.tag_for(version):
        return None

    assets_by_name = {}
    for raw_asset in raw_assets:
        if not isinstance(raw_asset, dict):
            continue
        record = _asset_record(raw_asset)
        if record is not None:
            assets_by_name.setdefault(record["name"], record)

    artifacts = {}
    for platform_info in iter_backend_platforms(spec.name):
        expected_name = spec.expected_asset_name(platform_info, version)
        asset = assets_by_name.get(expected_name)
        if asset is not None:
            artifact = dict(asset)
            artifact["archive_format"] = _archive_format(asset["name"])
            artifact["executable"] = _executable_name(spec, platform_info, asset["name"], version)
            artifacts[platform_info.asset_key] = artifact
    return {
        "version": version,
        "tag": tag,
        "release_id": release_id,
        "release_url": release_url,
        "published_at": published_at,
        "artifacts": artifacts,
    }


def _parse_manifest(text):  # type: (str) -> dict
    return {name: digest.lower() for name, digest in _MANIFEST_DIGEST.findall(text)}


def _parse_dgst(text):  # type: (str) -> str
    match = _DGST_DIGEST.search(text)
    if match is None:
        raise CatalogMaintenanceError("upstream .dgst asset has no SHA2-256 value")
    return match.group(1).lower()


def _set_digest_evidence(raw_asset, evidence):
    # type: (dict, dict) -> None
    values = set(evidence.values())
    if len(values) > 1:
        raw_asset["_catalog_sha256"] = None
        raw_asset["_catalog_verification"] = "conflicting-upstream-sha256"
        return
    if not values:
        return
    raw_asset["_catalog_sha256"] = next(iter(values))
    if len(evidence) > 1:
        verification = "cross-checked-upstream-sha256"
    elif "github" in evidence:
        verification = "github-release-digest"
    elif "dgst" in evidence:
        verification = "upstream-dgst"
    else:
        verification = "upstream-release-manifest"
    raw_asset["_catalog_verification"] = verification


def _release_assets(raw_release):
    raw_assets = raw_release.get("assets")
    if not isinstance(raw_assets, list):
        return {}
    return {
        asset.get("name"): asset
        for asset in raw_assets
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    }


def _selected_assets(spec, raw_release):
    if raw_release.get("draft") is not False or raw_release.get("prerelease") is not False:
        return []
    tag = raw_release.get("tag_name")
    if not isinstance(tag, str):
        return []
    try:
        version = spec.normalize_version(tag)
    except ValueError:
        return []
    if not is_stable_version(version):
        return []
    assets = _release_assets(raw_release)
    selected = []
    for platform_info in iter_backend_platforms(spec.name):
        asset = assets.get(spec.expected_asset_name(platform_info, version))
        if asset is not None:
            selected.append(asset)
    return selected


def _reuse_recorded_digest_evidence(spec, releases, previous):
    if previous is None:
        return
    recorded = {}
    for version in previous[spec.name]["versions"]:
        for artifact in version["artifacts"].values():
            recorded[artifact["asset_id"]] = artifact
    for raw_release in releases:
        for raw_asset in _selected_assets(spec, raw_release):
            if _release_digest(raw_asset) is not None:
                continue
            old = recorded.get(raw_asset.get("id"))
            if old is None:
                continue
            identity_matches = (
                old["name"] == raw_asset.get("name")
                and old["url"] == raw_asset.get("browser_download_url")
                and old["size"] == raw_asset.get("size")
                and old["updated_at"] == raw_asset.get("updated_at")
            )
            if identity_matches and old["sha256"] is not None:
                raw_asset["_catalog_sha256"] = old["sha256"]
                raw_asset["_catalog_verification"] = old["verification"]


def _needs_checksum_fallback(raw_asset):
    return _release_digest(raw_asset) is None and "_catalog_verification" not in raw_asset


def _enrich_v2ray_digests(source, spec, releases):
    selected = []
    for raw_release in releases:
        selected_assets = [asset for asset in _selected_assets(spec, raw_release) if _needs_checksum_fallback(asset)]
        if not selected_assets:
            continue
        selected.append((raw_release, selected_assets))

    def fetch(item):
        raw_release, selected_assets = item
        assets = _release_assets(raw_release)
        manifests = {}
        for manifest_name in ("Release", "Release.unsigned"):
            manifest_asset = assets.get(manifest_name)
            if manifest_asset is None:
                continue
            url = manifest_asset.get("browser_download_url")
            if isinstance(url, str):
                manifests[manifest_name] = _parse_manifest(source.asset_text(url, spec.repository))
        return selected_assets, manifests

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(fetch, item) for item in selected]
        for future in as_completed(futures):
            selected_assets, manifests = future.result()
            for raw_asset in selected_assets:
                name = raw_asset.get("name")
                evidence = {}
                github_digest = _release_digest(raw_asset)
                if github_digest is not None:
                    evidence["github"] = github_digest
                for manifest_name, manifest in manifests.items():
                    if name in manifest:
                        evidence[manifest_name] = manifest[name]
                _set_digest_evidence(raw_asset, evidence)


def _enrich_xray_digests(source, spec, releases):
    tasks = []
    for raw_release in releases:
        assets = _release_assets(raw_release)
        for raw_asset in _selected_assets(spec, raw_release):
            if not _needs_checksum_fallback(raw_asset):
                continue
            sidecar = assets.get("%s.dgst" % raw_asset.get("name"))
            sidecar_url = sidecar.get("browser_download_url") if sidecar is not None else None
            if isinstance(sidecar_url, str):
                tasks.append((raw_asset, sidecar_url))

    def fetch(item):
        raw_asset, url = item
        return raw_asset, _parse_dgst(source.asset_text(url, spec.repository))

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(fetch, item) for item in tasks]
        for future in as_completed(futures):
            raw_asset, sidecar_digest = future.result()
            evidence = {"dgst": sidecar_digest}
            github_digest = _release_digest(raw_asset)
            if github_digest is not None:
                evidence["github"] = github_digest
            _set_digest_evidence(raw_asset, evidence)


def enrich_upstream_digests(source, spec, releases, previous=None):
    """Use GitHub digests first, then recorded or upstream checksum metadata."""
    _reuse_recorded_digest_evidence(spec, releases, previous)
    if spec.name == "v2ray":
        _enrich_v2ray_digests(source, spec, releases)
    elif spec.name == "xray":
        _enrich_xray_digests(source, spec, releases)


def build_catalog(releases_by_backend):  # type: (dict) -> dict
    """Return deterministic catalog JSON data from release API objects."""
    expected_names = [spec.name for spec in iter_backends()]
    if sorted(releases_by_backend) != expected_names:
        raise ValueError("release input must contain exactly: %s" % ", ".join(expected_names))
    catalogs = {}
    for spec in iter_backends():
        raw_releases = releases_by_backend[spec.name]
        if not isinstance(raw_releases, list):
            raise TypeError("release input for %s must be a list" % spec.name)
        versions = []
        updated_values = []
        seen = set()
        for raw_release in raw_releases:
            record = _version_record(spec, raw_release)
            if record is None:
                continue
            if record["version"] in seen:
                raise CatalogMaintenanceError("duplicate %s release version %s" % (spec.name, record["version"]))
            seen.add(record["version"])
            versions.append(record)
            updated_at = raw_release.get("updated_at")
            if isinstance(updated_at, str):
                updated_values.append(updated_at)
        versions.sort(key=lambda item: version_sort_key(item["version"]), reverse=True)
        if not versions:
            raise CatalogMaintenanceError("no supported release versions found for %s" % spec.name)
        if not any(
            artifact["sha256"] is not None
            for version in versions
            for artifact in version["artifacts"].values()
        ):
            raise CatalogMaintenanceError("no verified release assets found for %s" % spec.name)
        if not updated_values:
            raise CatalogMaintenanceError("release metadata has no update timestamps for %s" % spec.name)
        catalogs[spec.name] = {
            "backend": spec.name,
            "generated_at": max(updated_values),
            "repository": spec.repository,
            "versions": versions,
        }
    BackendCatalog.from_values(catalogs)
    return catalogs


def fetch_catalog(source=None, previous=None):  # type: (GitHubReleaseSource, Optional[dict]) -> dict
    """Fetch all registered upstream releases and build a validated catalog."""
    source = source or GitHubReleaseSource()
    releases = {}
    for spec in iter_backends():
        backend_releases = source.releases(spec.repository)
        enrich_upstream_digests(source, spec, backend_releases, previous=previous)
        releases[spec.name] = backend_releases
    return build_catalog(releases)


def load_existing_catalog(directory):  # type: (Path) -> Optional[dict]
    """Load all existing flat files, returning ``None`` for a clean bootstrap."""
    directory = Path(directory)
    expected_names = [spec.name for spec in iter_backends()]
    existing = [(directory / ("%s.json" % name)).is_file() for name in expected_names]
    if not any(existing):
        return None
    if not all(existing):
        raise CatalogMaintenanceError("existing backend catalog is incomplete")
    return {name: read_backend_catalog_json(name, directory=directory) for name in expected_names}


def validate_catalog_transition(previous, current):  # type: (dict, dict) -> None
    """Reject deletion or mutation of an already recorded stable release asset."""
    if previous is None:
        return
    for spec in iter_backends():
        old_versions = {item["version"]: item for item in previous[spec.name]["versions"]}
        new_versions = {item["version"]: item for item in current[spec.name]["versions"]}
        for version, old_release in old_versions.items():
            if not is_stable_version(version):
                continue
            new_release = new_versions.get(version)
            if new_release is None:
                raise CatalogMaintenanceError("upstream removed recorded %s %s" % (spec.name, version))
            for key in ("tag", "release_id", "release_url", "published_at"):
                if old_release.get(key) != new_release.get(key):
                    raise CatalogMaintenanceError("upstream mutated %s %s release field %s" % (spec.name, version, key))
            for platform_key, old_asset in old_release["artifacts"].items():
                new_asset = new_release["artifacts"].get(platform_key)
                if new_asset is None:
                    raise CatalogMaintenanceError(
                        "upstream removed %s %s asset for %s" % (spec.name, version, platform_key)
                    )
                identity_keys = (
                    "asset_id",
                    "name",
                    "url",
                    "size",
                    "updated_at",
                    "archive_format",
                    "executable",
                )
                if any(old_asset.get(key) != new_asset.get(key) for key in identity_keys):
                    raise CatalogMaintenanceError(
                        "upstream mutated %s %s asset for %s" % (spec.name, version, platform_key)
                    )
                if old_asset.get("sha256") is not None and old_asset.get("sha256") != new_asset.get("sha256"):
                    raise CatalogMaintenanceError(
                        "upstream mutated %s %s asset digest for %s" % (spec.name, version, platform_key)
                    )


def _write_json(path, value):
    descriptor, temporary_name = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        if os.name == "posix":
            path.chmod(0o644)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def write_catalog(directory, values):  # type: (Path, dict) -> None
    """Atomically write one deterministic UTF-8 JSON file per backend."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    expected_names = [spec.name for spec in iter_backends()]
    if sorted(values) != expected_names:
        raise ValueError("catalog output must contain exactly: %s" % ", ".join(expected_names))
    for name in expected_names:
        _write_json(directory / ("%s.json" % name), values[name])


def validate_catalog(directory):  # type: (Path) -> BackendCatalog
    """Validate the four catalog files without accessing the network."""
    directory = Path(directory)
    values = {}
    for spec in iter_backends():
        values[spec.name] = read_backend_catalog_json(spec.name, directory=directory)
    return BackendCatalog.from_values(values)


def main(argv=None):  # type: (list) -> int
    parser = argparse.ArgumentParser(description="Update JerryProxy's packaged backend catalog")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--validate-only", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.validate_only:
        catalog = validate_catalog(arguments.output)
        print("Catalog valid: %d backends; source updated %s" % (len(catalog.backend_names), catalog.generated_at))
        return 0
    previous = load_existing_catalog(arguments.output)
    value = fetch_catalog(previous=previous)
    validate_catalog_transition(previous, value)
    write_catalog(arguments.output, value)
    catalog = validate_catalog(arguments.output)
    print("Catalog updated: %d backends; source updated %s" % (len(catalog.backend_names), catalog.generated_at))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
