"""Minimal GitHub release metadata client used by the backend catalog."""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..errors import ReleaseResolutionError
from .model import ReleaseAsset


class GitHubReleaseClient(object):
    """Resolve release assets without depending on the local ``gh`` CLI."""

    api_root = "https://api.github.com"
    maximum_metadata_bytes = 8 * 1024 * 1024

    def __init__(self, token=None, timeout=20.0, opener=None):
        # type: (Optional[str], float, Any) -> None
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.timeout = timeout
        self.opener = opener or urlopen

    def release_assets(self, repository, tag):  # type: (str, str) -> List[ReleaseAsset]
        repository_parts = repository.split("/")
        if len(repository_parts) != 2 or not all(repository_parts):
            raise ValueError("GitHub repository must be OWNER/REPO: %r" % repository)
        url = "%s/repos/%s/releases/tags/%s" % (
            self.api_root,
            "/".join(quote(part, safe="") for part in repository_parts),
            quote(tag, safe=""),
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "JerryProxy-release-resolver",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer %s" % self.token
        request = Request(url, headers=headers)
        try:
            response = self.opener(request, timeout=self.timeout)
            with response:
                payload = response.read(self.maximum_metadata_bytes + 1)
        except HTTPError as error:
            # HTTPError is expected for a missing tag, private repository, or API rate limit.
            raise ReleaseResolutionError(
                "GitHub release lookup failed for %s@%s: HTTP %s" % (repository, tag, error.code)
            )
        except URLError as error:
            # URLError is expected for DNS, TLS, proxy, and connection failures.
            raise ReleaseResolutionError("GitHub release lookup failed for %s@%s: %s" % (repository, tag, error.reason))
        if len(payload) > self.maximum_metadata_bytes:
            raise ReleaseResolutionError("GitHub release metadata exceeds the safety limit")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            # UnicodeDecodeError/ValueError are expected for a corrupt or non-JSON API response.
            raise ReleaseResolutionError("invalid GitHub release metadata: %s" % error)
        return self._parse_assets(value)

    @staticmethod
    def _parse_assets(value):  # type: (Dict[str, Any]) -> List[ReleaseAsset]
        raw_assets = value.get("assets")
        if not isinstance(raw_assets, list):
            raise ReleaseResolutionError("GitHub release metadata has no asset list")
        assets = []
        for raw_asset in raw_assets:
            if not isinstance(raw_asset, dict):
                continue
            name = raw_asset.get("name")
            url = raw_asset.get("browser_download_url")
            digest = raw_asset.get("digest")
            size = raw_asset.get("size")
            if not isinstance(name, str) or not isinstance(url, str) or not isinstance(size, int):
                continue
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                continue
            sha256 = digest.split(":", 1)[1].lower()
            if len(sha256) != 64 or any(character not in "0123456789abcdef" for character in sha256):
                continue
            assets.append(ReleaseAsset(name=name, url=url, sha256=sha256, size=size))
        return assets


def select_release_asset(spec, version, platform_info, assets):
    expected_name = spec.expected_asset_name(platform_info, version)
    matches = [asset for asset in assets if asset.name == expected_name]
    if len(matches) != 1:
        raise ReleaseResolutionError(
            "expected exactly one %s asset for %s@%s, found %d"
            % (expected_name, spec.name, spec.normalize_version(version), len(matches))
        )
    return matches[0]
