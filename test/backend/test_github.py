import json
from urllib.error import HTTPError, URLError

import pytest

from jerryproxy.backend.github import GitHubReleaseClient, select_release_asset
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.backend.registry import get_backend
from jerryproxy.errors import ReleaseResolutionError


class FakeResponse(object):
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        return False

    def read(self, maximum):
        return self.payload[:maximum]


def fake_opener_for(value):
    payload = json.dumps(value).encode("utf-8")

    def opener(request, timeout):
        assert request.full_url.endswith("/repos/MetaCubeX/mihomo/releases/tags/v1.19.29")
        assert timeout == 20.0
        return FakeResponse(payload)

    return opener


def test_release_assets_require_github_digest():
    value = {
        "assets": [
            {
                "name": "mihomo-linux-amd64-v1.19.29.gz",
                "browser_download_url": "https://example.test/mihomo.gz",
                "digest": "sha256:" + "a" * 64,
                "size": 123,
            },
            {
                "name": "unsigned.zip",
                "browser_download_url": "https://example.test/unsigned.zip",
                "digest": None,
                "size": 456,
            },
            "not-an-object",
            {
                "name": None,
                "browser_download_url": "https://example.test/missing-name.zip",
                "digest": "sha256:" + "b" * 64,
                "size": 1,
            },
            {
                "name": "invalid-length.zip",
                "browser_download_url": "https://example.test/invalid-length.zip",
                "digest": "sha256:abcd",
                "size": 1,
            },
            {
                "name": "invalid-hex.zip",
                "browser_download_url": "https://example.test/invalid-hex.zip",
                "digest": "sha256:" + "z" * 64,
                "size": 1,
            },
        ]
    }
    assets = GitHubReleaseClient(opener=fake_opener_for(value)).release_assets("MetaCubeX/mihomo", "v1.19.29")
    assert [asset.name for asset in assets] == ["mihomo-linux-amd64-v1.19.29.gz"]
    assert assets[0].sha256 == "a" * 64


def test_exact_asset_selection_rejects_ambiguity():
    spec = get_backend("mihomo")
    platform_info = PlatformInfo("linux", "amd64")
    with pytest.raises(ReleaseResolutionError):
        select_release_asset(spec, "1.19.29", platform_info, [])


def test_invalid_release_shape_is_rejected():
    client = GitHubReleaseClient(opener=fake_opener_for({"assets": "not-a-list"}))
    with pytest.raises(ReleaseResolutionError):
        client.release_assets("MetaCubeX/mihomo", "v1.19.29")


def test_release_lookup_rejects_invalid_repository_name():
    with pytest.raises(ValueError, match="OWNER/REPO"):
        GitHubReleaseClient().release_assets("missing-owner", "v1.0.0")


def test_release_lookup_sends_explicit_token_and_escaped_path():
    def opener(request, timeout):
        assert request.full_url.endswith("/repos/owner%20name/repo/releases/tags/v1.0.0%2Bmeta")
        assert request.get_header("Authorization") == "Bearer test-token"
        return FakeResponse(b'{"assets": []}')

    assets = GitHubReleaseClient(token="test-token", opener=opener).release_assets(
        "owner name/repo",
        "v1.0.0+meta",
    )
    assert assets == []


@pytest.mark.parametrize(
    ("error_kind", "message"),
    [
        ("http", "HTTP 403"),
        ("url", "TLS unavailable"),
    ],
)
def test_release_lookup_translates_transport_errors(error_kind, message):
    if error_kind == "http":
        error = HTTPError("https://api.github.test", 403, "Forbidden", {}, None)
    else:
        error = URLError("TLS unavailable")

    def opener(request, timeout):
        raise error

    with pytest.raises(ReleaseResolutionError, match=message):
        GitHubReleaseClient(opener=opener).release_assets("MetaCubeX/mihomo", "v1.19.29")


def test_release_lookup_rejects_oversized_metadata():
    client = GitHubReleaseClient(opener=lambda request, timeout: FakeResponse(b"12345"))
    client.maximum_metadata_bytes = 4
    with pytest.raises(ReleaseResolutionError, match="exceeds the safety limit"):
        client.release_assets("MetaCubeX/mihomo", "v1.19.29")


@pytest.mark.parametrize("payload", [b"not-json", b"\xff"])
def test_release_lookup_rejects_invalid_metadata(payload):
    client = GitHubReleaseClient(opener=lambda request, timeout: FakeResponse(payload))
    with pytest.raises(ReleaseResolutionError, match="invalid GitHub release metadata"):
        client.release_assets("MetaCubeX/mihomo", "v1.19.29")


def test_exact_asset_selection_returns_the_only_exact_match():
    assets = GitHubReleaseClient(
        opener=fake_opener_for(
            {
                "assets": [
                    {
                        "name": "mihomo-linux-amd64-v1.19.29.gz",
                        "browser_download_url": "https://example.test/mihomo.gz",
                        "digest": "sha256:" + "a" * 64,
                        "size": 123,
                    }
                ]
            }
        )
    ).release_assets("MetaCubeX/mihomo", "v1.19.29")

    selected = select_release_asset(
        get_backend("mihomo"),
        "1.19.29",
        PlatformInfo("linux", "amd64"),
        assets,
    )
    assert selected == assets[0]
