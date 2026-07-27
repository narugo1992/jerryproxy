import json

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
