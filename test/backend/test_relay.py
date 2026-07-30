import pytest

from jerryproxy.backend.relay import (
    RelayProfile,
    build_download_sources,
    custom_relay,
    get_builtin_relay,
    iter_builtin_relays,
    render_relay_url,
)
from jerryproxy.errors import DownloadPolicyError

OFFICIAL_URL = (
    "https://github.com/XTLS/Xray-core/releases/download/"
    "v26.3.27/Xray-linux-64.zip"
)


def test_builtin_relays_are_small_stable_hostname_profiles():
    profiles = iter_builtin_relays()

    assert [item.name for item in profiles] == [
        "gh-proxy.com",
        "cdn.akaere.online",
        "gh.geekertao.top",
    ]
    assert [item.base_url for item in profiles] == [
        "https://gh-proxy.com",
        "https://cdn.akaere.online",
        "https://gh.geekertao.top",
    ]
    assert all(item.pattern == "full_url_path" for item in profiles)
    assert get_builtin_relay("gh-proxy.com") is profiles[0]


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (
            "full_url_path",
            "https://relay.example/prefix/" + OFFICIAL_URL,
        ),
        (
            "host_path",
            (
                "https://relay.example/prefix/github.com/XTLS/Xray-core/"
                "releases/download/v26.3.27/Xray-linux-64.zip"
            ),
        ),
        (
            "query_q",
            (
                "https://relay.example/prefix/?q=https%3A%2F%2Fgithub.com%2F"
                "XTLS%2FXray-core%2Freleases%2Fdownload%2Fv26.3.27%2F"
                "Xray-linux-64.zip"
            ),
        ),
    ],
)
def test_render_relay_url_supports_the_three_measured_patterns(pattern, expected):
    profile = custom_relay("https://relay.example/prefix/", pattern)

    assert render_relay_url(profile, OFFICIAL_URL) == expected


@pytest.mark.parametrize(
    "base_url",
    [
        "http://relay.example",
        "https://user@relay.example",
        "https://relay.example?q=secret",
        "https://relay.example/#fragment",
        "https://relay.example/\\escape",
        "https://relay.example/%0aescape",
        "https://relay.example/%zz",
        "https://relay.example:99999",
        "https://relay.example:0",
        "https://[",
    ],
)
def test_custom_relay_rejects_unsafe_bases(base_url):
    with pytest.raises(DownloadPolicyError):
        custom_relay(base_url, "full_url_path")


@pytest.mark.parametrize(
    "official_url",
    [
        "http://github.com/XTLS/Xray-core/releases/download/v1/a.zip",
        "https://example.com/XTLS/Xray-core/releases/download/v1/a.zip",
        "https://github.com/XTLS/Xray-core/archive/v1.zip",
        "https://github.com/XTLS/Xray-core/releases/file/v1/a.zip",
        "https://github.com/XTLS/Xray-core/releases/download/v1/a.zip?q=token",
        "https://[",
    ],
)
def test_relay_rendering_accepts_only_public_github_release_assets(official_url):
    with pytest.raises(DownloadPolicyError):
        render_relay_url(get_builtin_relay("gh-proxy.com"), official_url)


def test_download_source_policies_are_explicit_and_bounded():
    direct = build_download_sources(OFFICIAL_URL)
    automatic = build_download_sources(OFFICIAL_URL, relay="auto")
    named = build_download_sources(OFFICIAL_URL, relay="cdn.akaere.online")
    custom = build_download_sources(
        OFFICIAL_URL,
        relay_url="https://relay.example",
        relay_pattern="host_path",
    )

    assert [(item.label, item.url) for item in direct] == [("direct", OFFICIAL_URL)]
    assert [item.label for item in automatic] == [
        "direct",
        "gh-proxy.com",
        "cdn.akaere.online",
        "gh.geekertao.top",
    ]
    assert [item.label for item in named] == ["cdn.akaere.online"]
    assert [item.label for item in custom] == ["custom relay"]
    assert custom[0].url.startswith("https://relay.example/github.com/")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"relay": "unknown"},
        {"relay": "direct", "relay_url": "https://relay.example"},
        {"relay_pattern": "host_path"},
        {"relay_url": "https://relay.example", "relay_pattern": "unknown"},
    ],
)
def test_download_source_policy_rejects_conflicts(kwargs):
    with pytest.raises(DownloadPolicyError):
        build_download_sources(OFFICIAL_URL, **kwargs)


def test_render_relay_url_rejects_an_unknown_profile_pattern():
    profile = RelayProfile("test", "https://relay.example", "unknown")

    with pytest.raises(DownloadPolicyError, match="unsupported relay URL pattern"):
        render_relay_url(profile, OFFICIAL_URL)
