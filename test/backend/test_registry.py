import pytest

from jerryproxy.backend.model import PlatformInfo
from jerryproxy.backend.registry import get_backend, iter_backends
from jerryproxy.errors import UnsupportedBackendError, UnsupportedPlatformError


@pytest.mark.parametrize(
    ("backend", "platform_info", "version", "expected"),
    [
        (
            "mihomo",
            PlatformInfo("linux", "amd64", "glibc"),
            "1.19.29",
            "mihomo-linux-amd64-v1.19.29.gz",
        ),
        (
            "mihomo",
            PlatformInfo("windows", "arm64"),
            "v1.19.29",
            "mihomo-windows-arm64-v1.19.29.zip",
        ),
        ("xray", PlatformInfo("darwin", "arm64"), "26.3.27", "Xray-macos-arm64-v8a.zip"),
        ("v2ray", PlatformInfo("linux", "amd64"), "5.51.2", "v2ray-linux-64.zip"),
    ],
)
def test_exact_asset_names(backend, platform_info, version, expected):
    assert get_backend(backend).expected_asset_name(platform_info, version) == expected


def test_registry_order_is_stable():
    assert [spec.name for spec in iter_backends()] == ["mihomo", "v2ray", "xray"]


def test_unknown_backend_is_rejected():
    with pytest.raises(UnsupportedBackendError):
        get_backend("unknown")


def test_mihomo_openbsd_is_not_guessed():
    with pytest.raises(UnsupportedPlatformError):
        get_backend("mihomo").expected_asset_name(PlatformInfo("openbsd", "amd64"), "1.19.29")


@pytest.mark.parametrize(
    "version",
    ["", ".", "..", "../1", "a/b", "a\\b", "C:", "C:escape", "white space", "version?"],
)
def test_unsafe_versions_are_rejected(version):
    with pytest.raises(ValueError):
        get_backend("mihomo").normalize_version(version)


@pytest.mark.parametrize(
    ("backend", "platform_info"),
    [
        ("mihomo", PlatformInfo("darwin", "armv7")),
        ("mihomo", PlatformInfo("linux", "loong64")),
        ("xray", PlatformInfo("windows", "armv7")),
        ("v2ray", PlatformInfo("linux", "s390x")),
        ("v2ray", PlatformInfo("linux", "ppc64le")),
    ],
)
def test_nonexistent_release_platform_pairs_are_rejected(backend, platform_info):
    with pytest.raises(UnsupportedPlatformError):
        get_backend(backend).expected_asset_name(platform_info, "1.0.0")
