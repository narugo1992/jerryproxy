import pytest

from jerryproxy.backend.model import PlatformInfo
from jerryproxy.backend.registry import BackendSpec, get_backend, is_stable_version, iter_backends
from jerryproxy.errors import UnsupportedBackendError, UnsupportedPlatformError


@pytest.mark.parametrize(
    ("backend", "platform_info", "version", "expected"),
    [
        (
            "mihomo",
            PlatformInfo("linux", "amd64", "glibc"),
            "1.19.29",
            "mihomo-linux-amd64-v1-v1.19.29.gz",
        ),
        (
            "mihomo",
            PlatformInfo("windows", "arm64"),
            "v1.19.29",
            "mihomo-windows-arm64-v1.19.29.zip",
        ),
        (
            "sing-box",
            PlatformInfo("linux", "amd64", "glibc"),
            "1.13.14",
            "sing-box-1.13.14-linux-amd64-glibc.tar.gz",
        ),
        (
            "sing-box",
            PlatformInfo("linux", "amd64", "musl"),
            "1.13.14",
            "sing-box-1.13.14-linux-amd64-musl.tar.gz",
        ),
        (
            "sing-box",
            PlatformInfo("windows", "arm64"),
            "v1.13.14",
            "sing-box-1.13.14-windows-arm64.zip",
        ),
        (
            "sing-box",
            PlatformInfo("darwin", "arm64"),
            "1.13.14",
            "sing-box-1.13.14-darwin-arm64.tar.gz",
        ),
        ("xray", PlatformInfo("darwin", "arm64"), "26.3.27", "Xray-macos-arm64-v8a.zip"),
        ("v2ray", PlatformInfo("linux", "amd64"), "5.51.2", "v2ray-linux-64.zip"),
    ],
)
def test_exact_asset_names(backend, platform_info, version, expected):
    assert get_backend(backend).expected_asset_name(platform_info, version) == expected


def test_registry_order_is_stable():
    assert [spec.name for spec in iter_backends()] == ["mihomo", "sing-box", "v2ray", "xray"]


def test_platform_catalog_keys_prefer_exact_libc_then_portable_assets():
    platform_info = PlatformInfo("linux", "amd64", "musl")

    assert platform_info.asset_key == "linux-amd64-musl"
    assert platform_info.compatible_asset_keys == ("linux-amd64-musl", "linux-amd64")


@pytest.mark.parametrize("version", ["1.0.0", "v1.13.14", "26.3.27+build.1"])
def test_stable_versions_are_accepted(version):
    assert is_stable_version(version)


@pytest.mark.parametrize("version", ["1.0-alpha1", "1.0-beta.2", "1.0-rc1", "1.0-preview"])
def test_prerelease_versions_are_not_stable(version):
    assert not is_stable_version(version)


def test_unknown_backend_is_rejected():
    with pytest.raises(UnsupportedBackendError):
        get_backend("unknown")


def test_unknown_asset_family_is_rejected_as_an_unsupported_platform_rule():
    spec = BackendSpec("custom", "owner/repo", "custom", "unknown", "Custom", ("version",))

    with pytest.raises(UnsupportedPlatformError, match="unknown asset family"):
        spec.expected_asset_name(PlatformInfo("linux", "amd64"), "1.0.0")


def test_mihomo_openbsd_is_not_guessed():
    with pytest.raises(UnsupportedPlatformError):
        get_backend("mihomo").expected_asset_name(PlatformInfo("openbsd", "amd64"), "1.19.29")


def test_mihomo_amd64_uses_the_conservative_cpu_baseline():
    spec = get_backend("mihomo")

    assert spec.expected_asset_name(PlatformInfo("linux", "amd64"), "1.19.29") == (
        "mihomo-linux-amd64-v1-v1.19.29.gz"
    )
    assert spec.expected_asset_name(PlatformInfo("linux", "amd64"), "1.18.10") == (
        "mihomo-linux-amd64-compatible-v1.18.10.gz"
    )


def test_sing_box_linux_asset_names_follow_version_and_architecture_policy():
    spec = get_backend("sing-box")

    assert spec.expected_asset_name(PlatformInfo("linux", "amd64", "glibc"), "1.13.14") == (
        "sing-box-1.13.14-linux-amd64-glibc.tar.gz"
    )
    assert spec.expected_asset_name(PlatformInfo("linux", "amd64", "musl"), "1.13.14") == (
        "sing-box-1.13.14-linux-amd64-musl.tar.gz"
    )
    assert spec.expected_asset_name(PlatformInfo("linux", "amd64", "glibc"), "1.12.25") == (
        "sing-box-1.12.25-linux-amd64.tar.gz"
    )
    assert spec.expected_asset_name(PlatformInfo("linux", "amd64", "musl"), "1.12.25") == (
        "sing-box-1.12.25-linux-amd64-musl.tar.gz"
    )
    assert spec.expected_asset_name(PlatformInfo("linux", "armv5"), "1.13.14") == (
        "sing-box-1.13.14-linux-armv5.tar.gz"
    )

    with pytest.raises(UnsupportedPlatformError, match="known Linux libc"):
        spec.expected_asset_name(PlatformInfo("linux", "amd64"), "1.13.14")


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
        ("sing-box", PlatformInfo("freebsd", "amd64")),
        ("xray", PlatformInfo("windows", "armv7")),
        ("v2ray", PlatformInfo("linux", "s390x")),
        ("v2ray", PlatformInfo("linux", "ppc64le")),
    ],
)
def test_nonexistent_release_platform_pairs_are_rejected(backend, platform_info):
    with pytest.raises(UnsupportedPlatformError):
        get_backend(backend).expected_asset_name(platform_info, "1.0.0")
