from copy import deepcopy
from pathlib import Path

import pytest

import jerryproxy.data as data_module
from jerryproxy.backend.catalog import BackendCatalog
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.backend.platform import detect_platform
from jerryproxy.backend.registry import is_stable_version, iter_backend_platforms, iter_backends, version_sort_key
from jerryproxy.data import backend_catalog_resource_names, read_backend_catalog_bytes, read_backend_catalog_json
from jerryproxy.errors import BackendCatalogError, UnsupportedPlatformError


def packaged_value():
    return {name: read_backend_catalog_json(name) for name in backend_catalog_resource_names()}


def test_data_package_exposes_four_flat_json_resources():
    assert backend_catalog_resource_names() == ("mihomo", "sing-box", "v2ray", "xray")
    data_root = Path(data_module.__file__).parent
    assert sorted(path.name for path in data_root.glob("*.json")) == [
        "mihomo.json",
        "sing-box.json",
        "v2ray.json",
        "xray.json",
    ]
    for name in backend_catalog_resource_names():
        payload = read_backend_catalog_bytes(name)
        assert payload.endswith(b"\n")
        assert read_backend_catalog_json(name)["backend"] == name


def test_data_package_rejects_unknown_missing_and_invalid_resources(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="unknown backend catalog resource"):
        read_backend_catalog_bytes("unknown")

    monkeypatch.setattr(data_module.pkgutil, "get_data", lambda package, name: None)
    with pytest.raises(FileNotFoundError, match="resource is missing"):
        read_backend_catalog_bytes("mihomo")

    (tmp_path / "mihomo.json").write_bytes(b"\xff")
    with pytest.raises(ValueError, match="not valid UTF-8 JSON"):
        read_backend_catalog_json("mihomo", directory=tmp_path)

    (tmp_path / "mihomo.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        read_backend_catalog_json("mihomo", directory=tmp_path)


def test_data_package_enforces_resource_size_limit(tmp_path, monkeypatch):
    (tmp_path / "mihomo.json").write_text("{}", encoding="ascii")
    monkeypatch.setattr(data_module, "MAXIMUM_DATA_RESOURCE_BYTES", 1)

    with pytest.raises(ValueError, match="exceeds the safety limit"):
        read_backend_catalog_bytes("mihomo", directory=tmp_path)


def test_catalog_resources_have_only_stable_static_fields():
    top_level_keys = {"backend", "generated_at", "repository", "versions"}
    version_keys = {"artifacts", "published_at", "release_id", "release_url", "tag", "version"}
    artifact_keys = {
        "archive_format",
        "asset_id",
        "executable",
        "name",
        "sha256",
        "size",
        "updated_at",
        "url",
        "verification",
    }
    for name in backend_catalog_resource_names():
        value = read_backend_catalog_json(name)
        assert set(value) == top_level_keys
        for version in value["versions"]:
            assert set(version) == version_keys
            assert is_stable_version(version["version"])
            for artifact in version["artifacts"].values():
                assert set(artifact) == artifact_keys


def test_packaged_catalog_covers_all_backends_and_registered_platforms():
    catalog = BackendCatalog.load()

    assert catalog.backend_names == ("mihomo", "sing-box", "v2ray", "xray")
    assert sum(len(catalog.versions(name)) for name in catalog.backend_names) >= 350
    for spec in iter_backends():
        versions = catalog.versions(spec.name)
        assert [item.version for item in versions] == sorted(
            [item.version for item in versions], key=version_sort_key, reverse=True
        )
        assert len({item.version for item in versions}) == len(versions)
        for platform_info in iter_backend_platforms(spec.name):
            available = catalog.available_versions(spec.name, platform_info)
            assert available, "%s has no verified stable %s artifact" % (spec.name, platform_info.asset_key)
            artifact = available[0].artifact_for(platform_info)
            assert artifact.verified
            assert artifact.platform == platform_info.asset_key
            assert artifact.url.startswith("https://github.com/%s/releases/download/" % spec.repository)
            assert artifact.size > 0
            assert len(artifact.sha256) == 64


@pytest.mark.parametrize("backend", ["mihomo", "sing-box", "xray", "v2ray"])
def test_catalog_resolves_first_available_stable_version(backend):
    catalog = BackendCatalog.load()
    platform_info = detect_platform()
    expected = catalog.available_versions(backend, platform_info)[0]
    artifact = catalog.resolve(backend, platform_info=platform_info)

    assert artifact.version == expected.version
    assert artifact == expected.artifact_for(platform_info)
    assert artifact.verified


def test_sing_box_linux_catalog_selects_the_detected_libc():
    catalog = BackendCatalog.load()
    glibc = catalog.resolve("sing-box", platform_info=PlatformInfo("linux", "amd64", "glibc"))
    musl = catalog.resolve("sing-box", platform_info=PlatformInfo("linux", "amd64", "musl"))

    assert glibc.platform == "linux-amd64-glibc"
    assert glibc.name.endswith("-linux-amd64-glibc.tar.gz")
    assert musl.platform == "linux-amd64-musl"
    assert musl.name.endswith("-linux-amd64-musl.tar.gz")
    assert glibc.asset_id != musl.asset_id

    legacy_glibc = catalog.resolve("sing-box", "1.12.25", PlatformInfo("linux", "amd64", "glibc"))
    assert legacy_glibc.platform == "linux-amd64-glibc"
    assert legacy_glibc.name == "sing-box-1.12.25-linux-amd64.tar.gz"
    with pytest.raises(UnsupportedPlatformError, match="no catalog asset"):
        catalog.resolve("sing-box", "1.12.25", PlatformInfo("linux", "amd64", "musl"))

    portable = catalog.resolve("sing-box", platform_info=PlatformInfo("linux", "armv5", "musl"))
    assert portable.platform == "linux-armv5"
    assert portable.name.endswith("-linux-armv5.tar.gz")


def test_catalog_rejects_an_asset_name_from_the_wrong_platform():
    value = deepcopy(packaged_value())
    newest = value["sing-box"]["versions"][0]
    newest["artifacts"]["linux-amd64-musl"] = deepcopy(newest["artifacts"]["linux-amd64-glibc"])

    with pytest.raises(BackendCatalogError, match="does not match the registered platform asset"):
        BackendCatalog.from_values(value)


def test_explicit_unverified_historical_asset_fails_closed():
    catalog = BackendCatalog.load()
    version = next(
        item
        for item in catalog.versions("mihomo")
        if (item.artifact_for(PlatformInfo("linux", "amd64")) is not None)
        and not item.artifact_for(PlatformInfo("linux", "amd64")).verified
    )

    with pytest.raises(BackendCatalogError, match="no upstream SHA-256 fingerprint"):
        catalog.resolve("mihomo", version.version, PlatformInfo("linux", "amd64"))


def test_version_sort_key_orders_numeric_prerelease_suffixes():
    versions = ["1.3-beta9", "1.3-beta14", "1.3-alpha50", "1.3", "1.2.10"]

    assert sorted(versions, key=version_sort_key, reverse=True) == [
        "1.3",
        "1.3-beta14",
        "1.3-beta9",
        "1.3-alpha50",
        "1.2.10",
    ]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("xray"), "backend set"),
        (
            lambda value: value["mihomo"]["versions"].reverse(),
            "not sorted newest to oldest",
        ),
        (
            lambda value: value["mihomo"]["versions"][0]["artifacts"]["linux-amd64"].update(
                url="http://example.test/backend.gz"
            ),
            "exact official GitHub release URL",
        ),
    ],
)
def test_catalog_rejects_corrupt_public_payloads(mutation, message):
    value = deepcopy(packaged_value())
    mutation(value)

    with pytest.raises(BackendCatalogError, match=message):
        BackendCatalog.from_values(value)
