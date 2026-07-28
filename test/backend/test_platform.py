import pytest

from jerryproxy.backend.platform import detect_platform
from jerryproxy.errors import UnsupportedPlatformError


@pytest.mark.parametrize(
    ("system_platform", "machine", "expected"),
    [
        ("linux", "x86_64", ("linux", "amd64")),
        ("linux", "aarch64", ("linux", "arm64")),
        ("win32", "AMD64", ("windows", "amd64")),
        ("darwin", "arm64", ("darwin", "arm64")),
        ("freebsd13", "i386", ("freebsd", "386")),
    ],
)
def test_platform_normalization(system_platform, machine, expected):
    result = detect_platform(system_platform=system_platform, machine=machine)
    assert (result.os_name, result.architecture) == expected


def test_unknown_platform_fails_early():
    with pytest.raises(UnsupportedPlatformError):
        detect_platform(system_platform="plan9", machine="amd64")


def test_unknown_architecture_fails_early():
    with pytest.raises(UnsupportedPlatformError):
        detect_platform(system_platform="linux", machine="mystery-cpu")


def test_linux_musl_is_reported_through_public_platform_detection(monkeypatch):
    monkeypatch.setattr(
        "jerryproxy.backend.platform.platform.libc_ver",
        lambda: ("musl", "1.2.5"),
    )
    result = detect_platform(system_platform="linux", machine="x86_64")
    assert result.libc == "musl"
    assert result.key == "linux-amd64-musl"
