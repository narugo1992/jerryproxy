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


def test_linux_musl_loader_is_used_when_python_reports_no_libc(monkeypatch):
    monkeypatch.setattr("jerryproxy.backend.platform.platform.libc_ver", lambda: ("", ""))
    monkeypatch.setattr("jerryproxy.backend.platform.glob.glob", lambda pattern: ["/lib/ld-musl-test.so.1"])

    result = detect_platform(system_platform="linux", machine="x86_64")

    assert result.libc == "musl"


def test_linux_glibc_confstr_is_used_when_python_reports_no_libc(monkeypatch):
    monkeypatch.setattr("jerryproxy.backend.platform.platform.libc_ver", lambda: ("", ""))
    monkeypatch.setattr("jerryproxy.backend.platform.glob.glob", lambda pattern: [])
    monkeypatch.setattr(
        "jerryproxy.backend.platform.os.confstr",
        lambda name: "glibc 2.27",
        raising=False,
    )

    result = detect_platform(system_platform="linux", machine="x86_64")

    assert result.libc == "glibc"
    assert result.key == "linux-amd64-glibc"


def test_linux_unknown_libc_fails_closed_when_confstr_is_unsupported(monkeypatch):
    monkeypatch.setattr("jerryproxy.backend.platform.platform.libc_ver", lambda: ("", ""))
    monkeypatch.setattr("jerryproxy.backend.platform.glob.glob", lambda pattern: [])

    def unsupported_confstr(name):
        raise ValueError(name)

    monkeypatch.setattr("jerryproxy.backend.platform.os.confstr", unsupported_confstr, raising=False)

    result = detect_platform(system_platform="linux", machine="x86_64")

    assert result.libc is None
    assert result.key == "linux-amd64"
