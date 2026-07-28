"""Built-in backend definitions and exact upstream asset naming."""

import re
from dataclasses import dataclass

from ..errors import UnsupportedBackendError, UnsupportedPlatformError
from .model import PlatformInfo

_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SEMANTIC_VERSION_PATTERN = re.compile(r"^(\d+(?:\.\d+)*)(?:-([A-Za-z0-9.-]+))?(?:\+[A-Za-z0-9.-]+)?$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {"COM%d" % index for index in range(1, 10)}
    | {"LPT%d" % index for index in range(1, 10)}
)
_SING_BOX_LIBC_ARCHITECTURES = frozenset(("386", "amd64", "arm64", "armv7", "loong64", "riscv64"))
_SING_BOX_LIBC_ASSET_VERSION = "1.13.0"

_SUPPORTED_PLATFORM_PAIRS = {
    "mihomo": frozenset(
        {
            ("linux", "386"),
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("linux", "armv5"),
            ("linux", "armv6"),
            ("linux", "armv7"),
            ("linux", "ppc64le"),
            ("linux", "riscv64"),
            ("linux", "s390x"),
            ("windows", "386"),
            ("windows", "amd64"),
            ("windows", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("freebsd", "386"),
            ("freebsd", "amd64"),
            ("freebsd", "arm64"),
        }
    ),
    "sing-box": frozenset(
        {
            ("linux", "386"),
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("linux", "armv5"),
            ("linux", "armv6"),
            ("linux", "armv7"),
            ("linux", "loong64"),
            ("linux", "ppc64le"),
            ("linux", "riscv64"),
            ("linux", "s390x"),
            ("windows", "386"),
            ("windows", "amd64"),
            ("windows", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
        }
    ),
    "xray": frozenset(
        {
            ("linux", "386"),
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("linux", "armv5"),
            ("linux", "armv6"),
            ("linux", "armv7"),
            ("linux", "loong64"),
            ("linux", "ppc64le"),
            ("linux", "riscv64"),
            ("linux", "s390x"),
            ("windows", "386"),
            ("windows", "amd64"),
            ("windows", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("freebsd", "386"),
            ("freebsd", "amd64"),
            ("freebsd", "arm64"),
            ("freebsd", "armv7"),
            ("openbsd", "386"),
            ("openbsd", "amd64"),
            ("openbsd", "arm64"),
            ("openbsd", "armv7"),
        }
    ),
    "v2ray": frozenset(
        {
            ("linux", "386"),
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("linux", "armv5"),
            ("linux", "armv6"),
            ("linux", "armv7"),
            ("linux", "loong64"),
            ("linux", "riscv64"),
            ("windows", "386"),
            ("windows", "amd64"),
            ("windows", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("freebsd", "386"),
            ("freebsd", "amd64"),
            ("freebsd", "arm64"),
            ("freebsd", "armv6"),
            ("freebsd", "armv7"),
            ("openbsd", "386"),
            ("openbsd", "amd64"),
            ("openbsd", "arm64"),
            ("openbsd", "armv6"),
            ("openbsd", "armv7"),
        }
    ),
}


@dataclass(frozen=True)
class BackendSpec:
    name: str
    repository: str
    executable: str
    asset_family: str
    description: str
    version_arguments: tuple

    def normalize_version(self, version):  # type: (str) -> str
        normalized = version.strip()
        if normalized.startswith("v"):
            normalized = normalized[1:]
        if (
            not _VERSION_PATTERN.fullmatch(normalized)
            or normalized.endswith((".", " "))
            or normalized.upper() in _WINDOWS_RESERVED_NAMES
        ):
            raise ValueError("invalid backend version: %r" % version)
        return normalized

    def tag_for(self, version):  # type: (str) -> str
        return "v%s" % self.normalize_version(version)

    def executable_filename(self, platform_info):  # type: (PlatformInfo) -> str
        suffix = ".exe" if platform_info.os_name == "windows" else ""
        return "%s%s" % (self.executable, suffix)

    def expected_asset_name(self, platform_info, version):  # type: (PlatformInfo, str) -> str
        normalized = self.normalize_version(version)
        pair = (platform_info.os_name, platform_info.architecture)
        if pair not in _SUPPORTED_PLATFORM_PAIRS[self.asset_family]:
            raise UnsupportedPlatformError("%s has no registered asset rule for %s" % (self.name, platform_info.key))
        if self.asset_family == "mihomo":
            return _mihomo_asset_name(platform_info, normalized)
        if self.asset_family == "sing-box":
            return _sing_box_asset_name(platform_info, normalized)
        if self.asset_family in ("xray", "v2ray"):
            return _v2ray_family_asset_name(self.asset_family, platform_info)
        raise UnsupportedPlatformError("unknown asset family: %s" % self.asset_family)


def _mihomo_asset_name(platform_info, version):  # type: (PlatformInfo, str) -> str
    extension = "zip" if platform_info.os_name == "windows" else "gz"
    variant = ""
    if platform_info.architecture == "amd64":
        variant = "-v1" if version_sort_key(version) >= version_sort_key("1.19.0") else "-compatible"
    return "mihomo-%s-%s%s-v%s.%s" % (
        platform_info.os_name,
        platform_info.architecture,
        variant,
        version,
        extension,
    )


def _sing_box_asset_name(platform_info, version):  # type: (PlatformInfo, str) -> str
    extension = "zip" if platform_info.os_name == "windows" else "tar.gz"
    libc_suffix = ""
    if platform_info.os_name == "linux" and platform_info.architecture in _SING_BOX_LIBC_ARCHITECTURES:
        if platform_info.libc == "musl":
            libc_suffix = "-musl"
        elif platform_info.libc == "glibc":
            if version_sort_key(version) >= version_sort_key(_SING_BOX_LIBC_ASSET_VERSION):
                libc_suffix = "-glibc"
        else:
            raise UnsupportedPlatformError("sing-box requires a known Linux libc for %s" % platform_info.key)
    return "sing-box-%s-%s-%s%s.%s" % (
        version,
        platform_info.os_name,
        platform_info.architecture,
        libc_suffix,
        extension,
    )


def _v2ray_family_asset_name(family, platform_info):  # type: (str, PlatformInfo) -> str
    os_tokens = {
        "linux": "linux",
        "windows": "windows",
        "darwin": "macos",
        "freebsd": "freebsd",
        "openbsd": "openbsd",
    }
    architecture_tokens = {
        "386": "32",
        "amd64": "64",
        "arm64": "arm64-v8a",
        "armv5": "arm32-v5",
        "armv6": "arm32-v6",
        "armv7": "arm32-v7a",
        "loong64": "loong64",
        "ppc64le": "ppc64le",
        "riscv64": "riscv64",
        "s390x": "s390x",
    }
    os_token = os_tokens.get(platform_info.os_name)
    architecture_token = architecture_tokens.get(platform_info.architecture)
    if os_token is None or architecture_token is None:
        raise UnsupportedPlatformError("%s has no registered asset rule for %s" % (family, platform_info.key))
    prefix = "Xray" if family == "xray" else "v2ray"
    return "%s-%s-%s.zip" % (prefix, os_token, architecture_token)


_BACKENDS = {
    "mihomo": BackendSpec(
        name="mihomo",
        repository="MetaCubeX/mihomo",
        executable="mihomo",
        asset_family="mihomo",
        description="Preferred default candidate pending compatibility/security PoC.",
        version_arguments=("-v",),
    ),
    "sing-box": BackendSpec(
        name="sing-box",
        repository="SagerNet/sing-box",
        executable="sing-box",
        asset_family="sing-box",
        description="Optional backend for native sing-box profiles.",
        version_arguments=("version",),
    ),
    "xray": BackendSpec(
        name="xray",
        repository="XTLS/Xray-core",
        executable="xray",
        asset_family="xray",
        description="Optional Xray-family specialist backend.",
        version_arguments=("version",),
    ),
    "v2ray": BackendSpec(
        name="v2ray",
        repository="v2fly/v2ray-core",
        executable="v2ray",
        asset_family="v2ray",
        description="Legacy V2Ray compatibility backend.",
        version_arguments=("version",),
    ),
}  # type: Dict[str, BackendSpec]


def get_backend(name):  # type: (str) -> BackendSpec
    normalized = name.strip().lower()
    try:
        return _BACKENDS[normalized]
    except KeyError:
        # KeyError is expected only when a user requests an unregistered backend id.
        raise UnsupportedBackendError("unsupported backend: %s" % name)


def iter_backends():  # type: () -> Iterable[BackendSpec]
    return (_BACKENDS[name] for name in sorted(_BACKENDS))


def iter_backend_platforms(name):  # type: (str) -> Iterable[PlatformInfo]
    """Yield every desktop/server platform registered for one backend."""
    spec = get_backend(name)
    for os_name, architecture in sorted(_SUPPORTED_PLATFORM_PAIRS[spec.asset_family]):
        if spec.name == "sing-box" and os_name == "linux" and architecture in _SING_BOX_LIBC_ARCHITECTURES:
            yield PlatformInfo(os_name=os_name, architecture=architecture, libc="glibc")
            yield PlatformInfo(os_name=os_name, architecture=architecture, libc="musl")
        else:
            yield PlatformInfo(os_name=os_name, architecture=architecture)


def version_sort_key(version):  # type: (str) -> tuple
    """Return a deterministic descending-sort key for catalog versions."""
    normalized = version[1:] if version.startswith("v") else version
    match = _SEMANTIC_VERSION_PATTERN.fullmatch(normalized)
    if match is None:
        raise ValueError("unsupported catalog version: %r" % version)
    numeric = tuple(int(part) for part in match.group(1).split("."))
    prerelease = match.group(2)
    prerelease_tokens = ()
    if prerelease:
        prerelease_tokens = tuple(
            (1, int(part)) if part.isdigit() else (0, part.lower())
            for identifier in re.split(r"[.-]", prerelease)
            for part in re.findall(r"[A-Za-z]+|\d+", identifier)
        )
    return numeric, 1 if prerelease is None else 0, prerelease_tokens


def is_stable_version(version):  # type: (str) -> bool
    """Return whether a normalized backend version has no prerelease suffix."""
    return version_sort_key(version)[1] == 1
