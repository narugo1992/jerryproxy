"""Normalize host operating-system and CPU names for release assets."""

import glob
import os
import platform
import sys

from ..errors import UnsupportedPlatformError
from .model import PlatformInfo

_OS_NAMES = {
    "linux": "linux",
    "win32": "windows",
    "cygwin": "windows",
    "darwin": "darwin",
}

_ARCHITECTURES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "i386": "386",
    "i686": "386",
    "x86": "386",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armv7",
    "armv6l": "armv6",
    "armv5l": "armv5",
    "riscv64": "riscv64",
    "loongarch64": "loong64",
    "loong64": "loong64",
    "ppc64le": "ppc64le",
    "s390x": "s390x",
}


def _detect_linux_libc():  # type: () -> Optional[str]
    libc_name = (platform.libc_ver()[0] or "").lower()
    if "musl" in libc_name:
        return "musl"
    if libc_name:
        return "glibc"
    if glob.glob("/lib/ld-musl-*.so.1") or glob.glob("/usr/lib/ld-musl-*.so.1"):
        return "musl"
    try:
        glibc_version = os.confstr("CS_GNU_LIBC_VERSION")
    except (AttributeError, OSError, ValueError):
        # confstr is absent or unsupported on non-glibc Linux runtimes.
        glibc_version = None
    if glibc_version:
        return "glibc"
    return None


def detect_platform(system_platform=None, machine=None):  # type: (str, str) -> PlatformInfo
    raw_os = (system_platform or sys.platform).lower()
    os_name = None
    for prefix, normalized in _OS_NAMES.items():
        if raw_os.startswith(prefix):
            os_name = normalized
            break
    if os_name is None:
        raise UnsupportedPlatformError("unsupported operating system: %s" % raw_os)

    raw_machine = (machine or platform.machine()).lower()
    architecture = _ARCHITECTURES.get(raw_machine)
    if architecture is None:
        raise UnsupportedPlatformError("unsupported CPU architecture: %s" % raw_machine)

    libc = _detect_linux_libc() if os_name == "linux" else None
    return PlatformInfo(os_name=os_name, architecture=architecture, libc=libc)
