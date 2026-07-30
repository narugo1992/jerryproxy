"""Lightweight black-box checks for source and packaged JerryProxy CLIs."""

import hashlib
import os
import platform
import sys
import tempfile
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from .backend import BackendCatalog, BackendManager, iter_backends
from .backend.platform import detect_platform
from .backend.relay import (
    RELAY_PROBE_BYTES,
    RELAY_PROBE_SHA256,
    RELAY_PROBE_SIZE,
    RELAY_PROBE_URL,
    iter_builtin_relays,
    render_relay_url,
)
from .config.meta import __VERSION__
from .errors import BackendCatalogError, JerryProxyError, UnsupportedPlatformError
from .lock import JerryProxyOperationLock, filelock_status

_ANSI_BOLD = "\033[1m"
_ANSI_CYAN = "\033[1;36m"
_ANSI_GREEN = "\033[1;32m"
_ANSI_YELLOW = "\033[1;33m"
_ANSI_RED = "\033[1;31m"
_ANSI_RESET = "\033[0m"
_RELAY_CHECK_TIMEOUT = 5.0
_RELAY_CHECK_MAX_REDIRECTS = 5
_RELAY_CHECK_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class CheckResult:
    """One completed self-check result at an explicit severity level."""

    level: str
    detail: str

    @classmethod
    def ok(cls, detail):
        return cls("OK", detail)

    @classmethod
    def warn(cls, detail):
        return cls("WARN", detail)

    @classmethod
    def fail(cls, detail):
        return cls("FAIL", detail)

    @classmethod
    def err(cls, detail):
        return cls("ERR", detail)


def _paint(text, code, color):
    return "%s%s%s" % (code, text, _ANSI_RESET) if color else text


def _error_result(error):
    message = str(error).strip() or repr(error)
    return CheckResult.err("%s: %s" % (error.__class__.__name__, message))


def ansi_color_enabled(stream, requested=None):
    """Resolve explicit flags and conventional color environment variables."""
    if requested is not None:
        return bool(requested)
    if "NO_COLOR" in os.environ:
        return False
    forced = os.environ.get("FORCE_COLOR")
    if forced is not None:
        return forced not in ("", "0")
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        # Output adapters may not expose a TTY or may reject the terminal probe.
        return False


def _directory_paths(paths):
    return (
        paths.root,
        paths.backends,
        paths.bin,
        paths.downloads,
        paths.providers,
        paths.runtimes,
        paths.logs,
        paths.locks,
        paths.active,
    )


def _check_runtime():
    if sys.version_info < (3, 7):
        return CheckResult.fail("Python 3.7 or newer is required")
    if not __VERSION__:
        return CheckResult.fail("package version is empty")
    frozen = bool(getattr(sys, "frozen", False))
    return CheckResult.ok(
        "Python %s; JerryProxy %s; frozen=%s"
        % (platform.python_version(), __VERSION__, str(frozen).lower())
    )


def _check_platform():
    try:
        platform_info = detect_platform()
    except (OSError, RuntimeError, UnsupportedPlatformError) as error:
        # Host platform detection may fail on unsupported or unreadable systems.
        return _error_result(error)
    return CheckResult.ok(platform_info.key)


def _check_home_layout(paths):
    try:
        with JerryProxyOperationLock(paths):
            directory_paths = _directory_paths(paths)
            missing = [str(path) for path in directory_paths if not path.is_dir()]
    except (JerryProxyError, OSError) as error:
        # Home initialization can fail through lock contention or filesystem access.
        return _error_result(error)
    if missing:
        return CheckResult.fail("missing state directories: %s" % ", ".join(missing))
    return CheckResult.ok("%d private state directories" % len(directory_paths))


def _check_home_writable(paths):
    try:
        with JerryProxyOperationLock(paths):
            descriptor, temporary_name = tempfile.mkstemp(prefix=".self-check-", dir=str(paths.root))
            try:
                os.write(descriptor, b"jerryproxy-self-check\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)
    except (JerryProxyError, OSError) as error:
        # Lock contention and filesystem writes are expected operational failures.
        return _error_result(error)
    return CheckResult.ok("temporary write and cleanup succeeded")


def _check_private_permissions(paths):
    try:
        with JerryProxyOperationLock(paths):
            if os.name != "posix":
                return CheckResult.ok("POSIX mode check not applicable")
            unexpected = []
            for path in _directory_paths(paths):
                mode = path.stat().st_mode & 0o777
                if mode != 0o700:
                    unexpected.append("%s=%03o" % (path, mode))
    except (JerryProxyError, OSError) as error:
        # Permission inspection can fail through lock or filesystem access.
        return _error_result(error)
    if unexpected:
        return CheckResult.fail("state directory modes are not 0700: %s" % ", ".join(unexpected))
    return CheckResult.ok("all state directories are 0700")


def _check_backend_registry():
    try:
        platform_info = detect_platform()
        specs = list(iter_backends())
        names = [spec.name for spec in specs]
        compatible = []
        for spec in specs:
            try:
                spec.expected_asset_name(platform_info, "1.0.0")
            except UnsupportedPlatformError:
                # A backend may intentionally omit release assets for this platform.
                continue
            compatible.append(spec.name)
    except (OSError, RuntimeError, ValueError) as error:
        # Registry evaluation can fail on invalid platform metadata.
        return _error_result(error)
    if not names or len(names) != len(set(names)):
        return CheckResult.fail("backend registry is empty or contains duplicate names")
    if not compatible:
        return CheckResult.fail("no registered backend supports %s" % platform_info.key)
    return CheckResult.ok(
        "%d registered; %d compatible: %s"
        % (len(names), len(compatible), ", ".join(compatible))
    )


def _check_backend_catalog():
    try:
        catalog = BackendCatalog.load()
        platform_info = detect_platform()
        missing = []
        total_releases = 0
        for spec in iter_backends():
            versions = catalog.versions(spec.name)
            total_releases += len(versions)
            if not catalog.compatible_versions(spec.name, platform_info):
                missing.append(spec.name)
    except (BackendCatalogError, OSError, RuntimeError, ValueError) as error:
        # Packaged catalog parsing and platform selection may fail independently.
        return _error_result(error)
    if missing:
        return CheckResult.fail(
            "catalog has no verified stable %s asset for: %s"
            % (platform_info.key, ", ".join(missing))
        )
    return CheckResult.ok(
        "%d releases; 4/4 compatible; snapshot %s" % (total_releases, catalog.generated_at)
    )


def _check_filelock():
    status = filelock_status()
    if status.level == "WARN":
        return CheckResult.warn(status.detail)
    return CheckResult.ok(status.detail)


def _check_backend_inventory(paths):
    try:
        inventory = BackendManager(paths).inventory()
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Inventory reads can fail on invalid state or filesystem access.
        return _error_result(error)
    return CheckResult.ok(
        "%d installed; %d active" % (len(inventory.installed), len(inventory.active))
    )


def _relay_warning(reason):
    return CheckResult.warn("bounded 1 MiB verification failed: %s" % reason)


def _check_relay(profile, session_factory):
    session = session_factory()
    response = None
    started = time.monotonic()
    try:
        session.max_redirects = _RELAY_CHECK_MAX_REDIRECTS
        response = session.get(
            render_relay_url(profile, RELAY_PROBE_URL),
            headers={
                "Range": "bytes=0-%d" % (RELAY_PROBE_BYTES - 1),
                "User-Agent": "JerryProxy-self-check",
            },
            allow_redirects=True,
            stream=True,
            timeout=_RELAY_CHECK_TIMEOUT,
        )
        response_at = time.monotonic()
        if len(response.history) > _RELAY_CHECK_MAX_REDIRECTS:
            return _relay_warning("redirect limit exceeded")
        redirect_urls = [item.url for item in response.history] + [response.url]
        if any(urlparse(item).scheme != "https" for item in redirect_urls):
            return _relay_warning("redirect chain did not remain HTTPS")
        if response.status_code != 206:
            return _relay_warning("HTTP response was not 206")
        expected_range = "bytes 0-%d/%d" % (RELAY_PROBE_BYTES - 1, RELAY_PROBE_SIZE)
        if response.headers.get("Content-Range") != expected_range:
            return _relay_warning("Content-Range did not match the pinned asset")
        body = bytearray()
        chunk_count = 0
        first_chunk_at = None
        first_chunk_size = 0
        for block in response.iter_content(chunk_size=_RELAY_CHECK_CHUNK_SIZE):
            if not block:
                continue
            remaining = RELAY_PROBE_BYTES + 1 - len(body)
            accepted = block[:remaining]
            received_at = time.monotonic()
            body.extend(accepted)
            chunk_count += 1
            if first_chunk_at is None:
                first_chunk_at = received_at
                first_chunk_size = len(accepted)
            if len(body) > RELAY_PROBE_BYTES:
                break
        if len(body) != RELAY_PROBE_BYTES:
            return _relay_warning("response body was not exactly 1 MiB")
        if hashlib.sha256(bytes(body)).hexdigest() != RELAY_PROBE_SHA256:
            return _relay_warning("pinned 1 MiB sample digest did not match")
        completed_at = time.monotonic()
        first_chunk_seconds = max(first_chunk_at - started, 0.0)
        streamed_bytes = len(body) - first_chunk_size
        stream_seconds = max(completed_at - first_chunk_at, 0.001)
        throughput = streamed_bytes / 1024.0 / stream_seconds
        return CheckResult.ok(
            "verified 1 MiB; response %.1f ms; first chunk %.1f ms; stream %.1f KiB/s over %d chunks"
            % (
                (response_at - started) * 1000.0,
                first_chunk_seconds * 1000.0,
                throughput,
                chunk_count,
            )
        )
    except requests.exceptions.TooManyRedirects:
        # Requests raises this when the configured redirect ceiling is exceeded.
        return _relay_warning("redirect limit exceeded")
    except requests.exceptions.ProxyError:
        # The system-configured HTTP proxy may be unavailable or reject the request.
        return _relay_warning("system proxy connection failed")
    except requests.exceptions.SSLError:
        # TLS negotiation and system CA validation failures are availability warnings.
        return _relay_warning("TLS validation failed")
    except requests.exceptions.Timeout:
        # The bounded relay request may exceed the fixed self-check deadline.
        return _relay_warning("request timed out")
    except requests.exceptions.ConnectionError:
        # DNS and TCP connection failures are relay availability warnings.
        return _relay_warning("connection failed")
    except requests.exceptions.RequestException:
        # Other documented Requests transport failures remain sanitized warnings.
        return _relay_warning("request failed")
    finally:
        if response is not None:
            response.close()
        session.close()


def build_checks(paths, relay_session_factory=None):
    session_factory = (
        relay_session_factory if relay_session_factory is not None else requests.Session
    )
    checks = (
        ("Python runtime", _check_runtime),
        ("platform detection", _check_platform),
        ("home directory layout", lambda: _check_home_layout(paths)),
        ("home write access", lambda: _check_home_writable(paths)),
        ("private directory permissions", lambda: _check_private_permissions(paths)),
        ("backend registry", _check_backend_registry),
        ("packaged backend catalog", _check_backend_catalog),
        ("filelock compatibility", _check_filelock),
        ("backend inventory", lambda: _check_backend_inventory(paths)),
    )
    return checks + tuple(
        (
            "relay %s" % profile.name,
            lambda selected=profile: _check_relay(selected, session_factory),
        )
        for profile in iter_builtin_relays()
    )


def run_checks(checks, output, color=False):
    counts = {"OK": 0, "WARN": 0, "FAIL": 0, "ERR": 0}
    colors = {"OK": _ANSI_GREEN, "WARN": _ANSI_YELLOW, "FAIL": _ANSI_RED, "ERR": _ANSI_RED}
    total = len(checks)
    for index, (name, check) in enumerate(checks, start=1):
        label = "[%d/%d] %s" % (index, total, name)
        result = check()
        counts[result.level] += 1
        output(
            "%s: %s - %s"
            % (
                _paint(label, _ANSI_CYAN, color),
                _paint(result.level, colors[result.level], color),
                result.detail,
            )
        )

    output(
        "%s: %s, %s, %s, %s"
        % (
            _paint("Summary", _ANSI_BOLD, color),
            _paint("%d OK" % counts["OK"], _ANSI_GREEN, color),
            _paint("%d WARN" % counts["WARN"], _ANSI_YELLOW, color),
            _paint("%d FAIL" % counts["FAIL"], _ANSI_RED, color),
            _paint("%d ERR" % counts["ERR"], _ANSI_RED, color),
        )
    )
    if counts["FAIL"] or counts["ERR"]:
        output(_paint("Self-check FAILED", _ANSI_RED, color))
        return 1
    if counts["WARN"]:
        output(_paint("Self-check PASSED with warnings", _ANSI_YELLOW, color))
        return 0
    output(_paint("Self-check PASSED", _ANSI_GREEN, color))
    return 0


def run_self_check(paths, output=print, color=False, relay_session_factory=None):
    output(_paint("JerryProxy self-check %s" % __VERSION__, _ANSI_CYAN, color))
    output("%s: %s" % (_paint("Home", _ANSI_BOLD, color), paths.root))
    return run_checks(
        build_checks(paths, relay_session_factory=relay_session_factory),
        output,
        color=color,
    )
