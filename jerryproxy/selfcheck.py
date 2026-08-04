"""Lightweight black-box checks for source and packaged JerryProxy CLIs."""

import errno
import hashlib
import multiprocessing
import os
import platform
import re
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests

from .backend import BackendCatalog, BackendManager, get_backend, iter_backend_platforms, iter_backends
from .backend.installation import InstallTransaction
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
from .errors import (
    BackendCatalogError,
    IntegrityError,
    JerryProxyBusyError,
    JerryProxyError,
    UnsupportedPlatformError,
)
from .home import JerryProxyPaths
from .lock import JerryProxyOperationLock, filelock_status
from .runtime.health import DEFAULT_HEALTH_TARGETS, RecoveryPolicy
from .runtime.mihomo import build_provider_config
from .subscription import parse_subscription_body
from .utils.fs import atomic_write_json, read_json

_ANSI_BOLD = "\033[1m"
_ANSI_CYAN = "\033[1;36m"
_ANSI_GREEN = "\033[1;32m"
_ANSI_YELLOW = "\033[1;33m"
_ANSI_RED = "\033[1;31m"
_ANSI_RESET = "\033[0m"
_RELAY_CHECK_TIMEOUT = 5.0
_RELAY_CHECK_TOTAL_TIMEOUT = 30.0
_RELAY_CHECK_MAX_REDIRECTS = 5
_RELAY_CHECK_CHUNK_SIZE = 64 * 1024
_RECOVERY_PROCESS_TIMEOUT = 30.0
_RECOVERY_CHILD_INSTALL = 71
_RECOVERY_CHILD_ACTIVATION_ROLLBACK = 72
_RECOVERY_CHILD_ACTIVATION_ROLLFORWARD = 73
_RECOVERY_CHILD_REMOVAL_ROLLBACK = 74
_RECOVERY_CHILD_REMOVAL_ROLLFORWARD = 75
_RECOVERY_CHILD_ERROR = 90
_CHILD_STDERR_CAPTURE_ERROR = 96
_CHILD_START_CANCELLED = 97
_CHILD_START_GATE_TIMEOUT = 35.0
_PROCESS_SUPERVISION_WAIT = 10.0
_MAXIMUM_DETAIL_CHARACTERS = 2048
_MAXIMUM_DIAGNOSTIC_CHARACTERS = 64 * 1024
_MAXIMUM_DIAGNOSTIC_INPUT_CHARACTERS = 256 * 1024
_MAXIMUM_CHILD_RESULT_BYTES = 128 * 1024
_PROCESS_CONTROL_EXCEPTIONS = (AssertionError, AttributeError, OSError, RuntimeError, ValueError)
_DIAGNOSTIC_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)
_DIAGNOSTIC_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_DIAGNOSTIC_NAMED_SECRET = re.compile(
    r"\b(password|passwd|pwd|token|access[ _-]?token|secret|api[ _-]?key|public[ _-]?key|"
    r"private[ _-]?key|short[ _-]?id|uuid)(\s*(?::|=)\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)
_DIAGNOSTIC_BEARER = re.compile(
    r"\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]+",
    re.IGNORECASE,
)
_DIAGNOSTIC_PEM = re.compile(
    r"-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----",
    re.DOTALL,
)
_DIAGNOSTIC_SSH_KEY = re.compile(
    r"\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?"
)


@dataclass(frozen=True)
class CheckResult:
    """One completed self-check result at an explicit severity level."""

    level: str
    detail: str
    diagnostics: tuple = ()

    @classmethod
    def ok(cls, detail):
        return cls("OK", detail)

    @classmethod
    def warn(cls, detail):
        return cls("WARN", detail)

    @classmethod
    def skip(cls, detail):
        return cls("SKIP", detail)

    @classmethod
    def fail(cls, detail):
        return cls("FAIL", detail)

    @classmethod
    def err(cls, detail, diagnostics=()):
        return cls("ERR", detail, tuple(diagnostics))


def _paint(text, code, color):
    return "%s%s%s" % (code, text, _ANSI_RESET) if color else text


def _redact_diagnostic(value):
    text = str(value)
    text = _DIAGNOSTIC_PEM.sub("[REDACTED KEY]", text)
    text = _DIAGNOSTIC_SSH_KEY.sub("[REDACTED KEY]", text)
    text = _DIAGNOSTIC_URL.sub("[REDACTED URL]", text)
    text = _DIAGNOSTIC_BEARER.sub("[REDACTED TOKEN]", text)
    text = _DIAGNOSTIC_NAMED_SECRET.sub(
        lambda match: "%s%s[REDACTED]" % (match.group(1), match.group(2)),
        text,
    )
    return _DIAGNOSTIC_UUID.sub("[REDACTED UUID]", text)


def _bounded_line(value):
    text = " ".join(_redact_diagnostic(value).splitlines()).strip()
    if not text:
        text = _redact_diagnostic(repr(value))
    return text[:_MAXIMUM_DETAIL_CHARACTERS]


def _bounded_diagnostic(value):
    return _redact_diagnostic(value).strip()[:_MAXIMUM_DIAGNOSTIC_CHARACTERS]


def _error_result(error):
    message = _bounded_line(error)
    formatted = _bounded_diagnostic(traceback.format_exc())
    diagnostics = () if formatted.startswith("NoneType: None") else (formatted,)
    return CheckResult.err(
        "%s: %s" % (error.__class__.__name__, message),
        diagnostics=diagnostics,
    )


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
        paths.subscriptions,
        paths.nodes,
        paths.leases,
        paths.config,
    )


def _check_runtime():
    if sys.version_info < (3, 7):
        return CheckResult.fail("Python 3.7 or newer is required")
    if not __VERSION__:
        return CheckResult.fail("package version is empty")
    frozen = bool(getattr(sys, "frozen", False))
    return CheckResult.ok(
        "Python %s; JerryProxy %s; frozen=%s" % (platform.python_version(), __VERSION__, str(frozen).lower())
    )


def _check_platform():
    try:
        platform_info = detect_platform()
    except UnsupportedPlatformError as error:
        # Platform-dependent checks have no applicable target on an unsupported host.
        return CheckResult.skip("%s: %s" % (error.__class__.__name__, _bounded_line(error)))
    except (OSError, RuntimeError) as error:
        # Host platform metadata may be temporarily unreadable.
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
                return CheckResult.skip("POSIX mode checks do not apply on %s" % os.name)
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
        specs = list(iter_backends())
        names = [spec.name for spec in specs]
    except (RuntimeError, ValueError) as error:
        # Built-in registry construction rejects invalid backend metadata.
        return _error_result(error)
    if not names or len(names) != len(set(names)):
        return CheckResult.fail("backend registry is empty or contains duplicate names")
    try:
        platform_info = detect_platform()
        compatible = []
        for spec in specs:
            try:
                spec.expected_asset_name(platform_info, "1.0.0")
            except UnsupportedPlatformError:
                # A backend may intentionally omit release assets for this platform.
                continue
            compatible.append(spec.name)
    except UnsupportedPlatformError as error:
        # Asset naming has no meaning until the host platform is supported.
        return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
    except (OSError, RuntimeError, ValueError) as error:
        # Registry evaluation can fail on invalid platform metadata.
        return _error_result(error)
    if not compatible:
        return CheckResult.fail("no registered backend supports %s" % platform_info.key)
    return CheckResult.ok("%d registered; %d compatible: %s" % (len(names), len(compatible), ", ".join(compatible)))


def _check_backend_catalog():
    try:
        catalog = BackendCatalog.load()
        missing = []
        total_releases = 0
        for spec in iter_backends():
            versions = catalog.versions(spec.name)
            total_releases += len(versions)
            if not versions:
                missing.append(spec.name)
    except BackendCatalogError as error:
        # Invalid packaged catalog data is a failed product resource invariant.
        return CheckResult.fail("%s: %s" % (error.__class__.__name__, _bounded_line(error)))
    except (OSError, RuntimeError, ValueError) as error:
        # Packaged resource access may fail in a damaged installation.
        return _error_result(error)
    if missing:
        return CheckResult.fail("catalog has no stable releases for: %s" % ", ".join(missing))
    return CheckResult.ok("%d stable releases; snapshot %s" % (total_releases, catalog.generated_at))


def _check_backend_catalog_selection():
    try:
        catalog = BackendCatalog.load()
    except BackendCatalogError as error:
        # Platform selection is meaningless when its packaged catalog prerequisite is invalid.
        return CheckResult.skip("packaged catalog prerequisite failed: %s" % _bounded_line(error))
    except (OSError, RuntimeError, ValueError) as error:
        # Platform selection cannot run when the packaged resource is unreadable.
        return CheckResult.skip("packaged catalog prerequisite is unavailable: %s" % _bounded_line(error))
    try:
        platform_info = detect_platform()
        missing = [
            spec.name
            for spec in iter_backends()
            if not catalog.compatible_versions(spec.name, platform_info)
        ]
    except UnsupportedPlatformError as error:
        # Catalog selection has no applicable target on an unsupported host platform.
        return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
    except (OSError, RuntimeError, ValueError) as error:
        # Selection may fail on unreadable or invalid platform metadata.
        return _error_result(error)
    if missing:
        return CheckResult.fail(
            "catalog has no verified stable %s asset for: %s" % (platform_info.key, ", ".join(missing))
        )
    return CheckResult.ok("4/4 backends have verified stable %s assets" % platform_info.key)


def _check_subscription_parser():
    """Exercise the packaged URI classifier without reading private state."""

    fixture = (
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
        b"vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1NS01NTU1NTU1NTU1IiwibmV0IjoidGNwIiwicG9ydCI6IjQ0MyIsInBzIjoidm1lc3MiLCJ2IjoyfQ==\n"
        b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443?security=reality&sni=www.example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&flow=xtls-rprx-vision#vless\n"
    )
    try:
        parsed = parse_subscription_body(fixture, format_hint="uri-lines")
    except (ValueError, JerryProxyError) as error:
        # The product parser is an installed-resource capability, not a unit
        # test proxy; a malformed packaged fixture is a diagnostic error.
        return _error_result(error)
    schemes = tuple(item[0] for item in parsed.records)
    if schemes != ("ss", "vmess", "vless"):
        return CheckResult.fail("subscription parser classified an unexpected scheme set")
    if any("@" in item[1] or "=" in item[1] for item in parsed.records):
        return CheckResult.fail("subscription parser produced a credential-shaped display")
    return CheckResult.ok("Base64/plain URI parser accepted SS, VMess, and VLESS safely")


def _check_runtime_projection():
    """Exercise the Mihomo projection API in a private temporary directory."""

    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-runtime-self-check-") as temporary:
            root = Path(temporary)
            provider = root / "xdg-config" / "mihomo" / "provider.txt"
            config = root / "config.yaml"
            provider.parent.mkdir(mode=0o700, parents=True)
            provider.write_bytes(b"ss://opaque\n")
            payload = build_provider_config(provider, b"ss://opaque\n", 17777, "user", "password")
            config.write_bytes(payload)
            text = payload.decode("utf-8")
            if "MATCH,jerryproxy" not in text or "allow-lan: false" not in text:
                return CheckResult.fail("Mihomo projection lacks the loopback-only rule")
    except (OSError, UnicodeError, RuntimeError, ValueError) as error:
        # Temporary projection and encoding failures are diagnostic errors.
        return _error_result(error)
    policy = RecoveryPolicy()
    if len(DEFAULT_HEALTH_TARGETS) != 3 or policy.alternate_delays != (4.0, 8.0):
        return CheckResult.fail("runtime health/recovery policy is incomplete")
    return CheckResult.ok("Mihomo projection and bounded health recovery policy are usable")


def _check_filelock():
    status = filelock_status()
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-filelock-self-check-") as temporary:
            paths = JerryProxyPaths(Path(temporary) / ".jerryproxy")
            with JerryProxyOperationLock(paths):
                try:
                    with JerryProxyOperationLock(paths):
                        return CheckResult.fail("filelock allowed a concurrent exclusive acquisition")
                except JerryProxyBusyError:
                    # A second acquisition must observe the real platform lock as busy.
                    pass
            with JerryProxyOperationLock(paths):
                pass
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Temporary-home creation and real lock operations may fail in the host environment.
        return _error_result(error)
    detail = "%s; exclusive acquire, contention, release, and reacquire succeeded" % status.detail
    if status.level == "WARN":
        return CheckResult.warn(detail)
    return CheckResult.ok(detail)


def _check_backend_inventory(paths):
    try:
        inventory = BackendManager(paths, platform_info=detect_platform()).inventory()
    except UnsupportedPlatformError as error:
        # Inventory interpretation depends on the current backend platform contract.
        return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))
    except IntegrityError as error:
        # Retained managed-state evidence is a failed integrity requirement.
        message = str(error).strip() or repr(error)
        return CheckResult.fail("%s: %s" % (error.__class__.__name__, message))
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Operational and unexpected inventory failures are diagnostic errors.
        return _error_result(error)
    return CheckResult.ok("%d installed; %d active" % (len(inventory.installed), len(inventory.active)))


def _recovery_platform():
    platform_info = detect_platform()
    spec = get_backend("mihomo")
    supported = {item.asset_key for item in iter_backend_platforms(spec.name)}
    compatible = [key for key in platform_info.compatible_asset_keys if key in supported]
    if not compatible:
        return platform_info, spec, None
    return platform_info, spec, compatible[0]


def _write_probe_archive(root, spec, platform_info, version, payload):
    archive = Path(root) / ("%s-%s.zip" % (spec.name, version))
    executable_name = spec.executable_filename(platform_info)
    with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr(executable_name, payload)
    return archive, executable_name, hashlib.sha256(archive.read_bytes()).hexdigest()


def _install_probe_version(manager, root, spec, platform_info, asset_platform, version, payload):
    archive, executable_name, digest = _write_probe_archive(
        root,
        spec,
        platform_info,
        version,
        payload,
    )
    return manager.install_from_archive(
        spec.name,
        version,
        archive,
        expected_sha256=digest,
        asset_name=archive.name,
        asset_platform=asset_platform,
        archive_executable=executable_name,
        activate=False,
    )


def _probe_manager(paths, platform_info):
    return BackendManager(
        paths,
        platform_info=platform_info,
        probe_runner=lambda installed: None,
    )


def _write_recovery_child_error(path):
    descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags, 0o600)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        payload = _bounded_diagnostic(traceback.format_exc()).encode("utf-8")
        while payload:
            written = os.write(descriptor, payload)
            if written <= 0:
                raise OSError(errno.EIO, "diagnostic write made no progress")
            payload = payload[written:]
    except OSError:
        # The parent still reports the child exit code when its diagnostic file is unavailable.
        pass
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                # Diagnostic cleanup must not replace the hard-exit probe's intended status.
                pass


class _BoundedChildStderr(object):
    def __init__(self, stream):
        self._stream = stream
        self._remaining = _MAXIMUM_DIAGNOSTIC_CHARACTERS
        self._pending = ""
        self._discarding_line = False
        self._inside_pem = False
        self.encoding = "utf-8"

    def _write_sanitized_line(self, value):
        if "-----BEGIN " in value and " KEY-----" in value:
            self._inside_pem = True
            value = "[REDACTED KEY]\n"
        elif self._inside_pem:
            if "-----END " in value and " KEY-----" in value:
                self._inside_pem = False
            value = "[REDACTED KEY]\n"
        else:
            value = _redact_diagnostic(value)
        payload = value.encode("utf-8", errors="replace")[: self._remaining]
        if payload:
            self._stream.write(payload)
            self._remaining -= len(payload)

    def write(self, value):
        text = str(value)
        size = len(text)
        if self._remaining <= 0:
            return size
        if self._discarding_line:
            separator = text.find("\n")
            if separator < 0:
                return size
            text = text[separator + 1 :]
            self._discarding_line = False
        self._pending += text
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            self._write_sanitized_line(line + "\n")
        if len(self._pending) > _MAXIMUM_DIAGNOSTIC_INPUT_CHARACTERS:
            self._write_sanitized_line("[child stderr line exceeded capture limit]\n")
            self._pending = ""
            self._discarding_line = True
        return size

    def flush(self):
        self._stream.flush()

    def finish(self):
        if self._pending and not self._discarding_line:
            self._write_sanitized_line(self._pending)
        self._pending = ""
        self._stream.flush()

    def isatty(self):
        return False


def _child_start_allowed(
    start_allowed,
    start_cancelled,
    start_ready,
    start_budget,
):
    ready_at = time.monotonic()
    start_ready.set()
    gate_deadline = ready_at + _CHILD_START_GATE_TIMEOUT
    while True:
        if start_cancelled.is_set():
            return False
        if start_allowed.is_set():
            elapsed = time.monotonic() - ready_at
            return start_budget.value > elapsed and not start_cancelled.is_set()
        remaining = gate_deadline - time.monotonic()
        if remaining <= 0.0:
            return False
        start_allowed.wait(min(remaining, 0.05))


def _captured_child_entry(
    target,
    arguments,
    stderr_log,
    start_allowed,
    start_cancelled,
    start_ready,
    start_budget,
):
    diagnostic_descriptor = None
    null_descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        diagnostic_descriptor = os.open(
            str(stderr_log),
            flags,
            0o600,
        )
        if os.name == "posix":
            os.fchmod(diagnostic_descriptor, 0o600)
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_descriptor, 2)
        diagnostic_stream = os.fdopen(diagnostic_descriptor, "wb", buffering=0)
        diagnostic_descriptor = None
    except (OSError, ValueError):
        # A child without a private stderr boundary must not execute or inherit the terminal.
        if diagnostic_descriptor is not None:
            try:
                os.close(diagnostic_descriptor)
            except OSError:
                # A rejected capture boundary is already represented by the child exit code.
                pass
        if null_descriptor is not None:
            try:
                os.close(null_descriptor)
            except OSError:
                # A rejected capture boundary is already represented by the child exit code.
                pass
        os._exit(_CHILD_STDERR_CAPTURE_ERROR)
    if null_descriptor != 2:
        try:
            os.close(null_descriptor)
        except OSError:
            # The duplicated stderr descriptor remains authoritative for diagnostics.
            pass
    diagnostic_writer = _BoundedChildStderr(diagnostic_stream)
    sys.stderr = diagnostic_writer
    if not _child_start_allowed(start_allowed, start_cancelled, start_ready, start_budget):
        diagnostic_writer.finish()
        os._exit(_CHILD_START_CANCELLED)
    try:
        target(*arguments)
    finally:
        diagnostic_writer.finish()


def _install_recovery_child(root, error_log):
    try:
        paths = JerryProxyPaths(Path(root))
        platform_info, spec, asset_platform = _recovery_platform()
        artifact = {
            "sha256": "0" * 64,
            "size": 1,
            "asset_name": "interrupted.zip",
            "platform": asset_platform,
        }
        with JerryProxyOperationLock(paths, platform_info=platform_info):
            transaction = InstallTransaction.prepare(paths, spec.name, "9.9.9", artifact)
            staging = transaction.begin_staging()
            (staging / "partial").write_bytes(b"interrupted")
        os._exit(_RECOVERY_CHILD_INSTALL)
    except (JerryProxyError, OSError, RuntimeError, ValueError):
        # Child setup failures are serialized for the parent self-check result.
        _write_recovery_child_error(error_log)
        os._exit(_RECOVERY_CHILD_ERROR)


def _activation_recovery_child(root, version, direction, error_log):
    try:
        from .backend import activation as activation_module

        paths = JerryProxyPaths(Path(root))
        platform_info = detect_platform()
        manager = _probe_manager(paths, platform_info)
        if direction == "rollback":
            original_replace = activation_module.durable_replace

            def crash_after_first_publication(source, destination, *args, **kwargs):
                original_replace(source, destination, *args, **kwargs)
                os._exit(_RECOVERY_CHILD_ACTIVATION_ROLLBACK)

            activation_module.durable_replace = crash_after_first_publication
        else:

            def crash_after_commit(paths, platform_info):
                del paths, platform_info
                os._exit(_RECOVERY_CHILD_ACTIVATION_ROLLFORWARD)

            activation_module.recover_use_transactions = crash_after_commit
        manager.use("mihomo", version)
        os._exit(_RECOVERY_CHILD_ERROR)
    except (JerryProxyError, OSError, RuntimeError, ValueError):
        # Child activation failures are serialized for the parent self-check result.
        _write_recovery_child_error(error_log)
        os._exit(_RECOVERY_CHILD_ERROR)


def _removal_recovery_child(root, version, direction, error_log):
    try:
        from .backend import removal as removal_module

        paths = JerryProxyPaths(Path(root))
        manager = _probe_manager(paths, detect_platform())
        if direction == "rollback":
            original_move = removal_module._move_no_replace

            def crash_after_first_move(*args, **kwargs):
                original_move(*args, **kwargs)
                os._exit(_RECOVERY_CHILD_REMOVAL_ROLLBACK)

            removal_module._move_no_replace = crash_after_first_move
        else:
            original_write = removal_module._write_removal_journal

            def crash_after_commit(*args, **kwargs):
                result = original_write(*args, **kwargs)
                if kwargs.get("phase", "staging") == "committed":
                    os._exit(_RECOVERY_CHILD_REMOVAL_ROLLFORWARD)
                return result

            removal_module._write_removal_journal = crash_after_commit
        manager.uninstall("mihomo", version, deactivate=True)
        os._exit(_RECOVERY_CHILD_ERROR)
    except (JerryProxyError, OSError, RuntimeError, ValueError):
        # Child removal failures are serialized for the parent self-check result.
        _write_recovery_child_error(error_log)
        os._exit(_RECOVERY_CHILD_ERROR)


def _preferred_process_context():
    methods = multiprocessing.get_all_start_methods()
    preferred = ("spawn", "fork")
    start_method = next((method for method in preferred if method in methods), None)
    if start_method is None:
        return None, None
    return start_method, multiprocessing.get_context(start_method)


def _process_control_error(action, error):
    return "%s failed: %s: %s" % (action, error.__class__.__name__, _bounded_line(error))


def _join_process(process, timeout, diagnostics):
    try:
        process.join(timeout)
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Host process supervision may reject a bounded join operation.
        diagnostics.append(_process_control_error("join", error))


class _ProcessSupervision(object):
    """Aggregate cleanup outcomes for process starts that return after a deadline."""

    def __init__(self):
        self._lock = threading.Lock()
        self._settled = threading.Event()
        self._settled.set()
        self._registered = 0
        self._pending = 0
        self._survivors = 0
        self._diagnostics = []

    def register(self):
        with self._lock:
            self._registered += 1
            self._pending += 1
            self._settled.clear()

    def complete(self, alive, diagnostics):
        with self._lock:
            self._pending -= 1
            if alive:
                self._survivors += 1
            self._diagnostics.extend(diagnostics)
            if self._pending == 0:
                self._settled.set()

    def wait(self, timeout):
        return self._settled.wait(timeout)

    def result(self):
        with self._lock:
            registered = self._registered
            pending = self._pending
            survivors = self._survivors
            diagnostics = tuple(self._diagnostics)
        if pending:
            noun = "cleanup is" if pending == 1 else "cleanups are"
            return CheckResult.err(
                "%d delayed child %s still pending" % (pending, noun),
                diagnostics=diagnostics,
            )
        if survivors:
            noun = "child remained" if survivors == 1 else "children remained"
            return CheckResult.err(
                "%d delayed %s alive after kill" % (survivors, noun),
                diagnostics=diagnostics,
            )
        if not registered:
            return CheckResult.ok("no delayed child starts required cleanup")
        noun = "start was" if registered == 1 else "starts were"
        return CheckResult.ok("%d delayed child %s cancelled and reaped" % (registered, noun))


def _check_process_supervision(supervision):
    supervision.wait(_PROCESS_SUPERVISION_WAIT)
    return supervision.result()


def _start_process(
    process,
    start_allowed,
    start_cancelled,
    start_ready,
    start_budget,
    deadline,
    supervision=None,
):
    outcome = []
    start_finished = threading.Event()
    cleanup_required = threading.Event()
    ownership_decided = threading.Event()
    supervision_registered = []

    def abandon(status, error=None, track_cleanup=True):
        cleanup_required.set()
        if supervision is not None and track_cleanup:
            supervision.register()
            supervision_registered.append(True)
        try:
            start_cancelled.set()
        except _PROCESS_CONTROL_EXCEPTIONS as cancellation_error:
            # Local cleanup ownership must survive a failed cross-process cancellation signal.
            status = "error"
            error = cancellation_error
        finally:
            ownership_decided.set()
        return status, error

    def start():
        try:
            process.start()
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # Process creation failures are returned to the supervising thread.
            outcome.append(error)
        else:
            outcome.append(None)
        finally:
            start_finished.set()
        ownership_decided.wait()
        if cleanup_required.is_set():
            alive = False
            diagnostics = []
            if outcome and outcome[0] is None:
                _join_process(process, 5.0, diagnostics)
                alive = _process_is_alive(process, diagnostics)
                if alive:
                    alive, stop_diagnostics = _stop_process(process)
                    diagnostics.extend(stop_diagnostics)
            if supervision_registered:
                supervision.complete(alive, tuple(diagnostics))

    thread = threading.Thread(target=start, name="jerryproxy-self-check-start", daemon=True)
    try:
        thread.start()
    except RuntimeError as error:
        # A host that rejects thread startup cannot provide a bounded process launch.
        return abandon("unavailable", error, track_cleanup=False)
    while not start_finished.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return abandon("timeout")
        if start_finished.wait(min(remaining, 0.05)):
            break
        if not thread.is_alive():
            return abandon("error", RuntimeError("process start thread returned no outcome"))
    if time.monotonic() >= deadline:
        return abandon("timeout")
    if not outcome:
        return abandon("error", RuntimeError("process start thread returned no outcome"))
    if outcome[0] is not None:
        ownership_decided.set()
        return "unavailable", outcome[0]
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return abandon("timeout")
        try:
            if start_ready.wait(min(remaining, 0.05)):
                break
            if not process.is_alive():
                try:
                    start_cancelled.set()
                except _PROCESS_CONTROL_EXCEPTIONS as error:
                    # A dead child needs no cleanup, but cancellation publication still failed.
                    ownership_decided.set()
                    return "error", error
                ownership_decided.set()
                return "started", None
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # Child readiness and liveness are required before authorization.
            return abandon("error", error)
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        return abandon("timeout")
    try:
        start_budget.value = remaining
        start_allowed.set()
    except (OSError, RuntimeError, ValueError) as error:
        # A started child must remain gated when its budget or authorization cannot be published.
        return abandon("error", error)
    if time.monotonic() >= deadline:
        return abandon("timeout")
    ownership_decided.set()
    return "started", None


def _process_is_alive(process, diagnostics):
    try:
        return process.is_alive()
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Unknown process state must be treated as alive so hard-kill cleanup is attempted.
        diagnostics.append(_process_control_error("liveness check", error))
        return True


def _stop_process(process):
    diagnostics = []
    try:
        process.terminate()
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Termination failure must not prevent the later hard-kill attempt.
        diagnostics.append(_process_control_error("terminate", error))
    _join_process(process, 5.0, diagnostics)
    alive = _process_is_alive(process, diagnostics)
    if alive:
        try:
            process.kill()
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # A rejected hard kill is reported after the final liveness check.
            diagnostics.append(_process_control_error("kill", error))
        _join_process(process, 5.0, diagnostics)
        alive = _process_is_alive(process, diagnostics)
    return alive, tuple(diagnostics)


def _run_recovery_child(target, arguments, expected_exit, error_log, supervision=None):
    started_at = time.monotonic()
    deadline = started_at + _RECOVERY_PROCESS_TIMEOUT
    start_method, context = _preferred_process_context()
    if start_method is None:
        return CheckResult.skip("no supported multiprocessing start method is available")
    stderr_log = Path("%s.stderr" % error_log)
    try:
        start_allowed = context.Event()
        start_cancelled = context.Event()
        start_ready = context.Event()
        start_budget = context.Value("d", 0.0)
        process = context.Process(
            target=_captured_child_entry,
            args=(
                target,
                tuple(arguments) + (str(error_log),),
                str(stderr_log),
                start_allowed,
                start_cancelled,
                start_ready,
                start_budget,
            ),
            daemon=True,
        )
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Frozen-runtime or host process policy may reject process construction.
        return CheckResult.skip(
            "%s hard-exit probe unavailable: %s: %s"
            % (start_method, error.__class__.__name__, _bounded_line(error))
        )
    start_status, start_error = _start_process(
        process,
        start_allowed,
        start_cancelled,
        start_ready,
        start_budget,
        deadline,
        supervision=supervision,
    )
    if start_status == "timeout":
        diagnostics = ()
        if supervision is not None:
            diagnostics = ("delayed process-start cleanup will be verified by the final supervision check",)
        return CheckResult.err(
            "hard-exit recovery child startup exceeded the %.3g-second timeout"
            % _RECOVERY_PROCESS_TIMEOUT,
            diagnostics=diagnostics,
        )
    if start_status == "unavailable":
        # Frozen-runtime or host process policy may reject the selected start method.
        return CheckResult.skip(
            "%s hard-exit probe unavailable: %s: %s"
            % (start_method, start_error.__class__.__name__, _bounded_line(start_error))
        )
    if start_status == "error":
        return CheckResult.err(
            "hard-exit recovery child startup supervision failed: %s: %s"
            % (start_error.__class__.__name__, _bounded_line(start_error))
        )
    wait_diagnostics = []
    remaining = max(_RECOVERY_PROCESS_TIMEOUT - (time.monotonic() - started_at), 0.0)
    _join_process(process, remaining, wait_diagnostics)
    alive = _process_is_alive(process, wait_diagnostics)
    if wait_diagnostics:
        if alive:
            alive, stop_diagnostics = _stop_process(process)
            wait_diagnostics.extend(stop_diagnostics)
        wait_diagnostics.extend(_child_diagnostics(error_log, stderr_log))
        if alive:
            return CheckResult.err(
                "timed-out hard-exit recovery child remained alive after kill",
                diagnostics=tuple(wait_diagnostics),
            )
        return CheckResult.err(
            "hard-exit recovery child supervision failed",
            diagnostics=tuple(wait_diagnostics),
        )
    if alive:
        alive, stop_diagnostics = _stop_process(process)
        stop_diagnostics = stop_diagnostics + _child_diagnostics(error_log, stderr_log)
        if alive:
            return CheckResult.err(
                "timed-out hard-exit recovery child remained alive after kill",
                diagnostics=stop_diagnostics,
            )
        return CheckResult.err(
            "hard-exit recovery child exceeded the %.0f-second timeout" % _RECOVERY_PROCESS_TIMEOUT,
            diagnostics=stop_diagnostics,
        )
    if process.exitcode == expected_exit:
        return None
    diagnostics = _child_diagnostics(error_log, stderr_log)
    return CheckResult.err(
        "hard-exit recovery child returned %s instead of %s" % (process.exitcode, expected_exit),
        diagnostics=diagnostics,
    )


def _recovery_artifacts(paths):
    return (
        tuple(paths.runtimes.glob(".install-*"))
        + tuple(paths.runtimes.glob(".use-*"))
        + tuple(paths.runtimes.glob(".remove-*"))
        + tuple(paths.bin.glob(".*.use-*.candidate"))
        + tuple(paths.active.glob(".*.use-*.candidate.json"))
    )


def _recovery_failure(error):
    if isinstance(error, IntegrityError):
        return CheckResult.fail("%s: %s" % (error.__class__.__name__, _bounded_line(error)))
    return _error_result(error)


def _unsupported_recovery_platform(error):
    return CheckResult.skip("platform prerequisite is unsupported: %s" % _bounded_line(error))


def _check_isolated_backend_lifecycle():
    try:
        platform_info, spec, asset_platform = _recovery_platform()
        if asset_platform is None:
            return CheckResult.skip("no Mihomo fixture asset shape supports %s" % platform_info.key)
        with tempfile.TemporaryDirectory(prefix="jerryproxy-lifecycle-self-check-") as temporary:
            root = Path(temporary)
            paths = JerryProxyPaths(root / ".jerryproxy")
            manager = _probe_manager(paths, platform_info)
            installed = _install_probe_version(
                manager,
                root,
                spec,
                platform_info,
                asset_platform,
                "1.0.0",
                b"jerryproxy-lifecycle-self-check\n",
            )
            active = manager.use(spec.name, installed.version)
            manager.verify(spec.name, installed.version)
            manager.uninstall(spec.name, installed.version, deactivate=True)
            inventory = manager.inventory()
            if inventory.installed or inventory.active or _recovery_artifacts(paths):
                return CheckResult.fail("isolated backend lifecycle left managed state behind")
            if active.version != installed.version:
                return CheckResult.fail("isolated backend lifecycle activated the wrong version")
    except UnsupportedPlatformError as error:
        # The synthetic lifecycle has no meaningful backend asset shape on this host.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Local archive, installation, activation, verification, and removal failures are diagnostics.
        return _recovery_failure(error)
    return CheckResult.ok("install, use, verify, and uninstall succeeded in an isolated home")


def _check_install_recovery(supervision=None):
    try:
        platform_info, unused_spec, asset_platform = _recovery_platform()
        if asset_platform is None:
            return CheckResult.skip("no recovery fixture asset shape supports %s" % platform_info.key)
        with tempfile.TemporaryDirectory(prefix="jerryproxy-install-recovery-self-check-") as temporary:
            paths = JerryProxyPaths(Path(temporary) / ".jerryproxy")
            error_log = Path(temporary) / "child-error.log"
            result = _run_recovery_child(
                _install_recovery_child,
                (str(paths.root),),
                _RECOVERY_CHILD_INSTALL,
                error_log,
                supervision=supervision,
            )
            if result is not None:
                return result
            inventory = _probe_manager(paths, platform_info).inventory()
            if inventory.installed or inventory.active:
                return CheckResult.fail("hard-exit install rollback retained public backend state")
            if _recovery_artifacts(paths) or any(paths.backends.rglob(".*.install-*")):
                return CheckResult.fail("hard-exit install rollback retained recovery evidence")
    except UnsupportedPlatformError as error:
        # Install recovery requires a supported backend platform fixture.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Spawn coordination and isolated install recovery may fail operationally.
        return _recovery_failure(error)
    return CheckResult.ok("hard-exit install staging rolled back and converged")


def _prepare_activation_recovery(temporary):
    root = Path(temporary)
    platform_info, spec, asset_platform = _recovery_platform()
    if asset_platform is None:
        return platform_info, spec, None, None
    paths = JerryProxyPaths(root / ".jerryproxy")
    manager = _probe_manager(paths, platform_info)
    _install_probe_version(
        manager,
        root,
        spec,
        platform_info,
        asset_platform,
        "1.0.0",
        b"jerryproxy-recovery-previous\n",
    )
    target = _install_probe_version(
        manager,
        root,
        spec,
        platform_info,
        asset_platform,
        "2.0.0",
        b"jerryproxy-recovery-target\n",
    )
    manager.use(spec.name, "1.0.0")
    return platform_info, spec, manager, target


def _check_activation_recovery(direction, supervision=None):
    expected_exit = (
        _RECOVERY_CHILD_ACTIVATION_ROLLBACK if direction == "rollback" else _RECOVERY_CHILD_ACTIVATION_ROLLFORWARD
    )
    expected_version = "1.0.0" if direction == "rollback" else "2.0.0"
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-activation-recovery-self-check-") as temporary:
            platform_info, spec, manager, target = _prepare_activation_recovery(temporary)
            if manager is None:
                return CheckResult.skip("no recovery fixture asset shape supports %s" % platform_info.key)
            error_log = Path(temporary) / "child-error.log"
            result = _run_recovery_child(
                _activation_recovery_child,
                (str(manager.paths.root), target.version, direction),
                expected_exit,
                error_log,
                supervision=supervision,
            )
            if result is not None:
                return result
            active = manager.current(spec.name)
            if active is None or active.version != expected_version:
                return CheckResult.fail("activation %s recovery selected the wrong version" % direction)
            if active.link.read_bytes() != active.executable.read_bytes() or _recovery_artifacts(manager.paths):
                return CheckResult.fail("activation %s recovery did not converge cleanly" % direction)
    except UnsupportedPlatformError as error:
        # Activation recovery requires a supported backend platform fixture.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Isolated activation setup, hard exit, and lock-triggered recovery may fail operationally.
        return _recovery_failure(error)
    return CheckResult.ok("hard-exit activation %s converged to %s" % (direction, expected_version))


def _check_removal_recovery(direction, supervision=None):
    expected_exit = _RECOVERY_CHILD_REMOVAL_ROLLBACK if direction == "rollback" else _RECOVERY_CHILD_REMOVAL_ROLLFORWARD
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-removal-recovery-self-check-") as temporary:
            root = Path(temporary)
            platform_info, spec, asset_platform = _recovery_platform()
            if asset_platform is None:
                return CheckResult.skip("no recovery fixture asset shape supports %s" % platform_info.key)
            paths = JerryProxyPaths(root / ".jerryproxy")
            manager = _probe_manager(paths, platform_info)
            installed = _install_probe_version(
                manager,
                root,
                spec,
                platform_info,
                asset_platform,
                "1.0.0",
                b"jerryproxy-removal-recovery\n",
            )
            manager.use(spec.name, installed.version)
            error_log = root / "child-error.log"
            result = _run_recovery_child(
                _removal_recovery_child,
                (str(paths.root), installed.version, direction),
                expected_exit,
                error_log,
                supervision=supervision,
            )
            if result is not None:
                return result
            inventory = manager.inventory()
            if direction == "rollback":
                if len(inventory.installed) != 1 or len(inventory.active) != 1:
                    return CheckResult.fail("removal rollback did not restore installed and active state")
                if inventory.active[0].link.read_bytes() != inventory.active[0].executable.read_bytes():
                    return CheckResult.fail("removal rollback restored an unusable active command")
            elif inventory.installed or inventory.active:
                return CheckResult.fail("committed removal recovery did not dispose public state")
            if _recovery_artifacts(paths):
                return CheckResult.fail("removal %s recovery retained transaction evidence" % direction)
    except UnsupportedPlatformError as error:
        # Removal recovery requires a supported backend platform fixture.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Isolated removal setup, hard exit, and lock-triggered recovery may fail operationally.
        return _recovery_failure(error)
    return CheckResult.ok("hard-exit removal %s converged" % direction)


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
            if received_at - started > _RELAY_CHECK_TOTAL_TIMEOUT:
                return _relay_warning(
                    "stream exceeded the %.0f-second total timeout" % _RELAY_CHECK_TOTAL_TIMEOUT
                )
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
        try:
            if response is not None:
                response.close()
        finally:
            session.close()


def _read_child_diagnostic(path):
    try:
        with Path(path).open("rb") as stream:
            payload = stream.read(_MAXIMUM_DIAGNOSTIC_CHARACTERS + 1)
    except FileNotFoundError:
        # A child that produced no stderr or expected-error log leaves no diagnostic file.
        return ()
    except OSError as error:
        # Diagnostic read failure is secondary to the child supervision failure.
        return (
            _bounded_diagnostic("Unable to read child diagnostic: %s: %s" % (error.__class__.__name__, error)),
        )
    if not payload:
        return ()
    truncated = len(payload) > _MAXIMUM_DIAGNOSTIC_CHARACTERS
    if truncated:
        marker = "\n[diagnostic truncated]"
        text = payload[: _MAXIMUM_DIAGNOSTIC_CHARACTERS - len(marker)].decode("utf-8", errors="replace")
        text += marker
    else:
        text = payload.decode("utf-8", errors="replace")
    text = "\n".join(text.splitlines())
    return (_bounded_diagnostic(text),)


def _child_diagnostics(*paths):
    diagnostics = ()
    for path in paths:
        diagnostics += _read_child_diagnostic(path)
    return diagnostics


def _relay_probe_child(profile, result_path):
    try:
        result = _check_relay(profile, requests.Session)
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        # Malformed runtime responses and local dependency failures become diagnostic results.
        result = _error_result(error)
    diagnostics = [_bounded_diagnostic(result.diagnostics[0])] if result.diagnostics else []
    atomic_write_json(
        Path(result_path),
        {
            "level": result.level,
            "detail": _bounded_line(result.detail),
            "diagnostics": diagnostics,
        },
    )


def _relay_child_result(result_path):
    try:
        payload = read_json(Path(result_path), maximum_bytes=_MAXIMUM_CHILD_RESULT_BYTES)
    except (OSError, ValueError) as error:
        # A completed child with an unreadable result file is a diagnostic error.
        return _error_result(error)
    if (
        set(payload) != {"level", "detail", "diagnostics"}
        or payload["level"] not in ("OK", "WARN", "SKIP", "FAIL", "ERR")
        or not isinstance(payload["detail"], str)
        or not isinstance(payload["diagnostics"], list)
        or len(payload["diagnostics"]) > 1
        or any(not isinstance(item, str) for item in payload["diagnostics"])
    ):
        return CheckResult.err("relay probe child returned an invalid diagnostic result")
    return CheckResult(
        payload["level"],
        _bounded_line(payload["detail"]),
        tuple(_bounded_diagnostic(item) for item in payload["diagnostics"]),
    )


def _read_relay_child_result(result_path):
    try:
        exists = Path(result_path).is_file()
    except OSError as error:
        # Result-file observation failure is an internal probe error.
        return _error_result(error)
    return _relay_child_result(result_path) if exists else None


def _check_relay_in_process(profile, supervision=None):
    started = time.monotonic()
    deadline = started + _RELAY_CHECK_TOTAL_TIMEOUT
    start_method, context = _preferred_process_context()
    if start_method is None:
        return CheckResult.skip("no supported multiprocessing start method is available")
    with tempfile.TemporaryDirectory(prefix="jerryproxy-relay-self-check-") as temporary:
        result_path = Path(temporary) / "result.json"
        stderr_log = Path(temporary) / "stderr.log"
        try:
            start_allowed = context.Event()
            start_cancelled = context.Event()
            start_ready = context.Event()
            start_budget = context.Value("d", 0.0)
            process = context.Process(
                target=_captured_child_entry,
                args=(
                    _relay_probe_child,
                    (profile, str(result_path)),
                    str(stderr_log),
                    start_allowed,
                    start_cancelled,
                    start_ready,
                    start_budget,
                ),
                daemon=True,
            )
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # Frozen-runtime or host process policy may reject process construction.
            return CheckResult.skip(
                "%s relay probe unavailable: %s: %s"
                % (start_method, error.__class__.__name__, _bounded_line(error))
            )
        start_status, start_error = _start_process(
            process,
            start_allowed,
            start_cancelled,
            start_ready,
            start_budget,
            deadline,
            supervision=supervision,
        )
        if start_status == "timeout":
            diagnostics = ()
            if supervision is not None:
                diagnostics = ("delayed process-start cleanup will be verified by the final supervision check",)
            return CheckResult.err(
                "relay probe child startup exceeded the %.3g-second total deadline"
                % _RELAY_CHECK_TOTAL_TIMEOUT,
                diagnostics=diagnostics,
            )
        if start_status == "unavailable":
            # Frozen-runtime or host process policy may reject the selected start method.
            return CheckResult.skip(
                "%s relay probe unavailable: %s: %s"
                % (start_method, start_error.__class__.__name__, _bounded_line(start_error))
            )
        if start_status == "error":
            return CheckResult.err(
                "relay probe child startup supervision failed: %s: %s"
                % (start_error.__class__.__name__, _bounded_line(start_error))
            )
        wait_diagnostics = []
        remaining = max(_RELAY_CHECK_TOTAL_TIMEOUT - (time.monotonic() - started), 0.0)
        _join_process(process, remaining, wait_diagnostics)
        elapsed = time.monotonic() - started
        alive = _process_is_alive(process, wait_diagnostics)
        if wait_diagnostics:
            if alive:
                alive, stop_diagnostics = _stop_process(process)
                wait_diagnostics.extend(stop_diagnostics)
            wait_diagnostics.extend(_child_diagnostics(stderr_log))
            if alive:
                return CheckResult.err(
                    "timed-out relay probe child remained alive after kill",
                    diagnostics=tuple(wait_diagnostics),
                )
            return CheckResult.err(
                "relay probe child supervision failed",
                diagnostics=tuple(wait_diagnostics),
            )
        timed_out = alive or elapsed >= _RELAY_CHECK_TOTAL_TIMEOUT
        if alive:
            stop_diagnostics = ()
            alive, stop_diagnostics = _stop_process(process)
            if alive:
                return CheckResult.err(
                    "timed-out relay probe child remained alive after kill",
                    diagnostics=stop_diagnostics + _child_diagnostics(stderr_log),
                )
        child_result = _read_relay_child_result(result_path)
        if timed_out:
            if child_result is not None and child_result.level in ("FAIL", "ERR"):
                return child_result
            return _relay_warning("total probe deadline exceeded")
        if process.exitcode != 0:
            return CheckResult.err(
                "relay probe child returned exit code %s" % process.exitcode,
                diagnostics=_child_diagnostics(stderr_log),
            )
        if child_result is None:
            return CheckResult.err(
                "relay probe child exited without a diagnostic result",
                diagnostics=_child_diagnostics(stderr_log),
            )
        return child_result


def build_checks(paths, relay_session_factory=None):
    supervision = _ProcessSupervision()
    checks = (
        ("Python runtime", _check_runtime),
        ("platform detection", _check_platform),
        ("home directory layout", lambda: _check_home_layout(paths)),
        ("home write access", lambda: _check_home_writable(paths)),
        ("private directory permissions", lambda: _check_private_permissions(paths)),
        ("backend registry", _check_backend_registry),
        ("packaged backend catalog", _check_backend_catalog),
        ("catalog platform selection", _check_backend_catalog_selection),
        ("subscription parser", _check_subscription_parser),
        ("runtime projection", _check_runtime_projection),
        ("filelock compatibility", _check_filelock),
        ("backend inventory", lambda: _check_backend_inventory(paths)),
        ("isolated backend lifecycle", _check_isolated_backend_lifecycle),
        ("recovery install rollback", lambda: _check_install_recovery(supervision)),
        ("recovery activation rollback", lambda: _check_activation_recovery("rollback", supervision)),
        ("recovery activation rollforward", lambda: _check_activation_recovery("rollforward", supervision)),
        ("recovery removal rollback", lambda: _check_removal_recovery("rollback", supervision)),
        ("recovery removal rollforward", lambda: _check_removal_recovery("rollforward", supervision)),
    )
    relay_checks = tuple(
        (
            "relay %s" % profile.name,
            (
                (lambda selected=profile: _check_relay_in_process(selected, supervision))
                if relay_session_factory is None
                else (lambda selected=profile: _check_relay(selected, relay_session_factory))
            ),
        )
        for profile in iter_builtin_relays()
    )
    return checks + relay_checks + (
        (
            "delayed process cleanup",
            lambda: _check_process_supervision(supervision),
        ),
    )


def run_checks(checks, output, color=False):
    counts = {"OK": 0, "WARN": 0, "SKIP": 0, "FAIL": 0, "ERR": 0}
    colors = {
        "OK": _ANSI_GREEN,
        "WARN": _ANSI_YELLOW,
        "SKIP": _ANSI_CYAN,
        "FAIL": _ANSI_RED,
        "ERR": _ANSI_RED,
    }
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
                _bounded_line(result.detail),
            )
        )
        for diagnostic in result.diagnostics:
            for line in _bounded_diagnostic(diagnostic).splitlines():
                output("    %s" % _paint(line, colors[result.level], color))

    output(
        "%s: %s, %s, %s, %s, %s"
        % (
            _paint("Summary", _ANSI_BOLD, color),
            _paint("%d OK" % counts["OK"], _ANSI_GREEN, color),
            _paint("%d WARN" % counts["WARN"], _ANSI_YELLOW, color),
            _paint("%d SKIP" % counts["SKIP"], _ANSI_CYAN, color),
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
    if counts["SKIP"]:
        output(_paint("Self-check PASSED with skips", _ANSI_CYAN, color))
        return 0
    output(_paint("Self-check PASSED", _ANSI_GREEN, color))
    return 0


def run_self_check(paths, output=print, color=False, relay_session_factory=None):
    output(_paint("JerryProxy self-check %s" % __VERSION__, _ANSI_CYAN, color))
    output(
        "%s: Python %s %s; JerryProxy %s; frozen=%s"
        % (
            _paint("Runtime", _ANSI_BOLD, color),
            platform.python_implementation(),
            platform.python_version(),
            __VERSION__,
            str(bool(getattr(sys, "frozen", False))).lower(),
        )
    )
    output(
        "%s: %s %s; machine=%s; os.name=%s"
        % (
            _paint("System", _ANSI_BOLD, color),
            platform.system() or "unknown",
            platform.release() or "unknown",
            platform.machine() or "unknown",
            os.name,
        )
    )
    output("%s: %s" % (_paint("Home", _ANSI_BOLD, color), paths.root))
    return run_checks(
        build_checks(paths, relay_session_factory=relay_session_factory),
        output,
        color=color,
    )
