"""Strict static validation for installed and active backend state."""

import os
import re
import stat
import unicodedata
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlparse

from ..errors import ArchiveError, IntegrityError, UnsupportedBackendError
from ..home import is_path_alias
from ..utils.fs import read_json_stream
from .anchored import AnchoredDirectory
from .identity import identity_matches
from .model import ActiveBackend, InstalledBackend
from .registry import get_backend, iter_backend_platforms

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$"
)
_INSTALLED_KEYS = {
    "name",
    "version",
    "platform",
    "asset_name",
    "sha256",
    "executable_sha256",
    "source_url",
    "catalog_generated_at",
    "executable",
    "installed_at",
}
_ACTIVE_KEYS = {"name", "version", "executable", "link", "activated_at", "link_mode"}


def _read_state(path, label):
    path = Path(path)
    try:
        aliased = is_path_alias(path)
    except OSError as error:
        # Alias inspection is part of the managed-state authority boundary.
        raise IntegrityError("invalid %s: %s" % (label, path)) from error
    if aliased:
        raise IntegrityError("invalid %s: managed state path is aliased: %s" % (label, path))
    try:
        status = path.lstat()
    except OSError as error:
        # A required managed state file may disappear or become unreadable after enumeration.
        raise IntegrityError("invalid %s: %s" % (label, path)) from error
    if not stat.S_ISREG(status.st_mode):
        raise IntegrityError("invalid %s: managed state is not a regular file: %s" % (label, path))
    if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
        raise IntegrityError("invalid %s: unsafe permissions on %s" % (label, path))
    try:
        with AnchoredDirectory(path.parent) as parent:
            stream, identity = parent.open_existing_file((path.name,))
            with stream:
                before = os.fstat(stream.fileno())
                if os.name == "posix" and stat.S_IMODE(before.st_mode) != 0o600:
                    raise IntegrityError("invalid %s: unsafe permissions on %s" % (label, path))
                value = read_json_stream(stream, path)
                after = os.fstat(stream.fileno())
                before_snapshot = (
                    before.st_dev,
                    before.st_ino,
                    stat.S_IFMT(before.st_mode),
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                after_snapshot = (
                    after.st_dev,
                    after.st_ino,
                    stat.S_IFMT(after.st_mode),
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                parent.assert_bound()
                if before_snapshot != after_snapshot or not identity_matches(path, identity):
                    raise IntegrityError("managed state changed while being read: %s" % path)
            return value
    except (ArchiveError, OSError, ValueError, IntegrityError) as error:
        # Fixed-handle JSON decoding and binding checks define the managed-state authority boundary.
        raise IntegrityError("invalid %s: %s" % (label, path)) from error


def _nonempty_string(value, field, maximum_bytes):
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum_bytes
        or unicodedata.normalize("NFC", value) != value
    ):
        raise IntegrityError("invalid managed state %s" % field)
    return value


def _digest(value, field):
    if not isinstance(value, str) or _DIGEST_PATTERN.match(value) is None:
        raise IntegrityError("invalid managed state %s" % field)
    return value


def _timestamp(value, field):
    value = _nonempty_string(value, field, 32)
    if value.isascii() is False or _TIMESTAMP_PATTERN.match(value) is None:
        raise IntegrityError("invalid managed state %s" % field)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        # datetime validates calendar and clock fields after the strict lexical check.
        raise IntegrityError("invalid managed state %s" % field) from error
    return value


def _safe_leaf(value, field, maximum_bytes=255):
    value = _nonempty_string(value, field, maximum_bytes)
    if value in (".", "..") or "/" in value or "\\" in value:
        raise IntegrityError("invalid managed state %s" % field)
    return value


def _relative_parts(value, field):
    value = _nonempty_string(value, field, 1024)
    if "\\" in value or value.startswith("/"):
        raise IntegrityError("invalid managed state %s" % field)
    raw_parts = value.split("/")
    windows = PureWindowsPath(value)
    if (
        not raw_parts
        or any(part in ("", ".", "..") for part in raw_parts)
        or PurePosixPath(value).is_absolute()
        or windows.is_absolute()
        or windows.drive
    ):
        raise IntegrityError("invalid managed state %s" % field)
    return tuple(raw_parts)


def _source_url(value):
    if value is None:
        return None
    value = _nonempty_string(value, "source URL", 2048)
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise IntegrityError("invalid managed state source URL")
    return value


def _validate_chain(root, target, label):
    root = Path(root)
    current = Path(target)
    while True:
        try:
            aliased = is_path_alias(current)
        except OSError as error:
            # Every ancestor must remain inspectable while validating containment.
            raise IntegrityError("invalid %s: unable to inspect managed path: %s" % (label, current)) from error
        if aliased:
            raise IntegrityError("invalid %s: managed path is aliased: %s" % (label, current))
        if current == root:
            return
        if current.parent == current:
            raise IntegrityError("invalid %s: managed path escapes its root: %s" % (label, target))
        current = current.parent


def _validate_installed_manifest_value(
    paths,
    manifest,
    value,
    expected_manifest=None,
):
    manifest = Path(manifest)
    try:
        try:
            manifest.absolute().relative_to(paths.backends.absolute())
        except ValueError as error:
            raise IntegrityError("invalid managed state containing path") from error
        if set(value) != _INSTALLED_KEYS:
            raise IntegrityError("invalid managed state keys")
        name = _nonempty_string(value["name"], "backend name", 64)
        spec = get_backend(name)
        version = _nonempty_string(value["version"], "backend version", 128)
        normalized_version = spec.normalize_version(version)
        if version != normalized_version:
            raise IntegrityError("invalid managed state backend version")
        canonical_manifest = paths.backends / spec.name / version / "manifest.json"
        required_manifest = canonical_manifest if expected_manifest is None else Path(expected_manifest)
        if required_manifest.absolute() != canonical_manifest.absolute():
            raise IntegrityError("invalid managed state containing path")
        if expected_manifest is None and manifest.absolute() != canonical_manifest.absolute():
            raise IntegrityError("invalid managed state containing path")
        platform = _nonempty_string(value["platform"], "platform", 128)
        if platform not in {item.asset_key for item in iter_backend_platforms(spec.name)}:
            raise IntegrityError("invalid managed state platform")
        asset_name = _safe_leaf(value["asset_name"], "asset name")
        archive_digest = _digest(value["sha256"], "sha256")
        executable_digest = _digest(value["executable_sha256"], "executable sha256")
        _source_url(value["source_url"])
        _timestamp(value["catalog_generated_at"], "catalog timestamp")
        _timestamp(value["installed_at"], "installed timestamp")
        executable_parts = _relative_parts(value["executable"], "executable path")
        executable = manifest.parent.joinpath(*executable_parts)
    except (KeyError, OSError, UnsupportedBackendError, ValueError, IntegrityError) as error:
        # Exact schema, registry normalization, and no-follow filesystem validation share one domain boundary.
        raise IntegrityError("invalid installed backend manifest: %s" % manifest) from error
    return InstalledBackend(
        name=spec.name,
        version=version,
        executable=executable,
        manifest=manifest,
        asset_name=asset_name,
        sha256=archive_digest,
        platform=platform,
        executable_sha256=executable_digest,
    )


def _load_installed_manifest(paths, manifest, expected_manifest=None):
    manifest = Path(manifest)
    label = "installed backend manifest"
    _validate_chain(paths.backends, manifest, label)
    try:
        manifest_status = manifest.lstat()
    except OSError as error:
        # Required installed state may disappear after its containing chain is validated.
        raise IntegrityError("invalid installed backend manifest: %s" % manifest) from error
    if not stat.S_ISREG(manifest_status.st_mode):
        raise IntegrityError("invalid installed backend manifest: managed state is not a regular file: %s" % manifest)
    if os.name == "posix" and stat.S_IMODE(manifest_status.st_mode) != 0o600:
        raise IntegrityError("invalid installed backend manifest: unsafe permissions on %s" % manifest)
    try:
        with AnchoredDirectory(manifest.parent) as version_tree:
            value, unused_manifest_identity = version_tree.read_json((manifest.name,))
            installed = _validate_installed_manifest_value(
                paths,
                manifest,
                value,
                expected_manifest=expected_manifest,
            )
            executable_parts = installed.executable.relative_to(manifest.parent).parts
            executable_size, executable_digest, executable_identity = version_tree.file_evidence(
                executable_parts
            )
            version_tree.assert_bound()
        if executable_digest != installed.executable_sha256:
            raise IntegrityError(
                "%s %s executable SHA-256 mismatch: expected %s, got %s"
                % (
                    installed.name,
                    installed.version,
                    installed.executable_sha256,
                    executable_digest,
                )
            )
    except (ArchiveError, OSError, ValueError, IntegrityError) as error:
        # Manifest and executable evidence must come from one pinned immutable version tree.
        raise IntegrityError(
            "invalid installed backend manifest: %s: %s" % (manifest, error)
        ) from error
    return installed, executable_size, executable_digest, executable_identity


def load_installed_manifest(paths, manifest):
    # type: (JerryProxyPaths, Path) -> InstalledBackend
    """Load one exact immutable installed-backend manifest."""

    installed, unused_size, unused_digest, unused_identity = _load_installed_manifest(paths, manifest)
    return installed


def load_installed_manifest_evidence(paths, manifest):
    # type: (JerryProxyPaths, Path) -> tuple
    """Load one installation and return fixed-handle executable evidence."""

    return _load_installed_manifest(paths, manifest)


def load_staged_installed_manifest(paths, manifest, expected_manifest):
    # type: (JerryProxyPaths, Path, Path) -> InstalledBackend
    """Validate a private staged manifest against its canonical final identity."""

    installed, unused_size, unused_digest, unused_identity = _load_installed_manifest(
        paths,
        manifest,
        expected_manifest=expected_manifest,
    )
    return installed


def validate_staged_installed_manifest_value(paths, manifest, expected_manifest, value):
    # type: (JerryProxyPaths, Path, Path, dict) -> InstalledBackend
    """Validate an anchored staged manifest value without reopening its path."""

    return _validate_installed_manifest_value(
        paths,
        manifest,
        value,
        expected_manifest=expected_manifest,
    )


def load_active_state(paths, name, platform_info):
    # type: (JerryProxyPaths, str, PlatformInfo) -> Optional[Tuple[ActiveBackend, dict]]
    """Load one exact active pair, rejecting one-sided or malformed state."""

    spec = get_backend(name)
    manifest = paths.active / ("%s.json" % spec.name)
    link = paths.bin / spec.executable_filename(platform_info)
    manifest_exists = os.path.lexists(str(manifest))
    link_exists = os.path.lexists(str(link))
    if not manifest_exists and not link_exists:
        return None
    if manifest_exists != link_exists:
        raise IntegrityError("active backend state is incomplete: %s" % spec.name)
    value = _read_state(manifest, "active backend manifest")
    try:
        if set(value) != _ACTIVE_KEYS:
            raise IntegrityError("invalid managed state keys")
        if value["name"] != spec.name:
            raise IntegrityError("invalid managed state backend name")
        version = _nonempty_string(value["version"], "backend version", 128)
        if spec.normalize_version(version) != version:
            raise IntegrityError("invalid managed state backend version")
        _timestamp(value["activated_at"], "activated timestamp")
        link_mode = value["link_mode"]
        if link_mode not in ("symlink", "copy"):
            raise IntegrityError("invalid managed state link mode")
        executable_parts = _relative_parts(value["executable"], "active executable path")
        link_parts = _relative_parts(value["link"], "active link path")
        executable = paths.root.joinpath(*executable_parts)
        recorded_link = paths.root.joinpath(*link_parts)
        installed, installed_size, installed_digest, unused_installed_identity = load_installed_manifest_evidence(
            paths,
            paths.backends / spec.name / version / "manifest.json",
        )
        if executable != installed.executable or recorded_link != link:
            raise IntegrityError("invalid managed state active paths")
        if link_mode == "symlink":
            expected_target = os.path.relpath(str(installed.executable), str(link.parent))
            with AnchoredDirectory(paths.bin) as active_bin:
                actual_target, unused_link_identity = active_bin.read_symlink((link.name,))
            if actual_target != expected_target:
                raise IntegrityError("invalid managed state active symlink")
        else:
            with AnchoredDirectory(paths.bin) as active_bin:
                link_size, link_digest, unused_link_identity = active_bin.file_evidence(
                    (link.name,)
                )
            if link_size != installed_size:
                raise IntegrityError("invalid managed state active copy size")
            if link_digest != installed_digest:
                raise IntegrityError("invalid managed state active copy digest")
    except (ArchiveError, KeyError, OSError, ValueError, IntegrityError) as error:
        # Active payload, immutable source, and public link form one strict state object.
        raise IntegrityError(
            "invalid active backend manifest: %s: %s" % (manifest, error)
        ) from error
    return (
        ActiveBackend(
            name=spec.name,
            version=version,
            executable=installed.executable,
            link=link,
            link_mode=link_mode,
        ),
        value,
    )
