"""Strict activation journals and deterministic crash-recovery planning."""

import errno
import hashlib
import json
import os
import re
import secrets
import stat
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

from ..errors import ArchiveError, DurabilityError, IntegrityError, UnsupportedBackendError
from ..home import is_path_alias
from ..utils.fs import MAXIMUM_JSON_BYTES
from .anchored import AnchoredDirectory
from .durable import durable_replace as _filesystem_durable_replace
from .durable import flush_descriptor, flush_directory
from .identity import capture_identity, identity_matches, validate_identity
from .registry import get_backend
from .removal import _secure_remove_tree
from .state import load_active_state, load_installed_manifest_evidence

_OPERATION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_JOURNAL_PATTERN = re.compile(r"^\.use-([0-9a-f]{32})\.json$")
_TEMPORARY_PATTERN = re.compile(r"^\.use-([0-9a-f]{32})\.json\.tmp-([0-9a-f]{32})$")
_LINK_CANDIDATE_PATTERN = re.compile(r"^\.(.+)\.use-([0-9a-f]{32})\.candidate$")
_MANIFEST_CANDIDATE_PATTERN = re.compile(r"^\.(.+)\.use-([0-9a-f]{32})\.candidate\.json$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$")

PRECOMMIT_PHASES = frozenset(
    (
        "prepared",
        "link-building",
        "link-ready",
        "manifest-building",
        "candidates-ready",
        "link-published",
        "manifest-published",
    )
)
PHASES = PRECOMMIT_PHASES | frozenset(("committed",))
RECOVERY_DIRECTIONS = frozenset(("rollback-previous", "rollback-absent", "rollforward-target"))
_PURPOSES = frozenset(("target", "recovery-previous", "recovery-target"))
_CANDIDATE_STATES = frozenset(("absent", "building", "ready", "published", "discarding"))
_COPY_CHUNK_SIZE = 1024 * 1024
_LOGICAL_KEYS = {
    "version",
    "executable",
    "executable_size",
    "executable_sha256",
    "link_mode",
    "manifest_payload",
}
_MANIFEST_KEYS = {"name", "version", "executable", "link", "activated_at", "link_mode"}
_CANDIDATE_KEYS = {
    "path",
    "purpose",
    "state",
    "identity",
    "size",
    "sha256",
    "target",
    "displaced_identity",
    "displaced_purpose",
}
_TOP_LEVEL_KEYS = {
    "kind",
    "operation",
    "phase",
    "backend",
    "link",
    "manifest",
    "previous",
    "target",
    "candidates",
    "recovery",
}
_WINDOWS_SYMLINK_FALLBACK_WINERRORS = frozenset((1, 50, 1314))
_WINDOWS_SYMLINK_FALLBACK_ERRNOS = frozenset(
    (
        errno.EPERM,
        getattr(errno, "ENOSYS", -1),
        getattr(errno, "ENOTSUP", -1),
        getattr(errno, "EOPNOTSUPP", -1),
    )
)


def _windows_symlink_fallback_allowed(error):
    if os.name != "nt":
        return False
    if isinstance(error, NotImplementedError):
        return True
    winerror = getattr(error, "winerror", None)
    if winerror is not None:
        return winerror in _WINDOWS_SYMLINK_FALLBACK_WINERRORS
    return getattr(error, "errno", None) in _WINDOWS_SYMLINK_FALLBACK_ERRNOS


@dataclass(frozen=True)
class ActivationClassification:
    """Physical public and candidate classifications for one use journal."""

    link: str
    manifest: str
    link_candidate: str
    manifest_candidate: str
    link_evidence: dict = None
    manifest_evidence: dict = None
    link_candidate_evidence: dict = None
    manifest_candidate_evidence: dict = None


@dataclass(frozen=True)
class ActivationRecoveryPlan:
    """One durable, idempotent recovery transition selected by journal phase."""

    journal: dict
    direction: str
    action: str
    object_name: str = None
    precondition: dict = None


@dataclass(frozen=True)
class ActivationRecord:
    """One validated authoritative record for global conflict preflight."""

    kind: str
    operation: str
    journal_path: Path
    read_paths: tuple
    write_paths: tuple
    state: dict
    journal_identity: dict
    temporaries: tuple = ()


def _fail(message):
    raise IntegrityError("invalid activation journal: %s" % message)


def _exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        _fail("invalid %s keys" % label)


def _bounded_string(value, label, maximum):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        _fail("invalid %s" % label)
    return value


def _relative_path(value, label):
    value = _bounded_string(value, label, 1024)
    windows = PureWindowsPath(value)
    parts = value.split("/")
    if (
        "\\" in value
        or value.startswith("/")
        or not parts
        or any(part in ("", ".", "..") for part in parts)
        or PurePosixPath(value).is_absolute()
        or windows.is_absolute()
        or windows.drive
    ):
        _fail("invalid %s" % label)
    return value


def _digest(value, label):
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        _fail("invalid %s" % label)
    return value


def _size(value, label):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail("invalid %s" % label)
    return value


def _timestamp(value):
    value = _bounded_string(value, "activation timestamp", 32)
    if not value.isascii() or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        _fail("invalid activation timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        # datetime validates calendar fields after the exact lexical check.
        raise IntegrityError("invalid activation journal: invalid activation timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _fail("invalid activation timestamp")
    return value


def _canonical_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _logical_state(paths, backend, link, value, allow_incomplete, label):
    _exact_keys(value, _LOGICAL_KEYS, label)
    spec = get_backend(backend)
    version = _bounded_string(value["version"], "%s version" % label, 128)
    try:
        if spec.normalize_version(version) != version:
            _fail("noncanonical %s version" % label)
    except ValueError as error:
        raise IntegrityError("invalid activation journal: invalid %s version" % label) from error
    executable = _relative_path(value["executable"], "%s executable" % label)
    executable_size = _size(value["executable_size"], "%s executable size" % label)
    executable_sha256 = _digest(value["executable_sha256"], "%s executable digest" % label)
    try:
        installed, actual_size, actual_digest, unused_identity = load_installed_manifest_evidence(
            paths,
            paths.backends / backend / version / "manifest.json",
        )
    except (OSError, IntegrityError) as error:
        # Immutable installation evidence can become unreadable or invalid after journal publication.
        raise IntegrityError("invalid activation journal: unreadable immutable executable") from error
    expected_executable = str(PurePosixPath(*installed.executable.relative_to(paths.root).parts))
    if executable != expected_executable:
        _fail("%s executable does not match immutable installation" % label)
    if executable_size != actual_size or executable_sha256 != actual_digest:
        _fail("%s executable evidence does not match immutable installation" % label)

    mode = value["link_mode"]
    payload = value["manifest_payload"]
    if allow_incomplete and mode is None and payload is None:
        return
    if mode not in ("symlink", "copy"):
        _fail("invalid %s link mode" % label)
    _exact_keys(payload, _MANIFEST_KEYS, "%s manifest payload" % label)
    if (
        payload["name"] != backend
        or payload["version"] != version
        or payload["executable"] != executable
        or payload["link"] != link
        or payload["link_mode"] != mode
    ):
        _fail("%s manifest payload does not match its logical state" % label)
    _timestamp(payload["activated_at"])


def _candidate(value, expected_path, recovery, phase, name, desired):
    _exact_keys(value, _CANDIDATE_KEYS, "%s candidate" % name)
    if _relative_path(value["path"], "%s candidate path" % name) != expected_path:
        _fail("incorrect %s candidate path" % name)
    purpose = value["purpose"]
    state = value["state"]
    if purpose not in _PURPOSES or state not in _CANDIDATE_STATES:
        _fail("invalid %s candidate purpose or state" % name)
    identity = value["identity"]
    size = value["size"]
    digest = value["sha256"]
    target = value["target"]
    displaced_identity = value["displaced_identity"]
    displaced_purpose = value["displaced_purpose"]
    if (displaced_identity is None) != (displaced_purpose is None):
        _fail("incomplete %s displaced candidate evidence" % name)
    if displaced_identity is not None:
        if state != "ready" or displaced_purpose not in ("previous", "target"):
            _fail("invalid %s displaced candidate evidence" % name)
        validate_identity(displaced_identity)
    if state == "absent":
        if any(
            item is not None
            for item in (identity, size, digest, target, displaced_identity, displaced_purpose)
        ):
            _fail("absent %s candidate retains evidence" % name)
    elif state == "building":
        if any(item is not None for item in (size, digest, target, displaced_identity, displaced_purpose)):
            _fail("building %s candidate has ready evidence" % name)
        if identity is not None:
            validate_identity(identity, expected_file_type="regular")
    else:
        if identity is None:
            _fail("%s %s candidate has no identity" % (state, name))
        validate_identity(identity)
        file_type = identity["file_type"]
        if file_type == "regular":
            if state == "discarding" and size is None and digest is None:
                pass
            else:
                _size(size, "%s candidate size" % name)
                _digest(digest, "%s candidate digest" % name)
            if target is not None:
                _fail("regular %s candidate has a symlink target" % name)
        elif file_type == "symlink":
            if size is not None or digest is not None:
                _fail("symlink %s candidate has regular-file evidence" % name)
            _bounded_string(target, "%s candidate symlink target" % name, 1024)
        else:
            _fail("candidate cannot be a directory")
        if state in ("ready", "published") or (state == "discarding" and (file_type == "symlink" or size is not None)):
            if desired is None:
                _fail("candidate purpose has no logical state")
            if name == "link":
                if desired["link_mode"] == "copy":
                    if (
                        file_type != "regular"
                        or size != desired["executable_size"]
                        or digest != desired["executable_sha256"]
                    ):
                        _fail("link candidate evidence does not match its purpose")
                else:
                    expected_target = os.path.relpath(desired["executable"], "bin")
                    if file_type != "symlink" or target != expected_target:
                        _fail("link candidate evidence does not match its purpose")
            else:
                payload = _canonical_bytes(desired["manifest_payload"])
                if file_type != "regular" or size != len(payload) or digest != hashlib.sha256(payload).hexdigest():
                    _fail("manifest candidate evidence does not match its purpose")

    if recovery is None:
        if purpose != "target":
            _fail("normal candidate has a recovery purpose")
        if state == "building" and phase not in ("link-building", "manifest-building"):
            _fail("building candidate is illegal in this normal phase")
    else:
        expected_purpose = {
            "rollback-previous": "recovery-previous",
            "rollforward-target": "recovery-target",
        }.get(recovery["direction"])
        if state != "discarding" and purpose != "target" and purpose != expected_purpose:
            _fail("candidate purpose disagrees with recovery direction")


def _validate_normal_phase(value):
    phase = value["phase"]
    target = value["target"]
    link_state = value["candidates"]["link"]["state"]
    manifest_state = value["candidates"]["manifest"]["state"]
    if phase == "prepared":
        expected = ("absent", "absent")
        if target["link_mode"] is not None or target["manifest_payload"] is not None:
            _fail("prepared target must be incomplete")
    else:
        if target["link_mode"] is None or target["manifest_payload"] is None:
            _fail("target must be complete after prepared")
        expected = {
            "link-building": ("building", "absent"),
            "link-ready": ("ready", "absent"),
            "manifest-building": ("ready", "building"),
            "candidates-ready": ("ready", "ready"),
            "link-published": ("published", "ready"),
            "manifest-published": ("published", "published"),
        }.get(phase)
        if phase == "committed":
            if link_state not in ("published", "discarding", "absent") or manifest_state not in (
                "published",
                "discarding",
                "absent",
            ):
                _fail("invalid committed candidate state")
            return
    if (link_state, manifest_state) != expected:
        _fail("candidate states disagree with normal phase")


def _validate_recovery_phase(value):
    phase = value["phase"]
    expected = {
        "prepared": ("absent", "absent"),
        "link-building": ("building", "absent"),
        "link-ready": ("ready", "absent"),
        "manifest-building": ("ready", "building"),
        "candidates-ready": ("ready", "ready"),
        "link-published": ("published", "ready"),
        "manifest-published": ("published", "published"),
        "committed": ("published", "published"),
    }[phase]
    for name, original_state in zip(("link", "manifest"), expected):
        candidate = value["candidates"][name]
        if candidate["purpose"] != "target":
            continue
        allowed = {original_state, "discarding", "absent"}
        if candidate["state"] not in allowed:
            _fail("candidate states disagree with original phase")


def recovery_direction(journal):
    # type: (dict) -> str
    """Return the only recovery direction authorized by the commit phase."""

    if journal["phase"] == "committed":
        return "rollforward-target"
    return "rollback-absent" if journal["previous"] is None else "rollback-previous"


def _load_use_journal(paths, journal, platform_info, expected_identity=None):
    journal = Path(journal)
    match = _JOURNAL_PATTERN.fullmatch(journal.name)
    if match is None or journal.parent.absolute() != paths.runtimes.absolute():
        _fail("invalid authoritative filename")
    if is_path_alias(journal):
        _fail("authoritative journal is aliased")
    try:
        status = journal.lstat()
        if not stat.S_ISREG(status.st_mode):
            _fail("authoritative journal is not regular")
        if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
            _fail("unsafe authoritative journal permissions")
        with AnchoredDirectory(paths.runtimes) as runtimes:
            value, journal_identity = runtimes.read_json(
                (journal.name,),
                expected_identity=expected_identity,
            )
    except (ArchiveError, OSError, ValueError) as error:
        # Bounded strict JSON and filesystem inspection define the journal input boundary.
        raise IntegrityError("invalid activation journal: unreadable authoritative record") from error
    _exact_keys(value, _TOP_LEVEL_KEYS, "top-level")
    operation = value["operation"]
    if value["kind"] != "use" or not isinstance(operation, str) or _OPERATION_PATTERN.fullmatch(operation) is None:
        _fail("invalid kind or operation")
    if operation != match.group(1):
        _fail("operation does not match filename")
    phase = value["phase"]
    if phase not in PHASES:
        _fail("invalid phase")
    backend = _bounded_string(value["backend"], "backend", 64)
    try:
        spec = get_backend(backend)
    except UnsupportedBackendError as error:
        raise IntegrityError("invalid activation journal: unsupported backend") from error
    if spec.name != backend:
        _fail("noncanonical backend")
    link = "bin/%s" % spec.executable_filename(platform_info)
    manifest = "active/%s.json" % backend
    if value["link"] != link or value["manifest"] != manifest:
        _fail("incorrect public paths")
    expected_link_candidate = "bin/.%s.use-%s.candidate" % (Path(link).name, operation)
    expected_manifest_candidate = "active/.%s.use-%s.candidate.json" % (backend, operation)
    _exact_keys(value["candidates"], {"link", "manifest"}, "candidates")

    recovery = value["recovery"]
    if recovery is not None:
        _exact_keys(recovery, {"direction"}, "recovery")
        if recovery["direction"] not in RECOVERY_DIRECTIONS:
            _fail("invalid recovery direction")
    _logical_state(paths, backend, link, value["target"], phase == "prepared", "target")
    if value["previous"] is not None:
        _logical_state(paths, backend, link, value["previous"], False, "previous")
    for name, expected in (("link", expected_link_candidate), ("manifest", expected_manifest_candidate)):
        candidate = value["candidates"][name]
        desired = value["target"]
        if candidate.get("purpose") == "recovery-previous":
            desired = value["previous"]
        _candidate(candidate, expected, recovery, phase, name, desired)
        if candidate["displaced_purpose"] == "previous" and value["previous"] is None:
            _fail("%s displaced candidate has no previous logical state" % name)
        displaced_logical = (
            value["previous"] if candidate["displaced_purpose"] == "previous" else value["target"]
        )
        if candidate["displaced_identity"] is not None:
            expected_type = "regular"
            if name == "link" and displaced_logical["link_mode"] == "symlink":
                expected_type = "symlink"
            if candidate["displaced_identity"]["file_type"] != expected_type:
                _fail("%s displaced candidate type disagrees with its logical state" % name)
    if recovery is None:
        _validate_normal_phase(value)
    elif recovery["direction"] != recovery_direction(value):
        _fail("persisted recovery direction disagrees with commit phase")
    else:
        _validate_recovery_phase(value)
    return value, journal_identity


def load_use_journal(paths, journal, platform_info):
    # type: (JerryProxyPaths, Path, PlatformInfo) -> dict
    """Strictly load and validate one authoritative activation journal."""

    value, unused_identity = _load_use_journal(paths, journal, platform_info)
    return value


def _record_paths(paths, value, temporaries=()):
    read_paths = {value["link"], value["manifest"]}
    write_paths = {
        "runtimes/.use-%s.json" % value["operation"],
        value["link"],
        value["manifest"],
        value["candidates"]["link"]["path"],
        value["candidates"]["manifest"]["path"],
    }
    for logical in (value["previous"], value["target"]):
        if logical is None:
            continue
        read_paths.add(logical["executable"])
        read_paths.add("backends/%s/%s/manifest.json" % (value["backend"], logical["version"]))
    write_paths.update(str(PurePosixPath(*path.relative_to(paths.root).parts)) for path, unused_identity in temporaries)
    return tuple(sorted(read_paths)), tuple(sorted(write_paths))


def _validate_writer_temporary(path):
    if is_path_alias(path):
        raise IntegrityError("invalid activation recovery writer temporary alias: %s" % path)
    try:
        status = path.lstat()
    except OSError as error:
        # Enumerated writer evidence must remain inspectable through preflight.
        raise IntegrityError("unable to inspect activation recovery writer temporary: %s" % path) from error
    if not stat.S_ISREG(status.st_mode) or status.st_size > MAXIMUM_JSON_BYTES:
        raise IntegrityError("invalid activation recovery writer temporary: %s" % path)
    if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
        raise IntegrityError("unsafe activation recovery writer temporary permissions: %s" % path)
    return capture_identity(path)


def _scan_candidate_namespace(area, pattern):
    owned = {}
    try:
        entries = sorted(area.iterdir(), key=lambda item: item.name)
    except OSError as error:
        # Candidate namespaces must be enumerated completely before recovery mutates state.
        raise IntegrityError("unable to enumerate activation recovery candidates: %s" % area) from error
    for entry in entries:
        if ".use-" not in entry.name:
            continue
        match = pattern.fullmatch(entry.name)
        if match is None:
            raise IntegrityError("invalid activation recovery candidate entry: %s" % entry)
        owned.setdefault(match.group(2), []).append(entry)
    return owned


def _scan_use_recovery(paths, platform_info):
    journals = {}
    temporaries = {}
    try:
        entries = sorted(paths.runtimes.iterdir(), key=lambda item: item.name)
    except OSError as error:
        # Runtime enumeration must complete before the coordinator permits mutation.
        raise IntegrityError("unable to enumerate activation journals") from error
    for entry in entries:
        if not entry.name.startswith(".use-"):
            continue
        journal_match = _JOURNAL_PATTERN.fullmatch(entry.name)
        temporary_match = _TEMPORARY_PATTERN.fullmatch(entry.name)
        if journal_match is not None:
            operation = journal_match.group(1)
            if operation in journals:
                raise IntegrityError("duplicate activation recovery operation: %s" % operation)
            journals[operation] = entry
        elif temporary_match is not None:
            operation = temporary_match.group(1)
            identity = _validate_writer_temporary(entry)
            temporaries.setdefault(operation, []).append((entry, identity))
        else:
            raise IntegrityError("invalid activation recovery runtime entry: %s" % entry)

    link_candidates = _scan_candidate_namespace(paths.bin, _LINK_CANDIDATE_PATTERN)
    manifest_candidates = _scan_candidate_namespace(paths.active, _MANIFEST_CANDIDATE_PATTERN)
    records = []
    for operation in sorted(journals):
        journal = journals[operation]
        state, journal_identity = _load_use_journal(paths, journal, platform_info)
        if not identity_matches(journal, journal_identity):
            raise IntegrityError("activation recovery journal changed during preflight: %s" % journal)
        expected = {
            paths.root / state["candidates"]["link"]["path"],
            paths.root / state["candidates"]["manifest"]["path"],
        }
        actual = set(link_candidates.get(operation, ())) | set(manifest_candidates.get(operation, ()))
        unexpected = actual.difference(expected)
        if unexpected:
            raise IntegrityError("unexpected activation recovery candidate: %s" % sorted(unexpected)[0])
        operation_temporaries = tuple(sorted(temporaries.get(operation, ()), key=lambda item: item[0]))
        read_paths, write_paths = _record_paths(paths, state, operation_temporaries)
        records.append(
            ActivationRecord(
                kind="use",
                operation=state["operation"],
                journal_path=journal,
                read_paths=read_paths,
                write_paths=write_paths,
                state=state,
                journal_identity=journal_identity,
                temporaries=operation_temporaries,
            )
        )
    owned_operations = set(link_candidates) | set(manifest_candidates)
    missing_authority = owned_operations.difference(journals)
    if missing_authority:
        operation = sorted(missing_authority)[0]
        raise IntegrityError("activation recovery candidate exists without authority: %s" % operation)
    orphan_temporaries = []
    for operation, items in temporaries.items():
        if operation in journals:
            continue
        if operation in owned_operations:
            raise IntegrityError("activation recovery writer temporary has owned candidate without authority")
        orphan_temporaries.extend(items)
    return tuple(records), tuple(sorted(orphan_temporaries, key=lambda item: item[0]))


def discover_use_journals(paths, platform_info):
    # type: (JerryProxyPaths, PlatformInfo) -> tuple
    """Discover and strictly parse authoritative use records without mutation."""

    records, unused_orphans = _scan_use_recovery(paths, platform_info)
    return records


def _matches_link(path, state, evidence):
    if state is None or evidence is None:
        return False
    if state["link_mode"] == "symlink":
        expected = os.path.relpath(
            str(path.parents[1] / state["executable"]),
            str(path.parent),
        )
        return evidence == ("symlink", expected)
    return evidence == (
        "regular",
        state["executable_size"],
        state["executable_sha256"],
    )


def _read_link_evidence(path):
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode):
        return "symlink", os.readlink(str(path))
    if not stat.S_ISREG(status.st_mode):
        return None
    with AnchoredDirectory(path.parent) as parent:
        size, digest, unused_identity = parent.file_evidence((path.name,))
    return "regular", size, digest


def classify_public_link(paths, journal):
    # type: (JerryProxyPaths, dict) -> str
    """Classify the physical active command as P, T, B, M, or U."""

    path = paths.root / journal["link"]
    if not os.path.lexists(str(path)):
        return "M"
    try:
        evidence = _read_link_evidence(path)
    except (ArchiveError, OSError, IntegrityError):
        # Inaccessible or racing public objects are unknown, never absent.
        return "U"
    previous = _matches_link(path, journal["previous"], evidence)
    target = _matches_link(path, journal["target"], evidence)
    if previous and target:
        return "B"
    if previous:
        return "P"
    if target:
        return "T"
    return "U"


def _read_manifest_classification(path):
    if is_path_alias(path):
        return None
    try:
        with AnchoredDirectory(Path(path).parent) as parent:
            value, unused_identity = parent.read_json((Path(path).name,))
        return value
    except (ArchiveError, OSError, ValueError, IntegrityError):
        # Malformed or racing public state is unknown, never absent.
        return None


def classify_public_manifest(paths, journal):
    # type: (JerryProxyPaths, dict) -> str
    """Classify the physical active manifest as P, T, M, or U."""

    path = paths.root / journal["manifest"]
    if not os.path.lexists(str(path)):
        return "M"
    value = _read_manifest_classification(path)
    if value is None:
        return "U"
    if journal["previous"] is not None and value == journal["previous"]["manifest_payload"]:
        return "P"
    if value == journal["target"]["manifest_payload"]:
        return "T"
    return "U"


def classify_candidate(paths, journal, name):
    # type: (JerryProxyPaths, dict, str) -> str
    """Classify one activation candidate without changing or pinning it."""

    candidate = journal["candidates"][name]
    path = paths.root / candidate["path"]
    if not os.path.lexists(str(path)):
        if candidate["state"] == "building" and candidate["identity"] is not None:
            return "unknown"
        if candidate["state"] in ("ready", "published"):
            public = paths.root / journal[name if name == "link" else "manifest"]
            physical = (
                classify_public_link(paths, journal) if name == "link" else classify_public_manifest(paths, journal)
            )
            if candidate["state"] == "published" and physical == "M":
                return "missing"
            if candidate["identity"] is None or not identity_matches(public, candidate["identity"]):
                return "unknown"
            desired = "P" if candidate["purpose"] == "recovery-previous" else "T"
            if physical != desired and not (name == "link" and physical == "B"):
                return "unknown"
            return "recorded-owned"
        return "missing"
    identity = candidate["identity"]
    if identity is not None:
        if not identity_matches(path, identity):
            displaced_identity = candidate["displaced_identity"]
            public = paths.root / journal[name if name == "link" else "manifest"]
            physical = (
                classify_public_link(paths, journal) if name == "link" else classify_public_manifest(paths, journal)
            )
            desired_physical = "P" if candidate["purpose"] == "recovery-previous" else "T"
            if (
                candidate["state"] == "ready"
                and displaced_identity is not None
                and identity_matches(path, displaced_identity)
                and identity_matches(public, identity)
                and (physical == desired_physical or (name == "link" and physical == "B"))
            ):
                return "displaced-public"
            return "unknown"
        if candidate["state"] == "published":
            return "unknown"
        if candidate["state"] in ("ready", "discarding"):
            try:
                status = path.lstat()
                if identity["file_type"] == "regular":
                    with AnchoredDirectory(_candidate_area(paths, name)) as parent:
                        size, digest, opened_identity = parent.file_evidence(
                            (path.name,),
                            expected_identity=identity,
                        )
                    if opened_identity != identity:
                        return "unknown"
                    if candidate["size"] is not None and (size != candidate["size"] or digest != candidate["sha256"]):
                        return "unknown"
                elif not stat.S_ISLNK(status.st_mode) or os.readlink(str(path)) != candidate["target"]:
                    return "unknown"
            except (ArchiveError, OSError, IntegrityError):
                # Candidate evidence may become unreadable or change during concurrent inspection.
                return "unknown"
        return "recorded-owned"
    try:
        status = path.lstat()
        if stat.S_ISREG(status.st_mode) and status.st_size == 0 and candidate["state"] == "building":
            return "exact-unrecorded-empty-regular"
        desired = journal["target"]
        if candidate["purpose"] == "recovery-previous":
            desired = journal["previous"]
        if stat.S_ISREG(status.st_mode) and desired is not None:
            with AnchoredDirectory(_candidate_area(paths, name)) as parent:
                size, digest, unused_identity = parent.file_evidence((path.name,))
            if name == "link" and desired["link_mode"] != "symlink":
                if size == desired["executable_size"] and digest == desired["executable_sha256"]:
                    return "exact-unrecorded-purpose-object"
            elif name == "manifest":
                payload = _canonical_bytes(desired["manifest_payload"])
                if size == len(payload) and digest == hashlib.sha256(payload).hexdigest():
                    return "exact-unrecorded-purpose-object"
        if (
            name == "link"
            and candidate["state"] in ("absent", "building")
            and desired is not None
            and stat.S_ISLNK(status.st_mode)
            and os.readlink(str(path)) == os.path.relpath(str(paths.root / desired["executable"]), str(path.parent))
        ):
            return "exact-unrecorded-purpose-object"
    except (ArchiveError, OSError, IntegrityError):
        # An unrecorded candidate may disappear or become unreadable while it is classified.
        return "unknown"
    return "unknown"


def _classify_with_stable_evidence(path, classify):
    if not os.path.lexists(str(path)):
        result = classify()
        if result == "M" and not os.path.lexists(str(path)):
            return result, {"classification": result, "identity": None}
        return "U", None
    try:
        identity = capture_identity(path)
        result = classify()
        if not identity_matches(path, identity):
            return "U", None
    except (OSError, IntegrityError):
        # Racing or unsupported filesystem objects are unknown physical state.
        return "U", None
    return result, {"classification": result, "identity": identity}


def _classify_candidate_with_stable_evidence(paths, journal, name):
    path = paths.root / journal["candidates"][name]["path"]
    if not os.path.lexists(str(path)):
        result = classify_candidate(paths, journal, name)
        if result != "unknown" and not os.path.lexists(str(path)):
            return result, {"classification": result, "identity": None}
        return "unknown", None
    try:
        identity = capture_identity(path)
        result = classify_candidate(paths, journal, name)
        if not identity_matches(path, identity):
            return "unknown", None
    except (OSError, IntegrityError):
        # Racing or unsupported candidate objects never gain recovery authority.
        return "unknown", None
    return result, {"classification": result, "identity": identity}


def classify_activation(paths, journal):
    # type: (JerryProxyPaths, dict) -> ActivationClassification
    """Return the complete non-mutating physical classification."""

    link, link_evidence = _classify_with_stable_evidence(
        paths.root / journal["link"],
        lambda: classify_public_link(paths, journal),
    )
    manifest, manifest_evidence = _classify_with_stable_evidence(
        paths.root / journal["manifest"],
        lambda: classify_public_manifest(paths, journal),
    )
    link_candidate, link_candidate_evidence = _classify_candidate_with_stable_evidence(paths, journal, "link")
    manifest_candidate, manifest_candidate_evidence = _classify_candidate_with_stable_evidence(
        paths, journal, "manifest"
    )
    return ActivationClassification(
        link=link,
        manifest=manifest,
        link_candidate=link_candidate,
        manifest_candidate=manifest_candidate,
        link_evidence=link_evidence,
        manifest_evidence=manifest_evidence,
        link_candidate_evidence=link_candidate_evidence,
        manifest_candidate_evidence=manifest_candidate_evidence,
    )


def _copy_journal(journal):
    return json.loads(json.dumps(journal, allow_nan=False))


def _adopt_displaced_candidate(journal, name):
    candidate = journal["candidates"][name]
    displaced_purpose = candidate["displaced_purpose"]
    logical = journal[displaced_purpose]
    candidate["purpose"] = "recovery-previous" if displaced_purpose == "previous" else "recovery-target"
    candidate["state"] = "discarding"
    candidate["identity"] = candidate["displaced_identity"]
    candidate["size"] = None
    candidate["sha256"] = None
    candidate["target"] = None
    if name == "link" and logical["link_mode"] == "symlink":
        candidate["target"] = os.path.relpath(logical["executable"], "bin")
    candidate["displaced_identity"] = None
    candidate["displaced_purpose"] = None


def plan_activation_recovery(journal, classification):
    # type: (dict, ActivationClassification) -> ActivationRecoveryPlan
    """Plan one restart-safe transition; callers durably publish returned journals."""

    if "U" in (classification.link, classification.manifest) or "unknown" in (
        classification.link_candidate,
        classification.manifest_candidate,
    ):
        raise IntegrityError("activation recovery found unknown physical state")
    updated = _copy_journal(journal)
    direction = recovery_direction(updated)
    if updated["recovery"] is None:
        updated["recovery"] = {"direction": direction}
        return ActivationRecoveryPlan(updated, direction, "persist-direction")
    if updated["recovery"] != {"direction": direction}:
        raise IntegrityError("activation recovery direction changed after publication")

    expected_purpose = {
        "rollback-previous": "recovery-previous",
        "rollforward-target": "recovery-target",
    }.get(direction)
    candidate_classifications = (
        ("link", classification.link_candidate),
        ("manifest", classification.manifest_candidate),
    )
    for name, candidate_classification in candidate_classifications:
        candidate = updated["candidates"][name]
        if candidate["state"] != "discarding":
            continue
        if candidate_classification != "missing":
            return ActivationRecoveryPlan(updated, direction, "delete-candidate", name)
        _clear_candidate(candidate)
        candidate["purpose"] = expected_purpose or "target"
        return ActivationRecoveryPlan(updated, direction, "persist-candidate-absent", name)

    desired_link = "M" if direction == "rollback-absent" else ("P" if direction == "rollback-previous" else "T")
    desired_manifest = desired_link
    for name, candidate_classification in candidate_classifications:
        candidate = updated["candidates"][name]
        if candidate["purpose"] != "target":
            continue
        if candidate_classification == "displaced-public":
            _adopt_displaced_candidate(updated, name)
            return ActivationRecoveryPlan(updated, direction, "persist-displaced-candidate", name)
        if candidate_classification in (
            "exact-unrecorded-purpose-object",
            "exact-unrecorded-empty-regular",
        ):
            evidence = (
                classification.link_candidate_evidence if name == "link" else classification.manifest_candidate_evidence
            )
            return ActivationRecoveryPlan(
                updated,
                direction,
                "pin-unrecorded-candidate",
                name,
                evidence,
            )
        if candidate["state"] != "absent":
            if (
                candidate["state"] == "building"
                and candidate_classification == "missing"
                and candidate["identity"] is None
            ):
                _clear_candidate(candidate)
                return ActivationRecoveryPlan(
                    updated,
                    direction,
                    "persist-candidate-absent",
                    name,
                )
            candidate["state"] = "discarding"
            candidate["displaced_identity"] = None
            candidate["displaced_purpose"] = None
            return ActivationRecoveryPlan(updated, direction, "persist-discarding", name)

    for name, candidate_classification, physical in (
        ("link", classification.link_candidate, classification.link),
        ("manifest", classification.manifest_candidate, classification.manifest),
    ):
        candidate = updated["candidates"][name]
        if candidate["purpose"] == "target":
            continue
        if candidate["purpose"] != expected_purpose:
            raise IntegrityError("activation recovery candidate purpose changed")
        state = candidate["state"]
        desired_physical = "P" if plan_direction_is_previous(direction) else "T"
        if state == "absent":
            if physical == desired_physical or (name == "link" and physical == "B" and desired_physical in ("P", "T")):
                continue
            candidate["state"] = "building"
            return ActivationRecoveryPlan(updated, direction, "start-repair-candidate", name)
        if state == "building":
            if candidate_classification not in (
                "missing",
                "recorded-owned",
                "exact-unrecorded-purpose-object",
                "exact-unrecorded-empty-regular",
            ):
                raise IntegrityError("activation recovery building candidate is unknown")
            return ActivationRecoveryPlan(updated, direction, "resume-building-candidate", name)
        if state == "ready":
            if candidate_classification == "displaced-public":
                _adopt_displaced_candidate(updated, name)
                return ActivationRecoveryPlan(updated, direction, "persist-displaced-candidate", name)
            if candidate_classification != "recorded-owned":
                raise IntegrityError("activation recovery ready candidate is unknown")
            if physical == desired_physical or (name == "link" and physical == "B" and desired_physical in ("P", "T")):
                return ActivationRecoveryPlan(updated, direction, "persist-published", name)
            evidence = classification.link_evidence if name == "link" else classification.manifest_evidence
            return ActivationRecoveryPlan(
                updated,
                direction,
                "publish-repair-candidate",
                name,
                evidence,
            )
        if state == "published":
            candidate["state"] = "discarding"
            return ActivationRecoveryPlan(updated, direction, "persist-discarding", name)

    for name, physical, desired in (
        ("link", classification.link, desired_link),
        ("manifest", classification.manifest, desired_manifest),
    ):
        if physical == desired or (name == "link" and physical == "B" and desired in ("P", "T")):
            continue
        if direction == "rollback-absent":
            evidence = classification.link_evidence if name == "link" else classification.manifest_evidence
            return ActivationRecoveryPlan(
                updated,
                direction,
                "delete-public",
                name,
                evidence,
            )
        purpose = "recovery-previous" if direction == "rollback-previous" else "recovery-target"
        updated["candidates"][name]["purpose"] = purpose
        return ActivationRecoveryPlan(updated, direction, "build-repair-candidate", name)
    return ActivationRecoveryPlan(updated, direction, "dispose-journal")


def plan_direction_is_previous(direction):
    return direction == "rollback-previous"


def recover_use_record(paths, record):
    # type: (JerryProxyPaths, ActivationRecord) -> ActivationRecoveryPlan
    """Reclassify and plan the next recovery step for one preflighted record."""

    if not isinstance(record, ActivationRecord) or record.kind != "use":
        raise IntegrityError("invalid activation recovery record")
    return plan_activation_recovery(record.state, classify_activation(paths, record.state))


def _writer_temporary(paths, operation, write_id):
    return paths.runtimes / (".use-%s.json.tmp-%s" % (operation, write_id()))


def _write_activation_record(paths, journal_path, value, write_id, expected_identity=None):
    temporary = _writer_temporary(paths, value["operation"], write_id)
    try:
        with AnchoredDirectory(paths.runtimes) as runtimes:
            unused_payload, journal_identity = runtimes.write_json(
                (Path(journal_path).name,),
                value,
                (temporary.name,),
                replace_existing=expected_identity is not None,
                expected_destination_identity=expected_identity,
            )
    except ArchiveError as error:
        raise IntegrityError("unable to publish anchored activation journal: %s" % journal_path) from error
    return journal_identity


def _require_activation_authority_value(journal, journal_identity, expected_value):
    try:
        with AnchoredDirectory(Path(journal).parent) as runtimes:
            value, unused_identity = runtimes.read_json(
                (Path(journal).name,),
                expected_identity=journal_identity,
            )
        if value != expected_value:
            raise IntegrityError("activation journal content changed")
    except (ArchiveError, OSError, ValueError, IntegrityError) as error:
        # Recovery authority may disappear or change identity/content after planning.
        raise IntegrityError("activation journal changed before recovery action: %s" % journal) from error


class _ActivationJournalAuthority(object):
    """Track the exact authoritative activation record between transitions."""

    def __init__(self, paths, journal_path, value, write_id, journal_identity=None):
        self.paths = paths
        self.journal_path = Path(journal_path)
        self.value = deepcopy(value)
        self.write_id = write_id
        self.journal_identity = journal_identity

    @classmethod
    def from_record(cls, paths, record, write_id):
        return cls(
            paths,
            record.journal_path,
            record.state,
            write_id,
            journal_identity=record.journal_identity,
        )

    def require(self):
        if self.journal_identity is None:
            return
        _require_activation_authority_value(
            self.journal_path,
            self.journal_identity,
            self.value,
        )

    def publish(self, value):
        self.require()
        self.journal_identity = _write_activation_record(
            self.paths,
            self.journal_path,
            value,
            self.write_id,
            expected_identity=self.journal_identity,
        )
        self.value = deepcopy(value)


def _publish_activation_value(paths, journal_path, value, write_id, authority=None):
    if authority is None:
        _write_activation_record(paths, journal_path, value, write_id)
    else:
        authority.publish(value)


def _logical_from_installed(paths, installed_evidence, link, link_mode, manifest_payload):
    installed, executable_size, digest, unused_identity = installed_evidence
    executable = str(PurePosixPath(*installed.executable.relative_to(paths.root).parts))
    if digest != installed.executable_sha256:
        raise IntegrityError("activation source executable digest changed")
    return {
        "version": installed.version,
        "executable": executable,
        "executable_size": executable_size,
        "executable_sha256": digest,
        "link_mode": link_mode,
        "manifest_payload": manifest_payload,
    }


def _manifest_payload(backend, logical, link, activated_at, link_mode):
    return {
        "name": backend,
        "version": logical["version"],
        "executable": logical["executable"],
        "link": link,
        "activated_at": activated_at,
        "link_mode": link_mode,
    }


def _clear_candidate(candidate):
    candidate.update(
        {
            "state": "absent",
            "identity": None,
            "size": None,
            "sha256": None,
            "target": None,
            "displaced_identity": None,
            "displaced_purpose": None,
        }
    )


def _candidate_area(paths, name):
    return paths.bin if name == "link" else paths.active


def _candidate_path(paths, value, name):
    return paths.root / value["candidates"][name]["path"]


def _public_path(paths, value, name):
    return paths.root / value[name if name == "link" else "manifest"]


def _create_symlink_candidate(paths, value, target):
    path = _candidate_path(paths, value, "link")
    try:
        with AnchoredDirectory(paths.bin) as anchored:
            return anchored.create_symlink((path.name,), target)
    except ArchiveError as error:
        cause = error.__cause__
        if str(error) == "unable to create anchored symlink" and isinstance(cause, OSError):
            # Native symlink creation failures retain the existing public OSError contract.
            raise cause
        raise IntegrityError("activation candidate ancestor changed") from error


def durable_replace(
    source,
    destination,
    expected_identity=None,
    expected_destination_identity=None,
):
    source = Path(source)
    destination = Path(destination)
    if source.parent != destination.parent:
        return _filesystem_durable_replace(source, destination)
    try:
        with AnchoredDirectory(source.parent) as anchored:
            outcome = anchored.replace(
                (source.name,),
                (destination.name,),
                expected_identity=expected_identity,
                replace_existing=expected_destination_identity is not None,
                expected_destination_identity=expected_destination_identity,
            )
        return (outcome,)
    except ArchiveError as error:
        raise IntegrityError("activation publication ancestor changed") from error


def _verify_recovery_precondition(paths, value, name, evidence, candidate=False):
    if not isinstance(evidence, dict) or set(evidence) != {"classification", "identity"}:
        raise IntegrityError("activation recovery action has no stable precondition")
    path = _candidate_path(paths, value, name) if candidate else _public_path(paths, value, name)
    expected_identity = evidence["identity"]
    if expected_identity is None:
        if os.path.lexists(str(path)):
            raise IntegrityError("managed object changed after activation recovery planning")
        return
    if not identity_matches(path, expected_identity):
        raise IntegrityError("managed object changed after activation recovery planning")
    if candidate:
        actual = classify_candidate(paths, value, name)
    elif name == "link":
        actual = classify_public_link(paths, value)
    else:
        actual = classify_public_manifest(paths, value)
    if actual != evidence["classification"] or not identity_matches(path, expected_identity):
        raise IntegrityError("managed object changed after activation recovery planning")


def _remove_candidate(paths, value, name):
    candidate = value["candidates"][name]
    path = _candidate_path(paths, value, name)
    if not os.path.lexists(str(path)):
        return
    allowed = (path,) if candidate["identity"]["file_type"] == "symlink" else ()
    removed = _secure_remove_tree(
        _candidate_area(paths, name),
        path,
        IntegrityError,
        allowed_symlinks=allowed,
        expected_identity=candidate["identity"],
        private_names=True,
    )
    if removed:
        flush_directory(path.parent)


def _remove_public(paths, value, name, expected_identity):
    path = _public_path(paths, value, name)
    if not os.path.lexists(str(path)):
        return
    candidate = _candidate_path(paths, value, name)
    try:
        with AnchoredDirectory(_candidate_area(paths, name)) as parent:
            parent.replace(
                (path.name,),
                (candidate.name,),
                expected_identity=expected_identity,
                replace_existing=False,
            )
    except ArchiveError as error:
        raise IntegrityError("unable to isolate public activation state for recovery") from error


def _open_regular_candidate(path):
    output = None
    try:
        with AnchoredDirectory(Path(path).parent) as anchored:
            output, identity = anchored.create_file((Path(path).name,))
            output.flush()
            flush_descriptor(output.fileno(), "empty activation candidate")
            anchored.flush()
            return output, identity
    except (ArchiveError, DurabilityError) as error:
        if output is not None:
            output.close()
        if isinstance(error, DurabilityError):
            raise
        raise IntegrityError("activation candidate ancestor changed") from error


def _open_anchored_regular_candidate(paths, value, name):
    path = _candidate_path(paths, value, name)
    output, identity = _open_regular_candidate(path)
    try:
        if not identity_matches(path, identity):
            raise IntegrityError("activation candidate changed while being created")
        return output, identity
    except (OSError, IntegrityError):
        output.close()
        raise


def _reopen_regular_candidate(paths, value, name, identity):
    path = _candidate_path(paths, value, name)
    try:
        with AnchoredDirectory(_candidate_area(paths, name)) as anchored:
            output, unused_identity = anchored.open_existing_file(
                (path.name,),
                writable=True,
                expected_identity=identity,
            )
        return output
    except ArchiveError as error:
        raise IntegrityError("activation candidate changed while reopening") from error


def _prepare_regular_candidate(paths, journal_path, value, name, write_id, authority=None):
    if authority is not None:
        authority.require()
    candidate = value["candidates"][name]
    path = _candidate_path(paths, value, name)
    if candidate["identity"] is None:
        if os.path.lexists(str(path)):
            identity = capture_identity(path)
            status = path.lstat()
            if not stat.S_ISREG(status.st_mode) or status.st_size != 0:
                raise IntegrityError("unrecorded activation candidate is not empty")
            output = _reopen_regular_candidate(paths, value, name, identity)
        else:
            output, identity = _open_anchored_regular_candidate(paths, value, name)
        candidate["identity"] = identity
        try:
            _publish_activation_value(paths, journal_path, value, write_id, authority)
        except (OSError, IntegrityError):
            # A failed identity publication must not leak the candidate output stream.
            output.close()
            raise
    else:
        output = _reopen_regular_candidate(paths, value, name, candidate["identity"])
    return candidate, output


def _mark_regular_candidate_ready(
    paths,
    journal_path,
    value,
    candidate,
    size,
    digest,
    write_id,
    ready_phase,
    authority=None,
):
    candidate.update(
        {
            "state": "ready",
            "size": size,
            "sha256": digest,
            "target": None,
        }
    )
    if ready_phase is not None:
        value["phase"] = ready_phase
    _publish_activation_value(paths, journal_path, value, write_id, authority)


def _write_regular_candidate(
    paths,
    journal_path,
    value,
    name,
    payload,
    write_id,
    ready_phase=None,
    authority=None,
):
    candidate, output = _prepare_regular_candidate(
        paths,
        journal_path,
        value,
        name,
        write_id,
        authority=authority,
    )
    if authority is not None:
        authority.require()
    with output:
        os.ftruncate(output.fileno(), 0)
        written = 0
        while written < len(payload):
            block = payload[written : written + _COPY_CHUNK_SIZE]
            block_written = output.write(block)
            if (
                not isinstance(block_written, int)
                or isinstance(block_written, bool)
                or block_written <= 0
                or block_written > len(block)
            ):
                raise IntegrityError("activation candidate write made no valid progress")
            written += block_written
        output.flush()
        flush_descriptor(output.fileno(), "activation candidate")
    _mark_regular_candidate_ready(
        paths,
        journal_path,
        value,
        candidate,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        write_id,
        ready_phase,
        authority=authority,
    )


def _copy_regular_candidate(
    paths,
    journal_path,
    value,
    name,
    source,
    expected_size,
    expected_digest,
    write_id,
    ready_phase=None,
    authority=None,
):
    candidate, output = _prepare_regular_candidate(
        paths,
        journal_path,
        value,
        name,
        write_id,
        authority=authority,
    )
    if authority is not None:
        authority.require()
    source = Path(source)
    try:
        source_parts = source.relative_to(paths.backends).parts
    except ValueError as error:
        raise IntegrityError("activation source executable escapes installed backends") from error
    digest = hashlib.sha256()
    written = 0
    with output:
        os.ftruncate(output.fileno(), 0)
        try:
            with AnchoredDirectory(paths.backends) as installed_tree:
                input_stream, source_identity = installed_tree.open_existing_file(source_parts)
                with input_stream:
                    before = os.fstat(input_stream.fileno())
                    while written < expected_size:
                        block = input_stream.read(min(_COPY_CHUNK_SIZE, expected_size - written))
                        if not block:
                            raise IntegrityError("activation source executable ended during copy")
                        block_written = 0
                        while block_written < len(block):
                            progress = output.write(block[block_written:])
                            if (
                                not isinstance(progress, int)
                                or isinstance(progress, bool)
                                or progress <= 0
                                or progress > len(block) - block_written
                            ):
                                raise IntegrityError("activation candidate write made no valid progress")
                            digest.update(block[block_written : block_written + progress])
                            block_written += progress
                            written += progress
                    if input_stream.read(1):
                        raise IntegrityError("activation source executable grew during copy")
                    after = os.fstat(input_stream.fileno())
                    before_snapshot = (
                        int(before.st_dev),
                        int(before.st_ino),
                        stat.S_IFMT(before.st_mode),
                        int(before.st_size),
                        int(before.st_mtime_ns),
                        int(before.st_ctime_ns),
                    )
                    after_snapshot = (
                        int(after.st_dev),
                        int(after.st_ino),
                        stat.S_IFMT(after.st_mode),
                        int(after.st_size),
                        int(after.st_mtime_ns),
                        int(after.st_ctime_ns),
                    )
                    if before_snapshot != after_snapshot:
                        raise IntegrityError("activation source executable changed during copy")
                installed_tree.assert_bound()
                if not identity_matches(source, source_identity):
                    raise IntegrityError("activation source executable changed while opening")
        except ArchiveError as error:
            raise IntegrityError("activation source executable changed while opening") from error
        output.flush()
        flush_descriptor(output.fileno(), "activation candidate")
    actual_digest = digest.hexdigest()
    if written != expected_size or actual_digest != expected_digest:
        raise IntegrityError("activation source executable changed during copy")
    _mark_regular_candidate_ready(
        paths,
        journal_path,
        value,
        candidate,
        written,
        actual_digest,
        write_id,
        ready_phase,
        authority=authority,
    )


def _write_link_candidate(
    paths,
    journal_path,
    value,
    logical,
    write_id,
    ready_phase=None,
    authority=None,
):
    candidate = value["candidates"]["link"]
    path = _candidate_path(paths, value, "link")
    if authority is not None:
        authority.require()
    if logical["link_mode"] == "symlink":
        target = os.path.relpath(str(paths.root / logical["executable"]), str(path.parent))
        created_identity = None
        if not os.path.lexists(str(path)):
            created_identity = _create_symlink_candidate(paths, value, target)
        elif not path.is_symlink() or os.readlink(str(path)) != target:
            raise IntegrityError("unrecorded activation symlink candidate changed")
        candidate.update(
            {
                "state": "ready",
                "identity": created_identity or capture_identity(path),
                "size": None,
                "sha256": None,
                "target": target,
            }
        )
        if ready_phase is not None:
            value["phase"] = ready_phase
        _publish_activation_value(paths, journal_path, value, write_id, authority)
        return
    _copy_regular_candidate(
        paths,
        journal_path,
        value,
        "link",
        paths.root / logical["executable"],
        logical["executable_size"],
        logical["executable_sha256"],
        write_id,
        ready_phase=ready_phase,
        authority=authority,
    )


def _write_manifest_candidate(
    paths,
    journal_path,
    value,
    logical,
    write_id,
    ready_phase=None,
    authority=None,
):
    payload = _canonical_bytes(logical["manifest_payload"])
    _write_regular_candidate(
        paths,
        journal_path,
        value,
        "manifest",
        payload,
        write_id,
        ready_phase=ready_phase,
        authority=authority,
    )


def _publish_candidate(
    paths,
    journal_path,
    value,
    name,
    write_id,
    expected_public_identity,
    displaced_purpose,
    published_phase=None,
    authority=None,
):
    if authority is not None:
        authority.require()
    candidate_path = _candidate_path(paths, value, name)
    public_path = _public_path(paths, value, name)
    if os.path.lexists(str(candidate_path)):
        if not identity_matches(candidate_path, value["candidates"][name]["identity"]):
            raise IntegrityError("activation candidate changed before publication")
        candidate = value["candidates"][name]
        if candidate["identity"]["file_type"] == "regular":
            try:
                with AnchoredDirectory(_candidate_area(paths, name)) as parent:
                    size, digest, opened_identity = parent.file_evidence(
                        (candidate_path.name,),
                        expected_identity=candidate["identity"],
                    )
                if (
                    opened_identity != candidate["identity"]
                    or size != candidate["size"]
                    or digest != candidate["sha256"]
                ):
                    raise IntegrityError("activation candidate content changed before publication")
            except (ArchiveError, OSError) as error:
                # Ready regular candidates must remain readable through publication.
                raise IntegrityError("activation candidate content changed before publication") from error
        candidate["displaced_identity"] = expected_public_identity
        candidate["displaced_purpose"] = displaced_purpose
        if authority is not None:
            authority.publish(value)
        durable_replace(
            candidate_path,
            public_path,
            candidate["identity"],
            expected_destination_identity=expected_public_identity,
        )
    else:
        if not identity_matches(public_path, value["candidates"][name]["identity"]):
            raise IntegrityError("activation candidate disappeared before publication")
        flush_directory(public_path.parent)
    value["candidates"][name]["state"] = "published"
    value["candidates"][name]["displaced_identity"] = None
    value["candidates"][name]["displaced_purpose"] = None
    if published_phase is not None:
        value["phase"] = published_phase
    _publish_activation_value(paths, journal_path, value, write_id, authority)


class ActivationTransaction(object):
    """One journaled active-backend publication under the home-wide lock."""

    def __init__(self, paths, platform_info, journal_path, value, write_id):
        self.paths = paths
        self.platform_info = platform_info
        self.journal_path = Path(journal_path)
        self.value = value
        self._write_id = write_id
        self._authority = _ActivationJournalAuthority(
            paths,
            self.journal_path,
            value,
            write_id,
        )

    @classmethod
    def prepare(
        cls,
        paths,
        platform_info,
        name,
        version,
        activated_at=None,
        operation=None,
        write_id=None,
    ):
        """Publish activation intent before creating either candidate object."""

        spec = get_backend(name)
        version = spec.normalize_version(version)
        operation = operation or secrets.token_hex(16)
        if _OPERATION_PATTERN.fullmatch(operation) is None:
            raise ValueError("activation operation must be 32 lowercase hexadecimal characters")
        link = "bin/%s" % spec.executable_filename(platform_info)
        manifest = "active/%s.json" % spec.name
        installed = load_installed_manifest_evidence(
            paths,
            paths.backends / spec.name / version / "manifest.json",
        )
        target = _logical_from_installed(paths, installed, link, None, None)
        previous_state = load_active_state(paths, spec.name, platform_info)
        previous = None
        if previous_state is not None:
            active, previous_payload = previous_state
            previous_installed = load_installed_manifest_evidence(
                paths,
                paths.backends / spec.name / active.version / "manifest.json",
            )
            previous = _logical_from_installed(
                paths,
                previous_installed,
                link,
                active.link_mode,
                previous_payload,
            )
        value = {
            "kind": "use",
            "operation": operation,
            "phase": "prepared",
            "backend": spec.name,
            "link": link,
            "manifest": manifest,
            "previous": previous,
            "target": target,
            "candidates": {
                "link": {
                    "path": "bin/.%s.use-%s.candidate" % (Path(link).name, operation),
                    "purpose": "target",
                    "state": "absent",
                    "identity": None,
                    "size": None,
                    "sha256": None,
                    "target": None,
                    "displaced_identity": None,
                    "displaced_purpose": None,
                },
                "manifest": {
                    "path": "active/.%s.use-%s.candidate.json" % (spec.name, operation),
                    "purpose": "target",
                    "state": "absent",
                    "identity": None,
                    "size": None,
                    "sha256": None,
                    "target": None,
                    "displaced_identity": None,
                    "displaced_purpose": None,
                },
            },
            "recovery": None,
        }
        transaction = cls(
            paths,
            platform_info,
            paths.runtimes / (".use-%s.json" % operation),
            value,
            write_id or (lambda: secrets.token_hex(16)),
        )
        if os.path.lexists(str(transaction.journal_path)):
            raise IntegrityError("activation journal already exists")
        transaction.activated_at = activated_at or datetime.now(timezone.utc).isoformat()
        transaction._authority.publish(value)
        load_use_journal(paths, transaction.journal_path, platform_info)
        return transaction

    def execute(self):
        """Build, publish, validate, and commit the target active pair."""

        self._authority.require()
        initial = classify_activation(self.paths, self.value)
        expected_link_states = ("M",) if self.value["previous"] is None else ("P", "B")
        expected_manifest_state = "M" if self.value["previous"] is None else "P"
        if initial.link_candidate != "missing" or initial.manifest_candidate != "missing":
            raise IntegrityError("unrecorded activation candidate is not empty")
        if initial.link not in expected_link_states or initial.manifest != expected_manifest_state:
            raise IntegrityError("active state changed before activation candidate construction")
        expected_public_identities = {
            "link": initial.link_evidence["identity"] if initial.link_evidence is not None else None,
            "manifest": (
                initial.manifest_evidence["identity"] if initial.manifest_evidence is not None else None
            ),
        }
        displaced_purpose = "previous" if self.value["previous"] is not None else None
        target = self.value["target"]
        link_candidate = self.value["candidates"]["link"]
        link_path = _candidate_path(self.paths, self.value, "link")
        target_path = os.path.relpath(
            str(self.paths.root / target["executable"]),
            str(link_path.parent),
        )
        try:
            created_identity = _create_symlink_candidate(self.paths, self.value, target_path)
        except (OSError, NotImplementedError) as error:
            if not _windows_symlink_fallback_allowed(error):
                raise
            target["link_mode"] = "copy"
            target["manifest_payload"] = _manifest_payload(
                self.value["backend"], target, self.value["link"], self.activated_at, "copy"
            )
            link_candidate["state"] = "building"
            self.value["phase"] = "link-building"
            self._authority.publish(self.value)
            _write_link_candidate(
                self.paths,
                self.journal_path,
                self.value,
                target,
                self._write_id,
                ready_phase="link-ready",
                authority=self._authority,
            )
        else:
            target["link_mode"] = "symlink"
            target["manifest_payload"] = _manifest_payload(
                self.value["backend"], target, self.value["link"], self.activated_at, "symlink"
            )
            link_candidate.update(
                {
                    "state": "ready",
                    "identity": created_identity,
                    "size": None,
                    "sha256": None,
                    "target": target_path,
                }
            )
            self.value["phase"] = "link-ready"
            self._authority.publish(self.value)

        self.value["candidates"]["manifest"]["state"] = "building"
        self.value["phase"] = "manifest-building"
        self._authority.publish(self.value)
        _write_manifest_candidate(
            self.paths,
            self.journal_path,
            self.value,
            target,
            self._write_id,
            ready_phase="candidates-ready",
            authority=self._authority,
        )

        _publish_candidate(
            self.paths,
            self.journal_path,
            self.value,
            "link",
            self._write_id,
            expected_public_identities["link"],
            displaced_purpose,
            published_phase="link-published",
            authority=self._authority,
        )
        _publish_candidate(
            self.paths,
            self.journal_path,
            self.value,
            "manifest",
            self._write_id,
            expected_public_identities["manifest"],
            displaced_purpose,
            published_phase="manifest-published",
            authority=self._authority,
        )
        self._authority.require()
        classification = classify_activation(self.paths, self.value)
        if (classification.link, classification.manifest) not in (("T", "T"), ("B", "T")):
            raise IntegrityError("published activation pair failed validation")
        self.value["phase"] = "committed"
        self._authority.publish(self.value)
        recover_use_transactions(self.paths, self.platform_info)
        active = load_active_state(self.paths, self.value["backend"], self.platform_info)
        if active is None:
            raise IntegrityError("committed activation state disappeared")
        return active[0]


def _execute_recovery_plan(paths, record, plan, platform_info, write_id):
    authority = _ActivationJournalAuthority.from_record(paths, record, write_id)
    authority.require()
    value = plan.journal
    journal = record.journal_path
    name = plan.object_name
    if plan.action in (
        "persist-direction",
        "persist-discarding",
        "build-repair-candidate",
        "start-repair-candidate",
    ):
        authority.publish(value)
        return
    if plan.action == "persist-candidate-absent":
        flush_directory(_candidate_path(paths, value, name).parent)
        authority.publish(value)
        return
    if plan.action == "pin-unrecorded-candidate":
        candidate = value["candidates"][name]
        _verify_recovery_precondition(paths, value, name, plan.precondition, candidate=True)
        identity = plan.precondition["identity"]
        candidate["state"] = "discarding"
        candidate["identity"] = identity
        if identity["file_type"] == "symlink":
            desired = value["target"]
            candidate["target"] = os.path.relpath(desired["executable"], "bin")
        authority.publish(value)
        return
    if plan.action == "delete-candidate":
        _remove_candidate(paths, value, name)
        return
    if plan.action == "delete-public":
        _verify_recovery_precondition(paths, value, name, plan.precondition)
        _remove_public(paths, value, name, plan.precondition["identity"])
        return
    if plan.action == "resume-building-candidate":
        logical = value["previous"] if plan.direction == "rollback-previous" else value["target"]
        if name == "link":
            _write_link_candidate(
                paths,
                journal,
                value,
                logical,
                write_id,
                authority=authority,
            )
        else:
            _write_manifest_candidate(
                paths,
                journal,
                value,
                logical,
                write_id,
                authority=authority,
            )
        return
    if plan.action == "publish-repair-candidate":
        _verify_recovery_precondition(paths, value, name, plan.precondition)
        displaced_classification = plan.precondition["classification"]
        displaced_purpose = None
        if displaced_classification in ("P", "B"):
            displaced_purpose = "previous"
        elif displaced_classification == "T":
            displaced_purpose = "target"
        _publish_candidate(
            paths,
            journal,
            value,
            name,
            write_id,
            plan.precondition["identity"],
            displaced_purpose,
            authority=authority,
        )
        return
    if plan.action == "persist-displaced-candidate":
        authority.publish(value)
        return
    if plan.action == "persist-published":
        value["candidates"][name]["state"] = "published"
        value["candidates"][name]["displaced_identity"] = None
        value["candidates"][name]["displaced_purpose"] = None
        authority.publish(value)
        return
    if plan.action == "dispose-journal":
        removed = False
        for temporary, identity in record.temporaries:
            if os.path.lexists(str(temporary)):
                removed = (
                    _secure_remove_tree(
                        paths.runtimes,
                        temporary,
                        IntegrityError,
                        expected_identity=identity,
                        private_names=True,
                    )
                    or removed
                )
        if os.path.lexists(str(journal)):
            removed = (
                _secure_remove_tree(
                    paths.runtimes,
                    journal,
                    IntegrityError,
                    expected_identity=record.journal_identity,
                    private_names=True,
                )
                or removed
            )
        if removed:
            flush_directory(paths.runtimes)
        return
    raise IntegrityError("unsupported activation recovery action: %s" % plan.action)


def _flush_public_parents_before_recovery(paths, record, flushed_operations):
    if record.state["recovery"] is None or record.operation in flushed_operations:
        return
    flush_directory(paths.bin)
    flush_directory(paths.active)
    flushed_operations.add(record.operation)


def recover_use_transactions(paths, platform_info, write_id=None):
    # type: (JerryProxyPaths, PlatformInfo, Optional[Callable]) -> None
    """Recover every authoritative use journal in lexical operation order."""

    write_id = write_id or (lambda: secrets.token_hex(16))
    flushed_operations = set()
    while True:
        records = discover_use_journals(paths, platform_info)
        if not records:
            return
        progressed = False
        for record in records:
            _flush_public_parents_before_recovery(paths, record, flushed_operations)
            plan = recover_use_record(paths, record)
            _execute_recovery_plan(paths, record, plan, platform_info, write_id)
            progressed = True
        if not progressed:  # pragma: no cover - each accepted plan advances or disposes
            raise IntegrityError("activation recovery made no progress")


def _recover_use_operation(paths, platform_info, operation, write_id=None):
    """Recover one preflighted activation operation to convergence."""

    write_id = write_id or (lambda: secrets.token_hex(16))
    flushed_operations = set()
    while True:
        records = discover_use_journals(paths, platform_info)
        selected = [record for record in records if record.operation == operation]
        if not selected:
            return
        if len(selected) != 1:  # pragma: no cover - filenames make duplicates impossible
            raise IntegrityError("duplicate activation recovery operation")
        record = selected[0]
        _flush_public_parents_before_recovery(paths, record, flushed_operations)
        plan = recover_use_record(paths, record)
        _execute_recovery_plan(paths, record, plan, platform_info, write_id)
