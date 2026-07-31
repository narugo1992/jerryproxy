"""Durable installation journals and process-crash recovery."""

import os
import re
import secrets
import stat
from copy import deepcopy
from pathlib import Path, PurePosixPath, PureWindowsPath

from ..errors import ArchiveError, IntegrityError, UnsupportedBackendError
from ..home import is_path_alias
from ..utils.fs import MAXIMUM_JSON_BYTES
from .anchored import AnchoredDirectory
from .archive import ArchiveLimits
from .durable import flush_directory
from .identity import capture_identity, identity_matches, validate_identity
from .registry import get_backend, iter_backend_platforms
from .removal import _secure_remove_tree
from .state import load_installed_manifest

_OPERATION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_JOURNAL_PATTERN = re.compile(r"^\.install-([0-9a-f]{32})\.json$")
_TEMPORARY_PATTERN = re.compile(r"^\.install-([0-9a-f]{32})\.json\.tmp-([0-9a-f]{32})$")
_STAGING_PATTERN = re.compile(r"^\.(.+)\.install-([0-9a-f]{32})$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_KEYS = {
    "kind",
    "operation",
    "phase",
    "backend",
    "version",
    "staging",
    "final",
    "tree_identity",
    "artifact",
    "publication",
}
_ARTIFACT_KEYS = {"sha256", "size", "asset_name", "platform"}
_PUBLICATION_KEYS = {
    "manifest_sha256",
    "executable",
    "executable_sha256",
    "executable_size",
}
_PHASES = frozenset(("prepared", "extracting", "validated", "committed"))


def _operation_id(value):
    if not isinstance(value, str) or _OPERATION_PATTERN.match(value) is None:
        raise IntegrityError("invalid install operation ID")
    return value


def _bounded_string(value, field, maximum_bytes):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum_bytes:
        raise IntegrityError("invalid install journal %s" % field)
    return value


def _digest(value, field):
    if not isinstance(value, str) or _DIGEST_PATTERN.match(value) is None:
        raise IntegrityError("invalid install journal %s" % field)
    return value


def _size(value, field, maximum):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise IntegrityError("invalid install journal %s" % field)
    return value


def _safe_leaf(value, field):
    value = _bounded_string(value, field, 255)
    if value in (".", "..") or "/" in value or "\\" in value:
        raise IntegrityError("invalid install journal %s" % field)
    return value


def _relative_parts(value, field):
    value = _bounded_string(value, field, 1024)
    windows = PureWindowsPath(value)
    parts = value.split("/")
    if (
        "\\" in value
        or value.startswith("/")
        or PurePosixPath(value).is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise IntegrityError("invalid install journal %s" % field)
    return tuple(parts)


def _validate_artifact(value, backend):
    if not isinstance(value, dict) or set(value) != _ARTIFACT_KEYS:
        raise IntegrityError("invalid install journal artifact")
    limits = ArchiveLimits()
    _digest(value["sha256"], "artifact digest")
    _size(value["size"], "artifact size", limits.maximum_compressed_bytes)
    _safe_leaf(value["asset_name"], "asset name")
    platform = _bounded_string(value["platform"], "platform", 128)
    supported = {item.asset_key for item in iter_backend_platforms(backend)}
    if platform not in supported:
        raise IntegrityError("invalid install journal platform")
    return dict(value)


def _validate_publication(value):
    if not isinstance(value, dict) or set(value) != _PUBLICATION_KEYS:
        raise IntegrityError("invalid install journal publication")
    limits = ArchiveLimits()
    _digest(value["manifest_sha256"], "manifest digest")
    _digest(value["executable_sha256"], "executable digest")
    _size(value["executable_size"], "executable size", limits.maximum_file_bytes)
    _relative_parts(value["executable"], "executable path")
    return dict(value)


class InstallRecoveryRecord(object):
    """One fully parsed install journal and its semantic path set."""

    def __init__(
        self,
        paths,
        journal,
        value,
        temporaries=(),
        temporary_evidence=(),
        journal_identity=None,
    ):
        self.paths = paths
        self.kind = "install"
        self.journal = Path(journal)
        self.value = value
        self.operation = value["operation"]
        self.phase = value["phase"]
        self.backend = value["backend"]
        self.version = value["version"]
        self.staging = paths.root.joinpath(*PurePosixPath(value["staging"]).parts)
        self.final = paths.root.joinpath(*PurePosixPath(value["final"]).parts)
        self.temporaries = tuple(sorted(Path(item) for item in temporaries))
        self.temporary_evidence = tuple(
            sorted(((Path(path), identity) for path, identity in temporary_evidence), key=lambda item: item[0])
        )
        self.journal_identity = journal_identity
        self.authority_value = deepcopy(value)
        journal_relative = _relative_posix(paths, self.journal)
        self.read_set = frozenset((journal_relative,))
        self.write_set = frozenset(
            (journal_relative, value["staging"], value["final"])
            + tuple(_relative_posix(paths, item) for item in self.temporaries)
        )


def _relative_posix(paths, path):
    relative = Path(path).relative_to(paths.root)
    return str(PurePosixPath(*relative.parts))


def _validate_record(
    paths,
    journal,
    value,
    filename_operation,
    temporaries=(),
    temporary_evidence=(),
    journal_identity=None,
):
    if not isinstance(value, dict) or set(value) != _TOP_LEVEL_KEYS:
        raise IntegrityError("invalid install journal keys: %s" % journal)
    if value["kind"] != "install":
        raise IntegrityError("invalid install journal kind: %s" % journal)
    operation = _operation_id(value["operation"])
    if operation != filename_operation:
        raise IntegrityError("install journal operation does not match filename: %s" % journal)
    phase = value["phase"]
    if phase not in _PHASES:
        raise IntegrityError("invalid install journal phase: %s" % journal)
    backend = _bounded_string(value["backend"], "backend", 64)
    version = _bounded_string(value["version"], "version", 128)
    try:
        spec = get_backend(backend)
        normalized_version = spec.normalize_version(version)
    except (UnsupportedBackendError, ValueError) as error:
        # Registry normalization defines the accepted backend/version grammar.
        raise IntegrityError("invalid install journal backend or version: %s" % journal) from error
    if backend != spec.name or version != normalized_version:
        raise IntegrityError("noncanonical install journal backend or version: %s" % journal)
    expected_staging = "backends/%s/.%s.install-%s" % (backend, version, operation)
    expected_final = "backends/%s/%s" % (backend, version)
    if value["staging"] != expected_staging or value["final"] != expected_final:
        raise IntegrityError("invalid derived install journal path: %s" % journal)
    _relative_parts(value["staging"], "staging path")
    _relative_parts(value["final"], "final path")
    value = dict(value)
    value["artifact"] = _validate_artifact(value["artifact"], backend)
    identity = value["tree_identity"]
    publication = value["publication"]
    if phase == "prepared":
        if identity is not None or publication is not None:
            raise IntegrityError("invalid prepared install evidence: %s" % journal)
    else:
        if identity is None:
            raise IntegrityError("missing install tree identity: %s" % journal)
        validate_identity(identity, "directory")
        if phase == "extracting":
            if publication is not None:
                raise IntegrityError("premature install publication evidence: %s" % journal)
        elif publication is None:
            raise IntegrityError("missing install publication evidence: %s" % journal)
        else:
            value["publication"] = _validate_publication(publication)
    return InstallRecoveryRecord(
        paths,
        journal,
        value,
        temporaries,
        temporary_evidence,
        journal_identity,
    )


def _read_journal(paths, journal, operation, temporaries):
    if is_path_alias(journal):
        raise IntegrityError("install journal must not be an alias: %s" % journal)
    try:
        with AnchoredDirectory(paths.runtimes) as runtimes:
            value, journal_identity = runtimes.read_json((journal.name,))
    except (ArchiveError, OSError, ValueError) as error:
        # Strict bounded JSON and no-follow metadata checks define this authority boundary.
        raise IntegrityError("unable to read install journal: %s" % journal) from error
    return _validate_record(
        paths,
        journal,
        value,
        operation,
        tuple(path for path, unused_identity in temporaries),
        temporaries,
        journal_identity,
    )


def _validate_temporary(path):
    if is_path_alias(path):
        raise IntegrityError("install journal temporary must not be an alias: %s" % path)
    try:
        status = path.lstat()
    except OSError as error:
        # Enumerated recovery evidence may become inaccessible before it is pinned.
        raise IntegrityError("unable to inspect install journal temporary: %s" % path) from error
    if not stat.S_ISREG(status.st_mode) or status.st_size > MAXIMUM_JSON_BYTES:
        raise IntegrityError("invalid install journal temporary: %s" % path)
    if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
        raise IntegrityError("install journal temporary has unsafe permissions: %s" % path)
    return capture_identity(path)


def _owned_staging(paths):
    owned = {}
    for backend_path in paths.backends.iterdir():
        if not backend_path.is_dir() or is_path_alias(backend_path):
            if ".install-" in backend_path.name:
                raise IntegrityError("invalid install staging namespace: %s" % backend_path)
            continue
        for candidate in backend_path.iterdir():
            if ".install-" not in candidate.name:
                continue
            match = _STAGING_PATTERN.match(candidate.name)
            if match is None:
                raise IntegrityError("invalid install staging name: %s" % candidate)
            operation = match.group(2)
            owned.setdefault(operation, []).append(candidate)
    return owned


def _scan_install_recovery(paths):
    journals = {}
    temporaries = {}
    if not paths.runtimes.exists():
        return (), ()
    if is_path_alias(paths.runtimes) or not paths.runtimes.is_dir():
        raise IntegrityError("invalid install recovery namespace: %s" % paths.runtimes)
    if is_path_alias(paths.backends) or not paths.backends.is_dir():
        raise IntegrityError("invalid install staging namespace: %s" % paths.backends)
    for entry in paths.runtimes.iterdir():
        if not entry.name.startswith(".install-"):
            continue
        journal_match = _JOURNAL_PATTERN.match(entry.name)
        temporary_match = _TEMPORARY_PATTERN.match(entry.name)
        if journal_match is not None:
            operation = journal_match.group(1)
            journals[operation] = entry
        elif temporary_match is not None:
            operation = temporary_match.group(1)
            identity = _validate_temporary(entry)
            temporaries.setdefault(operation, []).append((entry, identity))
        else:
            raise IntegrityError("unknown install recovery entry: %s" % entry)
    owned = _owned_staging(paths)
    records = []
    for operation in sorted(journals):
        record = _read_journal(paths, journals[operation], operation, temporaries.get(operation, ()))
        operation_staging = owned.get(operation, ())
        unexpected = [path for path in operation_staging if path != record.staging]
        if unexpected:
            raise IntegrityError("unexpected install staging object: %s" % unexpected[0])
        records.append(record)
    orphan_temporaries = []
    for operation, values in temporaries.items():
        if operation in journals:
            continue
        if owned.get(operation):
            raise IntegrityError("install writer temporary has owned staging without authority")
        orphan_temporaries.extend(values)
    for operation, values in owned.items():
        if operation not in journals:
            raise IntegrityError("install staging has no authoritative journal: %s" % values[0])
    for index, first in enumerate(records):
        for second in records[index + 1 :]:
            if recovery_path_sets_conflict(first, second):
                raise IntegrityError(
                    "conflicting install recovery records: %s and %s" % (first.journal, second.journal)
                )
    return tuple(records), tuple(sorted(orphan_temporaries, key=lambda item: item[0]))


def preflight_install_recovery(paths):
    # type: (JerryProxyPaths) -> tuple
    """Strictly parse all install evidence and return normalized path sets."""

    records, unused_orphans = _scan_install_recovery(paths)
    return records


def recovery_path_sets_conflict(first, second):
    # type: (InstallRecoveryRecord, InstallRecoveryRecord) -> bool
    """Return whether two normalized recovery path sets semantically conflict."""

    first_paths = tuple((path, path in first.write_set) for path in first.read_set | first.write_set)
    second_paths = tuple((path, path in second.write_set) for path in second.read_set | second.write_set)
    for first_path, first_writes in first_paths:
        first_parts = PurePosixPath(first_path).parts
        for second_path, second_writes in second_paths:
            if not first_writes and not second_writes:
                continue
            second_parts = PurePosixPath(second_path).parts
            shortest = min(len(first_parts), len(second_parts))
            if first_parts[:shortest] == second_parts[:shortest]:
                return True
    return False


def _writer_temporary(operation, write_id):
    return ".install-%s.json.tmp-%s" % (operation, _operation_id(write_id()))


def _publish_record(transaction, write_id):
    if transaction.journal_identity is not None:
        _require_record_authority(transaction)
    temporary_name = _writer_temporary(transaction.operation, write_id)
    try:
        with AnchoredDirectory(transaction.paths.runtimes) as runtimes:
            unused_payload, journal_identity = runtimes.write_json(
                (transaction.journal.name,),
                transaction.value,
                (temporary_name,),
                replace_existing=transaction.journal_identity is not None,
                expected_destination_identity=transaction.journal_identity,
            )
    except ArchiveError as error:
        raise IntegrityError("unable to publish anchored install journal: %s" % transaction.journal) from error
    transaction.journal_identity = journal_identity
    transaction.authority_value = deepcopy(transaction.value)


def _write_record(transaction):
    _publish_record(transaction, transaction._write_id)


def _require_record_authority(record):
    journal = record.journal
    try:
        with AnchoredDirectory(record.paths.runtimes) as runtimes:
            value, unused_identity = runtimes.read_json(
                (journal.name,),
                expected_identity=record.journal_identity,
            )
        if value != record.authority_value:
            raise IntegrityError("install journal content changed")
    except (ArchiveError, OSError, ValueError, IntegrityError) as error:
        # Recovery authority may disappear, change identity, permissions, or content after preflight.
        raise IntegrityError("install journal changed before recovery action: %s" % journal) from error


def _dispose_file(paths, path, expected_identity):
    if os.path.lexists(str(path)):
        _secure_remove_tree(
            paths.runtimes,
            path,
            IntegrityError,
            expected_identity=expected_identity,
            private_names=True,
        )
        flush_directory(path.parent)


def _dispose_record(record):
    for temporary, identity in record.temporary_evidence:
        _require_record_authority(record)
        _dispose_file(record.paths, temporary, identity)
    _require_record_authority(record)
    _dispose_file(record.paths, record.journal, record.journal_identity)


def _remove_staging(record, expected_identity):
    _require_record_authority(record)
    if _secure_remove_tree(
        record.paths.backends,
        record.staging,
        IntegrityError,
        expected_identity=expected_identity,
        private_names=True,
    ):
        flush_directory(record.staging.parent)


def _classify_staging(record):
    if not os.path.lexists(str(record.staging)):
        return "absent", None
    if is_path_alias(record.staging):
        return "unknown", None
    try:
        status = record.staging.lstat()
    except OSError as error:
        # Recovery classification cannot treat inaccessible evidence as absent.
        raise IntegrityError("unable to inspect install staging: %s" % record.staging) from error
    if not stat.S_ISDIR(status.st_mode):
        return "unknown", None
    if record.value["tree_identity"] is not None:
        if identity_matches(record.staging, record.value["tree_identity"]):
            return "identity", record.value["tree_identity"]
        return "unknown", None
    identity = capture_identity(record.staging)
    try:
        if any(record.staging.iterdir()):
            return "unknown", None
    except OSError as error:
        # Directory enumeration is required to prove prepared staging is empty.
        raise IntegrityError("unable to inspect prepared install staging: %s" % record.staging) from error
    if not identity_matches(record.staging, identity):
        return "unknown", None
    return "empty", identity


def _verify_final(record):
    if not os.path.lexists(str(record.final)):
        return "absent"
    if is_path_alias(record.final) or not identity_matches(record.final, record.value["tree_identity"]):
        return "unknown"
    publication = record.value["publication"]
    if publication is None:
        return "unknown"
    try:
        executable_parts = _relative_parts(publication["executable"], "executable path")
        executable = record.final.joinpath(*executable_parts)
        with AnchoredDirectory(
            record.final,
            expected_identity=record.value["tree_identity"],
        ) as final_tree:
            installed = load_installed_manifest(record.paths, record.final / "manifest.json")
            unused_manifest_size, manifest_digest, unused_manifest_identity = final_tree.file_evidence(
                ("manifest.json",)
            )
            executable_size, executable_digest, unused_executable_identity = final_tree.file_evidence(executable_parts)
            final_tree.assert_bound(record.value["tree_identity"])
    except (ArchiveError, OSError, IntegrityError) as error:
        # Exact immutable manifest and executable evidence define a valid final tree.
        raise IntegrityError("invalid recovered installation: %s" % record.final) from error
    if (
        installed.executable != executable
        or installed.asset_name != record.value["artifact"]["asset_name"]
        or installed.sha256 != record.value["artifact"]["sha256"]
        or installed.platform != record.value["artifact"]["platform"]
        or installed.executable_sha256 != publication["executable_sha256"]
        or manifest_digest != publication["manifest_sha256"]
        or executable_size != publication["executable_size"]
        or executable_digest != publication["executable_sha256"]
    ):
        return "unknown"
    if not identity_matches(record.final, record.value["tree_identity"]):
        raise IntegrityError("installed tree changed during validation: %s" % record.final)
    return "identity"


def _require_final_identity(record):
    if not identity_matches(record.final, record.value["tree_identity"]):
        raise IntegrityError("installed tree changed before authority disposal: %s" % record.final)


def _advance_committed(record):
    _require_record_authority(record)
    record.value["phase"] = "committed"
    _publish_record(record, lambda: secrets.token_hex(16))
    record.phase = "committed"


def preflight_install_record(record):
    # type: (InstallRecoveryRecord) -> tuple
    """Classify one install record completely without mutating recovery state."""

    if not isinstance(record, InstallRecoveryRecord) or record.kind != "install":
        raise IntegrityError("invalid install recovery record")
    staging, staging_identity = _classify_staging(record)
    final = _verify_final(record)
    phase = record.phase
    if phase == "prepared":
        if final != "absent" or staging not in ("absent", "empty"):
            raise IntegrityError("unknown prepared install recovery evidence: %s" % record.journal)
        return staging, staging_identity, final
    if phase in ("extracting", "validated") and staging in ("identity", "absent") and final == "absent":
        return staging, staging_identity, final
    if phase == "validated" and staging == "absent" and final == "identity":
        return staging, staging_identity, final
    if phase == "committed" and staging == "absent" and final == "identity":
        return staging, staging_identity, final
    raise IntegrityError(  # pragma: no cover - strict preflight exhausts every accepted row
        "unknown install recovery evidence: %s" % record.journal
    )


def _recover_record(record):
    staging, staging_identity, final = preflight_install_record(record)
    phase = record.phase
    if phase == "prepared":
        if staging == "empty":
            _remove_staging(record, staging_identity)
        _dispose_record(record)
        return
    if phase in ("extracting", "validated") and staging == "identity" and final == "absent":
        _remove_staging(record, staging_identity)
        _dispose_record(record)
        return
    if phase in ("extracting", "validated") and staging == "absent" and final == "absent":
        _require_record_authority(record)
        flush_directory(record.staging.parent)
        _dispose_record(record)
        return
    if phase == "validated" and staging == "absent" and final == "identity":
        _require_record_authority(record)
        flush_directory(record.final.parent)
        _advance_committed(record)
        _require_final_identity(record)
        _dispose_record(record)
        return
    if phase == "committed" and staging == "absent" and final == "identity":
        _require_final_identity(record)
        _dispose_record(record)
        return


def recover_install_transactions(paths):
    # type: (JerryProxyPaths) -> None
    """Recover every preflighted install journal in lexical operation order."""

    records, orphan_temporaries = _scan_install_recovery(paths)
    for record in records:
        _recover_record(record)
    for temporary, identity in orphan_temporaries:
        _dispose_file(paths, temporary, identity)


class InstallTransaction(InstallRecoveryRecord):
    """Small manager-facing API for one immutable installation publication."""

    def __init__(self, paths, journal, value, write_id):
        record = _validate_record(paths, journal, value, value["operation"])
        super(InstallTransaction, self).__init__(paths, journal, record.value)
        self._write_id = write_id

    @classmethod
    def prepare(cls, paths, backend, version, artifact, operation=None, write_id=None):
        # type: (JerryProxyPaths, str, str, dict, Optional[str], Optional[Callable]) -> "InstallTransaction"
        """Publish recovery intent before any installation staging mutation."""

        operation = _operation_id(operation or secrets.token_hex(16))
        value = {
            "kind": "install",
            "operation": operation,
            "phase": "prepared",
            "backend": backend,
            "version": version,
            "staging": "backends/%s/.%s.install-%s" % (backend, version, operation),
            "final": "backends/%s/%s" % (backend, version),
            "tree_identity": None,
            "artifact": artifact,
            "publication": None,
        }
        journal = paths.runtimes / (".install-%s.json" % operation)
        transaction = cls(paths, journal, value, write_id or (lambda: secrets.token_hex(16)))
        if os.path.lexists(str(journal)):
            raise IntegrityError("install journal already exists: %s" % journal)
        _write_record(transaction)
        return transaction

    def begin_staging(self):
        # type: () -> Path
        """Create and identify the private tree before extraction begins."""

        _require_record_authority(self)
        try:
            with AnchoredDirectory(self.paths.backends) as backends:
                backends.ensure_directory((self.value["backend"],))
                tree_identity = backends.create_directory((self.value["backend"], self.staging.name))
        except ArchiveError as error:
            raise IntegrityError("unable to create anchored backend staging") from error
        self.value["tree_identity"] = tree_identity
        self.value["phase"] = "extracting"
        self.phase = "extracting"
        _write_record(self)
        return self.staging

    def mark_validated(self, publication, staging_anchor=None):
        # type: (dict, Optional[AnchoredDirectory]) -> None
        """Persist exact staged publication evidence before its public rename."""

        if self.phase != "extracting":
            raise IntegrityError("install staging changed before validation")
        _require_record_authority(self)
        if staging_anchor is None:
            if not identity_matches(self.staging, self.value["tree_identity"]):
                raise IntegrityError("install staging changed before validation")
            try:
                with AnchoredDirectory(
                    self.staging,
                    expected_identity=self.value["tree_identity"],
                ) as owned_staging:
                    owned_staging.flush_tree()
            except ArchiveError as error:
                raise IntegrityError("install staging changed before validation") from error
        else:
            if staging_anchor.root != self.staging:
                raise IntegrityError("install staging anchor does not match the transaction")
            try:
                staging_anchor.assert_bound(self.value["tree_identity"])
                staging_anchor.flush_tree()
            except ArchiveError as error:
                raise IntegrityError("install staging changed before validation") from error
        self.value["publication"] = _validate_publication(publication)
        self.value["phase"] = "validated"
        self.phase = "validated"
        _write_record(self)

    def commit(self):
        # type: () -> Path
        """Publish a validated immutable tree, verify it, and dispose intent."""

        if self.phase != "validated":
            raise IntegrityError("install transaction is not validated")
        _require_record_authority(self)
        if os.path.lexists(str(self.final)):
            raise IntegrityError("immutable installation destination already exists: %s" % self.final)
        if not identity_matches(self.staging, self.value["tree_identity"]):
            raise IntegrityError("install staging changed before publication")
        try:
            with AnchoredDirectory(self.paths.backends) as backends:
                backends.replace(
                    (self.value["backend"], self.staging.name),
                    (self.value["backend"], self.final.name),
                    expected_identity=self.value["tree_identity"],
                    replace_existing=False,
                )
        except ArchiveError as error:
            if isinstance(error.__cause__, FileExistsError):
                raise IntegrityError("immutable installation destination already exists: %s" % self.final) from error
            raise IntegrityError("unable to publish anchored immutable installation: %s" % self.final) from error
        record = InstallRecoveryRecord(self.paths, self.journal, self.value)
        if _verify_final(record) != "identity":
            raise IntegrityError("published installation failed static validation: %s" % self.final)
        self.value["phase"] = "committed"
        self.phase = "committed"
        _write_record(self)
        _require_final_identity(self)
        _dispose_record(self)
        return self.final
