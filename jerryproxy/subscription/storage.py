"""Private, lock-serialized subscription publication and inventory."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
import tempfile
from datetime import datetime, timezone

from ..backend.anchored import AnchoredDirectory
from ..backend.durable import flush_directory
from ..backend.identity import capture_identity, identity_matches, validate_identity
from ..backend.removal import _secure_remove_tree
from ..errors import (
    ArchiveError,
    IntegrityError,
    SubscriptionFetchError,
    SubscriptionNodesMismatchError,
    SubscriptionParseError,
    SubscriptionStateError,
)
from ..home import is_path_alias
from ..lock import JerryProxyOperationLock
from .interfaces import SubscriptionParser
from .model import NodeRecord, SubscriptionRecord
from .transport import (
    MAXIMUM_BODY_BYTES,
    MIHOMO_SUBSCRIPTION_PARSER,
    source_digest,
    validate_source_url,
)

MAXIMUM_SUBSCRIPTIONS = 64
_NAME_BYTES = 64
_ID_HEX = 32
_MAXIMUM_DISPLAY_BYTES = 512
_MAXIMUM_URI_BYTES = 16 * 1024
_MAXIMUM_STATE_BYTES = 16 * 1024 * 1024
_FORMATS = ("uri-lines", "base64-uri-lines")
_IDENTITY_KEY_BYTES = 32
_MAXIMUM_TOMBSTONES = 4096
_IDENTITY_FILE = "identity.key"
_TOMBSTONES_FILE = "tombstones.json"
_PUBLICATION_JOURNAL = ".publication.journal.json"
_HISTORY_PREFIX = ".history-"
_MAXIMUM_HISTORY = 8
_RECORD_KEYS = {
    "body",
    "enabled",
    "format",
    "id",
    "name",
    "nodes",
    "revision",
    "source_url",
    "updated_at",
}
_NODE_KEYS = {"display", "fingerprint", "id", "occurrence", "scheme", "uri"}


def _identity_path(paths):  # type: (object) -> object
    return paths.nodes / _IDENTITY_FILE


def _tombstones_path(paths):  # type: (object) -> object
    return paths.nodes / _TOMBSTONES_FILE


def _publication_journal_path(paths):  # type: (object) -> object
    return paths.subscriptions / _PUBLICATION_JOURNAL


def _quarantine_path(paths, operation):  # type: (object, str) -> object
    return paths.runtimes / (".subscription-remove-%s.json" % operation)


def _history_path(paths, record):  # type: (object, SubscriptionRecord) -> object
    return paths.subscriptions / (
        "%s%s-%s.json" % (_HISTORY_PREFIX, record.subscription_id, record.revision)
    )


def _is_history_path(path):  # type: (object) -> bool
    return path.name.startswith(_HISTORY_PREFIX) and path.suffix == ".json"


def _name_digest(name):  # type: (str) -> str
    return hashlib.sha256(name.encode("ascii")).hexdigest()


def _ensure_identity_key_locked(paths):  # type: (object) -> bytes
    """Create or read the home-local node identity key under the home lock."""

    _ensure_extension_directory(paths.nodes)
    path = _identity_path(paths)
    if is_path_alias(path):
        raise IntegrityError("node identity key is aliased")
    if path.exists():
        if not path.is_file():
            raise IntegrityError("node identity key is not a regular file")
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise IntegrityError("node identity key has unsafe permissions")
        try:
            value = path.read_bytes()
        except OSError as error:
            # The private identity key cannot be read safely.
            raise IntegrityError("node identity key cannot be read") from error
        if len(value) != _IDENTITY_KEY_BYTES:
            raise IntegrityError("node identity key has an invalid length")
        return value
    value = secrets.token_bytes(_IDENTITY_KEY_BYTES)
    descriptor = -1
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(
            str(path),
            flags,
            0o600,
        )
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                raise IntegrityError("node identity key write made no progress")
            written += count
        if os.fstat(descriptor).st_size != len(value):
            raise IntegrityError("node identity key has an invalid published length")
        os.fsync(descriptor)
        flush_directory(path.parent)
        return value
    except FileExistsError:
        # Another operation cannot win while the home lock is held; treat this
        # as an integrity failure rather than silently adopting an unknown key.
        raise IntegrityError("node identity key was created concurrently")
    except OSError as error:
        # Private key publication may fail through filesystem errors.
        raise IntegrityError("node identity key publication failed") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)


def _read_tombstones_locked(paths):  # type: (object) -> list
    """Read retained retired node IDs, treating absent state as empty."""

    path = _tombstones_path(paths)
    if not path.exists():
        return []
    if is_path_alias(path) or not path.is_file():
        raise IntegrityError("node tombstone state is invalid")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise IntegrityError("node tombstone state has unsafe permissions")
    try:
        value = _read_json(path)
    except SubscriptionStateError as error:
        # Tombstone corruption must fail closed before identity allocation.
        raise IntegrityError("node tombstone state cannot be read") from error
    entries = value.get("entries")
    if set(value) != {"entries"} or not isinstance(entries, list):
        raise IntegrityError("node tombstone state is invalid")
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "removed_at"}:
            raise IntegrityError("node tombstone entry is invalid")
        node_id = entry["id"]
        removed_at = entry["removed_at"]
        if (
            not isinstance(node_id, str)
            or len(node_id) != _ID_HEX
            or any(char not in "0123456789abcdef" for char in node_id)
            or not isinstance(removed_at, str)
        ):
            raise IntegrityError("node tombstone entry is invalid")
        result.append(entry)
    if len(result) > _MAXIMUM_TOMBSTONES:
        raise IntegrityError("node tombstone count exceeds the safety bound")
    return result


def _retire_node_ids_locked(paths, node_ids):  # type: (object, object) -> None
    """Reserve removed IDs before unlinking a subscription record."""

    if not node_ids:
        return
    entries = _read_tombstones_locked(paths)
    existing = {entry["id"] for entry in entries}
    now = _now()
    for node_id in node_ids:
        if node_id not in existing:
            entries.append({"id": node_id, "removed_at": now})
            existing.add(node_id)
    entries = entries[-_MAXIMUM_TOMBSTONES:]
    _write_json(_tombstones_path(paths), {"entries": entries})


def _unretire_node_ids_locked(paths, node_ids):  # type: (object, object) -> None
    """Undo a prepared removal when recovery restores the old record."""

    if not node_ids:
        return
    retired = set(node_ids)
    entries = _read_tombstones_locked(paths)
    retained = [entry for entry in entries if entry["id"] not in retired]
    if retained != entries:
        _write_json(_tombstones_path(paths), {"entries": retained})


def _canonical_node_bytes(subscription_id, format_name, scheme, display, uri, occurrence):
    # type: (str, str, str, str, str, int) -> bytes
    """Build a length-prefixed private reconciliation preimage."""

    fields = (
        subscription_id.encode("utf-8"),
        format_name.encode("utf-8"),
        scheme.encode("utf-8"),
        display.encode("utf-8"),
        uri.encode("utf-8"),
        str(occurrence).encode("ascii"),
    )
    return b"jerryproxy-node-fingerprint-v1\x00" + b"".join(
        struct.pack(">I", len(value)) + value for value in fields
    )


def _private_node_fingerprint(key, subscription_id, format_name, scheme, display, uri, occurrence):
    # type: (bytes, str, str, str, str, str, int) -> str
    """Return the private keyed identity used to reconcile one source node."""

    return hmac.new(
        key,
        _canonical_node_bytes(subscription_id, format_name, scheme, display, uri, occurrence),
        hashlib.sha256,
    ).hexdigest()


def _validate_record_identity_if_present(paths, record):  # type: (object, SubscriptionRecord) -> None
    identity_path = _identity_path(paths)
    if not identity_path.exists():
        if _tombstones_path(paths).exists() or any(node.fingerprint for node in record.nodes):
            raise IntegrityError("node identity key is missing while fingerprinted state exists")
        return
    key = _ensure_identity_key_locked(paths)
    for node in record.nodes:
        expected = _private_node_fingerprint(
            key,
            record.subscription_id,
            record.format,
            node.scheme,
            node.display,
            node.uri,
            node.occurrence,
        )
        if node.fingerprint != expected:
            raise IntegrityError("subscription node fingerprint does not match the home key")


def validate_subscription_name(name):  # type: (str) -> str
    if not isinstance(name, str) or not name or len(name.encode("ascii", "ignore")) != len(name):
        raise SubscriptionStateError("subscription name must be ASCII")
    if len(name.encode("ascii")) > _NAME_BYTES:
        raise SubscriptionStateError("subscription name is too long")
    if not (name[0].isalnum() and all(char.isalnum() or char in "_.-" for char in name)):
        raise SubscriptionStateError("subscription name is invalid")
    return name


def _now():
    return datetime.now(timezone.utc).isoformat()


def _ensure_extension_directory(path):  # type: (Path) -> None
    if is_path_alias(path):
        raise IntegrityError("managed subscription path is aliased: %s" % path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if is_path_alias(path) or not path.is_dir():
        raise IntegrityError("managed subscription path is invalid: %s" % path)
    if os.name == "posix":
        path.chmod(0o700)


def _read_json(path):  # type: (Path) -> dict
    if is_path_alias(path) or not path.is_file():
        raise SubscriptionStateError("subscription state file is invalid")
    try:
        if path.stat().st_size > _MAXIMUM_STATE_BYTES:
            raise SubscriptionStateError("subscription state exceeds the size bound")
    except OSError as error:
        # A state file whose metadata cannot be checked is not safe to parse.
        raise SubscriptionStateError("subscription state cannot be read") from error

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SubscriptionStateError("subscription state contains duplicate keys")
            value[key] = item
        return value

    try:
        with path.open("r", encoding="utf-8") as stream:
            payload = stream.read(_MAXIMUM_STATE_BYTES + 1)
        if len(payload.encode("utf-8")) > _MAXIMUM_STATE_BYTES:
            raise SubscriptionStateError("subscription state exceeds the size bound")
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        # Filesystem and JSON decoder failures identify corrupt private state.
        raise SubscriptionStateError("subscription state cannot be read") from error
    if not isinstance(value, dict):
        raise SubscriptionStateError("subscription state must be an object")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SubscriptionStateError("subscription state has unsafe permissions")
    return value


def _write_json(path, value):  # type: (Path, dict) -> None
    _ensure_extension_directory(path.parent)
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    temporary = None
    descriptor = -1
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="") as stream:
            descriptor = -1
            stream.write(payload)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
        temporary = None
        flush_directory(path.parent)
    except OSError as error:
        # Atomic private state publication may fail through filesystem errors.
        raise SubscriptionStateError("subscription state publication failed") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _write_publication_journal_locked(paths, value):  # type: (object, dict) -> None
    """Persist a non-secret generation journal before changing public state."""

    if value.get("kind") == "remove":
        # Removal journals must remain opaque: the quarantine contains the
        # private record needed for rollback, while this file contains only
        # public identity, object identity, and transaction state.
        allowed = {
            "kind",
            "operation",
            "phase",
            "quarantine_identity",
            "retired_at",
            "subscription_id",
        }
    else:
        allowed = {
            "kind",
            "name_digest",
            "new_revision",
            "old_revision",
            "operation",
            "phase",
            "quarantine_identity",
            "subscription_id",
        }
    if set(value) != allowed:
        raise IntegrityError("subscription publication journal has an invalid shape")
    _write_json(_publication_journal_path(paths), value)


def _read_publication_journal_locked(paths):  # type: (object) -> object
    path = _publication_journal_path(paths)
    if not path.exists():
        return None
    if is_path_alias(path) or not path.is_file():
        raise IntegrityError("subscription publication journal is invalid")
    try:
        value = _read_json(path)
    except SubscriptionStateError as error:
        # A journal is authoritative recovery state and cannot be ignored.
        raise IntegrityError("subscription publication journal cannot be read") from error
    if not isinstance(value, dict) or value.get("kind") not in ("publish", "remove"):
        raise IntegrityError("subscription publication journal has an invalid shape")
    if value["kind"] == "remove":
        required = {
            "kind",
            "operation",
            "phase",
            "quarantine_identity",
            "retired_at",
            "subscription_id",
        }
    else:
        required = {
            "kind",
            "name_digest",
            "new_revision",
            "old_revision",
            "operation",
            "phase",
            "quarantine_identity",
            "subscription_id",
        }
    if set(value) != required:
        raise IntegrityError("subscription publication journal has an invalid shape")
    if value["phase"] not in ("prepared", "committed"):
        raise IntegrityError("subscription publication journal has an invalid phase")
    for key in ("name_digest", "operation", "subscription_id"):
        if key == "name_digest" and value["kind"] == "remove":
            continue
        if not isinstance(value[key], str):
            raise IntegrityError("subscription publication journal has invalid identity")
    if value["kind"] == "publish" and (
        len(value["name_digest"]) != 64
        or any(char not in "0123456789abcdef" for char in value["name_digest"])
    ):
        raise IntegrityError("subscription publication journal has an invalid name identity")
    if len(value["operation"]) != 32 or any(char not in "0123456789abcdef" for char in value["operation"]):
        raise IntegrityError("subscription publication journal has an invalid operation identity")
    if len(value["subscription_id"]) != _ID_HEX or any(
        char not in "0123456789abcdef" for char in value["subscription_id"]
    ):
        raise IntegrityError("subscription publication journal has an invalid subscription identity")
    if value["kind"] == "remove":
        if not isinstance(value["retired_at"], str) or not value["retired_at"]:
            raise IntegrityError("subscription removal journal has an invalid retirement time")
        try:
            validate_identity(value["quarantine_identity"], expected_file_type="regular")
        except IntegrityError as error:
            raise IntegrityError("subscription removal journal has an invalid quarantine identity") from error
    elif value["quarantine_identity"] is not None:
        raise IntegrityError("subscription publication journal has an unexpected quarantine identity")
    if value["kind"] == "publish":
        for key in ("old_revision", "new_revision"):
            revision = value[key]
            if revision is not None and (
                not isinstance(revision, str)
                or len(revision) != 64
                or any(char not in "0123456789abcdef" for char in revision)
            ):
                raise IntegrityError("subscription publication journal has an invalid revision")
    return value


def _clear_publication_journal_locked(paths):  # type: (object) -> None
    path = _publication_journal_path(paths)
    if not path.exists():
        return
    if is_path_alias(path) or not path.is_file():
        raise IntegrityError("subscription publication journal is invalid")
    try:
        path.unlink()
        flush_directory(path.parent)
    except OSError as error:
        # Recovery evidence cannot be silently discarded after a mutation.
        raise IntegrityError("subscription publication journal cleanup failed") from error


def _record_path(paths, name):  # type: (JerryProxyPaths, str) -> Path
    return paths.subscriptions / (name + ".json")


def _capture_record_identity(path):  # type: (Path) -> dict
    if is_path_alias(path) or not path.is_file():
        raise IntegrityError("subscription record path is invalid")
    try:
        identity = capture_identity(path)
        validate_identity(identity, expected_file_type="regular")
        return identity
    except (IntegrityError, OSError) as error:
        # The record must remain an identity-pinned regular file at removal time.
        raise IntegrityError("subscription record identity cannot be captured") from error


def _stage_record_locked(paths, path, operation, expected_identity):  # type: (object, Path, str, dict) -> Path
    """Move one record into a private, identity-anchored quarantine."""

    quarantine = _quarantine_path(paths, operation)
    if is_path_alias(quarantine) or os.path.lexists(str(quarantine)):
        raise IntegrityError("subscription removal quarantine already exists")
    try:
        with AnchoredDirectory(paths.root, require_private_permissions=False) as anchored:
            anchored.replace(
                path.relative_to(paths.root).parts,
                quarantine.relative_to(paths.root).parts,
                expected_identity=expected_identity,
                replace_existing=False,
            )
    except (ArchiveError, IntegrityError, ValueError) as error:
        # The anchored primitive refuses path substitution and unsupported atomic moves.
        raise IntegrityError("subscription removal quarantine staging failed") from error
    try:
        if not identity_matches(quarantine, expected_identity):
            raise IntegrityError("subscription removal quarantine identity changed")
    except IntegrityError:
        raise
    return quarantine


def _restore_record_locked(paths, quarantine, expected_identity, parser):  # type: (object, Path, dict, SubscriptionParser) -> SubscriptionRecord
    """Restore a quarantined record without copying or replacing a target."""

    if is_path_alias(quarantine) or not quarantine.is_file():
        raise IntegrityError("subscription removal quarantine is invalid")
    # Rollback restores the exact quarantined bytes and only reads the record's
    # name and node identities, so recoverable projection drift must not strand
    # an interrupted removal.  The journal identity match proves these are the
    # bytes this transaction isolated, and the keyed fingerprint check proves
    # the node identities about to be unretired are this home's own.
    record = _record_from_value(_read_json(quarantine), parser=parser, allow_node_mismatch=True)
    if not identity_matches(quarantine, expected_identity):
        raise IntegrityError("subscription removal quarantine identity changed")
    _validate_record_identity_if_present(paths, record)
    destination = _record_path(paths, record.name)
    if os.path.lexists(str(destination)):
        raise IntegrityError("subscription removal rollback destination already exists")
    try:
        with AnchoredDirectory(paths.root, require_private_permissions=False) as anchored:
            anchored.replace(
                quarantine.relative_to(paths.root).parts,
                destination.relative_to(paths.root).parts,
                expected_identity=expected_identity,
                replace_existing=False,
            )
    except (ArchiveError, IntegrityError, ValueError) as error:
        # The anchored primitive rejects aliases, substitution, and overwrite races.
        raise IntegrityError("subscription removal rollback failed") from error
    if not identity_matches(destination, expected_identity):
        raise IntegrityError("subscription removal rollback identity changed")
    return record


def _remove_quarantine_locked(paths, operation, expected_identity):  # type: (object, str, dict) -> None
    quarantine = _quarantine_path(paths, operation)
    if not os.path.lexists(str(quarantine)):
        return
    try:
        removed = _secure_remove_tree(
            paths.runtimes,
            quarantine,
            IntegrityError,
            expected_identity=expected_identity,
            private_names=True,
        )
        if removed:
            flush_directory(quarantine.parent)
    except IntegrityError:
        raise
    except OSError as error:
        # Committed removal retains its quarantine when physical cleanup fails.
        raise SubscriptionStateError("subscription removal quarantine cleanup failed") from error


def _node_mismatch_error(name):  # type: (str) -> SubscriptionNodesMismatchError
    """Report recoverable drift together with the command that repairs it.

    The name has already passed :func:`validate_subscription_name`, so it is
    bounded ASCII and safe to render.  No source bytes, URL, or node material
    is included.
    """

    return SubscriptionNodesMismatchError(
        "subscription nodes do not match source bytes: %s; "
        "run `jerryproxy subscription refresh %s` to rebuild them" % (name, name)
    )


def _node_from_value(value):  # type: (dict) -> NodeRecord
    required = ("id", "scheme", "display", "uri", "occurrence", "fingerprint")
    if not isinstance(value, dict) or any(key not in value for key in required):
        raise SubscriptionStateError("subscription node state is incomplete")
    if set(value) != _NODE_KEYS:
        raise SubscriptionStateError("subscription node state contains unknown keys")
    node_id = value["id"]
    if not isinstance(node_id, str) or len(node_id) != _ID_HEX or any(
        char not in "0123456789abcdef" for char in node_id
    ):
        raise SubscriptionStateError("subscription node identity is invalid")
    if not isinstance(value["scheme"], str) or value["scheme"] not in ("ss", "vmess", "vless"):
        raise SubscriptionStateError("subscription node scheme is invalid")
    if not isinstance(value["display"], str) or not value["display"]:
        raise SubscriptionStateError("subscription node state is invalid")
    if len(value["display"].encode("utf-8")) > _MAXIMUM_DISPLAY_BYTES:
        raise SubscriptionStateError("subscription node display is too long")
    fingerprint = value["fingerprint"]
    if not isinstance(fingerprint, str) or len(fingerprint) != 64 or any(
        char not in "0123456789abcdef" for char in fingerprint
    ):
        raise SubscriptionStateError("subscription node fingerprint is invalid")
    if not isinstance(value["uri"], str) or not value["uri"]:
        raise SubscriptionStateError("subscription node URI state is invalid")
    if len(value["uri"].encode("utf-8")) > _MAXIMUM_URI_BYTES:
        raise SubscriptionStateError("subscription node URI is too long")
    occurrence = value["occurrence"]
    if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence < 0:
        raise SubscriptionStateError("subscription node occurrence is invalid")
    return NodeRecord(node_id, value["scheme"], value["display"], value["uri"], occurrence, fingerprint)


def _record_from_value(value, parser=None, allow_node_mismatch=False):
    # type: (dict, Optional[SubscriptionParser], bool) -> SubscriptionRecord
    """Validate one durable record, optionally tolerating node-projection drift.

    ``allow_node_mismatch`` relaxes exactly one check: the fresh reparse of the
    digest-protected source bytes no longer has to reproduce the stored node
    projection.  Every other check in this function still applies, and every
    caller pairs it with :func:`_validate_record_identity_if_present`, whose
    keyed per-node fingerprint means a tolerant read cannot accept node content
    this home never wrote for this subscription and format.  That fingerprint
    is per node: it does not attest the order, completeness, or revision of the
    node list, so a tolerant read is only safe where the caller does not
    consume node semantics.
    """

    required = ("name", "id", "revision", "format", "enabled", "updated_at", "body", "nodes")
    if not isinstance(value, dict) or any(key not in value for key in required):
        raise SubscriptionStateError("subscription state is incomplete")
    if set(value) != _RECORD_KEYS:
        raise SubscriptionStateError("subscription state contains unknown keys")
    validate_subscription_name(value["name"])
    if not isinstance(value["id"], str) or len(value["id"]) != _ID_HEX or any(
        char not in "0123456789abcdef" for char in value["id"]
    ):
        raise SubscriptionStateError("subscription identity is invalid")
    if not isinstance(value["revision"], str) or len(value["revision"]) != 64:
        raise SubscriptionStateError("subscription revision is invalid")
    if not isinstance(value["body"], str):
        raise SubscriptionStateError("subscription source bytes are invalid")
    try:
        body = base64.b64decode(value["body"].encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        # Decoder errors identify corrupt private source bytes.
        raise SubscriptionStateError("subscription source bytes are invalid") from error
    if len(body) > MAXIMUM_BODY_BYTES or source_digest(body) != value["revision"]:
        raise SubscriptionStateError("subscription revision digest does not match source bytes")
    if value["format"] not in _FORMATS:
        raise SubscriptionStateError("subscription format is invalid")
    if not isinstance(value["enabled"], bool):
        raise SubscriptionStateError("subscription enabled flag is invalid")
    if not isinstance(value["updated_at"], str):
        raise SubscriptionStateError("subscription timestamp is invalid")
    try:
        timestamp = datetime.fromisoformat(value["updated_at"])
    except ValueError as error:
        # Invalid ISO-8601 timestamps identify corrupt private state.
        raise SubscriptionStateError("subscription timestamp is invalid") from error
    if timestamp.tzinfo is None:
        raise SubscriptionStateError("subscription timestamp has no timezone")
    if not isinstance(value["nodes"], list) or not value["nodes"]:
        raise SubscriptionStateError("subscription has no node records")
    nodes = tuple(_node_from_value(item) for item in value["nodes"])
    node_ids = [node.node_id for node in nodes]
    if len(set(node_ids)) != len(node_ids):
        raise SubscriptionStateError("subscription node identities are duplicated")
    expected_occurrences = {}
    for node in nodes:
        expected = expected_occurrences.get(node.uri, 0)
        if node.occurrence != expected:
            raise SubscriptionStateError("subscription node occurrence is invalid")
        expected_occurrences[node.uri] = expected + 1
    source_url = value.get("source_url")
    if source_url is not None and not isinstance(source_url, str):
        raise SubscriptionStateError("subscription source URL is invalid")
    if source_url is not None:
        try:
            source_url = validate_source_url(source_url)
        except (SubscriptionFetchError, TypeError, ValueError) as error:
            # State URL validation must not reclassify malformed private state
            # as a network transport error.
            raise SubscriptionStateError("subscription source URL is invalid") from error
    parser = parser or MIHOMO_SUBSCRIPTION_PARSER
    try:
        parsed = parser.parse(
            body,
            format_hint="auto" if value["format"] == "base64-uri-lines" else "uri-lines",
        )
    except (SubscriptionFetchError, SubscriptionParseError, SubscriptionStateError, ValueError) as error:
        # The digest-protected source must remain parseable before its private
        # node projection can be trusted.
        raise SubscriptionStateError("subscription source bytes cannot be revalidated") from error
    if not allow_node_mismatch and tuple(parsed.records) != tuple(
        (node.scheme, node.display, node.uri) for node in nodes
    ):
        raise _node_mismatch_error(value["name"])
    return SubscriptionRecord(
        value["name"],
        value["id"],
        value["revision"],
        value["format"],
        value["enabled"],
        timestamp.astimezone(timezone.utc).isoformat(),
        nodes,
        source_url,
        body,
    )


def _require_node_projection(record, parser):  # type: (SubscriptionRecord, SubscriptionParser) -> None
    """Reject a record whose stored projection no longer matches its source.

    This repeats the strict half of :func:`_record_from_value` for a record
    that was already read tolerantly, so a caller can locate one subscription
    among drifted neighbours and still refuse to consume a drifted selection.
    """

    try:
        parsed = parser.parse(
            record.body,
            format_hint="auto" if record.format == "base64-uri-lines" else "uri-lines",
        )
    except (SubscriptionFetchError, SubscriptionParseError, SubscriptionStateError, ValueError) as error:
        # A tolerant read already accepted these bytes; a parse failure here is
        # still corrupt private state rather than recoverable drift.
        raise SubscriptionStateError("subscription source bytes cannot be revalidated") from error
    if tuple(parsed.records) != tuple((node.scheme, node.display, node.uri) for node in record.nodes):
        raise _node_mismatch_error(record.name)


def _record_value(record):  # type: (SubscriptionRecord) -> dict
    return {
        "body": base64.b64encode(record.body).decode("ascii"),
        "enabled": bool(record.enabled),
        "format": record.format,
        "id": record.subscription_id,
        "name": record.name,
        "nodes": [
            {
                "display": node.display,
                "fingerprint": node.fingerprint,
                "id": node.node_id,
                "occurrence": node.occurrence,
                "scheme": node.scheme,
                "uri": node.uri,
            }
            for node in record.nodes
        ],
        "revision": record.revision,
        "source_url": record.source_url,
        "updated_at": record.updated_at,
    }


def _materialize_record_fingerprints_locked(paths, record):  # type: (object, SubscriptionRecord) -> SubscriptionRecord
    """Attach private fingerprints before a record enters durable state."""

    key = _ensure_identity_key_locked(paths)
    nodes = []
    changed = False
    for node in record.nodes:
        expected = _private_node_fingerprint(
            key,
            record.subscription_id,
            record.format,
            node.scheme,
            node.display,
            node.uri,
            node.occurrence,
        )
        if node.fingerprint and node.fingerprint != expected:
            raise IntegrityError("subscription node fingerprint does not match the home key")
        fingerprint = node.fingerprint or expected
        changed = changed or fingerprint != node.fingerprint
        nodes.append(NodeRecord(node.node_id, node.scheme, node.display, node.uri, node.occurrence, fingerprint))
    if not changed:
        return record
    return SubscriptionRecord(
        record.name,
        record.subscription_id,
        record.revision,
        record.format,
        record.enabled,
        record.updated_at,
        tuple(nodes),
        record.source_url,
        record.body,
    )


def _history_records_locked(paths, parser):  # type: (object, object) -> list
    """Read and validate bounded last-good generations in the private namespace.

    History entries are addressed by subscription ID and revision, are never
    returned to a caller, and are only inventoried or pruned, so their node
    projection is always read tolerantly.  Repairing a drifted subscription
    archives the drifted generation it replaced; a strict read here would let
    that archive break every later inventory of an already repaired home.  The
    keyed fingerprint check below still rejects foreign state.
    """

    if not paths.subscriptions.exists():
        return []
    result = []
    for path in sorted(paths.subscriptions.iterdir(), key=lambda item: item.name):
        if not _is_history_path(path):
            continue
        if is_path_alias(path) or not path.is_file():
            raise IntegrityError("subscription history entry is invalid")
        identity = path.stem[len(_HISTORY_PREFIX) :]
        parts = identity.split("-", 1)
        if len(parts) != 2 or len(parts[0]) != _ID_HEX or len(parts[1]) != 64:
            raise IntegrityError("subscription history filename is invalid")
        if any(char not in "0123456789abcdef" for char in parts[0] + parts[1]):
            raise IntegrityError("subscription history filename is invalid")
        record = _record_from_value(_read_json(path), parser=parser, allow_node_mismatch=True)
        _validate_record_identity_if_present(paths, record)
        if record.subscription_id != parts[0] or record.revision != parts[1]:
            raise IntegrityError("subscription history identity does not match its filename")
        result.append(record)
    return result


def _remove_history_for_id_locked(paths, subscription_id):  # type: (object, str) -> None
    prefix = "%s%s-" % (_HISTORY_PREFIX, subscription_id)
    if not paths.subscriptions.exists():
        return
    for path in tuple(paths.subscriptions.iterdir()):
        if not path.name.startswith(prefix) or not _is_history_path(path):
            continue
        if is_path_alias(path) or not path.is_file():
            raise IntegrityError("subscription history entry is invalid")
        try:
            path.unlink()
        except OSError as error:
            # Removal must not leave an untracked secret-bearing generation.
            raise SubscriptionStateError("subscription history cleanup failed") from error
    flush_directory(paths.subscriptions)


def _remove_history_record_locked(paths, record):  # type: (object, SubscriptionRecord) -> None
    """Remove one exact rollback generation after a recovery decision."""

    path = _history_path(paths, record)
    if not path.exists():
        return
    if is_path_alias(path) or not path.is_file():
        raise IntegrityError("subscription history entry is invalid")
    try:
        path.unlink()
        flush_directory(path.parent)
    except OSError as error:
        # Recovery cannot discard a secret-bearing rollback generation
        # without durable evidence that the unlink completed.
        raise IntegrityError("subscription history cleanup failed") from error


def _prune_history_locked(paths, subscription_id, parser):  # type: (object, str, object) -> None
    entries = [item for item in _history_records_locked(paths, parser) if item.subscription_id == subscription_id]
    entries.sort(key=lambda item: item.updated_at, reverse=True)
    for record in entries[_MAXIMUM_HISTORY:]:
        path = _history_path(paths, record)
        try:
            path.unlink()
        except OSError as error:
            # History pruning is part of the locked publication operation.
            raise SubscriptionStateError("subscription history pruning failed") from error
    if entries[_MAXIMUM_HISTORY:]:
        flush_directory(paths.subscriptions)


class SubscriptionStore(object):
    """Lock-aware store for current subscription generations."""

    def __init__(self, paths, parser=None):  # type: (JerryProxyPaths, Optional[SubscriptionParser]) -> None
        self.paths = paths
        self.parser = parser or MIHOMO_SUBSCRIPTION_PARSER
        if not isinstance(self.parser, SubscriptionParser):
            raise TypeError("parser must implement SubscriptionParser")

    def _records_without_recovery_locked(self, allow_node_mismatch=False):  # type: (bool) -> list
        if not self.paths.subscriptions.exists():
            return []
        if is_path_alias(self.paths.subscriptions) or not self.paths.subscriptions.is_dir():
            raise IntegrityError("subscription namespace is invalid")
        records = []
        try:
            entries = sorted(self.paths.subscriptions.iterdir(), key=lambda item: item.name)
        except OSError as error:
            # A private inventory directory that cannot be enumerated is not
            # safe to interpret as an empty subscription set.
            raise IntegrityError("subscription namespace cannot be enumerated") from error
        for path in entries:
            if path.name == _PUBLICATION_JOURNAL or _is_history_path(path):
                continue
            if is_path_alias(path) or not path.is_file() or path.suffix != ".json":
                raise IntegrityError("subscription namespace contains unexpected content")
            # Read tolerantly, then classify in order of severity: the keyed
            # fingerprint decides tampering before the reparse decides drift,
            # so forged node content can never be reported as recoverable or
            # be answered with a repair instruction.
            record = _record_from_value(_read_json(path), parser=self.parser, allow_node_mismatch=True)
            _validate_record_identity_if_present(self.paths, record)
            if not allow_node_mismatch:
                _require_node_projection(record, self.parser)
            if path.stem != record.name:
                raise SubscriptionStateError("subscription filename does not match its name")
            records.append(record)
        if len(records) > MAXIMUM_SUBSCRIPTIONS:
            raise SubscriptionStateError("subscription count exceeds the safety bound")
        return records

    def _recover_publication_journal_locked(self):  # type: () -> None
        journal = _read_publication_journal_locked(self.paths)
        if journal is None:
            return
        # Journal recovery compares subscription IDs, name digests, and
        # revisions only.  Mandatory recovery runs on every acquired lock, so a
        # recoverable node-projection drift must never make it unreachable.
        records = self._records_without_recovery_locked(allow_node_mismatch=True)
        if journal["kind"] == "publish":
            matches = [
                record
                for record in records
                if record.subscription_id == journal["subscription_id"]
                and _name_digest(record.name) == journal["name_digest"]
            ]
            if len(matches) > 1:
                raise IntegrityError("subscription publication journal matches multiple records")
            current_revision = matches[0].revision if matches else None
            old_revision = journal["old_revision"]
            new_revision = journal["new_revision"]
            allowed = (new_revision,) if journal["phase"] == "committed" else (old_revision, new_revision)
            if current_revision not in allowed:
                raise IntegrityError("subscription publication journal has an ambiguous current generation")
        else:
            matches = [record for record in records if record.subscription_id == journal["subscription_id"]]
            if len(matches) > 1:
                raise IntegrityError("subscription removal journal matches multiple records")
            current = matches[0] if matches else None
            quarantine = _quarantine_path(self.paths, journal["operation"])
            quarantine_exists = os.path.lexists(str(quarantine))
            if quarantine_exists:
                if is_path_alias(quarantine) or not quarantine.is_file():
                    raise IntegrityError("subscription removal quarantine is invalid")
                if not identity_matches(quarantine, journal["quarantine_identity"]):
                    raise IntegrityError("subscription removal quarantine identity changed")
            if journal["phase"] == "committed":
                if current is not None:
                    raise IntegrityError("subscription removal journal has an ambiguous current generation")
                _remove_quarantine_locked(
                    self.paths,
                    journal["operation"],
                    journal["quarantine_identity"],
                )
                _remove_history_for_id_locked(self.paths, journal["subscription_id"])
            else:
                if current is not None:
                    if quarantine_exists:
                        raise IntegrityError("subscription removal journal has ambiguous public and quarantine state")
                    rollback = current
                else:
                    if not quarantine_exists:
                        raise IntegrityError("subscription removal journal has no rollback quarantine")
                    rollback = _restore_record_locked(
                        self.paths,
                        quarantine,
                        journal["quarantine_identity"],
                        self.parser,
                    )
                _unretire_node_ids_locked(self.paths, [node.node_id for node in rollback.nodes])
                if quarantine_exists:
                    _remove_quarantine_locked(
                        self.paths,
                        journal["operation"],
                        journal["quarantine_identity"],
                    )
        _clear_publication_journal_locked(self.paths)

    def _records_locked(self, allow_node_mismatch=False):  # type: (bool) -> list
        self._recover_publication_journal_locked()
        records = self._records_without_recovery_locked(allow_node_mismatch=allow_node_mismatch)
        _history_records_locked(self.paths, self.parser)
        return records

    def _list_locked(self, allow_node_mismatch=False):  # type: (bool) -> tuple
        """Read records while the caller owns the home-wide operation lock."""

        return tuple(self._records_locked(allow_node_mismatch=allow_node_mismatch))

    def list(self, allow_node_mismatch=False):  # type: (bool) -> tuple
        """Read all records without creating an absent home.

        ``allow_node_mismatch`` returns records whose stored node projection
        drifted from their source bytes.  Callers that render only
        credential-free record metadata use it so one drifted record cannot
        hide the whole inventory; callers that consume node semantics must not.
        """

        if not self.paths._validate_existing_layout():
            return ()
        with JerryProxyOperationLock(self.paths, initialize=False):
            return self._list_locked(allow_node_mismatch=allow_node_mismatch)

    def _get_locked(self, name, allow_node_mismatch=False):  # type: (str, bool) -> SubscriptionRecord
        validate_subscription_name(name)
        # Other subscriptions are only enumerated to locate this one, so their
        # projection drift must not mask the requested record.  The selected
        # record itself is revalidated strictly unless the caller opts out.
        for record in self._records_locked(allow_node_mismatch=True):
            if record.name == name:
                if not allow_node_mismatch:
                    _require_node_projection(record, self.parser)
                return record
        raise SubscriptionStateError("subscription not found: %s" % name)

    def get(self, name):  # type: (str) -> SubscriptionRecord
        validate_subscription_name(name)
        if not self.paths._validate_existing_layout():
            raise SubscriptionStateError("subscription not found: %s" % name)
        with JerryProxyOperationLock(self.paths, initialize=False):
            return self._get_locked(name)

    def _publish_locked(self, record, replace=False, expected_revision=None):
        # type: (SubscriptionRecord, bool, Optional[str]) -> SubscriptionRecord
        """Publish while the caller owns the home-wide operation lock."""

        record = _materialize_record_fingerprints_locked(self.paths, record)
        validate_subscription_name(record.name)
        _ensure_extension_directory(self.paths.subscriptions)
        path = _record_path(self.paths, record.name)
        existing = None
        if path.exists():
            # The generation being replaced contributes only its revision and
            # identity to this transaction, so publication must stay available
            # while its projection is drifted and awaiting repair.
            existing = _record_from_value(_read_json(path), parser=self.parser, allow_node_mismatch=True)
            _validate_record_identity_if_present(self.paths, existing)
        if existing is not None and not replace:
            raise SubscriptionStateError("subscription already exists: %s" % record.name)
        if expected_revision is not None and (existing is None or existing.revision != expected_revision):
            raise SubscriptionStateError("subscription changed during update")
        if existing is not None and existing.subscription_id != record.subscription_id:
            raise SubscriptionStateError("subscription identity changed during replacement")
        # The safety bound counts records; a drifted neighbour still occupies a
        # slot and must not turn an unrelated publication into a hard failure.
        if existing is None and len(self._records_locked(allow_node_mismatch=True)) >= MAXIMUM_SUBSCRIPTIONS:
            raise SubscriptionStateError("subscription count exceeds the safety bound")
        _validate_record_identity_if_present(self.paths, record)
        if existing is not None and existing.revision != record.revision:
            _write_json(_history_path(self.paths, existing), _record_value(existing))
        journal = {
            "kind": "publish",
            "name_digest": _name_digest(record.name),
            "new_revision": record.revision,
            "old_revision": existing.revision if existing is not None else None,
            "operation": secrets.token_hex(16),
            "phase": "prepared",
            "quarantine_identity": None,
            "subscription_id": record.subscription_id,
        }
        _write_publication_journal_locked(self.paths, journal)
        _write_json(path, _record_value(record))
        journal["phase"] = "committed"
        _write_publication_journal_locked(self.paths, journal)
        _clear_publication_journal_locked(self.paths)
        _prune_history_locked(self.paths, record.subscription_id, self.parser)
        return record

    def publish(self, record, replace=False, expected_revision=None):
        # type: (SubscriptionRecord, bool, Optional[str]) -> SubscriptionRecord
        """Atomically publish a current record under the home-wide lock."""

        with JerryProxyOperationLock(self.paths):
            return self._publish_locked(record, replace=replace, expected_revision=expected_revision)

    def _remove_locked(self, name):  # type: (str) -> SubscriptionRecord
        validate_subscription_name(name)
        path = _record_path(self.paths, name)
        if not path.exists():
            raise SubscriptionStateError("subscription not found: %s" % name)
        # Removal retires this record's node identities and discards it, so a
        # drifted projection must remain deletable rather than permanent.  The
        # keyed fingerprint check still applies: retiring a forged identity
        # would let foreign state reserve this home's node ID space.
        record = _record_from_value(_read_json(path), parser=self.parser, allow_node_mismatch=True)
        _validate_record_identity_if_present(self.paths, record)
        record_identity = _capture_record_identity(path)
        operation = secrets.token_hex(16)
        journal = {
            "kind": "remove",
            "operation": operation,
            "phase": "prepared",
            "quarantine_identity": record_identity,
            "retired_at": _now(),
            "subscription_id": record.subscription_id,
        }
        _write_publication_journal_locked(self.paths, journal)
        # The quarantined record is the rollback generation.  Keeping a second
        # history copy would duplicate secret-bearing bytes and complicate
        # prepared recovery without adding authority.
        _retire_node_ids_locked(self.paths, [node.node_id for node in record.nodes])
        _stage_record_locked(self.paths, path, operation, record_identity)
        journal["phase"] = "committed"
        _write_publication_journal_locked(self.paths, journal)
        # Keep the rollback generation until the committed marker is durable;
        # a hard exit before that marker must still be able to restore it.
        _remove_history_for_id_locked(self.paths, record.subscription_id)
        _remove_quarantine_locked(self.paths, operation, record_identity)
        _clear_publication_journal_locked(self.paths)
        return record

    def remove(self, name):  # type: (str) -> SubscriptionRecord
        """Remove one private record under the operation lock."""

        with JerryProxyOperationLock(self.paths):
            return self._remove_locked(name)


def build_record(
    name,
    subscription_id,
    parsed,
    source_url=None,
    previous=None,
    retain_source_url=True,
    paths=None,
    reserved_ids=None,
):
    # type: (str, str, object, Optional[str], Optional[SubscriptionRecord], bool, object, object) -> SubscriptionRecord
    """Build a new record while reconciling exact URI identities."""

    nodes = []
    identity_key = _ensure_identity_key_locked(paths) if paths is not None else None
    record_subscription_id = previous.subscription_id if previous is not None else subscription_id
    previous_by_fingerprint = {}
    previous_by_uri = {}
    if previous is not None:
        for node in previous.nodes:
            previous_by_uri.setdefault(node.uri, []).append(node.node_id)
            if node.fingerprint:
                previous_by_fingerprint.setdefault(node.fingerprint, []).append(node.node_id)
    reserved = set(reserved_ids or ())
    if paths is not None:
        reserved.update(entry["id"] for entry in _read_tombstones_locked(paths))
    occurrences = {}
    for scheme, display, uri in parsed.records:
        if len(display.encode("utf-8")) > _MAXIMUM_DISPLAY_BYTES:
            raise SubscriptionParseError("subscription node display is too long")
        if len(uri.encode("utf-8")) > _MAXIMUM_URI_BYTES:
            raise SubscriptionParseError("subscription node URI is too long")
        occurrence = occurrences.get(uri, 0)
        occurrences[uri] = occurrence + 1
        fingerprint = (
            _private_node_fingerprint(
                identity_key,
                record_subscription_id,
                parsed.format,
                scheme,
                display,
                uri,
                occurrence,
            )
            if identity_key is not None
            else ""
        )
        old_ids = previous_by_fingerprint.get(fingerprint, []) if fingerprint else previous_by_uri.get(uri, [])
        if occurrence < len(old_ids):
            node_id = old_ids[occurrence]
        else:
            node_id = None
            # Public IDs are independent random 128-bit values.  The private
            # fingerprint above is the reconciliation key; it must never be
            # recoverable from the public node identity.
            for _ in range(16):
                candidate = secrets.token_hex(16)
                if candidate not in reserved and all(item.node_id != candidate for item in nodes):
                    node_id = candidate
                    break
            if node_id is None:
                raise IntegrityError("subscription node identity collision limit exceeded")
        reserved.add(node_id)
        nodes.append(NodeRecord(node_id, scheme, display, uri, occurrence, fingerprint))
    return SubscriptionRecord(
        name=name,
        subscription_id=previous.subscription_id if previous is not None else subscription_id,
        revision=source_digest(parsed.body),
        format=parsed.format,
        enabled=previous.enabled if previous is not None else True,
        updated_at=_now(),
        nodes=tuple(nodes),
        source_url=(
            source_url
            if source_url is not None
            else (previous.source_url if previous is not None and retain_source_url else None)
        ),
        body=parsed.body,
    )
