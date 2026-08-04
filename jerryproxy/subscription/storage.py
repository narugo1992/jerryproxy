"""Private, lock-serialized subscription publication and inventory."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
from datetime import datetime, timezone

from ..backend.durable import flush_directory
from ..errors import IntegrityError, SubscriptionFetchError, SubscriptionParseError, SubscriptionStateError
from ..home import is_path_alias
from ..lock import JerryProxyOperationLock
from .interfaces import SubscriptionParser
from .model import NodeRecord, SubscriptionRecord
from .transport import (
    DEFAULT_SUBSCRIPTION_PARSER,
    MAXIMUM_BODY_BYTES,
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
_NODE_KEYS = {"display", "id", "occurrence", "scheme", "uri"}


def _identity_path(paths):  # type: (object) -> object
    return paths.nodes / _IDENTITY_FILE


def _tombstones_path(paths):  # type: (object) -> object
    return paths.nodes / _TOMBSTONES_FILE


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


def _canonical_node_bytes(scheme, display, uri, occurrence):  # type: (str, str, str, int) -> bytes
    value = {
        "display": display,
        "occurrence": occurrence,
        "scheme": scheme,
        "uri": uri,
    }
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _derive_node_id(key, scheme, display, uri, occurrence, ordinal=0):
    preimage = b"jerryproxy-node-v1\x00" + _canonical_node_bytes(scheme, display, uri, occurrence)
    if ordinal:
        preimage += b"\x00collision-%d" % ordinal
    return hmac.new(key, preimage, hashlib.sha256).hexdigest()[:_ID_HEX]


def _node_id_matches(key, node):  # type: (bytes, NodeRecord) -> bool
    for ordinal in range(17):
        if _derive_node_id(
            key,
            node.scheme,
            node.display,
            node.uri,
            node.occurrence,
            ordinal=ordinal,
        ) == node.node_id:
            return True
    return False


def _validate_record_identity_if_present(paths, record):  # type: (object, SubscriptionRecord) -> None
    identity_path = _identity_path(paths)
    if not identity_path.exists():
        if _tombstones_path(paths).exists():
            raise IntegrityError("node identity key is missing while tombstones exist")
        return
    key = _ensure_identity_key_locked(paths)
    if any(not _node_id_matches(key, node) for node in record.nodes):
        raise IntegrityError("subscription node identity does not match the home key")


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


def _record_path(paths, name):  # type: (JerryProxyPaths, str) -> Path
    return paths.subscriptions / (name + ".json")


def _node_from_value(value):  # type: (dict) -> NodeRecord
    required = ("id", "scheme", "display", "uri", "occurrence")
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
    if not isinstance(value["uri"], str) or not value["uri"]:
        raise SubscriptionStateError("subscription node URI state is invalid")
    if len(value["uri"].encode("utf-8")) > _MAXIMUM_URI_BYTES:
        raise SubscriptionStateError("subscription node URI is too long")
    occurrence = value["occurrence"]
    if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence < 0:
        raise SubscriptionStateError("subscription node occurrence is invalid")
    return NodeRecord(node_id, value["scheme"], value["display"], value["uri"], occurrence)


def _record_from_value(value, parser=None):  # type: (dict, Optional[SubscriptionParser]) -> SubscriptionRecord
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
    parser = parser or DEFAULT_SUBSCRIPTION_PARSER
    try:
        parsed = parser.parse(
            body,
            format_hint="auto" if value["format"] == "base64-uri-lines" else "uri-lines",
        )
    except (SubscriptionFetchError, SubscriptionParseError, SubscriptionStateError, ValueError) as error:
        # The digest-protected source must remain parseable before its private
        # node projection can be trusted.
        raise SubscriptionStateError("subscription source bytes cannot be revalidated") from error
    expected = tuple(parsed.records)
    actual = tuple((node.scheme, node.display, node.uri) for node in nodes)
    if actual != expected:
        raise SubscriptionStateError("subscription nodes do not match source bytes")
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


class SubscriptionStore(object):
    """Lock-aware store for current subscription generations."""

    def __init__(self, paths, parser=None):  # type: (JerryProxyPaths, Optional[SubscriptionParser]) -> None
        self.paths = paths
        self.parser = parser or DEFAULT_SUBSCRIPTION_PARSER
        if not isinstance(self.parser, SubscriptionParser):
            raise TypeError("parser must implement SubscriptionParser")

    def _records_locked(self):  # type: () -> list
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
            if is_path_alias(path) or not path.is_file() or path.suffix != ".json":
                raise IntegrityError("subscription namespace contains unexpected content")
            record = _record_from_value(_read_json(path), parser=self.parser)
            _validate_record_identity_if_present(self.paths, record)
            if path.stem != record.name:
                raise SubscriptionStateError("subscription filename does not match its name")
            records.append(record)
        if len(records) > MAXIMUM_SUBSCRIPTIONS:
            raise SubscriptionStateError("subscription count exceeds the safety bound")
        return records

    def _list_locked(self):  # type: () -> tuple
        """Read records while the caller owns the home-wide operation lock."""

        return tuple(self._records_locked())

    def list(self):  # type: () -> tuple
        """Read all records without creating an absent home."""

        if not self.paths._validate_existing_layout():
            return ()
        with JerryProxyOperationLock(self.paths, initialize=False):
            return self._list_locked()

    def _get_locked(self, name):  # type: (str) -> SubscriptionRecord
        validate_subscription_name(name)
        for record in self._records_locked():
            if record.name == name:
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

        validate_subscription_name(record.name)
        _ensure_extension_directory(self.paths.subscriptions)
        path = _record_path(self.paths, record.name)
        existing = None
        if path.exists():
            existing = _record_from_value(_read_json(path), parser=self.parser)
            _validate_record_identity_if_present(self.paths, existing)
        if existing is not None and not replace:
            raise SubscriptionStateError("subscription already exists: %s" % record.name)
        if expected_revision is not None and (existing is None or existing.revision != expected_revision):
            raise SubscriptionStateError("subscription changed during update")
        if existing is not None and existing.subscription_id != record.subscription_id:
            raise SubscriptionStateError("subscription identity changed during replacement")
        if existing is None and len(self._records_locked()) >= MAXIMUM_SUBSCRIPTIONS:
            raise SubscriptionStateError("subscription count exceeds the safety bound")
        _validate_record_identity_if_present(self.paths, record)
        _write_json(path, _record_value(record))
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
        record = _record_from_value(_read_json(path), parser=self.parser)
        # Retire identities before removing the public record.  A crash between
        # this journal-like publication and unlink is harmless: the old record
        # remains readable and the ID is conservatively never reused.
        _retire_node_ids_locked(self.paths, [node.node_id for node in record.nodes])
        try:
            path.unlink()
            flush_directory(path.parent)
        except OSError as error:
            # Removing a private record may fail through filesystem errors.
            raise SubscriptionStateError("subscription removal failed") from error
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

    previous_by_uri = {}
    if previous is not None:
        for node in previous.nodes:
            previous_by_uri.setdefault(node.uri, []).append(node.node_id)
    nodes = []
    identity_key = _ensure_identity_key_locked(paths) if paths is not None else None
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
        old_ids = previous_by_uri.get(uri, [])
        if occurrence < len(old_ids):
            node_id = old_ids[occurrence]
        elif identity_key is None:
            node_id = secrets.token_hex(16)
        else:
            node_id = None
            for ordinal in range(17):
                candidate = _derive_node_id(
                    identity_key,
                    scheme,
                    display,
                    uri,
                    occurrence,
                    ordinal=ordinal,
                )
                if candidate not in reserved and all(item.node_id != candidate for item in nodes):
                    node_id = candidate
                    break
            if node_id is None:
                raise IntegrityError("subscription node identity collision limit exceeded")
        reserved.add(node_id)
        nodes.append(NodeRecord(node_id, scheme, display, uri, occurrence))
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
