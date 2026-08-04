"""Private, lock-serialized subscription publication and inventory."""

import base64
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
_FORMATS = ("uri-lines", "base64-uri-lines")
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

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SubscriptionStateError("subscription state contains duplicate keys")
            value[key] = item
        return value

    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream, object_pairs_hook=reject_duplicates)
    except (OSError, ValueError) as error:
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
        parsed = parser.parse(body, format_hint="uri-lines")
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
        if existing is not None and not replace:
            raise SubscriptionStateError("subscription already exists: %s" % record.name)
        if expected_revision is not None and (existing is None or existing.revision != expected_revision):
            raise SubscriptionStateError("subscription changed during update")
        if existing is not None and existing.subscription_id != record.subscription_id:
            raise SubscriptionStateError("subscription identity changed during replacement")
        if existing is None and len(self._records_locked()) >= MAXIMUM_SUBSCRIPTIONS:
            raise SubscriptionStateError("subscription count exceeds the safety bound")
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


def build_record(name, subscription_id, parsed, source_url=None, previous=None):
    # type: (str, str, object, str, Optional[SubscriptionRecord]) -> SubscriptionRecord
    """Build a new record while reconciling exact URI identities."""

    previous_by_uri = {}
    if previous is not None:
        for node in previous.nodes:
            previous_by_uri.setdefault(node.uri, []).append(node.node_id)
    nodes = []
    occurrences = {}
    for scheme, display, uri in parsed.records:
        if len(display.encode("utf-8")) > _MAXIMUM_DISPLAY_BYTES:
            raise SubscriptionParseError("subscription node display is too long")
        if len(uri.encode("utf-8")) > _MAXIMUM_URI_BYTES:
            raise SubscriptionParseError("subscription node URI is too long")
        occurrence = occurrences.get(uri, 0)
        occurrences[uri] = occurrence + 1
        old_ids = previous_by_uri.get(uri, [])
        node_id = old_ids[occurrence] if occurrence < len(old_ids) else secrets.token_hex(16)
        nodes.append(NodeRecord(node_id, scheme, display, uri, occurrence))
    return SubscriptionRecord(
        name=name,
        subscription_id=previous.subscription_id if previous is not None else subscription_id,
        revision=source_digest(parsed.body),
        format=parsed.format,
        enabled=previous.enabled if previous is not None else True,
        updated_at=_now(),
        nodes=tuple(nodes),
        source_url=source_url if source_url is not None else (previous.source_url if previous else None),
        body=parsed.body,
    )
