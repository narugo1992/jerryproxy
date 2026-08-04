"""Public subscription orchestration built on the existing home lock."""

import secrets

from ..errors import SubscriptionError, SubscriptionFetchError, SubscriptionStateError
from ..lock import JerryProxyOperationLock
from .interfaces import SubscriptionParser
from .storage import SubscriptionStore, build_record, validate_subscription_name
from .transport import DEFAULT_SUBSCRIPTION_PARSER, fetch_subscription, validate_source_url


class SubscriptionManager(object):
    """Fetch, classify, publish, and inventory V2RAY_SUBSCRIPTION records."""

    def __init__(self, paths, session=None, parser=None):
        # type: (JerryProxyPaths, object, Optional[SubscriptionParser]) -> None
        self.paths = paths
        self.session = session
        self.parser = parser or DEFAULT_SUBSCRIPTION_PARSER
        if not isinstance(self.parser, SubscriptionParser):
            raise TypeError("parser must implement SubscriptionParser")
        self.store = SubscriptionStore(paths, parser=self.parser)

    def list(self):  # type: () -> tuple
        return self.store.list()

    def _list_locked(self):  # type: () -> tuple
        return self.store._list_locked()

    def get(self, name):  # type: (str) -> SubscriptionRecord
        return self.store.get(name)

    def _get_locked(self, name):  # type: (str) -> SubscriptionRecord
        return self.store._get_locked(name)

    @staticmethod
    def _source_body(source_url, body, format_hint, session, allow_http):
        if allow_http:
            raise SubscriptionFetchError("HTTP subscription sources cannot be persisted")
        if body is None:
            if not source_url:
                raise SubscriptionStateError("subscription source is required")
            fetched = fetch_subscription(source_url, session=session, allow_http=allow_http)
            return fetched.body, fetched.final_url, format_hint
        if not isinstance(body, bytes):
            raise TypeError("subscription body must be bytes")
        if source_url is not None:
            source_url = validate_source_url(source_url, allow_http=allow_http)
        return body, source_url, format_hint

    def add(self, name, source_url, body=None, format_hint="auto", allow_http=False):
        # type: (str, str, bytes, str, bool) -> SubscriptionRecord
        """Add one source after bounded transport and classification."""

        with JerryProxyOperationLock(self.paths):
            return self._add_locked(name, source_url, body, format_hint, allow_http)

    def _add_locked(self, name, source_url, body=None, format_hint="auto", allow_http=False):
        validate_subscription_name(name)
        body, source_url, format_hint = self._source_body(
            source_url, body, format_hint, self.session, allow_http
        )
        parsed = self.parser.parse(body, format_hint)
        record = build_record(name, secrets.token_hex(16), parsed, source_url=source_url)
        return self.store._publish_locked(record)

    def replace(self, name, source_url=None, body=None, format_hint="auto", allow_http=False):
        # type: (str, str, bytes, str, bool) -> SubscriptionRecord
        """Replace one source while retaining its public subscription ID."""

        with JerryProxyOperationLock(self.paths):
            return self._replace_locked(name, source_url, body, format_hint, allow_http)

    def _replace_locked(self, name, source_url=None, body=None, format_hint="auto", allow_http=False):
        validate_subscription_name(name)
        previous = self.store._get_locked(name)
        body, source_url, format_hint = self._source_body(
            source_url, body, format_hint, self.session, allow_http
        )
        parsed = self.parser.parse(body, format_hint)
        record = build_record(name, previous.subscription_id, parsed, source_url=source_url, previous=previous)
        return self.store._publish_locked(record, replace=True, expected_revision=previous.revision)

    def refresh(self, name):  # type: (str) -> SubscriptionRecord
        """Refresh the exact persisted URL and preserve the last good record on failure."""

        with JerryProxyOperationLock(self.paths):
            return self._refresh_locked(name)

    def _refresh_locked(self, name):  # type: (str) -> SubscriptionRecord
        previous = self.store._get_locked(name)
        if not previous.source_url:
            raise SubscriptionStateError("subscription has no remote source URL")
        return self._replace_locked(name, source_url=previous.source_url, format_hint="auto")

    def validate(self, name):  # type: (str) -> SubscriptionRecord
        """Re-parse the private source bytes without changing state."""

        if not self.paths._validate_existing_layout():
            raise SubscriptionStateError("subscription not found: %s" % name)
        with JerryProxyOperationLock(self.paths, initialize=False):
            return self._validate_locked(name)

    def _validate_locked(self, name):  # type: (str) -> SubscriptionRecord
        record = self.store._get_locked(name)
        parsed = self.parser.parse(record.body, record.format if record.format != "base64-uri-lines" else "auto")
        if len(parsed.records) != len(record.nodes):
            raise SubscriptionError("subscription validation changed node count")
        return record

    def remove(self, name):  # type: (str) -> SubscriptionRecord
        with JerryProxyOperationLock(self.paths):
            return self.store._remove_locked(name)
