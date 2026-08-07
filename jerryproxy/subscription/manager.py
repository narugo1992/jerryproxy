"""Public subscription orchestration built on the existing home lock."""

import base64
import json
import multiprocessing
import os
import secrets
import stat
import tempfile
import threading
import time

from ..backend.durable import flush_directory
from ..backend.removal import _secure_remove_tree
from ..errors import (
    SubscriptionError,
    SubscriptionFetchError,
    SubscriptionNodesMismatchError,
    SubscriptionParseError,
    SubscriptionStateError,
)
from ..lock import JerryProxyOperationLock
from .interfaces import SubscriptionParser
from .storage import SubscriptionStore, _require_node_projection, build_record, validate_subscription_name
from .transport import MIHOMO_SUBSCRIPTION_PARSER, FetchedSubscription, fetch_subscription, validate_source_url

_DEFAULT_FETCH_SUBSCRIPTION = fetch_subscription
_FETCH_WALL_SECONDS = 30.0
_FETCH_START_SECONDS = 5.0
_FETCH_STOP_SECONDS = 2.0
_FETCH_LATE_CLEANUP_SECONDS = 5.0
_FETCH_RESULT_MAXIMUM_BYTES = 16 * 1024 * 1024


def _fetch_process_alive(process):  # type: (object) -> bool
    if process is None:
        return False
    try:
        return bool(process.is_alive())
    except AssertionError:
        # multiprocessing rejects liveness checks during a late start; retain
        # the worker boundary until the supervising start thread settles.
        return True
    except (OSError, RuntimeError):
        # An unreadable liveness state is treated as alive for cleanup.
        return True


def _stop_fetch_process(process):  # type: (object) -> bool
    """Terminate, hard-kill, and join one worker within bounded intervals."""

    if not _fetch_process_alive(process):
        return True
    try:
        process.terminate()
    except (OSError, RuntimeError, AssertionError):
        pass
    try:
        process.join(_FETCH_STOP_SECONDS)
    except (OSError, RuntimeError, AssertionError):
        pass
    if _fetch_process_alive(process) and hasattr(process, "kill"):
        try:
            process.kill()
        except (OSError, RuntimeError, AssertionError):
            pass
        try:
            process.join(_FETCH_STOP_SECONDS)
        except (OSError, RuntimeError, AssertionError):
            pass
    return not _fetch_process_alive(process)


def _write_fetch_result(path, value):  # type: (str, dict) -> None
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(payload.encode("ascii")) > _FETCH_RESULT_MAXIMUM_BYTES:
        return
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        written = 0
        encoded = (payload + "\n").encode("ascii")
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                return
            written += count
        os.fsync(descriptor)
        flush_directory(os.path.dirname(path))
    except OSError:
        # The parent treats a missing result as a bounded worker failure.
        return
    finally:
        if descriptor != -1:
            os.close(descriptor)


class _FetchCleanupSupervisor(object):
    """Own bounded cleanup after a process start returns too late."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending = set()

    def register(self, startup_thread, process, runtime_root, temporary):  # type: (object, object, str, str) -> bool
        """Register one delayed starter and run its independent cleanup."""

        token = object()
        with self._lock:
            self._pending.add(token)
        worker = threading.Thread(
            target=self._cleanup,
            args=(token, startup_thread, process, runtime_root, temporary),
            name="jerryproxy-subscription-cleanup",
        )
        worker.daemon = True
        try:
            worker.start()
        except RuntimeError:
            # A host that rejects another thread cannot provide delayed cleanup;
            # retain the evidence for the caller's explicit recovery path.
            with self._lock:
                self._pending.discard(token)
            return False
        return True

    def _cleanup(self, token, startup_thread, process, runtime_root, temporary):
        deadline = time.monotonic() + _FETCH_LATE_CLEANUP_SECONDS
        completed = False
        try:
            while startup_thread is not None and startup_thread.is_alive():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                startup_thread.join(min(0.05, remaining))
            while not _stop_fetch_process(process):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                time.sleep(min(0.05, remaining))
            try:
                _secure_remove_tree(runtime_root, temporary, SubscriptionFetchError, private_names=True)
            except (OSError, SubscriptionFetchError):
                # Recovery evidence remains available when safe deletion fails.
                return
            completed = True
        finally:
            if completed:
                with self._lock:
                    self._pending.discard(token)


def _fetch_worker(url, result_path, allow_http, format_hint, start_gate, cancel_gate):
    # type: (str, str, bool, str, object, object) -> None
    """Fetch one source and publish only a strict private result envelope."""

    for name in tuple(os.environ):
        if "SUBSCRIPTION" in name.upper() or name.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            os.environ.pop(name, None)
    if not start_gate.wait(_FETCH_START_SECONDS) or cancel_gate.is_set():
        return
    try:
        fetched = fetch_subscription(url, allow_http=allow_http)
        MIHOMO_SUBSCRIPTION_PARSER.parse(fetched.body, format_hint=format_hint)
    except (SubscriptionFetchError, SubscriptionParseError, SubscriptionStateError, ValueError):
        # Transport failures are represented without carrying remote details.
        _write_fetch_result(result_path, {"error": "subscription source fetch failed", "ok": False})
        return
    _write_fetch_result(
        result_path,
        {
            "body": base64.b64encode(fetched.body).decode("ascii"),
            "final_url": fetched.final_url,
            "ok": True,
        },
    )


def _read_fetch_result(path):  # type: (str) -> object
    path = os.path.abspath(path)
    if os.path.islink(path) or not os.path.isfile(path):
        raise SubscriptionFetchError("subscription worker result is missing")
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise SubscriptionFetchError("subscription worker result is invalid")
        if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
            raise SubscriptionFetchError("subscription worker result has unsafe permissions")
        if status.st_size > _FETCH_RESULT_MAXIMUM_BYTES:
            raise SubscriptionFetchError("subscription worker result exceeds the size bound")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(_FETCH_RESULT_MAXIMUM_BYTES + 1)
    except OSError as error:
        # Result files are private worker state and must be readable after stop.
        raise SubscriptionFetchError("subscription worker result cannot be read") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(payload) > _FETCH_RESULT_MAXIMUM_BYTES:
        raise SubscriptionFetchError("subscription worker result exceeds the size bound")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        # A malformed worker envelope is an integrity failure at the boundary.
        raise SubscriptionFetchError("subscription worker result is invalid") from error
    if not isinstance(value, dict) or value.get("ok") is not True or set(value) != {"body", "final_url", "ok"}:
        if isinstance(value, dict) and value == {"error": "subscription source fetch failed", "ok": False}:
            raise SubscriptionFetchError("subscription source fetch failed")
        raise SubscriptionFetchError("subscription worker result is invalid")
    try:
        body = base64.b64decode(value["body"].encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        # The worker body must be one canonical Base64 envelope.
        raise SubscriptionFetchError("subscription worker result body is invalid") from error
    if len(body) > 8 * 1024 * 1024 or not isinstance(value["final_url"], str):
        raise SubscriptionFetchError("subscription worker result is invalid")
    try:
        final_url = validate_source_url(value["final_url"])
    except (SubscriptionFetchError, TypeError) as error:
        # A worker result must not smuggle an unvalidated bearer source URL.
        raise SubscriptionFetchError("subscription worker result URL is invalid") from error
    return body, final_url


class SubscriptionManager(object):
    """Fetch, classify, publish, and inventory V2RAY_SUBSCRIPTION records."""

    def __init__(self, paths, session=None, parser=None):
        # type: (JerryProxyPaths, object, Optional[SubscriptionParser]) -> None
        self.paths = paths
        self.session = session
        self.parser = parser or MIHOMO_SUBSCRIPTION_PARSER
        if not isinstance(self.parser, SubscriptionParser):
            raise TypeError("parser must implement SubscriptionParser")
        self.store = SubscriptionStore(paths, parser=self.parser)
        self._fetch_cleanup = _FetchCleanupSupervisor()

    def list(self, allow_node_mismatch=False):  # type: (bool) -> tuple
        return self.store.list(allow_node_mismatch=allow_node_mismatch)

    def _list_locked(self, allow_node_mismatch=False):  # type: (bool) -> tuple
        return self.store._list_locked(allow_node_mismatch=allow_node_mismatch)

    def get(self, name):  # type: (str) -> SubscriptionRecord
        return self.store.get(name)

    def _fetch_remote(self, source_url, allow_http, format_hint):  # type: (str, bool, str) -> object
        # Injected sessions and monkeypatched transports are deterministic test
        # boundaries; production's default transport runs in a spawned worker.
        if (
            self.session is not None
            or fetch_subscription is not _DEFAULT_FETCH_SUBSCRIPTION
            or self.parser is not MIHOMO_SUBSCRIPTION_PARSER
        ):
            return fetch_subscription(source_url, session=self.session, allow_http=allow_http)
        runtime_root = self.paths.runtimes
        # Worker artifacts are managed state; reject symlink/reparse aliases
        # before creating or traversing the runtime namespace.
        self.paths._ensure_directory(runtime_root, reject_alias=True)
        temporary = tempfile.mkdtemp(prefix=".subscription-fetch-", dir=str(runtime_root))
        result_path = os.path.join(temporary, "result.json")
        process = None
        operation_error = None
        startup_thread = None
        startup_done = None
        deadline = time.monotonic() + _FETCH_WALL_SECONDS
        cancel_gate = None
        preserve_worker_tree = False
        try:
            context = multiprocessing.get_context("spawn")
            start_gate = context.Event()
            cancel_gate = context.Event()
            process = context.Process(
                target=_fetch_worker,
                args=(source_url, result_path, allow_http, format_hint, start_gate, cancel_gate),
            )
            process.daemon = True
            startup_error = []
            startup_done = threading.Event()

            def start_worker():
                try:
                    process.start()
                except (OSError, RuntimeError) as error:
                    startup_error.append(error)
                finally:
                    startup_done.set()
                    if cancel_gate.is_set():
                        _stop_fetch_process(process)

            startup_thread = threading.Thread(target=start_worker, name="jerryproxy-subscription-start")
            startup_thread.daemon = True
            startup_thread.start()
            startup_budget = min(_FETCH_START_SECONDS, max(0.0, deadline - time.monotonic()))
            if not startup_done.wait(startup_budget):
                cancel_gate.set()
                _stop_fetch_process(process)
                startup_thread.join(_FETCH_STOP_SECONDS)
                # Only the cleanup block below may decide to retain the worker
                # tree.  Deciding it here would freeze a stale liveness reading:
                # a starter that finishes during the raise would leave a
                # secret-bearing tree that is neither deleted nor supervised.
                if startup_thread.is_alive():
                    raise SubscriptionFetchError("subscription source worker startup deadline exhausted")
                raise SubscriptionFetchError("subscription source worker startup failed")
            if startup_error:
                raise SubscriptionFetchError("subscription source worker failed") from startup_error[0]
            start_gate.set()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SubscriptionFetchError("subscription source worker deadline exhausted")
            process.join(remaining)
            if not _stop_fetch_process(process):
                raise SubscriptionFetchError("subscription source worker could not be stopped")
            if process.exitcode != 0:
                raise SubscriptionFetchError("subscription source worker failed")
            body, final_url = _read_fetch_result(result_path)
            return FetchedSubscription(body, final_url)
        except SubscriptionFetchError as error:
            operation_error = error
            raise
        except (OSError, RuntimeError) as error:
            # Worker construction failures are bounded source failures.
            operation_error = error
            raise SubscriptionFetchError("subscription source worker failed") from error
        finally:
            cleanup_error = None
            if startup_thread is not None and startup_thread.is_alive():
                if cancel_gate is not None:
                    cancel_gate.set()
                if not _stop_fetch_process(process):
                    cleanup_error = SubscriptionFetchError("subscription source worker could not be stopped")
                startup_thread.join(_FETCH_STOP_SECONDS)
                if startup_thread.is_alive():
                    preserve_worker_tree = True
                    registered = self._fetch_cleanup.register(
                        startup_thread,
                        process,
                        runtime_root,
                        temporary,
                    )
                    if not registered:
                        cleanup_error = SubscriptionFetchError(
                            "subscription source worker cleanup supervisor unavailable; recovery artifact retained"
                        )
                    else:
                        cleanup_error = SubscriptionFetchError(
                            "subscription source worker startup cleanup failed; recovery supervisor retained"
                        )
            elif process is not None and not _stop_fetch_process(process):
                preserve_worker_tree = True
                registered = self._fetch_cleanup.register(
                    None,
                    process,
                    runtime_root,
                    temporary,
                )
                if not registered:
                    cleanup_error = SubscriptionFetchError(
                        "subscription source worker cleanup supervisor unavailable; recovery artifact retained"
                    )
                else:
                    cleanup_error = SubscriptionFetchError(
                        "subscription source worker could not be stopped; recovery supervisor retained"
                    )
            if not preserve_worker_tree:
                try:
                    _secure_remove_tree(runtime_root, temporary, SubscriptionFetchError, private_names=True)
                except (OSError, SubscriptionFetchError) as error:
                    cleanup_error = SubscriptionFetchError("subscription worker cleanup failed")
                    cleanup_error.__cause__ = error
            if cleanup_error is not None:
                # Preserve a primary source failure; a successful operation must
                # fail rather than silently leave a secret-bearing worker tree.
                if operation_error is None:
                    raise cleanup_error
                raise SubscriptionFetchError(
                    "subscription source operation and worker cleanup failed (%s); recovery artifact retained"
                    % cleanup_error
                ) from operation_error

    def _source_body(self, source_url, body, format_hint, allow_http):
        if source_url is not None and body is not None:
            raise SubscriptionStateError("subscription source URL and body are mutually exclusive")
        if allow_http:
            raise SubscriptionFetchError("HTTP subscription sources cannot be persisted")
        if body is None:
            if not source_url:
                raise SubscriptionStateError("subscription source is required")
            source_url = validate_source_url(source_url, allow_http=allow_http)
            fetched = self._fetch_remote(source_url, allow_http, format_hint)
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
            source_url, body, format_hint, allow_http
        )
        parsed = self.parser.parse(body, format_hint)
        # Only node identities are reserved here, so an unrelated drifted
        # subscription must not block adding a new one.
        current_ids = {
            node.node_id
            for record in self.store._list_locked(allow_node_mismatch=True)
            for node in record.nodes
        }
        record = build_record(
            name,
            secrets.token_hex(16),
            parsed,
            source_url=source_url,
            paths=self.paths,
            reserved_ids=current_ids,
        )
        return self.store._publish_locked(record)

    def replace(self, name, source_url=None, body=None, format_hint="auto", allow_http=False):
        # type: (str, str, bytes, str, bool) -> SubscriptionRecord
        """Replace one source while retaining its public subscription ID."""

        with JerryProxyOperationLock(self.paths):
            return self._replace_locked(name, source_url, body, format_hint, allow_http)

    def _replace_locked(self, name, source_url=None, body=None, format_hint="auto", allow_http=False):
        validate_subscription_name(name)
        # Replacement discards the stored projection entirely and rebuilds it
        # from freshly parsed bytes, so it is the repair path for a drifted
        # record and must be able to read one.
        previous = self.store._get_locked(name, allow_node_mismatch=True)
        body_source = body is not None
        body, source_url, format_hint = self._source_body(
            source_url, body, format_hint, allow_http
        )
        parsed = self.parser.parse(body, format_hint)
        current_ids = {
            node.node_id
            for record in self.store._list_locked(allow_node_mismatch=True)
            if record.name != name
            for node in record.nodes
        }
        record = build_record(
            name,
            previous.subscription_id,
            parsed,
            source_url=source_url,
            previous=previous,
            retain_source_url=not body_source,
            paths=self.paths,
            reserved_ids=current_ids,
        )
        return self.store._publish_locked(record, replace=True, expected_revision=previous.revision)

    def refresh(self, name):  # type: (str) -> SubscriptionRecord
        """Refresh the exact persisted URL and preserve the last good record on failure.

        Refreshing is also the repair for a record whose stored node projection
        no longer matches its source bytes: the saved URL is fetched again and
        the projection is rebuilt, so the drifted generation is replaced rather
        than trusted.  A failed refresh leaves the previous generation intact.
        """

        with JerryProxyOperationLock(self.paths):
            return self._refresh_locked(name)

    def _refresh_locked(self, name):  # type: (str) -> SubscriptionRecord
        # Only the saved source URL is carried forward; the drifted projection
        # is discarded and rebuilt by the replacement below.
        previous = self.store._get_locked(name, allow_node_mismatch=True)
        if not previous.source_url:
            raise SubscriptionStateError(
                "subscription has no remote source URL: %s; "
                "run `jerryproxy subscription replace %s` to supply the source again" % (name, name)
            )
        return self._replace_locked(name, source_url=previous.source_url, format_hint="auto")

    def repair_node_projection(self, name):  # type: (str) -> SubscriptionRecord
        """Return one record, rebuilding a drifted node projection once.

        A consistent record is returned untouched and no source is contacted.
        A record whose stored nodes no longer match its source bytes is
        repaired by one refresh of the saved URL and then revalidated, so the
        caller always receives a strictly consistent record or an error naming
        the next command.  Tampering fails the keyed fingerprint earlier and is
        never repaired here.
        """

        with JerryProxyOperationLock(self.paths):
            return self._repair_node_projection_locked(name)

    def _repair_node_projection_locked(self, name):  # type: (str) -> SubscriptionRecord
        try:
            return self.store._get_locked(name)
        except SubscriptionNodesMismatchError:
            # Recoverable drift: rebuild from the saved source below.
            pass
        drifted = self.store._get_locked(name, allow_node_mismatch=True)
        if not drifted.source_url:
            raise SubscriptionStateError(
                "subscription nodes do not match source bytes: %s; it has no saved source URL, "
                "so run `jerryproxy subscription replace %s` to supply the source again" % (name, name)
            )
        try:
            repaired = self._refresh_locked(name)
        except SubscriptionError as error:
            # The previous generation is preserved.  Report the next action
            # rather than retrying a repair that already failed.
            raise SubscriptionStateError(
                "subscription nodes do not match source bytes: %s; refreshing its saved source failed, "
                "so run `jerryproxy subscription refresh %s` or replace the source" % (name, name)
            ) from error
        # Exactly one automatic repair: a projection that is still inconsistent
        # raises out of this call instead of refreshing again.
        _require_node_projection(repaired, self.parser)
        return repaired

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
