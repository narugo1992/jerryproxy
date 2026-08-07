"""Synchronous foreground runtime ownership, health checks, and recovery."""

import json
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ..backend.durable import flush_directory
from ..backend.manager import BackendManager
from ..backend.removal import _secure_remove_tree
from ..errors import (
    BackendNotInstalledError,
    JerryProxyError,
    RuntimeSessionError,
    SubscriptionError,
    SubscriptionNodesMismatchError,
    SubscriptionStateError,
)
from ..home import is_path_alias
from ..lock import JerryProxyOperationLock
from ..subscription import SubscriptionManager
from ..subscription.interfaces import NodeSource
from ..subscription.redaction import redact_text, terminal_safe_text
from ..subscription.storage import _ensure_extension_directory, _require_node_projection
from ..subscription.transport import MIHOMO_SUBSCRIPTION_PARSER
from .health import ConnectivityProbe, RecoveryDeadline, RecoveryPolicy
from .interfaces import RuntimeDriver
from .mihomo import (
    LISTENER_ADDRESSES,
    LISTENER_PROTOCOLS,
    MAXIMUM_LOG_BYTES,
    QUALIFIED_VERSION,
    MihomoDriver,
    _private_bytes,
    reserve_loopback_port,
)

_LOG_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_SESSION_ID = re.compile(r"^[0-9a-f]{32}$")


def _token_urlsafe(byte_count):  # type: (int) -> str
    return secrets.token_urlsafe(byte_count).rstrip("=")


def _remove_private_tree(root):  # type: (object) -> None
    """Remove an owned session tree without following aliases."""

    root = Path(os.path.abspath(str(root)))
    _secure_remove_tree(root.parent, root, RuntimeSessionError, private_names=True)


def _parse_timestamp(value):  # type: (str) -> datetime
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        # A malformed private timestamp is invalid state, not a stale source.
        raise SubscriptionStateError("subscription timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise SubscriptionStateError("subscription timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


class RuntimeSession(object):
    """One foreground Mihomo session with bounded recovery.

    Automatic recovery is intentionally in-memory.  The user's selected node
    remains the saved preference; a successful failover changes only this
    foreground session's effective node and never rewrites subscription state.
    """

    def __init__(
        self,
        paths,
        manager=None,
        backend_version=None,
        relay=None,
        relay_url=None,
        relay_pattern=None,
        log_level="INFO",
        backend_log_level="INFO",
        authenticate=False,
        session_id=None,
        health_probe=None,
        recovery_policy=None,
        process_factory=None,
        subscription_manager=None,
        clock=None,
        sleeper=None,
        driver=None,
        listener_protocol="mixed",
        log_sink=None,
        preferred_port=None,
        strict_port=False,
        bind_address="127.0.0.1",
    ):
        self.paths = paths
        self.manager = manager or BackendManager(paths)
        self.subscription_manager = subscription_manager or SubscriptionManager(paths)
        if driver is not None and process_factory is not None:
            raise TypeError("driver and process_factory are mutually exclusive")
        self.driver = driver or MihomoDriver(process_factory=process_factory)
        if not isinstance(self.driver, RuntimeDriver):
            raise TypeError("driver must implement RuntimeDriver")
        self.backend_version = backend_version or QUALIFIED_VERSION
        if listener_protocol not in LISTENER_PROTOCOLS:
            raise ValueError("unsupported local proxy protocol")
        self.listener_protocol = listener_protocol
        if bind_address not in LISTENER_ADDRESSES:
            raise ValueError("unsupported listener bind address")
        self.bind_address = bind_address
        if preferred_port is not None and (
            not isinstance(preferred_port, int)
            or isinstance(preferred_port, bool)
            or not 1 <= preferred_port <= 65535
        ):
            raise ValueError("preferred port is outside the TCP port range")
        if not isinstance(strict_port, bool):
            raise ValueError("strict_port must be a boolean")
        self.preferred_port = preferred_port
        self.strict_port = strict_port
        self.relay = relay
        self.relay_url = relay_url
        self.relay_pattern = relay_pattern
        self.log_level = log_level
        self.backend_log_level = str(backend_log_level).upper()
        if not isinstance(authenticate, bool):
            raise ValueError("authenticate must be a boolean")
        self.authenticate = authenticate
        self.log_level = str(log_level).upper()
        if self.log_level not in _LOG_LEVELS:
            raise ValueError("unsupported JerryProxy log level")
        if self.backend_log_level not in ("OFF", "DEBUG", "INFO", "WARN", "ERROR"):
            raise ValueError("unsupported backend log level")
        self.log_sink = log_sink
        self.session_id = session_id or secrets.token_hex(16)
        if not isinstance(self.session_id, str) or not _SESSION_ID.fullmatch(self.session_id):
            raise ValueError("session_id must be 32 lowercase hexadecimal characters")
        self.session_root = self.paths.leases / self.session_id
        # Mihomo's safe-path policy permits file providers only below its
        # private XDG configuration home.  Keep that directory inside the
        # session lease so no user-global config can influence the child.
        self.provider_path = self.session_root / "xdg-config" / "mihomo" / "provider.txt"
        self.config_path = self.session_root / "config.yaml"
        self.access_path = self.session_root / "access.json"
        self.access_staging_path = self.session_root / ".access.pending.json"
        # Keep UTC startup time in the filename while retaining the session id
        # to avoid collisions when sessions start within the same second.
        started_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.log_path = self.paths.logs / ("runtime-%s-%s.log" % (started_at, self.session_id))
        self.port = None
        self.username = None
        self.password = None
        self.process = None
        self.executable = None
        self.node = None
        self.subscription = None
        self.preference_node_id = None
        self.health_probe = health_probe or ConnectivityProbe(protocol=listener_protocol)
        self.recovery_policy = recovery_policy or RecoveryPolicy()
        self.clock = clock or time.monotonic
        self.sleeper = sleeper or time.sleep
        self._health_failures = 0
        self._next_health_at = None
        self._cooldowns = {}
        self._operation_lock = None
        self._log_file_lock = threading.Lock()
        self._log_errors = []
        self.last_health = None
        self._startup_health_failure_logged = False

    def _append_log_line(self, source, level, message):
        safe = terminal_safe_text(redact_text(" ".join(str(message).split())))[:4096]
        if not safe:
            return
        if source == "jerryproxy":
            line = ("[%s] %s\n" % (level, safe)).encode("utf-8", "replace")
        else:
            line = ("[%s] %s\n" % (source, safe)).encode("utf-8", "replace")
        descriptor = -1
        try:
            with self._log_file_lock:
                _ensure_extension_directory(self.log_path.parent)
                if is_path_alias(self.log_path):
                    raise RuntimeSessionError("runtime log path is aliased")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(str(self.log_path), flags, 0o600)
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode):
                    raise RuntimeSessionError("runtime log path is not a regular file")
                if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
                    raise RuntimeSessionError("runtime log path has unsafe permissions")
                if status.st_size < MAXIMUM_LOG_BYTES:
                    os.write(descriptor, line[: MAXIMUM_LOG_BYTES - status.st_size])
        except (OSError, RuntimeSessionError, ValueError) as error:
            # Logging must not interrupt proxy service; retain a bounded error.
            if len(self._log_errors) < 8:
                self._log_errors.append(redact_text(error)[:1024])
        finally:
            if descriptor != -1:
                os.close(descriptor)

    def _log(self, level, message):
        normalized = str(level).upper()
        if normalized not in _LOG_LEVELS or _LOG_LEVELS[normalized] < _LOG_LEVELS[self.log_level]:
            return
        self._append_log_line("jerryproxy", normalized, message)
        if self.log_sink is not None:
            try:
                self.log_sink("jerryproxy", normalized, redact_text(message))
            except (OSError, ValueError):
                # The caller's terminal may close while the foreground child runs.
                pass

    def _enter_operation_lock(self):
        """Own the home-wide lock for the complete foreground session."""

        if self._operation_lock is not None:
            return
        platform_info = getattr(self.manager, "platform_info", None)
        lock = JerryProxyOperationLock(self.paths, platform_info=platform_info)
        lock.__enter__()
        self._operation_lock = lock

    def _leave_operation_lock(self):
        lock = self._operation_lock
        self._operation_lock = None
        if lock is not None:
            lock.__exit__(None, None, None)

    def _locked_records(self, allow_node_mismatch=False):  # type: (bool) -> tuple
        """Read the inventory through the session's already-held home lock."""

        list_locked = getattr(self.subscription_manager, "_list_locked", None)
        if list_locked is None:
            return tuple(self.subscription_manager.list())
        return tuple(list_locked(allow_node_mismatch=allow_node_mismatch))

    def _check_node_projection(self, record):  # type: (object) -> None
        """Reject a record whose stored projection drifted from its source."""

        parser = getattr(self.subscription_manager, "parser", None) or MIHOMO_SUBSCRIPTION_PARSER
        _require_node_projection(record, parser)

    def _locked_refresh(self, name):  # type: (str) -> object
        refresh_locked = getattr(self.subscription_manager, "_refresh_locked", None)
        if refresh_locked is None:
            return self.subscription_manager.refresh(name)
        return refresh_locked(name)

    def _locked_repair(self, name):  # type: (str) -> object
        """Repair one drifted projection through the already-held home lock."""

        repair_locked = getattr(self.subscription_manager, "_repair_node_projection_locked", None)
        if repair_locked is None:
            return self.subscription_manager.repair_node_projection(name)
        return repair_locked(name)

    def _select_subscription(self, name=None):
        # Neighbouring records are only enumerated to choose one, so their node
        # projection drift must not decide which subscription this session gets.
        records = self._locked_records(allow_node_mismatch=True)
        if name is not None:
            for record in records:
                if record.name == name:
                    if not record.enabled:
                        raise SubscriptionStateError("subscription is disabled: %s" % name)
                    return self._resolve_subscription(record)
            raise SubscriptionStateError("subscription not found: %s" % name)
        enabled = [record for record in records if record.enabled]
        if len(enabled) != 1:
            if not enabled:
                raise SubscriptionStateError("no enabled subscription is available")
            raise SubscriptionStateError("multiple subscriptions require --subscription NAME")
        return self._resolve_subscription(enabled[0])

    def _resolve_subscription(self, record):  # type: (object) -> object
        """Return a strictly revalidated record, repairing one node drift.

        A stored projection can stop matching its source bytes after a parser
        upgrade even though nothing was tampered with.  That state would
        otherwise block every start, so the manager's single repair path
        refreshes the saved source once and revalidates the result.  Tampering
        fails the keyed home fingerprint earlier and never reaches this path.
        """

        try:
            self._check_node_projection(record)
            return record
        except SubscriptionNodesMismatchError:
            # Recoverable drift: rebuild the projection from the saved source.
            pass
        self._log(
            "WARN",
            "subscription %s no longer matches its source bytes; refreshing the saved source once"
            % terminal_safe_text(record.name),
        )
        repaired = self._locked_repair(record.name)
        self._log("INFO", "subscription %s refreshed; continuing startup" % terminal_safe_text(record.name))
        return repaired

    @staticmethod
    def _select_node(record, node_id=None):
        if not isinstance(record, NodeSource):
            raise SubscriptionStateError("selected source does not expose a node collection")
        nodes = tuple(record.iter_nodes())
        if node_id is not None:
            for node in nodes:
                if node.node_id == node_id:
                    return node
            # A repaired or refreshed projection reissues node identities, so
            # name the command that lists the current ones.  A direct-node
            # source has no subscription to list and keeps the plain message.
            source_name = getattr(record, "name", None)
            if not source_name:
                raise SubscriptionStateError("node not found: %s" % node_id)
            raise SubscriptionStateError(
                "node not found: %s; run `jerryproxy node list %s` for current node identities"
                % (node_id, source_name)
            )
        if len(nodes) != 1:
            raise SubscriptionStateError("multiple nodes require --node NODE_ID")
        return nodes[0]

    def _prepare_paths(self):
        _ensure_extension_directory(self.paths.leases)
        _ensure_extension_directory(self.paths.logs)
        _ensure_extension_directory(self.session_root)
        for path in (self.paths.leases, self.paths.logs, self.session_root):
            if is_path_alias(path):
                raise RuntimeSessionError("runtime path is aliased")

    def _write_access(self):
        if self.authenticate:
            self.username = _token_urlsafe(16)
            self.password = _token_urlsafe(32)
        else:
            self.username = None
            self.password = None
        value = {
            "session": self.session_id,
            "backend": self.driver.name,
            "backend_version": self.backend_version,
            "controller": None,
            "authentication": self.authenticate,
            "listeners": [
                {
                    "kind": self.listener_protocol,
                    "protocol": self.listener_protocol,
                    "address": self.bind_address,
                    "port": self.port,
                    "primary": True,
                    "authentication": self.authenticate,
                    "username": self.username,
                    "password": self.password,
                }
            ],
            "platform": "windows" if os.name == "nt" else "posix",
        }
        _private_bytes(
            self.access_staging_path,
            (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            boundary=self.session_root,
        )

    def _publish_access(self):
        if is_path_alias(self.access_staging_path) or is_path_alias(self.access_path):
            raise RuntimeSessionError("runtime access path is aliased")
        try:
            os.replace(str(self.access_staging_path), str(self.access_path))
            flush_directory(self.session_root)
        except OSError as error:
            # Access publication is the final readiness boundary.
            raise RuntimeSessionError("runtime access publication failed") from error

    def _write_projection(self):
        projection = self.driver.projection(
            self.provider_path,
            self.node,
            self.port,
            self.username,
            self.password,
            listener_protocol=self.listener_protocol,
            backend_log_level=self.backend_log_level,
            bind_address=self.bind_address,
        )
        if projection.provider is not None:
            _private_bytes(self.provider_path, projection.provider, boundary=self.session_root)
        _private_bytes(self.config_path, projection.config, boundary=self.session_root)

    def _resolve_executable(self, install_missing):
        which_locked = getattr(self.manager, "_which_locked", None)
        try:
            if which_locked is not None:
                installed = which_locked(self.driver.name, self.backend_version)
            else:
                installed = self.manager.which(self.driver.name, self.backend_version)
        except BackendNotInstalledError:
            # A missing exact backend is the only bootstrap condition.
            if not install_missing:
                raise
            install_locked = getattr(self.manager, "_install_locked", None)
            if install_locked is not None:
                installed = install_locked(
                    self.driver.name,
                    self.backend_version,
                    activate=False,
                    relay=self.relay,
                    relay_url=self.relay_url,
                    relay_pattern=self.relay_pattern,
                )
            else:
                installed = self.manager.install(
                    self.driver.name,
                    self.backend_version,
                    activate=False,
                    relay=self.relay,
                    relay_url=self.relay_url,
                    relay_pattern=self.relay_pattern,
                )
        self.executable = installed.executable
        return self.executable

    def _stop_process(self, deadline=None):
        process = self.process
        if process is None:
            return
        try:
            timeout = None
            if deadline is not None:
                timeout = max(0.01, min(2.0, deadline.remaining()))
            self.driver.stop(process, timeout=timeout)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            # Process termination failures are terminal recovery failures.
            raise RuntimeSessionError("mihomo backend cleanup failed") from error
        self.process = None

    def _launch_node(self, node, deadline=None):
        self.node = node
        self._write_projection()
        try:
            process_options = {
                "backend_log_level": self.backend_log_level,
            }
            if self.log_sink is not None:
                process_options["log_sink"] = self.log_sink
            self.process = self.driver.create_process(
                self.executable,
                self.config_path,
                self.session_root,
                self.log_path,
                **process_options
            )
            set_log_lock = getattr(self.process, "set_log_lock", None)
            if set_log_lock is not None:
                set_log_lock(self._log_file_lock)
            set_readiness_challenge = getattr(self.process, "set_readiness_challenge", None)
            if set_readiness_challenge is not None:
                set_readiness_challenge(
                    self.username,
                    self.password,
                    self.listener_protocol,
                    self.bind_address,
                )
            self.process.start()
            if deadline is not None:
                remaining = deadline.remaining()
                if remaining <= 0:
                    raise RuntimeSessionError("proxy recovery deadline exhausted")
                self.driver.wait_ready(self.process, self.port, timeout=min(5.0, remaining))
            else:
                self.driver.wait_ready(self.process, self.port, timeout=5.0)
        except (OSError, RuntimeSessionError) as error:
            # The caller decides whether this candidate is recoverable; no raw
            # backend diagnostics cross this boundary.
            self.process = None if self.process is None else self.process
            raise RuntimeSessionError("mihomo backend candidate failed to start") from error

    def _check_health(self, deadline=None):
        if self.port is None:
            raise RuntimeSessionError("proxy listener is not configured")
        checker = getattr(self.health_probe, "check", None)
        if checker is None:
            raise RuntimeSessionError("proxy health probe is unavailable")
        if isinstance(self.health_probe, ConnectivityProbe) and deadline is not None:
            result = checker(
                self.port,
                self.username,
                self.password,
                timeout=deadline.remaining(),
            )
        else:
            result = checker(self.port, self.username, self.password)
        if not hasattr(result, "ok"):
            raise RuntimeSessionError("proxy health probe returned an invalid result")
        return result

    def _log_health(self, level, phase, snapshot, action=None):
        """Render one sanitized health result and its next action."""

        passed = int(getattr(snapshot, "passed", 0))
        required = int(getattr(snapshot, "required", 0))
        status = "passed" if bool(snapshot.ok) else "failed"
        message = "%s health check %s (%d/%d targets passed)" % (
            phase,
            status,
            passed,
            required,
        )
        failed = []
        for target in tuple(getattr(snapshot, "targets", ())):
            if getattr(target, "ok", False):
                continue
            name = redact_text(getattr(target, "name", "target"))[:64]
            detail = redact_text(getattr(target, "detail", "failed"))[:96] or "failed"
            failed.append("%s:%s" % (name, detail))
        if failed:
            message += "; failed=%s" % ",".join(failed[:8])
        if action:
            message += "; next=%s" % redact_text(action)
        self._log(level, message)

    def _startup_health(self, deadline=None):
        deadline = deadline or RecoveryDeadline(self.recovery_policy.recovery_deadline, clock=self.clock)
        delays = tuple(self.recovery_policy.startup_retry_delays)
        for index, delay in enumerate(delays):
            if not self._sleep_with_deadline(deadline, delay):
                raise RuntimeSessionError("proxy startup deadline exhausted")
            if self.process is None or self.process.process.poll() is not None:
                raise RuntimeSessionError("mihomo backend exited before health readiness")
            snapshot = self._check_health(deadline=deadline)
            if snapshot.ok:
                self.last_health = snapshot
                self._log_health("INFO", "startup", snapshot)
                return snapshot
            retrying = index + 1 < len(delays)
            missing_socks = any(
                getattr(target, "detail", "") == "socks_dependency_missing"
                for target in tuple(getattr(snapshot, "targets", ()))
            )
            if missing_socks:
                action = "install PySocks>=1.7.1 and retry the SOCKS5 server"
            else:
                action = "retrying current node" if retrying else "no startup retry remains; stopping session"
            self._log_health(
                "WARN" if retrying else "ERROR",
                "startup",
                snapshot,
                action,
            )
            if not retrying:
                self._startup_health_failure_logged = True
            if index + 1 < len(delays):
                self._stop_process(deadline=deadline)
                if deadline.remaining() <= 0:
                    raise RuntimeSessionError("proxy startup deadline exhausted")
                self._launch_node(self.node, deadline=deadline)
        raise RuntimeSessionError("proxy connectivity quorum failed during startup")

    def start(self, subscription_name=None, node_id=None, install_missing=True):
        """Prepare, launch, authenticate, and health-check one selected node."""

        self._enter_operation_lock()
        try:
            self.subscription = self._select_subscription(subscription_name)
            self.node = self._select_node(self.subscription, node_id)
            self.preference_node_id = self.node.node_id
            self._prepare_paths()
            self._log(
                "INFO",
                "starting backend %s %s with %s listener for node %s"
                % (self.driver.name, self.backend_version, self.listener_protocol, self.node.node_id),
            )
            self.port = reserve_loopback_port(
                preferred=self.preferred_port,
                strict=self.strict_port,
                bind_address=self.bind_address,
            )
            self._write_access()
            self._resolve_executable(install_missing)
            startup_deadline = RecoveryDeadline(self.recovery_policy.recovery_deadline, clock=self.clock)
            self._launch_node(self.node, deadline=startup_deadline)
            self._startup_health(startup_deadline)
            self._publish_access()
            self._next_health_at = self.clock() + self.recovery_policy.health_interval
            self._health_failures = 0
            self._log(
                "INFO",
                "proxy listener ready at %s:%d using %s"
                % (self.bind_address, self.port, self.listener_protocol),
            )
        except (JerryProxyError, OSError) as error:
            # Startup failures must not leave a live child or secret-bearing
            # lease behind.  The original domain error remains user-visible.
            if not self._startup_health_failure_logged:
                self._log(
                    "ERROR",
                    "startup failed before a healthy listener was published; stopping session: %s"
                    % redact_text(error),
                )
            try:
                self._stop_process()
                _remove_private_tree(self.session_root)
            except (OSError, RuntimeSessionError) as cleanup_error:
                raise RuntimeSessionError("runtime startup cleanup failed") from cleanup_error
            else:
                self._leave_operation_lock()
            raise error
        return self

    def _is_stale(self, record=None):
        """Return whether a stored record is too old for automatic failover."""

        record = record or self.subscription
        if record is None:
            raise SubscriptionStateError("subscription is not selected")
        updated = _parse_timestamp(record.updated_at)
        age = max(0.0, (datetime.now(timezone.utc) - updated).total_seconds())
        return age >= self.recovery_policy.refresh_stale_seconds

    def _mark_cooldown(self, node):
        self._cooldowns[node.node_id] = self.clock() + self.recovery_policy.failure_cooldown

    def _cooldown_active(self, node):
        return self._cooldowns.get(node.node_id, 0.0) > self.clock()

    def _eligible_alternates(self, record, attempted):
        if not record.enabled or self._is_stale(record):
            return ()
        # The ranking subsystem is not part of this URI slice.  Public node
        # identity is therefore the deterministic tie-breaker and current
        # fallback ordering; a later rank provider can be inserted before it.
        if not isinstance(record, NodeSource):
            raise SubscriptionStateError("subscription does not expose a node collection")
        return tuple(
            node
            for node in sorted(record.iter_nodes(), key=lambda item: item.node_id)
            if node.node_id not in attempted and not self._cooldown_active(node)
        )

    def _try_candidate(self, node, deadline):
        if deadline.remaining() <= 0:
            return False
        previous_node = self.node
        try:
            self._stop_process(deadline=deadline)
            self._launch_node(node, deadline=deadline)
            if deadline.remaining() <= 0:
                raise RuntimeSessionError("proxy recovery deadline exhausted")
            snapshot = self._check_health(deadline=deadline)
            if deadline.remaining() <= 0:
                raise RuntimeSessionError("proxy recovery deadline exhausted")
            if snapshot.ok:
                return True
        except RuntimeSessionError:
            # Candidate failures are classified and the next candidate is
            # attempted after bounded cleanup.
            pass
        self._mark_cooldown(node)
        try:
            self._stop_process(deadline=deadline)
        except RuntimeSessionError:
            raise
        # A failed candidate never becomes the effective node.  Keep the
        # last known effective identity for diagnostics and refresh selection.
        self.node = previous_node
        return False

    def _recover(self):
        """Apply restart -> alternate sweep -> optional source refresh once."""

        deadline = RecoveryDeadline(self.recovery_policy.recovery_deadline, clock=self.clock)
        attempted = {self.node.node_id}
        self._log("INFO", "health recovery action: restarting the current node")

        if not self._sleep_with_deadline(deadline, self.recovery_policy.same_node_delay):
            raise RuntimeSessionError("proxy recovery deadline exhausted")
        if self._try_candidate(self.node, deadline):
            return

        alternates = self._eligible_alternates(self.subscription, attempted)
        for index, candidate in enumerate(alternates):
            attempted.add(candidate.node_id)
            self._log("INFO", "health recovery action: trying an alternate node")
            delay = self.recovery_policy.alternate_delays[0]
            if index != 0:
                delay = self.recovery_policy.alternate_delays[-1]
            if not self._sleep_with_deadline(deadline, delay):
                raise RuntimeSessionError("proxy recovery deadline exhausted")
            if self._try_candidate(candidate, deadline):
                return

        if self.recovery_policy.refresh_on_failure and self.subscription.source_url:
            if deadline.remaining() <= 0:
                raise RuntimeSessionError("proxy recovery deadline exhausted")
            self._log("INFO", "health recovery action: refreshing the subscription source")
            try:
                refreshed = self._locked_refresh(self.subscription.name)
            except SubscriptionError:
                # Refresh is best effort; the last-known-good record remains
                # effective and the original source URL is never rendered.
                refreshed = None
            if refreshed is not None:
                self.subscription = refreshed
                for index, candidate in enumerate(self._eligible_alternates(refreshed, attempted)):
                    attempted.add(candidate.node_id)
                    delay = self.recovery_policy.alternate_delays[-1] if index else 0.0
                    if not self._sleep_with_deadline(deadline, delay):
                        raise RuntimeSessionError("proxy recovery deadline exhausted")
                    if self._try_candidate(candidate, deadline):
                        return

        raise RuntimeSessionError("proxy connectivity recovery exhausted")

    def _sleep_with_deadline(self, deadline, delay):
        if delay > deadline.remaining():
            return False
        if delay > 0:
            self.sleeper(delay)
        return True

    def public_info(self):  # type: () -> dict
        """Return the noncredential session envelope for human/JSON output."""

        return {
            "session": self.session_id,
            "backend": self.driver.name,
            "backend_version": self.backend_version,
            "listener": {
                "address": self.bind_address,
                "port": self.port,
                "kind": self.listener_protocol,
                "protocol": self.listener_protocol,
                "authentication": self.authenticate,
            },
            "subscription": self.subscription.name if self.subscription else None,
            "node": self.node.node_id if self.node else None,
            "preference_node": self.preference_node_id,
        }

    def wait(self):  # type: () -> int
        """Wait in the foreground and apply health recovery synchronously."""

        if self.process is None or self.process.process is None:
            raise RuntimeSessionError("runtime session is not running")
        next_health = self._next_health_at or (self.clock() + self.recovery_policy.health_interval)
        try:
            while True:
                process = self.process.process
                return_code = process.poll()
                if return_code is not None:
                    return return_code
                now = self.clock()
                if now >= next_health:
                    snapshot = self._check_health()
                    if snapshot.ok:
                        self._log_health(
                            "INFO",
                            "periodic",
                            snapshot,
                            "continuing the current node" if self._health_failures else None,
                        )
                        self._health_failures = 0
                    else:
                        self._health_failures += 1
                        if self._health_failures >= 2:
                            self._log_health(
                                "ERROR",
                                "periodic",
                                snapshot,
                                "starting recovery: restart current node, try alternates, then refresh if permitted",
                            )
                            try:
                                self._recover()
                            except RuntimeSessionError as error:
                                self._log(
                                    "ERROR",
                                    "health recovery action failed; stopping session: %s" % redact_text(error),
                                )
                                raise
                            self._log("INFO", "health recovery action completed; continuing the foreground session")
                            self._health_failures = 0
                        else:
                            self._log_health(
                                "WARN",
                                "periodic",
                                snapshot,
                                "one more failed check will start recovery",
                            )
                    next_health = self.clock() + self.recovery_policy.health_interval
                    self._next_health_at = next_health
                self.sleeper(min(0.2, max(0.01, next_health - self.clock())))
        except KeyboardInterrupt:
            self.stop()
            return 130

    def stop(self):
        """Stop the child and remove secret-bearing session artifacts."""

        if self._operation_lock is None:
            if self.process is None and not self.session_root.exists():
                return
            self._enter_operation_lock()
        try:
            self._stop_process()
            try:
                _remove_private_tree(self.session_root)
            except OSError as error:
                raise RuntimeSessionError("runtime session cleanup failed") from error
            self.process = None
            self._leave_operation_lock()
        except (OSError, RuntimeSessionError):
            # Keep ownership if termination or purge did not prove that no
            # child remains; another home mutation must not race live state.
            raise


__all__ = ["RuntimeSession"]
