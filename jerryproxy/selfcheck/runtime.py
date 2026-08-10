"""Runtime projection, driver contract, and loopback listener checks."""

import os
import socket
import tempfile
from pathlib import Path

from ..errors import JerryProxyBusyError, JerryProxyError, UnsupportedPlatformError
from ..home import JerryProxyPaths
from ..lock import JerryProxyOperationLock
from ..runtime.health import DEFAULT_HEALTH_TARGETS, HealthSnapshot, RecoveryPolicy
from ..runtime.interfaces import RuntimeDriver, RuntimeProjection
from ..runtime.mihomo import build_provider_config
from ..runtime.session import RuntimeSession
from ..subscription.manager import SubscriptionManager
from .fixtures import (
    _install_probe_version,
    _probe_manager,
    _recovery_failure,
    _recovery_platform,
    _unsupported_recovery_platform,
)
from .result import CheckResult, _error_result
from .subscription import _SUBSCRIPTION_PROBE_BODY, _SUBSCRIPTION_PROBE_SECRETS


class _ProbeHealth(object):
    """A health probe that reports reachable without touching the network."""

    def check(self, port, username, password):  # type: (int, str, str) -> HealthSnapshot
        del port, username, password
        return HealthSnapshot(targets=(), passed=1, required=1, started_at=0.0)


class _ProbeChild(object):
    """The object a real driver would return from the operating system."""

    def __init__(self):
        self.returncode = None

    def poll(self):  # type: () -> object
        return self.returncode


class _ProbeProcess(object):
    """A child stand-in, so no backend is ever executed by the diagnostic."""

    def __init__(self):
        self.process = _ProbeChild()
        self.started = False
        self.stopped = False

    def start(self):  # type: () -> object
        self.started = True
        return self.process

    def wait_ready(self, port):  # type: (int) -> None
        del port

    def stop(self):  # type: () -> None
        self.stopped = True
        self.process.returncode = 0


class _ProbeDriver(RuntimeDriver):
    """A driver that is not Mihomo, to prove the session does not assume one."""

    def __init__(self, backend_name):
        self._backend_name = backend_name
        self.projections = 0
        self.created = 0
        self.stopped = 0

    @property
    def name(self):  # type: () -> str
        return self._backend_name

    def projection(
        self,
        provider_path,
        node,
        port,
        username,
        password,
        listener_protocol,
        backend_log_level,
        bind_address="127.0.0.1",
    ):
        del provider_path, port, username, password, listener_protocol, backend_log_level
        del bind_address
        self.projections += 1
        # Reading the node through the runtime boundary is the point: a driver
        # receives the secret URI, while everything public went through public().
        return RuntimeProjection(
            config=b"probe-config\n",
            provider=node.secret_uri().encode("utf-8") + b"\n",
        )

    def create_process(
        self, executable, config_path, session_root, log_path, backend_log_level, log_sink=None
    ):
        del executable, config_path, session_root, log_path, backend_log_level, log_sink
        self.created += 1
        return _ProbeProcess()

    def wait_ready(self, process, port, timeout):
        del process, port, timeout

    def stop(self, process, timeout=None):
        del timeout
        self.stopped += 1
        process.stop()


def _check_runtime_driver_contract():
    """Run a foreground session against a substitute driver.

    ``RuntimeSession`` owns the home-wide lock, publication, and cleanup, while
    a driver owns only backend config and child lifecycle. If that separation
    slipped, a replaced driver would either fail to run at all or leave the lock
    or a secret-bearing artifact behind, and only a real lock on a real
    filesystem can answer that.
    """

    try:
        platform_info, spec, asset_platform = _recovery_platform()
        if asset_platform is None:
            return CheckResult.skip("no backend fixture asset shape supports %s" % platform_info.key)
        with tempfile.TemporaryDirectory(prefix="jerryproxy-driver-self-check-") as temporary:
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
                b"jerryproxy-driver-self-check\n",
            )
            subscriptions = SubscriptionManager(paths)
            published = subscriptions.add("self-check", None, body=_SUBSCRIPTION_PROBE_BODY)
            # A multi-node subscription has no implicit default, exactly as the
            # command line requires, so the probe selects one explicitly.
            selected = published.nodes[0].node_id

            driver = _ProbeDriver(spec.name)
            session = RuntimeSession(
                paths,
                manager=manager,
                subscription_manager=subscriptions,
                backend_version=installed.version,
                driver=driver,
                health_probe=_ProbeHealth(),
                recovery_policy=RecoveryPolicy(
                    startup_retry_delays=(0.0,),
                    recovery_deadline=5.0,
                ),
                sleeper=lambda delay: None,
            )
            session.start(subscription_name="self-check", node_id=selected)
            try:
                if driver.projections == 0 or driver.created == 0:
                    return CheckResult.fail("the session did not run through the injected driver")
                try:
                    with JerryProxyOperationLock(paths):
                        return CheckResult.fail(
                            "the running session did not hold the home-wide lock"
                        )
                except JerryProxyBusyError:
                    # The session owns the one home lock for its whole lifetime.
                    pass
            finally:
                session.stop()
            if driver.stopped == 0:
                return CheckResult.fail("session cleanup did not stop the injected driver")
            with JerryProxyOperationLock(paths):
                # Releasing only after cleanup is the contract; a second holder
                # must be able to take the lock once stop() has returned.
                pass
            remaining = _secret_bearing_artifacts(paths)
            if remaining:
                return CheckResult.fail(
                    "session cleanup left secret-bearing runtime state: %s" % ", ".join(remaining)
                )
    except UnsupportedPlatformError as error:
        # The synthetic backend has no meaningful asset shape on this host.
        return _unsupported_recovery_platform(error)
    except (JerryProxyError, OSError, RuntimeError, TypeError, ValueError) as error:
        # Installation, publication, session start, and cleanup are real operations.
        return _recovery_failure(error)
    return CheckResult.ok(
        "a substitute driver ran the session, which held the home lock and cleaned up"
    )


def _secret_bearing_artifacts(paths):  # type: (JerryProxyPaths) -> list
    """Runtime files still containing probe credential material after cleanup."""

    remaining = []
    runtimes = Path(paths.root) / "runtimes"
    if not runtimes.is_dir():
        return remaining
    for current, unused_directories, files in os.walk(str(runtimes)):
        for name in files:
            target = os.path.join(current, name)
            try:
                with open(target, "rb") as stream:
                    content = stream.read(64 * 1024)
            except OSError:
                # An unreadable leftover is itself state that should not remain.
                remaining.append(os.path.relpath(target, str(runtimes)))
                continue
            text = content.decode("utf-8", "replace")
            if any(secret in text for secret in _SUBSCRIPTION_PROBE_SECRETS):
                remaining.append(os.path.relpath(target, str(runtimes)))
    return remaining[:5]


def _check_loopback_listener():
    """Bind, accept, and connect on loopback, which the product depends on.

    Every JerryProxy listener is loopback-only, so a host that cannot bind
    ``127.0.0.1`` -- a restricted network namespace, a locked-down container --
    makes the product unusable in a way no other check would report.
    """

    listener = None
    client = None
    accepted = None
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(5.0)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        accepted, unused_address = listener.accept()
        accepted.settimeout(5.0)
        client.sendall(b"jerryproxy")
        if accepted.recv(16) != b"jerryproxy":
            return CheckResult.fail("a loopback connection did not deliver its bytes intact")
    except (OSError, socket.timeout) as error:
        # Binding, connecting, and transferring are host network capabilities.
        return _error_result(error)
    finally:
        for handle in (accepted, client, listener):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    # A close failure during cleanup must not mask the result.
                    pass
    return CheckResult.ok("bound an ephemeral 127.0.0.1 port and completed a loopback round trip")


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
