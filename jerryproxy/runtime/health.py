"""Bounded local-listener connectivity probes and foreground recovery policy."""

import hashlib
import math
import threading
import time
from dataclasses import dataclass

import requests
from urllib3.exceptions import MaxRetryError, ProxyError

from ..errors import RuntimeSessionError
from ._probe import ProbeProcess
from .recovery import RETRY_POLICIES, parse_retry_chain

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _connect_authentication_failed(error):
    """Recognize only the pinned Requests/urllib3/stdlib CONNECT error chain."""

    wrapped = error.args[0] if len(error.args) == 1 else None
    proxy = wrapped.reason if isinstance(wrapped, MaxRetryError) else None
    cause = proxy.original_error if isinstance(proxy, ProxyError) else None
    # http.client discards the numeric status when raising OSError. Inspect its
    # exact locally generated prefix only after verifying the exception chain;
    # never search arbitrary messages or retain the remote reason phrase.
    return (type(cause) is OSError and len(cause.args) == 1 and isinstance(cause.args[0], str)
            and cause.args[0].startswith("Tunnel connection failed: 407 "))


@dataclass(frozen=True)
class HealthTarget(object):
    """One public target contract used by the unattended global quorum."""

    name: str
    url: str
    status: int
    maximum_bytes: int = 0
    sha256: str = _EMPTY_SHA256
    required_header: str = ""


# These targets are the high-confidence global primary quorum from the P0
# contract.  Only stable labels are retained in health results and logs.
DEFAULT_HEALTH_TARGETS = (
    HealthTarget("global-google", "https://www.google.com/generate_204", 204),
    HealthTarget("global-cloudflare", "https://speed.cloudflare.com/__down?bytes=0", 200),
    HealthTarget(
        "global-ubuntu",
        "https://connectivity-check.ubuntu.com/",
        204,
        required_header="X-NetworkManager-Status: online",
    ),
)


@dataclass(frozen=True)
class TargetHealth(object):
    """Sanitized result for one target; no URL or response body is retained."""

    name: str
    ok: bool
    header_latency: float = 0.0
    first_chunk_latency: float = 0.0
    speed_bytes_per_second: float = 0.0
    detail: str = ""


@dataclass(frozen=True)
class HealthSnapshot(object):
    """One complete quorum result."""

    targets: tuple
    passed: int
    required: int
    started_at: float

    @property
    def ok(self):  # type: () -> bool
        return self.passed >= self.required


class ConnectivityProbe(object):
    """Probe public targets through one local proxy listener."""

    def __init__(
        self,
        targets=None,
        timeout=10.0,
        quorum=2,
        session_factory=None,
        clock=None,
        protocol="http",
    ):
        self.targets = tuple(DEFAULT_HEALTH_TARGETS if targets is None else targets)
        if not self.targets:
            raise ValueError("at least one health target is required")
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("health timeout must be positive")
        if not isinstance(quorum, int) or isinstance(quorum, bool) or not 1 <= quorum <= len(self.targets):
            raise ValueError("health quorum is outside the target set")
        self.timeout = float(timeout)
        self.quorum = quorum
        self._network_process = ProbeProcess() if session_factory is None else None
        self.session_factory = session_factory or requests.Session
        self.clock = clock or time.monotonic
        if protocol not in ("http", "mixed", "socks5"):
            raise ValueError("unsupported local proxy protocol")
        self.protocol = protocol
        self._workers = []
        self._worker_done = []
        self._cancel = threading.Event()

    @staticmethod
    def _proxy_url(port, username, password, protocol="http"):
        # Credentials are constructed only in the private request boundary and
        # never appear in a result, exception, or diagnostic string.
        from urllib.parse import quote

        scheme = "socks5h" if protocol == "socks5" else "http"
        if username is None and password is None:
            return "%s://127.0.0.1:%d" % (scheme, port)
        if username is None or password is None:
            raise ValueError("proxy authentication requires both username and password")
        return "%s://%s:%s@127.0.0.1:%d" % (
            scheme,
            quote(username, safe=""),
            quote(password, safe=""),
            port,
        )

    def _one(self, target, port, username, password, timeout):
        request_budget = min(self.timeout, timeout)
        started = self.clock()
        session = self.session_factory()
        try:
            if hasattr(session, "trust_env"):
                session.trust_env = False
            proxy = self._proxy_url(port, username, password, self.protocol)
            response = session.get(
                target.url,
                proxies={"http": proxy, "https": proxy},
                allow_redirects=False,
                stream=True,
                timeout=(min(5.0, request_budget), request_budget),
                headers={"User-Agent": "JerryProxy-health/0.1"},
            )
            try:
                header_latency = max(0.0, self.clock() - started)
                if response.status_code == 407:
                    return TargetHealth(target.name, False, header_latency, detail="proxy_authentication_failed")
                if response.status_code != target.status:
                    return TargetHealth(target.name, False, header_latency, detail="unexpected_status")
                if getattr(response, "is_redirect", False) or response.headers.get("Location"):
                    return TargetHealth(target.name, False, header_latency, detail="unexpected_redirect")
                if target.required_header:
                    key, separator, expected = target.required_header.partition(":")
                    if not separator or response.headers.get(key.strip(), "").strip() != expected.strip():
                        return TargetHealth(target.name, False, header_latency, detail="required_header_missing")
                total = 0
                first_chunk = None
                digest = hashlib.sha256()
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    if self.clock() - started >= request_budget:
                        return TargetHealth(
                            target.name,
                            False,
                            header_latency,
                            first_chunk or 0.0,
                            detail="probe_deadline",
                        )
                    if first_chunk is None:
                        first_chunk = max(0.0, self.clock() - started)
                    total += len(chunk)
                    digest.update(chunk)
                    if total > target.maximum_bytes:
                        return TargetHealth(
                            target.name,
                            False,
                            header_latency,
                            first_chunk or 0.0,
                            detail="body_too_large",
                        )
                if total != target.maximum_bytes:
                    return TargetHealth(
                        target.name,
                        False,
                        header_latency,
                        first_chunk or 0.0,
                        detail="body_size_mismatch",
                    )
                if target.sha256 != digest.hexdigest():
                    return TargetHealth(target.name, False, header_latency, detail="target_contract_invalid")
                elapsed = max(0.0, self.clock() - started)
                speed = float(total) / max(elapsed - (first_chunk or elapsed), 0.000001) if total else 0.0
                return TargetHealth(target.name, True, header_latency, first_chunk or 0.0, speed)
            finally:
                response.close()
        except requests.exceptions.SSLError:
            # Certificate validation failures are terminal, never outage retries.
            return TargetHealth(target.name, False, detail="tls_failed")
        except requests.exceptions.Timeout:
            # Timeout is a normal degraded target result; it is not an
            # exception shown to the user or recorded with the target URL.
            return TargetHealth(target.name, False, detail="timeout")
        except requests.exceptions.InvalidSchema:
            # Requests raises InvalidSchema when the optional SOCKS transport
            # dependency is absent; keep the action-oriented diagnosis without
            # exposing the target URL or the raw exception text.
            detail = "socks_dependency_missing" if self.protocol == "socks5" else "invalid_proxy_schema"
            return TargetHealth(target.name, False, detail=detail)
        except requests.exceptions.ProxyError as error:
            # CONNECT refusal loses its response in Requests; only a verified
            # 407 wrapper is authentication failure, other proxy errors retry.
            detail = "proxy_authentication_failed" if _connect_authentication_failed(error) else "transport_failed"
            return TargetHealth(target.name, False, detail=detail)
        except requests.exceptions.RequestException:
            # Transport failures are classified as a failed target only.
            return TargetHealth(target.name, False, detail="transport_failed")
        finally:
            close = getattr(session, "close", None)
            if close is not None:
                close()

    def check(self, port, username, password, timeout=None):  # type: (int, str, str, object) -> HealthSnapshot
        """Run all quorum targets concurrently within one bounded timeout."""

        if self._network_process is not None:
            budget = self.timeout if timeout is None else min(self.timeout, float(timeout))
            return self._network_process.check(self.targets, self.quorum, budget, self.protocol,
                                               port, username, password)
        started = self.clock()
        effective_timeout = self.timeout if timeout is None else min(self.timeout, float(timeout))
        if any(not done.is_set() or worker.is_alive()
               for worker, done in zip(self._workers, self._worker_done)):
            # A timed-out request must finish before another check can allocate
            # workers. Never reuse its late result as evidence of current health.
            return HealthSnapshot(
                tuple(TargetHealth(target.name, False, detail="probe_worker_alive") for target in self.targets),
                0, self.quorum, started,
            )
        results = [None] * len(self.targets)
        threads = []
        self._workers = threads
        self._worker_done = []
        self._cancel.clear()
        worker_count = min(3, len(self.targets))
        deadline = started + max(0.0, effective_timeout)

        def run(worker_index, done):
            try:
                for index in range(worker_index, len(self.targets), worker_count):
                    remaining = deadline - self.clock()
                    if remaining <= 0 or self._cancel.is_set():
                        break
                    results[index] = self._one(self.targets[index], port, username, password, timeout=remaining)
            finally:
                done.set()

        try:
            for index in range(worker_count):
                done = threading.Event()
                thread = threading.Thread(target=run, args=(index, done), name="jerryproxy-health-%d" % index)
                thread.daemon = True
                threads.append(thread)
                self._worker_done.append(done)
                try:
                    thread.start()
                except RuntimeError as error:
                    # Thread allocation failed before its target could run.
                    threads.pop()
                    self._worker_done.pop()
                    self._cancel.set()
                    raise RuntimeSessionError("health worker could not start") from error
            for done in self._worker_done:
                remaining = deadline - self.clock()
                if remaining > 0:
                    done.wait(remaining)
        except KeyboardInterrupt:
            # Wait on completion events, not Thread.join: interrupted joins can
            # mark a still-running worker stopped on older CPython versions.
            self._cancel.set()
            raise
        for index, result in enumerate(results):
            if result is None:
                done = self._worker_done[index % worker_count]
                detail = "probe_deadline" if done.is_set() else "probe_worker_alive"
                results[index] = TargetHealth(self.targets[index].name, False, detail=detail)
        passed = sum(1 for result in results if result.ok)
        return HealthSnapshot(tuple(results), passed, self.quorum, started)

    def close(self, timeout=2.0):
        """Cancel pending targets and confirm worker cleanup before unlocking."""

        if self._network_process is not None:
            self._network_process.close(timeout)
        self._cancel.set()
        deadline = time.monotonic() + timeout
        for done in self._worker_done:
            if not done.wait(max(0.0, deadline - time.monotonic())):
                raise RuntimeSessionError("health worker cleanup remains unconfirmed")
        for worker in self._workers:
            worker.join(max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                raise RuntimeSessionError("health worker cleanup remains unconfirmed")


@dataclass(frozen=True)
class RecoveryPolicy(object):
    """Persistent recovery with a bounded budget per round, not per session."""

    retry_policy: str = "fallback"
    retry_chain: str = None
    confirmation_delay: float = 3.0
    refresh_interval: float = 60.0
    fast_probe_timeout: float = 3.0
    cache_retry_budget: float = 6.0
    refresh_timeout: float = 10.0
    health_interval: float = 30.0
    recovery_deadline: float = 120.0
    refresh_on_failure: bool = True
    refresh_stale_seconds: float = 43200.0

    def __post_init__(self):
        if self.retry_policy not in RETRY_POLICIES:
            raise ValueError("unknown retry policy")
        if self.retry_chain is not None:
            if self.retry_policy != "fallback":
                raise ValueError("retry chain requires fallback policy")
            parse_retry_chain(self.retry_chain)
        durations = (
            self.confirmation_delay, self.refresh_interval, self.health_interval,
            self.recovery_deadline, self.refresh_stale_seconds,
            self.fast_probe_timeout, self.cache_retry_budget, self.refresh_timeout,
        )
        if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(float(value)) or value <= 0
            for value in durations
        ):
            raise ValueError("health and recovery durations must be finite and positive")
        if not isinstance(self.refresh_on_failure, bool):
            raise ValueError("refresh_on_failure must be boolean")


class RecoveryDeadline(object):
    """One monotonic deadline shared by waits, starts, probes, and cleanup."""

    def __init__(self, duration, clock=None):
        self.clock = clock or time.monotonic
        self.end = self.clock() + duration

    def remaining(self):  # type: () -> float
        return max(0.0, self.end - self.clock())

    def sleep(self, delay):  # type: (float) -> bool
        if delay > self.remaining():
            return False
        if delay > 0:
            time.sleep(delay)
        return True


def require_health(snapshot):
    """Turn a failed initial quorum into the public runtime error type."""

    if not snapshot.ok:
        raise RuntimeSessionError("proxy connectivity quorum failed")
    return snapshot


__all__ = [
    "ConnectivityProbe",
    "DEFAULT_HEALTH_TARGETS",
    "HealthSnapshot",
    "HealthTarget",
    "RecoveryDeadline",
    "RecoveryPolicy",
    "TargetHealth",
    "require_health",
]
