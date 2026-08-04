"""Bounded authenticated connectivity probes and foreground recovery policy."""

import hashlib
import math
import threading
import time
from dataclasses import dataclass

import requests

from ..errors import RuntimeSessionError

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


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
    """Probe public targets through the authenticated local HTTP listener."""

    def __init__(
        self,
        targets=None,
        timeout=10.0,
        quorum=2,
        session_factory=None,
        clock=None,
    ):
        self.targets = tuple(targets or DEFAULT_HEALTH_TARGETS)
        if not self.targets:
            raise ValueError("at least one health target is required")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("health timeout must be positive")
        if not isinstance(quorum, int) or isinstance(quorum, bool) or not 1 <= quorum <= len(self.targets):
            raise ValueError("health quorum is outside the target set")
        self.timeout = float(timeout)
        self.quorum = quorum
        self.session_factory = session_factory or requests.Session
        self.clock = clock or time.monotonic

    @staticmethod
    def _proxy_url(port, username, password):
        # Credentials are constructed only in the private request boundary and
        # never appear in a result, exception, or diagnostic string.
        from urllib.parse import quote

        return "http://%s:%s@127.0.0.1:%d" % (
            quote(username, safe=""),
            quote(password, safe=""),
            port,
        )

    def _one(self, target, port, username, password, timeout=None):
        request_budget = self.timeout if timeout is None else min(self.timeout, float(timeout))
        if request_budget <= 0:
            return TargetHealth(target.name, False, detail="probe_deadline")
        started = self.clock()
        session = self.session_factory()
        try:
            if hasattr(session, "trust_env"):
                session.trust_env = False
            proxy = self._proxy_url(port, username, password)
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
        except requests.exceptions.Timeout:
            # Timeout is a normal degraded target result; it is not an
            # exception shown to the user or recorded with the target URL.
            return TargetHealth(target.name, False, detail="timeout")
        except requests.exceptions.RequestException:
            # Transport failures are classified as a failed target only.
            return TargetHealth(target.name, False, detail="transport_failed")
        finally:
            close = getattr(session, "close", None)
            if close is not None:
                close()

    def check(self, port, username, password, timeout=None):  # type: (int, str, str, object) -> HealthSnapshot
        """Run all quorum targets concurrently within one bounded timeout."""

        started = self.clock()
        effective_timeout = self.timeout if timeout is None else min(self.timeout, float(timeout))
        results = [None] * len(self.targets)
        threads = []

        def run(index, target):
            results[index] = self._one(target, port, username, password, timeout=effective_timeout)

        for index, target in enumerate(self.targets):
            thread = threading.Thread(target=run, args=(index, target), name="jerryproxy-health-%s" % target.name)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        deadline = started + max(0.0, effective_timeout)
        for thread in threads:
            remaining = deadline - self.clock()
            if remaining > 0:
                thread.join(remaining)
        for thread in threads:
            if thread.is_alive():
                # Requests read timeouts are bounded, but a custom injected
                # session may ignore them; retain an explicit failed result
                # rather than allowing an unjoined worker to count as healthy.
                thread.join(0.05)
        for index, result in enumerate(results):
            if result is None:
                detail = "probe_worker_alive" if threads[index].is_alive() else "probe_deadline"
                results[index] = TargetHealth(self.targets[index].name, False, detail=detail)
        passed = sum(1 for result in results if result.ok)
        return HealthSnapshot(tuple(results), passed, self.quorum, started)


@dataclass(frozen=True)
class RecoveryPolicy(object):
    """Deterministic foreground health recovery policy."""

    health_interval: float = 300.0
    recovery_deadline: float = 120.0
    startup_retry_delays: tuple = (0.0, 1.0, 2.0)
    same_node_delay: float = 1.0
    alternate_delays: tuple = (4.0, 8.0)
    refresh_on_failure: bool = True
    refresh_stale_seconds: float = 43200.0
    failure_cooldown: float = 300.0

    def __post_init__(self):
        durations = (
            self.health_interval,
            self.recovery_deadline,
            self.refresh_stale_seconds,
            self.failure_cooldown,
        )
        if any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or value <= 0
            for value in durations
        ):
            raise ValueError("health and recovery durations must be positive")
        if (
            not isinstance(self.same_node_delay, (int, float))
            or isinstance(self.same_node_delay, bool)
            or not math.isfinite(float(self.same_node_delay))
            or self.same_node_delay < 0
        ):
            raise ValueError("same-node delay must be finite and non-negative")
        if not isinstance(self.refresh_on_failure, bool):
            raise ValueError("refresh_on_failure must be boolean")
        if not self.startup_retry_delays or any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or value < 0
            for value in self.startup_retry_delays
        ):
            raise ValueError("startup retry delays must be finite and non-negative")
        if not self.alternate_delays or any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or value < 0
            for value in self.alternate_delays
        ):
            raise ValueError("alternate delays must be finite and non-negative")


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
