"""A disposable network process gives health checks a hard wall budget."""

import json
import math
import multiprocessing
import threading
import time

from ..errors import RuntimeSessionError

_MAXIMUM_RESULT = 65536


def _worker(connection, gate, targets, quorum, timeout, protocol, port, username, password):
    import os

    import requests

    from .health import ConnectivityProbe

    for name in tuple(os.environ):
        if "SUBSCRIPTION" in name.upper() or name.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            os.environ.pop(name, None)
    try:
        if not gate.wait(5):
            return
        probe = ConnectivityProbe(targets=targets, quorum=quorum, timeout=timeout,
                                  protocol=protocol, session_factory=requests.Session)
        result = probe.check(port, username, password)
        value = [[item.ok, item.header_latency, item.first_chunk_latency, item.speed_bytes_per_second, item.detail]
                 for item in result.targets]
        payload = json.dumps(value, separators=(",", ":")).encode("ascii")
        if len(payload) > _MAXIMUM_RESULT:
            return
        connection.send_bytes(payload)
    finally:
        connection.close()


class ProbeProcess:
    """Own one spawned network worker until its termination is confirmed."""

    def __init__(self):
        self.process = None
        self.starter = None
        self.started = threading.Event()
        self.start_errors = []

    def close(self, timeout=2.0):
        deadline = time.monotonic() + timeout
        if self.starter is not None:
            if not self.started.wait(max(0.0, deadline - time.monotonic())):
                raise RuntimeSessionError("health process startup cleanup remains unconfirmed")
            self.starter.join(max(0.0, deadline - time.monotonic()))
            if self.starter.is_alive():
                raise RuntimeSessionError("health process startup cleanup remains unconfirmed")
        process = self.process
        if process is not None and process.pid is not None:
            if process.is_alive():
                process.terminate()
                process.join(max(0.0, min(0.5, deadline - time.monotonic())))
            if process.is_alive():
                process.kill()
                process.join(max(0.0, deadline - time.monotonic()))
            if process.is_alive():
                raise RuntimeSessionError("health process cleanup remains unconfirmed")
            process.join(0)
            process.close()
        self.process = None
        self.starter = None

    def check(self, targets, quorum, timeout, protocol, port, username, password):
        from .health import HealthSnapshot, TargetHealth

        self.close()
        started_at = time.monotonic()
        if timeout <= 0:
            return HealthSnapshot(tuple(TargetHealth(target.name, False, detail="probe_deadline")
                                        for target in targets), 0, quorum, started_at)
        deadline = started_at + timeout
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        gate = context.Event()
        self.started.clear()
        self.start_errors = []
        self.process = context.Process(target=_worker, args=(sender, gate, targets, quorum, timeout,
                                                             protocol, port, username, password))
        self.process.daemon = True

        def start():
            try:
                self.process.start()
            except (OSError, RuntimeError) as error:
                # Process allocation failure is terminal, never an outage verdict.
                self.start_errors.append(error)
            finally:
                self.started.set()

        self.starter = threading.Thread(target=start, name="jerryproxy-health-start", daemon=True)
        payload = None
        try:
            try:
                self.starter.start()
            except RuntimeError as error:
                # No process start was attempted when thread allocation fails.
                self.starter = None
                self.started.set()
                raise RuntimeSessionError("health process starter could not start") from error
            if not self.started.wait(max(0.0, deadline - time.monotonic())):
                raise RuntimeSessionError("health process startup deadline exhausted")
            if self.start_errors:
                raise RuntimeSessionError("health process could not start") from self.start_errors[0]
            sender.close()
            gate.set()
            remaining = deadline - time.monotonic()
            if remaining > 0 and receiver.poll(remaining):
                try:
                    payload = receiver.recv_bytes(_MAXIMUM_RESULT)
                    if time.monotonic() >= deadline:
                        payload = None
                except (EOFError, OSError) as error:
                    # A broken or oversized private result is an invalid worker.
                    raise RuntimeSessionError("health process result is unavailable") from error
        finally:
            try:
                self.close()
            finally:
                receiver.close()
                sender.close()
        if payload is None:
            return HealthSnapshot(tuple(TargetHealth(target.name, False, detail="probe_deadline")
                                        for target in targets), 0, quorum, started_at)
        try:
            values = json.loads(payload.decode("ascii"))
        except (ValueError, UnicodeError, RecursionError) as error:
            # Only a small closed result envelope may cross the process boundary.
            raise RuntimeSessionError("health process result is invalid") from error
        details = {"", "probe_deadline", "probe_worker_alive", "unexpected_status", "unexpected_redirect",
                   "required_header_missing", "body_too_large", "body_size_mismatch", "target_contract_invalid",
                   "tls_failed", "proxy_authentication_failed", "timeout", "socks_dependency_missing",
                   "invalid_proxy_schema", "transport_failed"}
        if not isinstance(values, list) or len(values) != len(targets):
            raise RuntimeSessionError("health process result is invalid")
        results = []
        for target, value in zip(targets, values):
            if (not isinstance(value, list) or len(value) != 5 or not isinstance(value[0], bool)
                    or any(not isinstance(number, (int, float)) or isinstance(number, bool)
                           or number < 0 or number > 1e12 or not math.isfinite(number) for number in value[1:4])
                    or not isinstance(value[4], str) or value[4] not in details
                    or value[0] != (value[4] == "")):
                raise RuntimeSessionError("health process result is invalid")
            results.append(TargetHealth(target.name, *value))
        return HealthSnapshot(tuple(results), sum(item.ok for item in results), quorum, started_at)
