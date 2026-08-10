"""Bounded, integrity-checked availability probes for the built-in relays."""

import hashlib
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from ..backend.relay import (
    RELAY_PROBE_BYTES,
    RELAY_PROBE_SHA256,
    RELAY_PROBE_SIZE,
    RELAY_PROBE_URL,
    render_relay_url,
)
from ..utils.fs import atomic_write_json, read_json
from .processes import (
    _MAXIMUM_CHILD_RESULT_BYTES,
    _PROCESS_CONTROL_EXCEPTIONS,
    _captured_child_entry,
    _child_diagnostics,
    _join_process,
    _preferred_process_context,
    _process_is_alive,
    _start_process,
    _stop_process,
)
from .result import CheckResult, _bounded_diagnostic, _bounded_line, _error_result

_RELAY_CHECK_TIMEOUT = 5.0
_RELAY_CHECK_TOTAL_TIMEOUT = 30.0
_RELAY_CHECK_MAX_REDIRECTS = 5
_RELAY_CHECK_CHUNK_SIZE = 64 * 1024


def _relay_warning(reason):
    return CheckResult.warn("bounded 1 MiB verification failed: %s" % reason)


def _check_relay(profile, session_factory):
    session = session_factory()
    response = None
    started = time.monotonic()
    try:
        session.max_redirects = _RELAY_CHECK_MAX_REDIRECTS
        response = session.get(
            render_relay_url(profile, RELAY_PROBE_URL),
            headers={
                "Range": "bytes=0-%d" % (RELAY_PROBE_BYTES - 1),
                "User-Agent": "JerryProxy-self-check",
            },
            allow_redirects=True,
            stream=True,
            timeout=_RELAY_CHECK_TIMEOUT,
        )
        response_at = time.monotonic()
        if len(response.history) > _RELAY_CHECK_MAX_REDIRECTS:
            return _relay_warning("redirect limit exceeded")
        redirect_urls = [item.url for item in response.history] + [response.url]
        if any(urlparse(item).scheme != "https" for item in redirect_urls):
            return _relay_warning("redirect chain did not remain HTTPS")
        if response.status_code != 206:
            return _relay_warning("HTTP response was not 206")
        expected_range = "bytes 0-%d/%d" % (RELAY_PROBE_BYTES - 1, RELAY_PROBE_SIZE)
        if response.headers.get("Content-Range") != expected_range:
            return _relay_warning("Content-Range did not match the pinned asset")
        body = bytearray()
        chunk_count = 0
        first_chunk_at = None
        first_chunk_size = 0
        for block in response.iter_content(chunk_size=_RELAY_CHECK_CHUNK_SIZE):
            if not block:
                continue
            remaining = RELAY_PROBE_BYTES + 1 - len(body)
            accepted = block[:remaining]
            received_at = time.monotonic()
            if received_at - started > _RELAY_CHECK_TOTAL_TIMEOUT:
                return _relay_warning(
                    "stream exceeded the %.0f-second total timeout" % _RELAY_CHECK_TOTAL_TIMEOUT
                )
            body.extend(accepted)
            chunk_count += 1
            if first_chunk_at is None:
                first_chunk_at = received_at
                first_chunk_size = len(accepted)
            if len(body) > RELAY_PROBE_BYTES:
                break
        if len(body) != RELAY_PROBE_BYTES:
            return _relay_warning("response body was not exactly 1 MiB")
        if hashlib.sha256(bytes(body)).hexdigest() != RELAY_PROBE_SHA256:
            return _relay_warning("pinned 1 MiB sample digest did not match")
        completed_at = time.monotonic()
        first_chunk_seconds = max(first_chunk_at - started, 0.0)
        streamed_bytes = len(body) - first_chunk_size
        stream_seconds = max(completed_at - first_chunk_at, 0.001)
        throughput = streamed_bytes / 1024.0 / stream_seconds
        return CheckResult.ok(
            "verified 1 MiB; response %.1f ms; first chunk %.1f ms; stream %.1f KiB/s over %d chunks"
            % (
                (response_at - started) * 1000.0,
                first_chunk_seconds * 1000.0,
                throughput,
                chunk_count,
            )
        )
    except requests.exceptions.TooManyRedirects:
        # Requests raises this when the configured redirect ceiling is exceeded.
        return _relay_warning("redirect limit exceeded")
    except requests.exceptions.ProxyError:
        # The system-configured HTTP proxy may be unavailable or reject the request.
        return _relay_warning("system proxy connection failed")
    except requests.exceptions.SSLError:
        # TLS negotiation and system CA validation failures are availability warnings.
        return _relay_warning("TLS validation failed")
    except requests.exceptions.Timeout:
        # The bounded relay request may exceed the fixed self-check deadline.
        return _relay_warning("request timed out")
    except requests.exceptions.ConnectionError:
        # DNS and TCP connection failures are relay availability warnings.
        return _relay_warning("connection failed")
    except requests.exceptions.RequestException:
        # Other documented Requests transport failures remain sanitized warnings.
        return _relay_warning("request failed")
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            session.close()


def _relay_probe_child(profile, result_path):
    try:
        result = _check_relay(profile, requests.Session)
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        # Malformed runtime responses and local dependency failures become diagnostic results.
        result = _error_result(error)
    diagnostics = [_bounded_diagnostic(result.diagnostics[0])] if result.diagnostics else []
    atomic_write_json(
        Path(result_path),
        {
            "level": result.level,
            "detail": _bounded_line(result.detail),
            "diagnostics": diagnostics,
        },
    )


def _relay_child_result(result_path):
    try:
        payload = read_json(Path(result_path), maximum_bytes=_MAXIMUM_CHILD_RESULT_BYTES)
    except (OSError, ValueError) as error:
        # A completed child with an unreadable result file is a diagnostic error.
        return _error_result(error)
    if (
        set(payload) != {"level", "detail", "diagnostics"}
        or payload["level"] not in ("OK", "WARN", "SKIP", "FAIL", "ERR")
        or not isinstance(payload["detail"], str)
        or not isinstance(payload["diagnostics"], list)
        or len(payload["diagnostics"]) > 1
        or any(not isinstance(item, str) for item in payload["diagnostics"])
    ):
        return CheckResult.err("relay probe child returned an invalid diagnostic result")
    return CheckResult(
        payload["level"],
        _bounded_line(payload["detail"]),
        tuple(_bounded_diagnostic(item) for item in payload["diagnostics"]),
    )


def _read_relay_child_result(result_path):
    try:
        exists = Path(result_path).is_file()
    except OSError as error:
        # Result-file observation failure is an internal probe error.
        return _error_result(error)
    return _relay_child_result(result_path) if exists else None


def _check_relay_in_process(profile, supervision=None):
    started = time.monotonic()
    deadline = started + _RELAY_CHECK_TOTAL_TIMEOUT
    start_method, context = _preferred_process_context()
    if start_method is None:
        return CheckResult.skip("no supported multiprocessing start method is available")
    with tempfile.TemporaryDirectory(prefix="jerryproxy-relay-self-check-") as temporary:
        result_path = Path(temporary) / "result.json"
        stderr_log = Path(temporary) / "stderr.log"
        try:
            start_allowed = context.Event()
            start_cancelled = context.Event()
            start_ready = context.Event()
            start_budget = context.Value("d", 0.0)
            process = context.Process(
                target=_captured_child_entry,
                args=(
                    _relay_probe_child,
                    (profile, str(result_path)),
                    str(stderr_log),
                    start_allowed,
                    start_cancelled,
                    start_ready,
                    start_budget,
                ),
                daemon=True,
            )
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # Frozen-runtime or host process policy may reject process construction.
            return CheckResult.skip(
                "%s relay probe unavailable: %s: %s"
                % (start_method, error.__class__.__name__, _bounded_line(error))
            )
        start_status, start_error = _start_process(
            process,
            start_allowed,
            start_cancelled,
            start_ready,
            start_budget,
            deadline,
            supervision=supervision,
        )
        if start_status == "timeout":
            diagnostics = ()
            if supervision is not None:
                diagnostics = ("delayed process-start cleanup will be verified by the final supervision check",)
            return CheckResult.err(
                "relay probe child startup exceeded the %.3g-second total deadline"
                % _RELAY_CHECK_TOTAL_TIMEOUT,
                diagnostics=diagnostics,
            )
        if start_status == "unavailable":
            # Frozen-runtime or host process policy may reject the selected start method.
            return CheckResult.skip(
                "%s relay probe unavailable: %s: %s"
                % (start_method, start_error.__class__.__name__, _bounded_line(start_error))
            )
        if start_status == "error":
            return CheckResult.err(
                "relay probe child startup supervision failed: %s: %s"
                % (start_error.__class__.__name__, _bounded_line(start_error))
            )
        wait_diagnostics = []
        remaining = max(_RELAY_CHECK_TOTAL_TIMEOUT - (time.monotonic() - started), 0.0)
        _join_process(process, remaining, wait_diagnostics)
        elapsed = time.monotonic() - started
        alive = _process_is_alive(process, wait_diagnostics)
        if wait_diagnostics:
            if alive:
                alive, stop_diagnostics = _stop_process(process)
                wait_diagnostics.extend(stop_diagnostics)
            wait_diagnostics.extend(_child_diagnostics(stderr_log))
            if alive:
                return CheckResult.err(
                    "timed-out relay probe child remained alive after kill",
                    diagnostics=tuple(wait_diagnostics),
                )
            return CheckResult.err(
                "relay probe child supervision failed",
                diagnostics=tuple(wait_diagnostics),
            )
        timed_out = alive or elapsed >= _RELAY_CHECK_TOTAL_TIMEOUT
        if alive:
            stop_diagnostics = ()
            alive, stop_diagnostics = _stop_process(process)
            if alive:
                return CheckResult.err(
                    "timed-out relay probe child remained alive after kill",
                    diagnostics=stop_diagnostics + _child_diagnostics(stderr_log),
                )
        child_result = _read_relay_child_result(result_path)
        if timed_out:
            if child_result is not None and child_result.level in ("FAIL", "ERR"):
                return child_result
            return _relay_warning("total probe deadline exceeded")
        if process.exitcode != 0:
            return CheckResult.err(
                "relay probe child returned exit code %s" % process.exitcode,
                diagnostics=_child_diagnostics(stderr_log),
            )
        if child_result is None:
            return CheckResult.err(
                "relay probe child exited without a diagnostic result",
                diagnostics=_child_diagnostics(stderr_log),
            )
        return child_result
