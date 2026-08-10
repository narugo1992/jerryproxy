"""Bounded child-process supervision shared by the spawning probes."""

import errno
import multiprocessing
import os
import sys
import threading
import time
import traceback
from pathlib import Path

from .result import (
    _MAXIMUM_DIAGNOSTIC_CHARACTERS,
    _MAXIMUM_DIAGNOSTIC_INPUT_CHARACTERS,
    CheckResult,
    _bounded_diagnostic,
    _bounded_line,
    _redact_diagnostic,
)

_RECOVERY_PROCESS_TIMEOUT = 30.0
_RECOVERY_CHILD_ERROR = 90
_CHILD_STDERR_CAPTURE_ERROR = 96
_CHILD_START_CANCELLED = 97
_CHILD_START_GATE_TIMEOUT = 35.0
_PROCESS_SUPERVISION_WAIT = 10.0
_MAXIMUM_CHILD_RESULT_BYTES = 128 * 1024
_PROCESS_CONTROL_EXCEPTIONS = (AssertionError, AttributeError, OSError, RuntimeError, ValueError)


def _write_recovery_child_error(path):
    descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags, 0o600)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        payload = _bounded_diagnostic(traceback.format_exc()).encode("utf-8")
        while payload:
            written = os.write(descriptor, payload)
            if written <= 0:
                raise OSError(errno.EIO, "diagnostic write made no progress")
            payload = payload[written:]
    except OSError:
        # The parent still reports the child exit code when its diagnostic file is unavailable.
        pass
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                # Diagnostic cleanup must not replace the hard-exit probe's intended status.
                pass


class _BoundedChildStderr(object):
    def __init__(self, stream):
        self._stream = stream
        self._remaining = _MAXIMUM_DIAGNOSTIC_CHARACTERS
        self._pending = ""
        self._discarding_line = False
        self._inside_pem = False
        self.encoding = "utf-8"

    def _write_sanitized_line(self, value):
        if "-----BEGIN " in value and " KEY-----" in value:
            self._inside_pem = True
            value = "[REDACTED KEY]\n"
        elif self._inside_pem:
            if "-----END " in value and " KEY-----" in value:
                self._inside_pem = False
            value = "[REDACTED KEY]\n"
        else:
            value = _redact_diagnostic(value)
        payload = value.encode("utf-8", errors="replace")[: self._remaining]
        if payload:
            self._stream.write(payload)
            self._remaining -= len(payload)

    def write(self, value):
        text = str(value)
        size = len(text)
        if self._remaining <= 0:
            return size
        if self._discarding_line:
            separator = text.find("\n")
            if separator < 0:
                return size
            text = text[separator + 1 :]
            self._discarding_line = False
        self._pending += text
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            self._write_sanitized_line(line + "\n")
        if len(self._pending) > _MAXIMUM_DIAGNOSTIC_INPUT_CHARACTERS:
            self._write_sanitized_line("[child stderr line exceeded capture limit]\n")
            self._pending = ""
            self._discarding_line = True
        return size

    def flush(self):
        self._stream.flush()

    def finish(self):
        if self._pending and not self._discarding_line:
            self._write_sanitized_line(self._pending)
        self._pending = ""
        self._stream.flush()

    def isatty(self):
        return False


def _child_start_allowed(
    start_allowed,
    start_cancelled,
    start_ready,
    start_budget,
):
    ready_at = time.monotonic()
    start_ready.set()
    gate_deadline = ready_at + _CHILD_START_GATE_TIMEOUT
    while True:
        if start_cancelled.is_set():
            return False
        if start_allowed.is_set():
            elapsed = time.monotonic() - ready_at
            return start_budget.value > elapsed and not start_cancelled.is_set()
        remaining = gate_deadline - time.monotonic()
        if remaining <= 0.0:
            return False
        start_allowed.wait(min(remaining, 0.05))


def _captured_child_entry(
    target,
    arguments,
    stderr_log,
    start_allowed,
    start_cancelled,
    start_ready,
    start_budget,
):
    diagnostic_descriptor = None
    null_descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        diagnostic_descriptor = os.open(
            str(stderr_log),
            flags,
            0o600,
        )
        if os.name == "posix":
            os.fchmod(diagnostic_descriptor, 0o600)
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_descriptor, 2)
        diagnostic_stream = os.fdopen(diagnostic_descriptor, "wb", buffering=0)
        diagnostic_descriptor = None
    except (OSError, ValueError):
        # A child without a private stderr boundary must not execute or inherit the terminal.
        if diagnostic_descriptor is not None:
            try:
                os.close(diagnostic_descriptor)
            except OSError:
                # A rejected capture boundary is already represented by the child exit code.
                pass
        if null_descriptor is not None:
            try:
                os.close(null_descriptor)
            except OSError:
                # A rejected capture boundary is already represented by the child exit code.
                pass
        os._exit(_CHILD_STDERR_CAPTURE_ERROR)
    if null_descriptor != 2:
        try:
            os.close(null_descriptor)
        except OSError:
            # The duplicated stderr descriptor remains authoritative for diagnostics.
            pass
    diagnostic_writer = _BoundedChildStderr(diagnostic_stream)
    sys.stderr = diagnostic_writer
    if not _child_start_allowed(start_allowed, start_cancelled, start_ready, start_budget):
        diagnostic_writer.finish()
        os._exit(_CHILD_START_CANCELLED)
    try:
        target(*arguments)
    finally:
        diagnostic_writer.finish()


def _preferred_process_context():
    methods = multiprocessing.get_all_start_methods()
    preferred = ("spawn", "fork")
    start_method = next((method for method in preferred if method in methods), None)
    if start_method is None:
        return None, None
    return start_method, multiprocessing.get_context(start_method)


def _process_control_error(action, error):
    return "%s failed: %s: %s" % (action, error.__class__.__name__, _bounded_line(error))


def _join_process(process, timeout, diagnostics):
    try:
        process.join(timeout)
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Host process supervision may reject a bounded join operation.
        diagnostics.append(_process_control_error("join", error))


class _ProcessSupervision(object):
    """Aggregate cleanup outcomes for process starts that return after a deadline."""

    def __init__(self):
        self._lock = threading.Lock()
        self._settled = threading.Event()
        self._settled.set()
        self._registered = 0
        self._pending = 0
        self._survivors = 0
        self._diagnostics = []

    def register(self):
        with self._lock:
            self._registered += 1
            self._pending += 1
            self._settled.clear()

    def complete(self, alive, diagnostics):
        with self._lock:
            self._pending -= 1
            if alive:
                self._survivors += 1
            self._diagnostics.extend(diagnostics)
            if self._pending == 0:
                self._settled.set()

    def wait(self, timeout):
        return self._settled.wait(timeout)

    def result(self):
        with self._lock:
            registered = self._registered
            pending = self._pending
            survivors = self._survivors
            diagnostics = tuple(self._diagnostics)
        if pending:
            noun = "cleanup is" if pending == 1 else "cleanups are"
            return CheckResult.err(
                "%d delayed child %s still pending" % (pending, noun),
                diagnostics=diagnostics,
            )
        if survivors:
            noun = "child remained" if survivors == 1 else "children remained"
            return CheckResult.err(
                "%d delayed %s alive after kill" % (survivors, noun),
                diagnostics=diagnostics,
            )
        if not registered:
            return CheckResult.ok("no delayed child starts required cleanup")
        noun = "start was" if registered == 1 else "starts were"
        return CheckResult.ok("%d delayed child %s cancelled and reaped" % (registered, noun))


def _check_process_supervision(supervision):
    supervision.wait(_PROCESS_SUPERVISION_WAIT)
    return supervision.result()


def _start_process(
    process,
    start_allowed,
    start_cancelled,
    start_ready,
    start_budget,
    deadline,
    supervision=None,
):
    outcome = []
    start_finished = threading.Event()
    cleanup_required = threading.Event()
    ownership_decided = threading.Event()
    supervision_registered = []

    def abandon(status, error=None, track_cleanup=True):
        cleanup_required.set()
        if supervision is not None and track_cleanup:
            supervision.register()
            supervision_registered.append(True)
        try:
            start_cancelled.set()
        except _PROCESS_CONTROL_EXCEPTIONS as cancellation_error:
            # Local cleanup ownership must survive a failed cross-process cancellation signal.
            status = "error"
            error = cancellation_error
        finally:
            ownership_decided.set()
        return status, error

    def start():
        try:
            process.start()
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # Process creation failures are returned to the supervising thread.
            outcome.append(error)
        else:
            outcome.append(None)
        finally:
            start_finished.set()
        ownership_decided.wait()
        if cleanup_required.is_set():
            alive = False
            diagnostics = []
            if outcome and outcome[0] is None:
                _join_process(process, 5.0, diagnostics)
                alive = _process_is_alive(process, diagnostics)
                if alive:
                    alive, stop_diagnostics = _stop_process(process)
                    diagnostics.extend(stop_diagnostics)
            if supervision_registered:
                supervision.complete(alive, tuple(diagnostics))

    thread = threading.Thread(target=start, name="jerryproxy-self-check-start", daemon=True)
    try:
        thread.start()
    except RuntimeError as error:
        # A host that rejects thread startup cannot provide a bounded process launch.
        return abandon("unavailable", error, track_cleanup=False)
    while not start_finished.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return abandon("timeout")
        if start_finished.wait(min(remaining, 0.05)):
            break
        if not thread.is_alive():
            return abandon("error", RuntimeError("process start thread returned no outcome"))
    if time.monotonic() >= deadline:
        return abandon("timeout")
    if not outcome:
        return abandon("error", RuntimeError("process start thread returned no outcome"))
    if outcome[0] is not None:
        ownership_decided.set()
        return "unavailable", outcome[0]
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return abandon("timeout")
        try:
            if start_ready.wait(min(remaining, 0.05)):
                break
            if not process.is_alive():
                try:
                    start_cancelled.set()
                except _PROCESS_CONTROL_EXCEPTIONS as error:
                    # A dead child needs no cleanup, but cancellation publication still failed.
                    ownership_decided.set()
                    return "error", error
                ownership_decided.set()
                return "started", None
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # Child readiness and liveness are required before authorization.
            return abandon("error", error)
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        return abandon("timeout")
    try:
        start_budget.value = remaining
        start_allowed.set()
    except (OSError, RuntimeError, ValueError) as error:
        # A started child must remain gated when its budget or authorization cannot be published.
        return abandon("error", error)
    if time.monotonic() >= deadline:
        return abandon("timeout")
    ownership_decided.set()
    return "started", None


def _process_is_alive(process, diagnostics):
    try:
        return process.is_alive()
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Unknown process state must be treated as alive so hard-kill cleanup is attempted.
        diagnostics.append(_process_control_error("liveness check", error))
        return True


def _stop_process(process):
    diagnostics = []
    try:
        process.terminate()
    except _PROCESS_CONTROL_EXCEPTIONS as error:
        # Termination failure must not prevent the later hard-kill attempt.
        diagnostics.append(_process_control_error("terminate", error))
    _join_process(process, 5.0, diagnostics)
    alive = _process_is_alive(process, diagnostics)
    if alive:
        try:
            process.kill()
        except _PROCESS_CONTROL_EXCEPTIONS as error:
            # A rejected hard kill is reported after the final liveness check.
            diagnostics.append(_process_control_error("kill", error))
        _join_process(process, 5.0, diagnostics)
        alive = _process_is_alive(process, diagnostics)
    return alive, tuple(diagnostics)


def _read_child_diagnostic(path):
    try:
        with Path(path).open("rb") as stream:
            payload = stream.read(_MAXIMUM_DIAGNOSTIC_CHARACTERS + 1)
    except FileNotFoundError:
        # A child that produced no stderr or expected-error log leaves no diagnostic file.
        return ()
    except OSError as error:
        # Diagnostic read failure is secondary to the child supervision failure.
        return (
            _bounded_diagnostic("Unable to read child diagnostic: %s: %s" % (error.__class__.__name__, error)),
        )
    if not payload:
        return ()
    truncated = len(payload) > _MAXIMUM_DIAGNOSTIC_CHARACTERS
    if truncated:
        marker = "\n[diagnostic truncated]"
        text = payload[: _MAXIMUM_DIAGNOSTIC_CHARACTERS - len(marker)].decode("utf-8", errors="replace")
        text += marker
    else:
        text = payload.decode("utf-8", errors="replace")
    text = "\n".join(text.splitlines())
    return (_bounded_diagnostic(text),)


def _child_diagnostics(*paths):
    diagnostics = ()
    for path in paths:
        diagnostics += _read_child_diagnostic(path)
    return diagnostics


def _run_recovery_child(target, arguments, expected_exit, error_log, supervision=None):
    started_at = time.monotonic()
    deadline = started_at + _RECOVERY_PROCESS_TIMEOUT
    start_method, context = _preferred_process_context()
    if start_method is None:
        return CheckResult.skip("no supported multiprocessing start method is available")
    stderr_log = Path("%s.stderr" % error_log)
    try:
        start_allowed = context.Event()
        start_cancelled = context.Event()
        start_ready = context.Event()
        start_budget = context.Value("d", 0.0)
        process = context.Process(
            target=_captured_child_entry,
            args=(
                target,
                tuple(arguments) + (str(error_log),),
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
            "%s hard-exit probe unavailable: %s: %s"
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
            "hard-exit recovery child startup exceeded the %.3g-second timeout"
            % _RECOVERY_PROCESS_TIMEOUT,
            diagnostics=diagnostics,
        )
    if start_status == "unavailable":
        # Frozen-runtime or host process policy may reject the selected start method.
        return CheckResult.skip(
            "%s hard-exit probe unavailable: %s: %s"
            % (start_method, start_error.__class__.__name__, _bounded_line(start_error))
        )
    if start_status == "error":
        return CheckResult.err(
            "hard-exit recovery child startup supervision failed: %s: %s"
            % (start_error.__class__.__name__, _bounded_line(start_error))
        )
    wait_diagnostics = []
    remaining = max(_RECOVERY_PROCESS_TIMEOUT - (time.monotonic() - started_at), 0.0)
    _join_process(process, remaining, wait_diagnostics)
    alive = _process_is_alive(process, wait_diagnostics)
    if wait_diagnostics:
        if alive:
            alive, stop_diagnostics = _stop_process(process)
            wait_diagnostics.extend(stop_diagnostics)
        wait_diagnostics.extend(_child_diagnostics(error_log, stderr_log))
        if alive:
            return CheckResult.err(
                "timed-out hard-exit recovery child remained alive after kill",
                diagnostics=tuple(wait_diagnostics),
            )
        return CheckResult.err(
            "hard-exit recovery child supervision failed",
            diagnostics=tuple(wait_diagnostics),
        )
    if alive:
        alive, stop_diagnostics = _stop_process(process)
        stop_diagnostics = stop_diagnostics + _child_diagnostics(error_log, stderr_log)
        if alive:
            return CheckResult.err(
                "timed-out hard-exit recovery child remained alive after kill",
                diagnostics=stop_diagnostics,
            )
        return CheckResult.err(
            "hard-exit recovery child exceeded the %.0f-second timeout" % _RECOVERY_PROCESS_TIMEOUT,
            diagnostics=stop_diagnostics,
        )
    if process.exitcode == expected_exit:
        return None
    diagnostics = _child_diagnostics(error_log, stderr_log)
    return CheckResult.err(
        "hard-exit recovery child returned %s instead of %s" % (process.exitcode, expected_exit),
        diagnostics=diagnostics,
    )
