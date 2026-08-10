"""Module-level spawn targets shared by the self-check tests.

A spawned child re-imports its target by module path, so these must live at
module level in one place rather than inside the test that uses them.
"""

import threading
import time
from pathlib import Path
from types import SimpleNamespace

from jerryproxy.utils.fs import atomic_write_json


def _write_maximum_relay_diagnostic(unused_profile, result_path):
    diagnostic = "relay child diagnostic start\n%s\nrelay child diagnostic end" % (
        "x" * (64 * 1024 - 128)
    )
    atomic_write_json(
        Path(result_path),
        {
            "level": "ERR",
            "detail": "maximum diagnostic from child",
            "diagnostics": [diagnostic],
        },
    )


def _write_partial_relay_result_and_stall(unused_profile, result_path):
    Path(result_path).write_text('{"level":', encoding="utf-8")
    time.sleep(10.0)


def _crash_with_sensitive_relay_diagnostic(unused_profile, result_path):
    del result_path
    raise RuntimeError(
        "https://user:pass@example.com/?token=secret "
        "Authorization: Bearer ghp_SUPERSECRET "
        "uuid=123e4567-e89b-12d3-a456-426614174000 "
        "private key: cHJpdmF0ZQ=="
    )


def _crash_with_sensitive_recovery_diagnostic(error_log):
    del error_log
    raise RuntimeError(
        "https://user:pass@example.com/?token=secret "
        "Authorization: Bearer ghp_SUPERSECRET "
        "uuid=123e4567-e89b-12d3-a456-426614174000 "
        "private key: cHJpdmF0ZQ=="
    )


def _write_start_gate_sentinel(path):
    Path(path).write_text("business code ran", encoding="utf-8")


def _fake_process_context(process_factory):
    events = []

    def event_factory():
        event = threading.Event()
        events.append(event)
        if len(events) == 3:
            event.set()
        return event

    return SimpleNamespace(
        Process=process_factory,
        Event=event_factory,
        Value=lambda typecode, value: SimpleNamespace(value=value),
    )


class _FakeProcessContextBase(object):
    def Event(self):
        count = getattr(self, "_event_count", 0) + 1
        self._event_count = count
        event = threading.Event()
        if count == 3:
            event.set()
        return event

    @staticmethod
    def Value(typecode, value):
        del typecode
        return SimpleNamespace(value=value)
