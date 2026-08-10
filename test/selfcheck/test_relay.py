import hashlib
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import CheckResult, build_checks, run_checks, run_self_check
from jerryproxy.selfcheck import processes as processes_module
from jerryproxy.selfcheck import relay as selfcheck_module
from jerryproxy.selfcheck import result as result_module
from jerryproxy.selfcheck import runner as runner_module
from test.selfcheck.children import (
    _crash_with_sensitive_relay_diagnostic,
    _fake_process_context,
    _FakeProcessContextBase,
    _write_maximum_relay_diagnostic,
    _write_partial_relay_result_and_stall,
)
from test.selfcheck.fakes import (
    FakeRelayResponse,
    RelaySessionFactory,
    relay_payload,
    verified_relay_session_factory,
)


def test_relay_checks_use_exact_bounded_range_and_report_metrics(tmp_path, monkeypatch):
    lines = []
    relay_factory = verified_relay_session_factory(monkeypatch)

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    assert len(relay_factory.sessions) == 3
    assert (
        sum(
            "relay " in line and "verified 1 MiB; response" in line and "; first chunk" in line and "; stream " in line
            for line in lines
        )
        == 3
    )
    for session in relay_factory.sessions:
        assert session.closed is True
        assert session.max_redirects == 5
        assert len(session.calls) == 1
        url, options = session.calls[0]
        assert url.startswith("https://")
        assert options["headers"]["Range"] == "bytes=0-1048575"
        assert options["allow_redirects"] is True
        assert options["stream"] is True
        assert options["timeout"] == 5.0
        assert session.outcome.closed is True


@pytest.mark.parametrize(
    "error, expected",
    [
        (
            selfcheck_module.requests.exceptions.TooManyRedirects("private redirect URL"),
            "redirect limit exceeded",
        ),
        (selfcheck_module.requests.exceptions.Timeout("private timeout URL"), "request timed out"),
        (selfcheck_module.requests.exceptions.SSLError("private TLS URL"), "TLS validation failed"),
        (selfcheck_module.requests.exceptions.ConnectionError("private connect URL"), "connection failed"),
        (selfcheck_module.requests.exceptions.ProxyError("private proxy URL"), "system proxy connection failed"),
        (selfcheck_module.requests.exceptions.RequestException("private request URL"), "request failed"),
    ],
)
def test_relay_transport_failures_are_sanitized_warnings(tmp_path, error, expected):
    relay_factory = RelaySessionFactory(lambda: error)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail
    assert "private" not in result.detail


def test_relay_http_failure_is_a_sanitized_warning(tmp_path):
    response = FakeRelayResponse(relay_payload(), status_code=403)
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn("bounded 1 MiB verification failed: HTTP response was not 206")
    assert "signed-value" not in result.detail


@pytest.mark.parametrize(
    "response, expected",
    [
        (
            FakeRelayResponse(
                relay_payload(),
                history=[SimpleNamespace(url="https://relay.example/%d" % index) for index in range(6)],
            ),
            "redirect limit exceeded",
        ),
        (
            FakeRelayResponse(
                relay_payload(),
                history=[SimpleNamespace(url="http://private.example/signed-query")],
            ),
            "redirect chain did not remain HTTPS",
        ),
    ],
)
def test_relay_redirect_policy_failures_are_sanitized_warnings(tmp_path, response, expected):
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail
    assert "private" not in result.detail


@pytest.mark.parametrize(
    "response_factory, expected",
    [
        (
            lambda: FakeRelayResponse(relay_payload(), content_range="bytes 0-1/2"),
            "Content-Range did not match the pinned asset",
        ),
        (
            lambda: FakeRelayResponse(relay_payload()[:-1]),
            "response body was not exactly 1 MiB",
        ),
        (
            lambda: FakeRelayResponse(relay_payload()),
            "pinned 1 MiB sample digest did not match",
        ),
    ],
)
def test_relay_content_failures_are_warnings(tmp_path, response_factory, expected, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "RELAY_PROBE_SHA256", "0" * 64)
    relay_factory = RelaySessionFactory(response_factory)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "WARN"
    assert expected in result.detail


def test_relay_probe_stops_after_one_bounded_overflow_chunk(tmp_path):
    response = FakeRelayResponse(relay_payload() + b"unexpected trailing response" * 4096)
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn("bounded 1 MiB verification failed: response body was not exactly 1 MiB")
    assert response.iterated_bytes <= selfcheck_module.RELAY_PROBE_BYTES + 64 * 1024


def test_relay_probe_ignores_empty_chunks_before_a_valid_stream(tmp_path, monkeypatch):
    payload = relay_payload()
    monkeypatch.setattr(
        selfcheck_module,
        "RELAY_PROBE_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    chunks = [b""] + [payload[offset : offset + 64 * 1024] for offset in range(0, len(payload), 64 * 1024)]
    relay_factory = RelaySessionFactory(lambda: FakeRelayResponse(payload, chunks=chunks))
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result.level == "OK"
    assert "over 16 chunks" in result.detail


def test_relay_probe_enforces_the_total_stream_budget(tmp_path, monkeypatch):
    moments = iter((0.0, 0.1, 30.1))
    monkeypatch.setattr(selfcheck_module.time, "monotonic", lambda: next(moments))
    response = FakeRelayResponse(relay_payload())
    relay_factory = RelaySessionFactory(lambda: response)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    result = relay_check()

    assert result == CheckResult.warn(
        "bounded 1 MiB verification failed: stream exceeded the 30-second total timeout"
    )
    assert response.closed is True


def test_production_relay_probe_uses_a_parent_enforced_deadline(monkeypatch):
    class TimedOutProcess(object):
        exitcode = None

        def __init__(self):
            self.join_timeouts = []
            self.terminated = False

        def start(self):
            pass

        def join(self, timeout):
            self.join_timeouts.append(timeout)

        def is_alive(self):
            return not self.terminated

        def terminate(self):
            self.terminated = True

    process = TimedOutProcess()
    profile = next(iter(runner_module.iter_builtin_relays()))

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            assert kwargs["target"] is selfcheck_module._captured_child_entry
            assert kwargs["args"][0] is selfcheck_module._relay_probe_child
            assert kwargs["args"][1][0] is profile
            assert Path(kwargs["args"][1][1]).name == "result.json"
            assert Path(kwargs["args"][2]).name == "stderr.log"
            assert kwargs["daemon"] is True
            return process

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(profile)

    assert result == CheckResult.warn("bounded 1 MiB verification failed: total probe deadline exceeded")
    assert process.terminated is True
    assert 0.0 < process.join_timeouts[0] <= 30.0


def test_production_relay_probe_reports_an_unstoppable_timeout_as_error(monkeypatch):
    class UnstoppableProcess(object):
        exitcode = None

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return True

        def terminate(self):
            pass

        def kill(self):
            pass

    process = UnstoppableProcess()

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return process

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result == CheckResult.err("timed-out relay probe child remained alive after kill")


def test_production_relay_probe_returns_the_child_result(monkeypatch):
    class CompletedProcess(object):
        exitcode = 0

        def __init__(self, result_path):
            self.result_path = result_path

        def start(self):
            selfcheck_module.atomic_write_json(
                self.result_path,
                {"level": "OK", "detail": "verified from child", "diagnostics": []},
            )

        def join(self, timeout):
            assert 0.0 < timeout <= 30.0

        def is_alive(self):
            return False

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return CompletedProcess(Path(kwargs["args"][1][1]))

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result == CheckResult.ok("verified from child")


def test_production_relay_probe_reads_a_maximum_bounded_file_result(monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_relay_probe_child", _write_maximum_relay_diagnostic)

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result.level == "ERR"
    assert result.detail == "maximum diagnostic from child"
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].startswith("relay child diagnostic start")
    assert result.diagnostics[0].endswith("relay child diagnostic end")
    assert len(result.diagnostics[0]) > 63 * 1024


def test_production_relay_probe_never_blocks_on_a_partial_result_file(monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_RELAY_CHECK_TOTAL_TIMEOUT", 3.0)
    monkeypatch.setattr(selfcheck_module, "_relay_probe_child", _write_partial_relay_result_and_stall)
    started = time.monotonic()

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert time.monotonic() - started < 5.0
    assert result.level in ("WARN", "ERR")
    if result.level == "ERR":
        assert "JSON" in result.detail


def test_production_relay_probe_captures_and_redacts_unexpected_child_stderr(monkeypatch, capfd):
    monkeypatch.setattr(selfcheck_module, "_relay_probe_child", _crash_with_sensitive_relay_diagnostic)

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))
    lines = []
    exit_code = run_checks((("relay crash", lambda: result),), lines.append)
    captured = capfd.readouterr()
    rendered = "\n".join(lines) + captured.out + captured.err

    assert exit_code == 1
    assert result.level == "ERR"
    assert result.diagnostics and "Traceback" in result.diagnostics[0]
    assert "[REDACTED" in rendered
    assert "user:pass" not in rendered
    assert "ghp_SUPERSECRET" not in rendered
    assert "123e4567-e89b-12d3-a456-426614174000" not in rendered
    assert "cHJpdmF0ZQ==" not in rendered


def test_production_relay_probe_skips_without_a_process_start_method(monkeypatch):
    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result == CheckResult.skip("no supported multiprocessing start method is available")


def test_production_relay_probe_bounds_a_stalled_process_start(monkeypatch):
    release = threading.Event()
    finished = threading.Event()
    terminated = threading.Event()
    reaped = threading.Event()
    captured = {}

    class StalledProcess(object):
        alive = False

        def start(self):
            release.wait(5.0)
            self.alive = True
            finished.set()

        def join(self, timeout):
            del timeout
            reaped.set()

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.alive = False
            terminated.set()

        def kill(self):
            self.alive = False

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            captured.update(kwargs)
            return StalledProcess()

    monkeypatch.setattr(selfcheck_module, "_RELAY_CHECK_TOTAL_TIMEOUT", 0.1)
    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())
    supervision = processes_module._ProcessSupervision()
    started = time.monotonic()
    try:
        result = selfcheck_module._check_relay_in_process(
            next(iter(runner_module.iter_builtin_relays())),
            supervision=supervision,
        )
        elapsed = time.monotonic() - started
    finally:
        release.set()
        finished.wait(1.0)
        reaped.wait(1.0)

    assert elapsed < 1.0
    assert result == CheckResult.err(
        "relay probe child startup exceeded the 0.1-second total deadline",
        diagnostics=("delayed process-start cleanup will be verified by the final supervision check",),
    )
    assert captured["daemon"] is True
    assert captured["args"][3].is_set() is False
    assert captured["args"][4].is_set() is True
    assert terminated.is_set()
    assert reaped.is_set()
    assert supervision.wait(1.0)
    assert supervision.result() == CheckResult.ok("1 delayed child start was cancelled and reaped")


def test_production_relay_probe_cancels_when_start_authorization_cannot_be_published(monkeypatch):
    events = []

    class AuthorizationEvent(threading.Event):
        def set(self):
            raise OSError("authorization event unavailable")

    class Context(object):
        def Event(self):
            event = AuthorizationEvent() if not events else threading.Event()
            events.append(event)
            if len(events) == 3:
                event.set()
            return event

        def Value(self, typecode, value):
            del typecode
            return SimpleNamespace(value=value)

        def Process(self, **kwargs):
            return SimpleNamespace(start=lambda: None)

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result == CheckResult.err(
        "relay probe child startup supervision failed: OSError: authorization event unavailable"
    )
    assert events[1].is_set() is True


def test_production_relay_probe_skips_when_process_construction_fails(monkeypatch):
    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            raise OSError("process construction denied")

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result == CheckResult.skip("spawn relay probe unavailable: OSError: process construction denied")


def test_production_relay_probe_skips_when_process_start_fails(monkeypatch):
    class RejectedProcess(object):
        def start(self):
            raise RuntimeError("spawn disabled")

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return RejectedProcess()

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result == CheckResult.skip("spawn relay probe unavailable: RuntimeError: spawn disabled")


def test_production_relay_probe_stops_a_child_after_join_failure(monkeypatch):
    class UnjoinableProcess(object):
        exitcode = None

        def __init__(self):
            self.terminated = False

        def start(self):
            pass

        def join(self, timeout):
            raise OSError("join denied")

        def is_alive(self):
            return not self.terminated

        def terminate(self):
            self.terminated = True

    process = UnjoinableProcess()

    class Context(_FakeProcessContextBase):
        def Process(self, **kwargs):
            return process

    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: Context())

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result.level == "ERR"
    assert result.detail == "relay probe child supervision failed"
    assert process.terminated is True
    assert result.diagnostics and "join failed: OSError: join denied" in result.diagnostics[0]


@pytest.mark.parametrize(
    "payload",
    (
        {"level": "BOGUS", "detail": "invalid", "diagnostics": []},
        {"level": "OK", "detail": 17, "diagnostics": []},
        {"level": "OK", "detail": "invalid", "diagnostics": "not a list"},
        {"level": "OK", "detail": "invalid", "diagnostics": ["one", "two"]},
        {"level": "OK", "detail": "invalid", "diagnostics": [17]},
        {"level": "OK", "detail": "invalid", "diagnostics": [], "extra": True},
    ),
)
def test_relay_child_result_rejects_invalid_contracts(tmp_path, payload):
    result_path = tmp_path / "result.json"
    selfcheck_module.atomic_write_json(result_path, payload)

    assert selfcheck_module._relay_child_result(result_path) == CheckResult.err(
        "relay probe child returned an invalid diagnostic result"
    )


def test_relay_child_result_handles_missing_invalid_and_oversized_files(tmp_path):
    result_path = tmp_path / "result.json"
    assert selfcheck_module._read_relay_child_result(result_path) is None

    result_path.write_text('{"level":', encoding="utf-8")
    invalid = selfcheck_module._relay_child_result(result_path)
    assert invalid.level == "ERR"
    assert "JSON" in invalid.detail

    result_path.write_bytes(b"{" + b" " * selfcheck_module._MAXIMUM_CHILD_RESULT_BYTES + b"}")
    oversized = selfcheck_module._relay_child_result(result_path)
    assert oversized.level == "ERR"
    assert "safety limit" in oversized.detail


def test_relay_child_result_accepts_valid_statuses_and_bounds_diagnostics(tmp_path):
    result_path = tmp_path / "result.json"
    diagnostic = "x" * result_module._MAXIMUM_DIAGNOSTIC_CHARACTERS
    selfcheck_module.atomic_write_json(
        result_path,
        {"level": "ERR", "detail": "child failure", "diagnostics": [diagnostic]},
    )

    result = selfcheck_module._relay_child_result(result_path)

    assert result == CheckResult.err("child failure", (diagnostic,))

    selfcheck_module.atomic_write_json(
        result_path,
        {"level": "OK", "detail": "ready", "diagnostics": []},
    )
    assert selfcheck_module._relay_child_result(result_path) == CheckResult.ok("ready")


def test_relay_probe_child_serializes_one_bounded_diagnostic(tmp_path, monkeypatch):
    result_path = tmp_path / "result.json"
    monkeypatch.setattr(
        selfcheck_module,
        "_check_relay",
        lambda profile, factory: CheckResult.err("failed", ("first", "second")),
    )

    selfcheck_module._relay_probe_child(next(iter(runner_module.iter_builtin_relays())), result_path)

    assert selfcheck_module._relay_child_result(result_path) == CheckResult.err("failed", ("first",))


def test_relay_probe_child_serializes_operational_exceptions(tmp_path, monkeypatch):
    result_path = tmp_path / "result.json"

    def fail_check(profile, factory):
        del profile, factory
        raise ValueError("token=secret-value")

    monkeypatch.setattr(selfcheck_module, "_check_relay", fail_check)

    selfcheck_module._relay_probe_child(next(iter(runner_module.iter_builtin_relays())), result_path)
    result = selfcheck_module._relay_child_result(result_path)
    rendered = result.detail + "\n" + "\n".join(result.diagnostics)

    assert result.level == "ERR"
    assert "[REDACTED]" in rendered
    assert "secret-value" not in rendered


@pytest.mark.parametrize(
    "exitcode, expected",
    (
        (17, "relay probe child returned exit code 17"),
        (0, "relay probe child exited without a diagnostic result"),
    ),
)
def test_production_relay_probe_reports_abnormal_child_results(monkeypatch, exitcode, expected):
    class CompletedProcess(object):
        def __init__(self):
            self.exitcode = exitcode

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return False

    context = _fake_process_context(lambda **kwargs: CompletedProcess())
    monkeypatch.setattr(processes_module.multiprocessing, "get_all_start_methods", lambda: ("spawn",))
    monkeypatch.setattr(processes_module.multiprocessing, "get_context", lambda method: context)

    result = selfcheck_module._check_relay_in_process(next(iter(runner_module.iter_builtin_relays())))

    assert result.level == "ERR"
    assert result.detail == expected
