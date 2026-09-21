"""Explicit and guided server commands share one validated retry policy."""

import json

import pytest
from click.testing import CliRunner

import jerryproxy.cli._common as common
import jerryproxy.cli.server as server_module
from jerryproxy.cli import cli
from jerryproxy.errors import BackendNotInstalledError, RuntimeSessionError


@pytest.fixture
def runtime(monkeypatch):
    captured = {}

    class Runtime(object):
        process = None

        def __init__(self, paths, **options):
            captured.update(options)

        def start(self, subscription_name, node_id, install_missing):
            captured["targets"] = (subscription_name, node_id)
            self.process = captured.get("child")
            if captured.get("start_error"):
                raise captured["start_error"]
            captured["log_sink"]("jerryproxy", "DEBUG", "debug-details")
            policy = captured["recovery_policy"]
            captured["event_sink"]({"event": "session.ready", "data": {
                "reason": "startup_healthy", "node": node_id, "attempts": 1,
                "candidates": 1, "delay": 0, "retry_policy": policy.retry_policy,
                "retry_chain": (policy.retry_chain or "current:1,adaptive:3,random:all")
                if policy.retry_policy == "fallback" else None,
            }})

        def public_info(self):
            if captured.get("invalid_envelope"):
                return None
            return {"listener": {"address": "127.0.0.1", "port": 17777, "protocol": "mixed"}}

        def wait(self):
            return captured.get("exit_code", 0)

        def stop(self):
            captured["stopped"] = True
            self.process = None

    monkeypatch.setattr(server_module, "RuntimeSession", Runtime)
    return captured


@pytest.mark.parametrize("policy", ["none", "fixed", "random", "adaptive", "fallback"])
def test_complete_command_selects_policy_without_prompts(tmp_path, monkeypatch, runtime, policy):
    def prompt(*args, **kwargs):
        pytest.fail("a complete command must not prompt")

    monkeypatch.setattr(common, "select", prompt)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--node", "a" * 32, "--retry-policy", policy,
                                     "--no-install-missing", "--log-format", "jsonl"])
    assert result.exit_code == 0, result.output
    assert runtime["recovery_policy"].retry_policy == policy
    ready = next(json.loads(line) for line in result.output.splitlines() if line.startswith("{"))
    assert ready["data"]["retry_policy"] == policy
    assert ready["data"]["retry_chain"] == ("current:1,adaptive:3,random:all" if policy == "fallback" else None)


@pytest.mark.parametrize("options", [
    ["--retry-policy", "fixed", "--retry-chain", "random:all"],
    ["--retry-chain", "random:0"], ["--retry-chain", "random:all,random:1"],
])
def test_invalid_chain_fails_before_selection_or_state_creation(tmp_path, runtime, options):
    home = tmp_path / "absent"
    result = CliRunner().invoke(cli, ["--home", str(home), "server"] + options)
    assert result.exit_code == 2, result.output
    assert "Error:" in result.output and "retry" in result.output
    assert "No such option" not in result.output
    assert not runtime and not home.exists()


def test_custom_chain_reaches_runtime(tmp_path, runtime):
    chain = "current:1,random:all"
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--node", "a" * 32, "--retry-chain", chain,
                                     "--no-install-missing", "--log-format", "jsonl"])
    assert result.exit_code == 0, result.output
    assert runtime["recovery_policy"].retry_chain == chain


@pytest.mark.parametrize("policy", ["none", "fixed", "random", "adaptive", "fallback"])
def test_guided_mode_offers_all_policies(tmp_path, monkeypatch, runtime, policy):
    monkeypatch.setattr(common, "interactive_available", lambda: True)
    monkeypatch.setattr(common, "select_subscription", lambda *args, **kwargs: "main")
    monkeypatch.setattr(common, "select_subscription_node", lambda *args: "a" * 32)
    offered = []

    def select(message, choices):
        offered.extend(choice.value for choice in choices)
        return policy

    monkeypatch.setattr(common, "select", select)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--protocol", "http", "--port", "17777",
                                     "--no-install-missing"])
    assert result.exit_code == 0, result.output
    assert set(offered) == {"none", "fixed", "random", "adaptive", "fallback"}
    assert runtime["recovery_policy"].retry_policy == policy
    assert "Recovery policy: %s" % policy in result.output


def test_jsonl_never_enters_guided_target_selection(tmp_path, monkeypatch, runtime):
    monkeypatch.setattr(common, "interactive_available", lambda: True)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--log-format", "jsonl"])
    assert result.exit_code == 2
    assert "required" in result.output
    assert not runtime


def test_jsonl_requires_an_explicit_node_even_on_a_tty(tmp_path, monkeypatch, runtime):
    monkeypatch.setattr(common, "interactive_available", lambda: True)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--log-format", "jsonl"])
    assert result.exit_code == 2
    assert "--node NODE_ID is required" in result.output
    assert not runtime


@pytest.mark.parametrize("width", [72, 80, 100, 120])
def test_rendered_help_describes_persistent_strategy_choices(width):
    result = CliRunner().invoke(cli, ["server", "--help"], terminal_width=width)
    assert result.exit_code == 0
    assert "--retry-policy" in result.output and "--retry-chain" in result.output
    assert "fixed" in result.output and "adaptive" in result.output
    assert max(map(len, result.output.splitlines())) <= width


@pytest.mark.parametrize("options, message", [
    (["--subscription", "a", "--subscription", "b"], "repeatable"),
    (["--backend", "xray"], "only Mihomo"),
    (["--backend-version", "0.0.0"], "qualified version"),
    (["--relay", "direct", "--relay-url", "https://example.com"], "mutually exclusive"),
    (["--relay-pattern", "host_path"], "requires --relay-url"),
])
def test_unsupported_server_options_are_rejected_before_runtime(tmp_path, runtime, options, message):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server"] + options)
    assert result.exit_code == 2
    assert message in result.output
    assert not runtime


@pytest.mark.parametrize("case", ["interrupt", "domain_error", "invalid_envelope", "child_exit", "success_child"])
def test_runtime_exit_and_failure_paths_clean_up(tmp_path, runtime, case):
    runtime["child"] = object()
    if case == "interrupt":
        runtime["start_error"] = KeyboardInterrupt()
    elif case == "domain_error":
        runtime["start_error"] = RuntimeSessionError("fixture failure")
    elif case == "invalid_envelope":
        runtime["invalid_envelope"] = True
    elif case == "child_exit":
        runtime["exit_code"] = 7
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--node", "a" * 32, "--no-install-missing", "--log-format", "jsonl"])
    assert result.exit_code == (0 if case in ("interrupt", "success_child") else 1), result.output
    assert runtime["stopped"]


def test_bootstrap_decline_never_creates_runtime(tmp_path, monkeypatch, runtime):
    class Missing(object):
        def which(self, *args):
            raise BackendNotInstalledError("missing")

    monkeypatch.setattr(common, "manager", lambda context: Missing())
    monkeypatch.setattr(common, "confirm_dangerous_operation", lambda *args, **kwargs: False)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--node", "a" * 32])
    assert result.exit_code == 1 and "bootstrap cancelled" in result.output
    assert not runtime


def test_guided_protocol_and_port_share_the_complete_runtime_path(tmp_path, monkeypatch, runtime):
    monkeypatch.setattr(common, "interactive_available", lambda: True)
    monkeypatch.setattr(common, "select_subscription", lambda *args, **kwargs: "main")
    monkeypatch.setattr(common, "select_subscription_node", lambda *args: "a" * 32)
    monkeypatch.setattr(common, "select", lambda message, choices: "http")
    monkeypatch.setattr(common, "prompt_text", lambda *args, **kwargs: "auto")
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--no-install-missing",
                                     "--retry-policy", "fixed"])
    assert result.exit_code == 0, result.output
    assert runtime["listener_protocol"] == "http"
    assert runtime["preferred_port"] is None
    assert runtime["recovery_policy"].retry_policy == "fixed"


@pytest.mark.parametrize("log_format", ["jsonl", "human"])
def test_lifecycle_output_reports_recovery_at_error_log_level(tmp_path, monkeypatch, log_format):
    from test.runtime.test_persistent import Clock, Probe, ReloadingDriver
    from test.runtime.test_session import _record, _session

    clock = Clock()
    record = _record(nodes=1)
    session = _session(tmp_path, record, Probe(lambda: clock.now >= 20),
                       clock=clock, sleeper=clock.sleep)
    session.driver = ReloadingDriver()
    session.wait = lambda: 0

    def runtime_factory(paths, **options):
        session.event_sink = options.get("event_sink")
        session.log_sink = options["log_sink"]
        session.log_level = options["log_level"]
        return session

    monkeypatch.setattr(server_module, "RuntimeSession", runtime_factory)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--node", record.nodes[0].node_id, "--no-install-missing",
                                     "--log-format", log_format, "--log-level", "ERROR"])
    assert result.exit_code == 0, result.output
    if log_format == "jsonl":
        events = [json.loads(line) for line in result.stdout.splitlines()]
        names = [event["event"] for event in events]
        assert names[0] == "session.starting"
        assert names[-2:] == ["session.ready", "session.stopped"]
        assert names.count("session.ready") == 1
        assert "session.degraded" in names and "session.retrying" in names
        assert events[-2]["data"]["health"]["ok"]
    else:
        assert "session.degraded" in result.output
        assert "session.ready" in result.output
        assert "session.stopped" in result.output


@pytest.mark.parametrize("guided", [False, True])
@pytest.mark.parametrize("override", [False, True])
def test_fast_recovery_defaults_and_overrides_match_both_entry_modes(tmp_path, monkeypatch, runtime, guided, override):
    monkeypatch.setattr(common, "interactive_available", lambda: True)
    monkeypatch.setattr(common, "select_subscription", lambda *args, **kwargs: "main")
    monkeypatch.setattr(common, "select_subscription_node", lambda *args: "a" * 32)
    questions = []

    def select(message, choices):
        questions.append(message)
        return "fallback"

    monkeypatch.setattr(common, "select", select)
    options = ["--home", str(tmp_path), "server", "--no-install-missing", "--protocol", "http", "--port", "17777"]
    if not guided:
        options += ["--subscription", "main", "--node", "a" * 32]
    if override:
        options += ["--fast-probe-timeout", "4", "--cache-retry-budget", "8",
                    "--refresh-timeout", "15", "--refresh-interval", "90"]
    result = CliRunner().invoke(cli, options)
    assert result.exit_code == 0, result.output
    policy = runtime["recovery_policy"]
    assert (policy.fast_probe_timeout, policy.cache_retry_budget, policy.refresh_timeout,
            policy.refresh_interval) == ((4, 8, 15, 90) if override else (3, 6, 10, 60))
    assert questions == (["Select an outage recovery policy:"] if guided else [])


@pytest.mark.parametrize("option,invalid", [
    ("--fast-probe-timeout", "0"), ("--fast-probe-timeout", "11"),
    ("--cache-retry-budget", "0"), ("--cache-retry-budget", "121"),
    ("--refresh-timeout", "0"), ("--refresh-timeout", "31"),
    ("--refresh-interval", "9"), ("--refresh-interval", "3601"),
])
def test_invalid_timing_option_never_starts_selection(tmp_path, runtime, option, invalid):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", option, invalid])
    assert result.exit_code == 2
    assert option in result.output and "range" in result.output
    assert not runtime


@pytest.mark.parametrize("width", [72, 80, 100, 120])
def test_rendered_help_exposes_fast_defaults_without_extra_mode(width):
    result = CliRunner().invoke(cli, ["server", "--help"], terminal_width=width)
    assert result.exit_code == 0
    for name, default in [("fast-probe-timeout", 3), ("cache-retry-budget", 6),
                          ("refresh-timeout", 10), ("refresh-interval", 60)]:
        section = result.output.split("--" + name, 1)[1].split("\n  --", 1)[0]
        assert "default: %d" % default in " ".join(section.split())
    assert max(map(len, result.output.splitlines())) <= width
