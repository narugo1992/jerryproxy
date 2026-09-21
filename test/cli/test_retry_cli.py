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
