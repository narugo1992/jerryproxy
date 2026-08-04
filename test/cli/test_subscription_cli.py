import base64
import json

import pytest
from click.testing import CliRunner

import jerryproxy.cli._common as cli_common
import jerryproxy.cli.server as server_module
import jerryproxy.cli.subscription._common as subscription_common
from jerryproxy.cli import cli

SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
VMESS = "vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1NS01NTU1NTU1NTU1NTUiLCJuZXQiOiJ0Y3AiLCJwb3J0IjoiNDQzIiwicHMiOiJ2bWVzcyIsInRscyI6InRscyIsInYiOjJ9\n"


def _invoke(runner, home, *args, **kwargs):
    return runner.invoke(cli, ["--home", str(home)] + list(args), **kwargs)


def test_subscription_and_node_commands_publish_sanitized_records(tmp_path):
    runner = CliRunner()
    home = tmp_path / "home"
    body = tmp_path / "subscription.txt"
    body.write_text(SS + VMESS, encoding="ascii")

    added = _invoke(runner, home, "subscription", "add", "main", "--file", str(body), "--json")
    assert added.exit_code == 0, added.output
    value = json.loads(added.output)
    assert value["node_count"] == 2
    assert "source_url" not in added.output
    assert "password" not in added.output

    listed = _invoke(runner, home, "subscription", "list", "--json")
    assert listed.exit_code == 0
    assert json.loads(listed.output)[0]["name"] == "main"

    nodes = _invoke(runner, home, "node", "list", "main", "--json")
    assert nodes.exit_code == 0
    node_values = json.loads(nodes.output)
    assert len(node_values) == 2
    assert {item["scheme"] for item in node_values} == {"ss", "vmess"}
    assert "YWVzLTI1Ni1nY20" not in nodes.output

    shown = _invoke(runner, home, "subscription", "show", "main", "--json")
    assert shown.exit_code == 0
    assert len(json.loads(shown.output)["nodes"]) == 2

    validated = _invoke(runner, home, "subscription", "validate", "main", "--json")
    assert validated.exit_code == 0


def test_subscription_replace_keeps_id_and_changes_revision(tmp_path):
    runner = CliRunner()
    home = tmp_path / "home"
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text(SS, encoding="ascii")
    second.write_text(SS.replace("#ss", "#changed"), encoding="ascii")

    created = _invoke(runner, home, "subscription", "add", "main", "--file", str(first), "--json")
    replaced = _invoke(runner, home, "subscription", "replace", "main", "--file", str(second), "--json")
    assert created.exit_code == 0
    assert replaced.exit_code == 0, replaced.output
    assert json.loads(created.output)["id"] == json.loads(replaced.output)["id"]
    assert json.loads(created.output)["revision"] != json.loads(replaced.output)["revision"]


def test_destructive_json_requires_explicit_yes(tmp_path):
    runner = CliRunner()
    home = tmp_path / "home"
    body = tmp_path / "subscription.txt"
    body.write_text(SS, encoding="ascii")
    assert _invoke(runner, home, "subscription", "add", "main", "--file", str(body)).exit_code == 0

    refused = _invoke(runner, home, "subscription", "remove", "main", "--json")
    assert refused.exit_code == 2
    assert "requires -y/--yes" in refused.output
    assert _invoke(runner, home, "subscription", "show", "main", "--json").exit_code == 0

    removed = _invoke(runner, home, "subscription", "remove", "main", "--json", "-y")
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.output)["removed"] is True


def test_add_source_options_are_exclusive_and_json_never_prompts(tmp_path):
    runner = CliRunner()
    home = tmp_path / "home"
    result = _invoke(
        runner,
        home,
        "subscription",
        "add",
        "main",
        "--url-stdin",
        "--body-stdin",
        "--json",
        input="https://provider.example/sub\n",
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output

    no_source = _invoke(runner, home, "subscription", "add", "main", "--json")
    assert no_source.exit_code == 2
    assert "provide --url-env" in no_source.output


def test_base64_body_file_is_accepted(tmp_path):
    runner = CliRunner()
    home = tmp_path / "home"
    body = tmp_path / "subscription.b64"
    body.write_bytes(base64.b64encode(SS.encode("ascii")))
    result = _invoke(runner, home, "subscription", "add", "main", "--file", str(body), "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["format"] == "base64-uri-lines"


def test_subscription_guided_leaf_selects_missing_name(tmp_path, monkeypatch):
    runner = CliRunner()
    home = tmp_path / "home"
    body = tmp_path / "subscription.txt"
    body.write_text(SS, encoding="ascii")
    created = _invoke(runner, home, "subscription", "add", "main", "--file", str(body), "--json")
    assert created.exit_code == 0, created.output

    class Prompt(object):
        def execute(self):
            return "main"

    monkeypatch.setattr(cli_common, "interactive_available", lambda: True)
    monkeypatch.setattr(cli_common.inquirer, "select", lambda **kwargs: Prompt())
    result = _invoke(runner, home, "subscription", "show")

    assert result.exit_code == 0, result.output
    assert "Subscription: main" in result.output
    assert "YWVzLTI1Ni1nY20" not in result.output


def test_subscription_group_guided_menu_dispatches_read_only_action(tmp_path, monkeypatch):
    class Prompt(object):
        def execute(self):
            return "list"

    monkeypatch.setattr(cli_common.inquirer, "select", lambda **kwargs: Prompt())
    result = _invoke(CliRunner(), tmp_path / "home", "subscription")

    assert result.exit_code == 0, result.output
    assert "No subscriptions stored." in result.output


def test_subscription_missing_name_is_rejected_for_json_and_noninteractive(tmp_path):
    runner = CliRunner()
    home = tmp_path / "home"
    body = tmp_path / "subscription.txt"
    body.write_text(SS, encoding="ascii")
    assert _invoke(runner, home, "subscription", "add", "main", "--file", str(body), "--json").exit_code == 0

    for arguments in (
        ("show", "--json"),
        ("refresh", "--json"),
        ("validate", "--json"),
        ("remove", "--json", "-y"),
    ):
        result = _invoke(runner, home, "subscription", *arguments)
        assert result.exit_code == 2, result.output
        assert "NAME is required" in result.output

    add = _invoke(runner, home, "subscription", "add", "--file", str(body), "--json")
    assert add.exit_code == 2
    assert "NAME is required" in add.output


def test_server_guided_selection_passes_explicit_targets_to_runtime(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setenv("COLUMNS", "200")

    class FakeRuntime(object):
        def __init__(self, paths, **kwargs):
            del paths
            captured["init"] = kwargs
            self.process = None

        def start(self, subscription_name, node_id, install_missing):
            captured["start"] = (subscription_name, node_id, install_missing)
            captured["init"]["log_sink"]("mihomo", "INFO", "[TCP] live request")

        def public_info(self):
            return {
                "listener": {
                    "address": "127.0.0.1",
                    "port": 1080,
                    "kind": "mixed",
                    "protocol": "http",
                },
                "access_file": str(tmp_path / "access.json"),
                "log_file": str(tmp_path / "runtime.log"),
            }

        def wait(self):
            return 0

        def stop(self):
            captured["stopped"] = True

    selections = iter(["main", "a" * 32])
    monkeypatch.setattr(server_module, "RuntimeSession", FakeRuntime)
    monkeypatch.setattr(cli_common, "interactive_available", lambda: True)
    monkeypatch.setattr(
        cli_common,
        "select_subscription",
        lambda context, message, enabled_only=False: next(selections),
    )
    monkeypatch.setattr(
        cli_common,
        "select_subscription_node",
        lambda context, name, message: next(selections),
    )

    result = _invoke(
        CliRunner(),
        tmp_path / "home",
        "server",
        "--no-install-missing",
        "--protocol",
        "http",
        "--port",
        "18080",
        terminal_width=200,
    )

    assert result.exit_code == 0, result.output
    assert captured["start"] == ("main", "a" * 32, False)
    assert captured["init"]["listener_protocol"] == "http"
    assert captured["init"]["authenticate"] is False
    assert captured["init"]["preferred_port"] == 18080
    assert captured["init"]["strict_port"] is True
    assert "JerryProxy is ready" in result.output
    assert "Proxy URL: http://127.0.0.1:1080" in result.output
    assert "[jerryproxy]" not in result.output
    compact_output = "".join(result.output.split())
    assert "exportHTTP_PROXY='http://127.0.0.1:1080'" in compact_output
    assert "exportHTTPS_PROXY='http://127.0.0.1:1080'" in compact_output
    assert "exportALL_PROXY='http://127.0.0.1:1080'" in compact_output
    assert "Access file:" not in result.output
    assert "Log file:" not in result.output
    assert "[mihomo]" in result.output
    assert "[TCP] live request" in result.output


@pytest.mark.parametrize("width", [72, 80, 100, 120])
def test_runtime_help_fits_supported_terminal_widths(width):
    result = CliRunner().invoke(cli, ["server", "--help"], terminal_width=width)

    assert result.exit_code == 0, result.output
    assert not [line for line in result.output.splitlines() if len(line) > width]


def test_server_yes_never_guesses_missing_subscription_or_node(tmp_path):
    result = _invoke(CliRunner(), tmp_path / "home", "server", "--yes", "--no-install-missing")

    assert result.exit_code == 2, result.output
    assert "cannot infer a subscription" in result.output


def test_server_auth_mode_prints_copyable_proxy_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")

    class FakeRuntime(object):
        def __init__(self, paths, **kwargs):
            del paths
            self.process = None
            self.username = "local-user"
            self.password = "local-password"
            assert kwargs["authenticate"] is True

        def start(self, subscription_name, node_id, install_missing):
            del subscription_name, node_id, install_missing

        def public_info(self):
            return {
                "listener": {
                    "address": "127.0.0.1",
                    "port": 1080,
                    "kind": "http",
                    "protocol": "http",
                    "authentication": True,
                },
                "access_file": str(tmp_path / "access.json"),
                "log_file": str(tmp_path / "runtime.log"),
            }

        def wait(self):
            return 0

        def stop(self):
            pass

    monkeypatch.setattr(server_module, "RuntimeSession", FakeRuntime)
    result = _invoke(
        CliRunner(),
        tmp_path / "home",
        "server",
        "--subscription",
        "main",
        "--node",
        "a" * 32,
        "--protocol",
        "http",
        "--auth",
        "--no-install-missing",
        terminal_width=400,
    )

    assert result.exit_code == 0, result.output
    assert "Authentication is enabled" in result.output
    compact_output = "".join(result.output.split())
    assert "username'local-user'andpassword'local-password'" in compact_output
    assert "exportHTTP_PROXY='http://local-user:local-password@127.0.0.1:1080'" in compact_output
    assert "exportHTTPS_PROXY='http://local-user:local-password@127.0.0.1:1080'" in compact_output
    assert "exportALL_PROXY='http://local-user:local-password@127.0.0.1:1080'" in compact_output
    assert "Accessfile:" not in result.output
    assert "Logfile:" not in result.output


def test_server_socks5_startup_prints_socks5h_environment_guide(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")

    class FakeRuntime(object):
        def __init__(self, paths, **kwargs):
            del paths
            self.process = None
            self.username = None
            self.password = None
            assert kwargs["listener_protocol"] == "socks5"

        def start(self, subscription_name, node_id, install_missing):
            del subscription_name, node_id, install_missing

        def public_info(self):
            return {
                "backend": "mihomo",
                "backend_version": "1.19.29",
                "listener": {
                    "address": "127.0.0.1",
                    "port": 1080,
                    "kind": "socks5",
                    "protocol": "socks5",
                    "authentication": False,
                },
                "access_file": str(tmp_path / "access.json"),
                "log_file": str(tmp_path / "runtime.log"),
            }

        def wait(self):
            return 0

        def stop(self):
            pass

    monkeypatch.setattr(server_module, "RuntimeSession", FakeRuntime)
    result = _invoke(
        CliRunner(),
        tmp_path / "home",
        "server",
        "--subscription",
        "main",
        "--node",
        "a" * 32,
        "--protocol",
        "socks5",
        "--no-install-missing",
        terminal_width=400,
    )

    assert result.exit_code == 0, result.output
    assert "Proxy URL: socks5h://127.0.0.1:1080" in result.output
    compact_output = "".join(result.output.split())
    assert "exportHTTP_PROXY='socks5h://127.0.0.1:1080'" in compact_output
    assert "exportHTTPS_PROXY='socks5h://127.0.0.1:1080'" in compact_output
    assert "exportALL_PROXY='socks5h://127.0.0.1:1080'" in compact_output
    assert "Access file:" not in result.output
    assert "Log file:" not in result.output


def test_server_bind_all_passes_wildcard_listener_and_warns(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setenv("COLUMNS", "200")

    class FakeRuntime(object):
        def __init__(self, paths, **kwargs):
            del paths
            captured.update(kwargs)
            self.process = None

        def start(self, subscription_name, node_id, install_missing):
            del subscription_name, node_id, install_missing

        def public_info(self):
            return {
                "listener": {
                    "address": "0.0.0.0",
                    "port": 1080,
                    "kind": "http",
                    "protocol": "http",
                    "authentication": False,
                },
                "access_file": str(tmp_path / "access.json"),
                "log_file": str(tmp_path / "runtime.log"),
            }

        def wait(self):
            return 0

        def stop(self):
            pass

    monkeypatch.setattr(server_module, "RuntimeSession", FakeRuntime)
    result = _invoke(
        CliRunner(),
        tmp_path / "home",
        "server",
        "--subscription",
        "main",
        "--node",
        "a" * 32,
        "--protocol",
        "http",
        "--bind-all",
        "--no-install-missing",
        terminal_width=200,
    )

    assert result.exit_code == 0, result.output
    assert captured["bind_address"] == "0.0.0.0"
    assert "proxy at 0.0.0.0:1080" in result.output
    assert "exposedonallinterfaces" in "".join(result.output.split())

    json_result = _invoke(
        CliRunner(),
        tmp_path / "home-json",
        "server",
        "--subscription",
        "main",
        "--node",
        "a" * 32,
        "--protocol",
        "http",
        "--bind-all",
        "--log-format",
        "jsonl",
        "--no-install-missing",
    )
    assert json_result.exit_code == 0, json_result.output
    assert "listener is exposed on all interfaces" in json_result.output


def test_guided_port_input_checks_default_and_accepts_entered_value(monkeypatch):
    monkeypatch.setattr(server_module, "_port_available", lambda port, bind_address="127.0.0.1": port == 19000)

    def reserve(preferred=None, strict=False, bind_address="127.0.0.1"):
        del preferred, strict, bind_address
        return 19000

    monkeypatch.setattr(server_module, "reserve_loopback_port", reserve)
    captured = {}

    def prompt(message, default=None):
        captured["message"] = message
        captured["default"] = default
        return default

    monkeypatch.setattr(cli_common, "prompt_text", prompt)

    assert server_module._select_interactive_port() == (19000, True)
    assert captured["default"] == "19000"
    assert "press Enter" in captured["message"]


def test_guided_port_input_accepts_auto(monkeypatch):
    monkeypatch.setattr(server_module, "_port_available", lambda port, bind_address="127.0.0.1": True)
    monkeypatch.setattr(cli_common, "prompt_text", lambda message, default=None: "auto")

    assert server_module._select_interactive_port() == (None, False)


def test_guided_add_source_wizard_discovers_and_completes_environment_names(tmp_path, monkeypatch):
    captured = {}

    class Prompt(object):
        def __init__(self, value):
            self.value = value

        def execute(self):
            return self.value

    class FakeRecord(object):
        name = "guided"
        revision = "r"
        format = "uri-lines"
        enabled = True
        node_count = 0
        nodes = ()

        def public(self, include_nodes=True):
            del include_nodes
            return {
                "name": self.name,
                "revision": self.revision,
                "format": self.format,
                "enabled": True,
                "node_count": 0,
            }

    class FakeManager(object):
        def add(self, name, source_url, body=None, format_hint="auto"):
            captured.update(name=name, source_url=source_url, body=body, format_hint=format_hint)
            return FakeRecord()

    monkeypatch.setenv("MY_V2RAY_SUBSCRIPTION", "https://provider.example/sub?token=hidden")
    monkeypatch.setattr(cli_common, "interactive_available", lambda: True)
    monkeypatch.setattr(subscription_common, "subscriptions", lambda context: FakeManager())
    selections = iter(["env", "__custom__"])
    text_kwargs = []
    monkeypatch.setattr(
        cli_common.inquirer,
        "select",
        lambda **kwargs: Prompt(next(selections)),
    )

    def text_prompt(**kwargs):
        text_kwargs.append(kwargs)
        return Prompt("MY_V2RAY_SUBSCRIPTION")

    monkeypatch.setattr(cli_common.inquirer, "text", text_prompt)
    result = _invoke(CliRunner(), tmp_path / "home", "subscription", "add", "guided")

    assert result.exit_code == 0, result.output
    assert captured == {
        "name": "guided",
        "source_url": "https://provider.example/sub?token=hidden",
        "body": None,
        "format_hint": "auto",
    }
    assert "MY_V2RAY_SUBSCRIPTION" in text_kwargs[0]["completer"]
    assert "hidden" not in result.output
