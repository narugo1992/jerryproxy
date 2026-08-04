import base64
import json

from click.testing import CliRunner

from jerryproxy.cli import cli

SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
VMESS = "vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTU1LTU1NTUtNTU1NTU1NTU1NTU1IiwibmV0IjoidGNwIiwicG9ydCI6IjQ0MyIsInBzIjoidm1lc3MiLCJ0bHMiOiJ0bHMiLCJ2IjoyfQ==\n"


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
