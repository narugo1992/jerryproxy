import gzip
import hashlib
import json
import runpy
import sys
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import jerryproxy.cli as cli_module
from jerryproxy.backend.catalog import BackendCatalog
from jerryproxy.backend.manager import BackendManager
from jerryproxy.backend.platform import detect_platform
from jerryproxy.cli import cli, main
from jerryproxy.home import JerryProxyPaths


def install_fake_mihomo(home, tmp_path, version, payload, activate):
    archive = tmp_path / ("mihomo-%s.gz" % version)
    with gzip.open(str(archive), "wb") as stream:
        stream.write(payload)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return BackendManager(JerryProxyPaths(home), probe_runner=lambda installed: None).install_from_archive(
        "mihomo",
        version,
        archive,
        expected_sha256=digest,
        activate=activate,
    )


def test_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "jerryproxy, version 0.1.0a1" in result.output


def test_home_override(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "home"])
    assert result.exit_code == 0
    assert result.output.strip() == str(tmp_path)


def test_backend_command_surface_is_consolidated():
    result = CliRunner().invoke(cli, ["backend", "--help"])
    assert result.exit_code == 0
    for command in ("available", "clean", "install", "list", "remove", "switch", "verify"):
        assert "  %s " % command in result.output
    for removed in ("artifact", "current", "supported", "update", "versions"):
        assert "  %s " % removed not in result.output


def test_empty_backend_list_uses_private_home(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "list"])
    assert result.exit_code == 0
    assert "No backend versions installed." in result.output
    assert (tmp_path / "backends").is_dir()


def test_doctor_reports_platform_and_counts(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "doctor"])
    assert result.exit_code == 0
    assert "JerryProxy 0.1.0a1" in result.output
    assert "Installed backends: 0" in result.output
    assert "Active backends: 0" in result.output
    assert "Backend catalog:" in result.output
    assert "Catalog compatibility: 4/4 backends" in result.output


def test_self_check_reports_each_check_and_summary(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "self-check"])

    assert result.exit_code == 0
    assert "[1/8] Python runtime: OK" in result.output
    assert "[7/8] packaged backend catalog: OK" in result.output
    assert "[8/8] backend inventory: OK" in result.output
    assert "Summary: 8 OK, 0 FAIL" in result.output
    assert "Self-check PASSED" in result.output


def test_self_check_can_force_ansi_color(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["--home", str(tmp_path), "self-check", "--color"],
        color=True,
    )

    assert result.exit_code == 0
    assert "\033[1;32mOK\033[0m" in result.output
    assert "\033[1;32mSelf-check PASSED\033[0m" in result.output


def test_self_check_failure_reaches_console_exit_code_through_real_state(tmp_path, monkeypatch, capsys):
    invalid_home = tmp_path / "invalid-home"
    invalid_home.mkdir()
    (invalid_home / "backends").write_text("not a directory", encoding="ascii")
    monkeypatch.setattr(
        sys,
        "argv",
        ["jerryproxy", "--home", str(invalid_home), "self-check"],
    )

    assert main() == 1
    captured = capsys.readouterr()
    assert "FileExistsError" in captured.out
    assert "Self-check FAILED" in captured.out
    assert "Error: self-check failed; inspect the diagnostics above" in captured.err


def test_install_unknown_backend_reports_domain_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "jerryproxy",
            "--home",
            str(tmp_path),
            "backend",
            "install",
            "unknown",
            "1.0.0",
        ],
    )
    assert main() == 1
    assert "Error: unsupported backend: unknown" in capsys.readouterr().err


def test_available_command_browses_overview_versions_and_exact_artifact_offline():
    runner = CliRunner()
    catalog = BackendCatalog.load()
    platform_info = detect_platform()
    expected_versions = catalog.available_versions("mihomo", platform_info)
    expected_artifact = expected_versions[0].artifact_for(platform_info)
    available = runner.invoke(cli, ["backend", "available", "--json"])

    assert available.exit_code == 0
    overview = {record["backend"]: record for record in json.loads(available.output)}
    assert sorted(overview) == ["mihomo", "sing-box", "v2ray", "xray"]
    assert set(overview["mihomo"]) == {
        "available_versions",
        "backend",
        "catalog_generated_at",
        "catalog_releases",
        "description",
        "latest",
        "platform",
        "upstream",
    }
    assert overview["mihomo"]["latest"] == expected_versions[0].version
    assert overview["mihomo"]["platform"] == platform_info.asset_key
    assert overview["mihomo"]["upstream"] == "MetaCubeX/mihomo"
    assert overview["mihomo"]["description"]

    human_available = runner.invoke(cli, ["backend", "available"])
    assert human_available.exit_code == 0
    assert "BACKEND" in human_available.output
    assert "AVAILABLE" in human_available.output
    assert "HOST" in human_available.output
    assert "UPSTREAM" in human_available.output
    assert platform_info.asset_key in human_available.output

    versions = runner.invoke(cli, ["backend", "available", "mihomo", "--limit", "2", "--json"])
    assert versions.exit_code == 0
    records = json.loads(versions.output)
    assert [record["version"] for record in records] == [item.version for item in expected_versions[:2]]
    assert all(record["backend"] == "mihomo" for record in records)
    assert all(record["platform"] == expected_artifact.platform for record in records)
    assert all(len(record["sha256"]) == 64 for record in records)

    human_versions = runner.invoke(cli, ["backend", "available", "mihomo", "--limit", "1"])
    assert human_versions.exit_code == 0
    assert "VERSION" in human_versions.output
    assert "TARGET" in human_versions.output
    assert expected_artifact.name in human_versions.output

    all_platforms = runner.invoke(
        cli,
        ["backend", "available", "mihomo", "--all-platforms", "--limit", "2"],
    )
    assert all_platforms.exit_code == 0
    assert "PLATFORMS" in all_platforms.output
    assert "PUBLISHED" in all_platforms.output
    assert expected_versions[0].version in all_platforms.output

    artifact = runner.invoke(cli, ["backend", "available", "mihomo", expected_artifact.version])
    assert artifact.exit_code == 0
    assert "Version: %s" % expected_artifact.version in artifact.output
    assert "Catalog target: %s" % expected_artifact.platform in artifact.output
    assert "SHA-256:" in artifact.output
    assert expected_artifact.url in artifact.output

    artifact_json = runner.invoke(
        cli,
        ["backend", "available", "mihomo", expected_artifact.version, "--json"],
    )
    assert artifact_json.exit_code == 0
    artifact_record = json.loads(artifact_json.output)
    assert set(artifact_record) == {
        "asset",
        "backend",
        "catalog_generated_at",
        "platform",
        "published_at",
        "sha256",
        "size",
        "url",
        "verification",
        "version",
    }
    assert artifact_record["version"] == expected_artifact.version
    assert artifact_record["sha256"] == expected_artifact.sha256
    assert artifact_record["verification"] == expected_artifact.verification

    invalid = runner.invoke(
        cli,
        ["backend", "available", "mihomo", expected_artifact.version, "--all-platforms"],
    )
    assert invalid.exit_code == 2
    assert "cannot be combined with VERSION" in invalid.output


def test_backend_inventory_switch_and_remove_commands(tmp_path, monkeypatch):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=True)
    install_fake_mihomo(home, tmp_path, "2.0.0", b"two", activate=False)
    runner = CliRunner()

    def manager(context):
        return BackendManager(
            JerryProxyPaths.from_value(context.obj.get("home")),
            probe_runner=lambda installed: None,
        )

    monkeypatch.setattr(cli_module, "_manager", manager)

    listed = runner.invoke(cli, ["--home", str(home), "backend", "list", "mihomo"])
    assert listed.exit_code == 0
    assert "*" in listed.output
    assert "mihomo" in listed.output
    assert "1.0.0" in listed.output
    assert "2.0.0" in listed.output

    switched = runner.invoke(cli, ["--home", str(home), "backend", "switch", "mihomo", "2.0.0"])
    assert switched.exit_code == 0
    assert "Active: mihomo 2.0.0" in switched.output

    active = runner.invoke(
        cli,
        ["--home", str(home), "backend", "list", "mihomo", "--active", "--json"],
    )
    assert active.exit_code == 0
    active_records = json.loads(active.output)
    assert len(active_records) == 1
    assert active_records[0]["backend"] == "mihomo"
    assert active_records[0]["version"] == "2.0.0"
    assert active_records[0]["active"] is True
    assert active_records[0]["mode"] in ("copy", "symlink")
    assert active_records[0]["link"]

    doctor = runner.invoke(cli, ["--home", str(home), "doctor"])
    assert doctor.exit_code == 0
    assert "Active backends: 1" in doctor.output
    assert "mihomo" in doctor.output
    assert "2.0.0" in doctor.output

    verified = runner.invoke(cli, ["--home", str(home), "backend", "verify", "mihomo"])
    assert verified.exit_code == 0
    assert "EXECUTABLE SHA256" in verified.output
    assert "mihomo" in verified.output

    removed = runner.invoke(cli, ["--home", str(home), "backend", "remove", "mihomo", "1.0.0", "-y"])
    assert removed.exit_code == 0
    assert "Removed 1 installed version(s): 1.0.0" in removed.output


def test_backend_remove_confirmation_rejection_preserves_installed_version(tmp_path, monkeypatch):
    home = tmp_path / "home"
    installed = install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=False)

    class Prompt(object):
        def execute(self):
            return False

    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: Prompt())
    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "remove", "mihomo", "1.0.0"])

    assert result.exit_code == 0
    assert "Cancelled." in result.output
    assert installed.manifest.is_file()


def test_backend_remove_yes_bypasses_prompt_and_cleans_matching_downloads(tmp_path, monkeypatch):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=False)
    cached = home / "downloads" / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(b"cache")

    def unexpected_prompt(**kwargs):
        raise AssertionError("-y must bypass InquirerPy confirmation")

    monkeypatch.setattr(cli_module.inquirer, "confirm", unexpected_prompt)
    result = CliRunner().invoke(
        cli,
        ["--home", str(home), "backend", "remove", "mihomo", "1.0.0", "--downloads", "-y"],
    )

    assert result.exit_code == 0
    assert "Cleaned downloads: 1 target(s), 5.0 B reclaimed" in result.output
    assert not cached.exists()


def test_backend_remove_all_deactivates_and_removes_every_version(tmp_path):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=True)
    install_fake_mihomo(home, tmp_path, "2.0.0", b"two", activate=False)

    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "remove", "mihomo", "-A", "-y"])

    assert result.exit_code == 0
    assert "Removed 2 installed version(s)" in result.output
    assert not (home / "backends" / "mihomo").exists()
    assert not (home / "active" / "mihomo.json").exists()
    assert not (home / "bin" / "mihomo").exists()


def test_backend_clean_explicit_areas_and_yes_are_noninteractive(tmp_path, monkeypatch):
    home = tmp_path / "home"
    paths = JerryProxyPaths(home)
    paths.ensure()
    (paths.logs / "backend.log").write_bytes(b"log")
    (paths.runtimes / "runtime.json").write_bytes(b"runtime")
    preserved = paths.backends / "mihomo" / "1.0.0" / "manifest.json"
    preserved.parent.mkdir(parents=True)
    preserved.write_text("{}", encoding="ascii")

    def unexpected_prompt(**kwargs):
        raise AssertionError("-y must bypass InquirerPy confirmation")

    monkeypatch.setattr(cli_module.inquirer, "confirm", unexpected_prompt)
    result = CliRunner().invoke(
        cli,
        ["--home", str(home), "backend", "clean", "--logs", "--runtimes", "-y"],
    )

    assert result.exit_code == 0
    assert "Cleaned logs, runtimes: 2 target(s), 10.0 B reclaimed" in result.output
    assert list(paths.logs.iterdir()) == []
    assert list(paths.runtimes.iterdir()) == []
    assert preserved.is_file()


def test_backend_clean_short_command_guides_scope_then_confirms(tmp_path, monkeypatch):
    home = tmp_path / "home"
    cached = home / "downloads" / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cache")
    selections = iter(["downloads-version", "1.0.0"])
    confirmations = []

    monkeypatch.setattr(cli_module, "_select", lambda message, choices: next(selections))
    monkeypatch.setattr(cli_module, "_select_backend", lambda message, names=None: "mihomo")
    monkeypatch.setattr(
        cli_module,
        "_confirm_dangerous_operation",
        lambda message, assume_yes: confirmations.append(message) or True,
    )
    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "clean"])

    assert result.exit_code == 0
    assert confirmations == ["Clean mihomo 1.0.0 downloads?"]
    assert not cached.exists()


def test_backend_group_short_command_dispatches_selected_operation(tmp_path, monkeypatch):
    class Prompt(object):
        def execute(self):
            return "list"

    monkeypatch.setattr(cli_module.inquirer, "select", lambda **kwargs: Prompt())

    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend"])

    assert result.exit_code == 0
    assert "No backend versions installed." in result.output


def test_guided_install_uses_real_inquirer_selection_boundary(tmp_path, monkeypatch):
    selections = iter(["mihomo", ""])
    prompts = []
    manager = BackendManager(JerryProxyPaths(tmp_path / "home"), probe_runner=lambda installed: None)
    captured = {}

    class Prompt(object):
        def __init__(self, value):
            self.value = value

        def execute(self):
            return self.value

    def select(**kwargs):
        prompts.append(kwargs["message"])
        return Prompt(next(selections))

    class GuidedManager(object):
        platform_info = manager.platform_info

        def available(self, name):
            return manager.available(name)

        def resolve_artifact(self, name, version):
            return manager.resolve_artifact(name, version)

        def install(self, name, version, activate):
            artifact = manager.resolve_artifact(name, version)
            captured.update(name=name, version=version, activate=activate)
            return SimpleNamespace(
                name=name,
                version=artifact.version,
                executable=tmp_path / "mihomo",
            )

    class ConfirmPrompt(object):
        def execute(self):
            return False

    monkeypatch.setattr(cli_module, "_manager", lambda context: GuidedManager())
    monkeypatch.setattr(cli_module.inquirer, "select", select)
    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: ConfirmPrompt())
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "install"])

    assert result.exit_code == 0
    assert prompts == ["Select a backend to install:", "Select a stable version:"]
    assert captured == {"name": "mihomo", "version": None, "activate": False}
    assert "Installed: mihomo" in result.output


def test_guided_remove_selects_active_version_and_final_confirmation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=True)
    selections = iter(["mihomo", "1.0.0"])
    confirmations = iter([False, True])

    class Prompt(object):
        def __init__(self, value):
            self.value = value

        def execute(self):
            return self.value

    monkeypatch.setattr(
        cli_module.inquirer,
        "select",
        lambda **kwargs: Prompt(next(selections)),
    )
    monkeypatch.setattr(
        cli_module.inquirer,
        "confirm",
        lambda **kwargs: Prompt(next(confirmations)),
    )
    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "remove"])

    assert result.exit_code == 0
    assert "Removed 1 installed version(s): 1.0.0" in result.output
    assert not (home / "active" / "mihomo.json").exists()


def test_incomplete_command_reports_unavailable_interactive_input(tmp_path, monkeypatch):
    class Prompt(object):
        def execute(self):
            raise EOFError()

    monkeypatch.setattr(cli_module.inquirer, "select", lambda **kwargs: Prompt())
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "install"])

    assert result.exit_code == 1
    assert "interactive selection unavailable" in result.output


def test_destructive_command_reports_unavailable_confirmation(tmp_path, monkeypatch):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=False)

    class Prompt(object):
        def execute(self):
            raise EOFError()

    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: Prompt())
    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "remove", "mihomo", "1.0.0"])

    assert result.exit_code == 1
    assert "interactive confirmation unavailable; rerun with --yes" in result.output


def test_guided_commands_report_empty_installed_inventory(tmp_path):
    switch = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "switch"])
    remove = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "remove", "mihomo"])

    assert switch.exit_code == 1
    assert "no backend matches this interactive operation" in switch.output
    assert remove.exit_code == 1
    assert "no installed versions found for mihomo" in remove.output


def test_clean_all_and_invalid_option_combinations(tmp_path):
    home = tmp_path / "home"
    paths = JerryProxyPaths(home)
    paths.ensure()
    (paths.providers / "provider.yaml").write_bytes(b"provider")

    cleaned = CliRunner().invoke(cli, ["--home", str(home), "backend", "clean", "-A", "-y"])
    combined = CliRunner().invoke(cli, ["--home", str(home), "backend", "clean", "-A", "--logs", "-y"])
    scoped = CliRunner().invoke(cli, ["--home", str(home), "backend", "clean", "mihomo", "--logs", "-y"])

    assert cleaned.exit_code == 0
    assert "Cleaned downloads, logs, providers, runtimes" in cleaned.output
    assert not (paths.providers / "provider.yaml").exists()
    assert combined.exit_code == 2
    assert "cannot be combined" in combined.output
    assert scoped.exit_code == 2
    assert "backend-scoped cleanup can only target downloads" in scoped.output


def test_clean_confirmation_rejection_preserves_cache(tmp_path, monkeypatch):
    home = tmp_path / "home"
    cached = home / "downloads" / "mihomo" / "1.0.0" / "archive.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cache")

    class Prompt(object):
        def execute(self):
            return False

    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: Prompt())
    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "clean", "mihomo"])

    assert result.exit_code == 0
    assert "Cancelled." in result.output
    assert cached.is_file()


def test_backend_switch_short_command_selects_installed_target(tmp_path, monkeypatch):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=False)

    def manager(context):
        return BackendManager(
            JerryProxyPaths.from_value(context.obj.get("home")),
            probe_runner=lambda installed: None,
        )

    monkeypatch.setattr(cli_module, "_manager", manager)
    monkeypatch.setattr(cli_module, "_select_backend", lambda message, names=None: "mihomo")
    monkeypatch.setattr(cli_module, "_select_installed_version", lambda manager, name: "1.0.0")

    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "switch"])

    assert result.exit_code == 0
    assert "Active: mihomo 1.0.0" in result.output


def test_active_list_reports_empty_backend(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["--home", str(tmp_path), "backend", "list", "--active"])
    machine = runner.invoke(cli, ["--home", str(tmp_path), "backend", "list", "--active", "--json"])

    assert result.exit_code == 0
    assert "No active backend." in result.output
    assert machine.exit_code == 0
    assert json.loads(machine.output) == []


def test_scoped_active_list_ignores_unrelated_corrupt_active_state(tmp_path, monkeypatch):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=True)
    (home / "active" / "xray.json").write_text("{}", encoding="ascii")

    def manager(context):
        return BackendManager(
            JerryProxyPaths.from_value(context.obj.get("home")),
            probe_runner=lambda installed: None,
        )

    monkeypatch.setattr(cli_module, "_manager", manager)
    result = CliRunner().invoke(
        cli,
        ["--home", str(home), "backend", "list", "mihomo", "--active", "--json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.output)[0]["version"] == "1.0.0"


def test_console_main_returns_success_for_real_version_command(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["jerryproxy", "--version"])
    assert main() == 0
    assert "jerryproxy, version 0.1.0a1" in capsys.readouterr().out


def test_console_main_returns_click_usage_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["jerryproxy", "missing-command"])
    assert main() == 2
    captured = capsys.readouterr()
    assert "No such command 'missing-command'" in captured.err


def test_python_module_entrypoint_executes_real_cli(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["python -m jerryproxy", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("jerryproxy.__main__", run_name="__main__")
    assert exit_info.value.code == 0
    assert "jerryproxy, version 0.1.0a1" in capsys.readouterr().out
