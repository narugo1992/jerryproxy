import gzip
import hashlib
import json
import runpy
import sys
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import jerryproxy.cli as cli_module
import jerryproxy.selfcheck as selfcheck_module
from jerryproxy.backend.catalog import BackendCatalog
from jerryproxy.backend.manager import BackendManager
from jerryproxy.backend.platform import detect_platform
from jerryproxy.cli import cli, main
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import filelock_status
from test.selfcheck.fakes import verified_relay_session_factory


@pytest.fixture(autouse=True)
def _isolate_self_check_relay_network(monkeypatch):
    relay_factory = verified_relay_session_factory(monkeypatch)
    monkeypatch.setattr(selfcheck_module.requests, "Session", relay_factory)
    return relay_factory


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
    assert "File lock:" in result.output
    assert "Backend catalog:" in result.output
    assert "Catalog compatibility: 4/4 backends" in result.output


def test_self_check_reports_each_check_and_summary(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "self-check"])

    assert result.exit_code == 0
    assert "[1/12] Python runtime: OK" in result.output
    assert "[7/12] packaged backend catalog: OK" in result.output
    assert "[8/12] filelock compatibility:" in result.output
    assert "[9/12] backend inventory: OK" in result.output
    assert "[12/12] relay gh.geekertao.top: OK" in result.output
    assert "0 FAIL, 0 ERR" in result.output
    assert "Self-check PASSED" in result.output


def test_self_check_help_discloses_bounded_network_behavior():
    result = CliRunner().invoke(cli, ["self-check", "--help"])
    normalized = " ".join(result.output.split())

    assert result.exit_code == 0
    assert "fixed 1 MiB Range" in normalized
    assert "5-second network timeout" in normalized
    assert "Response-header latency" in normalized
    assert "latency to the first chunk" in normalized
    assert "WARN" in normalized


def test_self_check_can_force_ansi_color(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["--home", str(tmp_path), "self-check", "--color"],
        color=True,
    )

    assert result.exit_code == 0
    assert "\033[1;32mOK\033[0m" in result.output
    if filelock_status().level == "WARN":
        assert "\033[1;33mSelf-check PASSED with warnings\033[0m" in result.output
    else:
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
    selections = iter(["mihomo", "", "direct"])
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

        def install(self, name, version, activate, relay, relay_url, relay_pattern):
            artifact = manager.resolve_artifact(name, version)
            captured.update(
                name=name,
                version=version,
                activate=activate,
                relay=relay,
                relay_url=relay_url,
                relay_pattern=relay_pattern,
            )
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
    assert prompts == [
        "Select a backend to install:",
        "Select a stable version:",
        "Select download transport:",
    ]
    assert captured == {
        "name": "mihomo",
        "version": None,
        "activate": False,
        "relay": "direct",
        "relay_url": None,
        "relay_pattern": None,
    }
    assert "Installed: mihomo" in result.output


def test_guided_install_collects_a_custom_relay_and_pattern(tmp_path, monkeypatch):
    selections = iter(["__custom__", "query_q"])
    captured = {}
    asset = SimpleNamespace(
        backend="mihomo",
        version="1.0.0",
        name="mihomo.gz",
        sha256="0" * 64,
    )

    class Prompt(object):
        def __init__(self, value):
            self.value = value

        def execute(self):
            return self.value

    class GuidedManager(object):
        platform_info = detect_platform()

        def resolve_artifact(self, name, version):
            return asset

        def install(self, name, version, activate, relay, relay_url, relay_pattern):
            captured.update(
                relay=relay,
                relay_url=relay_url,
                relay_pattern=relay_pattern,
            )
            return SimpleNamespace(name=name, version=asset.version, executable=tmp_path / "mihomo")

    monkeypatch.setattr(cli_module, "_manager", lambda context: GuidedManager())
    monkeypatch.setattr(cli_module, "_select_backend", lambda message: "mihomo")
    monkeypatch.setattr(cli_module, "_select_catalog_version", lambda selected_manager, name: None)
    monkeypatch.setattr(cli_module.inquirer, "select", lambda **kwargs: Prompt(next(selections)))
    monkeypatch.setattr(cli_module.inquirer, "text", lambda **kwargs: Prompt("https://relay.example/prefix"))
    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: Prompt(False))

    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "install"])

    assert result.exit_code == 0
    assert captured == {
        "relay": None,
        "relay_url": "https://relay.example/prefix",
        "relay_pattern": "query_q",
    }
    assert "Transport: custom relay (query_q)" in result.output


def test_guided_install_reports_when_no_compatible_stable_version_exists(tmp_path, monkeypatch):
    class EmptyManager(object):
        def available(self, name):
            return ()

    monkeypatch.setattr(cli_module, "_manager", lambda context: EmptyManager())
    monkeypatch.setattr(cli_module, "_select_backend", lambda message: "mihomo")

    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "install"])

    assert result.exit_code == 1
    assert "no compatible stable version is available for mihomo" in result.output


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


def test_interactive_prompts_translate_interrupts_and_missing_input(tmp_path, monkeypatch):
    class InterruptedPrompt(object):
        def execute(self):
            raise KeyboardInterrupt()

    monkeypatch.setattr(cli_module.inquirer, "select", lambda **kwargs: InterruptedPrompt())
    selected = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend"])
    assert selected.exit_code == 1
    assert "interactive selection cancelled" in selected.output

    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=False)
    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: InterruptedPrompt())
    removed = CliRunner().invoke(
        cli,
        ["--home", str(home), "backend", "remove", "mihomo", "1.0.0"],
    )
    assert removed.exit_code == 0
    assert "Cancelled." in removed.output


@pytest.mark.parametrize("error", [EOFError(), KeyboardInterrupt()])
def test_guided_install_translates_confirmation_failures(tmp_path, monkeypatch, error):
    manager = BackendManager(JerryProxyPaths(tmp_path / "home"), probe_runner=lambda installed: None)

    class Prompt(object):
        def execute(self):
            raise error

    monkeypatch.setattr(cli_module, "_manager", lambda context: manager)
    monkeypatch.setattr(cli_module, "_select_backend", lambda message: "mihomo")
    monkeypatch.setattr(cli_module, "_select_catalog_version", lambda selected_manager, name: None)
    monkeypatch.setattr(cli_module.inquirer, "confirm", lambda **kwargs: Prompt())
    result = CliRunner().invoke(
        cli,
        ["--home", str(tmp_path), "backend", "install", "--relay", "direct"],
    )

    assert result.exit_code == 1
    assert "interactive selection" in result.output


def test_backend_group_rejects_an_unavailable_interactive_action(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_module, "_select", lambda message, choices: "unknown")

    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend"])

    assert result.exit_code == 1
    assert "interactive backend operation is unavailable" in result.output


def test_available_rejects_global_all_platforms_and_reports_empty_versions(tmp_path, monkeypatch):
    invalid = CliRunner().invoke(cli, ["backend", "available", "--all-platforms"])
    assert invalid.exit_code == 2
    assert "requires a backend NAME" in invalid.output

    class EmptyManager(object):
        platform_info = detect_platform()
        catalog = SimpleNamespace(generated_at="2026-01-01T00:00:00Z")

        def available(self, name):
            return ()

    monkeypatch.setattr(cli_module, "_manager", lambda context: EmptyManager())
    empty = CliRunner().invoke(cli, ["backend", "available", "mihomo"])
    assert empty.exit_code == 0
    assert "No verified stable versions available." in empty.output


def test_explicit_install_prints_the_active_link(tmp_path, monkeypatch):
    executable = tmp_path / "mihomo"
    link = tmp_path / "bin" / "mihomo"
    asset = SimpleNamespace(
        backend="mihomo",
        version="1.0.0",
        name="mihomo.gz",
        sha256="0" * 64,
    )

    captured = {}

    class InstallManager(object):
        platform_info = detect_platform()

        def resolve_artifact(self, name, version):
            return asset

        def install(self, name, version, activate, relay, relay_url, relay_pattern):
            captured.update(
                relay=relay,
                relay_url=relay_url,
                relay_pattern=relay_pattern,
            )
            return SimpleNamespace(name=name, version="1.0.0", executable=executable)

        def current(self, name):
            return SimpleNamespace(link=link, link_mode="symlink")

    monkeypatch.setattr(cli_module, "_manager", lambda context: InstallManager())
    result = CliRunner().invoke(
        cli,
        [
            "backend",
            "install",
            "mihomo",
            "1.0.0",
            "--relay-url",
            "https://relay.example",
            "--relay-pattern",
            "host_path",
        ],
    )

    assert result.exit_code == 0
    assert captured == {
        "relay": None,
        "relay_url": "https://relay.example",
        "relay_pattern": "host_path",
    }
    assert "Transport: custom relay (host_path)" in result.output
    assert "Active link: %s (symlink)" % link in result.output


def test_explicit_install_defaults_to_auto_relay(tmp_path, monkeypatch):
    captured = {}
    asset = SimpleNamespace(
        backend="mihomo",
        version="1.0.0",
        name="mihomo.gz",
        sha256="0" * 64,
    )

    class InstallManager(object):
        platform_info = detect_platform()

        def resolve_artifact(self, name, version):
            return asset

        def install(self, name, version, activate, relay, relay_url, relay_pattern):
            captured.update(
                relay=relay,
                relay_url=relay_url,
                relay_pattern=relay_pattern,
            )
            return SimpleNamespace(name=name, version=asset.version, executable=tmp_path / "mihomo")

        def current(self, name):
            return SimpleNamespace(link=tmp_path / "bin" / name, link_mode="symlink")

    monkeypatch.setattr(cli_module, "_manager", lambda context: InstallManager())

    result = CliRunner().invoke(cli, ["backend", "install", "mihomo"])

    assert result.exit_code == 0
    assert captured == {
        "relay": "auto",
        "relay_url": None,
        "relay_pattern": None,
    }
    assert "Transport: auto" in result.output


@pytest.mark.parametrize(
    "arguments",
    [
        ["--relay", "auto", "--relay-url", "https://relay.example"],
        ["--relay-pattern", "host_path"],
    ],
)
def test_install_relay_option_conflicts_are_usage_errors(arguments):
    result = CliRunner().invoke(cli, ["backend", "install", "mihomo"] + arguments)

    assert result.exit_code == 2


def test_install_rejects_a_malformed_relay_url_without_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "jerryproxy",
            "--home",
            str(tmp_path),
            "backend",
            "install",
            "mihomo",
            "--relay-url",
            "https://[",
        ],
    )

    assert cli_module.main() == 1
    captured = capsys.readouterr()
    assert "relay URL is invalid" in captured.err
    assert "Traceback" not in captured.err


def test_backend_install_help_explains_relay_modes_and_patterns():
    result = CliRunner().invoke(cli, ["backend", "install", "--help"], terminal_width=72)

    assert result.exit_code == 0
    assert "--relay MODE" in result.output
    assert "--relay-url HTTPS_BASE_URL" in result.output
    assert "--relay-pattern PATTERN" in result.output
    assert "Relay MODE values for --relay MODE:" in result.output
    assert "relay contact is acceptable. There is no fallback." in result.output
    assert "Try exactly this order: direct GitHub, gh-proxy.com," in result.output
    assert "This is the default; a custom --relay-url" in result.output
    assert "is never included." in result.output
    assert "Request only https://gh-proxy.com/URL." in result.output
    assert "Request only https://cdn.akaere.online/URL." in result.output
    assert "Request only https://gh.geekertao.top/URL." in result.output
    assert "Custom relay options:" in result.output
    assert "full_url_path" in result.output
    assert "BASE/https://github.com/OWNER/REPO/releases/download/TAG/ASSET" in result.output
    assert "host_path" in result.output
    assert "BASE/github.com/OWNER/REPO/releases/download/TAG/ASSET" in result.output
    assert "query_q" in result.output
    assert "BASE/?q=<percent-encoded-official-URL>" in result.output
    assert "Fallback and verification:" in result.output
    assert "Privacy boundary:" in result.output
    assert "never sends GitHub credentials, private assets," in result.output
    assert "subscription URLs, provider data" in result.output
    assert "GitHub release API requests" in result.output
    assert "through a relay." in result.output
    assert "--relay-pattern requires --relay-url." in result.output
    assert "jerryproxy backend install mihomo --relay auto" in result.output
    assert "[default: auto]" in result.output


@pytest.mark.parametrize("terminal_width", [72, 80, 100, 120])
def test_backend_install_help_preserves_relay_layout(terminal_width):
    result = CliRunner().invoke(
        cli,
        ["backend", "install", "--help"],
        terminal_width=terminal_width,
    )

    assert result.exit_code == 0
    assert max(len(line) for line in result.output.splitlines()) <= terminal_width
    assert "    auto\n      Try exactly this order:" in result.output
    assert "    gh-proxy.com\n      Request only https://gh-proxy.com/URL." in result.output
    assert "      full_url_path\n        BASE/https://github.com/" in result.output
    assert "      host_path\n        BASE/github.com/" in result.output
    assert "      query_q\n        BASE/?q=<percent-encoded-official-URL>" in result.output
    assert "auto     Try" not in result.output


def test_backend_help_identifies_relay_install_entry_point():
    result = CliRunner().invoke(cli, ["backend", "--help"], terminal_width=72)

    assert result.exit_code == 0
    assert "install    Install via direct GitHub or a release relay." in result.output


def test_verify_empty_and_remove_invalid_option_combinations(tmp_path):
    empty = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "verify"])
    combined = CliRunner().invoke(
        cli,
        ["--home", str(tmp_path), "backend", "remove", "mihomo", "1.0.0", "-A", "-y"],
    )
    forced_all = CliRunner().invoke(
        cli,
        ["--home", str(tmp_path), "backend", "remove", "mihomo", "-A", "--force", "-y"],
    )

    assert empty.exit_code == 0
    assert "No backend versions installed." in empty.output
    assert combined.exit_code == 2
    assert "VERSION or -A/--all" in combined.output
    assert forced_all.exit_code == 2
    assert "--force only applies" in forced_all.output


@pytest.mark.parametrize("selected", ["__all__", "1.0.0"])
def test_guided_remove_handles_all_and_exact_selections(tmp_path, monkeypatch, selected):
    home = tmp_path / selected.replace("_", "all")
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=True)
    monkeypatch.setattr(cli_module, "_select_backend", lambda message, names=None: "mihomo")
    monkeypatch.setattr(
        cli_module,
        "_select_installed_version",
        lambda manager, name, allow_all=False: selected,
    )
    monkeypatch.setattr(cli_module, "_prompt_confirm", lambda message, default=False: False)
    monkeypatch.setattr(cli_module, "_confirm_dangerous_operation", lambda message, assume_yes: True)

    result = CliRunner().invoke(cli, ["--home", str(home), "backend", "remove"])

    assert result.exit_code == 0
    assert "Removed 1 installed version(s): 1.0.0" in result.output


@pytest.mark.parametrize("scope", ["all", "logs"])
def test_guided_clean_handles_all_and_single_area_scopes(tmp_path, monkeypatch, scope):
    monkeypatch.setattr(cli_module, "_select", lambda message, choices: scope)
    monkeypatch.setattr(cli_module, "_confirm_dangerous_operation", lambda message, assume_yes: False)

    result = CliRunner().invoke(cli, ["--home", str(tmp_path / scope), "backend", "clean"])

    assert result.exit_code == 0
    assert "Cancelled." in result.output
