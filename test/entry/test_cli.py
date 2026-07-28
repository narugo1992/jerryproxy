import gzip
import hashlib
import json
import runpy
import sys

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


def test_supported_backends():
    result = CliRunner().invoke(cli, ["backend", "supported"])
    assert result.exit_code == 0
    assert "mihomo" in result.output
    assert "sing-box" in result.output
    assert "xray" in result.output
    assert "v2ray" in result.output


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


def test_available_versions_and_artifact_commands_use_packaged_catalog_offline():
    runner = CliRunner()
    catalog = BackendCatalog.load()
    platform_info = detect_platform()
    expected_versions = catalog.available_versions("mihomo", platform_info)
    expected_artifact = expected_versions[0].artifact_for(platform_info)
    available = runner.invoke(cli, ["backend", "available", "--json"])

    assert available.exit_code == 0
    overview = {record["backend"]: record for record in json.loads(available.output)}
    assert sorted(overview) == ["mihomo", "sing-box", "v2ray", "xray"]
    assert overview["mihomo"]["latest"] == expected_versions[0].version
    assert overview["mihomo"]["platform"] == platform_info.asset_key

    human_available = runner.invoke(cli, ["backend", "available"])
    assert human_available.exit_code == 0
    assert "BACKEND" in human_available.output
    assert "AVAILABLE" in human_available.output
    assert "HOST" in human_available.output
    assert platform_info.asset_key in human_available.output

    versions = runner.invoke(cli, ["backend", "versions", "mihomo", "--limit", "2", "--json"])
    assert versions.exit_code == 0
    records = json.loads(versions.output)
    assert [record["version"] for record in records] == [item.version for item in expected_versions[:2]]
    assert all(record["backend"] == "mihomo" for record in records)
    assert all(record["platform"] == expected_artifact.platform for record in records)
    assert all(len(record["sha256"]) == 64 for record in records)

    human_versions = runner.invoke(cli, ["backend", "versions", "mihomo", "--limit", "1"])
    assert human_versions.exit_code == 0
    assert "VERSION" in human_versions.output
    assert "TARGET" in human_versions.output
    assert expected_artifact.name in human_versions.output

    all_platforms = runner.invoke(cli, ["backend", "versions", "mihomo", "--all-platforms", "--limit", "2"])
    assert all_platforms.exit_code == 0
    assert "PLATFORMS" in all_platforms.output
    assert "PUBLISHED" in all_platforms.output
    assert expected_versions[0].version in all_platforms.output

    artifact = runner.invoke(cli, ["backend", "artifact", "mihomo"])
    assert artifact.exit_code == 0
    assert "Version: %s" % expected_artifact.version in artifact.output
    assert "Catalog target: %s" % expected_artifact.platform in artifact.output
    assert "SHA-256:" in artifact.output
    assert expected_artifact.url in artifact.output


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

    current = runner.invoke(cli, ["--home", str(home), "backend", "current", "mihomo"])
    assert current.exit_code == 0
    assert "mihomo" in current.output
    assert "2.0.0" in current.output

    doctor = runner.invoke(cli, ["--home", str(home), "doctor"])
    assert doctor.exit_code == 0
    assert "Active backends: 1" in doctor.output
    assert "mihomo" in doctor.output
    assert "2.0.0" in doctor.output

    verified = runner.invoke(cli, ["--home", str(home), "backend", "verify", "mihomo"])
    assert verified.exit_code == 0
    assert "EXECUTABLE SHA256" in verified.output
    assert "mihomo" in verified.output

    removed = runner.invoke(cli, ["--home", str(home), "backend", "remove", "mihomo", "1.0.0"])
    assert removed.exit_code == 0
    assert "Removed: mihomo 1.0.0" in removed.output


def test_current_reports_empty_backend(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "current"])
    assert result.exit_code == 0
    assert "No active backend." in result.output


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
