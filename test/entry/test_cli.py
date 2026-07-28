import gzip
import hashlib
import sys

from click.testing import CliRunner

from jerryproxy.backend.manager import BackendManager
from jerryproxy.cli import cli, main
from jerryproxy.home import JerryProxyPaths


def install_fake_mihomo(home, tmp_path, version, payload, activate):
    archive = tmp_path / ("mihomo-%s.gz" % version)
    with gzip.open(str(archive), "wb") as stream:
        stream.write(payload)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return BackendManager(JerryProxyPaths(home)).install_from_archive(
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


def test_self_check_reports_each_check_and_summary(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "self-check"])

    assert result.exit_code == 0
    assert "[1/7] Python runtime: OK" in result.output
    assert "[7/7] backend inventory: OK" in result.output
    assert "Summary: 7 OK, 0 FAIL" in result.output
    assert "Self-check PASSED" in result.output


def test_self_check_failure_reaches_console_exit_code(tmp_path, monkeypatch, capsys):
    def failed_check(paths, output):
        output("[1/1] home write access: FAIL - OSError: read-only state directory")
        output("Summary: 0 OK, 1 FAIL")
        output("Self-check FAILED")
        return 1

    monkeypatch.setattr("jerryproxy.cli.run_self_check", failed_check)
    monkeypatch.setattr(
        sys,
        "argv",
        ["jerryproxy", "--home", str(tmp_path), "self-check"],
    )

    assert main() == 1
    captured = capsys.readouterr()
    assert "OSError: read-only state directory" in captured.out
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


def test_backend_inventory_switch_and_remove_commands(tmp_path):
    home = tmp_path / "home"
    install_fake_mihomo(home, tmp_path, "1.0.0", b"one", activate=True)
    install_fake_mihomo(home, tmp_path, "2.0.0", b"two", activate=False)
    runner = CliRunner()

    listed = runner.invoke(cli, ["--home", str(home), "backend", "list", "mihomo"])
    assert listed.exit_code == 0
    assert "*       mihomo   1.0.0" in listed.output
    assert "mihomo   2.0.0" in listed.output

    switched = runner.invoke(cli, ["--home", str(home), "backend", "switch", "mihomo", "2.0.0"])
    assert switched.exit_code == 0
    assert "Active: mihomo 2.0.0" in switched.output

    current = runner.invoke(cli, ["--home", str(home), "backend", "current", "mihomo"])
    assert current.exit_code == 0
    assert "mihomo 2.0.0" in current.output

    doctor = runner.invoke(cli, ["--home", str(home), "doctor"])
    assert doctor.exit_code == 0
    assert "Active backends: 1" in doctor.output
    assert "mihomo 2.0.0" in doctor.output

    removed = runner.invoke(cli, ["--home", str(home), "backend", "remove", "mihomo", "1.0.0"])
    assert removed.exit_code == 0
    assert "Removed: mihomo 1.0.0" in removed.output


def test_current_reports_empty_backend(tmp_path):
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "backend", "current"])
    assert result.exit_code == 0
    assert "No active backend." in result.output
