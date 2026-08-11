import os

import pytest

from jerryproxy.errors import UnsupportedPlatformError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.lock import filelock_status
from jerryproxy.selfcheck import CheckResult, build_checks, run_checks, run_self_check
from jerryproxy.selfcheck import relay as relay_module
from jerryproxy.selfcheck import runner as selfcheck_module
from test.selfcheck.fakes import (
    RelaySessionFactory,
    patch_across_selfcheck,
    verified_relay_session_factory,
)


def test_self_check_validates_an_empty_private_home(tmp_path, monkeypatch):
    lines = []
    relay_factory = verified_relay_session_factory(monkeypatch)

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    status = filelock_status()
    permission_skip = int(os.name != "posix")
    lock_warning = int(status.level == "WARN")
    # These totals are written out rather than derived from build_checks(), so
    # that adding or removing a check has to be acknowledged here. A derived
    # count would agree with any number of checks, including zero.
    expected = "Summary: %d OK, %d WARN, %d SKIP, 0 FAIL, 0 ERR" % (
        28 - permission_skip - lock_warning,
        lock_warning,
        permission_skip,
    )
    assert expected in lines
    assert lines[-1] in (
        "Self-check PASSED",
        "Self-check PASSED with skips",
        "Self-check PASSED with warnings",
    )
    assert lines[1].startswith("Runtime: Python ")
    assert "; JerryProxy " in lines[1]
    assert lines[2].startswith("System: ")
    assert not list(tmp_path.glob(".self-check-*"))
    for name in ("active", "backends", "bin", "downloads", "locks", "logs", "providers", "runtimes"):
        assert (tmp_path / name).is_dir()


def test_check_runner_renders_all_five_levels_and_only_fails_on_fail_or_error():
    visited = []
    lines = []

    def first():
        visited.append("first")
        return CheckResult.ok("ready")

    def warning():
        visited.append("warning")
        return CheckResult.warn("legacy dependency")

    def skipped():
        visited.append("skipped")
        return CheckResult.skip("not applicable")

    def failure():
        visited.append("failure")
        return CheckResult.fail("requirement unmet")

    def error():
        visited.append("error")
        return CheckResult.err("OSError: read-only state directory")

    exit_code = run_checks(
        (
            ("first", first),
            ("compatibility", warning),
            ("platform-only", skipped),
            ("policy", failure),
            ("writable state", error),
        ),
        output=lines.append,
    )

    assert exit_code == 1
    assert visited == ["first", "warning", "skipped", "failure", "error"]
    assert "[2/5] compatibility: WARN - legacy dependency" in lines
    assert "[3/5] platform-only: SKIP - not applicable" in lines
    assert "[4/5] policy: FAIL - requirement unmet" in lines
    assert "[5/5] writable state: ERR - OSError: read-only state directory" in lines
    assert "Summary: 1 OK, 1 WARN, 1 SKIP, 1 FAIL, 1 ERR" in lines
    assert lines[-1] == "Self-check FAILED"


def test_check_runner_warning_keeps_zero_exit_code():
    lines = []

    exit_code = run_checks((("compatibility", lambda: CheckResult.warn("upgrade recommended")),), lines.append)

    assert exit_code == 0
    assert "Summary: 0 OK, 1 WARN, 0 SKIP, 0 FAIL, 0 ERR" in lines
    assert lines[-1] == "Self-check PASSED with warnings"


def test_check_runner_skip_is_cyan_and_keeps_zero_exit_code():
    lines = []

    exit_code = run_checks(
        (("platform-only", lambda: CheckResult.skip("not applicable")),),
        lines.append,
        color=True,
    )

    assert exit_code == 0
    assert "\033[1;36mSKIP\033[0m" in lines[0]
    assert "\033[1;36m0 SKIP\033[0m" not in lines[-2]
    assert "\033[1;36m1 SKIP\033[0m" in lines[-2]
    assert lines[-1] == "\033[1;36mSelf-check PASSED with skips\033[0m"


def test_check_runner_renders_multiline_error_diagnostics():
    lines = []

    exit_code = run_checks(
        (("crash", lambda: CheckResult.err("RuntimeError: broken", ("Traceback line\nfinal frame",))),),
        lines.append,
    )

    assert exit_code == 1
    assert lines[0] == "[1/1] crash: ERR - RuntimeError: broken"
    assert lines[1:3] == ["    Traceback line", "    final frame"]


def test_check_runner_redacts_sensitive_error_details_and_diagnostics():
    lines = []
    secrets = (
        "https://alice:secret@example.com/provider?token=query-secret#fragment-secret",
        "vless://123e4567-e89b-f2d3-c456-426614174000@example.com:443?security=tls#private-node",
        "123e4567-e89b-f2d3-c456-426614174000",
        "password=hunter2",
        "public_key=QUJDREVGR0g=",
        "short_id=deadbeef",
        "public key: QUJDREVGR0g=",
        "private key: cHJpdmF0ZQ==",
        "API key: secret-value",
        "short id: deadbeef",
        "Authorization: Bearer ghp_SUPERSECRET",
    )
    exposed = " ".join(secrets)

    exit_code = run_checks(
        (("crash", lambda: CheckResult.err(exposed, ("Traceback: %s" % exposed,))),),
        lines.append,
    )

    rendered = "\n".join(lines)
    assert exit_code == 1
    assert "[REDACTED" in rendered
    assert all(secret not in rendered for secret in secrets)
    assert "query-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "hunter2" not in rendered
    assert "QUJDREVGR0g=" not in rendered
    assert "cHJpdmF0ZQ==" not in rendered
    assert "secret-value" not in rendered
    assert "deadbeef" not in rendered
    assert "ghp_SUPERSECRET" not in rendered


def test_check_runner_uses_ansi_status_colors_when_enabled():
    lines = []

    exit_code = run_checks(
        (("ready", lambda: CheckResult.ok("available")),),
        output=lines.append,
        color=True,
    )

    assert exit_code == 0
    assert "\033[1;36m[1/1] ready\033[0m" in lines[0]
    assert "\033[1;32mOK\033[0m" in lines[0]
    assert lines[-1] == "\033[1;32mSelf-check PASSED\033[0m"


def test_check_runner_colors_warning_failure_and_error_levels():
    lines = []

    exit_code = run_checks(
        (
            ("warning", lambda: CheckResult.warn("legacy")),
            ("failure", lambda: CheckResult.fail("unmet")),
            ("error", lambda: CheckResult.err("unavailable")),
        ),
        output=lines.append,
        color=True,
    )

    assert exit_code == 1
    assert "\033[1;33mWARN\033[0m" in lines[0]
    assert "\033[1;31mFAIL\033[0m" in lines[1]
    assert "\033[1;31mERR\033[0m" in lines[2]


def test_self_check_reports_corrupt_active_inventory_without_stopping_other_checks(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    (paths.active / "mihomo.json").write_text("{not-json", encoding="ascii")
    lines = []

    exit_code = run_self_check(
        paths,
        output=lines.append,
        relay_session_factory=verified_relay_session_factory(monkeypatch),
    )

    assert exit_code == 1
    assert any("backend inventory: FAIL" in line for line in lines)
    assert any("IntegrityError" in line for line in lines)
    assert lines[-1] == "Self-check FAILED"


@pytest.mark.parametrize(
    "check_name",
    (
        "isolated backend lifecycle",
        "runtime driver contract",
        "recovery activation rollback",
        "recovery removal rollback",
    ),
)
def test_isolated_business_checks_report_platform_setup_errors(tmp_path, monkeypatch, check_name):
    def fail_platform():
        raise OSError("temporary platform probe failure")

    patch_across_selfcheck(monkeypatch, "_recovery_platform", fail_platform)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))[check_name]()

    assert result.level == "ERR"
    assert result.detail == "OSError: temporary platform probe failure"
    assert result.diagnostics and "temporary platform probe failure" in result.diagnostics[0]


def test_platform_dependents_skip_after_an_unsupported_platform(tmp_path, monkeypatch):
    def unsupported_platform():
        raise UnsupportedPlatformError("unsupported host")

    patch_across_selfcheck(monkeypatch, "detect_platform", unsupported_platform)
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))

    assert checks["platform detection"]().level == "SKIP"
    dependent_names = (
        "backend registry",
        "catalog platform selection",
        "backend inventory",
        "isolated backend lifecycle",
        "recovery install rollback",
        "recovery activation rollback",
        "recovery activation rollforward",
        "recovery removal rollback",
        "recovery removal rollforward",
        "runtime driver contract",
    )
    results = [checks[name]() for name in dependent_names]

    assert [result.level for result in results] == ["SKIP"] * len(dependent_names)
    assert all("platform prerequisite is unsupported" in result.detail for result in results)


def test_build_checks_keeps_injected_relay_sessions_inline(tmp_path, monkeypatch):
    relay_factory = verified_relay_session_factory(monkeypatch)

    def reject_process_probe(profile):
        raise AssertionError("injected session unexpectedly crossed the process boundary")

    monkeypatch.setattr(selfcheck_module, "_check_relay_in_process", reject_process_probe)
    relay_check = dict(build_checks(JerryProxyPaths(tmp_path), relay_factory))["relay gh-proxy.com"]

    assert relay_check().level == "OK"


def test_relay_warnings_keep_the_full_self_check_exit_code_zero(tmp_path):
    lines = []
    relay_factory = RelaySessionFactory(lambda: relay_module.requests.exceptions.Timeout("secret request target"))

    exit_code = run_self_check(
        JerryProxyPaths(tmp_path),
        output=lines.append,
        relay_session_factory=relay_factory,
    )

    assert exit_code == 0
    status = filelock_status()
    permission_skip = int(os.name != "posix")
    lock_warning = int(status.level == "WARN")
    # These totals are written out rather than derived from build_checks(), so
    # that adding or removing a check has to be acknowledged here. A derived
    # count would agree with any number of checks, including zero.
    expected = "Summary: %d OK, %d WARN, %d SKIP, 0 FAIL, 0 ERR" % (
        25 - permission_skip - lock_warning,
        3 + lock_warning,
        permission_skip,
    )
    assert expected in lines
    assert lines[-1] == "Self-check PASSED with warnings"
    assert all("secret" not in line for line in lines)
