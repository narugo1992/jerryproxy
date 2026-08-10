from types import SimpleNamespace

import pytest

from jerryproxy.backend.model import PlatformInfo
from jerryproxy.errors import IntegrityError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import CheckResult, build_checks
from jerryproxy.selfcheck import recovery as selfcheck_module
from test.selfcheck.fakes import patch_across_selfcheck


def test_recovery_checks_use_isolated_homes_and_exercise_real_hard_exit_recovery(tmp_path):
    paths = JerryProxyPaths(tmp_path / "user-home")
    checks = dict(build_checks(paths))

    results = [
        checks[name]()
        for name in (
            "recovery install rollback",
            "recovery activation rollback",
            "recovery activation rollforward",
            "recovery removal rollback",
            "recovery removal rollforward",
        )
    ]

    assert [result.level for result in results] == ["OK"] * 5
    assert not paths.root.exists()


def test_recovery_checks_skip_without_a_compatible_backend_platform(tmp_path, monkeypatch):
    patch_across_selfcheck(
        monkeypatch,
        "detect_platform",
        lambda: PlatformInfo("unsupported", "architecture"),
    )

    checks = dict(build_checks(JerryProxyPaths(tmp_path)))
    results = [
        checks[name]()
        for name in (
            "isolated backend lifecycle",
            "recovery install rollback",
            "recovery activation rollback",
            "recovery activation rollforward",
            "recovery removal rollback",
            "recovery removal rollforward",
            "runtime driver contract",
        )
    ]

    assert [result.level for result in results] == ["SKIP"] * 7
    assert all("no " in result.detail and "fixture asset shape" in result.detail for result in results)


def test_install_recovery_check_fails_when_recovery_evidence_is_retained(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_recovery_artifacts", lambda paths: (paths.runtimes / "retained",))

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result == CheckResult.fail("hard-exit install rollback retained recovery evidence")


@pytest.mark.parametrize(
    "installed, active",
    (
        ((object(),), ()),
        ((), (object(),)),
    ),
)
def test_install_recovery_check_fails_when_public_backend_state_is_retained(
    tmp_path,
    monkeypatch,
    installed,
    active,
):
    manager = SimpleNamespace(inventory=lambda: SimpleNamespace(installed=installed, active=active))
    monkeypatch.setattr(
        selfcheck_module,
        "_recovery_platform",
        lambda: (PlatformInfo("linux", "amd64"), None, "linux-amd64"),
    )
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_probe_manager", lambda paths, platform_info: manager)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result == CheckResult.fail("hard-exit install rollback retained public backend state")


def test_activation_recovery_check_fails_when_recovery_evidence_is_retained(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_recovery_artifacts", lambda paths: (paths.runtimes / "retained",))

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery activation rollback"]()

    assert result == CheckResult.fail("activation rollback recovery did not converge cleanly")


def test_recovery_check_maps_integrity_failures_to_fail(tmp_path, monkeypatch):
    def fail_platform():
        raise IntegrityError("simulated retained recovery evidence")

    monkeypatch.setattr(selfcheck_module, "_recovery_platform", fail_platform)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result == CheckResult.fail("IntegrityError: simulated retained recovery evidence")


def test_recovery_check_maps_operational_failures_to_error_with_traceback(tmp_path, monkeypatch):
    def fail_platform():
        raise OSError("simulated temporary storage failure")

    monkeypatch.setattr(selfcheck_module, "_recovery_platform", fail_platform)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery install rollback"]()

    assert result.level == "ERR"
    assert result.detail == "OSError: simulated temporary storage failure"
    assert result.diagnostics and "simulated temporary storage failure" in result.diagnostics[0]


def test_recovery_checks_propagate_spawn_prerequisite_skips(tmp_path, monkeypatch):
    skipped = CheckResult.skip("spawn unavailable")
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: skipped)
    checks = dict(build_checks(JerryProxyPaths(tmp_path)))

    results = [
        checks["recovery install rollback"](),
        checks["recovery activation rollback"](),
        checks["recovery removal rollback"](),
    ]

    assert results == [skipped, skipped, skipped]


def test_activation_rollforward_check_detects_wrong_recovered_version(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery activation rollforward"]()

    assert result == CheckResult.fail("activation rollforward recovery selected the wrong version")


def test_removal_rollforward_check_detects_undisposed_public_state(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery removal rollforward"]()

    assert result == CheckResult.fail("committed removal recovery did not dispose public state")


def test_removal_recovery_check_detects_retained_transaction_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(selfcheck_module, "_run_recovery_child", lambda *args, **kwargs: None)
    monkeypatch.setattr(selfcheck_module, "_recovery_artifacts", lambda paths: (paths.runtimes / "retained",))

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["recovery removal rollback"]()

    assert result == CheckResult.fail("removal rollback recovery retained transaction evidence")
