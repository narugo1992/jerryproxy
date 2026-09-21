"""Runtime diagnostics must reject broken projections and policy contracts."""

from types import SimpleNamespace

import pytest

from jerryproxy.selfcheck import runtime as runtime_module


@pytest.mark.parametrize("payload", [b"allow-lan: false\n", b"MATCH,jerryproxy\n", b"\xff"])
def test_projection_diagnostic_rejects_missing_boundary_or_invalid_encoding(monkeypatch, payload):
    monkeypatch.setattr(runtime_module, "build_provider_config", lambda *a: payload)
    result = runtime_module._check_runtime_projection()
    assert result.level in ("FAIL", "ERR")


@pytest.mark.parametrize("broken", ["targets", "policy"])
def test_projection_diagnostic_requires_complete_recovery_contract(monkeypatch, broken):
    if broken == "targets":
        monkeypatch.setattr(runtime_module, "DEFAULT_HEALTH_TARGETS", ())
    else:
        monkeypatch.setattr(runtime_module, "RecoveryPolicy", lambda: SimpleNamespace(retry_policy="none"))
    result = runtime_module._check_runtime_projection()
    assert result.level == "FAIL"
    assert "policy is incomplete" in result.detail


@pytest.mark.parametrize("counter,method", [("projections", "projection"), ("created", "create_process"),
                                           ("stopped", "stop"), ("inspections", "loaded_nodes")])
def test_driver_contract_diagnostic_detects_missing_lifecycle_evidence(monkeypatch, counter, method):
    original = getattr(runtime_module._ProbeDriver, method)

    def missing(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        setattr(self, counter, 0)
        return result

    monkeypatch.setattr(runtime_module._ProbeDriver, method, missing)
    result = runtime_module._check_runtime_driver_contract()
    assert result.level == "FAIL"


def test_driver_contract_diagnostic_detects_remaining_private_state(monkeypatch):
    monkeypatch.setattr(runtime_module, "_secret_bearing_artifacts", lambda paths: ("retained-provider",))
    result = runtime_module._check_runtime_driver_contract()
    assert result.level == "FAIL"
    assert "retained-provider" in result.detail


def test_driver_contract_diagnostic_detects_missing_bypass_refusal(monkeypatch):
    original = runtime_module._ProbeDriver.loaded_nodes

    def hide_bypass(self, *args, **kwargs):
        self.bypassing = False
        return original(self, *args, **kwargs)

    monkeypatch.setattr(runtime_module._ProbeDriver, "loaded_nodes", hide_bypass)
    result = runtime_module._check_runtime_driver_contract()
    assert result.level == "FAIL"
    assert "routes traffic directly" in result.detail


def test_driver_contract_diagnostic_detects_missing_home_exclusion(monkeypatch):
    from contextlib import nullcontext

    monkeypatch.setattr(runtime_module, "JerryProxyOperationLock", lambda paths: nullcontext())
    result = runtime_module._check_runtime_driver_contract()
    assert result.level == "FAIL"
    assert "did not hold the home-wide lock" in result.detail


def test_substitute_driver_reload_requires_no_network_or_credentials():
    driver = runtime_module._ProbeDriver("mihomo")
    before = dict(vars(driver))
    assert driver.reload_provider(1, "unused-private-secret", 0.1) is None
    assert vars(driver) == before


def test_health_process_diagnostic_uses_real_spawn_and_reaps_worker():
    import multiprocessing

    before = {child.pid for child in multiprocessing.active_children()}
    result = runtime_module._check_health_process()
    assert result.level == "OK"
    assert {child.pid for child in multiprocessing.active_children()} == before


@pytest.mark.parametrize("outcome", ["unexpected_success", "wrong_failure", "spawn_error", "cleanup_error"])
def test_health_process_diagnostic_rejects_incomplete_verification(monkeypatch, outcome):
    from jerryproxy.errors import RuntimeSessionError
    from jerryproxy.runtime.health import HealthSnapshot, TargetHealth

    closed = []

    class Probe:
        def check(self, *args):
            if outcome == "spawn_error":
                raise RuntimeSessionError("health worker could not start")
            ok = outcome == "unexpected_success"
            detail = "" if ok else "probe_deadline" if outcome == "wrong_failure" else "transport_failed"
            return HealthSnapshot((TargetHealth("local-refusal", ok, detail=detail),), int(ok), 1, 0)

        def close(self):
            closed.append(True)
            if outcome == "cleanup_error":
                raise RuntimeSessionError("health cleanup remains unconfirmed")

    monkeypatch.setattr(runtime_module, "ConnectivityProbe", lambda **kwargs: Probe())
    result = runtime_module._check_health_process()
    assert result.level == ("ERR" if outcome.endswith("error") else "FAIL")
    assert closed == [True]
