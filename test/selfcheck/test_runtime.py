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
