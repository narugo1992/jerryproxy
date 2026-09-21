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
