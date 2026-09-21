"""Fixture composition checks independent of Docker and production secrets."""

import json

import pytest

from jerryproxy.subscription.audit import PROVIDER_TYPES
from tools.e2e import provision


def test_provider_fixtures_are_complete_and_emitted(tmp_path, monkeypatch):
    parts = {name: "fixture-" + name for name in provision.COMPOSITION_INPUTS}
    for name, value in parts.items():
        monkeypatch.setenv(name.upper(), value)
    providers = provision.compose_providers(parts)
    assert set(providers) == set(PROVIDER_TYPES)
    for scheme, node in providers.items():
        assert node["type"] == scheme
        assert node["name"] == "e2e-" + scheme
        assert node["server"] == provision.PROXY_HOST
    output = tmp_path / "environment"
    assert provision._emit_nodes(str(output)) == 0
    emitted = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(emitted[provision.PROVIDER_VARIABLE]) == providers
    assert providers["vless"]["reality-opts"]["public-key"] == parts["reality_public_key"]
    assert providers["tuic"]["uuid"] == parts["tuic_uuid"]
    assert providers["ss"]["password"] == parts["ss_password"]


def test_fixture_emission_requires_all_parts(tmp_path, monkeypatch):
    for name in provision.COMPOSITION_INPUTS:
        monkeypatch.delenv(name.upper(), raising=False)
    output = tmp_path / "environment"
    with pytest.raises(SystemExit, match="cannot compose nodes without:"):
        provision._emit_nodes(str(output))
    assert not output.exists()
