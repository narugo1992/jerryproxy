import base64
import json
import os

import pytest

from jerryproxy.errors import SubscriptionFetchError, SubscriptionStateError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.subscription import SingleNodeSource, SubscriptionManager, V2RaySubscriptionParser
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import parse_subscription_body

SS = b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
VMESS = b"vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1NS01NTU1NTU1NTU1NTUiLCJuZXQiOiJ0Y3AiLCJwb3J0IjoiNDQzIiwicHMiOiJ2bWVzcyIsInRscyI6InRscyIsInYiOjJ9\n"


def test_subscription_state_is_private_and_rooted_below_home(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    record = manager.add("main", None, body=SS + VMESS, format_hint="uri-lines")

    assert record.node_count == 2
    state = paths.subscriptions / "main.json"
    assert state.is_file()
    assert state.parent == paths.root / "subscriptions"
    if os.name == "posix":
        assert (state.stat().st_mode & 0o777) == 0o600
        assert (state.parent.stat().st_mode & 0o777) == 0o700
    assert manager.get("main").public()["nodes"][0]["id"] == record.nodes[0].node_id


def test_failed_refresh_preserves_last_known_good(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    parsed = parse_subscription_body(SS, format_hint="uri-lines")
    original = build_record("main", "a" * 32, parsed, source_url="https://example.invalid/sub")
    manager.store.publish(original)

    def fail(*args, **kwargs):
        raise SubscriptionFetchError("source unavailable")

    monkeypatch.setattr("jerryproxy.subscription.manager.fetch_subscription", fail)
    with pytest.raises(SubscriptionFetchError):
        manager.refresh("main")
    assert manager.get("main").revision == original.revision


def test_private_state_rejects_unknown_keys_and_wrong_enabled_type(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    manager.add("main", None, body=SS, format_hint="uri-lines")
    path = paths.subscriptions / "main.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["unknown"] = True
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SubscriptionStateError, match="unknown keys"):
        manager.get("main")

    value.pop("unknown")
    value["enabled"] = 1
    value["body"] = base64.b64encode(SS).decode("ascii")
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SubscriptionStateError, match="enabled"):
        manager.get("main")


def test_private_state_rejects_node_projection_tampering(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    manager.add("main", None, body=SS, format_hint="uri-lines")
    path = paths.subscriptions / "main.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["nodes"][0]["uri"] = "ss://YWVzLTI1Ni1nY206YXR0YWNrQDE5Mi4wLjIuMjo0NDM"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SubscriptionStateError, match="do not match source"):
        manager.get("main")


def test_http_sources_cannot_be_persisted_even_when_explicitly_requested(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    with pytest.raises(SubscriptionFetchError, match="cannot be persisted"):
        manager.add("main", "http://provider.example/sub", body=SS, allow_http=True)


def test_body_sources_validate_a_persisted_url_before_publication(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    with pytest.raises(SubscriptionFetchError, match="HTTPS"):
        manager.add("main", "http://provider.example/sub", body=SS)
    assert not (paths.subscriptions / "main.json").exists()


def test_publication_rejects_a_stale_revision_generation(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    original = manager.add("main", None, body=SS, format_hint="uri-lines")
    parsed = parse_subscription_body(VMESS, format_hint="uri-lines")
    candidate = build_record(
        "main",
        original.subscription_id,
        parsed,
        source_url=None,
        previous=original,
    )
    with pytest.raises(SubscriptionStateError, match="changed during update"):
        manager.store.publish(candidate, replace=True, expected_revision="0" * 64)
    assert manager.get("main").revision == original.revision


def test_body_replacement_clears_the_retired_bearer_source(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    original = manager.add(
        "main",
        "https://provider.example/secret",
        body=SS,
        format_hint="uri-lines",
    )
    assert original.source_url == "https://provider.example/secret"

    replaced = manager.replace("main", body=VMESS, format_hint="uri-lines")

    assert replaced.source_url is None
    with pytest.raises(SubscriptionStateError, match="no remote source URL"):
        manager.refresh("main")


def test_subscription_record_repr_does_not_include_bearer_or_uri_material(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    record = manager.add("main", "https://provider.example/secret", body=SS, format_hint="uri-lines")
    rendered = repr(record)
    assert "provider.example" not in rendered
    assert "YWVzLTI1Ni1nY20" not in rendered
    assert "source_url" not in rendered
    assert "body=" not in rendered


def test_subscription_parser_is_an_injectable_boundary_for_state_reads(tmp_path):
    class TrackingParser(V2RaySubscriptionParser):
        def __init__(self):
            self.calls = []

        def parse(self, body, format_hint="auto"):
            self.calls.append(format_hint)
            return super(TrackingParser, self).parse(body, format_hint=format_hint)

    parser = TrackingParser()
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / ".jerryproxy"), parser=parser)
    record = manager.add("main", None, body=SS, format_hint="uri-lines")
    assert manager.get("main").revision == record.revision
    assert parser.calls[:2] == ["uri-lines", "uri-lines"]


def test_single_node_source_reuses_the_subscription_node_contract(tmp_path):
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / ".jerryproxy"))
    record = manager.add("main", None, body=SS, format_hint="uri-lines")
    source = SingleNodeSource(record.nodes[0])
    assert tuple(source.iter_nodes()) == (record.nodes[0],)
    assert source.node.public()["id"] == record.nodes[0].node_id
