import base64
import json
import os
import threading
import time

import pytest

import jerryproxy.subscription.manager as manager_module
import jerryproxy.subscription.storage as storage_module
from jerryproxy.errors import IntegrityError, SubscriptionFetchError, SubscriptionStateError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.subscription import SingleNodeSource, SubscriptionManager, V2RaySubscriptionParser
from jerryproxy.subscription.manager import _read_fetch_result, _write_fetch_result
from jerryproxy.subscription.storage import build_record
from jerryproxy.subscription.transport import FetchedSubscription, parse_subscription_body

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
    identity = paths.nodes / "identity.key"
    assert identity.is_file()
    assert len(identity.read_bytes()) == 32
    assert len(record.nodes[0].fingerprint) == 64
    assert "fingerprint" not in record.nodes[0].public()
    if os.name == "posix":
        assert (state.stat().st_mode & 0o777) == 0o600
        assert (state.parent.stat().st_mode & 0o777) == 0o700
    assert manager.get("main").public()["nodes"][0]["id"] == record.nodes[0].node_id


def test_node_identity_is_bound_to_the_subscription_public_id(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    first = manager.add("first", None, body=SS, format_hint="uri-lines")
    second = manager.add("second", None, body=SS, format_hint="uri-lines")

    assert first.subscription_id != second.subscription_id
    assert first.nodes[0].node_id != second.nodes[0].node_id
    assert first.nodes[0].fingerprint != first.nodes[0].node_id


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


def test_fingerprinted_subscription_rejects_a_missing_identity_key(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    manager.add("main", None, body=SS, format_hint="uri-lines")
    paths.nodes.joinpath("identity.key").unlink()

    with pytest.raises(IntegrityError, match="fingerprinted state"):
        manager.get("main")


def test_source_url_and_body_cannot_be_supplied_together(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    with pytest.raises(SubscriptionStateError, match="mutually exclusive"):
        manager.add("main", "https://provider.example/sub", body=SS)


def test_subscription_worker_result_requires_a_private_validated_envelope(tmp_path):
    result = tmp_path / "result.json"
    _write_fetch_result(
        str(result),
        {
            "body": base64.b64encode(SS).decode("ascii"),
            "final_url": "https://provider.example/sub",
            "ok": True,
        },
    )
    assert _read_fetch_result(str(result))[0] == SS
    if os.name == "posix":
        result.chmod(0o644)
        with pytest.raises(SubscriptionFetchError, match="unsafe permissions"):
            _read_fetch_result(str(result))


def test_subscription_worker_result_rejects_an_unvalidated_url(tmp_path):
    result = tmp_path / "result.json"
    _write_fetch_result(
        str(result),
        {
            "body": base64.b64encode(SS).decode("ascii"),
            "final_url": "http://provider.example/sub",
            "ok": True,
        },
    )
    with pytest.raises(SubscriptionFetchError, match="URL is invalid"):
        _read_fetch_result(str(result))


def test_default_remote_fetch_uses_the_bounded_worker_boundary(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)

    class Gate(object):
        def __init__(self):
            self.value = False

        def wait(self, timeout):
            del timeout
            return True

        def is_set(self):
            return self.value

        def set(self):
            self.value = True

    class Process(object):
        def __init__(self, target, args):
            self.target = target
            self.args = args
            self.exitcode = None

        def start(self):
            self.target(*self.args)
            self.exitcode = 0

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return False

    class Context(object):
        Event = Gate

        @staticmethod
        def Process(target, args):
            return Process(target, args)

    def fake_worker(url, result_path, allow_http, format_hint, start_gate, cancel_gate):
        del url, allow_http, format_hint, start_gate, cancel_gate
        manager_module._write_fetch_result(
            result_path,
            {
                "body": base64.b64encode(SS).decode("ascii"),
                "final_url": "https://provider.example/sub",
                "ok": True,
            },
        )

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda name: Context())
    monkeypatch.setattr(manager_module, "_fetch_worker", fake_worker)
    fetched = manager._fetch_remote("https://provider.example/sub", False, "uri-lines")
    assert fetched.body == SS
    assert not tuple(paths.runtimes.glob(".subscription-fetch-*"))


def test_worker_cleanup_failure_is_reported_after_a_successful_fetch(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)

    class Gate(object):
        def wait(self, timeout):
            del timeout
            return True

        def is_set(self):
            return False

        def set(self):
            pass

    class Process(object):
        def __init__(self, target, args):
            self.target = target
            self.args = args
            self.exitcode = None

        def start(self):
            self.target(*self.args)
            self.exitcode = 0

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return False

    class Context(object):
        Event = Gate

        @staticmethod
        def Process(target, args):
            return Process(target, args)

    def fake_worker(url, result_path, allow_http, format_hint, start_gate, cancel_gate):
        del url, allow_http, format_hint, start_gate, cancel_gate
        manager_module._write_fetch_result(
            result_path,
            {
                "body": base64.b64encode(SS).decode("ascii"),
                "final_url": "https://provider.example/sub",
                "ok": True,
            },
        )

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda name: Context())
    monkeypatch.setattr(manager_module, "_fetch_worker", fake_worker)
    monkeypatch.setattr(
        manager_module,
        "_secure_remove_tree",
        lambda *args, **kwargs: (_ for _ in ()).throw(SubscriptionFetchError("cleanup denied")),
    )
    with pytest.raises(SubscriptionFetchError, match="worker cleanup failed"):
        manager._fetch_remote("https://provider.example/sub", False, "uri-lines")


def test_remote_worker_start_has_a_bounded_deadline(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)

    class Gate(object):
        def __init__(self):
            self.value = False

        def wait(self, timeout):
            del timeout
            return True

        def is_set(self):
            return self.value

        def set(self):
            self.value = True

    class SlowProcess(object):
        def __init__(self, target, args):
            del target, args
            self.started = False
            self.released = False
            self.exitcode = None

        def start(self):
            self.started = True
            while not self.released:
                threading.Event().wait(0.01)
            self.exitcode = 0

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return self.started and not self.released

        def terminate(self):
            self.released = True

    class Context(object):
        Event = Gate

        @staticmethod
        def Process(target, args):
            return SlowProcess(target, args)

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda name: Context())
    monkeypatch.setattr(manager_module, "_FETCH_START_SECONDS", 0.01)
    monkeypatch.setattr(manager_module, "_FETCH_STOP_SECONDS", 0.05)
    with pytest.raises(SubscriptionFetchError, match="startup (failed|deadline)"):
        manager._fetch_remote("https://provider.example/sub", False, "uri-lines")
    assert not tuple(paths.runtimes.glob(".subscription-fetch-*"))


def test_late_worker_start_is_owned_by_an_independent_cleanup_supervisor(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    release = threading.Event()

    class Gate(object):
        def wait(self, timeout):
            del timeout
            return True

        def is_set(self):
            return False

        def set(self):
            pass

    class LateProcess(object):
        def __init__(self, target, args):
            del target, args
            self.started = False
            self.exitcode = None

        def start(self):
            self.started = True
            release.wait(1.0)
            self.exitcode = 0

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return self.started and not release.is_set()

        def terminate(self):
            pass

        def kill(self):
            pass

    class Context(object):
        Event = Gate

        @staticmethod
        def Process(target, args):
            return LateProcess(target, args)

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda name: Context())
    monkeypatch.setattr(manager_module, "_FETCH_START_SECONDS", 0.01)
    monkeypatch.setattr(manager_module, "_FETCH_STOP_SECONDS", 0.01)
    monkeypatch.setattr(manager_module, "_FETCH_LATE_CLEANUP_SECONDS", 0.5)
    with pytest.raises(SubscriptionFetchError, match="cleanup failed"):
        manager._fetch_remote("https://provider.example/sub", False, "uri-lines")
    pending = tuple(paths.runtimes.glob(".subscription-fetch-*"))
    assert len(pending) == 1

    release.set()
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and tuple(paths.runtimes.glob(".subscription-fetch-*")):
        time.sleep(0.01)
    assert not tuple(paths.runtimes.glob(".subscription-fetch-*"))


def test_late_worker_start_retains_evidence_when_supervisor_cannot_start(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    release = threading.Event()

    class Gate(object):
        def wait(self, timeout):
            del timeout
            return True

        def is_set(self):
            return False

        def set(self):
            pass

    class LateProcess(object):
        def __init__(self, target, args):
            del target, args
            self.started = False
            self.exitcode = None

        def start(self):
            self.started = True
            release.wait(1.0)
            self.exitcode = 0

        def join(self, timeout):
            del timeout

        def is_alive(self):
            return self.started and not release.is_set()

        def terminate(self):
            pass

        def kill(self):
            pass

    class Context(object):
        Event = Gate

        @staticmethod
        def Process(target, args):
            return LateProcess(target, args)

    monkeypatch.setattr(manager_module.multiprocessing, "get_context", lambda name: Context())
    monkeypatch.setattr(manager_module, "_FETCH_START_SECONDS", 0.01)
    monkeypatch.setattr(manager_module, "_FETCH_STOP_SECONDS", 0.01)
    monkeypatch.setattr(manager._fetch_cleanup, "register", lambda *args: False)
    with pytest.raises(SubscriptionFetchError, match="supervisor unavailable"):
        manager._fetch_remote("https://provider.example/sub", False, "uri-lines")
    assert tuple(paths.runtimes.glob(".subscription-fetch-*"))

    release.set()


def test_body_sources_validate_a_persisted_url_before_publication(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    with pytest.raises(SubscriptionFetchError, match="HTTPS"):
        manager.add("main", "http://provider.example/sub")
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


def test_prepared_subscription_publication_journal_recovers_last_good_generation(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    original = manager.add("main", None, body=SS, format_hint="uri-lines")
    replacement = VMESS
    record_path = paths.subscriptions / "main.json"
    write_json = storage_module._write_json

    def crash_before_current_publication(path, value):
        if path == record_path:
            raise SystemExit("simulated publication interruption")
        return write_json(path, value)

    monkeypatch.setattr(storage_module, "_write_json", crash_before_current_publication)
    parsed = parse_subscription_body(replacement, format_hint="uri-lines")
    candidate = build_record("main", original.subscription_id, parsed, previous=original, paths=paths)
    with pytest.raises(SystemExit):
        manager.store.publish(candidate, replace=True, expected_revision=original.revision)

    assert (paths.subscriptions / ".publication.journal.json").is_file()
    monkeypatch.undo()
    assert manager.get("main").revision == original.revision
    assert not (paths.subscriptions / ".publication.journal.json").exists()


def test_committed_subscription_publication_journal_rolls_forward_on_reopen(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    original = manager.add("main", None, body=SS, format_hint="uri-lines")
    parsed = parse_subscription_body(VMESS, format_hint="uri-lines")
    candidate = build_record("main", original.subscription_id, parsed, previous=original, paths=paths)
    publish_journal = storage_module._write_publication_journal_locked

    def crash_after_current_publication(journal_paths, value):
        if value["phase"] == "committed":
            raise SystemExit("simulated commit marker interruption")
        return publish_journal(journal_paths, value)

    monkeypatch.setattr(storage_module, "_write_publication_journal_locked", crash_after_current_publication)
    with pytest.raises(SystemExit):
        manager.store.publish(candidate, replace=True, expected_revision=original.revision)

    monkeypatch.undo()
    assert manager.get("main").revision == candidate.revision
    assert not (paths.subscriptions / ".publication.journal.json").exists()


def test_prepared_subscription_removal_journal_restores_the_record_on_reopen(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    original = manager.add("main", None, body=SS, format_hint="uri-lines")
    write_journal = storage_module._write_publication_journal_locked

    def crash_before_commit(journal_paths, value):
        if value["kind"] == "remove" and value["phase"] == "committed":
            raise SystemExit("simulated removal commit interruption")
        return write_journal(journal_paths, value)

    monkeypatch.setattr(storage_module, "_write_publication_journal_locked", crash_before_commit)
    with pytest.raises(SystemExit):
        manager.remove("main")

    assert not (paths.subscriptions / "main.json").exists()
    journal = json.loads((paths.subscriptions / ".publication.journal.json").read_text(encoding="utf-8"))
    assert set(journal) == {
        "kind",
        "operation",
        "phase",
        "quarantine_identity",
        "retired_at",
        "subscription_id",
    }
    assert "name_digest" not in journal
    assert "old_revision" not in journal
    assert "new_revision" not in journal
    quarantine = paths.runtimes / (".subscription-remove-%s.json" % journal["operation"])
    assert quarantine.is_file()
    monkeypatch.undo()
    restored = manager.get("main")
    assert restored.revision == original.revision
    assert restored.nodes[0].node_id == original.nodes[0].node_id
    assert not (paths.subscriptions / ".publication.journal.json").exists()
    assert not quarantine.exists()
    tombstones = json.loads((paths.nodes / "tombstones.json").read_text(encoding="utf-8"))
    assert tombstones["entries"] == []


def test_prepared_subscription_removal_before_stage_rolls_back_without_quarantine(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    original = manager.add("main", None, body=SS, format_hint="uri-lines")

    def crash_before_stage(*args, **kwargs):
        del args, kwargs
        raise SystemExit("simulated removal interruption before stage")

    monkeypatch.setattr(storage_module, "_stage_record_locked", crash_before_stage)
    with pytest.raises(SystemExit):
        manager.remove("main")

    assert (paths.subscriptions / "main.json").is_file()
    assert not tuple(paths.runtimes.glob(".subscription-remove-*.json"))
    monkeypatch.undo()
    restored = manager.get("main")
    assert restored.revision == original.revision
    assert restored.nodes[0].node_id == original.nodes[0].node_id
    assert not (paths.subscriptions / ".publication.journal.json").exists()
    tombstones = json.loads((paths.nodes / "tombstones.json").read_text(encoding="utf-8"))
    assert tombstones["entries"] == []


def test_subscription_removal_quarantine_integrity_failure_is_not_downgraded(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    manager.add("main", None, body=SS, format_hint="uri-lines")

    def fail_integrity(*args, **kwargs):
        del args, kwargs
        raise IntegrityError("quarantine identity changed")

    monkeypatch.setattr(storage_module, "_secure_remove_tree", fail_integrity)
    with pytest.raises(IntegrityError, match="quarantine identity changed"):
        manager.remove("main")

    assert not (paths.subscriptions / "main.json").exists()
    assert (paths.subscriptions / ".publication.journal.json").is_file()


def test_subscription_history_is_bounded_and_removed_with_the_record(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    current = manager.add("main", None, body=SS, format_hint="uri-lines")
    for index in range(10):
        body = SS.replace(b"#ss", ("#ss-%d" % index).encode("ascii"))
        current = manager.replace("main", body=body, format_hint="uri-lines")

    history = sorted(paths.subscriptions.glob(".history-*.json"))
    assert len(history) == 8
    assert manager.get("main").revision == current.revision
    manager.remove("main")
    assert not history[0].exists()
    assert not tuple(paths.subscriptions.glob(".history-*.json"))


def test_body_replacement_clears_the_retired_bearer_source(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    monkeypatch.setattr(
        "jerryproxy.subscription.manager.fetch_subscription",
        lambda *args, **kwargs: FetchedSubscription(SS, "https://provider.example/secret"),
    )
    original = manager.add("main", "https://provider.example/secret", format_hint="uri-lines")
    assert original.source_url == "https://provider.example/secret"

    replaced = manager.replace("main", body=VMESS, format_hint="uri-lines")

    assert replaced.source_url is None
    with pytest.raises(SubscriptionStateError, match="no remote source URL"):
        manager.refresh("main")


def test_subscription_record_repr_does_not_include_bearer_or_uri_material(tmp_path, monkeypatch):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    manager = SubscriptionManager(paths)
    monkeypatch.setattr(
        "jerryproxy.subscription.manager.fetch_subscription",
        lambda *args, **kwargs: FetchedSubscription(SS, "https://provider.example/secret"),
    )
    record = manager.add("main", "https://provider.example/secret", format_hint="uri-lines")
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
