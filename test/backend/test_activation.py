import hashlib
import json
import os
from pathlib import Path

import pytest

from jerryproxy.backend import activation as activation_module
from jerryproxy.backend.activation import (
    ActivationClassification,
    ActivationTransaction,
    classify_activation,
    discover_use_journals,
    load_use_journal,
    plan_activation_recovery,
    recover_use_record,
    recover_use_transactions,
)
from jerryproxy.backend.identity import capture_identity
from jerryproxy.backend.model import PlatformInfo
from jerryproxy.backend.recovery import recover_backend_transactions
from jerryproxy.errors import ArchiveError, DurabilityError, IntegrityError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.utils.fs import atomic_write_json, read_json

PLATFORM = PlatformInfo("linux", "amd64", "glibc")
OPERATION = "0123456789abcdef0123456789abcdef"


def _digest(payload):
    return hashlib.sha256(payload).hexdigest()


def _layout(tmp_path):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    for path in (
        paths.root,
        paths.backends,
        paths.bin,
        paths.active,
        paths.runtimes,
    ):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            path.chmod(0o700)
    return paths


def _installed(paths, version, payload):
    root = paths.backends / "mihomo" / version
    root.mkdir(mode=0o700, parents=True)
    if os.name == "posix":
        root.parent.chmod(0o700)
        root.chmod(0o700)
    executable = root / "mihomo"
    executable.write_bytes(payload)
    manifest = {
        "name": "mihomo",
        "version": version,
        "platform": "linux-amd64",
        "asset_name": "mihomo-linux-amd64-v%s.gz" % version,
        "sha256": "a" * 64,
        "executable_sha256": _digest(payload),
        "source_url": "https://example.test/mihomo.gz",
        "catalog_generated_at": "2026-01-01T00:00:00Z",
        "executable": "mihomo",
        "installed_at": "2026-01-01T00:00:00+00:00",
    }
    atomic_write_json(root / "manifest.json", manifest)
    return executable


def _logical(paths, version, payload, activated_at):
    executable = paths.backends / "mihomo" / version / "mihomo"
    executable_relative = executable.relative_to(paths.root).as_posix()
    manifest = {
        "name": "mihomo",
        "version": version,
        "executable": executable_relative,
        "link": "bin/mihomo",
        "activated_at": activated_at,
        "link_mode": "symlink",
    }
    return {
        "version": version,
        "executable": executable_relative,
        "executable_size": len(payload),
        "executable_sha256": _digest(payload),
        "link_mode": "symlink",
        "manifest_payload": manifest,
    }


def _absent_candidate(path, purpose="target"):
    return {
        "path": path,
        "purpose": purpose,
        "state": "absent",
        "identity": None,
        "size": None,
        "sha256": None,
        "target": None,
    }


def _journal(paths, phase="prepared", previous=True):
    previous_bytes = b"previous"
    target_bytes = b"target"
    _installed(paths, "1.0.0", previous_bytes)
    _installed(paths, "2.0.0", target_bytes)
    old = _logical(paths, "1.0.0", previous_bytes, "2026-01-01T00:00:00+00:00")
    target = _logical(paths, "2.0.0", target_bytes, "2026-01-02T00:00:00+00:00")
    if phase == "prepared":
        target["link_mode"] = None
        target["manifest_payload"] = None
    value = {
        "kind": "use",
        "operation": OPERATION,
        "phase": phase,
        "backend": "mihomo",
        "link": "bin/mihomo",
        "manifest": "active/mihomo.json",
        "previous": old if previous else None,
        "target": target,
        "candidates": {
            "link": _absent_candidate("bin/.mihomo.use-%s.candidate" % OPERATION),
            "manifest": _absent_candidate("active/.mihomo.use-%s.candidate.json" % OPERATION),
        },
        "recovery": None,
    }
    return value


def _write_journal(paths, value, operation=OPERATION):
    path = paths.runtimes / (".use-%s.json" % operation)
    atomic_write_json(path, value)
    return path


def _candidate_identity(file_type):
    return {
        "kind": "posix",
        "device": 1,
        "inode": 2,
        "file_type": file_type,
    }


def _complete_journal(paths, phase="committed"):
    value = _journal(paths)
    value["phase"] = phase
    target = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["target"] = target
    link_target = os.path.relpath(target["executable"], "bin")
    value["candidates"]["link"].update(
        {
            "state": "published",
            "identity": _candidate_identity("symlink"),
            "target": link_target,
        }
    )
    manifest_bytes = (json.dumps(target["manifest_payload"], indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    value["candidates"]["manifest"].update(
        {
            "state": "published",
            "identity": _candidate_identity("regular"),
            "size": len(manifest_bytes),
            "sha256": _digest(manifest_bytes),
        }
    )
    return value


def _publish_link(paths, logical):
    link = paths.bin / "mihomo"
    if os.path.lexists(str(link)):
        link.unlink()
    target = paths.root / logical["executable"]
    link.symlink_to(os.path.relpath(str(target), str(link.parent)))


def _publish_manifest(paths, logical):
    atomic_write_json(paths.active / "mihomo.json", logical["manifest_payload"])


def test_load_use_journal_validates_exact_schema_and_derived_paths(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)

    assert load_use_journal(paths, journal, PLATFORM) == value

    value["extra"] = True
    _write_journal(paths, value)
    with pytest.raises(IntegrityError, match="top-level keys"):
        load_use_journal(paths, journal, PLATFORM)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda value: value.update({"operation": "A" * 32}), "kind or operation"),
        (lambda value: value.update({"link": "bin/xray"}), "public paths"),
        (lambda value: value.update({"phase": "done"}), "phase"),
        (
            lambda value: value["candidates"]["link"].update({"identity": {"kind": "bad"}}),
            "absent link candidate retains evidence",
        ),
    ],
)
def test_load_use_journal_rejects_noncanonical_records(tmp_path, mutation, message):
    paths = _layout(tmp_path)
    value = _journal(paths)
    mutation(value)
    journal = _write_journal(paths, value)
    with pytest.raises(IntegrityError, match=message):
        load_use_journal(paths, journal, PLATFORM)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("backend-type", "invalid backend"),
        ("backend-size", "invalid backend"),
        ("backend-unknown", "unsupported backend"),
        ("backend-case", "noncanonical backend"),
        ("version-prefix", "noncanonical target version"),
        ("version-invalid", "invalid target version"),
        ("executable-path", "invalid target executable"),
        ("executable-mismatch", "does not match immutable installation"),
        ("size-bool", "invalid target executable size"),
        ("size-negative", "invalid target executable size"),
        ("digest-case", "invalid target executable digest"),
        ("evidence-mismatch", "evidence does not match immutable installation"),
        ("link-mode", "invalid target link mode"),
        ("manifest-shape", "target manifest payload keys"),
        ("manifest-mismatch", "manifest payload does not match"),
        ("timestamp-lexical", "invalid activation timestamp"),
        ("timestamp-calendar", "invalid activation timestamp"),
        ("recovery-shape", "recovery keys"),
        ("recovery-direction", "invalid recovery direction"),
        ("previous-version", "noncanonical previous version"),
    ],
)
def test_activation_journal_rejects_invalid_logical_state_fields(tmp_path, case, message):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    target = value["target"]
    if case == "backend-type":
        value["backend"] = None
    elif case == "backend-size":
        value["backend"] = "m" * 65
    elif case == "backend-unknown":
        value["backend"] = "unknown"
    elif case == "backend-case":
        value["backend"] = "Mihomo"
    elif case == "version-prefix":
        target["version"] = "v2.0.0"
    elif case == "version-invalid":
        target["version"] = "../2.0.0"
    elif case == "executable-path":
        target["executable"] = "../outside"
    elif case == "executable-mismatch":
        target["executable"] = "backends/mihomo/1.0.0/mihomo"
    elif case == "size-bool":
        target["executable_size"] = True
    elif case == "size-negative":
        target["executable_size"] = -1
    elif case == "digest-case":
        target["executable_sha256"] = "A" * 64
    elif case == "evidence-mismatch":
        target["executable_size"] += 1
    elif case == "link-mode":
        target["link_mode"] = "hardlink"
    elif case == "manifest-shape":
        target["manifest_payload"]["extra"] = True
    elif case == "manifest-mismatch":
        target["manifest_payload"]["version"] = "1.0.0"
    elif case == "timestamp-lexical":
        target["manifest_payload"]["activated_at"] = "not-a-time"
    elif case == "timestamp-calendar":
        target["manifest_payload"]["activated_at"] = "2026-13-01T00:00:00+00:00"
    elif case == "recovery-shape":
        value["recovery"] = {"direction": "rollforward-target", "extra": True}
    elif case == "recovery-direction":
        value["recovery"] = {"direction": "sideways"}
    else:
        value["previous"]["version"] = "v1.0.0"
    journal = _write_journal(paths, value)

    with pytest.raises(IntegrityError, match=message):
        load_use_journal(paths, journal, PLATFORM)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("shape", "link candidate keys"),
        ("path", "incorrect link candidate path"),
        ("purpose", "invalid link candidate purpose or state"),
        ("state", "invalid link candidate purpose or state"),
        ("building-evidence", "building link candidate has ready evidence"),
        ("building-identity", "stable identity expected regular"),
        ("ready-identity", "published link candidate has no identity"),
        ("regular-target", "regular link candidate has a symlink target"),
        ("symlink-size", "symlink link candidate has regular-file evidence"),
        ("symlink-target", "invalid link candidate symlink target"),
        ("directory", "candidate cannot be a directory"),
        ("missing-purpose-state", "candidate purpose has no logical state"),
        ("copy-evidence", "link candidate evidence does not match its purpose"),
        ("symlink-evidence", "link candidate evidence does not match its purpose"),
        ("manifest-evidence", "manifest candidate evidence does not match its purpose"),
        ("normal-recovery-purpose", "normal candidate has a recovery purpose"),
        ("illegal-building", "building candidate is illegal"),
        ("recovery-purpose", "candidate purpose disagrees with recovery direction"),
    ],
)
def test_activation_journal_rejects_invalid_candidate_evidence(tmp_path, case, message):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    link = value["candidates"]["link"]
    manifest = value["candidates"]["manifest"]
    if case == "shape":
        link["extra"] = True
    elif case == "path":
        link["path"] = "bin/wrong"
    elif case == "purpose":
        link["purpose"] = "unknown"
    elif case == "state":
        link["state"] = "unknown"
    elif case == "building-evidence":
        value["phase"] = "link-building"
        link.update({"state": "building", "identity": None, "size": 0, "sha256": None, "target": None})
        manifest.update(_absent_candidate(manifest["path"]))
    elif case == "building-identity":
        value["phase"] = "link-building"
        link.update(
            {
                "state": "building",
                "identity": _candidate_identity("symlink"),
                "size": None,
                "sha256": None,
                "target": None,
            }
        )
        manifest.update(_absent_candidate(manifest["path"]))
    elif case == "ready-identity":
        link["identity"] = None
    elif case == "regular-target":
        link.update(
            {
                "identity": _candidate_identity("regular"),
                "size": value["target"]["executable_size"],
                "sha256": value["target"]["executable_sha256"],
                "target": "unexpected",
            }
        )
    elif case == "symlink-size":
        link["size"] = 1
    elif case == "symlink-target":
        link["target"] = None
    elif case == "directory":
        link["identity"] = _candidate_identity("directory")
    elif case == "missing-purpose-state":
        value["previous"] = None
        value["phase"] = "prepared"
        value["recovery"] = {"direction": "rollback-absent"}
        value["target"]["link_mode"] = None
        value["target"]["manifest_payload"] = None
        link.update(
            {
                "purpose": "recovery-previous",
                "state": "ready",
                "identity": _candidate_identity("symlink"),
                "target": "../backends/mihomo/1.0.0/mihomo",
            }
        )
        manifest.update(_absent_candidate(manifest["path"]))
    elif case == "copy-evidence":
        value["target"]["link_mode"] = "copy"
        value["target"]["manifest_payload"]["link_mode"] = "copy"
        link.update(
            {
                "identity": _candidate_identity("regular"),
                "size": value["target"]["executable_size"] + 1,
                "sha256": value["target"]["executable_sha256"],
                "target": None,
            }
        )
    elif case == "symlink-evidence":
        link["target"] = "../wrong"
    elif case == "manifest-evidence":
        manifest["sha256"] = "0" * 64
    elif case == "normal-recovery-purpose":
        link["purpose"] = "recovery-target"
    elif case == "illegal-building":
        link.update(
            {
                "state": "building",
                "identity": None,
                "size": None,
                "sha256": None,
                "target": None,
            }
        )
    else:
        value["recovery"] = {"direction": "rollback-previous"}
        link["purpose"] = "recovery-target"
    journal = _write_journal(paths, value)

    with pytest.raises(IntegrityError, match=message):
        load_use_journal(paths, journal, PLATFORM)


def test_activation_journal_accepts_discarding_regular_without_ready_evidence(tmp_path):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    link = value["candidates"]["link"]
    link.update(
        {
            "state": "discarding",
            "identity": _candidate_identity("regular"),
            "size": None,
            "sha256": None,
            "target": None,
        }
    )
    journal = _write_journal(paths, value)

    assert load_use_journal(paths, journal, PLATFORM) == value


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("prepared-complete", "prepared target must be incomplete"),
        ("phase-pair", "candidate states disagree with normal phase"),
        ("committed-state", "invalid committed candidate state"),
        ("direction", "persisted recovery direction disagrees"),
    ],
)
def test_activation_journal_rejects_phase_and_recovery_mismatch(tmp_path, case, message):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    if case == "prepared-complete":
        value["phase"] = "prepared"
    elif case == "phase-pair":
        value["phase"] = "link-ready"
        value["candidates"]["link"].update(_absent_candidate(value["candidates"]["link"]["path"]))
        value["candidates"]["manifest"].update(_absent_candidate(value["candidates"]["manifest"]["path"]))
    elif case == "committed-state":
        value["candidates"]["link"]["state"] = "ready"
    else:
        value["recovery"] = {"direction": "rollback-previous"}
    journal = _write_journal(paths, value)

    with pytest.raises(IntegrityError, match=message):
        load_use_journal(paths, journal, PLATFORM)


def test_activation_journal_maps_unreadable_immutable_executable(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    executable = paths.backends / "mihomo" / "2.0.0" / "mihomo"
    original_evidence = activation_module.load_installed_manifest_evidence

    def deny_executable_evidence(*args, **kwargs):
        evidence = original_evidence(*args, **kwargs)
        if evidence[0].executable == executable:
            raise PermissionError("denied")
        return evidence

    monkeypatch.setattr(
        activation_module,
        "load_installed_manifest_evidence",
        deny_executable_evidence,
    )
    journal = _write_journal(paths, value)

    with pytest.raises(IntegrityError, match="unreadable immutable executable"):
        load_use_journal(paths, journal, PLATFORM)


@pytest.mark.parametrize("payload", [b'{"kind":"use","kind":"install"}', b"\xff", b"[]"])
def test_load_use_journal_maps_strict_json_failures_to_integrity(tmp_path, payload):
    paths = _layout(tmp_path)
    journal = paths.runtimes / (".use-%s.json" % OPERATION)
    journal.write_bytes(payload)
    if os.name == "posix":
        journal.chmod(0o600)
    with pytest.raises(IntegrityError, match="activation journal"):
        load_use_journal(paths, journal, PLATFORM)


def test_discovery_is_lexical_nonmutating_and_exposes_complete_sets(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)
    before = journal.read_bytes()

    records = discover_use_journals(paths, PLATFORM)

    assert len(records) == 1
    record = records[0]
    assert record.kind == "use"
    assert record.operation == OPERATION
    assert "backends/mihomo/2.0.0/manifest.json" in record.read_paths
    assert "backends/mihomo/2.0.0/mihomo" in record.read_paths
    assert "bin/mihomo" in record.write_paths
    assert "active/.mihomo.use-%s.candidate.json" % OPERATION in record.write_paths
    assert journal.read_bytes() == before


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink classification")
@pytest.mark.parametrize(
    "link_state,manifest_state,expected",
    [
        ("P", "P", ("P", "P")),
        ("T", "P", ("T", "P")),
        ("M", "T", ("M", "T")),
        ("U", "M", ("U", "M")),
    ],
)
def test_physical_public_classification_covers_p_t_m_u(tmp_path, link_state, manifest_state, expected):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    if link_state in ("P", "T"):
        _publish_link(paths, value["previous"] if link_state == "P" else value["target"])
    elif link_state == "U":
        (paths.bin / "mihomo").write_bytes(b"unknown")
    if manifest_state in ("P", "T"):
        _publish_manifest(paths, value["previous"] if manifest_state == "P" else value["target"])

    actual = classify_activation(paths, value)
    assert (actual.link, actual.manifest) == expected


def test_equal_copy_bytes_are_classified_b(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    shared = b"same"
    for version in ("1.0.0", "2.0.0"):
        executable = paths.backends / "mihomo" / version / "mihomo"
        executable.write_bytes(shared)
        value["previous" if version == "1.0.0" else "target"] = _logical(
            paths, version, shared, "2026-01-01T00:00:00+00:00"
        )
        value["previous" if version == "1.0.0" else "target"]["link_mode"] = "copy"
        value["previous" if version == "1.0.0" else "target"]["manifest_payload"]["link_mode"] = "copy"
    (paths.bin / "mihomo").write_bytes(shared)

    assert classify_activation(paths, value).link == "B"


@pytest.mark.parametrize("phase", sorted(activation_module.PHASES))
@pytest.mark.parametrize("link_state", ("P", "T", "B", "M"))
@pytest.mark.parametrize("manifest_state", ("P", "T", "M"))
def test_activation_recovery_planner_accepts_the_closed_public_cartesian_matrix(
    tmp_path,
    phase,
    link_state,
    manifest_state,
):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["phase"] = phase
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    classification = ActivationClassification(
        link_state,
        manifest_state,
        "missing",
        "missing",
    )

    direction = plan_activation_recovery(value, classification)

    expected = "rollforward-target" if phase == "committed" else "rollback-previous"
    assert direction.action == "persist-direction"
    assert direction.direction == expected
    continued = plan_activation_recovery(direction.journal, classification)
    assert continued.direction == expected


@pytest.mark.parametrize(
    ("link_state", "manifest_state", "link_candidate", "manifest_candidate"),
    (
        ("U", "M", "missing", "missing"),
        ("M", "U", "missing", "missing"),
        ("M", "M", "unknown", "missing"),
        ("M", "M", "missing", "unknown"),
    ),
)
def test_activation_recovery_planner_rejects_every_unknown_evidence_position(
    tmp_path,
    link_state,
    manifest_state,
    link_candidate,
    manifest_candidate,
):
    paths = _layout(tmp_path)
    value = _journal(paths)
    classification = ActivationClassification(
        link_state,
        manifest_state,
        link_candidate,
        manifest_candidate,
    )

    with pytest.raises(IntegrityError, match="unknown physical state"):
        plan_activation_recovery(value, classification)


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative public copy read requires POSIX")
def test_public_copy_classification_does_not_reopen_the_command_by_path(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    public = paths.bin / "mihomo"
    public.write_bytes(b"previous")
    original_open = Path.open

    def deny_command_path_open(path, *args, **kwargs):
        if path == public:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_command_path_open)

    assert classify_activation(paths, value).link == "P"


def test_candidate_classification_requires_stable_identity(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    candidate = paths.root / value["candidates"]["manifest"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["manifest"].update({"state": "building", "identity": capture_identity(candidate)})

    assert classify_activation(paths, value).manifest_candidate == "recorded-owned"
    candidate.rename(tmp_path / "original-candidate")
    candidate.write_bytes(b"")
    assert classify_activation(paths, value).manifest_candidate == "unknown"


def test_ready_candidate_requires_recorded_identity_and_exact_content(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    candidate = paths.root / value["candidates"]["manifest"]["path"]
    candidate.write_bytes(b"wrong")
    value["candidates"]["manifest"].update(
        {
            "purpose": "recovery-previous",
            "state": "ready",
            "identity": capture_identity(candidate),
            "size": len(b"wrong"),
            "sha256": _digest(b"different"),
        }
    )

    assert classify_activation(paths, value).manifest_candidate == "unknown"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink candidate classification")
def test_unrecorded_exact_symlink_is_pinned_before_recovery_disposal(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    candidate = paths.root / value["candidates"]["link"]["path"]
    target = paths.root / value["target"]["executable"]
    candidate.symlink_to(os.path.relpath(str(target), str(candidate.parent)))

    classification = classify_activation(paths, value)
    assert classification.link_candidate == "exact-unrecorded-purpose-object"
    plan = plan_activation_recovery(value, classification)
    assert (plan.action, plan.object_name) == ("pin-unrecorded-candidate", "link")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink recovery")
def test_unrecorded_target_symlink_recovery_converges_to_previous_pair(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    candidate = paths.root / value["candidates"]["link"]["path"]
    target = paths.root / value["target"]["executable"]
    candidate.symlink_to(os.path.relpath(str(target), str(candidate.parent)))
    journal = _write_journal(paths, value)

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert not os.path.lexists(str(candidate))
    assert classify_activation(paths, value).link == "P"
    assert classify_activation(paths, value).manifest == "P"


def test_rollback_absent_deletes_an_exposed_public_link_and_disposes_authority(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths, previous=False)
    value["recovery"] = {"direction": "rollback-absent"}
    public = paths.bin / "mihomo"
    public.write_bytes(b"target")
    journal = _write_journal(paths, value)

    recover_use_transactions(paths, PLATFORM)

    assert not public.exists()
    assert not journal.exists()


def test_recovery_refuses_replaced_unrecorded_candidate_after_planning(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"]["state"] = "building"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery
    replacement_identity = []

    def replace_after_planning(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "pin-unrecorded-candidate" and not replacement_identity:
            candidate.rename(tmp_path / "original-candidate")
            candidate.write_bytes(b"")
            replacement_identity.append(capture_identity(candidate))
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", replace_after_planning)

    with pytest.raises(IntegrityError, match="changed after activation recovery planning"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert candidate.exists()
    assert capture_identity(candidate) == replacement_identity[0]


def test_recovery_refuses_replaced_public_object_before_deletion(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, previous=False)
    value["recovery"] = {"direction": "rollback-absent"}
    public = paths.bin / "mihomo"
    public.write_bytes(b"target")
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery
    replacement_identity = []

    def replace_after_planning(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "delete-public" and not replacement_identity:
            public.rename(tmp_path / "original-public")
            public.write_bytes(b"target")
            replacement_identity.append(capture_identity(public))
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", replace_after_planning)

    with pytest.raises(IntegrityError, match="changed after activation recovery planning"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert public.read_bytes() == b"target"
    assert capture_identity(public) == replacement_identity[0]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink repair candidate")
def test_recovery_refuses_new_public_destination_before_repair_publication(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    candidate = paths.root / value["candidates"]["link"]["path"]
    previous = value["previous"]
    candidate.symlink_to(os.path.relpath(str(paths.root / previous["executable"]), str(candidate.parent)))
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "ready",
            "identity": capture_identity(candidate),
            "target": os.readlink(str(candidate)),
        }
    )
    journal = _write_journal(paths, value)
    public = paths.bin / "mihomo"
    original_plan = activation_module.plan_activation_recovery
    replacement_identity = []

    def replace_after_planning(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "publish-repair-candidate" and not replacement_identity:
            public.write_bytes(b"replacement")
            replacement_identity.append(capture_identity(public))
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", replace_after_planning)

    with pytest.raises(IntegrityError, match="changed after activation recovery planning"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert public.read_bytes() == b"replacement"
    assert capture_identity(public) == replacement_identity[0]
    assert candidate.is_symlink()


@pytest.mark.parametrize(
    "phase,previous,direction",
    [
        ("prepared", True, "rollback-previous"),
        ("prepared", False, "rollback-absent"),
        ("committed", True, "rollforward-target"),
    ],
)
def test_recovery_direction_is_persisted_once_from_commit_phase(tmp_path, phase, previous, direction):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="prepared", previous=previous)
    if phase == "committed":
        value["phase"] = "committed"
        value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    classification = ActivationClassification("M", "M", "missing", "missing")

    plan = plan_activation_recovery(value, classification)

    assert plan.action == "persist-direction"
    assert plan.direction == direction
    assert plan.journal["recovery"] == {"direction": direction}
    assert value["recovery"] is None


def test_recovery_resume_advances_candidate_disposal_before_public_repair(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"].update(
        {
            "state": "ready",
            "identity": {
                "kind": "posix",
                "device": 1,
                "inode": 2,
                "file_type": "symlink",
            },
            "target": "../backends/mihomo/2.0.0/mihomo",
        }
    )
    classification = ActivationClassification("T", "M", "recorded-owned", "missing")

    first = plan_activation_recovery(value, classification)
    assert (first.action, first.object_name) == ("persist-discarding", "link")
    second = plan_activation_recovery(first.journal, classification)
    assert (second.action, second.object_name) == ("delete-candidate", "link")
    missing = ActivationClassification("T", "M", "missing", "missing")
    third = plan_activation_recovery(second.journal, missing)
    assert third.action == "persist-candidate-absent"
    fourth = plan_activation_recovery(third.journal, missing)
    assert (fourth.action, fourth.object_name) == ("build-repair-candidate", "link")


def test_recover_record_reclassifies_and_rejects_unknown_public_state(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)
    (paths.bin / "mihomo").write_bytes(b"unknown")
    record = discover_use_journals(paths, PLATFORM)[0]

    with pytest.raises(IntegrityError, match="unknown physical state"):
        recover_use_record(paths, record)
    assert journal.exists()


def test_recovery_rejects_direction_change_on_restart(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollforward-target"}
    classification = ActivationClassification("M", "M", "missing", "missing")
    with pytest.raises(IntegrityError, match="direction changed"):
        plan_activation_recovery(value, classification)


@pytest.mark.parametrize(
    "phase",
    [
        "link-building",
        "link-ready",
        "manifest-building",
        "candidates-ready",
        "link-published",
    ],
)
def test_recovery_mark_does_not_authorize_impossible_target_candidate_states(tmp_path, phase):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    value["phase"] = phase
    value["recovery"] = {"direction": "rollback-previous"}
    journal = _write_journal(paths, value)

    with pytest.raises(IntegrityError, match="candidate states disagree with original phase"):
        load_use_journal(paths, journal, PLATFORM)


def test_recovery_accepts_target_candidate_disposal_reachable_from_original_phase(
    tmp_path,
):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    value["phase"] = "link-ready"
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"]["state"] = "discarding"
    value["candidates"]["manifest"].update(_absent_candidate(value["candidates"]["manifest"]["path"]))
    journal = _write_journal(paths, value)

    assert load_use_journal(paths, journal, PLATFORM) == value


def test_activation_transaction_publishes_exact_target_and_disposes_intent(tmp_path):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")

    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    active = transaction.execute()

    assert active.version == "2.0.0"
    assert active.link.is_symlink()
    assert active.link.resolve() == active.executable.resolve()
    assert not transaction.journal_path.exists()
    assert not os.path.lexists(str(paths.root / transaction.value["candidates"]["link"]["path"]))
    assert not os.path.lexists(str(paths.root / transaction.value["candidates"]["manifest"]["path"]))


def test_activation_journal_transitions_use_one_anchored_identity_chain(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    original_write = activation_module.AnchoredDirectory.write_json
    publications = []

    def record_write(anchored, parts, value, temporary_parts, *args, **kwargs):
        result = original_write(anchored, parts, value, temporary_parts, *args, **kwargs)
        if anchored.root == paths.runtimes:
            publications.append((dict(kwargs), result[1]))
        return result

    monkeypatch.setattr(activation_module.AnchoredDirectory, "write_json", record_write)
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    transaction.execute()

    assert len(publications) > 2
    assert publications[0][0].get("replace_existing", False) is False
    assert publications[0][0].get("expected_destination_identity") is None
    for previous, current in zip(publications, publications[1:]):
        assert current[0]["replace_existing"] is True
        assert current[0]["expected_destination_identity"] == previous[1]


def test_precommit_activation_crash_recovers_previous_pair(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "1.0.0", b"previous")
    _installed(paths, "2.0.0", b"target")
    previous = _logical(paths, "1.0.0", b"previous", "2026-01-01T00:00:00+00:00")
    _publish_link(paths, previous)
    _publish_manifest(paths, previous)
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_durable_replace = activation_module.durable_replace
    calls = []

    def record_publication(destination, result):
        calls.append(Path(destination).name)
        if len(calls) == 1:
            raise OSError("simulated hard interruption after link publication")
        return result

    def crash_after_pathname_replace(source, destination, *args, **kwargs):
        return record_publication(
            destination,
            original_durable_replace(source, destination, *args, **kwargs),
        )

    monkeypatch.setattr(activation_module, "durable_replace", crash_after_pathname_replace)
    with pytest.raises(OSError, match="hard interruption"):
        transaction.execute()
    monkeypatch.setattr(activation_module, "durable_replace", original_durable_replace)

    recover_use_transactions(paths, PLATFORM)

    recovered = classify_activation(paths, transaction.value)
    assert (recovered.link, recovered.manifest) == ("P", "P")
    assert (paths.active / "mihomo.json").read_text(encoding="utf-8")
    assert not transaction.journal_path.exists()


def test_authoritative_use_journal_ignores_then_disposes_writer_temporary(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)
    temporary = paths.runtimes / (".use-%s.json.tmp-%s" % (OPERATION, "f" * 32))
    temporary.write_bytes(b"partial newer phase")
    if os.name == "posix":
        temporary.chmod(0o600)

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert not temporary.exists()


def test_orphan_use_writer_temporary_is_removed_without_owned_objects(tmp_path):
    paths = _layout(tmp_path)
    temporary = paths.runtimes / (".use-%s.json.tmp-%s" % (OPERATION, "f" * 32))
    temporary.write_bytes(b"partial initial write")
    if os.name == "posix":
        temporary.chmod(0o600)

    recover_backend_transactions(paths, PLATFORM)

    assert not temporary.exists()


def test_orphan_use_writer_temporary_with_candidate_fails_closed(tmp_path):
    paths = _layout(tmp_path)
    temporary = paths.runtimes / (".use-%s.json.tmp-%s" % (OPERATION, "f" * 32))
    temporary.write_bytes(b"partial initial write")
    candidate = paths.bin / (".mihomo.use-%s.candidate" % OPERATION)
    candidate.write_bytes(b"")
    if os.name == "posix":
        temporary.chmod(0o600)
        candidate.chmod(0o600)

    with pytest.raises(IntegrityError, match="without authority"):
        recover_backend_transactions(paths, PLATFORM)

    assert temporary.exists()
    assert candidate.exists()


@pytest.mark.parametrize(
    "area,name",
    [
        ("runtimes", ".use-invalid.json"),
        ("bin", ".mihomo.use-invalid.candidate"),
        ("active", ".mihomo.use-invalid.candidate.json"),
    ],
)
def test_unknown_use_recovery_namespace_entry_fails_closed(tmp_path, area, name):
    paths = _layout(tmp_path)
    entry = getattr(paths, area) / name
    entry.write_bytes(b"unknown")

    with pytest.raises(IntegrityError, match="activation recovery"):
        recover_backend_transactions(paths, PLATFORM)

    assert entry.exists()


def test_activation_journal_authority_rejects_filename_alias_type_and_permissions(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    invalid_name = paths.runtimes / ".use-invalid.json"
    atomic_write_json(invalid_name, value)
    with pytest.raises(IntegrityError, match="authoritative filename"):
        load_use_journal(paths, invalid_name, PLATFORM)
    invalid_name.unlink()

    journal = paths.runtimes / (".use-%s.json" % OPERATION)
    outside = tmp_path / "outside.json"
    atomic_write_json(outside, value)
    journal.symlink_to(outside)
    with pytest.raises(IntegrityError, match="aliased"):
        load_use_journal(paths, journal, PLATFORM)
    journal.unlink()

    journal.mkdir()
    with pytest.raises(IntegrityError, match="not regular"):
        load_use_journal(paths, journal, PLATFORM)
    journal.rmdir()

    atomic_write_json(journal, value)
    if os.name == "posix":
        journal.chmod(0o644)
        with pytest.raises(IntegrityError, match="unsafe authoritative"):
            load_use_journal(paths, journal, PLATFORM)


@pytest.mark.parametrize("failure", ("alias", "directory", "oversized", "permissions"))
def test_activation_writer_temporary_security_boundary(tmp_path, failure):
    paths = _layout(tmp_path)
    temporary = paths.runtimes / (".use-%s.json.tmp-%s" % (OPERATION, "f" * 32))
    if failure == "alias":
        temporary.symlink_to(tmp_path / "outside")
    elif failure == "directory":
        temporary.mkdir()
    elif failure == "oversized":
        temporary.write_bytes(b"x" * (1024 * 1024 + 1))
    else:
        temporary.write_bytes(b"partial")
        if os.name != "posix":
            pytest.skip("POSIX permission boundary")
        temporary.chmod(0o644)

    with pytest.raises(IntegrityError, match="activation recovery writer temporary"):
        discover_use_journals(paths, PLATFORM)


def test_activation_journal_rejects_operation_that_disagrees_with_filename(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["operation"] = "f" * 32
    journal = _write_journal(paths, value)

    with pytest.raises(IntegrityError, match="operation does not match filename"):
        load_use_journal(paths, journal, PLATFORM)


def test_discovery_rejects_unexpected_candidate_for_authoritative_operation(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)
    unexpected = paths.bin / (".xray.use-%s.candidate" % OPERATION)
    unexpected.write_bytes(b"")

    with pytest.raises(IntegrityError, match="unexpected activation recovery candidate"):
        discover_use_journals(paths, PLATFORM)

    assert journal.exists()
    assert unexpected.exists()


def test_discovery_preserves_journal_replaced_during_preflight(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)
    original_load = activation_module._load_use_journal
    replacement_identity = []

    def load_then_replace(*args, **kwargs):
        loaded = original_load(*args, **kwargs)
        payload = journal.read_bytes()
        journal.rename(tmp_path / "original-journal")
        journal.write_bytes(payload)
        if os.name == "posix":
            journal.chmod(0o600)
        replacement_identity.append(capture_identity(journal))
        return loaded

    monkeypatch.setattr(activation_module, "_load_use_journal", load_then_replace)

    with pytest.raises(IntegrityError, match="journal changed during preflight"):
        discover_use_journals(paths, PLATFORM)

    assert journal.exists()
    assert capture_identity(journal) == replacement_identity[0]


@pytest.mark.parametrize("failure", ("alias", "directory", "permissions", "malformed", "unexpected"))
def test_public_manifest_security_failures_classify_as_unknown(tmp_path, failure):
    paths = _layout(tmp_path)
    value = _journal(paths)
    manifest = paths.active / "mihomo.json"
    if failure == "alias":
        outside = tmp_path / "outside.json"
        atomic_write_json(outside, value["previous"]["manifest_payload"])
        manifest.symlink_to(outside)
    elif failure == "directory":
        manifest.mkdir()
    elif failure == "permissions":
        if os.name != "posix":
            pytest.skip("POSIX permission boundary")
        atomic_write_json(manifest, value["previous"]["manifest_payload"])
        manifest.chmod(0o644)
    elif failure == "malformed":
        manifest.write_bytes(b"not-json")
        if os.name == "posix":
            manifest.chmod(0o600)
    else:
        atomic_write_json(manifest, {"name": "unrelated"})

    assert classify_activation(paths, value).manifest == "U"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink classification")
def test_public_link_read_failure_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    public = paths.bin / "mihomo"
    _publish_link(paths, value["previous"])
    original_readlink = os.readlink

    def deny_public_readlink(path, *args, **kwargs):
        if Path(path) == public:
            raise PermissionError("denied")
        return original_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", deny_public_readlink)

    assert classify_activation(paths, value).link == "U"


def test_missing_recorded_building_candidate_classifies_as_unknown(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["candidates"]["link"].update(
        {
            "state": "building",
            "identity": _candidate_identity("regular"),
        }
    )

    assert classify_activation(paths, value).link_candidate == "unknown"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink candidate classification")
def test_published_candidate_rejects_public_object_with_wrong_logical_state(tmp_path):
    paths = _layout(tmp_path)
    value = _complete_journal(paths)
    public = paths.bin / "mihomo"
    _publish_link(paths, value["previous"])
    value["candidates"]["link"]["identity"] = capture_identity(public)

    assert classify_activation(paths, value).link_candidate == "unknown"


def test_activation_prepare_rejects_changed_source_digest(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    executable = _installed(paths, "2.0.0", b"target")
    original_evidence = activation_module.load_installed_manifest_evidence

    def changed_digest(selected_paths, manifest):
        installed, size, digest, identity = original_evidence(selected_paths, manifest)
        if installed.executable == executable:
            digest = "0" * 64
        return installed, size, digest, identity

    monkeypatch.setattr(activation_module, "load_installed_manifest_evidence", changed_digest)

    with pytest.raises(IntegrityError, match="source executable digest changed"):
        ActivationTransaction.prepare(paths, PLATFORM, "mihomo", "2.0.0", operation=OPERATION)


def test_activation_prepare_does_not_reopen_source_executable_by_path(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    executable = _installed(paths, "2.0.0", b"target")
    original_open = Path.open

    def deny_executable_path_open(path, *args, **kwargs):
        if path == executable:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_executable_path_open)

    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )

    assert transaction.value["target"]["executable_size"] == len(b"target")
    assert transaction.journal_path.is_file()


def test_activation_prepare_rejects_existing_journal_without_overwrite(tmp_path):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    journal = paths.runtimes / (".use-%s.json" % OPERATION)
    journal.write_bytes(b"existing authority")
    before = journal.read_bytes()

    with pytest.raises(IntegrityError, match="activation journal already exists"):
        ActivationTransaction.prepare(paths, PLATFORM, "mihomo", "2.0.0", operation=OPERATION)

    assert journal.read_bytes() == before


def test_activation_journal_preflight_does_not_reopen_authority_by_path(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    journal = _write_journal(paths, value)
    original_open = Path.open

    def deny_journal_path_open(path, *args, **kwargs):
        if path == journal:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_journal_path_open)

    records = discover_use_journals(paths, PLATFORM)

    assert len(records) == 1
    assert records[0].journal_path == journal


def test_activation_execute_retains_journal_when_published_pair_fails_validation(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    monkeypatch.setattr(
        activation_module,
        "classify_activation",
        lambda unused_paths, unused_value: ActivationClassification("M", "M", "missing", "missing"),
    )

    with pytest.raises(IntegrityError, match="published activation pair failed validation"):
        transaction.execute()

    assert transaction.journal_path.exists()
    assert os.path.lexists(str(paths.bin / "mihomo"))
    assert (paths.active / "mihomo.json").exists()


def test_activation_execute_reports_committed_state_that_disappears(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    monkeypatch.setattr(activation_module, "load_active_state", lambda *args, **kwargs: None)

    with pytest.raises(IntegrityError, match="committed activation state disappeared"):
        transaction.execute()

    assert not transaction.journal_path.exists()


def test_recovery_preserves_journal_replaced_before_disposal(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    _publish_link(paths, value["previous"])
    _publish_manifest(paths, value["previous"])
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery
    replacement_identity = []

    def replace_before_disposal(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "dispose-journal" and not replacement_identity:
            payload = journal.read_bytes()
            journal.rename(tmp_path / "original-journal")
            journal.write_bytes(payload)
            if os.name == "posix":
                journal.chmod(0o600)
            replacement_identity.append(capture_identity(journal))
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", replace_before_disposal)

    with pytest.raises(IntegrityError):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert capture_identity(journal) == replacement_identity[0]


def test_discovery_fails_closed_when_writer_temporary_disappears_during_inspection(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    temporary = paths.runtimes / (".use-%s.json.tmp-%s" % (OPERATION, "f" * 32))
    temporary.write_bytes(b"partial")
    if os.name == "posix":
        temporary.chmod(0o600)
    original_alias = activation_module.is_path_alias
    original_lstat = Path.lstat

    def stable_alias(path):
        if Path(path) == temporary:
            return False
        return original_alias(path)

    def disappear(path, *args, **kwargs):
        if path == temporary:
            raise FileNotFoundError("disappeared")
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(activation_module, "is_path_alias", stable_alias)
    monkeypatch.setattr(Path, "lstat", disappear)

    with pytest.raises(IntegrityError, match="unable to inspect activation recovery writer temporary"):
        discover_use_journals(paths, PLATFORM)

    assert temporary.exists()


@pytest.mark.parametrize(
    ("area", "message"),
    (
        ("runtimes", "unable to enumerate activation journals"),
        ("bin", "unable to enumerate activation recovery candidates"),
        ("active", "unable to enumerate activation recovery candidates"),
    ),
)
def test_discovery_fails_closed_when_recovery_namespace_cannot_be_enumerated(tmp_path, monkeypatch, area, message):
    paths = _layout(tmp_path)
    target = getattr(paths, area)
    original_iterdir = Path.iterdir

    def deny_target(path):
        if path == target:
            raise PermissionError("denied")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", deny_target)

    with pytest.raises(IntegrityError, match=message):
        discover_use_journals(paths, PLATFORM)


def test_public_identity_capture_failure_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    public = paths.bin / "mihomo"
    public.write_bytes(b"unknown")
    original_capture = activation_module.capture_identity

    def deny_public_identity(path):
        if Path(path) == public:
            raise PermissionError("denied")
        return original_capture(path)

    monkeypatch.setattr(activation_module, "capture_identity", deny_public_identity)

    assert classify_activation(paths, value).link == "U"


def test_candidate_identity_capture_failure_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["candidates"]["link"]["state"] = "building"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    original_capture = activation_module.capture_identity

    def deny_candidate_identity(path):
        if Path(path) == candidate:
            raise PermissionError("denied")
        return original_capture(path)

    monkeypatch.setattr(activation_module, "capture_identity", deny_candidate_identity)

    assert classify_activation(paths, value).link_candidate == "unknown"


def test_recorded_candidate_inspection_failure_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["link"].update(
        {
            "state": "ready",
            "identity": capture_identity(candidate),
            "size": 0,
            "sha256": _digest(b""),
        }
    )
    original_lstat = Path.lstat
    original_matches = activation_module.identity_matches

    def accept_recorded_identity(path, identity):
        if Path(path) == candidate:
            return True
        return original_matches(path, identity)

    def deny_candidate_inspection(path, *args, **kwargs):
        if path == candidate:
            raise PermissionError("denied")
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(activation_module, "identity_matches", accept_recorded_identity)
    monkeypatch.setattr(Path, "lstat", deny_candidate_inspection)

    assert activation_module.classify_candidate(paths, value, "link") == "unknown"


def test_recover_use_record_rejects_nonactivation_record(tmp_path):
    paths = _layout(tmp_path)

    with pytest.raises(IntegrityError, match="invalid activation recovery record"):
        recover_use_record(paths, object())


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="source alias requires symlink support")
def test_activation_prepare_rejects_aliased_source_executable(tmp_path):
    paths = _layout(tmp_path)
    executable = _installed(paths, "2.0.0", b"target")
    outside = tmp_path / "outside-backend"
    outside.write_bytes(b"target")
    executable.unlink()
    executable.symlink_to(outside)

    with pytest.raises(IntegrityError, match="invalid installed backend manifest"):
        ActivationTransaction.prepare(paths, PLATFORM, "mihomo", "2.0.0", operation=OPERATION)


def _replace_activation_journal_with_same_content(transaction):
    payload = transaction.journal_path.read_bytes()
    displaced = transaction.journal_path.with_name("displaced-activation-authority")
    transaction.journal_path.rename(displaced)
    transaction.journal_path.write_bytes(payload)
    if os.name == "posix":
        transaction.journal_path.chmod(0o600)
    return displaced


def test_activation_execute_rechecks_exact_journal_authority_before_candidate_creation(tmp_path):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    displaced = _replace_activation_journal_with_same_content(transaction)

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        transaction.execute()

    assert not (paths.bin / "mihomo").exists()
    assert not list(paths.bin.glob("*.candidate"))
    assert displaced.is_file()


def test_activation_execute_rechecks_authority_after_candidate_creation(
    tmp_path,
    monkeypatch,
):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_create = activation_module._create_symlink_candidate
    displaced = []

    def replace_authority_after_candidate(*args, **kwargs):
        identity = original_create(*args, **kwargs)
        displaced.append(_replace_activation_journal_with_same_content(transaction))
        return identity

    monkeypatch.setattr(
        activation_module,
        "_create_symlink_candidate",
        replace_authority_after_candidate,
    )

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        transaction.execute()

    candidate = paths.root / transaction.value["candidates"]["link"]["path"]
    assert candidate.is_symlink()
    assert not (paths.bin / "mihomo").exists()
    assert displaced and displaced[0].is_file()


def test_symlink_candidate_creation_flushes_its_pinned_parent_before_return(
    tmp_path,
    monkeypatch,
):
    paths = _layout(tmp_path)
    value = _journal(paths)
    target = "../backends/mihomo/2.0.0/mihomo"
    events = []
    original_flush = activation_module.flush_descriptor

    def record_flush(descriptor, kind):
        events.append(kind)
        return original_flush(descriptor, kind)

    monkeypatch.setattr("jerryproxy.backend.anchored.flush_descriptor", record_flush)

    activation_module._create_symlink_candidate(paths, value, target)

    assert events == ["anchored symlink parent"]


def test_regular_candidate_creation_flushes_empty_file_and_parent_before_return(
    tmp_path,
    monkeypatch,
):
    paths = _layout(tmp_path)
    candidate = paths.active / ".mihomo.use-candidate.json"
    events = []
    original_flush = activation_module.flush_descriptor

    def record_file_flush(descriptor, kind):
        events.append(("file", kind))
        return original_flush(descriptor, kind)

    def record_parent_flush(anchored):
        events.append(("parent", anchored.root))
        return "flushed"

    monkeypatch.setattr(activation_module, "flush_descriptor", record_file_flush)
    monkeypatch.setattr(
        activation_module.AnchoredDirectory,
        "flush",
        record_parent_flush,
    )

    output, unused_identity = activation_module._open_regular_candidate(candidate)
    output.close()

    assert events == [
        ("file", "empty activation candidate"),
        ("parent", paths.active),
    ]


def test_activation_execute_rechecks_authority_before_publication(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_publish = activation_module._publish_candidate
    displaced = []

    def replace_authority_before_publication(*args, **kwargs):
        if not displaced:
            displaced.append(_replace_activation_journal_with_same_content(transaction))
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(activation_module, "_publish_candidate", replace_authority_before_publication)

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        transaction.execute()

    assert not (paths.bin / "mihomo").exists()
    assert displaced and displaced[0].is_file()


def test_copy_mode_recovery_rebuilds_previous_active_pair(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    journal = _write_journal(paths, value)

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert (paths.bin / "mihomo").read_bytes() == b"previous"
    assert not (paths.bin / "mihomo").is_symlink()
    assert classify_activation(paths, value).manifest == "P"


@pytest.mark.parametrize("change", ("replace", "remove"))
def test_activation_execute_rejects_candidate_change_before_publication(tmp_path, monkeypatch, change):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_write = activation_module._write_manifest_candidate

    def change_link_candidate(*args, **kwargs):
        result = original_write(*args, **kwargs)
        candidate = paths.root / transaction.value["candidates"]["link"]["path"]
        target = os.readlink(str(candidate))
        if change == "replace":
            replacement = candidate.with_name(candidate.name + ".replacement")
            replacement.symlink_to(target)
            os.replace(str(replacement), str(candidate))
        else:
            candidate.unlink()
        return result

    monkeypatch.setattr(activation_module, "_write_manifest_candidate", change_link_candidate)

    with pytest.raises(IntegrityError, match="activation candidate (changed|disappeared) before publication"):
        transaction.execute()

    assert transaction.journal_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative ancestor race fixture requires POSIX")
@pytest.mark.parametrize("area", ("bin", "active"))
def test_activation_candidate_creation_rejects_replaced_managed_ancestor(tmp_path, monkeypatch, area):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    managed = getattr(paths, area)
    displaced = tmp_path / ("displaced-" + area)
    outside = tmp_path / ("outside-" + area)
    outside.mkdir(mode=0o700)
    sentinel_name = "mihomo" if area == "bin" else "mihomo.json"
    sentinel = outside / sentinel_name
    sentinel.write_bytes(b"outside-sentinel")
    swapped = []
    original_symlink = os.symlink
    original_open = os.open

    def replace_ancestor():
        managed.rename(displaced)
        managed.symlink_to(outside, target_is_directory=True)
        swapped.append(True)

    def symlink_after_replacement(source, destination, *args, **kwargs):
        if area == "bin" and ".candidate" in str(destination) and not swapped:
            replace_ancestor()
        return original_symlink(source, destination, *args, **kwargs)

    def open_after_replacement(path, flags, *args, **kwargs):
        if area == "active" and ".candidate.json" in str(path) and not swapped:
            replace_ancestor()
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "symlink", symlink_after_replacement)
    monkeypatch.setattr(os, "open", open_after_replacement)

    with pytest.raises(IntegrityError, match="activation .* ancestor changed"):
        transaction.execute()

    assert swapped == [True]
    assert sentinel.read_bytes() == b"outside-sentinel"
    assert transaction.journal_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative ancestor race fixture requires POSIX")
@pytest.mark.parametrize("area", ("bin", "active"))
def test_activation_publication_rejects_replaced_managed_ancestor(tmp_path, monkeypatch, area):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    managed = getattr(paths, area)
    displaced = tmp_path / ("displaced-publish-" + area)
    outside = tmp_path / ("outside-publish-" + area)
    outside.mkdir(mode=0o700)
    destination_name = "mihomo" if area == "bin" else "mihomo.json"
    sentinel = outside / destination_name
    sentinel.write_bytes(b"outside-sentinel")
    swapped = []
    original_durable_replace = activation_module.durable_replace
    original_replace = os.replace

    def replace_ancestor():
        managed.rename(displaced)
        managed.symlink_to(outside, target_is_directory=True)
        swapped.append(True)

    def pathname_replace_after_replacement(source, destination, *args, **kwargs):
        if Path(destination).name == destination_name and not swapped:
            replace_ancestor()
        return original_durable_replace(source, destination, *args, **kwargs)

    def anchored_replace_after_replacement(source, destination, *args, **kwargs):
        if str(destination) == destination_name and not swapped:
            replace_ancestor()
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(activation_module, "durable_replace", pathname_replace_after_replacement)
    monkeypatch.setattr(os, "replace", anchored_replace_after_replacement)

    with pytest.raises(IntegrityError, match="activation .* ancestor changed"):
        transaction.execute()

    assert swapped == [True]
    assert sentinel.read_bytes() == b"outside-sentinel"
    assert transaction.journal_path.exists()


def test_activation_rejects_same_inode_candidate_content_change_before_publication(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "1.0.0", b"previous")
    _installed(paths, "2.0.0", b"target")
    previous = _logical(paths, "1.0.0", b"previous", "2026-01-01T00:00:00+00:00")
    _publish_link(paths, previous)
    _publish_manifest(paths, previous)
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_write = activation_module._write_manifest_candidate
    candidate_identity = []

    def mutate_ready_manifest(*args, **kwargs):
        result = original_write(*args, **kwargs)
        candidate = paths.root / transaction.value["candidates"]["manifest"]["path"]
        identity = capture_identity(candidate)
        payload = bytearray(candidate.read_bytes())
        payload[0] = ord("!")
        with candidate.open("r+b") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        assert capture_identity(candidate) == identity
        candidate_identity.append(identity)
        return result

    monkeypatch.setattr(activation_module, "_write_manifest_candidate", mutate_ready_manifest)

    with pytest.raises(IntegrityError, match="activation candidate content changed before publication"):
        transaction.execute()

    assert candidate_identity
    assert json.loads((paths.active / "mihomo.json").read_text(encoding="utf-8")) == previous["manifest_payload"]
    assert transaction.journal_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative candidate read requires POSIX")
def test_activation_publication_does_not_reopen_ready_candidate_by_path(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_write = activation_module._write_manifest_candidate
    original_open = Path.open
    armed = []

    def arm_after_manifest_candidate(*args, **kwargs):
        result = original_write(*args, **kwargs)
        armed.append(True)
        return result

    def deny_candidate_path_open(path, *args, **kwargs):
        if armed and path == paths.root / transaction.value["candidates"]["manifest"]["path"]:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(
        activation_module,
        "_write_manifest_candidate",
        arm_after_manifest_candidate,
    )
    monkeypatch.setattr(Path, "open", deny_candidate_path_open)

    active = transaction.execute()

    assert active.version == "2.0.0"
    assert armed == [True]


def test_activation_never_adopts_an_exact_candidate_replacement_after_creation(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "1.0.0", b"previous")
    _installed(paths, "2.0.0", b"target")
    previous = _logical(paths, "1.0.0", b"previous", "2026-01-01T00:00:00+00:00")
    _publish_link(paths, previous)
    _publish_manifest(paths, previous)
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        activated_at="2026-01-02T00:00:00+00:00",
        operation=OPERATION,
    )
    original_create = activation_module.AnchoredDirectory.create_file
    displaced = paths.active / "displaced-candidate"
    replacement_identity = []

    def replace_after_creation(anchored, parts):
        output, identity = original_create(anchored, parts)
        if anchored.root == paths.active and parts[-1].endswith(".candidate.json"):
            candidate = paths.active / parts[-1]
            candidate.rename(displaced)
            payload = (
                json.dumps(
                    transaction.value["target"]["manifest_payload"],
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            candidate.write_bytes(payload)
            if os.name == "posix":
                candidate.chmod(0o600)
            replacement_identity.append(capture_identity(candidate))
        return output, identity

    monkeypatch.setattr(activation_module.AnchoredDirectory, "create_file", replace_after_creation)

    with pytest.raises(IntegrityError, match="activation candidate changed"):
        transaction.execute()

    candidate = paths.root / transaction.value["candidates"]["manifest"]["path"]
    assert replacement_identity
    assert capture_identity(candidate) == replacement_identity[0]
    assert read_json(transaction.journal_path)["candidates"]["manifest"]["identity"] != replacement_identity[0]
    assert json.loads((paths.active / "mihomo.json").read_text(encoding="utf-8")) == previous["manifest_payload"]


def test_recovery_persists_publication_observed_after_ready_journal(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    public = paths.bin / "mihomo"
    _publish_link(paths, value["previous"])
    _publish_manifest(paths, value["previous"])
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "ready",
            "identity": capture_identity(public),
            "target": os.readlink(str(public)),
        }
    )
    journal = _write_journal(paths, value)
    events = []
    original_write = activation_module._write_activation_record

    def record_write(*args, **kwargs):
        events.append("journal")
        return original_write(*args, **kwargs)

    def record_flush(path):
        events.append("flush:%s" % Path(path).name)

    monkeypatch.setattr(activation_module, "_write_activation_record", record_write)
    monkeypatch.setattr(
        activation_module,
        "flush_directory",
        record_flush,
        raising=False,
    )

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert classify_activation(paths, value).link == "P"
    assert "flush:bin" in events
    assert "flush:active" in events
    assert events.index("flush:bin") < events.index("journal")
    assert events.index("flush:active") < events.index("journal")


def test_recovery_retains_ready_authority_when_observed_publication_flush_fails(
    tmp_path,
    monkeypatch,
):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    public = paths.bin / "mihomo"
    _publish_link(paths, value["previous"])
    _publish_manifest(paths, value["previous"])
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "ready",
            "identity": capture_identity(public),
            "target": os.readlink(str(public)),
        }
    )
    journal = _write_journal(paths, value)

    def fail_public_parent(path):
        if Path(path) == paths.bin:
            raise DurabilityError("simulated public parent flush failure")

    monkeypatch.setattr(
        activation_module,
        "flush_directory",
        fail_public_parent,
        raising=False,
    )

    with pytest.raises(DurabilityError, match="public parent flush failure"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    retained = read_json(journal)
    assert retained["recovery"] == {"direction": "rollback-previous"}
    assert retained["candidates"]["link"]["state"] == "ready"


def test_rollback_absent_retries_public_parent_flush_before_any_recovery_mutation(
    tmp_path,
    monkeypatch,
):
    paths = _layout(tmp_path)
    value = _journal(paths, previous=False)
    value["recovery"] = {"direction": "rollback-absent"}
    journal = _write_journal(paths, value)
    publications = []
    original_write = activation_module._write_activation_record

    def record_write(*args, **kwargs):
        publications.append(True)
        return original_write(*args, **kwargs)

    def fail_public_parent(path):
        if Path(path) == paths.bin:
            raise DurabilityError("simulated interrupted public deletion flush")

    monkeypatch.setattr(activation_module, "_write_activation_record", record_write)
    monkeypatch.setattr(activation_module, "flush_directory", fail_public_parent)

    with pytest.raises(DurabilityError, match="interrupted public deletion flush"):
        recover_use_transactions(paths, PLATFORM)

    assert publications == []
    assert journal.exists()
    assert read_json(journal) == value


def test_recovery_rejects_public_object_disappearing_after_delete_plan(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, previous=False)
    value["recovery"] = {"direction": "rollback-absent"}
    public = paths.bin / "mihomo"
    public.write_bytes(b"target")
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery
    removed = []

    def remove_after_planning(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "delete-public" and not removed:
            public.unlink()
            removed.append(True)
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", remove_after_planning)

    with pytest.raises(IntegrityError, match="changed after activation recovery planning"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert not public.exists()


def test_recovery_rechecks_activation_authority_before_public_deletion(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, previous=False)
    value["recovery"] = {"direction": "rollback-absent"}
    public = paths.bin / "mihomo"
    public.write_bytes(b"target")
    journal = _write_journal(paths, value)
    displaced = tmp_path / "displaced-use-journal"
    original_plan = activation_module.plan_activation_recovery
    swapped = []

    def replace_authority_after_planning(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "delete-public" and not swapped:
            journal.rename(displaced)
            journal.write_bytes(displaced.read_bytes())
            if os.name == "posix":
                journal.chmod(0o600)
            swapped.append(journal)
        return plan

    monkeypatch.setattr(
        activation_module,
        "plan_activation_recovery",
        replace_authority_after_planning,
    )

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        recover_use_transactions(paths, PLATFORM)

    assert swapped == [journal]
    assert public.read_bytes() == b"target"
    assert journal.is_file()
    assert displaced.is_file()


def test_recorded_symlink_candidate_with_changed_target_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.symlink_to("../backends/mihomo/2.0.0/mihomo")
    identity = capture_identity(candidate)
    value["candidates"]["link"].update(
        {
            "state": "ready",
            "identity": identity,
            "target": "../different",
        }
    )
    original_matches = activation_module.identity_matches

    def retain_recorded_identity(path, expected):
        if Path(path) == candidate:
            return True
        return original_matches(path, expected)

    monkeypatch.setattr(activation_module, "identity_matches", retain_recorded_identity)

    assert activation_module.classify_candidate(paths, value, "link") == "unknown"


def test_unrecorded_candidate_inspection_failure_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["candidates"]["link"]["state"] = "building"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    original_lstat = Path.lstat

    def deny_candidate_inspection(path, *args, **kwargs):
        if path == candidate:
            raise PermissionError("denied")
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", deny_candidate_inspection)

    assert activation_module.classify_candidate(paths, value, "link") == "unknown"


def test_public_object_appearing_during_missing_classification_becomes_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    public = paths.bin / "mihomo"
    original_classify = activation_module.classify_public_link
    created = []

    def create_during_classification(current_paths, journal):
        if not created:
            public.write_bytes(b"replacement")
            created.append(True)
            return "M"
        return original_classify(current_paths, journal)

    monkeypatch.setattr(activation_module, "classify_public_link", create_during_classification)

    assert classify_activation(paths, value).link == "U"
    assert public.exists()


def test_public_object_identity_change_during_classification_becomes_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    public = paths.bin / "mihomo"
    public.write_bytes(b"unknown")
    original_matches = activation_module.identity_matches

    def report_public_replacement(path, identity):
        if Path(path) == public:
            return False
        return original_matches(path, identity)

    monkeypatch.setattr(activation_module, "identity_matches", report_public_replacement)

    assert classify_activation(paths, value).link == "U"


def test_candidate_identity_change_during_classification_becomes_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["candidates"]["link"]["state"] = "building"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    original_matches = activation_module.identity_matches

    def report_candidate_replacement(path, identity):
        if Path(path) == candidate:
            return False
        return original_matches(path, identity)

    monkeypatch.setattr(activation_module, "identity_matches", report_candidate_replacement)

    assert classify_activation(paths, value).link_candidate == "unknown"


def test_missing_unrecorded_building_candidate_is_cleared_before_repair(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"]["state"] = "building"
    classification = ActivationClassification("M", "M", "missing", "missing")

    plan = plan_activation_recovery(value, classification)

    assert (plan.action, plan.object_name) == ("persist-candidate-absent", "link")
    assert plan.journal["candidates"]["link"] == _absent_candidate(value["candidates"]["link"]["path"])


@pytest.mark.parametrize(
    ("state", "classification", "message"),
    (("ready", "missing", "ready candidate is unknown"),),
)
def test_recovery_planner_rejects_unknown_repair_candidate(state, classification, message, tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": state,
            "identity": _candidate_identity("symlink") if state == "ready" else None,
            "target": "../backends/mihomo/1.0.0/mihomo" if state == "ready" else None,
        }
    )
    physical = ActivationClassification("M", "M", classification, "missing")

    with pytest.raises(IntegrityError, match=message):
        plan_activation_recovery(value, physical)


def test_recovery_planner_deletes_recorded_discarding_repair_candidate(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "discarding",
            "identity": _candidate_identity("symlink"),
            "target": "../backends/mihomo/1.0.0/mihomo",
        }
    )
    classification = ActivationClassification("M", "M", "recorded-owned", "missing")

    plan = plan_activation_recovery(value, classification)

    assert (plan.action, plan.object_name) == ("delete-candidate", "link")


def test_recovery_rejects_delete_plan_without_stable_precondition(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, previous=False)
    value["recovery"] = {"direction": "rollback-absent"}
    public = paths.bin / "mihomo"
    public.write_bytes(b"target")
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery

    def discard_precondition(state, classification):
        plan = original_plan(state, classification)
        if plan.action != "delete-public":
            return plan
        return type(plan)(plan.journal, plan.direction, plan.action, plan.object_name, None)

    monkeypatch.setattr(activation_module, "plan_activation_recovery", discard_precondition)

    with pytest.raises(IntegrityError, match="no stable precondition"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert public.exists()


def test_recovery_replaces_known_target_manifest_with_previous_manifest(tmp_path):
    paths = _layout(tmp_path)
    value = _complete_journal(paths, phase="manifest-published")
    value["recovery"] = {"direction": "rollback-previous"}
    for candidate in value["candidates"].values():
        candidate.update(_absent_candidate(candidate["path"]))
    _publish_link(paths, value["previous"])
    _publish_manifest(paths, value["target"])
    journal = _write_journal(paths, value)

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert classify_activation(paths, value).manifest == "P"


@pytest.mark.parametrize("recorded", (False, True))
def test_copy_recovery_resumes_existing_empty_candidate(tmp_path, recorded):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "building",
            "identity": capture_identity(candidate) if recorded else None,
        }
    )
    journal = _write_journal(paths, value)

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert (paths.bin / "mihomo").read_bytes() == b"previous"


def test_copy_recovery_rejects_candidate_replaced_after_reopen(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "building",
            "identity": capture_identity(candidate),
        }
    )
    journal = _write_journal(paths, value)
    original_open = os.open
    replaced = []

    def replace_after_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == candidate and not replaced:
            replacement = candidate.with_name(candidate.name + ".replacement")
            replacement.write_bytes(b"")
            os.replace(str(replacement), str(candidate))
            replaced.append(capture_identity(candidate))
        return descriptor

    monkeypatch.setattr(os, "open", replace_after_open)

    with pytest.raises(IntegrityError, match="candidate changed while reopening"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert candidate.exists()
    assert capture_identity(candidate) == replaced[0]


def test_activation_prepare_rejects_invalid_operation_identifier(tmp_path):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")

    with pytest.raises(ValueError, match="32 lowercase hexadecimal"):
        ActivationTransaction.prepare(paths, PLATFORM, "mihomo", "2.0.0", operation="INVALID")


def test_recorded_regular_candidate_type_change_classifies_as_unknown(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    candidate = paths.root / value["candidates"]["manifest"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["manifest"].update(
        {
            "state": "ready",
            "identity": capture_identity(candidate),
            "size": 0,
            "sha256": _digest(b""),
        }
    )
    original_matches = activation_module.identity_matches
    original_lstat = Path.lstat

    def retain_recorded_identity(path, identity):
        if Path(path) == candidate:
            return True
        return original_matches(path, identity)

    def report_directory_type(path, *args, **kwargs):
        if path == candidate:
            return original_lstat(paths.active)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(activation_module, "identity_matches", retain_recorded_identity)
    monkeypatch.setattr(Path, "lstat", report_directory_type)

    assert activation_module.classify_candidate(paths, value, "manifest") == "unknown"


def test_nonempty_unrecorded_candidate_classifies_as_unknown(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-building")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["candidates"]["link"]["state"] = "building"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"unowned")

    assert activation_module.classify_candidate(paths, value, "link") == "unknown"


def test_activation_classification_rejects_directory_as_public_command(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    (paths.bin / "mihomo").mkdir()

    classification = classify_activation(paths, value)

    assert classification.link == "U"


def test_activation_recovery_rejects_changed_repair_candidate_purpose(tmp_path):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["candidates"]["link"]["purpose"] = "recovery-target"
    classification = ActivationClassification("M", "M", "missing", "missing")

    with pytest.raises(IntegrityError, match="candidate purpose changed"):
        plan_activation_recovery(value, classification)


def test_activation_prepare_maps_anchored_journal_publication_failure(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")

    def fail_publication(*args, **kwargs):
        raise ArchiveError("simulated activation journal publication failure")

    monkeypatch.setattr(activation_module.AnchoredDirectory, "write_json", fail_publication)

    with pytest.raises(IntegrityError, match="unable to publish anchored activation journal"):
        ActivationTransaction.prepare(
            paths,
            PLATFORM,
            "mihomo",
            "2.0.0",
            operation=OPERATION,
        )


def test_activation_execute_rejects_in_place_journal_content_change(tmp_path):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )
    changed = read_json(transaction.journal_path)
    changed["target"]["executable_sha256"] = "f" * 64
    transaction.journal_path.write_text(json.dumps(changed), encoding="utf-8")
    if os.name == "posix":
        transaction.journal_path.chmod(0o600)

    with pytest.raises(IntegrityError, match="journal changed before recovery action") as error:
        transaction.execute()

    assert "activation journal content changed" in str(error.value.__cause__)


def test_activation_execute_propagates_candidate_durability_failure(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )

    def fail_flush(*args, **kwargs):
        raise DurabilityError("simulated candidate flush failure")

    monkeypatch.setattr(activation_module, "flush_descriptor", fail_flush)

    with pytest.raises(DurabilityError, match="candidate flush failure"):
        transaction.execute()

    assert transaction.journal_path.exists()


def test_activation_execute_rejects_unreadable_ready_candidate_before_publication(
    tmp_path,
    monkeypatch,
):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )
    manifest_candidate = paths.root / transaction.value["candidates"]["manifest"]["path"]
    original_evidence = activation_module.AnchoredDirectory.file_evidence

    def fail_candidate_evidence(anchored, parts, *args, **kwargs):
        if anchored.root == paths.active and parts == (manifest_candidate.name,):
            raise ArchiveError("simulated candidate evidence failure")
        return original_evidence(anchored, parts, *args, **kwargs)

    monkeypatch.setattr(
        activation_module.AnchoredDirectory,
        "file_evidence",
        fail_candidate_evidence,
    )

    with pytest.raises(IntegrityError, match="candidate content changed before publication"):
        transaction.execute()

    assert transaction.journal_path.exists()


def test_durable_replace_supports_cross_directory_publication(tmp_path):
    source_dir = tmp_path / "source"
    destination_dir = tmp_path / "destination"
    source_dir.mkdir()
    destination_dir.mkdir()
    source = source_dir / "candidate"
    destination = destination_dir / "public"
    source.write_bytes(b"payload")

    activation_module.durable_replace(source, destination)

    assert destination.read_bytes() == b"payload"
    assert not source.exists()


def test_activation_execute_rejects_nonempty_unrecorded_manifest_candidate(tmp_path):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )
    candidate = paths.root / transaction.value["candidates"]["manifest"]["path"]
    candidate.write_bytes(b"unowned")

    with pytest.raises(IntegrityError, match="unrecorded activation candidate is not empty"):
        transaction.execute()

    assert candidate.read_bytes() == b"unowned"


def test_activation_execute_closes_candidate_when_identity_publication_fails(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )
    original_publish = transaction._authority.publish
    publications = []

    def fail_candidate_identity_publication(value):
        publications.append(value["phase"])
        if len(publications) == 3:
            raise IntegrityError("simulated candidate identity publication failure")
        return original_publish(value)

    monkeypatch.setattr(transaction._authority, "publish", fail_candidate_identity_publication)

    with pytest.raises(IntegrityError, match="candidate identity publication failure"):
        transaction.execute()

    candidate = paths.root / transaction.value["candidates"]["manifest"]["path"]
    with candidate.open("ab") as stream:
        stream.write(b"closed")


def test_activation_execute_rejects_candidate_write_without_progress(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    _installed(paths, "2.0.0", b"target")
    transaction = ActivationTransaction.prepare(
        paths,
        PLATFORM,
        "mihomo",
        "2.0.0",
        operation=OPERATION,
    )
    original_open = activation_module._open_anchored_regular_candidate

    class NoProgressWriter(object):
        def __init__(self, stream):
            self._stream = stream

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()

        def fileno(self):
            return self._stream.fileno()

        def flush(self):
            return self._stream.flush()

        def close(self):
            return self._stream.close()

        def write(self, payload):
            return 0

    def open_without_progress(selected_paths, value, name):
        stream, identity = original_open(selected_paths, value, name)
        return NoProgressWriter(stream), identity

    monkeypatch.setattr(
        activation_module,
        "_open_anchored_regular_candidate",
        open_without_progress,
    )

    with pytest.raises(IntegrityError, match="write made no valid progress"):
        transaction.execute()

    assert transaction.journal_path.exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="recovery symlink race fixture")
def test_activation_recovery_rejects_wrong_symlink_inserted_before_repair(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    journal = _write_journal(paths, value)
    candidate = paths.root / value["candidates"]["link"]["path"]
    original_plan = activation_module.plan_activation_recovery
    inserted = []

    def insert_before_repair(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "resume-building-candidate" and plan.object_name == "link":
            candidate.symlink_to("wrong-target")
            inserted.append(candidate)
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", insert_before_repair)

    with pytest.raises(IntegrityError, match="unrecorded activation symlink candidate changed"):
        recover_use_transactions(paths, PLATFORM)

    assert inserted == [candidate]
    assert journal.exists()


def test_recovery_rejects_manifest_identity_change_during_action_recheck(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _complete_journal(paths, phase="manifest-published")
    value["recovery"] = {"direction": "rollback-previous"}
    for candidate in value["candidates"].values():
        candidate.update(_absent_candidate(candidate["path"]))
    _publish_link(paths, value["previous"])
    _publish_manifest(paths, value["target"])
    journal = _write_journal(paths, value)
    public = paths.active / "mihomo.json"
    original_plan = activation_module.plan_activation_recovery
    original_matches = activation_module.identity_matches
    armed = []
    calls = []

    def arm_manifest_recheck(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "publish-repair-candidate" and plan.object_name == "manifest":
            armed.append(True)
        return plan

    def change_on_second_recheck(path, identity):
        if armed and Path(path) == public:
            calls.append(True)
            if len(calls) == 2:
                return False
        return original_matches(path, identity)

    monkeypatch.setattr(activation_module, "plan_activation_recovery", arm_manifest_recheck)
    monkeypatch.setattr(activation_module, "identity_matches", change_on_second_recheck)

    with pytest.raises(IntegrityError, match="changed after activation recovery planning"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
    assert classify_activation(paths, value).manifest == "T"


def test_recovery_converges_when_owned_candidate_disappears_after_delete_plan(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths, phase="link-ready")
    value["target"] = _logical(paths, "2.0.0", b"target", "2026-01-02T00:00:00+00:00")
    value["recovery"] = {"direction": "rollback-previous"}
    candidate = paths.root / value["candidates"]["link"]["path"]
    target = paths.root / value["target"]["executable"]
    candidate.symlink_to(os.path.relpath(str(target), str(candidate.parent)))
    value["candidates"]["link"].update(
        {
            "state": "ready",
            "identity": capture_identity(candidate),
            "target": os.readlink(str(candidate)),
        }
    )
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery
    removed = []
    flushed = []

    def remove_after_delete_plan(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "delete-candidate" and plan.object_name == "link" and not removed:
            candidate.unlink()
            removed.append(True)
        return plan

    monkeypatch.setattr(activation_module, "plan_activation_recovery", remove_after_delete_plan)
    monkeypatch.setattr(
        activation_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)),
        raising=False,
    )

    recover_use_transactions(paths, PLATFORM)

    assert not journal.exists()
    assert classify_activation(paths, value).link == "P"
    assert paths.bin in flushed


def test_copy_recovery_rejects_nonregular_reopened_descriptor(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "building",
            "identity": capture_identity(candidate),
        }
    )
    journal = _write_journal(paths, value)
    directory_status = paths.bin.stat()
    original_open = os.open
    original_fstat = os.fstat
    candidate_descriptors = []

    def record_candidate_descriptor(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if Path(path) == candidate or (path == candidate.name and kwargs.get("dir_fd") is not None):
            candidate_descriptors.append(descriptor)
        return descriptor

    def report_directory_descriptor(descriptor):
        if descriptor in candidate_descriptors:
            return directory_status
        return original_fstat(descriptor)

    monkeypatch.setattr(os, "open", record_candidate_descriptor)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        set(os.supports_dir_fd) | {record_candidate_descriptor},
    )
    monkeypatch.setattr(os, "fstat", report_directory_descriptor)

    with pytest.raises(IntegrityError, match="candidate changed while reopening") as error:
        recover_use_transactions(paths, PLATFORM)

    assert isinstance(error.value.__cause__, ArchiveError)
    assert "anchored input is not a stable private regular file" in str(error.value.__cause__)
    assert journal.exists()
    assert candidate.exists()


def test_copy_recovery_reopens_recorded_candidate_only_through_its_anchor(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    candidate = paths.root / value["candidates"]["link"]["path"]
    candidate.write_bytes(b"")
    value["candidates"]["link"].update(
        {
            "purpose": "recovery-previous",
            "state": "building",
            "identity": capture_identity(candidate),
        }
    )
    _write_journal(paths, value)
    original_open = os.open

    def deny_candidate_path_open(path, flags, *args, **kwargs):
        if Path(path) == candidate and kwargs.get("dir_fd") is None:
            raise PermissionError("pathname reopen denied")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_candidate_path_open)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        set(os.supports_dir_fd) | {deny_candidate_path_open},
    )

    recover_use_transactions(paths, PLATFORM)

    assert (paths.bin / "mihomo").read_bytes() == b"previous"


def test_copy_recovery_rejects_source_identity_change_while_opening(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    source = paths.root / value["previous"]["executable"]
    journal = _write_journal(paths, value)
    original_matches = activation_module.identity_matches

    def report_source_change(path, identity):
        if Path(path) == source:
            return False
        return original_matches(path, identity)

    monkeypatch.setattr(activation_module, "identity_matches", report_source_change)

    with pytest.raises(IntegrityError, match="source executable changed while opening"):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()


def test_copy_recovery_does_not_reopen_source_executable_by_path(tmp_path, monkeypatch):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    source = paths.root / value["previous"]["executable"]
    _write_journal(paths, value)
    original_open = Path.open

    def deny_source_path_open(path, *args, **kwargs):
        if path == source:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_source_path_open)

    recover_use_transactions(paths, PLATFORM)

    assert (paths.bin / "mihomo").read_bytes() == b"previous"
    assert not list(paths.runtimes.glob(".use-*"))


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b"prev", "source executable ended during copy"),
        (b"previous+", "source executable grew during copy"),
        (b"changed!", "source executable changed during copy"),
    ),
)
def test_copy_recovery_rejects_source_stream_change(tmp_path, monkeypatch, payload, message):
    paths = _layout(tmp_path)
    value = _journal(paths)
    value["recovery"] = {"direction": "rollback-previous"}
    value["previous"]["link_mode"] = "copy"
    value["previous"]["manifest_payload"]["link_mode"] = "copy"
    source = paths.root / value["previous"]["executable"]
    journal = _write_journal(paths, value)
    original_plan = activation_module.plan_activation_recovery
    original_open = activation_module.AnchoredDirectory.open_existing_file
    armed = []

    def arm_copy(state, classification):
        plan = original_plan(state, classification)
        if plan.action == "resume-building-candidate" and plan.object_name == "link":
            armed.append(True)
        return plan

    def changed_stream(anchored, parts, **kwargs):
        if armed and anchored.root == paths.backends and tuple(parts) == source.relative_to(paths.backends).parts:
            source.write_bytes(payload)
        return original_open(anchored, parts, **kwargs)

    monkeypatch.setattr(activation_module, "plan_activation_recovery", arm_copy)
    monkeypatch.setattr(
        activation_module.AnchoredDirectory,
        "open_existing_file",
        changed_stream,
    )

    with pytest.raises(IntegrityError, match=message):
        recover_use_transactions(paths, PLATFORM)

    assert journal.exists()
