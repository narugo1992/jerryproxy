import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import jerryproxy.backend.installation as installation_module
from jerryproxy.backend.identity import capture_identity
from jerryproxy.backend.installation import (
    InstallTransaction,
    preflight_install_record,
    preflight_install_recovery,
    recover_install_transactions,
    recovery_path_sets_conflict,
)
from jerryproxy.backend.recovery import recover_backend_transactions
from jerryproxy.errors import ArchiveError, DurabilityError, IntegrityError
from jerryproxy.home import JerryProxyPaths

OPERATION = "0123456789abcdef0123456789abcdef"
WRITE_ID = "fedcba9876543210fedcba9876543210"
DIGEST = "a" * 64
POSIX_FAULT_INJECTION = pytest.mark.skipif(
    os.name == "nt",
    reason="requires replacing filesystem objects while POSIX descriptors remain open",
)


def _paths(tmp_path):
    paths = JerryProxyPaths(tmp_path / "home")
    for path in (paths.root, paths.backends, paths.runtimes):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return paths


def _artifact():
    return {
        "sha256": DIGEST,
        "size": 123,
        "asset_name": "Xray-linux-64.zip",
        "platform": "linux-amd64",
    }


def _publication(executable="xray"):
    return {
        "manifest_sha256": "b" * 64,
        "executable": executable,
        "executable_sha256": "c" * 64,
        "executable_size": 7,
    }


def _record(phase="prepared", identity=None, publication=None):
    return {
        "kind": "install",
        "operation": OPERATION,
        "phase": phase,
        "backend": "xray",
        "version": "1.2.3",
        "staging": "backends/xray/.1.2.3.install-%s" % OPERATION,
        "final": "backends/xray/1.2.3",
        "tree_identity": identity,
        "artifact": _artifact(),
        "publication": publication,
    }


def _write_journal(paths, value):
    journal = paths.runtimes / (".install-%s.json" % OPERATION)
    journal.write_text(json.dumps(value), encoding="utf-8")
    if os.name == "posix":
        journal.chmod(0o600)
    return journal


def _canonical_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _make_valid_tree(paths):
    final = paths.backends / "xray" / "1.2.3"
    final.mkdir(parents=True)
    publication = _populate_valid_tree(final)
    return final, publication


def _populate_valid_tree(directory):
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory / "xray"
    executable.write_bytes(b"payload")
    manifest_value = {
        "name": "xray",
        "version": "1.2.3",
        "platform": "linux-amd64",
        "asset_name": "Xray-linux-64.zip",
        "sha256": DIGEST,
        "executable_sha256": hashlib.sha256(b"payload").hexdigest(),
        "source_url": None,
        "catalog_generated_at": "2026-01-01T00:00:00Z",
        "executable": "xray",
        "installed_at": "2026-01-01T00:00:00+00:00",
    }
    manifest_bytes = _canonical_json(manifest_value)
    (directory / "manifest.json").write_bytes(manifest_bytes)
    if os.name == "posix":
        (directory / "manifest.json").chmod(0o600)
    publication = {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "executable": "xray",
        "executable_sha256": hashlib.sha256(b"payload").hexdigest(),
        "executable_size": 7,
    }
    return publication


def test_transaction_publishes_exact_prepared_journal_and_exposes_sets(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )

    assert json.loads(transaction.journal.read_text(encoding="utf-8")) == _record()
    assert transaction.read_set == frozenset(("runtimes/.install-%s.json" % OPERATION,))
    assert transaction.write_set == frozenset(
        (
            "runtimes/.install-%s.json" % OPERATION,
            "backends/xray/.1.2.3.install-%s" % OPERATION,
            "backends/xray/1.2.3",
        )
    )
    assert not (paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))).exists()


def test_transaction_phase_transitions_record_identity_and_publication(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    extracting = json.loads(transaction.journal.read_text(encoding="utf-8"))
    assert extracting["phase"] == "extracting"
    assert extracting["tree_identity"] == capture_identity(staging)

    publication = _publication()
    transaction.mark_validated(publication)
    validated = json.loads(transaction.journal.read_text(encoding="utf-8"))
    assert validated["phase"] == "validated"
    assert validated["publication"] == publication


def test_install_journal_transitions_use_one_anchored_identity_chain(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    original_write = installation_module.AnchoredDirectory.write_json
    publications = []

    def record_write(anchored, parts, value, temporary_parts, *args, **kwargs):
        result = original_write(anchored, parts, value, temporary_parts, *args, **kwargs)
        if anchored.root == paths.runtimes:
            publications.append((dict(kwargs), result[1]))
        return result

    monkeypatch.setattr(installation_module.AnchoredDirectory, "write_json", record_write)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    transaction.begin_staging()

    assert len(publications) == 2
    assert publications[0][0].get("replace_existing", False) is False
    assert publications[0][0].get("expected_destination_identity") is None
    assert publications[1][0]["replace_existing"] is True
    assert publications[1][0]["expected_destination_identity"] == publications[0][1]


def test_transaction_commits_exact_validated_tree_and_disposes_journal(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)
    transaction.mark_validated(publication)

    final = transaction.commit()

    assert final == paths.backends / "xray" / "1.2.3"
    assert (final / "xray").read_bytes() == b"payload"
    assert not transaction.journal.exists()
    assert not staging.exists()


@POSIX_FAULT_INJECTION
def test_install_recovery_rejects_final_executable_replacement_during_fixed_handle_read(
    tmp_path,
    monkeypatch,
):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    value = _record("committed", capture_identity(final), publication)
    journal = _write_journal(paths, value)
    executable = final / "xray"
    displaced = final / "xray.displaced"
    replacement = final / "xray.replacement"
    replacement.write_bytes(executable.read_bytes())
    original_open = installation_module.AnchoredDirectory.open_existing_file
    replaced = []

    def replace_after_open(anchored, parts, **kwargs):
        stream, identity = original_open(anchored, parts, **kwargs)
        if anchored.root == final and parts == ("xray",) and not replaced:
            executable.rename(displaced)
            replacement.rename(executable)
            replaced.append(executable)
        return stream, identity

    monkeypatch.setattr(
        installation_module.AnchoredDirectory,
        "open_existing_file",
        replace_after_open,
    )

    with pytest.raises(IntegrityError, match="invalid recovered installation"):
        recover_install_transactions(paths)

    assert replaced == [executable]
    assert executable.read_bytes() == displaced.read_bytes()
    assert journal.is_file()


@pytest.mark.parametrize("missing", sorted(_record()))
def test_preflight_rejects_every_missing_top_level_key(tmp_path, missing):
    paths = _paths(tmp_path)
    value = _record()
    del value[missing]
    _write_journal(paths, value)
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(kind="use"),
        lambda value: value.update(operation="f" * 32),
        lambda value: value.update(backend="XRAY"),
        lambda value: value.update(version="v1.2.3"),
        lambda value: value.update(staging="backends/xray/wrong"),
        lambda value: value.update(final="backends/xray/wrong"),
        lambda value: value.update(phase="publishing"),
    ],
)
def test_preflight_rejects_noncanonical_or_mismatched_record(tmp_path, mutation):
    paths = _paths(tmp_path)
    value = _record()
    mutation(value)
    _write_journal(paths, value)
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "phase,identity,publication,valid",
    [
        ("prepared", None, None, True),
        ("prepared", {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}, None, False),
        ("extracting", {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}, None, True),
        ("extracting", None, None, False),
        ("validated", {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}, _publication(), True),
        ("validated", {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}, None, False),
        ("committed", {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}, _publication(), True),
        ("committed", None, _publication(), False),
    ],
)
def test_phase_matrix_is_exact(tmp_path, phase, identity, publication, valid):
    paths = _paths(tmp_path)
    _write_journal(paths, _record(phase, identity, publication))
    if valid:
        assert preflight_install_recovery(paths)[0].phase == phase
    else:
        with pytest.raises(IntegrityError):
            preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "A" * 64),
        ("sha256", "a" * 63),
        ("size", True),
        ("size", -1),
        ("size", 256 * 1024 * 1024 + 1),
        ("asset_name", "../asset.zip"),
        ("platform", "unknown-platform"),
    ],
)
def test_artifact_evidence_is_strict(tmp_path, field, value):
    paths = _paths(tmp_path)
    record = _record()
    record["artifact"][field] = value
    _write_journal(paths, record)
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "artifact",
    (
        [],
        {**_artifact(), "extra": True},
    ),
)
def test_artifact_evidence_requires_exact_object_shape(tmp_path, artifact):
    paths = _paths(tmp_path)
    value = _record()
    value["artifact"] = artifact
    _write_journal(paths, value)

    with pytest.raises(IntegrityError, match="invalid install journal artifact"):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_sha256", "B" * 64),
        ("executable_sha256", "c" * 63),
        ("executable_size", True),
        ("executable_size", 512 * 1024 * 1024 + 1),
        ("executable", "../xray"),
        ("executable", "C:\\xray.exe"),
    ],
)
def test_publication_evidence_is_strict(tmp_path, field, value):
    paths = _paths(tmp_path)
    identity = {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}
    publication = _publication()
    publication[field] = value
    _write_journal(paths, _record("validated", identity, publication))
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "publication",
    (
        [],
        {**_publication(), "extra": True},
    ),
)
def test_publication_evidence_requires_exact_object_shape(tmp_path, publication):
    paths = _paths(tmp_path)
    identity = {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}
    _write_journal(paths, _record("validated", identity, publication))

    with pytest.raises(IntegrityError, match="invalid install journal publication"):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("backend", "unknown"),
        ("version", "../bad"),
    ),
)
def test_install_journal_maps_registry_normalization_failures(tmp_path, field, value):
    paths = _paths(tmp_path)
    record = _record()
    record[field] = value
    _write_journal(paths, record)

    with pytest.raises(IntegrityError, match="invalid install journal backend or version"):
        preflight_install_recovery(paths)


def test_extracting_install_journal_rejects_premature_publication(tmp_path):
    paths = _paths(tmp_path)
    identity = {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}
    _write_journal(paths, _record("extracting", identity, _publication()))

    with pytest.raises(IntegrityError, match="premature install publication"):
        preflight_install_recovery(paths)


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"kind":"install","kind":"use"}',
        b'{"size":NaN}',
        b'{"size":1.5}',
        b"{",
        b"\xff",
    ],
)
def test_journal_reader_rejects_malformed_strict_json(tmp_path, payload):
    paths = _paths(tmp_path)
    journal = paths.runtimes / (".install-%s.json" % OPERATION)
    journal.write_bytes(payload)
    if os.name == "posix":
        journal.chmod(0o600)
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)


def test_journal_reader_rejects_alias_directory_and_unsafe_permissions(tmp_path):
    paths = _paths(tmp_path)
    journal = paths.runtimes / (".install-%s.json" % OPERATION)
    journal.symlink_to("missing")
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)
    journal.unlink()
    journal.mkdir()
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)
    journal.rmdir()
    _write_journal(paths, _record())
    if os.name == "posix":
        journal.chmod(0o644)
        with pytest.raises(IntegrityError):
            preflight_install_recovery(paths)


def test_writer_temporary_never_overrides_authoritative_phase(tmp_path):
    paths = _paths(tmp_path)
    _write_journal(paths, _record())
    temporary = paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))
    temporary.write_text(json.dumps(_record("committed", None, _publication())), encoding="utf-8")
    if os.name == "posix":
        temporary.chmod(0o600)

    item = preflight_install_recovery(paths)[0]
    assert item.phase == "prepared"
    assert item.temporaries == (temporary,)


def test_orphan_writer_temporary_is_removed_only_without_owned_staging(tmp_path):
    paths = _paths(tmp_path)
    temporary = paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))
    temporary.write_bytes(b"partial")
    if os.name == "posix":
        temporary.chmod(0o600)

    assert preflight_install_recovery(paths) == ()
    assert temporary.exists()
    recover_install_transactions(paths)
    assert not temporary.exists()

    temporary.write_bytes(b"partial")
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)
    assert temporary.exists()
    assert staging.exists()


def test_preflight_rejects_alias_and_oversized_writer_temporary(tmp_path):
    paths = _paths(tmp_path)
    _write_journal(paths, _record())
    temporary = paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))
    temporary.symlink_to("missing")
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)

    temporary.unlink()
    temporary.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(IntegrityError):
        preflight_install_recovery(paths)


def test_install_recovery_accepts_a_completely_absent_namespace(tmp_path):
    paths = JerryProxyPaths(tmp_path / "absent")

    assert preflight_install_recovery(paths) == ()


def test_install_recovery_rejects_unknown_runtime_and_staging_names(tmp_path):
    paths = _paths(tmp_path)
    unknown_runtime = paths.runtimes / (".install-" + "bad")
    unknown_runtime.write_bytes(b"evidence")
    with pytest.raises(IntegrityError, match="unknown install recovery entry"):
        preflight_install_recovery(paths)
    unknown_runtime.unlink()

    malformed_root = paths.backends / ("bad.install-" + OPERATION)
    malformed_root.write_bytes(b"evidence")
    with pytest.raises(IntegrityError, match="invalid install staging namespace"):
        preflight_install_recovery(paths)
    malformed_root.unlink()

    backend = paths.backends / "xray"
    backend.mkdir()
    malformed_staging = backend / (".install-" + OPERATION)
    malformed_staging.mkdir()
    with pytest.raises(IntegrityError, match="invalid install staging name"):
        preflight_install_recovery(paths)


def test_install_recovery_rejects_unexpected_and_unauthorized_staging(tmp_path):
    paths = _paths(tmp_path)
    backend = paths.backends / "xray"
    backend.mkdir()
    unexpected = backend / (".9.9.9.install-" + OPERATION)
    unexpected.mkdir()
    _write_journal(paths, _record())

    with pytest.raises(IntegrityError, match="unexpected install staging object"):
        preflight_install_recovery(paths)

    (paths.runtimes / (".install-%s.json" % OPERATION)).unlink()
    with pytest.raises(IntegrityError, match="no authoritative journal"):
        preflight_install_recovery(paths)


def test_prepared_recovery_removes_exact_empty_staging_and_journal(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    _write_journal(paths, _record())
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    flushed = []
    monkeypatch.setattr("jerryproxy.backend.installation.flush_directory", lambda path: flushed.append(Path(path)))

    recover_install_transactions(paths)

    assert not staging.exists()
    assert not any(paths.runtimes.iterdir())
    assert staging.parent in flushed
    assert paths.runtimes in flushed


def test_prepared_recovery_rejects_nonempty_or_aliased_staging_without_mutation(tmp_path):
    paths = _paths(tmp_path)
    journal = _write_journal(paths, _record())
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    sentinel = staging / "sentinel"
    sentinel.write_bytes(b"keep")

    with pytest.raises(IntegrityError):
        recover_install_transactions(paths)
    assert journal.exists()
    assert sentinel.read_bytes() == b"keep"


def test_extracting_recovery_requires_recorded_identity_and_is_idempotent(tmp_path):
    paths = _paths(tmp_path)
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    (staging / "partial").write_bytes(b"partial")
    identity = capture_identity(staging)
    _write_journal(paths, _record("extracting", identity, None))

    recover_install_transactions(paths)
    assert not staging.exists()
    assert not any(paths.runtimes.iterdir())

    _write_journal(paths, _record("extracting", identity, None))
    recover_install_transactions(paths)
    assert not any(paths.runtimes.iterdir())


@pytest.mark.parametrize("phase", ("extracting", "validated"))
def test_absent_staging_recovery_flushes_its_parent_before_disposing_authority(
    tmp_path,
    monkeypatch,
    phase,
):
    paths = _paths(tmp_path)
    backend_parent = paths.backends / "xray"
    backend_parent.mkdir()
    identity = {
        "kind": "posix",
        "device": 1,
        "inode": 2,
        "file_type": "directory",
    }
    publication = _publication() if phase == "validated" else None
    _write_journal(paths, _record(phase, identity, publication))
    flushed = []
    monkeypatch.setattr(
        installation_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)),
    )

    recover_install_transactions(paths)

    assert flushed[0] == backend_parent
    assert paths.runtimes in flushed


def test_recovery_does_not_delete_staging_replacement_after_classification(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    (staging / "partial").write_bytes(b"partial")
    identity = capture_identity(staging)
    journal = _write_journal(paths, _record("extracting", identity, None))
    displaced = staging.with_name(staging.name + ".displaced")
    original_remove = installation_module._secure_remove_tree

    def replace_before_delete(root, target, error_type, *args, **kwargs):
        if Path(target) == staging and not displaced.exists():
            staging.rename(displaced)
            staging.mkdir()
            (staging / "replacement").write_bytes(b"keep")
        return original_remove(root, target, error_type, *args, **kwargs)

    monkeypatch.setattr(installation_module, "_secure_remove_tree", replace_before_delete)
    with pytest.raises(IntegrityError, match="identity"):
        recover_install_transactions(paths)

    assert journal.exists()
    assert (staging / "replacement").read_bytes() == b"keep"
    assert (displaced / "partial").read_bytes() == b"partial"


def test_recovery_rechecks_install_authority_before_staging_deletion(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    partial = staging / "partial"
    partial.write_bytes(b"must survive")
    identity = capture_identity(staging)
    journal = _write_journal(paths, _record("extracting", identity, None))
    displaced = journal.with_name(journal.name + ".displaced")
    original_remove = installation_module._remove_staging
    swapped = []

    def replace_authority_before_delete(record, expected_identity):
        if not swapped:
            journal.rename(displaced)
            journal.write_bytes(displaced.read_bytes())
            if os.name == "posix":
                journal.chmod(0o600)
            swapped.append(journal)
        return original_remove(record, expected_identity)

    monkeypatch.setattr(installation_module, "_remove_staging", replace_authority_before_delete)

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        recover_install_transactions(paths)

    assert swapped == [journal]
    assert partial.read_bytes() == b"must survive"
    assert journal.is_file()
    assert displaced.is_file()


def test_validated_recovery_accepts_exact_renamed_final_and_advances_committed(tmp_path):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    _write_journal(paths, _record("validated", identity, publication))

    recover_install_transactions(paths)

    assert final.exists()
    assert not any(paths.runtimes.iterdir())


def test_validated_renamed_final_recovery_flushes_parent_before_disposing_authority(
    tmp_path,
    monkeypatch,
):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    _write_journal(paths, _record("validated", identity, publication))
    flushed = []
    monkeypatch.setattr(
        installation_module,
        "flush_directory",
        lambda path: flushed.append(Path(path)),
    )

    recover_install_transactions(paths)

    assert flushed[0] == final.parent
    assert paths.runtimes in flushed


def test_validated_renamed_final_recovery_retains_authority_when_parent_flush_fails(
    tmp_path,
    monkeypatch,
):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    journal = _write_journal(paths, _record("validated", identity, publication))

    def fail_parent(path):
        if Path(path) == final.parent:
            raise DurabilityError("simulated final parent flush failure")

    monkeypatch.setattr(installation_module, "flush_directory", fail_parent)

    with pytest.raises(DurabilityError, match="final parent flush failure"):
        recover_install_transactions(paths)

    assert json.loads(journal.read_text(encoding="utf-8"))["phase"] == "validated"
    assert final.is_dir()


def test_committed_recovery_accepts_exact_final_and_is_idempotent(tmp_path):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    _write_journal(paths, _record("committed", identity, publication))
    recover_install_transactions(paths)
    assert final.exists()
    assert not any(paths.runtimes.iterdir())


@POSIX_FAULT_INJECTION
def test_recovery_retains_authority_when_final_tree_changes_during_validation(
    tmp_path,
    monkeypatch,
):
    paths = _paths(tmp_path)
    paths.bin.mkdir(mode=0o700)
    paths.active.mkdir(mode=0o700)
    final, publication = _make_valid_tree(paths)
    recorded_identity = capture_identity(final)
    journal = _write_journal(paths, _record("committed", recorded_identity, publication))
    displaced = final.with_name("1.2.3.displaced")
    original_load = installation_module.load_installed_manifest
    calls = []

    def replace_during_second_validation(*args, **kwargs):
        installed = original_load(*args, **kwargs)
        calls.append(True)
        if len(calls) == 2:
            final.rename(displaced)
            _populate_valid_tree(final)
        return installed

    monkeypatch.setattr(
        installation_module,
        "load_installed_manifest",
        replace_during_second_validation,
    )

    with pytest.raises(IntegrityError, match="invalid recovered installation") as error:
        recover_backend_transactions(paths)

    assert "root changed during extraction" in str(error.value.__cause__)

    assert journal.exists()
    assert capture_identity(final) != recorded_identity
    assert (final / "xray").read_bytes() == b"payload"
    assert (displaced / "xray").read_bytes() == b"payload"


def test_impossible_phase_objects_fail_closed(tmp_path):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    journal = _write_journal(paths, _record("committed", identity, publication))
    for child in final.iterdir():
        child.unlink()
    final.rmdir()
    with pytest.raises(IntegrityError):
        recover_install_transactions(paths)
    assert journal.exists()

    journal.unlink()
    final, publication = _make_valid_tree(paths)
    _write_journal(paths, _record("extracting", capture_identity(final), None))
    with pytest.raises(IntegrityError):
        recover_install_transactions(paths)
    assert final.exists()


@pytest.mark.parametrize("phase", ["validated", "committed"])
def test_final_publication_digest_or_identity_mismatch_fails_closed(tmp_path, phase):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    publication["executable_sha256"] = "d" * 64
    journal = _write_journal(paths, _record(phase, identity, publication))

    with pytest.raises(IntegrityError):
        recover_install_transactions(paths)
    assert journal.exists()
    assert final.exists()


def test_validated_staging_and_final_both_present_is_unknown_evidence(tmp_path):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir()
    _write_journal(paths, _record("validated", identity, publication))
    with pytest.raises(IntegrityError):
        recover_install_transactions(paths)
    assert staging.exists() and final.exists()


def test_recovery_preflights_all_records_before_first_mutation(tmp_path):
    paths = _paths(tmp_path)
    first_operation = "0" * 32
    first = _record()
    first["operation"] = first_operation
    first["staging"] = "backends/xray/.1.2.3.install-%s" % first_operation
    first_journal = paths.runtimes / (".install-%s.json" % first_operation)
    first_journal.write_text(json.dumps(first), encoding="utf-8")
    if os.name == "posix":
        first_journal.chmod(0o600)
    bad = _record()
    bad["extra"] = True
    second_journal = _write_journal(paths, bad)

    with pytest.raises(IntegrityError):
        recover_install_transactions(paths)
    assert first_journal.exists()
    assert second_journal.exists()


def test_preflight_rejects_two_operations_writing_the_same_final_path(tmp_path):
    paths = _paths(tmp_path)
    journals = []
    for operation in ("0" * 32, "1" * 32):
        value = _record()
        value["operation"] = operation
        value["staging"] = "backends/xray/.1.2.3.install-%s" % operation
        journal = paths.runtimes / (".install-%s.json" % operation)
        journal.write_text(json.dumps(value), encoding="utf-8")
        if os.name == "posix":
            journal.chmod(0o600)
        journals.append(journal)

    with pytest.raises(IntegrityError, match="conflicting install recovery records"):
        recover_install_transactions(paths)
    assert all(journal.exists() for journal in journals)


def test_transaction_rejects_wrong_phase_existing_final_and_replaced_staging(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    with pytest.raises(IntegrityError, match="not validated"):
        transaction.commit()
    with pytest.raises(IntegrityError, match="changed before validation"):
        transaction.mark_validated(_publication())
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)
    transaction.mark_validated(publication)
    staging.rename(staging.with_name("displaced"))
    staging.mkdir()
    with pytest.raises(IntegrityError, match="changed before publication"):
        transaction.commit()


def test_prepare_rejects_existing_journal(tmp_path):
    paths = _paths(tmp_path)
    _write_journal(paths, _record())
    with pytest.raises(IntegrityError, match="already exists"):
        InstallTransaction.prepare(paths, "xray", "1.2.3", _artifact(), operation=OPERATION)


@pytest.mark.parametrize("target_kind", ["temporary", "journal"])
def test_recovery_never_deletes_replaced_install_record_evidence(
    tmp_path,
    monkeypatch,
    target_kind,
):
    paths = _paths(tmp_path)
    journal = _write_journal(paths, _record())
    temporary = paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))
    temporary.write_bytes(b"partial")
    if os.name == "posix":
        temporary.chmod(0o600)
    target = temporary if target_kind == "temporary" else journal
    displaced = target.with_name(target.name + ".displaced")
    original_remove = installation_module._secure_remove_tree
    swapped = []

    def replace_before_delete(root, selected, error_type, *args, **kwargs):
        if Path(selected) == target and not swapped:
            target.rename(displaced)
            if target_kind == "temporary":
                target.write_bytes(b"replacement")
            else:
                target.write_text(json.dumps(_record()), encoding="utf-8")
            if os.name == "posix":
                target.chmod(0o600)
            swapped.append(target)
        return original_remove(root, selected, error_type, *args, **kwargs)

    monkeypatch.setattr(installation_module, "_secure_remove_tree", replace_before_delete)

    with pytest.raises(IntegrityError, match="identity"):
        recover_install_transactions(paths)

    assert target.exists()
    assert displaced.exists()
    if target_kind == "temporary":
        assert target.read_bytes() == b"replacement"
        assert journal.exists()


@pytest.mark.parametrize("operation", ("short", "A" * 32, 123))
def test_install_prepare_rejects_invalid_operation_ids(tmp_path, operation):
    paths = _paths(tmp_path)
    with pytest.raises(IntegrityError, match="invalid install operation ID"):
        InstallTransaction.prepare(paths, "xray", "1.2.3", _artifact(), operation=operation)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("backend", ""),
        ("backend", "x" * 65),
        ("version", "v" * 129),
    ),
)
def test_install_journal_rejects_empty_and_oversized_strings(tmp_path, field, value):
    paths = _paths(tmp_path)
    record = _record()
    record[field] = value
    _write_journal(paths, record)

    with pytest.raises(IntegrityError, match="invalid install journal"):
        preflight_install_recovery(paths)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="recovery namespace alias fixture")
@pytest.mark.parametrize("area", ("runtimes", "backends"))
def test_install_recovery_rejects_aliased_managed_namespaces(tmp_path, area):
    paths = _paths(tmp_path)
    selected = getattr(paths, area)
    outside = tmp_path / ("outside-" + area)
    outside.mkdir()
    selected.rmdir()
    selected.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="invalid install"):
        preflight_install_recovery(paths)


@pytest.mark.parametrize("area", ("runtimes", "backends"))
def test_install_recovery_rejects_non_directory_managed_namespaces(tmp_path, area):
    paths = _paths(tmp_path)
    selected = getattr(paths, area)
    selected.rmdir()
    selected.write_bytes(b"not a directory")

    with pytest.raises(IntegrityError, match="invalid install"):
        preflight_install_recovery(paths)


def test_install_recovery_rejects_existing_runtimes_when_backends_is_absent(tmp_path):
    paths = _paths(tmp_path)
    paths.backends.rmdir()

    with pytest.raises(IntegrityError, match="invalid install staging namespace"):
        preflight_install_recovery(paths)


def test_install_recovery_ignores_unrelated_runtime_and_backend_entries(tmp_path):
    paths = _paths(tmp_path)
    (paths.runtimes / "provider.json").write_text("{}", encoding="utf-8")
    (paths.backends / "notes.txt").write_text("not managed", encoding="utf-8")

    assert preflight_install_recovery(paths) == ()


def test_orphan_temporary_with_owned_staging_fails_at_authority_boundary(tmp_path):
    paths = _paths(tmp_path)
    temporary = paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))
    temporary.write_bytes(b"partial")
    if os.name == "posix":
        temporary.chmod(0o600)
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)

    with pytest.raises(IntegrityError, match="owned staging without authority"):
        preflight_install_recovery(paths)


def test_install_temporary_observation_failure_is_an_integrity_error(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    temporary = paths.runtimes / (".install-%s.json.tmp-%s" % (OPERATION, WRITE_ID))
    temporary.write_bytes(b"partial")
    if os.name == "posix":
        temporary.chmod(0o600)
    original_lstat = Path.lstat

    def deny_temporary(path):
        if path == temporary:
            raise PermissionError("simulated temporary observation denial")
        return original_lstat(path)

    monkeypatch.setattr(installation_module, "is_path_alias", lambda path: False)
    monkeypatch.setattr(Path, "lstat", deny_temporary)
    with pytest.raises(IntegrityError, match="unable to inspect install journal temporary"):
        preflight_install_recovery(paths)


@pytest.mark.parametrize("kind", ("regular", "alias"))
def test_prepared_install_recovery_rejects_non_directory_staging(tmp_path, kind):
    paths = _paths(tmp_path)
    _write_journal(paths, _record())
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.parent.mkdir()
    if kind == "regular":
        staging.write_bytes(b"replacement")
    else:
        outside = tmp_path / "outside-staging"
        outside.mkdir()
        staging.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="unknown prepared install recovery evidence"):
        recover_install_transactions(paths)


def test_prepared_staging_enumeration_failure_preserves_authority(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    journal = _write_journal(paths, _record())
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    original_iterdir = Path.iterdir

    def deny_staging(path):
        if path == staging:
            raise PermissionError("simulated staging enumeration denial")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", deny_staging)
    with pytest.raises(IntegrityError, match="unable to inspect prepared install staging"):
        recover_install_transactions(paths)
    assert journal.exists()
    assert staging.exists()


def test_prepared_staging_inspection_failure_preserves_authority(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    journal = _write_journal(paths, _record())
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    original_lstat = Path.lstat

    def deny_staging(path):
        if path == staging:
            raise PermissionError("simulated staging inspection denial")
        return original_lstat(path)

    monkeypatch.setattr(installation_module, "is_path_alias", lambda path: False)
    monkeypatch.setattr(Path, "lstat", deny_staging)
    with pytest.raises(IntegrityError, match="unable to inspect install staging"):
        recover_install_transactions(paths)
    assert journal.exists()


def test_prepared_staging_identity_change_after_enumeration_is_unknown(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    journal = _write_journal(paths, _record())
    staging = paths.backends / "xray" / (".1.2.3.install-%s" % OPERATION)
    staging.mkdir(parents=True)
    original_matches = installation_module.identity_matches

    def reject_staging(path, identity):
        if Path(path) == staging:
            return False
        return original_matches(path, identity)

    monkeypatch.setattr(installation_module, "identity_matches", reject_staging)
    with pytest.raises(IntegrityError, match="unknown prepared install recovery evidence"):
        recover_install_transactions(paths)
    assert journal.exists()
    assert staging.exists()


def test_nonconflicting_install_records_preflight_together(tmp_path):
    paths = _paths(tmp_path)
    for operation, version in (("0" * 32, "1.2.3"), ("1" * 32, "1.2.4")):
        value = _record()
        value["operation"] = operation
        value["version"] = version
        value["staging"] = "backends/xray/.%s.install-%s" % (version, operation)
        value["final"] = "backends/xray/%s" % version
        journal = paths.runtimes / (".install-%s.json" % operation)
        journal.write_text(json.dumps(value), encoding="utf-8")
        if os.name == "posix":
            journal.chmod(0o600)

    assert len(preflight_install_recovery(paths)) == 2


def test_install_recovery_read_sets_do_not_conflict_without_a_writer():
    first = SimpleNamespace(read_set=frozenset(("runtimes/shared",)), write_set=frozenset())
    second = SimpleNamespace(read_set=frozenset(("runtimes/shared",)), write_set=frozenset())

    assert recovery_path_sets_conflict(first, second) is False


def test_install_recovery_maps_a_malformed_final_tree_and_preserves_journal(tmp_path):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    journal = _write_journal(paths, _record("committed", identity, publication))
    (final / "manifest.json").write_bytes(b"not json")

    with pytest.raises(IntegrityError, match="invalid recovered installation"):
        recover_install_transactions(paths)
    assert journal.exists()
    assert final.exists()


def test_install_recovery_rejects_a_final_tree_alias_without_following_it(tmp_path):
    paths = _paths(tmp_path)
    final = paths.backends / "xray" / "1.2.3"
    outside = tmp_path / "outside-final"
    outside.mkdir()
    final.parent.mkdir()
    final.symlink_to(outside, target_is_directory=True)
    identity = {"kind": "posix", "device": 1, "inode": 2, "file_type": "directory"}
    journal = _write_journal(paths, _record("committed", identity, _publication()))

    with pytest.raises(IntegrityError, match="unknown install recovery evidence"):
        recover_install_transactions(paths)
    assert journal.exists()
    assert final.is_symlink()


def test_install_recovery_rechecks_final_identity_before_authority_disposal(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    journal = _write_journal(paths, _record("validated", identity, publication))
    displaced = final.with_name("1.2.3.displaced")
    original_advance = installation_module._advance_committed

    def replace_after_commit_mark(record):
        original_advance(record)
        final.rename(displaced)
        _populate_valid_tree(final)

    monkeypatch.setattr(installation_module, "_advance_committed", replace_after_commit_mark)
    with pytest.raises(IntegrityError, match="changed before authority disposal"):
        recover_install_transactions(paths)
    assert journal.exists()
    assert final.exists()
    assert displaced.exists()


def test_install_recovery_rejects_final_identity_change_after_static_validation(
    tmp_path,
    monkeypatch,
):
    paths = _paths(tmp_path)
    final, publication = _make_valid_tree(paths)
    identity = capture_identity(final)
    journal = _write_journal(paths, _record("committed", identity, publication))
    original_matches = installation_module.identity_matches
    final_checks = []

    def change_after_validation(path, expected):
        if Path(path) == final:
            final_checks.append(Path(path))
            if len(final_checks) == 2:
                return False
        return original_matches(path, expected)

    monkeypatch.setattr(installation_module, "identity_matches", change_after_validation)

    with pytest.raises(IntegrityError, match="installed tree changed during validation"):
        recover_install_transactions(paths)

    assert journal.exists()


def test_install_record_preflight_rejects_non_record_values(tmp_path):
    with pytest.raises(IntegrityError, match="invalid install recovery record"):
        preflight_install_record(object())


def test_install_journal_preflight_does_not_reopen_authority_by_path(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    journal = _write_journal(paths, _record())
    original_open = Path.open

    def deny_journal_path_open(path, *args, **kwargs):
        if path == journal:
            raise PermissionError("pathname reopen denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_journal_path_open)

    records = preflight_install_recovery(paths)

    assert len(records) == 1
    assert records[0].journal == journal


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="backend staging parent alias fixture")
def test_install_staging_rejects_an_aliased_backend_parent(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    outside = tmp_path / "outside-backend"
    outside.mkdir()
    transaction.staging.parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="anchored backend staging"):
        transaction.begin_staging()
    assert transaction.journal.exists()
    assert not any(outside.iterdir())


def test_install_begin_staging_rechecks_exact_journal_authority(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    payload = transaction.journal.read_bytes()
    displaced = transaction.journal.with_name(transaction.journal.name + ".displaced")
    transaction.journal.rename(displaced)
    transaction.journal.write_bytes(payload)
    if os.name == "posix":
        transaction.journal.chmod(0o600)

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        transaction.begin_staging()

    assert not transaction.staging.exists()
    assert transaction.journal.read_bytes() == payload
    assert displaced.read_bytes() == payload


@pytest.mark.skipif(os.name != "posix", reason="POSIX staging ancestor replacement fixture")
def test_install_staging_never_creates_through_a_replaced_backend_parent(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    backend_parent = transaction.staging.parent
    displaced = tmp_path / "displaced-xray"
    outside = tmp_path / "outside-xray"
    outside.mkdir(mode=0o700)
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"outside")
    original_mkdir = os.mkdir
    replaced = []

    def replace_before_staging(path, *args, **kwargs):
        if path == transaction.staging.name and kwargs.get("dir_fd") is not None and not replaced:
            backend_parent.rename(displaced)
            backend_parent.symlink_to(outside, target_is_directory=True)
            replaced.append(True)
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", replace_before_staging)
    monkeypatch.setattr(os, "supports_dir_fd", set(os.supports_dir_fd) | {replace_before_staging})

    with pytest.raises(IntegrityError):
        transaction.begin_staging()

    assert replaced == [True]
    assert sentinel.read_bytes() == b"outside"
    assert not (outside / transaction.staging.name).exists()
    assert transaction.journal.exists()


def test_install_commit_rejects_an_existing_final_without_mutation(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    transaction.mark_validated(_populate_valid_tree(staging))
    transaction.final.mkdir()

    with pytest.raises(IntegrityError, match="destination already exists"):
        transaction.commit()
    assert transaction.journal.exists()
    assert staging.exists()


def test_install_mark_validated_rechecks_exact_journal_authority(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)
    payload = transaction.journal.read_bytes()
    displaced = transaction.journal.with_name(transaction.journal.name + ".displaced")
    transaction.journal.rename(displaced)
    transaction.journal.write_bytes(payload)
    if os.name == "posix":
        transaction.journal.chmod(0o600)

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        transaction.mark_validated(publication)

    assert transaction.phase == "extracting"
    assert staging.is_dir()
    assert transaction.journal.read_bytes() == payload


def test_install_mark_validated_flushes_complete_staging_tree_before_phase_publication(
    tmp_path,
    monkeypatch,
):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)
    events = []
    original_write = installation_module._write_record

    def record_flush_tree(anchored):
        events.append(("flush-tree", anchored.root))
        return ("flushed",)

    def record_write(record):
        events.append(("journal", record.phase))
        return original_write(record)

    monkeypatch.setattr(
        installation_module.AnchoredDirectory,
        "flush_tree",
        record_flush_tree,
        raising=False,
    )
    monkeypatch.setattr(installation_module, "_write_record", record_write)

    with installation_module.AnchoredDirectory(
        staging,
        expected_identity=transaction.value["tree_identity"],
    ) as staging_anchor:
        transaction.mark_validated(publication, staging_anchor=staging_anchor)

    assert events[:2] == [("flush-tree", staging), ("journal", "validated")]


def test_install_commit_rechecks_exact_journal_authority_before_publication(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    transaction.mark_validated(_populate_valid_tree(staging))
    payload = transaction.journal.read_bytes()
    displaced = transaction.journal.with_name(transaction.journal.name + ".displaced")
    transaction.journal.rename(displaced)
    transaction.journal.write_bytes(payload)
    if os.name == "posix":
        transaction.journal.chmod(0o600)

    with pytest.raises(IntegrityError, match="journal changed before recovery action"):
        transaction.commit()

    assert staging.is_dir()
    assert not transaction.final.exists()
    assert transaction.journal.read_bytes() == payload


def test_install_commit_never_replaces_a_final_created_during_publication(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    transaction.mark_validated(_populate_valid_tree(staging))
    original_replace = installation_module.AnchoredDirectory.replace
    injected_identity = []

    def create_final_before_publication(anchored, source_parts, destination_parts, *args, **kwargs):
        transaction.final.mkdir(mode=0o700)
        injected_identity.append(capture_identity(transaction.final))
        return original_replace(anchored, source_parts, destination_parts, *args, **kwargs)

    monkeypatch.setattr(installation_module.AnchoredDirectory, "replace", create_final_before_publication)

    with pytest.raises(IntegrityError, match="destination already exists"):
        transaction.commit()

    assert injected_identity
    assert capture_identity(transaction.final) == injected_identity[0]
    assert staging.exists()
    assert transaction.journal.exists()


def test_install_commit_retains_journal_when_published_tree_fails_static_validation(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths, "xray", "1.2.3", _artifact(), operation=OPERATION, write_id=lambda: WRITE_ID
    )
    staging = transaction.begin_staging()
    transaction.mark_validated(_populate_valid_tree(staging))
    monkeypatch.setattr(installation_module, "_verify_final", lambda record: "unknown")

    with pytest.raises(IntegrityError, match="failed static validation"):
        transaction.commit()
    assert transaction.journal.exists()
    assert transaction.final.exists()


def test_install_prepare_maps_anchored_journal_publication_failure(tmp_path, monkeypatch):
    paths = _paths(tmp_path)

    def fail_publication(*args, **kwargs):
        raise ArchiveError("simulated anchored publication failure")

    monkeypatch.setattr(installation_module.AnchoredDirectory, "write_json", fail_publication)

    with pytest.raises(IntegrityError, match="unable to publish anchored install journal"):
        InstallTransaction.prepare(
            paths,
            "xray",
            "1.2.3",
            _artifact(),
            operation=OPERATION,
            write_id=lambda: WRITE_ID,
        )


def test_install_transition_rejects_in_place_journal_content_change(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    changed = json.loads(transaction.journal.read_text(encoding="utf-8"))
    changed["artifact"]["sha256"] = "f" * 64
    transaction.journal.write_text(json.dumps(changed), encoding="utf-8")
    if os.name == "posix":
        transaction.journal.chmod(0o600)

    with pytest.raises(IntegrityError, match="journal changed before recovery action") as error:
        transaction.begin_staging()

    assert "install journal content changed" in str(error.value.__cause__)


def test_install_mark_validated_rejects_changed_staging_identity(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)
    original_matches = installation_module.identity_matches

    def reject_staging(path, identity):
        if Path(path) == staging:
            return False
        return original_matches(path, identity)

    monkeypatch.setattr(installation_module, "identity_matches", reject_staging)

    with pytest.raises(IntegrityError, match="staging changed before validation"):
        transaction.mark_validated(publication)

    assert transaction.journal.exists()


def test_install_mark_validated_maps_owned_tree_flush_failure(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)

    def fail_flush(anchored):
        raise ArchiveError("simulated staging flush failure")

    monkeypatch.setattr(installation_module.AnchoredDirectory, "flush_tree", fail_flush)

    with pytest.raises(IntegrityError, match="staging changed before validation"):
        transaction.mark_validated(publication)

    assert transaction.phase == "extracting"


def test_install_mark_validated_rejects_unrelated_staging_anchor(tmp_path):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)

    with installation_module.AnchoredDirectory(paths.backends) as wrong_anchor:
        with pytest.raises(IntegrityError, match="anchor does not match"):
            transaction.mark_validated(publication, staging_anchor=wrong_anchor)


def test_install_mark_validated_maps_supplied_anchor_flush_failure(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    staging = transaction.begin_staging()
    publication = _populate_valid_tree(staging)

    def fail_flush(anchored):
        raise ArchiveError("simulated supplied-anchor flush failure")

    monkeypatch.setattr(installation_module.AnchoredDirectory, "flush_tree", fail_flush)

    with installation_module.AnchoredDirectory(
        staging,
        expected_identity=transaction.value["tree_identity"],
    ) as staging_anchor:
        with pytest.raises(IntegrityError, match="staging changed before validation"):
            transaction.mark_validated(publication, staging_anchor=staging_anchor)


def test_install_commit_maps_nonconflict_anchored_publication_failure(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    transaction = InstallTransaction.prepare(
        paths,
        "xray",
        "1.2.3",
        _artifact(),
        operation=OPERATION,
        write_id=lambda: WRITE_ID,
    )
    staging = transaction.begin_staging()
    transaction.mark_validated(_populate_valid_tree(staging))

    def fail_replace(*args, **kwargs):
        raise ArchiveError("simulated anchored rename failure")

    monkeypatch.setattr(installation_module.AnchoredDirectory, "replace", fail_replace)

    with pytest.raises(IntegrityError, match="unable to publish anchored immutable installation"):
        transaction.commit()

    assert staging.exists()
    assert transaction.journal.exists()
