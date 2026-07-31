from pathlib import Path

import pytest

import jerryproxy.backend.removal as removal_module
from jerryproxy.backend.identity import capture_identity
from jerryproxy.backend.removal import (
    RemovalRecoveryRecord,
    preflight_removal_record,
    recover_removal_record,
)
from jerryproxy.errors import IntegrityError
from jerryproxy.home import JerryProxyPaths


def _record(transaction, phase, temporary_evidence=()):
    return RemovalRecoveryRecord(
        kind="remove",
        operation="a" * 32,
        transaction=Path(transaction),
        phase=phase,
        moves=(),
        read_paths=(),
        write_paths=(),
        transaction_identity=capture_identity(transaction),
        journal_identity=None,
        journal_value=None,
        temporary_evidence=temporary_evidence,
    )


@pytest.mark.parametrize("operation", (preflight_removal_record, recover_removal_record))
def test_public_removal_record_boundaries_reject_unparsed_values(tmp_path, operation):
    paths = JerryProxyPaths(tmp_path / "home")

    with pytest.raises(IntegrityError, match="invalid preflighted removal record"):
        if operation is recover_removal_record:
            operation(paths, object())
        else:
            operation(paths, object())


def test_terminal_removal_recovery_fails_if_transaction_disappears_before_disposal(
    tmp_path,
    monkeypatch,
):
    paths = JerryProxyPaths(tmp_path / "home")
    transaction = paths.runtimes / (".remove-" + "a" * 32)
    transaction.mkdir(parents=True)
    record = _record(transaction, "terminal")
    monkeypatch.setattr(
        removal_module,
        "_secure_remove_empty_directory",
        lambda *args, **kwargs: False,
    )

    with pytest.raises(IntegrityError, match="transaction disappeared before disposal"):
        recover_removal_record(paths, record)


def test_initial_writer_recovery_fails_if_transaction_disappears_before_disposal(
    tmp_path,
    monkeypatch,
):
    paths = JerryProxyPaths(tmp_path / "home")
    transaction = paths.runtimes / (".remove-" + "b" * 32)
    transaction.mkdir(parents=True)
    temporary = transaction / (".journal.json.tmp-" + "c" * 32)
    temporary.write_bytes(b"writer evidence")
    record = _record(
        transaction,
        "initial-temporary",
        ((temporary, capture_identity(temporary)),),
    )
    monkeypatch.setattr(
        removal_module,
        "_secure_remove_empty_directory",
        lambda *args, **kwargs: False,
    )

    with pytest.raises(IntegrityError, match="transaction disappeared before disposal"):
        recover_removal_record(paths, record)

    assert not temporary.exists()


def test_initial_writer_preflight_rejects_unrecorded_transaction_content(tmp_path):
    paths = JerryProxyPaths(tmp_path / "home")
    transaction = paths.runtimes / (".remove-" + "d" * 32)
    transaction.mkdir(parents=True)
    temporary = transaction / (".journal.json.tmp-" + "e" * 32)
    temporary.write_bytes(b"writer evidence")
    (transaction / "unexpected").write_bytes(b"unowned")
    record = _record(
        transaction,
        "initial-temporary",
        ((temporary, capture_identity(temporary)),),
    )

    with pytest.raises(IntegrityError, match="has no authoritative journal"):
        preflight_removal_record(paths, record)
