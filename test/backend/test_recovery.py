import os

import pytest

from jerryproxy.backend import removal as removal_module
from jerryproxy.backend.activation import ActivationTransaction
from jerryproxy.backend.installation import InstallTransaction
from jerryproxy.backend.recovery import recover_backend_transactions
from jerryproxy.errors import IntegrityError, RemovalCleanupError
from jerryproxy.utils.fs import atomic_write_json

from .test_manager import install_fake_mihomo, manager_for


def _active_bytes(manager):
    manifest = manager.paths.active / "mihomo.json"
    link = manager.paths.bin / "mihomo"
    return manifest.read_bytes(), link.read_bytes(), os.readlink(str(link))


def _initialize_recovery_namespaces(manager):
    for path in (
        manager.paths.root,
        manager.paths.backends,
        manager.paths.bin,
        manager.paths.active,
        manager.paths.runtimes,
    ):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)


def test_invalid_later_record_blocks_all_recovery_mutation(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    before = _active_bytes(manager)
    use = ActivationTransaction.prepare(
        manager.paths,
        manager.platform_info,
        "mihomo",
        "2.0.0",
        operation="1" * 32,
    )
    removal = manager.paths.runtimes / (".remove-%s" % ("2" * 32))
    removal.mkdir(mode=0o700)
    atomic_write_json(removal / "journal.json", {"invalid": True})

    with pytest.raises(IntegrityError, match="invalid removal transaction journal"):
        manager.current("mihomo")

    assert use.journal_path.exists()
    assert (removal / "journal.json").exists()
    assert _active_bytes(manager) == before


def test_cross_kind_read_write_conflict_blocks_all_recovery_mutation(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    installed = install_fake_mihomo(
        manager,
        tmp_path,
        "2.0.0",
        b"target",
        activate=False,
    )
    before = _active_bytes(manager)
    use = ActivationTransaction.prepare(
        manager.paths,
        manager.platform_info,
        "mihomo",
        "2.0.0",
        operation="1" * 32,
    )
    removal = manager.paths.runtimes / (".remove-%s" % ("2" * 32))
    removal.mkdir(mode=0o700)
    destination = removal / "installed-0"
    move = removal_module._removal_move(
        manager.paths,
        installed.manifest.parent,
        destination,
        "installed",
    )
    removal_module._write_removal_journal(removal, [move])

    with pytest.raises(IntegrityError, match="conflicting backend recovery records"):
        manager.current("mihomo")

    assert use.journal_path.exists()
    assert (removal / "journal.json").exists()
    assert installed.manifest.is_file()
    assert _active_bytes(manager) == before


def test_later_impossible_physical_record_blocks_earlier_recovery_mutation(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "1.0.0", b"previous", activate=True)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    before = _active_bytes(manager)
    use = ActivationTransaction.prepare(
        manager.paths,
        manager.platform_info,
        "mihomo",
        "2.0.0",
        operation="1" * 32,
    )
    install = InstallTransaction.prepare(
        manager.paths,
        "xray",
        "1.2.3",
        {
            "sha256": "a" * 64,
            "size": 1,
            "asset_name": "Xray-linux-64.zip",
            "platform": "linux-amd64",
        },
        operation="2" * 32,
    )
    install.value.update(
        {
            "phase": "committed",
            "tree_identity": {
                "kind": "posix",
                "device": 1,
                "inode": 2,
                "file_type": "directory",
            },
            "publication": {
                "manifest_sha256": "b" * 64,
                "executable": "xray",
                "executable_sha256": "c" * 64,
                "executable_size": 1,
            },
        }
    )
    atomic_write_json(install.journal, install.value)

    with pytest.raises(IntegrityError, match="unknown install recovery evidence"):
        manager.current("mihomo")

    assert use.journal_path.exists()
    assert install.journal.exists()
    assert _active_bytes(manager) == before


def test_coordinator_recovers_prepared_activation_to_absent_state(tmp_path):
    manager = manager_for(tmp_path)
    install_fake_mihomo(manager, tmp_path, "2.0.0", b"target", activate=False)
    transaction = ActivationTransaction.prepare(
        manager.paths,
        manager.platform_info,
        "mihomo",
        "2.0.0",
        operation="1" * 32,
    )

    recover_backend_transactions(manager.paths, manager.platform_info)

    assert not transaction.journal_path.exists()
    assert manager.current("mihomo") is None


def test_coordinator_disposes_prepared_install_authority(tmp_path):
    manager = manager_for(tmp_path)
    _initialize_recovery_namespaces(manager)
    artifact = {
        "sha256": "a" * 64,
        "size": 1,
        "asset_name": "Xray-linux-64.zip",
        "platform": "linux-amd64",
    }
    transaction = InstallTransaction.prepare(
        manager.paths,
        "xray",
        "1.2.3",
        artifact,
        operation="2" * 32,
    )

    recover_backend_transactions(manager.paths, manager.platform_info)

    assert not transaction.journal.exists()


def test_coordinator_disposes_orphan_install_writer_temporary(tmp_path):
    manager = manager_for(tmp_path)
    _initialize_recovery_namespaces(manager)
    temporary = manager.paths.runtimes / (".install-%s.json.tmp-%s" % ("2" * 32, "3" * 32))
    temporary.write_bytes(b"temporary")
    if os.name == "posix":
        temporary.chmod(0o600)

    recover_backend_transactions(manager.paths, manager.platform_info)

    assert not temporary.exists()


def test_coordinator_disposes_orphan_use_writer_temporary(tmp_path):
    manager = manager_for(tmp_path)
    _initialize_recovery_namespaces(manager)
    temporary = manager.paths.runtimes / (".use-%s.json.tmp-%s" % ("2" * 32, "3" * 32))
    temporary.write_bytes(b"temporary")
    if os.name == "posix":
        temporary.chmod(0o600)

    recover_backend_transactions(manager.paths, manager.platform_info)

    assert not temporary.exists()


def test_coordinator_finishes_committed_removal_after_cleanup_failure(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    installed = install_fake_mihomo(manager, tmp_path, "1.0.0", b"backend", activate=True)

    def fail_quarantine_cleanup(paths, transaction, platform_info=None, record=None):
        raise PermissionError("simulated quarantine cleanup failure")

    with monkeypatch.context() as context:
        context.setattr(removal_module, "_dispose_removal_transaction", fail_quarantine_cleanup)
        with pytest.raises(RemovalCleanupError, match="removal committed"):
            manager.uninstall("mihomo", "1.0.0", deactivate=True)

    transactions = list(manager.paths.runtimes.glob(".remove-*"))
    assert len(transactions) == 1
    assert not installed.manifest.parent.exists()

    recover_backend_transactions(manager.paths, manager.platform_info)

    assert not transactions[0].exists()
    assert manager.current("mihomo") is None
