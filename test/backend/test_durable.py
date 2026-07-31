import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import jerryproxy.backend.durable as durable_module
from jerryproxy.backend.durable import (
    FLUSHED,
    UNSUPPORTED,
    durable_replace,
    durable_write_json,
    flush_descriptor,
    flush_directory,
)
from jerryproxy.errors import DurabilityError, IntegrityError
from jerryproxy.utils.fs import read_json


def test_durable_json_publication_flushes_file_then_replaces_then_flushes_parent(tmp_path):
    destination = tmp_path / "journal.json"
    temporary = tmp_path / ".journal.json.tmp-0123456789abcdef0123456789abcdef"
    events = []

    def flush_file(descriptor):
        assert os.fstat(descriptor).st_size > 0
        events.append("file")
        return FLUSHED

    def replace(source, target):
        assert Path(source) == temporary
        assert Path(target) == destination
        events.append("replace")
        os.replace(source, target)

    def flush_directory(path):
        assert Path(path) == tmp_path
        events.append("parent")
        return FLUSHED

    outcomes = durable_write_json(
        destination,
        {"phase": "prepared"},
        temporary,
        flush_file=flush_file,
        replace=replace,
        flush_directory=flush_directory,
    )

    assert events == ["file", "replace", "parent"]
    assert outcomes == (FLUSHED, FLUSHED)
    assert read_json(destination) == {"phase": "prepared"}
    assert not temporary.exists()
    if os.name == "posix":
        assert destination.stat().st_mode & 0o777 == 0o600


def test_durable_json_keeps_new_authoritative_value_visible_when_parent_flush_fails(tmp_path):
    destination = tmp_path / "journal.json"
    temporary = tmp_path / ".journal.json.tmp-0123456789abcdef0123456789abcdef"

    def fail_parent(path):
        raise DurabilityError("directory flush failed")

    with pytest.raises(DurabilityError, match="directory flush failed"):
        durable_write_json(
            destination,
            {"phase": "committed"},
            temporary,
            flush_directory=fail_parent,
        )

    assert read_json(destination) == {"phase": "committed"}
    assert not temporary.exists()


def test_durable_json_rejects_an_existing_writer_temporary_without_touching_it(tmp_path):
    destination = tmp_path / "journal.json"
    temporary = tmp_path / ".journal.json.tmp-0123456789abcdef0123456789abcdef"
    temporary.write_bytes(b"evidence")

    with pytest.raises(FileExistsError):
        durable_write_json(destination, {"phase": "prepared"}, temporary)

    assert temporary.read_bytes() == b"evidence"
    assert not destination.exists()


@pytest.mark.parametrize("unsupported_errno", sorted({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}))
def test_flush_descriptor_classifies_only_documented_unsupported_errors(monkeypatch, unsupported_errno):
    def unsupported(descriptor):
        raise OSError(unsupported_errno, "unsupported")

    monkeypatch.setattr(os, "fsync", unsupported)
    if os.name == "nt":
        with pytest.raises(DurabilityError, match="unable to flush directory"):
            flush_descriptor(7, "directory")
    else:
        assert flush_descriptor(7, "directory") == UNSUPPORTED


def test_windows_regular_file_flush_never_downgrades_crt_errors(monkeypatch):
    def unsupported(descriptor):
        raise OSError(errno.EINVAL, "simulated CRT commit failure")

    monkeypatch.setattr(
        durable_module,
        "os",
        SimpleNamespace(name="nt", fsync=unsupported),
    )

    with pytest.raises(DurabilityError, match="unable to flush regular file"):
        flush_descriptor(7, "regular file")


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows durability primitives")
def test_windows_native_regular_file_flushes_and_directory_flush_is_explicitly_unsupported(tmp_path):
    path = tmp_path / "payload"
    with path.open("wb") as stream:
        stream.write(b"payload")
        stream.flush()
        assert flush_descriptor(stream.fileno(), "regular file") == FLUSHED

    assert path.read_bytes() == b"payload"
    assert flush_directory(tmp_path) == UNSUPPORTED


@pytest.mark.windows_native
@pytest.mark.skipif(os.name != "nt", reason="native Windows durable JSON publication")
def test_windows_native_durable_json_remains_visible_when_parent_flush_is_unsupported(tmp_path):
    destination = tmp_path / "journal.json"
    temporary = tmp_path / ".journal.json.tmp-0123456789abcdef0123456789abcdef"

    outcomes = durable_write_json(destination, {"phase": "committed"}, temporary)

    assert outcomes == (FLUSHED, UNSUPPORTED)
    assert read_json(destination) == {"phase": "committed"}
    assert not temporary.exists()


@pytest.mark.parametrize("failure_errno", [errno.EACCES, errno.ENOSPC, errno.EROFS, errno.EIO])
def test_flush_descriptor_does_not_downgrade_real_io_failures(monkeypatch, failure_errno):
    def fail(descriptor):
        raise OSError(failure_errno, "failed")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(DurabilityError, match="unable to flush directory"):
        flush_descriptor(7, "directory")


def test_durable_replace_flushes_both_parents_for_a_cross_directory_move(tmp_path):
    source_parent = tmp_path / "source"
    destination_parent = tmp_path / "destination"
    source_parent.mkdir()
    destination_parent.mkdir()
    source = source_parent / "candidate"
    destination = destination_parent / "public"
    source.write_bytes(b"payload")
    flushed = []

    outcomes = durable_replace(
        source,
        destination,
        flush_directory=lambda path: flushed.append(Path(path)) or FLUSHED,
    )

    assert destination.read_bytes() == b"payload"
    assert not source.exists()
    assert flushed == [source_parent, destination_parent]
    assert outcomes == (FLUSHED, FLUSHED)


def test_durable_replace_flushes_one_parent_once_for_an_adjacent_replace(tmp_path):
    source = tmp_path / "candidate"
    destination = tmp_path / "public"
    source.write_bytes(b"payload")
    flushed = []

    outcomes = durable_replace(
        source,
        destination,
        flush_directory=lambda path: flushed.append(Path(path)) or UNSUPPORTED,
    )

    assert destination.read_bytes() == b"payload"
    assert flushed == [tmp_path]
    assert outcomes == (UNSUPPORTED,)


def test_flush_directory_rejects_alias_without_touching_target(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrityError, match="must not be an alias"):
        flush_directory(alias)

    assert outside.is_dir()


@pytest.mark.parametrize(
    ("failure_errno", "expected"),
    (
        (errno.EINVAL, UNSUPPORTED),
        (errno.EACCES, DurabilityError),
    ),
)
def test_flush_directory_classifies_open_failures(
    tmp_path,
    monkeypatch,
    failure_errno,
    expected,
):
    def fail_open(path, flags):
        raise OSError(failure_errno, "simulated directory open failure")

    monkeypatch.setattr(durable_module.os, "open", fail_open)
    if expected == UNSUPPORTED:
        assert flush_directory(tmp_path) == UNSUPPORTED
    else:
        with pytest.raises(DurabilityError, match="unable to open directory"):
            flush_directory(tmp_path)


def test_flush_directory_rejects_a_non_directory_pinned_descriptor(tmp_path, monkeypatch):
    regular = tmp_path / "regular"
    regular.write_bytes(b"payload")
    original_fstat = durable_module.os.fstat

    def regular_status(descriptor):
        del descriptor
        return regular.stat()

    monkeypatch.setattr(durable_module.os, "fstat", regular_status)
    with pytest.raises(IntegrityError, match="not a directory"):
        flush_directory(tmp_path)
    monkeypatch.setattr(durable_module.os, "fstat", original_fstat)


def test_durable_json_rejects_a_nonadjacent_temporary(tmp_path):
    other = tmp_path / "other"
    other.mkdir()

    with pytest.raises(ValueError, match="must be adjacent"):
        durable_write_json(
            tmp_path / "journal.json",
            {"phase": "prepared"},
            other / "temporary",
        )


def test_durable_json_fdopen_failure_closes_and_removes_temporary(tmp_path, monkeypatch):
    temporary = tmp_path / ".journal.json.tmp"
    descriptors = []
    original_open = durable_module.os.open
    original_close = durable_module.os.close

    def record_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def fail_fdopen(descriptor, mode):
        del descriptor, mode
        raise OSError("simulated fdopen failure")

    monkeypatch.setattr(durable_module.os, "open", record_open)
    monkeypatch.setattr(durable_module.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(durable_module.os, "close", original_close)

    with pytest.raises(OSError, match="fdopen failure"):
        durable_write_json(tmp_path / "journal.json", {}, temporary)

    assert descriptors
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert not temporary.exists()
