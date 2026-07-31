import os
import stat

import pytest

import jerryproxy.backend.anchored as anchored_module
from jerryproxy.backend.anchored import AnchoredDirectory
from jerryproxy.errors import ArchiveError, IntegrityError

pytestmark = pytest.mark.unittest


def _write_private(path, payload=b"data"):
    path.write_bytes(payload)
    path.chmod(0o600)


@pytest.mark.parametrize(
    "parts",
    [(), ("",), (".",), ("..",), ("a/b",), ("a\\b",), (1,)],
)
def test_identity_rejects_invalid_relative_paths(tmp_path, parts):
    with AnchoredDirectory(tmp_path / "root") as anchored:
        with pytest.raises(ArchiveError, match="invalid anchored relative path"):
            anchored.identity(parts)


def test_enter_rejects_invalid_expected_identity(tmp_path):
    with pytest.raises(ArchiveError, match="invalid expected archive output root identity"):
        with AnchoredDirectory(tmp_path / "root", expected_identity={"kind": "invalid"}):
            pass


def test_enter_rejects_expected_identity_validation_error(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    identity = anchored_module.capture_identity(root)

    def fail_identity(path, expected):
        raise IntegrityError("identity unavailable")

    monkeypatch.setattr(anchored_module, "identity_matches", fail_identity)
    with pytest.raises(ArchiveError, match="unable to verify archive output root identity"):
        with AnchoredDirectory(root, expected_identity=identity):
            pass


def test_enter_rejects_wrong_expected_identity(tmp_path):
    root = tmp_path / "root"
    other = tmp_path / "other"
    root.mkdir()
    other.mkdir()
    identity = anchored_module.capture_identity(other)

    with pytest.raises(ArchiveError, match="root identity does not match"):
        with AnchoredDirectory(root, expected_identity=identity):
            pass


def test_enter_rejects_expected_identity_changed_after_pinning(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    identity = anchored_module.capture_identity(root)
    calls = {"count": 0}

    def change_after_first_check(path, expected):
        calls["count"] += 1
        return calls["count"] == 1

    monkeypatch.setattr(anchored_module, "identity_matches", change_after_first_check)
    with pytest.raises(ArchiveError, match="root changed while being pinned"):
        with AnchoredDirectory(root, expected_identity=identity):
            pass


def test_identity_reports_missing_entry_as_archive_error(tmp_path):
    with AnchoredDirectory(tmp_path / "root") as anchored:
        with pytest.raises(ArchiveError, match="unable to identify anchored entry"):
            anchored.identity(("missing",))


def test_identity_reports_unsupported_fifo_type(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.mkfifo(str(root / "pipe"))

    with AnchoredDirectory(root) as anchored:
        assert anchored.identity(("pipe",))["file_type"] == "unsupported"


def test_create_symlink_rejects_empty_target(tmp_path):
    with AnchoredDirectory(tmp_path / "root") as anchored:
        with pytest.raises(ArchiveError, match="invalid anchored symlink target"):
            anchored.create_symlink(("link",), "")


def test_create_symlink_rejects_existing_destination(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").write_text("occupied")

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unable to create anchored symlink"):
            anchored.create_symlink(("link",), "target")


def test_replace_uses_tracked_creation_identity(tmp_path):
    root = tmp_path / "root"
    with AnchoredDirectory(root) as anchored:
        stream, unused_identity = anchored.create_file(("candidate",))
        stream.close()
        anchored.replace(("candidate",), ("published",))

    assert (root / "published").is_file()


def test_replace_rejects_identity_disagreeing_with_tracked_creation(tmp_path):
    root = tmp_path / "root"
    with AnchoredDirectory(root) as anchored:
        stream, unused_identity = anchored.create_file(("candidate",))
        stream.close()
        with pytest.raises(ArchiveError, match="disagrees with tracked creation"):
            anchored.replace(
                ("candidate",),
                ("published",),
                expected_identity={
                    "kind": "posix",
                    "device": 1,
                    "inode": 2,
                    "file_type": "regular",
                },
            )


@pytest.mark.parametrize(
    "keyword, message",
    [
        ("expected_identity", "invalid anchored replacement identity"),
        ("expected_destination_identity", "invalid anchored replacement destination identity"),
    ],
)
def test_replace_rejects_invalid_identity_contracts(tmp_path, keyword, message):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")

    with AnchoredDirectory(root) as anchored:
        arguments = {keyword: {"kind": "invalid"}}
        with pytest.raises(ArchiveError, match=message):
            anchored.replace(("candidate",), ("published",), **arguments)


def test_replace_rejects_destination_identity_for_no_replace(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")
    _write_private(root / "published")
    identity = anchored_module.capture_identity(root / "published")

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="no-replace publication cannot expect"):
            anchored.replace(
                ("candidate",),
                ("published",),
                replace_existing=False,
                expected_destination_identity=identity,
            )


def test_replace_rejects_changed_destination_identity(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")
    _write_private(root / "published")
    identity = anchored_module.capture_identity(root / "published")
    (root / "published").rename(tmp_path / "original-published")
    _write_private(root / "published", b"replacement")

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="destination identity changed"):
            anchored.replace(
                ("candidate",),
                ("published",),
                expected_destination_identity=identity,
            )


def test_replace_maps_publication_oserror(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")

    def fail_replace(*args, **kwargs):
        raise OSError("rename failed")

    monkeypatch.setattr(anchored_module.os, "replace", fail_replace)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unable to publish anchored entry"):
            anchored.replace(("candidate",), ("published",))


def test_replace_rejects_published_identity_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")
    original_stat = anchored_module.os.stat
    calls = {"published": 0}

    def changed_after_publish(path, *args, **kwargs):
        status = original_stat(path, *args, **kwargs)
        if path == "published":
            calls["published"] += 1
            values = list(status)
            values[1] += 1
            return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.os, "stat", changed_after_publish)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="published a different entry"):
            anchored.replace(("candidate",), ("published",))


def test_create_directory_rejects_existing_entry(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "existing").mkdir()

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="anchored directory already exists"):
            anchored.create_directory(("existing",))


def test_create_file_rejects_existing_alias(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.symlink("target", str(root / "existing"))

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="archive output file already exists"):
            anchored.create_file(("existing",))


def test_open_existing_file_rejects_changed_expected_identity(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    identity = anchored_module.capture_identity(target)
    target.rename(tmp_path / "original-state")
    _write_private(target, b"replacement")

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="identity changed before opening"):
            anchored.open_existing_file(("state",), expected_identity=identity)


def test_open_existing_file_rejects_hard_link(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    os.link(str(target), str(root / "alias"))

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="stable private regular file"):
            anchored.open_existing_file(("state",))


def test_file_evidence_rejects_wrong_expected_identity_after_read(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    identity = anchored_module.capture_identity(target)
    different = dict(identity)
    different["inode"] += 1
    original_open = AnchoredDirectory.open_existing_file

    def ignore_expected(anchored, parts, expected_identity=None):
        return original_open(anchored, parts)

    monkeypatch.setattr(AnchoredDirectory, "open_existing_file", ignore_expected)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="identity changed while being read"):
            anchored.file_evidence(("state",), expected_identity=different)


def test_read_json_rejects_unsafe_permissions(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state.json"
    target.write_text("{}")
    target.chmod(0o644)

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unsafe permissions"):
            anchored.read_json(("state.json",))


def test_read_json_rejects_authority_changed_after_read(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state.json"
    _write_private(target, b"{}")
    identity = anchored_module.capture_identity(target)
    original_matches = anchored_module.identity_matches
    calls = {"count": 0}

    def fail_final_authority(path, expected):
        calls["count"] += 1
        if calls["count"] == 3:
            return False
        return original_matches(path, expected)

    monkeypatch.setattr(anchored_module, "identity_matches", fail_final_authority)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="authority changed while being read"):
            anchored.read_json(("state.json",), expected_identity=identity)


@pytest.mark.parametrize(
    "destination, temporary, replace_existing, expected, message",
    [
        (("state.json",), ("tmp", "state.json"), False, None, "temporary must be adjacent"),
        (("state.json",), ("tmp.json",), True, None, "replacement requires the exact destination identity"),
    ],
)
def test_write_json_rejects_invalid_publication_contract(
    tmp_path,
    destination,
    temporary,
    replace_existing,
    expected,
    message,
):
    with AnchoredDirectory(tmp_path / "root") as anchored:
        with pytest.raises(ArchiveError, match=message):
            anchored.write_json(
                destination,
                {},
                temporary,
                replace_existing=replace_existing,
                expected_destination_identity=expected,
            )


def test_validate_rejects_fifo_as_special_object(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.mkfifo(str(root / "pipe"))

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="alias or special object"):
            anchored.validate({})


def test_prepare_executable_rejects_hard_linked_candidate(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    executable = root / "backend"
    _write_private(executable)
    os.link(str(executable), str(root / "alias"))

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="alias or special object"):
            anchored.prepare_executable("backend")


def test_prepare_executable_rejects_existing_normalized_destination(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "backend")
    _write_private(root / "normalized")

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="destination already exists"):
            anchored.prepare_executable("backend", "normalized")


def test_prepare_executable_rejects_mode_normalization_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    executable = root / "backend"
    _write_private(executable)
    original_stat = anchored_module.os.stat

    def unsafe_selected(path, *args, **kwargs):
        status = original_stat(path, *args, **kwargs)
        if path == "backend" and kwargs.get("follow_symlinks") is False:
            values = list(status)
            values[0] = stat.S_IFREG | 0o600
            return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.os, "stat", unsafe_selected)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="changed during mode normalization"):
            anchored.prepare_executable("backend")


def test_fallback_validate_rejects_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.symlink("missing", str(root / "alias"))

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="path alias"):
            anchored.validate({})


def test_fallback_validate_rejects_fifo(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.mkfifo(str(root / "pipe"))

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="special object"):
            anchored.validate({})


def test_fallback_validate_maps_disappearing_entry_to_archive_error(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    original_lstat = anchored_module.Path.lstat
    calls = {"target": 0}

    def disappear_after_listing(path):
        if path == target:
            calls["target"] += 1
            if calls["target"] == 1:
                raise OSError("entry disappeared")
        return original_lstat(path)

    monkeypatch.setattr(anchored_module.Path, "lstat", disappear_after_listing)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to inspect extracted archive object"):
            anchored.validate({})


def test_fallback_flush_uses_visible_root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    outcomes = []

    def record_flush(path):
        outcomes.append(path)
        return "flushed"

    monkeypatch.setattr(anchored_module, "flush_directory", record_flush)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        assert anchored.flush() == "flushed"

    assert outcomes == [root]


def test_fallback_flush_tree_rejects_unreadable_directory(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    original_iterdir = anchored_module.Path.iterdir

    def fail_root_listing(path):
        if path == root:
            raise OSError("listing failed")
        return original_iterdir(path)

    monkeypatch.setattr(anchored_module.Path, "iterdir", fail_root_listing)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to inspect anchored tree directory"):
            anchored.flush_tree()


def test_fallback_flush_tree_rejects_disappearing_entry(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    original_lstat = anchored_module.Path.lstat

    def fail_target_inspection(path):
        if path == target:
            raise OSError("entry disappeared")
        return original_lstat(path)

    monkeypatch.setattr(anchored_module.Path, "lstat", fail_target_inspection)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to inspect anchored tree object"):
            anchored.flush_tree()


def test_fallback_flush_tree_rejects_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.symlink("missing", str(root / "alias"))

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="path alias"):
            anchored.flush_tree()


def test_fallback_flush_tree_rejects_unsafe_directory_permissions(tmp_path):
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    child.chmod(0o755)

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unsafe permissions"):
            anchored.flush_tree()


def test_fallback_flush_tree_rejects_special_object(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.mkfifo(str(root / "pipe"))

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="special object"):
            anchored.flush_tree()


def test_posix_flush_tree_rejects_disappearing_entry(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "state")
    original_stat = anchored_module.os.stat

    def fail_entry_inspection(path, *args, **kwargs):
        if path == "state" and kwargs.get("dir_fd") is not None:
            raise OSError("entry disappeared")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(anchored_module.os, "stat", fail_entry_inspection)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unable to inspect anchored tree object"):
            anchored.flush_tree()


def test_posix_flush_tree_rejects_directory_identity_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    child.chmod(0o700)
    original_fstat = anchored_module.os.fstat
    child_inode = child.stat().st_ino

    def changed_child_identity(descriptor):
        status = original_fstat(descriptor)
        if status.st_ino == child_inode:
            values = list(status)
            values[1] += 1
            return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.os, "fstat", changed_child_identity)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="anchored tree directory changed"):
            anchored.flush_tree()


def test_ensure_directory_rejects_visible_identity_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    original_stat = anchored_module.os.stat

    def changed_visible_identity(path, *args, **kwargs):
        status = original_stat(path, *args, **kwargs)
        if path == "child" and kwargs.get("follow_symlinks") is False:
            values = list(status)
            values[1] += 1
            return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.os, "stat", changed_visible_identity)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="ancestor changed while being opened"):
            anchored.ensure_directory(("child",))


def test_ensure_directory_rejects_recreated_tracked_directory(tmp_path):
    root = tmp_path / "root"
    with AnchoredDirectory(root) as anchored:
        anchored.ensure_directory(("child",))
        (root / "child").rmdir()
        (root / "inode-holder").mkdir(mode=0o700)
        (root / "child").mkdir(mode=0o700)
        with pytest.raises(ArchiveError, match="archive output identity changed"):
            anchored.ensure_directory(("child",))


def test_fallback_replace_rejects_no_replace_contract(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="atomic no-replace publication is unsupported"):
            anchored.replace(("candidate",), ("published",), replace_existing=False)


def test_fallback_replace_rejects_changed_source_identity(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    candidate = root / "candidate"
    _write_private(candidate)
    identity = anchored_module.capture_identity(candidate)
    candidate.rename(tmp_path / "original-candidate")
    _write_private(candidate, b"replacement")

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="source identity changed"):
            anchored.replace(("candidate",), ("published",), expected_identity=identity)


def test_fallback_replace_maps_publication_oserror(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")

    def fail_replace(source, destination):
        raise OSError("rename failed")

    monkeypatch.setattr(anchored_module.os, "replace", fail_replace)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to publish anchored entry"):
            anchored.replace(("candidate",), ("published",))


def test_fallback_create_directory_rejects_alias_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    original_alias_check = anchored_module.is_path_alias

    def mark_created_directory_unsafe(path):
        if path == root / "created":
            return True
        return original_alias_check(path)

    monkeypatch.setattr(anchored_module, "is_path_alias", mark_created_directory_unsafe)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="changed while being created"):
            anchored.create_directory(("created",))


def test_fallback_create_file_rejects_identity_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    original_matches = anchored_module.identity_matches

    def reject_created_file(path, identity):
        if path == root / "created":
            return False
        return original_matches(path, identity)

    monkeypatch.setattr(anchored_module, "identity_matches", reject_created_file)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="changed while being identified"):
            anchored.create_file(("created",))


def test_prepare_executable_rejects_hard_link_added_after_scan(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    executable = root / "backend"
    _write_private(executable)
    original_scan = AnchoredDirectory._scan_posix

    def link_after_scan(anchored, descriptor, prefix, result):
        original_scan(anchored, descriptor, prefix, result)
        if not prefix and not (root / "alias").exists():
            os.link(str(executable), str(root / "alias"))

    monkeypatch.setattr(AnchoredDirectory, "_scan_posix", link_after_scan)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="not a private regular file"):
            anchored.prepare_executable("backend")


def test_validate_accepts_untracked_exact_tree(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)

    with AnchoredDirectory(root) as anchored:
        anchored.validate({("state",): ("file", 4)})


def test_fallback_identity_maps_integrity_failure(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "state")

    def fail_capture(path):
        raise IntegrityError("identity invalid")

    monkeypatch.setattr(anchored_module, "capture_identity", fail_capture)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to identify anchored entry"):
            anchored.identity(("state",))


def test_create_symlink_rejects_changed_target_after_creation(tmp_path, monkeypatch):
    root = tmp_path / "root"

    def report_different_target(path, dir_fd=None):
        return "different"

    monkeypatch.setattr(anchored_module.os, "readlink", report_different_target)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="changed while being created"):
            anchored.create_symlink(("link",), "expected")


def test_fallback_create_symlink_rejects_changed_target(tmp_path, monkeypatch):
    root = tmp_path / "root"

    def report_different_target(path):
        return "different"

    monkeypatch.setattr(anchored_module.os, "readlink", report_different_target)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="changed while being created"):
            anchored.create_symlink(("link",), "expected")


def test_fallback_replace_maps_source_identity_validation_failure(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    candidate = root / "candidate"
    _write_private(candidate)
    identity = anchored_module.capture_identity(candidate)

    def fail_identity(path, expected):
        raise IntegrityError("identity unavailable")

    monkeypatch.setattr(anchored_module, "identity_matches", fail_identity)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to verify anchored replacement source"):
            anchored.replace(("candidate",), ("published",), expected_identity=identity)


def test_fallback_replace_rejects_wrong_destination_identity(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")
    destination = root / "published"
    _write_private(destination)
    identity = anchored_module.capture_identity(destination)
    destination.rename(tmp_path / "original-published")
    _write_private(destination, b"replacement")

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="destination identity changed"):
            anchored.replace(
                ("candidate",),
                ("published",),
                expected_destination_identity=identity,
            )


def test_fallback_replace_rejects_changed_published_identity(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    candidate = root / "candidate"
    _write_private(candidate)
    identity = anchored_module.capture_identity(candidate)
    original_matches = anchored_module.identity_matches

    def reject_published(path, expected):
        if path == root / "published":
            return False
        return original_matches(path, expected)

    monkeypatch.setattr(anchored_module, "identity_matches", reject_published)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="published a different entry"):
            anchored.replace(("candidate",), ("published",), expected_identity=identity)


def test_fallback_replace_flushes_distinct_parents(tmp_path, monkeypatch):
    root = tmp_path / "root"
    source_parent = root / "source"
    destination_parent = root / "destination"
    source_parent.mkdir(parents=True)
    destination_parent.mkdir()
    source_parent.chmod(0o700)
    destination_parent.chmod(0o700)
    _write_private(source_parent / "candidate")
    flushed = []

    def record_flush(path):
        flushed.append(path)
        return str(path)

    monkeypatch.setattr(anchored_module, "flush_directory", record_flush)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        outcome = anchored.replace(
            ("source", "candidate"),
            ("destination", "published"),
        )

    assert outcome == (str(source_parent), str(destination_parent))
    assert flushed == [source_parent, destination_parent]


def test_create_directory_maps_creation_oserror(tmp_path, monkeypatch):
    root = tmp_path / "root"
    original_mkdir = anchored_module.os.mkdir

    def fail_child_creation(path, *args, **kwargs):
        if os.fsdecode(path) == "created":
            raise PermissionError("denied")
        return original_mkdir(path, *args, **kwargs)

    with AnchoredDirectory(root) as anchored:
        monkeypatch.setattr(anchored_module.os, "mkdir", fail_child_creation)
        with pytest.raises(ArchiveError, match="unable to create anchored directory"):
            anchored.create_directory(("created",))


def test_create_file_rejects_visible_identity_race(tmp_path, monkeypatch):
    root = tmp_path / "root"
    original_stat = anchored_module.os.stat

    def changed_visible_identity(path, *args, **kwargs):
        status = original_stat(path, *args, **kwargs)
        if path == "created" and kwargs.get("follow_symlinks") is False:
            values = list(status)
            values[1] += 1
            return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.os, "stat", changed_visible_identity)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="file changed while being created"):
            anchored.create_file(("created",))


def test_open_existing_file_rejects_identity_changed_during_open(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    identity = anchored_module.capture_identity(target)
    original_matches = anchored_module.identity_matches
    calls = {"count": 0}

    def reject_second_check(path, expected):
        calls["count"] += 1
        if calls["count"] == 2:
            return False
        return original_matches(path, expected)

    monkeypatch.setattr(anchored_module, "identity_matches", reject_second_check)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="identity changed while opening"):
            anchored.open_existing_file(("state",), expected_identity=identity)


def test_read_json_rejects_metadata_change_while_reading(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state.json"
    _write_private(target, b"{}")
    target_inode = target.stat().st_ino
    original_fstat = anchored_module.os.fstat
    calls = {"target": 0}

    class ChangedStatus(object):
        def __init__(self, status):
            self._status = status
            self.st_mtime_ns = status.st_mtime_ns + 1

        def __getattr__(self, name):
            return getattr(self._status, name)

    def change_after_read(descriptor):
        status = original_fstat(descriptor)
        if status.st_ino == target_inode:
            calls["target"] += 1
            if calls["target"] == 3:
                return ChangedStatus(status)
        return status

    monkeypatch.setattr(anchored_module.os, "fstat", change_after_read)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="JSON file changed while being read"):
            anchored.read_json(("state.json",))


def test_fallback_prepare_executable_maps_disappearance_after_scan(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    executable = root / "backend"
    _write_private(executable)
    original_scan = AnchoredDirectory._scan_path

    def disappear_after_scan(anchored, path, prefix, result):
        original_scan(anchored, path, prefix, result)
        if not prefix and executable.exists():
            executable.unlink()

    monkeypatch.setattr(AnchoredDirectory, "_scan_path", disappear_after_scan)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unable to inspect extracted backend executable"):
            anchored.prepare_executable("backend")


def test_fallback_prepare_executable_rejects_hard_link_added_after_scan(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    executable = root / "backend"
    _write_private(executable)
    original_scan = AnchoredDirectory._scan_path

    def link_after_scan(anchored, path, prefix, result):
        original_scan(anchored, path, prefix, result)
        if not prefix and not (root / "alias").exists():
            os.link(str(executable), str(root / "alias"))

    monkeypatch.setattr(AnchoredDirectory, "_scan_path", link_after_scan)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="not a private regular file"):
            anchored.prepare_executable("backend")


def test_fallback_prepare_executable_maps_identity_validation_failure(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        stream, unused_identity = anchored.create_file(("backend",))
        stream.close()

        def fail_identity(path, expected):
            raise IntegrityError("identity unavailable")

        monkeypatch.setattr(anchored_module, "identity_matches", fail_identity)
        with pytest.raises(ArchiveError, match="unable to verify selected executable identity"):
            anchored.prepare_executable("backend")


def test_fallback_prepare_executable_rejects_identity_race_after_normalization(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    executable = root / "backend"
    _write_private(executable)
    original_lstat = anchored_module.Path.lstat
    calls = {"target": 0}

    def changed_after_normalization(path):
        status = original_lstat(path)
        if path == executable:
            calls["target"] += 1
            if calls["target"] == 3:
                values = list(status)
                values[1] += 1
                return os.stat_result(values)
        return status

    monkeypatch.setattr(anchored_module.Path, "lstat", changed_after_normalization)
    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="changed during normalization"):
            anchored.prepare_executable("backend")
