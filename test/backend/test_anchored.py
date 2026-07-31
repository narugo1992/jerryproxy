import errno
import os
import stat
from types import SimpleNamespace

import pytest

import jerryproxy.backend.anchored as anchored_module
from jerryproxy.backend.anchored import AnchoredDirectory
from jerryproxy.errors import ArchiveError, IntegrityError

pytestmark = pytest.mark.unittest
POSIX_FAULT_INJECTION = pytest.mark.skipif(
    os.name == "nt",
    reason="requires POSIX descriptors and replaceable open filesystem objects",
)


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


@POSIX_FAULT_INJECTION
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


@pytest.mark.skipif(os.name != "nt", reason="Windows path-based symlink observation")
def test_windows_path_fallback_reads_a_bound_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "target"
    target.write_bytes(b"target")
    link = root / "link"
    link.symlink_to(target.name)

    with AnchoredDirectory(root) as anchored:
        observed_target, identity = anchored.read_symlink(("link",))

    assert observed_target == target.name
    assert identity["file_type"] == "symlink"


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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
def test_replace_preserves_a_destination_substituted_at_the_native_rename(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    candidate = root / "candidate"
    published = root / "published"
    displaced = root / "displaced"
    replacement = root / "replacement"
    _write_private(candidate, b"candidate")
    _write_private(published, b"published")
    _write_private(replacement, b"replacement")
    source_identity = anchored_module.capture_identity(candidate)
    destination_identity = anchored_module.capture_identity(published)
    substituted = []

    if hasattr(anchored_module, "_rename_posix_exchange"):
        original_rename = anchored_module._rename_posix_exchange

        def substitute_at_exchange(*args, **kwargs):
            if not substituted:
                published.rename(displaced)
                replacement.rename(published)
                substituted.append(True)
            return original_rename(*args, **kwargs)

        monkeypatch.setattr(anchored_module, "_rename_posix_exchange", substitute_at_exchange)
    else:
        original_rename = anchored_module.os.replace

        def substitute_at_replace(*args, **kwargs):
            if not substituted:
                published.rename(displaced)
                replacement.rename(published)
                substituted.append(True)
            return original_rename(*args, **kwargs)

        monkeypatch.setattr(anchored_module.os, "replace", substitute_at_replace)

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="destination.*changed|publication boundary"):
            anchored.replace(
                (candidate.name,),
                (published.name,),
                expected_identity=source_identity,
                expected_destination_identity=destination_identity,
            )

    assert substituted
    assert candidate.read_bytes() == b"candidate"
    assert published.read_bytes() == b"replacement"
    assert displaced.read_bytes() == b"published"


@POSIX_FAULT_INJECTION
def test_replace_preserves_a_source_substituted_at_the_native_exchange(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    candidate = root / "candidate"
    published = root / "published"
    displaced = root / "displaced-source"
    replacement = root / "replacement-source"
    _write_private(candidate, b"candidate")
    _write_private(published, b"published")
    _write_private(replacement, b"replacement")
    source_identity = anchored_module.capture_identity(candidate)
    destination_identity = anchored_module.capture_identity(published)
    original_exchange = anchored_module._rename_posix_exchange
    substituted = []

    def substitute_at_exchange(*args, **kwargs):
        if not substituted:
            candidate.rename(displaced)
            replacement.rename(candidate)
            substituted.append(True)
        return original_exchange(*args, **kwargs)

    monkeypatch.setattr(anchored_module, "_rename_posix_exchange", substitute_at_exchange)

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="publication boundary"):
            anchored.replace(
                (candidate.name,),
                (published.name,),
                expected_identity=source_identity,
                expected_destination_identity=destination_identity,
            )

    assert displaced.read_bytes() == b"candidate"
    assert candidate.read_bytes() == b"replacement"
    assert published.read_bytes() == b"published"


@POSIX_FAULT_INJECTION
def test_replace_preserves_all_entries_when_exchange_reversal_fails(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    candidate = root / "candidate"
    published = root / "published"
    stolen = root / "stolen-candidate"
    _write_private(candidate, b"candidate")
    _write_private(published, b"published")
    source_identity = anchored_module.capture_identity(candidate)
    destination_identity = anchored_module.capture_identity(published)
    original_exchange = anchored_module._rename_posix_exchange
    calls = []

    def fail_reversal(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            result = original_exchange(*args, **kwargs)
            published.rename(stolen)
            _write_private(published, b"replacement")
            return result
        raise OSError(errno.EIO, "simulated exchange reversal failure")

    monkeypatch.setattr(anchored_module, "_rename_posix_exchange", fail_reversal)

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unable to publish anchored entry"):
            anchored.replace(
                (candidate.name,),
                (published.name,),
                expected_identity=source_identity,
                expected_destination_identity=destination_identity,
            )

    assert len(calls) == 2
    assert candidate.read_bytes() == b"published"
    assert published.read_bytes() == b"replacement"
    assert stolen.read_bytes() == b"candidate"


@pytest.mark.parametrize(
    ("rename", "message"),
    (
        ("_rename_posix_noreplace", "atomic no-replace publication is unsupported"),
        ("_rename_posix_exchange", "atomic exchange is unsupported"),
    ),
)
def test_linux_atomic_rename_flags_fail_closed_when_the_filesystem_rejects_them(
    monkeypatch,
    rename,
    message,
):
    class NativeRename(object):
        def __call__(self, *args):
            del args
            return -1

    class Libc(object):
        renameat2 = NativeRename()

    monkeypatch.setattr(anchored_module.sys, "platform", "linux")
    monkeypatch.setattr(anchored_module.ctypes, "CDLL", lambda *args, **kwargs: Libc())
    monkeypatch.setattr(anchored_module.ctypes, "get_errno", lambda: errno.ENOSYS)

    with pytest.raises(ArchiveError, match=message):
        getattr(anchored_module, rename)(11, "source", 12, "destination")


@pytest.mark.parametrize(
    ("machine", "expected_syscall"),
    (("armv5l", 382), ("loongarch64", 276), ("loong64", 276)),
)
@pytest.mark.parametrize("rename", ("_rename_posix_noreplace", "_rename_posix_exchange"))
def test_linux_atomic_rename_syscall_dispatch_supports_release_architectures(
    monkeypatch,
    machine,
    expected_syscall,
    rename,
):
    calls = []

    class Syscall(object):
        restype = None

        def __call__(self, *args):
            calls.append(args)
            return 0

    class Libc(object):
        syscall = Syscall()

    monkeypatch.setattr(anchored_module.sys, "platform", "linux")
    monkeypatch.setattr(
        anchored_module.os,
        "uname",
        lambda: type("Uname", (), {"machine": machine})(),
        raising=False,
    )
    monkeypatch.setattr(anchored_module.ctypes, "CDLL", lambda *args, **kwargs: Libc())

    getattr(anchored_module, rename)(11, "source", 12, "destination")

    assert calls
    assert calls[0][0].value == expected_syscall


@pytest.mark.parametrize("rename", ("_rename_posix_noreplace", "_rename_posix_exchange"))
def test_linux_atomic_rename_rejects_an_unknown_syscall_architecture(monkeypatch, rename):
    class Libc(object):
        syscall = object()

    monkeypatch.setattr(anchored_module.sys, "platform", "linux")
    monkeypatch.setattr(
        anchored_module.os,
        "uname",
        lambda: type("Uname", (), {"machine": "unknown-cpu"})(),
        raising=False,
    )
    monkeypatch.setattr(anchored_module.ctypes, "CDLL", lambda *args, **kwargs: Libc())

    with pytest.raises(ArchiveError, match="unsupported on this Linux architecture"):
        getattr(anchored_module, rename)(11, "source", 12, "destination")


@pytest.mark.parametrize(
    ("rename", "expected_flag"),
    (
        ("_rename_posix_noreplace", anchored_module._RENAME_EXCL),
        ("_rename_posix_exchange", anchored_module._RENAME_SWAP),
    ),
)
def test_macos_atomic_rename_dispatch_uses_the_required_native_flag(
    monkeypatch,
    rename,
    expected_flag,
):
    calls = []

    class NativeRename(object):
        def __call__(self, *args):
            calls.append(args)
            return 0

    class Libc(object):
        renameatx_np = NativeRename()

    monkeypatch.setattr(anchored_module.sys, "platform", "darwin")
    monkeypatch.setattr(anchored_module.ctypes, "CDLL", lambda *args, **kwargs: Libc())

    getattr(anchored_module, rename)(11, "source", 12, "destination")

    assert calls == [(11, b"source", 12, b"destination", expected_flag)]


@pytest.mark.parametrize("rename", ("_rename_posix_noreplace", "_rename_posix_exchange"))
def test_macos_atomic_rename_rejects_a_missing_native_operation(monkeypatch, rename):
    monkeypatch.setattr(anchored_module.sys, "platform", "darwin")
    monkeypatch.setattr(anchored_module.ctypes, "CDLL", lambda *args, **kwargs: object())

    with pytest.raises(ArchiveError, match="unsupported on this macOS runtime"):
        getattr(anchored_module, rename)(11, "source", 12, "destination")


def test_posix_entry_isolation_rechecks_the_moved_identity_before_returning(monkeypatch):
    status = SimpleNamespace(
        st_dev=17,
        st_ino=23,
        st_mode=stat.S_IFREG | 0o600,
    )
    calls = []

    def rename_noreplace(source_parent, source_name, destination_parent, destination_name):
        calls.append((source_parent, source_name, destination_parent, destination_name))

    monkeypatch.setattr(anchored_module.secrets, "token_hex", lambda size: "a" * (size * 2))
    monkeypatch.setattr(anchored_module.os, "stat", lambda *args, **kwargs: status)

    quarantine, moved = anchored_module._isolate_posix_entry(
        91,
        "managed",
        anchored_module._identity(status),
        ".jerryproxy-test-",
        rename_noreplace,
    )

    assert quarantine == ".jerryproxy-test-" + "a" * 32
    assert moved is status
    assert calls == [(91, "managed", 91, quarantine)]


@pytest.mark.parametrize("restore_fails", (False, True))
def test_posix_entry_isolation_handles_a_substituted_moved_object(monkeypatch, restore_fails):
    expected = SimpleNamespace(
        st_dev=17,
        st_ino=23,
        st_mode=stat.S_IFREG | 0o600,
    )
    substitute = SimpleNamespace(
        st_dev=17,
        st_ino=29,
        st_mode=stat.S_IFREG | 0o600,
    )
    calls = []

    def rename_noreplace(source_parent, source_name, destination_parent, destination_name):
        calls.append((source_parent, source_name, destination_parent, destination_name))
        if restore_fails and len(calls) == 2:
            raise OSError("simulated restore failure")

    monkeypatch.setattr(anchored_module.secrets, "token_hex", lambda size: "b" * (size * 2))
    monkeypatch.setattr(anchored_module.os, "stat", lambda *args, **kwargs: substitute)

    message = "substitute retained in quarantine" if restore_fails else "changed at the isolation boundary"
    with pytest.raises(ArchiveError, match=message):
        anchored_module._isolate_posix_entry(
            91,
            "managed",
            anchored_module._identity(expected),
            ".jerryproxy-test-",
            rename_noreplace,
        )

    quarantine = ".jerryproxy-test-" + "b" * 32
    assert calls == [
        (91, "managed", 91, quarantine),
        (91, quarantine, 91, "managed"),
    ]


def test_posix_entry_isolation_bounds_private_name_collisions():
    calls = []

    def collide(*args):
        calls.append(args)
        raise FileExistsError("simulated private-name collision")

    with pytest.raises(ArchiveError, match="unable to allocate a private anchored quarantine name"):
        anchored_module._isolate_posix_entry(
            91,
            "managed",
            (17, 23, stat.S_IFREG),
            ".jerryproxy-test-",
            collide,
        )

    assert len(calls) == 4


@pytest.mark.parametrize(
    ("mode", "expected_operation"),
    (
        (stat.S_IFREG | 0o600, "unlink"),
        (stat.S_IFDIR | 0o700, "rmdir"),
    ),
)
def test_posix_entry_disposal_uses_the_operation_for_the_verified_type(
    monkeypatch,
    mode,
    expected_operation,
):
    status = SimpleNamespace(st_dev=17, st_ino=23, st_mode=mode)
    calls = []

    monkeypatch.setattr(anchored_module.os, "stat", lambda *args, **kwargs: status)
    monkeypatch.setattr(
        anchored_module.os,
        "unlink",
        lambda name, dir_fd: calls.append(("unlink", name, dir_fd)),
    )
    monkeypatch.setattr(
        anchored_module.os,
        "rmdir",
        lambda name, dir_fd: calls.append(("rmdir", name, dir_fd)),
    )

    anchored_module._discard_posix_entry(91, "isolated", status)

    assert calls == [(expected_operation, "isolated", 91)]


def test_posix_entry_disposal_rejects_an_identity_change(monkeypatch):
    expected = SimpleNamespace(st_dev=17, st_ino=23, st_mode=stat.S_IFREG | 0o600)
    substitute = SimpleNamespace(st_dev=17, st_ino=29, st_mode=stat.S_IFREG | 0o600)

    monkeypatch.setattr(anchored_module.os, "stat", lambda *args, **kwargs: substitute)

    with pytest.raises(ArchiveError, match="changed before disposal"):
        anchored_module._discard_posix_entry(91, "isolated", expected)


def test_posix_entry_isolation_rejects_an_uninspectable_moved_object(monkeypatch):
    def fail_stat(*args, **kwargs):
        del args, kwargs
        raise OSError("simulated inspection failure")

    monkeypatch.setattr(anchored_module.os, "stat", fail_stat)

    with pytest.raises(ArchiveError, match="unable to inspect the isolated anchored entry"):
        anchored_module._isolate_posix_entry(
            91,
            "managed",
            (17, 23, stat.S_IFREG),
            ".jerryproxy-test-",
            lambda *args: None,
        )


@pytest.mark.parametrize("python_exposes_flag", (True, False))
@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor flag semantics")
def test_replace_opens_symlink_entries_without_combining_no_follow(
    tmp_path,
    monkeypatch,
    python_exposes_flag,
):
    root = tmp_path / "root"
    root.mkdir()
    (root / "source-target").write_bytes(b"source")
    (root / "destination-target").write_bytes(b"destination")
    (root / "candidate").symlink_to("source-target")
    (root / "published").symlink_to("destination-target")
    source_identity = anchored_module.capture_identity(root / "candidate")
    destination_identity = anchored_module.capture_identity(root / "published")
    native_platform = anchored_module.sys.platform
    native_o_symlink = hasattr(os, "O_SYMLINK")
    o_symlink = getattr(os, "O_SYMLINK", anchored_module._DARWIN_O_SYMLINK)
    original_open = anchored_module.os.open
    opened_symlink_flags = []
    anchored = AnchoredDirectory(root)

    def simulate_darwin_symlink_open(path, flags, *args, **kwargs):
        if flags & o_symlink:
            opened_symlink_flags.append(flags)
            assert not flags & getattr(os, "O_NOFOLLOW", 0)
            if not native_o_symlink and native_platform != "darwin":
                flags &= ~o_symlink
                flags |= getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
        return original_open(path, flags, *args, **kwargs)

    if python_exposes_flag:
        monkeypatch.setattr(anchored_module.os, "O_SYMLINK", o_symlink, raising=False)
    else:
        monkeypatch.delattr(anchored_module.os, "O_SYMLINK", raising=False)
        monkeypatch.setattr(anchored_module, "_symlink_open_flag", lambda: o_symlink)
    monkeypatch.setattr(anchored_module.os, "open", simulate_darwin_symlink_open)

    with anchored:
        anchored.replace(
            ("candidate",),
            ("published",),
            expected_identity=source_identity,
            expected_destination_identity=destination_identity,
        )

    assert len(opened_symlink_flags) == 2
    assert not (root / "candidate").exists()
    assert os.readlink(str(root / "published")) == "source-target"


@POSIX_FAULT_INJECTION
def test_replace_maps_publication_oserror(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _write_private(root / "candidate")

    def fail_replace(*args, **kwargs):
        raise OSError("rename failed")

    monkeypatch.setattr(anchored_module, "_rename_posix_noreplace", fail_replace)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unable to publish anchored entry"):
            anchored.replace(("candidate",), ("published",))


@POSIX_FAULT_INJECTION
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
        with pytest.raises(ArchiveError, match="publication boundary"):
            anchored.replace(("candidate",), ("published",))


def test_create_directory_rejects_existing_entry(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "existing").mkdir()

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="anchored directory already exists"):
            anchored.create_directory(("existing",))


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
def test_open_existing_file_rejects_hard_link(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    os.link(str(target), str(root / "alias"))

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="stable private regular file"):
            anchored.open_existing_file(("state",))


@POSIX_FAULT_INJECTION
def test_file_evidence_rejects_wrong_expected_identity_after_read(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state"
    _write_private(target)
    identity = anchored_module.capture_identity(target)
    different = dict(identity)
    different["inode"] += 1
    original_open = AnchoredDirectory.open_existing_file

    def ignore_expected(anchored, parts, writable=False, expected_identity=None):
        return original_open(anchored, parts, writable=writable)

    monkeypatch.setattr(AnchoredDirectory, "open_existing_file", ignore_expected)
    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="identity changed while being read"):
            anchored.file_evidence(("state",), expected_identity=different)


@POSIX_FAULT_INJECTION
def test_read_json_rejects_unsafe_permissions(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "state.json"
    target.write_text("{}")
    target.chmod(0o644)

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="unsafe permissions"):
            anchored.read_json(("state.json",))


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
def test_validate_rejects_fifo_as_special_object(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.mkfifo(str(root / "pipe"))

    with AnchoredDirectory(root) as anchored:
        with pytest.raises(ArchiveError, match="alias or special object"):
            anchored.validate({})


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
def test_fallback_flush_tree_rejects_unsafe_directory_permissions(tmp_path):
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    child.chmod(0o755)

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="unsafe permissions"):
            anchored.flush_tree()


@POSIX_FAULT_INJECTION
def test_fallback_flush_tree_rejects_special_object(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    os.mkfifo(str(root / "pipe"))

    with AnchoredDirectory(root) as anchored:
        anchored._posix = False
        with pytest.raises(ArchiveError, match="special object"):
            anchored.flush_tree()


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
def test_ensure_directory_rejects_recreated_tracked_directory(tmp_path):
    root = tmp_path / "root"
    with AnchoredDirectory(root) as anchored:
        anchored.ensure_directory(("child",))
        (root / "child").rmdir()
        (root / "inode-holder").mkdir(mode=0o700)
        (root / "child").mkdir(mode=0o700)
        with pytest.raises(ArchiveError, match="archive output identity changed"):
            anchored.ensure_directory(("child",))


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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


@POSIX_FAULT_INJECTION
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
