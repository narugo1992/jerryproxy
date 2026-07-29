import gzip
import io
import os
import stat
import struct
import tarfile
import zipfile
from types import SimpleNamespace

import pytest

from jerryproxy.backend.archive import extract_archive, find_executable
from jerryproxy.errors import ArchiveError


def test_standalone_gzip_extraction(tmp_path):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"fake executable")
    destination = tmp_path / "output"
    extract_archive(archive, destination, "mihomo")
    executable = find_executable(destination, "mihomo")
    assert executable.read_bytes() == b"fake executable"
    if os.name == "posix":
        assert executable.stat().st_mode & stat.S_IXUSR


def test_corrupt_standalone_gzip_is_a_domain_error(tmp_path):
    archive = tmp_path / "corrupt.gz"
    archive.write_bytes(b"not a gzip stream")
    with pytest.raises(ArchiveError, match="invalid GZip backend archive"):
        extract_archive(archive, tmp_path / "output", "mihomo")


def test_unsupported_archive_type_is_rejected(tmp_path):
    archive = tmp_path / "backend.xz"
    archive.write_bytes(b"unsupported")
    with pytest.raises(ArchiveError, match="unsupported backend archive"):
        extract_archive(archive, tmp_path / "output", "backend")


def test_gzip_extraction_enforces_size_limit(tmp_path):
    archive = tmp_path / "mihomo.gz"
    with gzip.open(str(archive), "wb") as stream:
        stream.write(b"12345")
    with pytest.raises(ArchiveError, match="safety limit"):
        extract_archive(archive, tmp_path / "output", "mihomo", maximum_bytes=4)


def test_zip_extraction_rejects_parent_traversal(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("../escape", b"bad")
    with pytest.raises(ArchiveError):
        extract_archive(archive, tmp_path / "output", "xray")
    assert not (tmp_path / "escape").exists()


def test_zip_extraction_rejects_windows_drive_path(tmp_path):
    archive = tmp_path / "windows-drive.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("C:/escape", b"bad")
    with pytest.raises(ArchiveError, match="unsafe archive member path"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_duplicate_casefolded_paths(tmp_path):
    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/Xray", b"one")
        stream.writestr("bin/xray", b"two")
    with pytest.raises(ArchiveError, match="duplicate backend archive member"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_symlink(tmp_path):
    archive = tmp_path / "evil-link.zip"
    info = zipfile.ZipInfo("xray")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(info, "target")
    with pytest.raises(ArchiveError):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_rejects_special_file(tmp_path):
    archive = tmp_path / "device.zip"
    info = zipfile.ZipInfo("device")
    info.create_system = 3
    info.external_attr = stat.S_IFCHR << 16
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(info, b"")

    with pytest.raises(ArchiveError, match="special files"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_preserves_nested_executable(tmp_path):
    archive = tmp_path / "xray.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("bin/", b"")
        stream.writestr("bin/xray", b"xray executable")

    destination = tmp_path / "output"
    extract_archive(archive, destination, "xray")
    assert find_executable(destination, "xray").read_bytes() == b"xray executable"


def test_zip_extraction_rejects_empty_member_path(tmp_path):
    archive = tmp_path / "empty-member.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr(".", b"empty")
    with pytest.raises(ArchiveError, match="empty archive member path"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_extraction_enforces_total_size_limit(tmp_path):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(str(archive), "w") as stream:
        stream.writestr("xray", b"12345")
    with pytest.raises(ArchiveError, match="safety limit"):
        extract_archive(archive, tmp_path / "output", "xray", maximum_bytes=4)


def test_corrupt_zip_is_a_domain_error(tmp_path):
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"not-zip")
    with pytest.raises(ArchiveError, match="invalid ZIP"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_zip_member_crc_failure_is_a_domain_error(tmp_path):
    archive = tmp_path / "bad-crc.zip"
    with zipfile.ZipFile(str(archive), "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("xray", b"backend")
    with zipfile.ZipFile(str(archive), "r") as stream:
        member = stream.getinfo("xray")
    with archive.open("r+b") as stream:
        stream.seek(member.header_offset)
        header = stream.read(30)
        filename_length, extra_length = struct.unpack("<HH", header[26:30])
        stream.seek(member.header_offset + 30 + filename_length + extra_length)
        first = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((first[0] ^ 0xFF,)))

    with pytest.raises(ArchiveError, match="invalid ZIP backend archive"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_duplicate_executable_is_rejected(tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir(parents=True)
    (root / "a" / "xray").write_bytes(b"one")
    (root / "b" / "xray").write_bytes(b"two")
    with pytest.raises(ArchiveError):
        find_executable(root, "xray")


def test_tar_gzip_extraction_preserves_nested_executable(tmp_path):
    archive = tmp_path / "sing-box.tar.gz"
    payload = b"fake sing-box executable"
    with tarfile.open(str(archive), "w:gz") as stream:
        directory = tarfile.TarInfo("sing-box-1.0.0")
        directory.type = tarfile.DIRTYPE
        stream.addfile(directory)
        executable = tarfile.TarInfo("sing-box-1.0.0/sing-box")
        executable.size = len(payload)
        stream.addfile(executable, io.BytesIO(payload))

    destination = tmp_path / "output"
    extract_archive(archive, destination, "sing-box")
    executable_path = find_executable(destination, "sing-box")
    assert executable_path.read_bytes() == payload


def test_tar_gzip_extraction_rejects_links(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(str(archive), "w:gz") as stream:
        link = tarfile.TarInfo("xray")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        stream.addfile(link)

    with pytest.raises(ArchiveError, match="links and special files"):
        extract_archive(archive, tmp_path / "output", "xray")


def test_tar_gzip_extraction_enforces_total_size_limit(tmp_path):
    archive = tmp_path / "large.tar.gz"
    payload = b"12345"
    with tarfile.open(str(archive), "w:gz") as stream:
        executable = tarfile.TarInfo("sing-box")
        executable.size = len(payload)
        stream.addfile(executable, io.BytesIO(payload))
    with pytest.raises(ArchiveError, match="safety limit"):
        extract_archive(archive, tmp_path / "output", "sing-box", maximum_bytes=4)


def test_corrupt_tar_gzip_is_a_domain_error(tmp_path):
    archive = tmp_path / "corrupt.tar.gz"
    archive.write_bytes(b"not-tar")
    with pytest.raises(ArchiveError, match="invalid TAR"):
        extract_archive(archive, tmp_path / "output", "sing-box")


def test_tar_regular_member_without_a_content_stream_is_rejected(tmp_path, monkeypatch):
    archive = tmp_path / "missing-stream.tar.gz"
    archive.write_bytes(b"placeholder")
    member = SimpleNamespace(name="sing-box", size=1, isdir=lambda: False, isfile=lambda: True)

    class FakeTar(object):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def getmembers(self):
            return [member]

        def extractfile(self, selected):
            assert selected is member
            return None

    monkeypatch.setattr(tarfile, "open", lambda *args, **kwargs: FakeTar())

    with pytest.raises(ArchiveError, match="unable to read backend archive member"):
        extract_archive(archive, tmp_path / "output", "sing-box")
