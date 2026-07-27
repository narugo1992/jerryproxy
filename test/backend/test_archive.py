import gzip
import io
import os
import stat
import tarfile
import zipfile

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
