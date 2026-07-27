"""Safe extraction for supported backend release archives."""

import gzip
import os
import stat
import tarfile
import zipfile
import zlib
from pathlib import PurePosixPath, PureWindowsPath

from ..errors import ArchiveError
from ..utils.fs import ensure_private_directory

DEFAULT_MAXIMUM_EXTRACTED_BYTES = 768 * 1024 * 1024
BAD_GZIP_FILE = getattr(gzip, "BadGzipFile", OSError)


def _safe_parts(member_name):  # type: (str) -> tuple
    normalized = member_name.replace("\\", "/")
    member = PurePosixPath(normalized)
    windows_member = PureWindowsPath(normalized)
    if member.is_absolute() or windows_member.is_absolute() or windows_member.drive or ".." in member.parts:
        raise ArchiveError("unsafe archive member path: %s" % member_name)
    parts = tuple(part for part in member.parts if part not in ("", "."))
    if not parts:
        raise ArchiveError("empty archive member path")
    return parts


def _copy_bounded(source, destination, maximum_bytes):
    total = 0
    with destination.open("wb") as output:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum_bytes:
                raise ArchiveError("extracted backend content exceeds the safety limit")
            output.write(block)
    return total


def extract_archive(archive, destination, standalone_name, maximum_bytes=DEFAULT_MAXIMUM_EXTRACTED_BYTES):
    # type: (Path, Path, str, int) -> None
    ensure_private_directory(destination)
    lower_name = archive.name.lower()
    if lower_name.endswith(".zip"):
        _extract_zip(archive, destination, maximum_bytes)
    elif lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
        _extract_tar(archive, destination, maximum_bytes)
    elif lower_name.endswith(".gz"):
        target = destination / standalone_name
        try:
            with gzip.open(str(archive), "rb") as source:
                _copy_bounded(source, target, maximum_bytes)
        except (BAD_GZIP_FILE, EOFError, zlib.error) as error:
            # GZip validation occurs while reading, after the archive has opened.
            raise ArchiveError("invalid GZip backend archive: %s" % error)
    else:
        raise ArchiveError("unsupported backend archive: %s" % archive.name)


def _extract_zip(archive, destination, maximum_bytes):  # type: (Path, Path, int) -> None
    total = 0
    seen = set()
    try:
        source = zipfile.ZipFile(str(archive), "r")
    except zipfile.BadZipFile as error:
        # BadZipFile is expected when a corrupt or mislabeled asset is supplied.
        raise ArchiveError("invalid ZIP backend archive: %s" % error)
    try:
        with source:
            for member in source.infolist():
                parts = _safe_parts(member.filename)
                _reject_duplicate(parts, seen)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ArchiveError("symbolic links are not allowed in backend archives")
                target = destination.joinpath(*parts)
                if member.is_dir():
                    ensure_private_directory(target)
                    continue
                total += member.file_size
                if total > maximum_bytes:
                    raise ArchiveError("extracted backend content exceeds the safety limit")
                ensure_private_directory(target.parent)
                with source.open(member, "r") as input_stream:
                    _copy_bounded(input_stream, target, member.file_size)
    except zipfile.BadZipFile as error:
        # CRC and member corruption can surface only while reading contents.
        raise ArchiveError("invalid ZIP backend archive: %s" % error)


def _extract_tar(archive, destination, maximum_bytes):  # type: (Path, Path, int) -> None
    total = 0
    seen = set()
    try:
        source = tarfile.open(str(archive), "r:gz")
    except tarfile.TarError as error:
        # TarError is expected when a corrupt or mislabeled asset is supplied.
        raise ArchiveError("invalid TAR backend archive: %s" % error)
    with source:
        for member in source.getmembers():
            parts = _safe_parts(member.name)
            _reject_duplicate(parts, seen)
            target = destination.joinpath(*parts)
            if member.isdir():
                ensure_private_directory(target)
                continue
            if not member.isfile():
                raise ArchiveError("links and special files are not allowed in backend archives")
            total += member.size
            if total > maximum_bytes:
                raise ArchiveError("extracted backend content exceeds the safety limit")
            input_stream = source.extractfile(member)
            if input_stream is None:
                raise ArchiveError("unable to read backend archive member: %s" % member.name)
            ensure_private_directory(target.parent)
            with input_stream:
                _copy_bounded(input_stream, target, member.size)


def _reject_duplicate(parts, seen):  # type: (tuple, set) -> None
    normalized = "/".join(parts).casefold()
    if normalized in seen:
        raise ArchiveError("duplicate backend archive member: %s" % "/".join(parts))
    seen.add(normalized)


def find_executable(root, executable_name):  # type: (Path, str) -> Path
    candidates = [path for path in root.rglob(executable_name) if path.is_file()]
    if len(candidates) != 1:
        raise ArchiveError("expected exactly one %s executable, found %d" % (executable_name, len(candidates)))
    executable = candidates[0]
    if os.name == "posix":
        executable.chmod(0o755)
    return executable
