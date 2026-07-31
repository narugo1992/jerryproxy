"""Measure the pinned official backend archive compatibility corpus."""

import argparse
import hashlib
import json
import os
import struct
import tarfile
import tempfile
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath

import requests

from jerryproxy.backend.archive import ArchiveLimits

PINNED_ARTIFACTS = (
    {
        "backend": "mihomo",
        "version": "1.8.0",
        "platform": "linux-amd64",
        "format": "gz",
        "name": "Clash.Meta-linux-amd64-v1.8.0-24-g0b72395.gz",
        "size": 5683676,
        "sha256": "3ffc924fc0e3b7714aadb9d10bf6b788a10cf18de0c4e4530111606f45184fe2",
        "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.8.0/Clash.Meta-linux-amd64-v1.8.0-24-g0b72395.gz",
    },
    {
        "backend": "mihomo",
        "version": "1.8.0",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "Clash.Meta-windows-amd64-v1.8.0-24-g0b72395.zip",
        "size": 5979006,
        "sha256": "2735abb8b4f408406cd4fada8ff79b756a562fc1ed389da6fc83cc314bcdac0f",
        "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.8.0/Clash.Meta-windows-amd64-v1.8.0-24-g0b72395.zip",
    },
    {
        "backend": "mihomo",
        "version": "1.19.29",
        "platform": "linux-amd64",
        "format": "gz",
        "name": "mihomo-linux-amd64-v1-v1.19.29.gz",
        "size": 17881554,
        "sha256": "a048ecbe2dc598321f63a6fbeffa93f0c10ca6db818f64b2b83cf19ef194d73f",
        "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-linux-amd64-v1-v1.19.29.gz",
    },
    {
        "backend": "mihomo",
        "version": "1.19.29",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "mihomo-windows-amd64-v1-v1.19.29.zip",
        "size": 17509589,
        "sha256": "4a5b4cdf76f1879043cea7488162517fd3fb95d5b7a205d89601f1942791ee39",
        "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-windows-amd64-v1-v1.19.29.zip",
    },
    {
        "backend": "sing-box",
        "version": "1.0",
        "platform": "linux-amd64-glibc",
        "format": "tar.gz",
        "name": "sing-box-1.0-linux-amd64.tar.gz",
        "size": 6964791,
        "sha256": "b65b1e20785dd5d121343ef2d7e7ea1a245c06e409e35e6dc2405829fbac3fcd",
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.0/sing-box-1.0-linux-amd64.tar.gz",
    },
    {
        "backend": "sing-box",
        "version": "1.0",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "sing-box-1.0-windows-amd64.zip",
        "size": 7136317,
        "sha256": "5c3073f2d97f182ff702613c8ee9452f705654af0c6e6681714df348823000c7",
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.0/sing-box-1.0-windows-amd64.zip",
    },
    {
        "backend": "sing-box",
        "version": "1.13.14",
        "platform": "linux-amd64-glibc",
        "format": "tar.gz",
        "name": "sing-box-1.13.14-linux-amd64-glibc.tar.gz",
        "size": 24614103,
        "sha256": "aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6",
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64-glibc.tar.gz",
    },
    {
        "backend": "sing-box",
        "version": "1.13.14",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "sing-box-1.13.14-windows-amd64.zip",
        "size": 20961591,
        "sha256": "f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341",
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-windows-amd64.zip",
    },
    {
        "backend": "xray",
        "version": "1.0.0",
        "platform": "linux-amd64",
        "format": "zip",
        "name": "Xray-linux-64.zip",
        "size": 8352563,
        "sha256": "f0c72a758395c208fb9298ee877e868d5030c35ca7a249fe4b983925083ec28d",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v1.0.0/Xray-linux-64.zip",
    },
    {
        "backend": "xray",
        "version": "1.0.0",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "Xray-windows-64.zip",
        "size": 8382059,
        "sha256": "9b525f9945aac08a0752055cfd3efa7779a8d86dc2d4bc1edfa49b6300593cd1",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v1.0.0/Xray-windows-64.zip",
    },
    {
        "backend": "xray",
        "version": "26.3.27",
        "platform": "linux-amd64",
        "format": "zip",
        "name": "Xray-linux-64.zip",
        "size": 21136402,
        "sha256": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip",
    },
    {
        "backend": "xray",
        "version": "26.3.27",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "Xray-windows-64.zip",
        "size": 20913304,
        "sha256": "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip",
    },
    {
        "backend": "v2ray",
        "version": "4.22.0",
        "platform": "linux-amd64",
        "format": "zip",
        "name": "v2ray-linux-64.zip",
        "size": 12129836,
        "sha256": "23be032742a212937549904ed7713217e8978e0e10854fe3790a0718ff1d9440",
        "url": "https://github.com/v2fly/v2ray-core/releases/download/v4.22.0/v2ray-linux-64.zip",
    },
    {
        "backend": "v2ray",
        "version": "4.22.0",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "v2ray-windows-64.zip",
        "size": 18154855,
        "sha256": "2d006d8412382afd63dd8a1aaece46bec3df1d5fd5033748c0c698a25b54a3f3",
        "url": "https://github.com/v2fly/v2ray-core/releases/download/v4.22.0/v2ray-windows-64.zip",
    },
    {
        "backend": "v2ray",
        "version": "5.51.2",
        "platform": "linux-amd64",
        "format": "zip",
        "name": "v2ray-linux-64.zip",
        "size": 19194904,
        "sha256": "7d034da48fb445fe0acd477ffc8fa9712c68cdf02f1431e3ed9c54c10bf81db3",
        "url": "https://github.com/v2fly/v2ray-core/releases/download/v5.51.2/v2ray-linux-64.zip",
    },
    {
        "backend": "v2ray",
        "version": "5.51.2",
        "platform": "windows-amd64",
        "format": "zip",
        "name": "v2ray-windows-64.zip",
        "size": 19249527,
        "sha256": "558cc0c017b4b24ae65f69b9d68ed4e99d8040115a1231ea7632d30701b82c50",
        "url": "https://github.com/v2fly/v2ray-core/releases/download/v5.51.2/v2ray-windows-64.zip",
    },
)

LIMITS = {
    "compressed_bytes": 256 * 1024 * 1024,
    "members": 4096,
    "files": 4096,
    "directories": 4096,
    "path_depth": 32,
    "component_bytes": 255,
    "path_bytes": 1024,
    "aggregate_path_bytes": 4 * 1024 * 1024,
    "largest_file_bytes": 512 * 1024 * 1024,
    "total_extracted_bytes": 768 * 1024 * 1024,
    "zip_central_directory_bytes": 32 * 1024 * 1024,
    "tar_raw_stream_bytes": 1024 * 1024 * 1024,
    "extension_bytes": 64 * 1024,
    "total_extension_bytes": 1024 * 1024,
}

_EOCD = struct.Struct("<4s4H2LH")
_RUNTIME_LIMIT_ATTRIBUTES = {
    "compressed_bytes": "maximum_compressed_bytes",
    "members": "maximum_members",
    "files": "maximum_files",
    "directories": "maximum_directories",
    "path_depth": "maximum_path_depth",
    "component_bytes": "maximum_component_bytes",
    "path_bytes": "maximum_path_bytes",
    "aggregate_path_bytes": "maximum_total_path_bytes",
    "largest_file_bytes": "maximum_file_bytes",
    "total_extracted_bytes": "maximum_extracted_bytes",
    "zip_central_directory_bytes": "maximum_zip_central_directory_bytes",
    "tar_raw_stream_bytes": "maximum_tar_stream_bytes",
    "extension_bytes": "maximum_extension_bytes",
    "total_extension_bytes": "maximum_total_extension_bytes",
}


def _cache_name(item):
    return "%s-%s-%s.%s" % (
        item["backend"],
        item["version"],
        item["platform"],
        item["format"],
    )


def _sha256_and_size(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def _download(item, destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".%s." % destination.name, dir=str(destination.parent))
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with requests.get(item["url"], stream=True, timeout=(15, 60)) as response:
            response.raise_for_status()
            with temporary.open("wb") as output:
                for block in response.iter_content(chunk_size=1024 * 1024):
                    if block:
                        output.write(block)
                output.flush()
                os.fsync(output.fileno())
        size, digest = _sha256_and_size(temporary)
        if size != item["size"] or digest != item["sha256"]:
            raise ValueError("downloaded archive identity mismatch: %s" % item["url"])
        os.replace(str(temporary), str(destination))
    finally:
        if temporary.exists():
            temporary.unlink()


def _parts(name):
    normalized = unicodedata.normalize("NFC", name.replace("\\", "/")).rstrip("/")
    return tuple(part for part in PurePosixPath(normalized).parts if part not in ("", "."))


def _path_metrics(entries):
    explicit_directories = set()
    implicit_directories = set()
    aggregate = 0
    maximum_depth = 0
    maximum_component = 0
    maximum_path = 0
    for name, is_directory in entries:
        parts = _parts(name)
        encoded_path = "/".join(parts).encode("utf-8")
        aggregate += len(encoded_path)
        maximum_depth = max(maximum_depth, len(parts))
        maximum_path = max(maximum_path, len(encoded_path))
        maximum_component = max(maximum_component, max((len(part.encode("utf-8")) for part in parts), default=0))
        parents = parts if is_directory else parts[:-1]
        for index in range(1, len(parents) + 1):
            implicit_directories.add("/".join(parts[:index]))
        if is_directory:
            explicit_directories.add("/".join(parts))
    return {
        "explicit_directories": len(explicit_directories),
        "implicit_directories": len(implicit_directories.difference(explicit_directories)),
        "directories": len(implicit_directories),
        "path_depth": maximum_depth,
        "component_bytes": maximum_component,
        "path_bytes": maximum_path,
        "aggregate_path_bytes": aggregate,
    }


def _zip_central_directory(path):
    size = Path(path).stat().st_size
    with Path(path).open("rb") as stream:
        window_size = min(size, 65557)
        stream.seek(size - window_size)
        window = stream.read(window_size)
    offset = window.rfind(b"PK\x05\x06")
    if offset < 0 or offset + _EOCD.size > len(window):
        raise ValueError("ZIP EOCD is missing: %s" % path)
    fields = _EOCD.unpack_from(window, offset)
    comment_length = fields[-1]
    if offset + _EOCD.size + comment_length != len(window):
        raise ValueError("ZIP EOCD does not end at the archive boundary: %s" % path)
    return fields[5], fields[6], fields[4]


def _gzip_container(path):
    payload = Path(path).read_bytes()
    if len(payload) < 10 or payload[:3] != b"\x1f\x8b\x08":
        raise ValueError("invalid GZip header: %s" % path)
    flags = []
    members = 0
    remaining = payload
    while remaining:
        if len(remaining) < 10 or remaining[:3] != b"\x1f\x8b\x08":
            raise ValueError("GZip trailing data is not another member: %s" % path)
        flags.append(int(remaining[3]))
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decompressor.decompress(remaining)
        if not decompressor.eof:
            raise ValueError("truncated GZip member: %s" % path)
        members += 1
        remaining = decompressor.unused_data
    return members, flags


def _analyze_zip(path):
    central_size, central_offset, central_entries = _zip_central_directory(path)
    entries = []
    file_sizes = []
    methods = set()
    flags = set()
    with zipfile.ZipFile(str(path), "r") as archive:
        members = archive.infolist()
        if len(members) != central_entries:
            raise ValueError("ZIP central-directory entry count mismatch: %s" % path)
        for member in members:
            is_directory = member.is_dir()
            entries.append((member.filename, is_directory))
            methods.add(int(member.compress_type))
            flags.add(int(member.flag_bits))
            if not is_directory:
                file_sizes.append(int(member.file_size))
    metrics = _path_metrics(entries)
    metrics.update(
        {
            "members": len(entries),
            "files": len(file_sizes),
            "largest_file_bytes": max(file_sizes or [0]),
            "total_extracted_bytes": sum(file_sizes),
            "zip_central_directory_bytes": central_size,
            "zip_central_directory_offset": central_offset,
            "zip_methods": sorted(methods),
            "zip_flags": sorted(flags),
            "tar_raw_stream_bytes": 0,
            "extension_bytes": 0,
            "total_extension_bytes": 0,
            "tar_extension_types": [],
            "gzip_members": 0,
            "gzip_flags": [],
        }
    )
    return metrics


def _tar_raw_metrics(path):
    import gzip

    raw_size = 0
    largest_extension = 0
    total_extension = 0
    extension_types = set()
    zero_blocks = 0
    with gzip.open(str(path), "rb") as stream:
        while True:
            header = stream.read(512)
            raw_size += len(header)
            if not header:
                break
            if len(header) != 512:
                raise ValueError("truncated TAR header: %s" % path)
            if header == b"\0" * 512:
                zero_blocks += 1
                if zero_blocks == 2:
                    while True:
                        block = stream.read(1024 * 1024)
                        if not block:
                            break
                        raw_size += len(block)
                    break
                continue
            zero_blocks = 0
            raw_size_field = header[124:136].rstrip(b"\0 ") or b"0"
            size = int(raw_size_field, 8)
            type_flag = header[156:157] or b"\0"
            if type_flag in (b"g", b"x", b"L", b"K"):
                extension_types.add(type_flag.decode("ascii"))
                largest_extension = max(largest_extension, size)
                total_extension += size
            padded = (size + 511) // 512 * 512
            remaining = padded
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError("truncated TAR payload: %s" % path)
                remaining -= len(block)
                raw_size += len(block)
    gzip_members, gzip_flags = _gzip_container(path)
    return raw_size, largest_extension, total_extension, sorted(extension_types), gzip_members, gzip_flags


def _analyze_tar(path):
    entries = []
    file_sizes = []
    with tarfile.open(str(path), "r:gz") as archive:
        for member in archive:
            is_directory = member.isdir()
            entries.append((member.name, is_directory))
            if member.isfile():
                file_sizes.append(int(member.size))
    raw_size, largest_extension, total_extension, extension_types, gzip_members, gzip_flags = _tar_raw_metrics(path)
    metrics = _path_metrics(entries)
    metrics.update(
        {
            "members": len(entries),
            "files": len(file_sizes),
            "largest_file_bytes": max(file_sizes or [0]),
            "total_extracted_bytes": sum(file_sizes),
            "zip_central_directory_bytes": 0,
            "zip_central_directory_offset": 0,
            "zip_methods": [],
            "zip_flags": [],
            "tar_raw_stream_bytes": raw_size,
            "extension_bytes": largest_extension,
            "total_extension_bytes": total_extension,
            "tar_extension_types": extension_types,
            "gzip_members": gzip_members,
            "gzip_flags": gzip_flags,
        }
    )
    return metrics


def _analyze_gzip(path):
    import gzip

    extracted = 0
    with gzip.open(str(path), "rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            extracted += len(block)
    gzip_members, gzip_flags = _gzip_container(path)
    return {
        "members": 1,
        "files": 1,
        "explicit_directories": 0,
        "implicit_directories": 0,
        "directories": 0,
        "path_depth": 1,
        "component_bytes": 0,
        "path_bytes": 0,
        "aggregate_path_bytes": 0,
        "largest_file_bytes": extracted,
        "total_extracted_bytes": extracted,
        "zip_central_directory_bytes": 0,
        "zip_central_directory_offset": 0,
        "zip_methods": [],
        "zip_flags": [],
        "tar_raw_stream_bytes": 0,
        "extension_bytes": 0,
        "total_extension_bytes": 0,
        "tar_extension_types": [],
        "gzip_members": gzip_members,
        "gzip_flags": gzip_flags,
    }


def _measure(item, cache):
    path = Path(cache) / _cache_name(item)
    size, digest = _sha256_and_size(path)
    if size != item["size"] or digest != item["sha256"]:
        raise ValueError("cached archive identity mismatch: %s" % path)
    if item["format"] == "zip":
        metrics = _analyze_zip(path)
    elif item["format"] == "tar.gz":
        metrics = _analyze_tar(path)
    else:
        metrics = _analyze_gzip(path)
    value = dict(item)
    value["compressed_bytes"] = size
    value.update(metrics)
    return value


def _maximum(records, key):
    return max(record[key] for record in records)


def _maxima(records):
    return {key: _maximum(records, key) for key in LIMITS}


def _validate_headroom(maxima):
    runtime_limits = ArchiveLimits()
    for key, limit in LIMITS.items():
        if getattr(runtime_limits, _RUNTIME_LIMIT_ATTRIBUTES[key]) != limit:
            raise ValueError("runtime archive limit differs from the measured corpus contract: %s" % key)
        measured = maxima[key]
        if measured * 4 > limit:
            raise ValueError("archive safety limit lacks four-times headroom: %s" % key)


def _write_measurements(cache, output):
    records = [_measure(item, cache) for item in PINNED_ARTIFACTS]
    maxima = _maxima(records)
    _validate_headroom(maxima)
    value = {"limits": LIMITS, "maxima": maxima, "artifacts": records}
    Path(output).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate_measurements(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"limits", "maxima", "artifacts"}:
        raise ValueError("invalid archive corpus measurement object")
    if value["limits"] != LIMITS:
        raise ValueError("archive corpus limits differ from the reviewed source limits")
    expected = [(item["backend"], item["version"], item["platform"]) for item in PINNED_ARTIFACTS]
    actual = [(item["backend"], item["version"], item["platform"]) for item in value["artifacts"]]
    if actual != expected:
        raise ValueError("archive corpus artifact roster differs from the pinned roster")
    maxima = _maxima(value["artifacts"])
    if value["maxima"] != maxima:
        raise ValueError("archive corpus maxima do not match the measured artifacts")
    _validate_headroom(maxima)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path("build/archive-corpus"))
    parser.add_argument("--output", type=Path, default=Path("tools/archive_corpus_measurements.json"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.validate_only:
        _validate_measurements(arguments.output)
        return 0
    arguments.cache.mkdir(parents=True, exist_ok=True)
    if arguments.download:
        for item in PINNED_ARTIFACTS:
            destination = arguments.cache / _cache_name(item)
            if destination.exists() and _sha256_and_size(destination) == (item["size"], item["sha256"]):
                continue
            _download(item, destination)
    _write_measurements(arguments.cache, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
