import binascii
import gzip
import io
import multiprocessing
import struct
import sys
import tarfile
import zipfile
from types import SimpleNamespace

import pytest

import jerryproxy.backend.archive as archive_module
import jerryproxy.backend.archive_preflight as archive_preflight_module
from jerryproxy.backend.archive import ArchiveLimits, extract_archive
from jerryproxy.backend.archive_preflight import preflight_gzip, preflight_tar_gzip, preflight_zip
from jerryproxy.errors import ArchiveError


def _limits(**overrides):
    values = {
        "maximum_compressed_bytes": 1024 * 1024,
        "maximum_members": 32,
        "maximum_file_bytes": 1024 * 1024,
        "maximum_extracted_bytes": 2 * 1024 * 1024,
        "maximum_zip_central_directory_bytes": 1024 * 1024,
        "maximum_tar_stream_bytes": 2 * 1024 * 1024,
        "maximum_extension_bytes": 64 * 1024,
        "maximum_total_extension_bytes": 1024 * 1024,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return output.getvalue()


def _descriptor_zip_bytes():
    class NonSeekable(io.BytesIO):
        def seekable(self):
            return False

        def seek(self, *args):
            raise io.UnsupportedOperation

    output = NonSeekable()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xray", b"payload")
    return output.getvalue()


def _central_offset(data):
    eocd = data.rfind(b"PK\x05\x06")
    return struct.unpack_from("<I", data, eocd + 16)[0]


def _zip64_archive(data):
    data = bytearray(data)
    eocd = data.rfind(b"PK\x05\x06")
    count = struct.unpack_from("<H", data, eocd + 10)[0]
    directory_size = struct.unpack_from("<I", data, eocd + 12)[0]
    directory_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    zip64 = struct.pack(
        "<4sQ2H2I4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        directory_size,
        directory_offset,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd, 1)
    legacy = bytearray(data[eocd:])
    struct.pack_into("<HHII", legacy, 8, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    return bytes(data[:eocd] + zip64 + locator + legacy)


def _zip64_central_entry(data):
    data = bytearray(data)
    central = _central_offset(data)
    eocd = data.rfind(b"PK\x05\x06")
    compressed_size, uncompressed_size = struct.unpack_from("<II", data, central + 20)
    name_length = struct.unpack_from("<H", data, central + 28)[0]
    local_offset = struct.unpack_from("<I", data, central + 42)[0]
    zip64_values = struct.pack(
        "<QQQI",
        uncompressed_size,
        compressed_size,
        local_offset,
        0,
    )
    zip64_extra = struct.pack("<HH", 1, len(zip64_values)) + zip64_values
    struct.pack_into("<II", data, central + 20, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into("<H", data, central + 28, name_length)
    struct.pack_into("<HH", data, central + 30, len(zip64_extra), 0)
    struct.pack_into("<H", data, central + 34, 0xFFFF)
    struct.pack_into("<I", data, central + 42, 0xFFFFFFFF)
    extra_offset = central + 46 + name_length
    data[extra_offset:extra_offset] = zip64_extra
    eocd += len(zip64_extra)
    directory_size = struct.unpack_from("<I", data, eocd + 12)[0]
    struct.pack_into("<I", data, eocd + 12, directory_size + len(zip64_extra))
    return bytes(data)


def _tar_gzip_bytes(members, pax_headers=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            if pax_headers:
                info.pax_headers = dict(pax_headers)
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _pax_record(key, value):
    body = ("%s=%s\n" % (key, value)).encode("utf-8")
    length = len(body) + 2
    while True:
        record = ("%d " % length).encode("ascii") + body
        if len(record) == length:
            return record
        length = len(record)


def _pax_record_with_size(key, size):
    minimum = max(0, size - len(key) - 32)
    for value_size in range(minimum, size):
        record = _pax_record(key, "x" * value_size)
        if len(record) == size:
            return record
    raise AssertionError("unable to construct an exact-size PAX record")


def _pax_payload_with_size(size, prefix):
    payload = bytearray()
    index = 0
    remaining = size
    while remaining > 4096:
        payload.extend(_pax_record_with_size("%s-%d" % (prefix, index), 4096))
        remaining -= 4096
        index += 1
    if remaining:
        payload.extend(_pax_record_with_size("%s-%d" % (prefix, index), remaining))
    assert len(payload) == size
    return bytes(payload)


def _raw_tar_member(name, payload=b"", type_flag=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = type_flag
    info.size = len(payload)
    header = info.tobuf(format=tarfile.PAX_FORMAT, encoding="utf-8", errors="strict")
    padding = b"\0" * ((-len(payload)) % 512)
    return header + payload + padding


def _raw_tar(*members):
    return b"".join(members) + b"\0" * 1024


def _rewrite_tar_checksum(raw, offset=0):
    raw[offset + 148 : offset + 156] = b"        "
    checksum = sum(raw[offset : offset + 512])
    raw[offset + 148 : offset + 156] = ("%06o\0 " % checksum).encode("ascii")


def _tar_with_declared_pax_size(size):
    header = bytearray(_raw_tar_member("pax", b"", tarfile.XHDTYPE)[:512])
    encoded = size.to_bytes(12, "big")
    header[124:136] = bytes((encoded[0] | 0x80,)) + encoded[1:]
    _rewrite_tar_checksum(header)
    return gzip.compress(bytes(header))


def _measure_declared_pax_rss(data, connection):
    import resource

    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    try:
        preflight_tar_gzip(io.BytesIO(data), _limits())
    except ArchiveError as error:
        message = str(error)
    else:
        message = "accepted"
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    connection.send((message, float(after - before) / divisor))
    connection.close()


def test_zip_preflight_returns_compact_member_metadata():
    plan = preflight_zip(io.BytesIO(_zip_bytes([("bin/xray", b"payload")])), _limits())

    assert plan.entry_count == 1
    assert plan.entries[0].name == "bin/xray"
    assert plan.entries[0].uncompressed_size == 7
    assert plan.entries[0].method == zipfile.ZIP_DEFLATED


def test_zip_preflight_accepts_maximum_legal_comment_and_fake_signature():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("xray", b"x")
        archive.comment = b"PK\x05\x06" + b"x" * (65535 - 4)

    assert preflight_zip(io.BytesIO(output.getvalue()), _limits()).entry_count == 1


def test_zip_preflight_accepts_valid_data_descriptor():
    plan = preflight_zip(io.BytesIO(_descriptor_zip_bytes()), _limits())
    assert plan.entries[0].flags & 0x0008


def test_zip_preflight_rejects_trailing_junk_and_multidisk():
    data = bytearray(_zip_bytes([("xray", b"x")]))
    with pytest.raises(ArchiveError, match="end record"):
        preflight_zip(io.BytesIO(bytes(data) + b"junk"), _limits())

    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd + 4, 1)
    with pytest.raises(ArchiveError, match="multi-disk"):
        preflight_zip(io.BytesIO(data), _limits())

    data = bytearray(_zip_bytes([("xray", b"x")]))
    eocd = data.rfind(b"PK\x05\x06")
    hidden = data[:eocd] + b"junk" + data[eocd:]
    with pytest.raises(ArchiveError, match="adjacent"):
        preflight_zip(io.BytesIO(hidden), _limits())


def test_zip_preflight_rejects_zip64_sentinel_without_records():
    data = bytearray(_zip_bytes([("xray", b"x")]))
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd + 12, 0xFFFFFFFF)

    with pytest.raises(ArchiveError, match="ZIP64"):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_enforces_directory_and_entry_limits():
    data = _zip_bytes([("one", b"1"), ("two", b"2")], zipfile.ZIP_STORED)
    with pytest.raises(ArchiveError, match="entries"):
        preflight_zip(io.BytesIO(data), _limits(maximum_members=1))

    eocd = data.rfind(b"PK\x05\x06")
    size = struct.unpack_from("<I", data, eocd + 12)[0]
    with pytest.raises(ArchiveError, match="central directory"):
        preflight_zip(io.BytesIO(data), _limits(maximum_zip_central_directory_bytes=size - 1))


def test_zip_preflight_accepts_exact_central_directory_limit():
    data = _zip_bytes([("one", b"1"), ("two", b"2")], zipfile.ZIP_STORED)
    eocd = data.rfind(b"PK\x05\x06")
    directory_size = struct.unpack_from("<I", data, eocd + 12)[0]

    plan = preflight_zip(
        io.BytesIO(data),
        _limits(maximum_zip_central_directory_bytes=directory_size),
    )

    assert plan.entry_count == 2


def test_zip_preflight_rejects_central_directory_limit_plus_one():
    data = _zip_bytes([("one", b"1"), ("two", b"2")], zipfile.ZIP_STORED)
    eocd = data.rfind(b"PK\x05\x06")
    directory_size = struct.unpack_from("<I", data, eocd + 12)[0]

    with pytest.raises(ArchiveError, match="central directory exceeds"):
        preflight_zip(
            io.BytesIO(data),
            _limits(maximum_zip_central_directory_bytes=directory_size - 1),
        )


def test_zip_preflight_rejects_unsupported_flags_and_methods():
    data = bytearray(_zip_bytes([("xray", b"x")], zipfile.ZIP_STORED))
    central = _central_offset(data)
    struct.pack_into("<H", data, central + 8, 1)
    struct.pack_into("<H", data, 6, 1)
    with pytest.raises(ArchiveError, match="flag"):
        preflight_zip(io.BytesIO(data), _limits())

    data = bytearray(_zip_bytes([("xray", b"x")], zipfile.ZIP_STORED))
    central = _central_offset(data)
    struct.pack_into("<H", data, central + 10, 99)
    struct.pack_into("<H", data, 8, 99)
    with pytest.raises(ArchiveError, match="compression method"):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_rejects_local_central_disagreement():
    data = bytearray(_zip_bytes([("xray", b"payload")]))
    data[30:34] = b"yyyy"

    with pytest.raises(ArchiveError, match="name disagrees"):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_rejects_duplicate_local_offsets():
    data = bytearray(_zip_bytes([("one", b"1"), ("two", b"2")], zipfile.ZIP_STORED))
    central = _central_offset(data)
    first_name_length, first_extra_length, first_comment_length = struct.unpack_from("<HHH", data, central + 28)
    second = central + 46 + first_name_length + first_extra_length + first_comment_length
    struct.pack_into("<I", data, second + 42, 0)

    with pytest.raises(ArchiveError, match="duplicate local"):
        preflight_zip(io.BytesIO(data), _limits())


@pytest.mark.parametrize("value", (None, 0, -1, True, "1"))
def test_archive_preflight_rejects_invalid_limits(value):
    with pytest.raises(ValueError, match="positive integer"):
        preflight_zip(
            io.BytesIO(_zip_bytes([("xray", b"x")])),
            _limits(maximum_members=value),
        )


def test_zip_preflight_rejects_ambiguous_end_records():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("xray", b"x")
        archive.comment = b"PK\x05\x06" + b"\0" * 16 + b"\0\0"

    with pytest.raises(ArchiveError, match="unambiguous end record"):
        preflight_zip(io.BytesIO(output.getvalue()), _limits())


def test_zip_preflight_accepts_consistent_zip64_end_records():
    data = _zip64_archive(_zip_bytes([("xray", b"payload")]))

    plan = preflight_zip(io.BytesIO(data), _limits())

    assert plan.entry_count == 1
    assert plan.entries[0].name == "xray"


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("count", "entry counts"),
        ("locator-disk", "multi-disk ZIP64"),
        ("locator-offset", "ZIP64 end record offset"),
        ("record-signature", "ZIP64 end record"),
        ("record-size", "malformed ZIP64"),
        ("record-disks", "multi-disk ZIP64"),
        ("legacy-mismatch", "inconsistent ZIP and ZIP64"),
    ],
)
def test_zip_preflight_rejects_inconsistent_zip64_metadata(case, message):
    data = bytearray(_zip64_archive(_zip_bytes([("xray", b"payload")])))
    eocd = data.rfind(b"PK\x05\x06")
    locator = eocd - 20
    zip64 = struct.unpack_from("<Q", data, locator + 8)[0]
    if case == "count":
        struct.pack_into("<H", data, eocd + 8, 1)
        struct.pack_into("<H", data, eocd + 10, 2)
    elif case == "locator-disk":
        struct.pack_into("<I", data, locator + 4, 1)
    elif case == "locator-offset":
        struct.pack_into("<Q", data, locator + 8, locator)
    elif case == "record-signature":
        data[zip64 : zip64 + 4] = b"NOPE"
    elif case == "record-size":
        struct.pack_into("<Q", data, zip64 + 4, 43)
    elif case == "record-disks":
        struct.pack_into("<I", data, zip64 + 16, 1)
    else:
        struct.pack_into("<H", data, eocd + 8, 2)
        struct.pack_into("<H", data, eocd + 10, 2)

    with pytest.raises(ArchiveError, match=message):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_accepts_local_zip64_size_extra():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        with archive.open("xray", "w", force_zip64=True) as member:
            member.write(b"payload")

    plan = preflight_zip(io.BytesIO(output.getvalue()), _limits())

    assert plan.entries[0].uncompressed_size == 7


def test_zip_preflight_accepts_complete_central_zip64_member_metadata():
    data = _zip64_central_entry(_zip_bytes([("xray", b"payload")]))

    plan = preflight_zip(io.BytesIO(data), _limits())

    assert plan.entry_count == 1
    assert plan.entries[0].name == "xray"
    assert plan.entries[0].uncompressed_size == 7


def test_zip_preflight_rejects_redundant_zip64_extra_without_sentinels():
    info = zipfile.ZipInfo("xray")
    info.extra = struct.pack("<HHQQQ", 0x0001, 24, 999, 999, 999)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(info, b"payload")

    with pytest.raises(ArchiveError, match="unexpected ZIP64 extra field"):
        preflight_zip(io.BytesIO(output.getvalue()), _limits())


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("option-flags", "option flags require deflate"),
        ("central-header", "central directory header"),
        ("central-disk", "multi-disk ZIP entries"),
        ("file-limit", "member exceeds"),
        ("total-limit", "expanded content"),
        ("name-encoding", "name encoding"),
        ("local-offset", "local ZIP header offset"),
        ("local-header", "local ZIP header"),
        ("local-extension", "extension data"),
        ("local-flags", "flags disagree"),
        ("local-crc", "sizes or CRC disagree"),
        ("member-overlap", "overlaps the central directory"),
    ],
)
def test_zip_preflight_rejects_cross_structure_disagreement(case, message):
    entries = [("xray", b"payload"), ("other", b"second")]
    data = bytearray(_zip_bytes(entries, zipfile.ZIP_STORED))
    central = _central_offset(data)
    if case == "option-flags":
        struct.pack_into("<H", data, 6, 0x0002)
        struct.pack_into("<H", data, central + 8, 0x0002)
    elif case == "central-header":
        data[central : central + 4] = b"NOPE"
    elif case == "central-disk":
        struct.pack_into("<H", data, central + 34, 1)
    elif case == "file-limit":
        with pytest.raises(ArchiveError, match=message):
            preflight_zip(io.BytesIO(data), _limits(maximum_file_bytes=6))
        return
    elif case == "total-limit":
        with pytest.raises(ArchiveError, match=message):
            preflight_zip(io.BytesIO(data), _limits(maximum_extracted_bytes=12))
        return
    elif case == "name-encoding":
        data[30] = 0xFF
        data[central + 46] = 0xFF
        struct.pack_into("<H", data, 6, 0x0800)
        struct.pack_into("<H", data, central + 8, 0x0800)
    elif case == "local-offset":
        struct.pack_into("<I", data, central + 42, central)
    elif case == "local-header":
        data[:4] = b"NOPE"
    elif case == "local-extension":
        struct.pack_into("<H", data, 28, 65)
        with pytest.raises(ArchiveError, match=message):
            preflight_zip(io.BytesIO(data), _limits(maximum_extension_bytes=64))
        return
    elif case == "local-flags":
        struct.pack_into("<H", data, 6, 0x0008)
    elif case == "local-crc":
        struct.pack_into("<I", data, 14, 0)
    else:
        struct.pack_into("<I", data, 18, central)
        struct.pack_into("<I", data, central + 20, central)

    with pytest.raises(ArchiveError, match=message):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_rejects_truncated_and_duplicate_extra_fields():
    info = zipfile.ZipInfo("xray")
    info.extra = struct.pack("<HH", 0xCAFE, 1) + b"x"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(info, b"payload")
    truncated = bytearray(output.getvalue())
    central = _central_offset(truncated)
    extra_start = central + 46 + len(info.filename)
    struct.pack_into("<H", truncated, extra_start + 2, 2)
    with pytest.raises(ArchiveError, match="truncated ZIP extra field"):
        preflight_zip(io.BytesIO(truncated), _limits())

    duplicate = zipfile.ZipInfo("xray")
    field = struct.pack("<HH", 0xCAFE, 1) + b"x"
    duplicate.extra = field + field
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(duplicate, b"payload")
    with pytest.raises(ArchiveError, match="duplicate ZIP extra field"):
        preflight_zip(io.BytesIO(output.getvalue()), _limits())


def test_zip_preflight_rejects_bad_data_descriptor():
    data = bytearray(_descriptor_zip_bytes())
    descriptor = data.find(b"PK\x07\x08")
    assert descriptor > 0
    data[descriptor + 4] ^= 1

    with pytest.raises(ArchiveError, match="data descriptor disagrees"):
        preflight_zip(io.BytesIO(data), _limits())


def test_gzip_preflight_verifies_crc_size_and_single_member_policy():
    data = gzip.compress(b"payload")
    plan = preflight_gzip(io.BytesIO(data), _limits())
    assert plan.expanded_size == 7

    corrupt = bytearray(data)
    corrupt[-8] ^= 1
    with pytest.raises(ArchiveError, match="CRC"):
        preflight_gzip(io.BytesIO(corrupt), _limits())

    with pytest.raises(ArchiveError, match="trailing|concatenated"):
        preflight_gzip(io.BytesIO(data + gzip.compress(b"second")), _limits())


def test_gzip_preflight_bounds_optional_header_fields():
    payload = gzip.compress(b"x")
    header = bytearray(payload[:10])
    header[3] |= 0x08
    data = bytes(header) + b"abc\0" + payload[10:]

    with pytest.raises(ArchiveError, match="extension"):
        preflight_gzip(io.BytesIO(data), _limits(maximum_extension_bytes=3))


def test_gzip_preflight_verifies_optional_header_crc():
    payload = gzip.compress(b"x")
    header = bytearray(payload[:10])
    header[3] |= 0x02
    checksum = struct.pack("<H", binascii.crc32(header) & 0xFFFF)
    assert preflight_gzip(io.BytesIO(bytes(header) + checksum + payload[10:]), _limits()).expanded_size == 1

    checksum = bytes((checksum[0] ^ 1, checksum[1]))
    with pytest.raises(ArchiveError, match="header CRC"):
        preflight_gzip(io.BytesIO(bytes(header) + checksum + payload[10:]), _limits())


def test_gzip_preflight_enforces_compressed_and_expanded_limits():
    data = gzip.compress(b"12345")
    with pytest.raises(ArchiveError, match="compressed"):
        preflight_gzip(io.BytesIO(data), _limits(maximum_compressed_bytes=len(data) - 1))
    with pytest.raises(ArchiveError, match="expanded"):
        preflight_gzip(io.BytesIO(data), _limits(maximum_extracted_bytes=4, maximum_file_bytes=4))


def test_gzip_preflight_accepts_bounded_extra_name_and_comment_fields():
    payload = gzip.compress(b"payload")
    header = bytearray(payload[:10])
    header[3] |= 0x1C
    optional = struct.pack("<H", 3) + b"abc" + b"name\0" + b"comment\0"
    data = bytes(header) + optional + payload[10:]

    assert preflight_gzip(io.BytesIO(data), _limits()).expanded_size == 7


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("magic", "invalid GZip header"),
        ("method", "invalid GZip header"),
        ("reserved", "reserved GZip header flags"),
        ("truncated-header", "truncated GZip header"),
        ("truncated-extra-length", "truncated GZip extra field"),
        ("truncated-extra", "truncated GZip extra field"),
        ("truncated-name", "truncated GZip extension|extension exceeds"),
        ("deflate", "invalid GZip deflate stream"),
        ("trailer", "truncated GZip trailer|truncated GZip deflate stream"),
        ("size", "GZip size does not match"),
    ],
)
def test_gzip_preflight_rejects_hostile_stream_structure(case, message):
    data = bytearray(gzip.compress(b"payload"))
    limits = _limits()
    if case == "magic":
        data[0] = 0
    elif case == "method":
        data[2] = 0
    elif case == "reserved":
        data[3] |= 0x20
    elif case == "truncated-header":
        data = data[:9]
    elif case == "truncated-extra-length":
        data[3] |= 0x04
        data = data[:11]
    elif case == "truncated-extra":
        data[3] |= 0x04
        data = data[:10] + struct.pack("<H", 4) + b"x"
    elif case == "truncated-name":
        data[3] |= 0x08
        data = data[:10] + b"unterminated"
        limits = _limits(maximum_extension_bytes=64)
    elif case == "deflate":
        data[10:12] = b"\xff\xff"
    elif case == "trailer":
        data = data[:-5]
    else:
        struct.pack_into("<I", data, len(data) - 4, 8)

    with pytest.raises(ArchiveError, match=message):
        preflight_gzip(io.BytesIO(data), limits)


def test_archive_preflight_requires_a_seekable_binary_handle():
    class Unseekable(io.BytesIO):
        def seek(self, *args, **kwargs):
            raise OSError("seek denied")

    with pytest.raises(ArchiveError, match="seekable binary handle"):
        preflight_gzip(Unseekable(gzip.compress(b"payload")), _limits())


def test_archive_preflight_rejects_a_negative_reported_size():
    class NegativeSize(io.BytesIO):
        calls = 0

        def tell(self):
            self.calls += 1
            return -1 if self.calls == 2 else super().tell()

    with pytest.raises(ArchiveError, match="invalid archive size"):
        preflight_gzip(NegativeSize(gzip.compress(b"payload")), _limits())


def test_zip_preflight_rejects_compressed_and_extension_boundaries():
    data = _zip_bytes([("long-name", b"payload")])
    with pytest.raises(ArchiveError, match="compressed input"):
        preflight_zip(io.BytesIO(data), _limits(maximum_compressed_bytes=len(data) - 1))
    with pytest.raises(ArchiveError, match="extension data"):
        preflight_zip(io.BytesIO(data), _limits(maximum_extension_bytes=8))
    with pytest.raises(ArchiveError, match="aggregate ZIP extension"):
        preflight_zip(io.BytesIO(data), _limits(maximum_total_extension_bytes=8))


def test_zip_preflight_counts_local_and_central_member_names_in_aggregate_limit():
    data = _zip_bytes([("long-name", b"payload")])

    with pytest.raises(ArchiveError, match="aggregate ZIP extension"):
        preflight_zip(io.BytesIO(data), _limits(maximum_total_extension_bytes=17))

    plan = preflight_zip(io.BytesIO(data), _limits(maximum_total_extension_bytes=18))
    assert plan.entry_count == 1


def test_zip_preflight_rejects_truncated_extra_header_and_outside_directory():
    truncated = bytearray(_zip_bytes([("xray", b"payload")]))
    central = _central_offset(truncated)
    name_length = struct.unpack_from("<H", truncated, central + 28)[0]
    insert = central + 46 + name_length
    truncated[insert:insert] = b"x"
    struct.pack_into("<H", truncated, central + 30, 1)
    eocd = truncated.rfind(b"PK\x05\x06")
    directory_size = struct.unpack_from("<I", truncated, eocd + 12)[0]
    struct.pack_into("<I", truncated, eocd + 12, directory_size + 1)
    with pytest.raises(ArchiveError, match="truncated ZIP extra field"):
        preflight_zip(io.BytesIO(truncated), _limits())

    data = bytearray(_zip_bytes([("xray", b"payload")]))
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd + 16, eocd + 1)
    with pytest.raises(ArchiveError, match="outside the archive"):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_rejects_a_sentinel_eocd_without_locator_space():
    eocd = bytearray(22)
    eocd[:4] = b"PK\x05\x06"
    struct.pack_into("<I", eocd, 12, 0xFFFFFFFF)

    with pytest.raises(ArchiveError, match="missing ZIP64 locator"):
        preflight_zip(io.BytesIO(eocd), _limits())


def test_zip_preflight_rejects_unaccounted_central_directory_bytes():
    data = bytearray(_zip_bytes([("xray", b"payload")]))
    eocd = data.rfind(b"PK\x05\x06")
    directory_size = struct.unpack_from("<I", data, eocd + 12)[0]
    data[eocd:eocd] = b"x"
    eocd += 1
    struct.pack_into("<I", data, eocd + 12, directory_size + 1)

    with pytest.raises(ArchiveError, match="extra or missing data"):
        preflight_zip(io.BytesIO(data), _limits())


def test_zip_preflight_accepts_descriptor_without_signature():
    data = bytearray(_descriptor_zip_bytes())
    descriptor = data.find(b"PK\x07\x08")
    central = _central_offset(data)
    del data[descriptor : descriptor + 4]
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd + 16, central - 4)

    assert preflight_zip(io.BytesIO(data), _limits()).entry_count == 1


def test_gzip_preflight_rejects_extra_field_limit_and_deflate_truncation():
    payload = gzip.compress(b"payload")
    header = bytearray(payload[:10])
    header[3] |= 0x04
    data = bytes(header) + struct.pack("<H", 4) + b"abcd" + payload[10:]
    with pytest.raises(ArchiveError, match="extension exceeds"):
        preflight_gzip(io.BytesIO(data), _limits(maximum_extension_bytes=3))

    with pytest.raises(ArchiveError, match="truncated GZip deflate stream"):
        preflight_gzip(io.BytesIO(payload[:11]), _limits())


def test_tar_gzip_preflight_streams_regular_members():
    data = _tar_gzip_bytes([("bin/sing-box", b"payload")])
    plan = preflight_tar_gzip(io.BytesIO(data), _limits())

    assert plan.entry_count == 1
    assert plan.entries[0].name == "bin/sing-box"
    assert plan.entries[0].size == 7
    assert plan.raw_size % 512 == 0


def test_tar_gzip_preflight_accepts_exact_raw_stream_limit():
    raw = _raw_tar(_raw_tar_member("sing-box", b"payload"))

    plan = preflight_tar_gzip(
        io.BytesIO(gzip.compress(raw)),
        _limits(maximum_tar_stream_bytes=len(raw)),
    )

    assert plan.raw_size == len(raw)


def test_tar_gzip_preflight_rejects_raw_stream_limit_plus_one():
    raw = _raw_tar(_raw_tar_member("sing-box", b"payload"))

    with pytest.raises(ArchiveError, match="expanded content exceeds"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(raw)),
            _limits(maximum_tar_stream_bytes=len(raw) - 1),
        )


def test_tar_gzip_preflight_rejects_bad_checksum_and_missing_end_blocks():
    raw = bytearray()
    with tarfile.open(fileobj=io.BytesIO(), mode="w"):
        pass
    data = _tar_gzip_bytes([("sing-box", b"x")])
    raw.extend(gzip.decompress(data))
    raw[0] ^= 1
    with pytest.raises(ArchiveError, match="checksum"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(raw))), _limits())

    valid_raw = gzip.decompress(data)
    with pytest.raises(ArchiveError, match="end blocks"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(valid_raw[:1024])), _limits())


def test_tar_gzip_preflight_rejects_nonzero_member_padding():
    data = _tar_gzip_bytes([("sing-box", b"x")])
    raw = bytearray(gzip.decompress(data))
    raw[513] = 1
    with pytest.raises(ArchiveError, match="padding"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(raw))), _limits())


def test_tar_gzip_preflight_rejects_links_sparse_and_member_overrun():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        archive.addfile(link)
    with pytest.raises(ArchiveError, match="links|type"):
        preflight_tar_gzip(io.BytesIO(output.getvalue()), _limits())

    data = _tar_gzip_bytes([("one", b"1"), ("two", b"2")])
    with pytest.raises(ArchiveError, match="members"):
        preflight_tar_gzip(io.BytesIO(data), _limits(maximum_members=1))


def test_tar_gzip_preflight_applies_pax_path_and_rejects_sparse_keys():
    data = _tar_gzip_bytes([("placeholder", b"x")], {"path": "bin/sing-box"})
    plan = preflight_tar_gzip(io.BytesIO(data), _limits())
    assert plan.entries[0].name == "bin/sing-box"

    sparse = _tar_gzip_bytes([("sing-box", b"x")], {"GNU.sparse.size": "1"})
    with pytest.raises(ArchiveError, match="sparse"):
        preflight_tar_gzip(io.BytesIO(sparse), _limits())


def test_tar_gzip_preflight_bounds_pax_payload_before_parsing():
    data = _tar_gzip_bytes([("sing-box", b"x")], {"comment": "x" * 200})
    with pytest.raises(ArchiveError, match="extension"):
        preflight_tar_gzip(io.BytesIO(data), _limits(maximum_extension_bytes=64))


def test_tar_install_rejects_multi_gib_declared_pax_before_parser_or_tarfile(tmp_path, monkeypatch):
    archive = tmp_path / "hostile.tar.gz"
    archive.write_bytes(_tar_with_declared_pax_size(4 * 1024 * 1024 * 1024))
    parser_called = []
    tarfile_called = []

    def reject_parser(stream, size):
        parser_called.append((stream, size))
        raise AssertionError("PAX parser must not receive an oversized payload")

    def reject_tarfile(*args, **kwargs):
        tarfile_called.append((args, kwargs))
        raise AssertionError("tarfile must not open an archive rejected by raw preflight")

    monkeypatch.setattr(archive_preflight_module, "_parse_pax", reject_parser)
    monkeypatch.setattr(archive_module.tarfile, "open", reject_tarfile)

    with pytest.raises(ArchiveError, match="TAR extension exceeds"):
        extract_archive(
            archive,
            tmp_path / "output",
            "sing-box",
            limits=ArchiveLimits(),
        )

    assert parser_called == []
    assert tarfile_called == []
    assert not (tmp_path / "output").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ru_maxrss evidence is unavailable on Windows")
def test_tar_preflight_multi_gib_declared_pax_has_bounded_spawned_rss():
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(
        target=_measure_declared_pax_rss,
        args=(_tar_with_declared_pax_size(4 * 1024 * 1024 * 1024), sending),
    )

    process.start()
    sending.close()
    process.join(15)

    assert process.exitcode == 0
    message, rss_growth_mib = receiving.recv()
    receiving.close()
    assert "TAR extension exceeds" in message
    assert rss_growth_mib < 16


def test_tar_gzip_preflight_accepts_exact_pax_extension_limits():
    payloads = [_pax_payload_with_size(64 * 1024, "header-%d" % index) for index in range(16)]
    members = [_raw_tar_member("pax-%d" % index, payload, tarfile.XHDTYPE) for index, payload in enumerate(payloads)]
    members.append(_raw_tar_member("sing-box", b"x"))
    raw = _raw_tar(*members)

    plan = preflight_tar_gzip(
        io.BytesIO(gzip.compress(raw)),
        _limits(
            maximum_extension_bytes=64 * 1024,
            maximum_total_extension_bytes=1024 * 1024,
        ),
    )

    assert plan.entries[0].name == "sing-box"


@pytest.mark.parametrize(
    ("single_limit", "total_limit", "message"),
    [
        (64 * 1024 - 1, 1024 * 1024, "TAR extension exceeds"),
        (64 * 1024, 1024 * 1024 - 1, "aggregate TAR extensions exceed"),
    ],
)
def test_tar_gzip_preflight_rejects_pax_extension_limits_plus_one(single_limit, total_limit, message):
    payloads = [_pax_payload_with_size(64 * 1024, "header-%d" % index) for index in range(16)]
    members = [_raw_tar_member("pax-%d" % index, payload, tarfile.XHDTYPE) for index, payload in enumerate(payloads)]
    members.append(_raw_tar_member("sing-box", b"x"))

    with pytest.raises(ArchiveError, match=message):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(_raw_tar(*members))),
            _limits(
                maximum_extension_bytes=single_limit,
                maximum_total_extension_bytes=total_limit,
            ),
        )


def test_tar_gzip_preflight_parses_pax_records_without_buffering_the_extension(monkeypatch):
    payload = _pax_record("comment-a", "a" * 3000) + _pax_record("comment-b", "b" * 3000)
    raw = _raw_tar(
        _raw_tar_member("pax", payload, tarfile.XHDTYPE),
        _raw_tar_member("sing-box", b"x"),
    )
    requested = []
    original_read = archive_preflight_module._GzipStream.read

    def bounded_read(stream, size):
        requested.append(size)
        return original_read(stream, size)

    monkeypatch.setattr(archive_preflight_module._GzipStream, "read", bounded_read)
    plan = preflight_tar_gzip(
        io.BytesIO(gzip.compress(raw)),
        _limits(maximum_extension_bytes=len(payload)),
    )

    assert plan.entries[0].name == "sing-box"
    assert max(requested) <= 4096


def test_tar_gzip_preflight_accepts_base256_size_and_ustar_prefix():
    raw = bytearray(_raw_tar(_raw_tar_member("sing-box", b"x")))
    raw[124:136] = b"\x80" + (1).to_bytes(11, "big")
    _rewrite_tar_checksum(raw)
    plan = preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(raw))), _limits())
    assert plan.entries[0].size == 1

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("prefix/" + "n" * 95)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    plan = preflight_tar_gzip(io.BytesIO(output.getvalue()), _limits())
    assert plan.entries[0].name.startswith("prefix/")


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("number", "invalid TAR member size"),
        ("utf8", "invalid UTF-8 TAR member path"),
        ("nfc", "must use Unicode NFC"),
        ("empty", "empty TAR member path"),
        ("directory-size", "directory has a nonzero size"),
        ("file-limit", "TAR member exceeds"),
        ("total-limit", "TAR expanded content"),
    ],
)
def test_tar_gzip_preflight_rejects_invalid_member_metadata(case, message):
    raw = bytearray(_raw_tar(_raw_tar_member("sing-box", b"payload")))
    limits = _limits()
    if case == "number":
        raw[124:136] = b"00000000008\0"
        _rewrite_tar_checksum(raw)
    elif case == "utf8":
        raw[0] = 0xFF
        _rewrite_tar_checksum(raw)
    elif case == "nfc":
        raw[:100] = b"e\xcc\x81" + b"\0" * 97
        _rewrite_tar_checksum(raw)
    elif case == "empty":
        raw[:100] = b"\0" * 100
        _rewrite_tar_checksum(raw)
    elif case == "directory-size":
        raw[156:157] = b"5"
        _rewrite_tar_checksum(raw)
    elif case == "file-limit":
        limits = _limits(maximum_file_bytes=6)
    else:
        limits = _limits(maximum_extracted_bytes=6)

    with pytest.raises(ArchiveError, match=message):
        preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(raw))), limits)


def test_tar_gzip_preflight_accepts_gnu_longname_and_rejects_longlink():
    long_name = "nested/" + "n" * 120
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        member = tarfile.TarInfo(long_name)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    plan = preflight_tar_gzip(io.BytesIO(output.getvalue()), _limits())
    assert plan.entries[0].name == long_name

    longlink = _raw_tar_member("././@LongLink", b"target\0", tarfile.GNUTYPE_LONGLINK)
    regular = _raw_tar_member("sing-box", b"x")
    with pytest.raises(ArchiveError, match="longlink"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(_raw_tar(longlink, regular))), _limits())


def test_tar_gzip_preflight_accepts_exact_gnu_longname_extension_limit():
    payload = b"n" * (64 * 1024 - 1) + b"\0"
    longname = _raw_tar_member("././@LongLink", payload, tarfile.GNUTYPE_LONGNAME)
    regular = _raw_tar_member("placeholder", b"x")

    plan = preflight_tar_gzip(
        io.BytesIO(gzip.compress(_raw_tar(longname, regular))),
        _limits(maximum_extension_bytes=len(payload)),
    )

    assert plan.entries[0].name == payload[:-1].decode("utf-8")


def test_tar_gzip_preflight_rejects_gnu_longname_extension_limit_plus_one():
    payload = b"n" * (64 * 1024 - 1) + b"\0"
    longname = _raw_tar_member("././@LongLink", payload, tarfile.GNUTYPE_LONGNAME)
    regular = _raw_tar_member("placeholder", b"x")

    with pytest.raises(ArchiveError, match="TAR extension exceeds"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(_raw_tar(longname, regular))),
            _limits(maximum_extension_bytes=len(payload) - 1),
        )


def test_tar_gzip_preflight_rejects_duplicate_and_orphan_longname():
    first = _raw_tar_member("././@LongLink", b"first\0", tarfile.GNUTYPE_LONGNAME)
    second = _raw_tar_member("././@LongLink", b"second\0", tarfile.GNUTYPE_LONGNAME)
    regular = _raw_tar_member("sing-box", b"x")
    with pytest.raises(ArchiveError, match="duplicate GNU longname"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(_raw_tar(first, second, regular))),
            _limits(),
        )

    with pytest.raises(ArchiveError, match="not followed by a member"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(_raw_tar(first))), _limits())


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("length", "PAX record length"),
        ("overlong", "invalid or overlong PAX record"),
        ("record", "invalid PAX record"),
        ("utf8", "invalid UTF-8 PAX record"),
        ("duplicate", "duplicate effective PAX key"),
        ("size-text", "invalid PAX member size"),
        ("size-overflow", "invalid PAX member size"),
        ("size-mismatch", "PAX size disagrees"),
    ],
)
def test_tar_gzip_preflight_rejects_hostile_pax_records(case, message):
    if case == "duplicate":
        first_payload = _pax_record("comment", "one")
        second_payload = _pax_record("comment", "two")
        members = (
            _raw_tar_member("pax-1", first_payload, tarfile.XHDTYPE),
            _raw_tar_member("pax-2", second_payload, tarfile.XHDTYPE),
            _raw_tar_member("sing-box", b"x"),
        )
    else:
        value = "x"
        key = "comment"
        if case == "size-text":
            key, value = "size", "x"
        elif case == "size-overflow":
            key, value = "size", "9" * 128
        elif case == "size-mismatch":
            key, value = "size", "2"
        payload = bytearray(_pax_record(key, value))
        if case == "length":
            payload[0] = ord("0")
        elif case == "overlong":
            space = payload.index(ord(" "))
            payload[:space] = b"9" * space
        elif case == "record":
            payload[payload.index(ord("="))] = ord(":")
        elif case == "utf8":
            payload[payload.index(ord("=")) + 1] = 0xFF
        members = (
            _raw_tar_member("pax", bytes(payload), tarfile.XHDTYPE),
            _raw_tar_member("sing-box", b"x"),
        )

    with pytest.raises(ArchiveError, match=message):
        preflight_tar_gzip(io.BytesIO(gzip.compress(_raw_tar(*members))), _limits())


@pytest.mark.parametrize(
    ("trailing", "message"),
    [
        (b"x", "block aligned"),
        (b"x" + b"\0" * 511, "nonzero data follows"),
    ],
)
def test_tar_gzip_preflight_rejects_data_after_end_blocks(trailing, message):
    raw = _raw_tar(_raw_tar_member("sing-box", b"x")) + trailing

    with pytest.raises(ArchiveError, match=message):
        preflight_tar_gzip(io.BytesIO(gzip.compress(raw)), _limits())


def test_tar_gzip_preflight_rejects_aggregate_extensions():
    first = _pax_record("comment", "one")
    second = _pax_record("path", "sing-box")
    raw = _raw_tar(
        _raw_tar_member("pax-1", first, tarfile.XHDTYPE),
        _raw_tar_member("pax-2", second, tarfile.XHDTYPE),
        _raw_tar_member("placeholder", b"x"),
    )

    with pytest.raises(ArchiveError, match="aggregate TAR extensions"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(raw)),
            _limits(maximum_total_extension_bytes=len(first) + len(second) - 1),
        )


def test_tar_gzip_preflight_counts_extension_headers_as_members():
    pax = _pax_record("path", "sing-box")
    raw = _raw_tar(
        _raw_tar_member("pax", pax, tarfile.XHDTYPE),
        _raw_tar_member("placeholder", b"x"),
    )

    with pytest.raises(ArchiveError, match="TAR members exceed"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(raw)),
            _limits(maximum_members=1),
        )


def test_tar_gzip_preflight_accepts_zero_octal_fields():
    raw = bytearray(_raw_tar(_raw_tar_member("empty", b"")))
    raw[124:136] = b"\0" * 12
    _rewrite_tar_checksum(raw)

    assert preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(raw))), _limits()).entries[0].size == 0


def test_tar_gzip_preflight_rejects_pax_without_length_separator():
    payload = b"x" * 4097
    raw = _raw_tar(
        _raw_tar_member("pax", payload, tarfile.XHDTYPE),
        _raw_tar_member("sing-box", b"x"),
    )

    with pytest.raises(ArchiveError, match="invalid or overlong PAX record"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(raw)),
            _limits(maximum_extension_bytes=8192),
        )


def test_tar_gzip_preflight_rejects_duplicate_key_inside_one_pax_header():
    payload = _pax_record("comment", "one") + _pax_record("comment", "two")
    raw = _raw_tar(
        _raw_tar_member("pax", payload, tarfile.XHDTYPE),
        _raw_tar_member("sing-box", b"x"),
    )

    with pytest.raises(ArchiveError, match="duplicate or empty PAX key"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(raw)), _limits())


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b"1", "invalid or overlong PAX record"),
        (b"12345678 ", "invalid PAX record length"),
    ),
)
def test_tar_gzip_preflight_rejects_a_pax_length_cut_off_inside_its_header(
    payload,
    message,
):
    raw = _raw_tar(
        _raw_tar_member("pax", payload, tarfile.XHDTYPE),
        _raw_tar_member("sing-box", b"x"),
    )

    with pytest.raises(ArchiveError, match=message):
        preflight_tar_gzip(io.BytesIO(gzip.compress(raw)), _limits())


def test_tar_gzip_preflight_rejects_a_truncated_pax_payload():
    header = bytearray(_raw_tar_member("pax", b"", tarfile.XHDTYPE)[:512])
    header[124:136] = b"00000000010\0"
    _rewrite_tar_checksum(header)

    with pytest.raises(ArchiveError, match="truncated TAR extension payload"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(header))), _limits())


def test_tar_gzip_preflight_rejects_a_numeric_pax_size_above_the_file_limit():
    payload = _pax_record("size", "9")
    raw = _raw_tar(
        _raw_tar_member("pax", payload, tarfile.XHDTYPE),
        _raw_tar_member("sing-box", b"123456789"),
    )

    with pytest.raises(ArchiveError, match="TAR member exceeds the safety limit"):
        preflight_tar_gzip(
            io.BytesIO(gzip.compress(raw)),
            _limits(maximum_file_bytes=8),
        )


def test_tar_gzip_preflight_rejects_non_nfc_effective_pax_path():
    payload = _pax_record("path", "e\u0301")
    raw = _raw_tar(
        _raw_tar_member("pax", payload, tarfile.XHDTYPE),
        _raw_tar_member("placeholder", b"x"),
    )

    with pytest.raises(ArchiveError, match="member path must use Unicode NFC"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(raw)), _limits())


def test_tar_gzip_preflight_rejects_sparse_type_and_malformed_end_blocks():
    sparse = _raw_tar(_raw_tar_member("sing-box", b"", tarfile.GNUTYPE_SPARSE))
    with pytest.raises(ArchiveError, match="sparse TAR members"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(sparse)), _limits())

    raw = _raw_tar_member("first", b"x") + b"\0" * 512 + _raw_tar_member("second", b"y") + b"\0" * 1024
    with pytest.raises(ArchiveError, match="end blocks are malformed"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(raw)), _limits())


def test_tar_gzip_preflight_rejects_short_header_and_payload():
    with pytest.raises(ArchiveError, match="truncated TAR header"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(b"x")), _limits())

    raw = bytearray(_raw_tar_member("sing-box", b"x"))
    raw[124:136] = b"00000001000\0"
    _rewrite_tar_checksum(raw)
    with pytest.raises(ArchiveError, match="truncated TAR member payload"):
        preflight_tar_gzip(io.BytesIO(gzip.compress(bytes(raw[:512]))), _limits())
