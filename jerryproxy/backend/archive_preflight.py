"""Bounded structural preflight for supported backend archive formats."""

import binascii
import os
import struct
import unicodedata
import zlib
from dataclasses import dataclass

from ..errors import ArchiveError

_EOCD = b"PK\x05\x06"
_ZIP64_EOCD = b"PK\x06\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_CENTRAL_HEADER = b"PK\x01\x02"
_LOCAL_HEADER = b"PK\x03\x04"
_DATA_DESCRIPTOR = b"PK\x07\x08"
_ZIP64_EXTRA = 0x0001
_ZIP_ALLOWED_FLAGS = 0x080E
_ZIP_METHODS = (0, 8)
_CHUNK_SIZE = 64 * 1024
_TAR_BLOCK_SIZE = 512
_PAX_LINE_LIMIT = 4096
_PAX_INTEGER_DIGITS = 20


@dataclass(frozen=True)
class ZipPreflightEntry:
    """Metadata needed to compare a later ``ZipInfo`` extraction pass."""

    name: str
    local_header_offset: int
    compressed_size: int
    uncompressed_size: int
    method: int
    flags: int
    crc32: int


@dataclass(frozen=True)
class ZipPreflightPlan:
    """Approved ZIP central-directory and member metadata."""

    entries: tuple
    central_directory_offset: int
    central_directory_size: int
    compressed_size: int

    @property
    def entry_count(self):
        return len(self.entries)


@dataclass(frozen=True)
class GzipPreflightPlan:
    """Verified dimensions of one standalone GZip member."""

    compressed_size: int
    expanded_size: int
    crc32: int


@dataclass(frozen=True)
class TarPreflightEntry:
    """Compact effective metadata for one TAR filesystem member."""

    name: str
    is_directory: bool
    size: int
    type_flag: bytes


@dataclass(frozen=True)
class TarPreflightPlan:
    """Approved metadata for one GZip-compressed TAR stream."""

    entries: tuple
    compressed_size: int
    raw_size: int

    @property
    def entry_count(self):
        return len(self.entries)


def _limit(limits, name):
    value = getattr(limits, name, None)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("%s must be a positive integer" % name)
    return value


def _file_size(handle):
    try:
        original = handle.tell()
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(original)
    except (OSError, ValueError) as error:
        # Archive preflight requires a caller-owned seekable binary handle.
        raise ArchiveError("archive preflight requires a seekable binary handle") from error
    if not isinstance(size, int) or size < 0:
        raise ArchiveError("invalid archive size")
    return size


def _read_exact(handle, size, message):
    data = handle.read(size)
    if len(data) != size:
        raise ArchiveError(message)
    return data


def _decode_zip_name(raw_name, flags):
    try:
        return raw_name.decode("utf-8" if flags & 0x0800 else "cp437")
    except UnicodeDecodeError as error:
        # ZIP UTF-8 names are untrusted archive metadata.
        raise ArchiveError("invalid ZIP member name encoding") from error


def _validate_zip_flags(flags, method):
    if flags & ~_ZIP_ALLOWED_FLAGS:
        raise ArchiveError("unsupported ZIP general-purpose flag")
    if method not in _ZIP_METHODS:
        raise ArchiveError("unsupported ZIP compression method")
    if flags & 0x0006 and method != 8:
        raise ArchiveError("ZIP compression option flags require deflate")


def _parse_extra_fields(data, maximum_total, total_so_far):
    fields = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ArchiveError("truncated ZIP extra field")
        field_id, field_size = struct.unpack_from("<HH", data, offset)
        offset += 4
        end = offset + field_size
        if end > len(data):
            raise ArchiveError("truncated ZIP extra field")
        if field_id in fields:
            raise ArchiveError("duplicate ZIP extra field")
        fields[field_id] = data[offset:end]
        offset = end
    total = total_so_far + len(data)
    if total > maximum_total:
        raise ArchiveError("aggregate ZIP extension data exceeds the safety limit")
    return fields, total


def _zip64_values(extra, values, allow_redundant=False):
    required = [value == sentinel for value, sentinel in zip(values, (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF))]
    if not any(required):
        if extra is not None and not allow_redundant:
            raise ArchiveError("unexpected ZIP64 extra field without sentinel metadata")
        if extra is not None:
            offset = 0
            for value, width in zip(values, (8, 8, 8, 4)):
                if offset == len(extra):
                    break
                if offset + width > len(extra):
                    raise ArchiveError("inconsistent ZIP64 extra field")
                if int.from_bytes(extra[offset : offset + width], "little") != value:
                    raise ArchiveError("inconsistent ZIP64 extra field")
                offset += width
            if offset != len(extra):
                raise ArchiveError("inconsistent ZIP64 extra field")
        return values
    if extra is None:
        raise ArchiveError("missing ZIP64 extra field")
    output = list(values)
    offset = 0
    widths = (8, 8, 8, 4)
    for index, needed in enumerate(required):
        if not needed:
            continue
        width = widths[index]
        if offset + width > len(extra):
            raise ArchiveError("inconsistent ZIP64 extra field")
        output[index] = int.from_bytes(extra[offset : offset + width], "little")
        offset += width
    if offset != len(extra):
        raise ArchiveError("inconsistent ZIP64 extra field")
    return tuple(output)


def _find_eocd(handle, size):
    window_size = min(size, 22 + 65535)
    handle.seek(size - window_size)
    window = _read_exact(handle, window_size, "truncated ZIP end record")
    candidates = []
    start = 0
    while True:
        index = window.find(_EOCD, start)
        if index < 0:
            break
        if index + 22 <= len(window):
            comment_length = struct.unpack_from("<H", window, index + 20)[0]
            if index + 22 + comment_length == len(window):
                candidates.append(size - window_size + index)
        start = index + 1
    if len(candidates) != 1:
        raise ArchiveError("ZIP must contain one unambiguous end record")
    return candidates[0]


def _resolve_zip_directory(handle, eocd_offset):
    handle.seek(eocd_offset)
    record = _read_exact(handle, 22, "truncated ZIP end record")
    disk, directory_disk, disk_count, total_count, directory_size, directory_offset = struct.unpack_from(
        "<4H2I", record, 4
    )
    if disk != 0 or directory_disk != 0:
        raise ArchiveError("multi-disk ZIP archives are not allowed")
    if disk_count != total_count:
        raise ArchiveError("inconsistent ZIP entry counts")
    sentinel = total_count == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF
    if not sentinel:
        return total_count, directory_size, directory_offset, eocd_offset

    locator_offset = eocd_offset - 20
    if locator_offset < 0:
        raise ArchiveError("missing ZIP64 locator")
    handle.seek(locator_offset)
    locator = _read_exact(handle, 20, "truncated ZIP64 locator")
    if locator[:4] != _ZIP64_LOCATOR:
        raise ArchiveError("missing ZIP64 locator")
    zip64_disk, zip64_offset, disk_total = struct.unpack_from("<IQI", locator, 4)
    if zip64_disk != 0 or disk_total != 1:
        raise ArchiveError("multi-disk ZIP64 archives are not allowed")
    if zip64_offset >= locator_offset:
        raise ArchiveError("invalid ZIP64 end record offset")
    handle.seek(zip64_offset)
    fixed = _read_exact(handle, 56, "truncated ZIP64 end record")
    if fixed[:4] != _ZIP64_EOCD:
        raise ArchiveError("missing ZIP64 end record")
    record_size = struct.unpack_from("<Q", fixed, 4)[0]
    if record_size < 44 or zip64_offset + 12 + record_size != locator_offset:
        raise ArchiveError("malformed ZIP64 end record")
    zip_disk, zip_directory_disk = struct.unpack_from("<II", fixed, 16)
    count_disk, count_total, size64, offset64 = struct.unpack_from("<4Q", fixed, 24)
    if zip_disk != 0 or zip_directory_disk != 0 or count_disk != count_total:
        raise ArchiveError("multi-disk ZIP64 archives are not allowed")
    for legacy, marker, extended in (
        (total_count, 0xFFFF, count_total),
        (directory_size, 0xFFFFFFFF, size64),
        (directory_offset, 0xFFFFFFFF, offset64),
    ):
        if legacy != marker and legacy != extended:
            raise ArchiveError("inconsistent ZIP and ZIP64 metadata")
    return count_total, size64, offset64, zip64_offset


def preflight_zip(handle, limits):
    # type: (object, object) -> ZipPreflightPlan
    """Validate raw ZIP structure from a seekable binary handle."""

    maximum_compressed = _limit(limits, "maximum_compressed_bytes")
    maximum_members = _limit(limits, "maximum_members")
    maximum_directory = _limit(limits, "maximum_zip_central_directory_bytes")
    maximum_extension = _limit(limits, "maximum_extension_bytes")
    maximum_total_extension = _limit(limits, "maximum_total_extension_bytes")
    maximum_file = _limit(limits, "maximum_file_bytes")
    maximum_expanded = _limit(limits, "maximum_extracted_bytes")
    size = _file_size(handle)
    if size > maximum_compressed:
        raise ArchiveError("compressed input exceeds the safety limit")
    eocd_offset = _find_eocd(handle, size)
    count, directory_size, directory_offset, directory_boundary = _resolve_zip_directory(handle, eocd_offset)
    if count > maximum_members:
        raise ArchiveError("ZIP entries/members exceeds the safety limit")
    if directory_size > maximum_directory:
        raise ArchiveError("ZIP central directory exceeds the safety limit")
    if directory_offset > eocd_offset or directory_size > eocd_offset - directory_offset:
        raise ArchiveError("ZIP central directory lies outside the archive")
    directory_end = directory_offset + directory_size
    if directory_end != directory_boundary:
        raise ArchiveError("ZIP central directory is not adjacent to its end records")
    handle.seek(directory_offset)
    entries = []
    total_extension = 0
    total_expanded = 0
    for _index in range(count):
        fixed = _read_exact(handle, 46, "truncated ZIP central directory")
        if fixed[:4] != _CENTRAL_HEADER:
            raise ArchiveError("invalid ZIP central directory header")
        values = struct.unpack_from("<6H3I5H2I", fixed, 4)
        flags, method = values[2], values[3]
        crc32, compressed_size, uncompressed_size = values[6:9]
        name_length, extra_length, comment_length = values[9:12]
        disk_start, local_offset = values[12], values[15]
        _validate_zip_flags(flags, method)
        if max(name_length, extra_length, comment_length) > maximum_extension:
            raise ArchiveError("ZIP extension data exceeds the safety limit")
        raw_name = _read_exact(handle, name_length, "truncated ZIP member name")
        raw_extra = _read_exact(handle, extra_length, "truncated ZIP member extra data")
        _read_exact(handle, comment_length, "truncated ZIP member comment")
        total_extension += name_length + comment_length
        fields, total_extension = _parse_extra_fields(raw_extra, maximum_total_extension, total_extension)
        if total_extension > maximum_total_extension:
            raise ArchiveError("aggregate ZIP extension data exceeds the safety limit")
        uncompressed_size, compressed_size, local_offset, disk_start = _zip64_values(
            fields.get(_ZIP64_EXTRA), (uncompressed_size, compressed_size, local_offset, disk_start)
        )
        if disk_start != 0:
            raise ArchiveError("multi-disk ZIP entries are not allowed")
        if uncompressed_size > maximum_file:
            raise ArchiveError("ZIP member exceeds the safety limit")
        total_expanded += uncompressed_size
        if total_expanded > maximum_expanded:
            raise ArchiveError("ZIP expanded content exceeds the safety limit")
        entry = ZipPreflightEntry(
            _decode_zip_name(raw_name, flags),
            local_offset,
            compressed_size,
            uncompressed_size,
            method,
            flags,
            crc32,
        )
        entries.append((raw_name, entry))
    if handle.tell() != directory_end:
        raise ArchiveError("ZIP central directory has extra or missing data")

    ranges = []
    offsets = set()
    approved = []
    for raw_name, entry in entries:
        if entry.local_header_offset in offsets:
            raise ArchiveError("duplicate local ZIP header offset")
        offsets.add(entry.local_header_offset)
        if entry.local_header_offset >= directory_offset:
            raise ArchiveError("invalid local ZIP header offset")
        handle.seek(entry.local_header_offset)
        local = _read_exact(handle, 30, "truncated local ZIP header")
        if local[:4] != _LOCAL_HEADER:
            raise ArchiveError("invalid local ZIP header")
        local_flags, local_method = struct.unpack_from("<HH", local, 6)
        local_crc, local_compressed, local_uncompressed = struct.unpack_from("<III", local, 14)
        local_name_length, local_extra_length = struct.unpack_from("<HH", local, 26)
        if max(local_name_length, local_extra_length) > maximum_extension:
            raise ArchiveError("ZIP extension data exceeds the safety limit")
        local_name = _read_exact(handle, local_name_length, "truncated local ZIP member name")
        local_extra = _read_exact(handle, local_extra_length, "truncated local ZIP extra data")
        if local_name != raw_name:
            raise ArchiveError("local ZIP member name disagrees with central directory")
        if local_flags != entry.flags or local_method != entry.method:
            raise ArchiveError("local ZIP method or flags disagree with central directory")
        local_fields, total_extension = _parse_extra_fields(local_extra, maximum_total_extension, total_extension)
        if not entry.flags & 0x0008:
            local_uncompressed, local_compressed, _unused_offset, _unused_disk = _zip64_values(
                local_fields.get(_ZIP64_EXTRA),
                (local_uncompressed, local_compressed, 0, 0),
                allow_redundant=True,
            )
            if (local_crc, local_compressed, local_uncompressed) != (
                entry.crc32,
                entry.compressed_size,
                entry.uncompressed_size,
            ):
                raise ArchiveError("local ZIP sizes or CRC disagree with central directory")
        data_start = handle.tell()
        data_end = data_start + entry.compressed_size
        if data_end > directory_offset:
            raise ArchiveError("ZIP member data overlaps the central directory")
        member_end = data_end
        if entry.flags & 0x0008:
            zip64_descriptor = entry.compressed_size > 0xFFFFFFFF or entry.uncompressed_size > 0xFFFFFFFF
            width = 8 if zip64_descriptor else 4
            handle.seek(data_end)
            descriptor = _read_exact(handle, 4, "truncated ZIP data descriptor")
            if descriptor == _DATA_DESCRIPTOR:
                descriptor_crc = struct.unpack("<I", _read_exact(handle, 4, "truncated ZIP data descriptor"))[0]
            else:
                descriptor_crc = struct.unpack("<I", descriptor)[0]
            compressed_raw = _read_exact(handle, width, "truncated ZIP data descriptor")
            uncompressed_raw = _read_exact(handle, width, "truncated ZIP data descriptor")
            descriptor_compressed = int.from_bytes(compressed_raw, "little")
            descriptor_uncompressed = int.from_bytes(uncompressed_raw, "little")
            if (descriptor_crc, descriptor_compressed, descriptor_uncompressed) != (
                entry.crc32,
                entry.compressed_size,
                entry.uncompressed_size,
            ):
                raise ArchiveError("ZIP data descriptor disagrees with central directory")
            member_end = handle.tell()
            if member_end > directory_offset:
                raise ArchiveError("ZIP data descriptor overlaps the central directory")
        ranges.append((entry.local_header_offset, member_end))
        approved.append(entry)
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if previous[1] > current[0]:
            raise ArchiveError("overlapping ZIP local headers or member data")
    return ZipPreflightPlan(tuple(approved), directory_offset, directory_size, size)


class _GzipStream(object):
    def __init__(self, handle, limits, expanded_limit):
        self.handle = handle
        self.compressed_size = _file_size(handle)
        if self.compressed_size > _limit(limits, "maximum_compressed_bytes"):
            raise ArchiveError("compressed input exceeds the safety limit")
        self.extension_limit = _limit(limits, "maximum_extension_bytes")
        self.expanded_limit = expanded_limit
        self.output = bytearray()
        self.pending = b""
        self.finished = False
        self.expanded_size = 0
        self.crc32 = 0
        self._parse_header()
        self.decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    def _parse_header(self):
        self.handle.seek(0)
        header = _read_exact(self.handle, 10, "truncated GZip header")
        if header[:2] != b"\x1f\x8b" or header[2] != 8:
            raise ArchiveError("invalid GZip header")
        flags = header[3]
        if flags & 0xE0:
            raise ArchiveError("reserved GZip header flags are set")
        extension_total = 0
        header_crc_data = bytearray(header)
        if flags & 0x04:
            raw_length = _read_exact(self.handle, 2, "truncated GZip extra field")
            header_crc_data.extend(raw_length)
            extra_length = struct.unpack("<H", raw_length)[0]
            extension_total += extra_length
            if extension_total > self.extension_limit:
                raise ArchiveError("GZip extension exceeds the safety limit")
            extra = _read_exact(self.handle, extra_length, "truncated GZip extra field")
            header_crc_data.extend(extra)
        for flag in (0x08, 0x10):
            if not flags & flag:
                continue
            while True:
                extension_total += 1
                if extension_total > self.extension_limit:
                    raise ArchiveError("GZip extension exceeds the safety limit")
                character = _read_exact(self.handle, 1, "truncated GZip extension")
                header_crc_data.extend(character)
                if character == b"\0":
                    break
        if flags & 0x02:
            expected = struct.unpack("<H", _read_exact(self.handle, 2, "truncated GZip header CRC"))[0]
            if expected != binascii.crc32(header_crc_data) & 0xFFFF:
                raise ArchiveError("GZip header CRC does not match")

    def _fill(self, wanted):
        while len(self.output) < wanted and not self.finished:
            if not self.pending:
                self.pending = self.handle.read(_CHUNK_SIZE)
                if not self.pending:
                    raise ArchiveError("truncated GZip deflate stream")
            try:
                chunk = self.decompressor.decompress(self.pending, _CHUNK_SIZE)
            except zlib.error as error:
                # Raw deflate corruption is expected for hostile archive input.
                raise ArchiveError("invalid GZip deflate stream") from error
            self.pending = self.decompressor.unconsumed_tail
            if chunk:
                self.expanded_size += len(chunk)
                if self.expanded_size > self.expanded_limit:
                    raise ArchiveError("GZip expanded content exceeds the safety limit")
                self.crc32 = binascii.crc32(chunk, self.crc32) & 0xFFFFFFFF
                self.output.extend(chunk)
            if self.decompressor.eof:
                trailer = self.decompressor.unused_data
                self.pending = b""
                if len(trailer) < 8:
                    trailer += _read_exact(self.handle, 8 - len(trailer), "truncated GZip trailer")
                expected_crc, expected_size = struct.unpack("<II", trailer[:8])
                if trailer[8:] or self.handle.read(1):
                    raise ArchiveError("concatenated GZip members or trailing data are not allowed")
                if expected_crc != self.crc32:
                    raise ArchiveError("GZip CRC does not match its payload")
                if expected_size != self.expanded_size & 0xFFFFFFFF:
                    raise ArchiveError("GZip size does not match its payload")
                self.finished = True
            elif not chunk and not self.pending:
                continue

    def read(self, size):
        if size < 0 or size > _CHUNK_SIZE:
            raise ValueError("bounded GZip reads must be between zero and 64 KiB")
        self._fill(size)
        result = bytes(self.output[:size])
        del self.output[:size]
        return result

    def finish(self):
        while not self.finished:
            self._fill(_CHUNK_SIZE)
            self.output.clear()
        return GzipPreflightPlan(self.compressed_size, self.expanded_size, self.crc32)


def preflight_gzip(handle, limits):
    # type: (object, object) -> GzipPreflightPlan
    """Validate one standalone GZip member without retaining its output."""

    expanded_limit = min(_limit(limits, "maximum_file_bytes"), _limit(limits, "maximum_extracted_bytes"))
    return _GzipStream(handle, limits, expanded_limit).finish()


def _tar_number(field, label):
    if not field:
        raise ArchiveError("invalid TAR %s" % label)
    if field[0] & 0x80:
        value = int.from_bytes(bytes((field[0] & 0x7F,)) + field[1:], "big", signed=False)
        return value
    raw = field.rstrip(b"\0 ").lstrip(b" ")
    if not raw:
        return 0
    if any(character < 48 or character > 55 for character in raw):
        raise ArchiveError("invalid TAR %s" % label)
    try:
        return int(raw, 8)
    except ValueError as error:
        # Strict octal fields can fail only on hostile TAR metadata.
        raise ArchiveError("invalid TAR %s" % label) from error


def _tar_text(raw, label):
    raw = raw.split(b"\0", 1)[0]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        # Backend TAR paths must be valid UTF-8.
        raise ArchiveError("invalid UTF-8 TAR %s" % label) from error
    if unicodedata.normalize("NFC", value) != value:
        raise ArchiveError("TAR %s must use Unicode NFC" % label)
    return value


def _parse_pax(stream, size):
    values = {}
    offset = 0
    maximum_digits = len(str(_PAX_LINE_LIMIT))
    while offset < size:
        record_start = offset
        length_raw = bytearray()
        while True:
            if offset >= size:
                raise ArchiveError("invalid or overlong PAX record")
            character = _read_stream_exact(stream, 1, "truncated TAR extension payload")
            offset += 1
            if character == b" ":
                break
            if character < b"0" or character > b"9":
                raise ArchiveError("invalid or overlong PAX record")
            length_raw.extend(character)
            if len(length_raw) > maximum_digits:
                raise ArchiveError("invalid PAX record length")
        if not length_raw or length_raw.startswith(b"0"):
            raise ArchiveError("invalid PAX record length")
        length = int(length_raw)
        header_size = offset - record_start
        if length > _PAX_LINE_LIMIT or length <= header_size or record_start + length > size:
            raise ArchiveError("invalid or overlong PAX record")
        record = _read_stream_exact(
            stream,
            length - header_size,
            "truncated TAR extension payload",
        )
        if not record.endswith(b"\n") or b"=" not in record:
            raise ArchiveError("invalid PAX record")
        raw_key, raw_value = record[:-1].split(b"=", 1)
        try:
            key = raw_key.decode("utf-8")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as error:
            # PAX keys and values are specified as UTF-8 text.
            raise ArchiveError("invalid UTF-8 PAX record") from error
        if not key or key in values:
            raise ArchiveError("duplicate or empty PAX key")
        if "sparse" in key.casefold():
            raise ArchiveError("sparse TAR metadata is not allowed")
        values[key] = value
        offset = record_start + length
    return values


def _read_stream_exact(stream, size, message):
    output = bytearray()
    while len(output) < size:
        block = stream.read(min(_CHUNK_SIZE, size - len(output)))
        if not block:
            raise ArchiveError(message)
        output.extend(block)
    return bytes(output)


def _discard(stream, size, message, require_zero=False):
    remaining = size
    while remaining:
        block = stream.read(min(_CHUNK_SIZE, remaining))
        if not block:
            raise ArchiveError(message)
        if require_zero and any(block):
            raise ArchiveError("TAR member padding is not zero")
        remaining -= len(block)


def preflight_tar_gzip(handle, limits):
    # type: (object, object) -> TarPreflightPlan
    """Stream-validate one GZip/TAR archive and return effective member metadata."""

    maximum_raw = _limit(limits, "maximum_tar_stream_bytes")
    maximum_members = _limit(limits, "maximum_members")
    maximum_file = _limit(limits, "maximum_file_bytes")
    maximum_expanded = _limit(limits, "maximum_extracted_bytes")
    maximum_extension = _limit(limits, "maximum_extension_bytes")
    maximum_total_extension = _limit(limits, "maximum_total_extension_bytes")
    stream = _GzipStream(handle, limits, maximum_raw)
    entries = []
    global_pax = {}
    local_pax = {}
    long_name = None
    total_extension = 0
    total_expanded = 0
    zero_blocks = 0
    members_seen = 0
    while True:
        header = stream.read(_TAR_BLOCK_SIZE)
        if not header:
            break
        if len(header) != _TAR_BLOCK_SIZE:
            raise ArchiveError("truncated TAR header")
        if header == b"\0" * _TAR_BLOCK_SIZE:
            zero_blocks += 1
            if zero_blocks >= 2:
                break
            continue
        if zero_blocks:
            raise ArchiveError("TAR end blocks are malformed")
        members_seen += 1
        if members_seen > maximum_members:
            raise ArchiveError("TAR members exceed the safety limit")
        stored_checksum = _tar_number(header[148:156], "checksum")
        calculated_checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
        if stored_checksum != calculated_checksum:
            raise ArchiveError("TAR header checksum does not match")
        size = _tar_number(header[124:136], "member size")
        type_flag = header[156:157] or b"\0"
        name = _tar_text(header[:100], "member path")
        prefix = _tar_text(header[345:500], "path prefix")
        if prefix:
            name = prefix + "/" + name
        padding = (-size) % _TAR_BLOCK_SIZE
        if type_flag in (b"x", b"g", b"L", b"K"):
            if size > maximum_extension:
                raise ArchiveError("TAR extension exceeds the safety limit")
            total_extension += size
            if total_extension > maximum_total_extension:
                raise ArchiveError("aggregate TAR extensions exceed the safety limit")
            if type_flag == b"K":
                raise ArchiveError("GNU longlink is not allowed")
            if type_flag == b"L":
                payload = _read_stream_exact(stream, size, "truncated TAR extension payload")
                if long_name is not None:
                    raise ArchiveError("duplicate GNU longname metadata")
                long_name = _tar_text(payload.rstrip(b"\0"), "GNU longname")
            else:
                parsed = _parse_pax(stream, size)
                target = global_pax if type_flag == b"g" else local_pax
                if any(key in target for key in parsed):
                    raise ArchiveError("duplicate effective PAX key")
                target.update(parsed)
            _discard(stream, padding, "truncated TAR extension padding", require_zero=True)
            continue
        if type_flag in (b"S",):
            raise ArchiveError("sparse TAR members are not allowed")
        if type_flag not in (b"\0", b"0", b"5"):
            raise ArchiveError("links and special files are not allowed in TAR archives")
        effective = dict(global_pax)
        effective.update(local_pax)
        effective_name = long_name if long_name is not None else effective.get("path", name)
        if not isinstance(effective_name, str) or not effective_name:
            raise ArchiveError("empty TAR member path")
        if unicodedata.normalize("NFC", effective_name) != effective_name:
            raise ArchiveError("TAR member path must use Unicode NFC")
        effective_size = size
        if "size" in effective:
            raw_size = effective["size"]
            if not raw_size.isdigit() or len(raw_size) > _PAX_INTEGER_DIGITS or len(raw_size) > len(str(maximum_file)):
                raise ArchiveError("invalid PAX member size")
            effective_size = int(raw_size)
            if effective_size > maximum_file:
                raise ArchiveError("TAR member exceeds the safety limit")
            if effective_size != size:
                raise ArchiveError("PAX size disagrees with TAR header")
        is_directory = type_flag == b"5"
        if is_directory and effective_size != 0:
            raise ArchiveError("TAR directory has a nonzero size")
        if not is_directory:
            if effective_size > maximum_file:
                raise ArchiveError("TAR member exceeds the safety limit")
            total_expanded += effective_size
            if total_expanded > maximum_expanded:
                raise ArchiveError("TAR expanded content exceeds the safety limit")
        _discard(stream, size, "truncated TAR member payload")
        _discard(stream, padding, "truncated TAR member padding", require_zero=True)
        entries.append(TarPreflightEntry(effective_name, is_directory, effective_size, type_flag))
        local_pax = {}
        long_name = None
    if zero_blocks < 2:
        raise ArchiveError("TAR archive is missing its end blocks")
    if local_pax or long_name is not None:
        raise ArchiveError("TAR extension is not followed by a member")
    while True:
        trailing = stream.read(_TAR_BLOCK_SIZE)
        if not trailing:
            break
        if len(trailing) != _TAR_BLOCK_SIZE:
            raise ArchiveError("TAR stream is not block aligned")
        if any(trailing):
            raise ArchiveError("nonzero data follows TAR end blocks")
    gzip_plan = stream.finish()
    return TarPreflightPlan(tuple(entries), gzip_plan.compressed_size, gzip_plan.expanded_size)
