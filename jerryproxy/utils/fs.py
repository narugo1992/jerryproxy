"""Private and atomic filesystem operations."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

MAXIMUM_JSON_BYTES = 1024 * 1024
MAXIMUM_JSON_DEPTH = 16
MAXIMUM_JSON_NODES = 8192
MAXIMUM_JSON_INTEGER_CHARACTERS = 32


def _reject_json_constant(value):
    # type: (str) -> None
    raise ValueError("non-standard JSON constant is not allowed: %s" % value)


def _reject_json_float(value):
    # type: (str) -> None
    raise ValueError("floating-point JSON values are not allowed: %s" % value)


def _parse_bounded_json_integer(value):
    # type: (str) -> int
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAXIMUM_JSON_INTEGER_CHARACTERS:
        raise ValueError("JSON integer is too long")
    return int(value)


def _strict_json_object(pairs):
    # type: (list) -> dict
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key: %s" % key)
        value[key] = item
    return value


def _validate_json_depth(text):
    # type: (str) -> None
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAXIMUM_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds the safety limit")
        elif character in "]}":
            depth -= 1


def _count_json_nodes(value):
    # type: (Any) -> int
    if isinstance(value, dict):
        return 1 + sum(_count_json_nodes(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(_count_json_nodes(item) for item in value)
    return 1


def ensure_private_directory(path):  # type: (Path) -> None
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)


def sha256_file(path):  # type: (Path) -> str
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def atomic_write_json(path, value):  # type: (Path, Dict[str, Any]) -> None
    ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        if os.name == "posix":
            path.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def read_json_stream(stream, source, maximum_bytes=MAXIMUM_JSON_BYTES):
    # type: (object, object, int) -> Dict[str, Any]
    """Read one bounded, strict UTF-8 JSON object from an already-open stream."""

    payload = stream.read(maximum_bytes + 1)
    if len(payload) > maximum_bytes:
        raise ValueError("JSON document exceeds the safety limit in %s" % source)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        # Managed JSON is always emitted as UTF-8 by atomic_write_json.
        raise ValueError("JSON document is not valid UTF-8: %s" % source) from error
    _validate_json_depth(text)
    value = json.loads(
        text,
        object_pairs_hook=_strict_json_object,
        parse_constant=_reject_json_constant,
        parse_float=_reject_json_float,
        parse_int=_parse_bounded_json_integer,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON object expected in %s" % source)
    if _count_json_nodes(value) > MAXIMUM_JSON_NODES:
        raise ValueError("JSON document contains too many values: %s" % source)
    return value


def read_json(path, maximum_bytes=MAXIMUM_JSON_BYTES):  # type: (Path, int) -> Dict[str, Any]
    """Read one bounded, strict UTF-8 JSON object."""

    with path.open("rb") as stream:
        return read_json_stream(stream, path, maximum_bytes=maximum_bytes)
