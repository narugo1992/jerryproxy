import hashlib
import json
import os

import pytest

import jerryproxy.utils.fs as fs_module
from jerryproxy.utils.fs import (
    MAXIMUM_JSON_BYTES,
    MAXIMUM_JSON_NODES,
    atomic_write_json,
    read_json,
    sha256_file,
)


def test_atomic_json_round_trip_uses_private_file(tmp_path):
    path = tmp_path / "state" / "manifest.json"
    value = {"name": "mihomo", "version": "1.0.0"}

    atomic_write_json(path, value)

    assert read_json(path) == value
    assert path.read_text(encoding="utf-8").endswith("\n")
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_atomic_json_failure_leaves_no_partial_state(tmp_path):
    path = tmp_path / "state" / "manifest.json"
    with pytest.raises(TypeError):
        atomic_write_json(path, {"unsupported": object()})
    assert not path.exists()
    assert not list(path.parent.glob(".manifest.json.*"))


def test_atomic_json_closes_raw_descriptor_when_fdopen_fails(tmp_path, monkeypatch):
    path = tmp_path / "state" / "manifest.json"
    captured = {}

    def fail_fdopen(descriptor, *args, **kwargs):
        captured["descriptor"] = descriptor
        raise OSError("fdopen failed")

    monkeypatch.setattr(fs_module.os, "fdopen", fail_fdopen)

    with pytest.raises(OSError, match="fdopen failed"):
        atomic_write_json(path, {"name": "mihomo"})

    with pytest.raises(OSError):
        os.fstat(captured["descriptor"])
    assert not path.exists()
    assert not list(path.parent.glob(".manifest.json.*"))


def test_read_json_rejects_non_object_documents(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("[]\n", encoding="ascii")
    with pytest.raises(ValueError, match="JSON object expected"):
        read_json(path)


@pytest.mark.parametrize(
    "payload, message",
    [
        (b'{"name":"mihomo","name":"xray"}', "duplicate JSON key"),
        (b'{"value":NaN}', "non-standard JSON constant"),
        (b'{"value":Infinity}', "non-standard JSON constant"),
        (b'{"value":1.5}', "floating-point JSON values"),
        (b'{"value":123456789012345678901234567890123}', "JSON integer is too long"),
    ],
)
def test_read_json_rejects_ambiguous_or_unbounded_values(tmp_path, payload, message):
    path = tmp_path / "state.json"
    path.write_bytes(payload)

    with pytest.raises(ValueError, match=message):
        read_json(path)


def test_read_json_enforces_byte_limit_before_decoding(tmp_path):
    path = tmp_path / "state.json"
    path.write_bytes(b" " * MAXIMUM_JSON_BYTES + b"{}")

    with pytest.raises(ValueError, match="exceeds the safety limit"):
        read_json(path)


def test_read_json_rejects_invalid_utf8_and_excessive_nesting(tmp_path):
    path = tmp_path / "state.json"
    path.write_bytes(b'{"value":"\xff"}')
    with pytest.raises(ValueError, match="valid UTF-8"):
        read_json(path)

    path.write_text('{"value":' + "[" * 17 + "0" + "]" * 17 + "}", encoding="ascii")
    with pytest.raises(ValueError, match="nesting exceeds"):
        read_json(path)


def test_read_json_rejects_too_many_structural_values(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"values": [0] * MAXIMUM_JSON_NODES}),
        encoding="ascii",
    )

    with pytest.raises(ValueError, match="contains too many values"):
        read_json(path)


def test_sha256_file_hashes_real_file_contents(tmp_path):
    path = tmp_path / "payload"
    path.write_bytes(b"jerryproxy")
    assert sha256_file(path) == hashlib.sha256(b"jerryproxy").hexdigest()
