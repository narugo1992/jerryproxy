import hashlib
import os

import pytest

from jerryproxy.utils.fs import atomic_write_json, read_json, sha256_file


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


def test_read_json_rejects_non_object_documents(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("[]\n", encoding="ascii")
    with pytest.raises(ValueError, match="JSON object expected"):
        read_json(path)


def test_sha256_file_hashes_real_file_contents(tmp_path):
    path = tmp_path / "payload"
    path.write_bytes(b"jerryproxy")
    assert sha256_file(path) == hashlib.sha256(b"jerryproxy").hexdigest()
