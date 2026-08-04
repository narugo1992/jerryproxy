import io
import os

import pytest

from jerryproxy.runtime.mihomo import MAXIMUM_LOG_BYTES, MihomoProcess


def test_backend_drain_continues_after_log_alias_failure(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "outside.log"
    target.write_bytes(b"outside")
    log_path = logs / "runtime.log"
    if os.name != "nt":
        log_path.symlink_to(target)
    else:
        pytest.skip("POSIX alias primitive is not available on this runner")
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, log_path)
    class NonClosingBytesIO(io.BytesIO):
        def close(self):
            pass

    stream = NonClosingBytesIO(b"secret backend output\n" * 4)
    process._drain(stream, "stderr")
    assert stream.tell() == len(stream.getvalue())
    assert process._drain_errors
    assert target.read_bytes() == b"outside"


def test_backend_drain_bounds_persisted_log(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    log_path = logs / "runtime.log"
    process = MihomoProcess(tmp_path / "mihomo", tmp_path / "config.yaml", tmp_path, log_path)
    process._drain(io.BytesIO(b"x" * (MAXIMUM_LOG_BYTES + 4096)), "stdout")
    assert log_path.stat().st_size <= MAXIMUM_LOG_BYTES
