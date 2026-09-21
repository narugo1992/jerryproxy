"""Bounded recent log retention on an already validated, locked descriptor."""

import os


def append_recent(descriptor, line, size, maximum):
    """Append a complete bounded line, retaining the newest half on overflow.

    Callers hold the shared writer lock and validate the opened regular file.
    Compaction uses that same descriptor, without a pathname rename or a second
    log file. A crash during compaction may lose log history, never managed
    configuration or credentials; these logs are best-effort diagnostics.
    """

    payload = line[:maximum]
    if size + len(payload) > maximum:
        keep = min(maximum // 2, maximum - len(payload))
        os.lseek(descriptor, max(0, size - keep), os.SEEK_SET)
        tail = os.read(descriptor, keep).partition(b"\n")[2]
        os.ftruncate(descriptor, 0)
        payload = tail + payload
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("runtime log write made no progress")
        remaining = remaining[written:]
