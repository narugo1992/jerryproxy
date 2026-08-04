"""Minimal foreground guardian for one qualified backend process.

The guardian is deliberately small: it owns the backend child, keeps the
backend in the guardian's process group, and records only non-secret process
identity metadata for the parent supervisor.  Backend output is inherited by
the guardian's already-bounded stdout/stderr pipes and is never interpreted
here.
"""

import argparse
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def _configure_parent_death_signal():
    if os.name != "posix" or not hasattr(signal, "SIGTERM"):
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        prctl = getattr(libc, "prctl", None)
        if prctl is not None:
            prctl(1, int(signal.SIGTERM), 0, 0, 0)
    except (AttributeError, OSError, TypeError):
        # A platform without prctl still has the parent's bounded group cleanup.
        return


def _start_time(pid):
    if sys.platform.startswith("linux"):
        try:
            text = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
            closing = text.rfind(")")
            fields = text[closing + 2 :].split()
            return int(fields[19]) if len(fields) > 19 else None
        except (OSError, UnicodeError, ValueError):
            # Procfs may not exist on non-Linux or can disappear during teardown.
            return None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=0.5,
            )
            token = result.stdout.decode("ascii", "strict").strip()
            return token or None
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            # macOS has no procfs start tick; lstart is a stable process token.
            return None
    return None


def _wait_for_start_gate(start_gate):
    """Wait for the parent authorization byte; EOF cancels before launch."""

    if start_gate is None:
        return True
    try:
        while True:
            chunk = os.read(int(start_gate), 1)
            if chunk:
                return True
            return False
    except (OSError, TypeError, ValueError):
        # A closed or invalid inherited descriptor cancels the child launch.
        return False
    finally:
        try:
            os.close(int(start_gate))
        except (OSError, TypeError, ValueError):
            pass


def _path_is_alias(path):
    """Detect symlinks and Windows reparse points without resolving them."""

    path = Path(path)
    if path.is_symlink():
        return True
    if os.name != "nt":
        return False
    try:
        attributes = path.lstat().st_file_attributes
    except FileNotFoundError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _validate_metadata_chain(path, boundary):
    current = Path(path)
    boundary = Path(boundary)
    while True:
        if _path_is_alias(current):
            raise OSError("guardian metadata path is aliased")
        if current == boundary:
            return
        if current.parent == current:
            raise OSError("guardian metadata path escaped its session root")
        current = current.parent


def _write_metadata(path, value, boundary):
    target = Path(path)
    _validate_metadata_chain(target.parent, boundary)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_metadata_chain(target.parent, boundary)
    descriptor, temporary = tempfile.mkstemp(prefix=".%s." % target.name, dir=str(target.parent))
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            descriptor = -1
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(target))
        temporary = None
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _terminate_child_group(child, hard=False):
    """Terminate the backend and every process in its guardian group."""

    if child is None or child.poll() is not None:
        return
    if os.name == "posix":
        try:
            pgid = os.getpgid(child.pid)
            os.killpg(pgid, signal.SIGKILL if hard else signal.SIGTERM)
        except (OSError, ValueError):
            # The child may have exited between poll and group lookup.
            pass
    else:
        try:
            (child.kill if hard else child.terminate)()
        except OSError:
            pass


def run(executable, config_path, metadata_path, session_root, start_gate=None):
    """Launch and own the backend until it exits."""

    if os.name == "posix":
        options = {
            "cwd": str(session_root),
            "stdin": subprocess.DEVNULL,
            "stdout": sys.stdout.buffer,
            "stderr": sys.stderr.buffer,
            "close_fds": True,
            "shell": False,
            "universal_newlines": False,
            "preexec_fn": _configure_parent_death_signal,
        }
    else:
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        options = {
            "cwd": str(session_root),
            "stdin": subprocess.DEVNULL,
            "stdout": sys.stdout,
            "stderr": sys.stderr,
            "close_fds": False,
            "shell": False,
            "creationflags": creationflags,
            "universal_newlines": False,
        }
    if not _wait_for_start_gate(start_gate):
        return 125
    child = None
    old_term = None
    old_int = None
    try:
        child = subprocess.Popen([str(executable), "-f", str(config_path)], **options)
    except OSError:
        return 127

    def _shutdown(signum, frame):
        del frame
        # Ignore the same signal while killing the process group; otherwise a
        # group-wide signal would recursively re-enter this handler.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        _terminate_child_group(child)
        try:
            child.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            _terminate_child_group(child, hard=True)
            try:
                child.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        raise SystemExit(128 + int(signum))

    if os.name == "posix":
        old_term = signal.signal(signal.SIGTERM, _shutdown)
        if hasattr(signal, "SIGINT"):
            old_int = signal.signal(signal.SIGINT, _shutdown)
    value = {
        "pid": int(child.pid),
        "executable": str(Path(executable).absolute()),
        "config": str(Path(config_path).absolute()),
        "start_time": _start_time(child.pid),
        "pgid": os.getpgid(child.pid) if os.name == "posix" else None,
        "sid": os.getsid(child.pid) if os.name == "posix" else None,
    }
    try:
        try:
            _write_metadata(metadata_path, value, session_root)
        except OSError:
            # The parent will fail closed when it cannot authenticate the child.
            _terminate_child_group(child, hard=True)
            child.wait()
            return 127
        return child.wait()
    finally:
        if old_term is not None:
            signal.signal(signal.SIGTERM, old_term)
        if old_int is not None:
            signal.signal(signal.SIGINT, old_int)


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--session-root", required=True)
    parser.add_argument("--start-gate", type=int)
    args = parser.parse_args(argv)
    _configure_parent_death_signal()
    return int(run(args.executable, args.config, args.metadata, args.session_root, args.start_gate))


if __name__ == "__main__":
    sys.exit(main())
