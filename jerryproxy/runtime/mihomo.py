"""Mihomo 1.19.29 foreground projection for an opaque NodeSet."""

import os
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ..backend.durable import flush_directory
from ..errors import RuntimeSessionError
from ..home import is_path_alias
from ..subscription.redaction import redact_text
from .interfaces import RuntimeDriver, RuntimeProjection

QUALIFIED_VERSION = "1.19.29"
MAXIMUM_LOG_BYTES = 4 * 1024 * 1024
LISTENER_PROTOCOLS = ("mixed", "http", "socks5")
LISTENER_ADDRESSES = ("127.0.0.1", "0.0.0.0")


def _config_log_level(value):  # type: (str) -> str
    levels = {
        "OFF": "silent",
        "DEBUG": "debug",
        "INFO": "info",
        "WARN": "warning",
        "ERROR": "error",
        "SILENT": "silent",
        "WARNING": "warning",
    }
    normalized = str(value).upper()
    if normalized not in levels:
        raise ValueError("unsupported Mihomo log level")
    return levels[normalized]


def _validate_private_chain(path, boundary=None):
    current = Path(path)
    boundary = Path(boundary) if boundary is not None else None
    while True:
        if is_path_alias(current):
            raise RuntimeSessionError("runtime projection path is aliased")
        if boundary is not None and current == boundary:
            return
        if current.parent == current:
            return
        current = current.parent


def _private_directory(path, boundary=None):  # type: (Path, object) -> None
    _validate_private_chain(path, boundary=boundary)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_private_chain(path, boundary=boundary)
    if not path.is_dir():
        raise RuntimeSessionError("runtime projection path is not a directory")
    if os.name == "posix":
        path.chmod(0o700)


def _private_bytes(path, payload, boundary=None):  # type: (Path, bytes, object) -> None
    _private_directory(path.parent, boundary=boundary)
    descriptor = -1
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
        temporary = None
        flush_directory(path.parent)
    except OSError as error:
        # Private runtime projection can fail through filesystem errors.
        raise RuntimeSessionError("runtime projection publication failed") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def reserve_loopback_port(preferred=None, strict=False, bind_address="127.0.0.1"):  # type: (int, bool, str) -> int
    """Reserve and release one TCP port immediately before launch."""

    if not isinstance(strict, bool):
        raise ValueError("strict must be a boolean")
    if bind_address not in LISTENER_ADDRESSES:
        raise ValueError("unsupported listener bind address")
    if preferred is not None and (
        not isinstance(preferred, int)
        or isinstance(preferred, bool)
        or not 1 <= preferred <= 65535
    ):
        raise ValueError("preferred port is outside the TCP port range")
    candidates = [preferred] if preferred is not None else []
    if not strict:
        candidates.extend(range(17777, 17827))
    for port in candidates:
        if port is None or not isinstance(port, int) or not 1 <= port <= 65535:
            continue
        descriptor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            descriptor.bind((bind_address, port))
            return port
        except OSError:
            continue
        finally:
            descriptor.close()
    if preferred is not None and strict:
        raise RuntimeSessionError("requested listener port is unavailable: %d" % preferred)
    descriptor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        descriptor.bind((bind_address, 0))
        return descriptor.getsockname()[1]
    except OSError as error:
        # A lack of a listener socket is a terminal launch failure.
        raise RuntimeSessionError("unable to reserve a listener port") from error
    finally:
        descriptor.close()


def build_provider_config(
    provider_path,
    uri_bytes,
    port,
    username,
    password,
    listener_protocol="mixed",
    log_level="warning",
    bind_address="127.0.0.1",
):
    # type: (Path, bytes, int, str, str, str, str, str) -> bytes
    """Build a minimal local-file Mihomo config without parsing credentials."""

    if listener_protocol not in LISTENER_PROTOCOLS:
        raise ValueError("unsupported Mihomo listener protocol")
    if bind_address not in LISTENER_ADDRESSES:
        raise ValueError("unsupported listener bind address")
    listener_key = {
        "mixed": "mixed-port",
        "http": "port",
        "socks5": "socks-port",
    }[listener_protocol]
    # The provider body remains opaque and is parsed by Mihomo 1.19.29.  The
    # generated projection contains no controller or secondary network source.
    escaped_path = str(provider_path).replace("\\", "/").replace("'", "''")
    lines = [
        "%s: %d" % (listener_key, port),
        "bind-address: %s" % bind_address,
        "allow-lan: %s" % ("true" if bind_address == "0.0.0.0" else "false"),
        "mode: rule",
        "ipv6: false",
        "log-level: %s" % _config_log_level(log_level),
        "proxy-providers:",
        "  jerryproxy:",
        "    type: file",
        "    path: '%s'" % escaped_path,
        "    health-check:",
        "      enable: false",
        "proxy-groups:",
        "  - name: jerryproxy",
        "    type: select",
        "    use:",
        "      - jerryproxy",
        "rules:",
        "  - MATCH,jerryproxy",
    ]
    if username is not None or password is not None:
        if username is None or password is None:
            raise ValueError("proxy authentication requires both username and password")
        lines[6:6] = [
            "authentication:",
            "  - '%s:%s'" % (username, password),
        ]
    del uri_bytes
    return ("\n".join(lines) + "\n").encode("utf-8")


class MihomoDriver(RuntimeDriver):
    """Runtime-driver adapter for the qualified Mihomo foreground core."""

    def __init__(self, process_factory=None):
        self.process_factory = process_factory or MihomoProcess

    @property
    def name(self):  # type: () -> str
        return "mihomo"

    def projection(
        self,
        provider_path,
        node,
        port,
        username,
        password,
        listener_protocol="mixed",
        backend_log_level="INFO",
        bind_address="127.0.0.1",
    ):
        # type: (Path, object, int, str, str, str, str, str) -> RuntimeProjection
        uri = node.secret_uri()
        provider = (uri + "\n").encode("utf-8")
        config = build_provider_config(
            provider_path,
            provider,
            port,
            username,
            password,
            listener_protocol=listener_protocol,
            log_level=backend_log_level,
            bind_address=bind_address,
        )
        return RuntimeProjection(config=config, provider=provider)

    def create_process(self, executable, config_path, session_root, log_path, backend_log_level, log_sink=None):
        # type: (Path, Path, Path, Path, str, object) -> object
        options = {
            "backend_log_level": backend_log_level,
        }
        if log_sink is not None:
            options["log_sink"] = log_sink
        return self.process_factory(
            executable,
            config_path,
            session_root,
            log_path,
            **options
        )

    def wait_ready(self, process, port, timeout):
        # type: (object, int, float) -> None
        if isinstance(process, MihomoProcess):
            process.wait_ready(port, timeout=timeout)
        else:
            process.wait_ready(port)

    def stop(self, process, timeout=None):
        # type: (object, object) -> None
        if isinstance(process, MihomoProcess):
            process.stop(timeout=timeout if timeout is not None else 2.0)
        else:
            process.stop()


def build_environment(executable, session_root):  # type: (Path, Path) -> dict
    """Construct the scrubbed child environment required by the contract."""

    backend_home = session_root / "backend-home"
    temporary = session_root / "tmp"
    config_home = session_root / "xdg-config"
    cache_home = session_root / "xdg-cache"
    data_home = session_root / "xdg-data"
    for path in (backend_home, temporary, config_home, cache_home, data_home):
        _private_directory(path, boundary=session_root)
    executable_parent = str(executable.parent)
    values = {
        "HOME": str(backend_home),
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "XDG_CONFIG_HOME": str(config_home),
        "XDG_CACHE_HOME": str(cache_home),
        "XDG_DATA_HOME": str(data_home),
        "PATH": executable_parent,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if not system_root:
            raise RuntimeSessionError("SystemRoot is unavailable for the backend environment")
        values.update(
            {
                "SystemRoot": system_root,
                "WINDIR": system_root,
                "USERPROFILE": str(backend_home),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            }
        )
    return values


class MihomoProcess(object):
    """One bounded Mihomo child with one redacted merged output stream."""

    def __init__(
        self,
        executable,
        config_path,
        session_root,
        log_path,
        backend_log_level="INFO",
        log_sink=None,
        backend_name="mihomo",
    ):
        self.executable = Path(executable)
        self.config_path = Path(config_path)
        self.session_root = Path(session_root)
        self.log_path = Path(log_path)
        self.backend_log_level = backend_log_level
        self.log_sink = log_sink
        self.backend_name = str(backend_name)
        self.process = None
        self._threads = []
        self._stop = threading.Event()
        self._drain_errors = []

    def _record_drain_error(self, error):
        if len(self._drain_errors) >= 8:
            return
        self._drain_errors.append(redact_text(error)[:1024])

    @staticmethod
    def _read_chunk(stream, descriptor):
        if descriptor is not None:
            return os.read(descriptor, 65536)
        reader = getattr(stream, "read1", None)
        if reader is not None:
            return reader(65536)
        return stream.read(65536)

    def _drain(self, stream):
        descriptor = -1
        written = 0
        stream_descriptor = None
        try:
            stream_descriptor = stream.fileno()
        except (AttributeError, OSError, ValueError):
            # In-memory test streams do not expose an OS file descriptor.
            stream_descriptor = None
        try:
            _private_directory(self.log_path.parent, boundary=self.log_path.parent)
            if self.backend_log_level != "OFF":
                if is_path_alias(self.log_path):
                    raise RuntimeSessionError("runtime log path is aliased")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(str(self.log_path), flags, 0o600)
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode):
                    raise RuntimeSessionError("runtime log path is not a regular file")
                if status.st_size > MAXIMUM_LOG_BYTES:
                    raise RuntimeSessionError("runtime log exceeds its size bound")
                written = status.st_size
        except (OSError, RuntimeSessionError, ValueError) as error:
            # Log publication can fail after launch; retain a bounded diagnostic
            # but continue draining the child pipe so a verbose backend cannot block.
            self._record_drain_error(error)
            if descriptor != -1:
                os.close(descriptor)
                descriptor = -1
        try:
            while True:
                try:
                    chunk = self._read_chunk(stream, stream_descriptor)
                except (OSError, ValueError) as error:
                    # A closed child pipe is a bounded teardown condition.
                    self._record_drain_error(error)
                    break
                if not chunk:
                    break
                if self.backend_log_level == "OFF":
                    continue
                # Backend bytes are never rendered verbatim.  Keep a bounded stream
                # summary for diagnostics while always draining the pipe.
                safe = b" ".join(chunk.splitlines()).decode("utf-8", "replace")
                safe = redact_text(" ".join(safe.split()))[:4096]
                if safe:
                    if descriptor != -1:
                        line = ("[%s] %s\n" % (self.backend_name, safe)).encode("utf-8", "replace")
                        if written >= MAXIMUM_LOG_BYTES:
                            self._record_drain_error(RuntimeSessionError("runtime log exceeds its size bound"))
                            os.close(descriptor)
                            descriptor = -1
                        else:
                            line = line[: MAXIMUM_LOG_BYTES - written]
                            try:
                                written += os.write(descriptor, line)
                            except OSError as error:
                                # Stop persisting after a write failure but keep draining.
                                self._record_drain_error(error)
                                os.close(descriptor)
                                descriptor = -1
                    if self.log_sink is not None:
                        try:
                            self.log_sink(self.backend_name, "INFO", safe)
                        except (OSError, ValueError) as error:
                            # A foreground log sink may close during shutdown;
                            # continue draining the backend pipe safely.
                            self._record_drain_error(error)
        finally:
            if descriptor != -1:
                os.close(descriptor)
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def start(self):
        env = build_environment(self.executable, self.session_root)
        if os.path.lexists(str(self.log_path)):
            if is_path_alias(self.log_path) or not self.log_path.is_file():
                raise RuntimeSessionError("runtime log path is aliased or not a regular file")
            if os.name == "posix" and stat.S_IMODE(self.log_path.stat().st_mode) != 0o600:
                raise RuntimeSessionError("runtime log path has unsafe permissions")
        try:
            options = {
                "cwd": str(self.session_root),
                "env": env,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                # Keep one backend stream so callers never need to reason
                # about whether a line came from stdout or stderr.
                "stderr": subprocess.STDOUT,
                "shell": False,
                "close_fds": True,
                "universal_newlines": False,
            }
            if os.name == "posix":
                options["start_new_session"] = True
            elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            self.process = subprocess.Popen(
                [str(self.executable), "-f", str(self.config_path)],
                **options
            )
        except OSError as error:
            # Executable launch failures are terminal runtime errors.
            raise RuntimeSessionError("mihomo backend launch failed") from error
        thread = threading.Thread(target=self._drain, args=(self.process.stdout,), name="jerryproxy-backend")
        thread.daemon = True
        thread.start()
        self._threads.append(thread)
        return self.process

    def wait_ready(self, port, timeout=5.0):  # type: (int, float) -> None
        if timeout <= 0:
            raise RuntimeSessionError("mihomo readiness deadline exhausted")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process is None:
                raise RuntimeSessionError("mihomo backend has not started")
            if self.process.poll() is not None:
                raise RuntimeSessionError("mihomo backend exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeSessionError("mihomo listener did not become ready")

    def stop(self, timeout=2.0):  # type: (float) -> None
        timeout = max(0.01, float(timeout))
        self._stop.set()
        process = self.process
        if process is not None and process.poll() is None:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except OSError:
                    process.terminate()
            else:
                process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        process.kill()
                else:
                    process.kill()
                process.wait(timeout=timeout)
        for thread in self._threads:
            thread.join(timeout=timeout)
        if any(thread.is_alive() for thread in self._threads):
            raise RuntimeSessionError("mihomo backend log drain did not stop")
        if self._drain_errors:
            raise RuntimeSessionError("mihomo backend log capture failed: %s" % self._drain_errors[0])
