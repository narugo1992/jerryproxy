"""Mihomo 1.19.29 foreground projection for an opaque NodeSet."""

import base64
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from ..backend.durable import flush_directory
from ..errors import RuntimeSessionError
from ..home import is_path_alias
from ..subscription.redaction import redact_bytes, redact_text, terminal_safe_text
from .interfaces import RuntimeDriver, RuntimeProjection

QUALIFIED_VERSION = "1.19.29"
MAXIMUM_LOG_BYTES = 4 * 1024 * 1024
MAXIMUM_BACKEND_LINE_BYTES = 16 * 1024
LISTENER_PROTOCOLS = ("mixed", "http", "socks5")
LISTENER_ADDRESSES = ("127.0.0.1", "0.0.0.0")
_HTTP_READINESS_STATUSES = frozenset((200, 400, 403, 404, 405, 500, 501, 502, 503, 504))
_MACOS_LSOF_PATHS = ("/usr/sbin/lsof", "/usr/bin/lsof")


def _configure_parent_death_signal():  # type: () -> None
    """Ask Linux to terminate the backend when its supervising process dies."""

    if os.name != "posix" or not hasattr(signal, "SIGTERM"):
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        prctl = getattr(libc, "prctl", None)
        if prctl is not None:
            prctl(1, int(signal.SIGTERM), 0, 0, 0)
    except (AttributeError, OSError, TypeError):
        # Platforms without Linux prctl retain the normal process-group cleanup.
        return


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
    if username is not None or password is not None:
        if username is None or password is None:
            raise ValueError("proxy authentication requires both username and password")
    # The provider body remains opaque and is parsed by Mihomo 1.19.29.  The
    # generated projection contains no controller or secondary network source.
    escaped_path = str(provider_path).replace("\\", "/").replace("'", "''")
    lines = [
        "%s: %d" % (
            {
                "mixed": "mixed-port",
                "http": "port",
                "socks5": "socks-port",
            }[listener_protocol],
            port,
        ),
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
    if username is not None:
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
        system_root = _windows_system_root()
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


def _windows_system_root():  # type: () -> str
    """Read the Windows directory from the native API, not ambient variables."""

    try:
        import ctypes

        get_directory = ctypes.windll.kernel32.GetWindowsDirectoryW
        get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        get_directory.restype = ctypes.c_uint32
        capacity = 260
        while capacity <= 32768:
            buffer = ctypes.create_unicode_buffer(capacity)
            length = int(get_directory(buffer, capacity))
            if length == 0:
                return ""
            if length < capacity:
                return buffer.value
            capacity *= 2
    except (AttributeError, OSError, TypeError, ValueError):
        # A native Windows API failure leaves the child environment unusable.
        return ""
    return ""


def _linux_listener_inodes(port, address):  # type: (int, str) -> object
    """Return LISTEN socket inodes for one IPv4 port from procfs."""

    try:
        expected_address = "%08X" % int.from_bytes(socket.inet_aton(address), "little")
    except (OSError, ValueError):
        return set()
    result = set()
    # JerryProxy currently publishes only IPv4 listener addresses.  Do not let
    # an unrelated IPv6 socket owned by the same PID satisfy an IPv4 probe.
    for table_name in ("tcp",):
        table = Path("/proc/net/%s" % table_name)
        if not table.is_file():
            continue
        try:
            lines = table.read_text(encoding="ascii").splitlines()[1:]
        except (OSError, UnicodeError):
            # Procfs may disappear while a process is being reaped.
            continue
        for line in lines:
            fields = line.split()
            if len(fields) <= 9 or fields[3] != "0A":
                continue
            endpoint = fields[1].split(":", 1)
            if len(endpoint) != 2:
                continue
            try:
                current_port = int(endpoint[1], 16)
            except ValueError:
                continue
            if current_port != port:
                continue
            if endpoint[0].upper() != expected_address:
                continue
            result.add(fields[9])
    return result


def _linux_process_socket_inodes(pid):  # type: (int) -> object
    root = Path("/proc/%d/fd" % pid)
    if not root.is_dir():
        return None
    try:
        entries = tuple(root.iterdir())
    except OSError:
        return None
    result = set()
    for entry in entries:
        try:
            target = os.readlink(str(entry))
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            result.add(target[8:-1])
    return result


def _listener_owned_by_linux_process(process, port, address):  # type: (object, int, str) -> object
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    listener_inodes = _linux_listener_inodes(port, address)
    process_inodes = _linux_process_socket_inodes(pid)
    if process_inodes is None:
        return None
    return bool(listener_inodes.intersection(process_inodes))


def _listener_owned_by_macos_process(process, port, address):  # type: (object, int, str) -> object
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    executable = None
    for candidate in _MACOS_LSOF_PATHS:
        path = Path(candidate)
        if path.is_file() and not is_path_alias(path):
            executable = candidate
            break
    if executable is None:
        # A PATH-provided lsof is not an ownership primitive: it can be
        # replaced by the caller and forge a successful readiness result.
        return None
    try:
        selector = "-iTCP:%d" % port if address == "0.0.0.0" else "-iTCP@%s:%d" % (address, port)
        result = subprocess.run(
            [
                executable,
                "-nP",
                "-a",
                "-p",
                str(pid),
                selector,
                "-sTCP:LISTEN",
                "-Fpn",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=0.5,
        )
    except (OSError, subprocess.TimeoutExpired):
        # macOS installations without lsof cannot prove listener ownership.
        return None
    for line in result.stdout.splitlines():
        if not line.startswith(b"n"):
            continue
        endpoint = line[1:].split(None, 1)[0].decode("ascii", "ignore")
        if address == "0.0.0.0":
            if endpoint in ("*:%d" % port, "0.0.0.0:%d" % port):
                return True
        elif endpoint == "%s:%d" % (address, port):
            return True
    return False


def _listener_owned_by_windows_process(process, port, address):  # type: (object, int, str) -> object
    """Use GetExtendedTcpTable when the native Windows API is available."""

    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        import ctypes

        class Row(ctypes.Structure):
            _fields_ = [
                ("state", ctypes.c_ulong),
                ("local_address", ctypes.c_ulong),
                ("local_port", ctypes.c_ulong),
                ("remote_address", ctypes.c_ulong),
                ("remote_port", ctypes.c_ulong),
                ("owning_pid", ctypes.c_ulong),
            ]

        get_table = ctypes.windll.iphlpapi.GetExtendedTcpTable
        get_table.restype = ctypes.c_ulong
        get_table.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_bool,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        size = ctypes.c_ulong(0)
        family_ipv4 = 2
        table_owner_pid_listener = 2
        error = int(get_table(None, ctypes.byref(size), False, family_ipv4, table_owner_pid_listener, 0))
        if error not in (0, 122) or size.value <= ctypes.sizeof(ctypes.c_ulong):
            return None
        buffer = ctypes.create_string_buffer(size.value)
        error = int(
            get_table(buffer, ctypes.byref(size), False, family_ipv4, table_owner_pid_listener, 0)
        )
        if error != 0:
            return None
        count = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ulong)).contents.value
        rows = (Row * count).from_buffer(buffer, ctypes.sizeof(ctypes.c_ulong))
        expected_address = int.from_bytes(socket.inet_aton(address), "little")
        for row in rows:
            # Windows stores the TCP port in network byte order inside a
            # DWORD.  Reading all four bytes as a big-endian integer turns
            # ordinary ports such as 17777 into a different value.
            current_port = _windows_tcp_port(row.local_port)
            if (
                current_port == port
                and row.owning_pid == pid
                and row.local_address == expected_address
            ):
                return True
        return False
    except (AttributeError, OSError, TypeError, ValueError):
        # Unsupported API variants cannot prove listener ownership.
        return None


def _windows_tcp_port(value):  # type: (object) -> int
    """Decode the network-order low word used by GetExtendedTcpTable."""

    return socket.ntohs(int(value) & 0xFFFF)


def _listener_owned_by_process(process, port, address):  # type: (object, int, str) -> object
    if sys.platform.startswith("linux"):
        return _listener_owned_by_linux_process(process, port, address)
    if sys.platform == "darwin":
        return _listener_owned_by_macos_process(process, port, address)
    if os.name == "nt":
        return _listener_owned_by_windows_process(process, port, address)
    return None


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
        self._log_lock = threading.Lock()
        self._readiness_username = None
        self._readiness_password = None
        self._readiness_protocol = "mixed"
        self._readiness_address = "127.0.0.1"

    def set_log_lock(self, log_lock):
        """Share the session log lock with the foreground runtime owner."""

        if log_lock is None or not hasattr(log_lock, "__enter__"):
            raise ValueError("log_lock must be a context-manager lock")
        self._log_lock = log_lock

    def set_readiness_challenge(self, username, password, protocol, address):
        """Set the private protocol challenge used to reject port substitutes."""

        if protocol not in LISTENER_PROTOCOLS or address not in LISTENER_ADDRESSES:
            raise ValueError("invalid listener readiness challenge")
        if (username is None) != (password is None):
            raise ValueError("readiness credentials must be supplied together")
        self._readiness_username = username
        self._readiness_password = password
        self._readiness_protocol = protocol
        self._readiness_address = address

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

    def _write_backend_line(self, payload):
        """Persist and forward one redacted line from the merged child stream."""

        if self.backend_log_level == "OFF":
            return
        # The child stream is deliberately opaque to the process supervisor:
        # decode only for diagnostics, redact credentials, and make control
        # characters visible before either persistence or terminal rendering.
        safe = terminal_safe_text(redact_bytes(payload)).strip()
        if not safe:
            return
        encoded = safe.encode("utf-8")
        if len(encoded) > MAXIMUM_BACKEND_LINE_BYTES:
            safe = encoded[:MAXIMUM_BACKEND_LINE_BYTES].decode("utf-8", "ignore") + " [line truncated]"
        line = ("[%s] %s\n" % (self.backend_name, safe)).encode("utf-8", "replace")
        descriptor = -1
        try:
            with self._log_lock:
                _private_directory(self.log_path.parent, boundary=self.log_path.parent)
                if is_path_alias(self.log_path):
                    raise RuntimeSessionError("runtime log path is aliased")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(str(self.log_path), flags, 0o600)
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode):
                    raise RuntimeSessionError("runtime log path is not a regular file")
                if os.name == "posix" and stat.S_IMODE(status.st_mode) != 0o600:
                    raise RuntimeSessionError("runtime log path has unsafe permissions")
                if status.st_size >= MAXIMUM_LOG_BYTES:
                    raise RuntimeSessionError("runtime log exceeds its size bound")
                os.write(descriptor, line[: MAXIMUM_LOG_BYTES - status.st_size])
        except (OSError, RuntimeSessionError, ValueError) as error:
            # Log publication can fail after launch; draining must continue.
            self._record_drain_error(error)
        finally:
            if descriptor != -1:
                os.close(descriptor)
        if self.log_sink is not None:
            try:
                self.log_sink(self.backend_name, "INFO", safe)
            except (OSError, ValueError):
                # A foreground log sink may close during shutdown.
                pass

    def _drain(self, stream):
        stream_descriptor = None
        try:
            stream_descriptor = stream.fileno()
        except (AttributeError, OSError, ValueError):
            # In-memory test streams do not expose an OS file descriptor.
            stream_descriptor = None
        pending = bytearray()
        pending_line_truncated = False
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
                pending.extend(chunk)
                while True:
                    try:
                        line_end = pending.index(10)
                    except ValueError:
                        break
                    line = bytes(pending[:line_end])
                    del pending[: line_end + 1]
                    if line.endswith(b"\r"):
                        line = line[:-1]
                    if pending_line_truncated:
                        line += b" [line truncated]"
                        pending_line_truncated = False
                    self._write_backend_line(line)
                # A backend may write a progress/blob line without a newline.
                # Emit bounded chunks so live diagnostics cannot consume
                # unbounded memory or wait for EOF, even across pipe reads.
                while len(pending) > MAXIMUM_BACKEND_LINE_BYTES:
                    line = bytes(pending[:MAXIMUM_BACKEND_LINE_BYTES])
                    del pending[:MAXIMUM_BACKEND_LINE_BYTES]
                    self._write_backend_line(line + b" [line truncated]")
                    pending_line_truncated = True
        finally:
            if pending:
                line = bytes(pending)
                if pending_line_truncated:
                    line += b" [line truncated]"
                self._write_backend_line(line)
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
                if sys.platform.startswith("linux"):
                    options["preexec_fn"] = _configure_parent_death_signal
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

    @staticmethod
    def _read_exact(stream, size):
        value = bytearray()
        while len(value) < size:
            chunk = stream.recv(size - len(value))
            if not chunk:
                raise RuntimeSessionError("listener closed during readiness challenge")
            value.extend(chunk)
        return bytes(value)

    def _challenge_listener(self, port):
        timeout = 0.3
        with socket.create_connection((self._readiness_address, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            if self._readiness_protocol == "socks5":
                method = b"\x02" if self._readiness_username is not None else b"\x00"
                stream.sendall(b"\x05\x01" + method)
                response = self._read_exact(stream, 2)
                if response[0] != 5 or response[1] != method[0]:
                    raise RuntimeSessionError("listener failed the SOCKS5 readiness challenge")
                if method == b"\x02":
                    username = self._readiness_username.encode("ascii")
                    password = self._readiness_password.encode("ascii")
                    if len(username) > 255 or len(password) > 255:
                        raise RuntimeSessionError("listener credentials exceed SOCKS5 limits")
                    stream.sendall(b"\x01" + bytes((len(username),)) + username + bytes((len(password),)) + password)
                    auth_response = self._read_exact(stream, 2)
                    if auth_response != b"\x01\x00":
                        raise RuntimeSessionError("listener rejected the SOCKS5 readiness credentials")
                return
            request = [
                b"CONNECT 127.0.0.1:1 HTTP/1.1",
                b"Host: 127.0.0.1:1",
                b"Proxy-Connection: close",
            ]
            if self._readiness_username is not None:
                credentials = (self._readiness_username + ":" + self._readiness_password).encode("ascii")
                request.append(b"Proxy-Authorization: Basic " + base64.b64encode(credentials))
            stream.sendall(b"\r\n".join(request) + b"\r\n\r\n")
            first_line = self._read_exact(stream, 1)
            while not first_line.endswith(b"\r\n"):
                first_line += self._read_exact(stream, 1)
                if len(first_line) > 256:
                    raise RuntimeSessionError("listener returned an invalid HTTP readiness response")
            parts = first_line[:-2].split(None, 2)
            if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or len(parts[1]) != 3:
                raise RuntimeSessionError("listener returned an invalid HTTP readiness response")
            if parts[1] == b"407":
                raise RuntimeSessionError("listener rejected the HTTP readiness credentials")
            try:
                status = int(parts[1])
            except ValueError as error:
                # The status line is backend-controlled protocol output.
                raise RuntimeSessionError("listener returned an invalid HTTP readiness response") from error
            if status not in _HTTP_READINESS_STATUSES:
                raise RuntimeSessionError("listener returned an unexpected HTTP readiness status")

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
                self._challenge_listener(port)
                ownership = _listener_owned_by_process(self.process, port, self._readiness_address)
                if ownership is not True:
                    raise RuntimeSessionError("cannot prove listener ownership by the Mihomo process")
                return
            except OSError:
                time.sleep(0.05)
            except RuntimeSessionError:
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
