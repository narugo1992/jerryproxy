"""Mihomo 1.19.29 foreground projection for an opaque NodeSet."""

import base64
import json
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
            prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            prctl.restype = ctypes.c_int
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
    if (username is None) != (password is None):
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


def _windows_create_job():  # type: () -> object
    """Create a kill-on-close Job Object, or return None when unavailable."""

    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            # JOBOBJECT_BASIC_LIMIT_INFORMATION is ordered exactly as the
            # native ABI; flags is the final DWORD, not the first field.
            _fields_ = [
                ("per_process_user_time_limit", ctypes.c_longlong),
                ("per_job_user_time_limit", ctypes.c_longlong),
                ("limit_flags", wintypes.DWORD),
                ("minimum_working_set", ctypes.c_size_t),
                ("maximum_working_set", ctypes.c_size_t),
                ("active_process_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling_class", wintypes.DWORD),
            ]
        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class ExtendedLimit(ctypes.Structure):
            _fields_ = [("basic", BasicLimit), ("io", IoCounters), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t),
                        ("peak_job_memory", ctypes.c_size_t)]

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None
        limits = ExtendedLimit()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION.
        limits.basic.limit_flags = 0x2000
        if not kernel32.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            kernel32.CloseHandle(handle)
            return None
        return handle
    except (AttributeError, OSError, TypeError, ValueError):
        # Native APIs may be absent or blocked by the host policy.
        return None


def _windows_assign_job(handle, process_handle):  # type: (object, object) -> bool
    if os.name != "nt" or handle is None:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.kernel32.AssignProcessToJobObject(handle, process_handle))
    except (AttributeError, OSError, TypeError):
        return False


def _windows_close_job(handle):  # type: (object) -> None
    if handle is None or os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.CloseHandle(handle)
    except (AttributeError, OSError, TypeError):
        pass


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
    pid = getattr(process, "backend_pid", None) or getattr(process, "pid", None)
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    listener_inodes = _linux_listener_inodes(port, address)
    process_inodes = _linux_process_socket_inodes(pid)
    if process_inodes is None:
        return None
    return bool(listener_inodes.intersection(process_inodes))


def _listener_owned_by_macos_process(process, port, address):  # type: (object, int, str) -> object
    pid = getattr(process, "backend_pid", None) or getattr(process, "pid", None)
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

    pid = getattr(process, "backend_pid", None) or getattr(process, "pid", None)
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


def _linux_process_start_time(pid):  # type: (int) -> object
    """Read procfs start time, which disambiguates a reused PID."""

    try:
        text = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
        closing = text.rfind(")")
        fields = text[closing + 2 :].split()
        # The post-comm fields start at proc field 4, so field 22 is index 19.
        return int(fields[19]) if len(fields) > 19 else None
    except (OSError, ValueError, UnicodeError):
        return None


def _linux_process_parent(pid):  # type: (int) -> object
    """Return a Linux process parent PID using the same robust stat parser."""

    try:
        text = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
        closing = text.rfind(")")
        fields = text[closing + 2 :].split()
        # Proc field 4 (ppid) is index 1 after the comm field.
        return int(fields[1]) if len(fields) > 1 else None
    except (OSError, ValueError, UnicodeError):
        return None


def _linux_process_group(pid):  # type: (int) -> object
    """Return the process-group ID from procfs without following aliases."""

    try:
        text = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
        closing = text.rfind(")")
        fields = text[closing + 2 :].split()
        return int(fields[2]) if len(fields) > 2 else None
    except (OSError, ValueError, UnicodeError):
        return None


def _linux_process_session(pid):  # type: (int) -> object
    """Return the process-session ID from procfs without following aliases."""

    try:
        text = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
        closing = text.rfind(")")
        fields = text[closing + 2 :].split()
        return int(fields[3]) if len(fields) > 3 else None
    except (OSError, ValueError, UnicodeError):
        return None


def _macos_process_info(pid):  # type: (int) -> object
    """Return ``(ppid, pgid, sid, start_token)`` from the fixed system ps."""

    if sys.platform != "darwin":
        return None
    try:
        result = subprocess.run(
            ["/bin/ps", "-o", "ppid=", "-p", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=0.5,
        )
        ppid = int(result.stdout.decode("ascii", "strict").strip())
        pgid = os.getpgid(pid)
        sid = os.getsid(pid)
        result = subprocess.run(
            ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=0.5,
        )
        start_token = result.stdout.decode("ascii", "strict").strip()
        if not start_token:
            return None
        return ppid, pgid, sid, start_token
    except (AttributeError, OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        # A missing or blocked system process table cannot authenticate a child.
        return None


def _posix_process_start_time(pid):  # type: (int) -> object
    if sys.platform.startswith("linux"):
        return _linux_process_start_time(pid)
    information = _macos_process_info(pid)
    return information[3] if information is not None else None


def _posix_process_parent(pid):  # type: (int) -> object
    if sys.platform.startswith("linux"):
        return _linux_process_parent(pid)
    information = _macos_process_info(pid)
    return information[0] if information is not None else None


def _posix_process_group(pid):  # type: (int) -> object
    if sys.platform.startswith("linux"):
        return _linux_process_group(pid)
    information = _macos_process_info(pid)
    return information[1] if information is not None else None


def _posix_process_session(pid):  # type: (int) -> object
    if sys.platform.startswith("linux"):
        return _linux_process_session(pid)
    information = _macos_process_info(pid)
    return information[2] if information is not None else None


def _posix_process_identity_matches(pid, start_time):  # type: (int, object) -> bool
    if start_time is None:
        return False
    return _posix_process_start_time(pid) == start_time


def _linux_process_group_members(pgid, session_id):  # type: (int, int) -> tuple
    """Return current process IDs in one verified process group/session."""

    if not sys.platform.startswith("linux"):
        return ()
    members = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return ()
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if _linux_process_group(pid) == pgid and _linux_process_session(pid) == session_id:
            members.append(pid)
    return tuple(sorted(set(members)))


def _windows_read_private_metadata(path, maximum):  # type: (Path, int) -> bytes
    """Read metadata through a native Windows no-follow handle."""

    if os.name != "nt":
        raise RuntimeSessionError("Windows metadata reader is unavailable")
    current = Path(path)
    while True:
        if is_path_alias(current):
            raise RuntimeSessionError("mihomo guardian metadata path is aliased")
        if current.parent == current:
            break
        current = current.parent
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        get_tag = kernel32.GetFileInformationByHandleEx
        get_tag.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD]
        get_tag.restype = wintypes.BOOL
        get_size = kernel32.GetFileSizeEx
        get_size.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
        get_size.restype = wintypes.BOOL
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        read_file.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        class AttributeTagInfo(ctypes.Structure):
            _fields_ = [("file_attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

        invalid = ctypes.c_void_p(-1).value
        flags = 0x00200000 | 0x02000000  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
        handle = create_file(
            str(Path(path)),
            0x80000000,
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            3,
            flags,
            None,
        )
        handle_value = ctypes.cast(handle, ctypes.c_void_p).value
        if handle_value in (None, invalid):
            error = ctypes.get_last_error()
            if error in (2, 3):
                raise FileNotFoundError(error, "metadata file is not available")
            raise RuntimeSessionError("mihomo guardian metadata could not be opened")
        try:
            before = AttributeTagInfo()
            if not get_tag(handle, 9, ctypes.byref(before), ctypes.sizeof(before)):
                raise RuntimeSessionError("mihomo guardian metadata attributes are unavailable")
            if before.file_attributes & (0x10 | 0x400):
                raise RuntimeSessionError("mihomo guardian metadata is a directory or reparse point")
            size = ctypes.c_longlong()
            if not get_size(handle, ctypes.byref(size)):
                raise RuntimeSessionError("mihomo guardian metadata size is unavailable")
            if size.value < 0 or size.value > maximum:
                raise RuntimeSessionError("mihomo guardian metadata is oversized")
            chunks = []
            remaining = int(size.value)
            while remaining:
                amount = min(65536, remaining)
                buffer = ctypes.create_string_buffer(amount)
                read = wintypes.DWORD()
                if not read_file(handle, buffer, amount, ctypes.byref(read), None):
                    raise RuntimeSessionError("mihomo guardian metadata read failed")
                if read.value <= 0:
                    raise RuntimeSessionError("mihomo guardian metadata ended early")
                chunks.append(buffer.raw[: read.value])
                remaining -= int(read.value)
            after = AttributeTagInfo()
            if not get_tag(handle, 9, ctypes.byref(after), ctypes.sizeof(after)):
                raise RuntimeSessionError("mihomo guardian metadata attributes changed")
            if (before.file_attributes, before.reparse_tag) != (after.file_attributes, after.reparse_tag):
                raise RuntimeSessionError("mihomo guardian metadata changed while being read")
            value = b"".join(chunks)
            if len(value) != int(size.value):
                raise RuntimeSessionError("mihomo guardian metadata changed while being read")
            return value
        finally:
            close_handle(handle)
    except (AttributeError, OSError, TypeError, ValueError) as error:
        # Missing files remain retryable; native API failures are terminal.
        if isinstance(error, FileNotFoundError):
            raise
        raise RuntimeSessionError("mihomo guardian metadata native read failed") from error


def _read_private_metadata(path, maximum):  # type: (Path, int) -> bytes
    """Read one private metadata file through a pinned, no-follow descriptor."""

    path = Path(path)
    descriptor = -1
    parent = -1
    try:
        if os.name == "posix" and os.open in os.supports_dir_fd:
            absolute = Path(os.path.abspath(str(path)))
            parts = absolute.parts
            if len(parts) < 2:
                raise RuntimeSessionError("guardian metadata path is invalid")
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            parent = os.open(parts[0] or os.sep, directory_flags)
            for component in parts[1:-1]:
                child = os.open(component, directory_flags, dir_fd=parent)
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode):
                    os.close(child)
                    raise RuntimeSessionError("guardian metadata parent is not a directory")
                os.close(parent)
                parent = child
            leaf_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(parts[-1], leaf_flags, dir_fd=parent)
        elif os.name == "nt":
            # Ordinary ``os.open`` follows reparse points.  Use the native
            # OPEN_REPARSE_POINT handle path instead of weakening this boundary.
            return _windows_read_private_metadata(path, maximum)
        else:
            if is_path_alias(path):
                raise RuntimeSessionError("mihomo guardian metadata is aliased")
            descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeSessionError("mihomo guardian metadata is not a regular file")
        if os.name == "posix" and stat.S_IMODE(before.st_mode) != 0o600:
            raise RuntimeSessionError("mihomo guardian metadata permissions are unsafe")
        if before.st_size < 0 or before.st_size > maximum:
            raise RuntimeSessionError("mihomo guardian metadata is oversized")
        chunks = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_size)
        identity_after = (after.st_dev, after.st_ino, after.st_mode, after.st_size)
        if identity_before != identity_after or len(b"".join(chunks)) != before.st_size:
            raise RuntimeSessionError("mihomo guardian metadata changed while being read")
        return b"".join(chunks)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if parent != -1:
            os.close(parent)


def _linux_process_identity_matches(pid, start_time):  # type: (int, object) -> bool
    if start_time is None:
        return False
    return _linux_process_start_time(pid) == start_time


def _linux_pidfd_open(pid):  # type: (int) -> int
    """Open a Linux pidfd on Python versions with or without ``os.pidfd_open``."""

    opener = getattr(os, "pidfd_open", None)
    if opener is not None:
        return int(opener(pid))
    # Python 3.7-3.8 do not expose os.pidfd_open.  Use the stable Linux
    # syscall number when the host kernel supports pidfds; callers may fall
    # back to the authenticated process-group boundary when it does not.
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        result = syscall(434, int(pid), 0)
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return int(result)
    except (AttributeError, OSError, TypeError, ValueError):
        raise OSError("pidfd_open is unavailable")


def _linux_optional_pidfd_open(pid):  # type: (int) -> object
    """Return a pidfd when available, otherwise use group identity cleanup."""

    try:
        return _linux_pidfd_open(pid)
    except OSError:
        # Older kernels, including some Python 3.7 deployment hosts, do not
        # implement pidfds.  Guardian start-time and process-group checks are
        # still required before any fallback signal is sent.
        return None


def _linux_pidfd_send_signal(pidfd, signum):  # type: (int, int) -> None
    """Send through a pidfd on Python 3.7+ without a second lock primitive."""

    sender = getattr(signal, "pidfd_send_signal", None)
    if sender is not None:
        sender(pidfd, signum)
        return
    # Python 3.7-3.10 do not expose the syscall even when the kernel does.
    # pidfd_send_signal is syscall 424 on the supported Linux architectures.
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        result = syscall(424, int(pidfd), int(signum), 0, 0)
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    except (AttributeError, OSError, TypeError, ValueError):
        raise OSError("pidfd_send_signal is unavailable")


class MihomoProcess(object):
    """One guarded Mihomo child with opaque fixed-output accounting."""

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
        self._pidfd = None
        self._linux_start_time = None
        self.backend_pid = None
        self._backend_pidfd = None
        self._backend_start_time = None
        self._backend_pgid = None
        self._backend_sid = None
        self._guardian_metadata_path = self.session_root / ".mihomo-guardian.json"
        self._windows_job = None
        self._start_gate_write = None
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

    def _release_start_gate(self):
        """Authorize the guardian to launch its backend exactly once."""

        descriptor = self._start_gate_write
        self._start_gate_write = None
        if descriptor is None:
            return
        try:
            remaining = b"\x01"
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("start authorization pipe made no progress")
                remaining = remaining[written:]
        except OSError as error:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise RuntimeSessionError("mihomo guardian authorization failed") from error
        try:
            os.close(descriptor)
        except OSError as error:
            raise RuntimeSessionError("mihomo guardian authorization cleanup failed") from error

    def _cancel_start_gate(self):
        """Close a pending authorization pipe so a guardian cannot start."""

        descriptor = self._start_gate_write
        self._start_gate_write = None
        if descriptor is None:
            return
        try:
            os.close(descriptor)
        except OSError:
            # The descriptor may already have been closed during a failed start.
            pass

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
        """Persist and forward one bounded, redacted merged backend line."""

        if self.backend_log_level == "OFF":
            return
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

    def _drain(self, stream, source=None):
        del source
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
        # The guardian module is part of the installed package.  A source-tree
        # invocation needs its package parent explicitly because the child cwd
        # is the private session lease rather than the repository root.
        package_parent = str(Path(__file__).resolve().parents[2])
        env["PYTHONPATH"] = package_parent
        if os.path.lexists(str(self.log_path)):
            if is_path_alias(self.log_path) or not self.log_path.is_file():
                raise RuntimeSessionError("runtime log path is aliased or not a regular file")
            if os.name == "posix" and stat.S_IMODE(self.log_path.stat().st_mode) != 0o600:
                raise RuntimeSessionError("runtime log path has unsafe permissions")
        real_popen = isinstance(getattr(subprocess, "Popen"), type)
        gate_read = None
        if real_popen:
            gate_read, gate_write = os.pipe()
            self._start_gate_write = gate_write
            try:
                os.set_inheritable(gate_read, True)
                os.set_inheritable(gate_write, False)
            except (OSError, ValueError) as error:
                self._cancel_start_gate()
                os.close(gate_read)
                raise RuntimeSessionError("mihomo guardian authorization setup failed") from error
        try:
            if os.name == "nt" and real_popen:
                self._windows_job = _windows_create_job()
                if self._windows_job is None:
                    raise RuntimeSessionError("mihomo Windows Job containment is unavailable")
            options = {
                "cwd": str(self.session_root),
                "env": env,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                # Merge both child streams before the supervisor sees them;
                # callers only need the backend owner label, never stdout vs stderr.
                "stderr": subprocess.STDOUT,
                "shell": False,
                "close_fds": os.name != "nt",
                "universal_newlines": False,
            }
            if os.name == "posix":
                if gate_read is not None:
                    options["pass_fds"] = (gate_read,)
                options["start_new_session"] = True
                if sys.platform.startswith("linux"):
                    options["preexec_fn"] = _configure_parent_death_signal
            else:
                # The guardian waits on the inherited authorization pipe. The
                # Job Object is assigned before the backend is allowed to run.
                options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if getattr(sys, "frozen", False):
                arguments = [sys.executable, "--jerryproxy-guardian"]
            else:
                guardian = Path(__file__).with_name("guardian.py")
                arguments = [sys.executable, str(guardian)]
            arguments.extend(
                [
                "--executable",
                str(self.executable),
                "--config",
                str(self.config_path),
                "--metadata",
                str(self._guardian_metadata_path),
                "--session-root",
                str(self.session_root),
                ]
            )
            if gate_read is not None:
                arguments.extend(["--start-gate", str(gate_read)])
            self.process = subprocess.Popen(arguments, **options)
        except OSError as error:
            self._cancel_start_gate()
            _windows_close_job(self._windows_job)
            self._windows_job = None
            # Executable/guardian launch failures are terminal runtime errors.
            raise RuntimeSessionError("mihomo backend launch failed") from error
        except RuntimeSessionError:
            self._cancel_start_gate()
            _windows_close_job(self._windows_job)
            self._windows_job = None
            raise
        finally:
            if gate_read is not None:
                try:
                    os.close(gate_read)
                except OSError:
                    pass
        if os.name == "nt" and real_popen:
            process_handle = getattr(self.process, "_handle", None)
            if process_handle is None or not _windows_assign_job(self._windows_job, process_handle):
                self._windows_abort_start()
                raise RuntimeSessionError("mihomo Windows Job containment is unavailable")
        popen_type = getattr(subprocess, "Popen")
        if isinstance(popen_type, type) and isinstance(self.process, popen_type):
            if sys.platform.startswith("linux"):
                self._pidfd = _linux_optional_pidfd_open(self.process.pid)
                if self._pidfd is not None:
                    try:
                        _linux_pidfd_send_signal(self._pidfd, 0)
                    except OSError:
                        try:
                            os.close(self._pidfd)
                        except OSError:
                            pass
                        self._pidfd = None
                self._linux_start_time = _linux_process_start_time(self.process.pid)
                if self._linux_start_time is None:
                    self._abort_start()
                    raise RuntimeSessionError("Linux guardian identity is unavailable")
        try:
            self._release_start_gate()
        except RuntimeSessionError:
            self._abort_start()
            raise
        if isinstance(popen_type, type) and isinstance(self.process, popen_type):
            self._load_guardian_identity(timeout=5.0)
            if sys.platform.startswith("linux"):
                self._backend_pidfd = _linux_optional_pidfd_open(self.backend_pid)
        stream = getattr(self.process, "stdout", None)
        if stream is not None:
            thread = threading.Thread(
                target=self._drain,
                args=(stream,),
                name="jerryproxy-backend-output",
            )
            thread.daemon = True
            thread.start()
            self._threads.append(thread)
        return self.process

    def _load_guardian_identity(self, timeout=5.0):
        """Authenticate the guardian's backend identity before draining output."""

        deadline = time.monotonic() + max(0.01, float(timeout))
        value = None
        while time.monotonic() < deadline:
            try:
                raw = _read_private_metadata(self._guardian_metadata_path, 4096)
                value = json.loads(raw.decode("ascii"))
                break
            except OSError:
                # The guardian may still be atomically publishing its record.
                pass
            except (RuntimeSessionError, UnicodeError, ValueError) as error:
                # A malformed or aliased record is terminal; never leave an
                # already-launched guardian running after failed authentication.
                self._abort_start()
                raise RuntimeSessionError("mihomo guardian identity could not be read") from error
            if self.process.poll() is not None:
                break
            time.sleep(0.01)
        if not isinstance(value, dict):
            self._abort_start()
            raise RuntimeSessionError("mihomo guardian did not publish identity")
        pid = value.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            self._abort_start()
            raise RuntimeSessionError("mihomo guardian identity is invalid")
        self.backend_pid = pid
        self._backend_start_time = value.get("start_time")
        self._backend_pgid = value.get("pgid")
        self._backend_sid = value.get("sid")
        executable_matches = value.get("executable") == str(self.executable.absolute())
        config_matches = value.get("config") == str(self.config_path.absolute())
        if not executable_matches or not config_matches:
            self._abort_start()
            raise RuntimeSessionError("mihomo guardian identity does not match the launch plan")
        self._linux_start_time = _posix_process_start_time(self.process.pid) if os.name == "posix" else None
        if os.name == "posix":
            if self._backend_start_time is None or self._linux_start_time is None:
                self._abort_start()
                raise RuntimeSessionError("mihomo process identity is unavailable")
            if not _posix_process_identity_matches(self.backend_pid, self._backend_start_time):
                self._abort_start()
                raise RuntimeSessionError("mihomo backend identity changed during launch")
            parent = _posix_process_parent(self.backend_pid)
            if parent != self.process.pid:
                self._abort_start()
                raise RuntimeSessionError("mihomo backend is not owned by its guardian")
            if (
                self._backend_pgid != self.process.pid
                or self._backend_sid != self.process.pid
                or _posix_process_group(self.backend_pid) != self.process.pid
                or _posix_process_session(self.backend_pid) != self.process.pid
            ):
                self._abort_start()
                raise RuntimeSessionError("mihomo backend process-group identity is invalid")

    def _windows_abort_start(self):
        self._cancel_start_gate()
        process = self.process
        if process is not None:
            try:
                process.kill()
                process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        _windows_close_job(self._windows_job)
        self._windows_job = None

    def _abort_start(self):
        self._cancel_start_gate()
        if sys.platform.startswith("linux") and self.process is not None and self._pidfd is None:
            # During the pre-authentication window the Popen PID is still the
            # freshly-created session leader.  Kill only that new process
            # group; no managed backend identity has been accepted yet.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
            return
        try:
            self.stop(timeout=2.0)
        except (OSError, RuntimeSessionError, subprocess.TimeoutExpired):
            # The caller reports the containment failure; cleanup is best effort.
            pass

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
                ownership = _listener_owned_by_process(self, port, self._readiness_address)
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
        self._cancel_start_gate()
        process = self.process
        failures = []

        def note(message):
            if not failures:
                failures.append(message)

        guardian_alive = process is not None and process.poll() is None
        group_id = self._backend_pgid
        session_id = self._backend_sid
        if sys.platform.startswith("linux") and group_id is None and guardian_alive:
            group_id = process.pid
            session_id = process.pid

        def group_authorized():
            if not sys.platform.startswith("linux") or not isinstance(group_id, int) or not isinstance(session_id, int):
                return os.name == "posix" and isinstance(group_id, int)
            if self.backend_pid and _linux_process_identity_matches(self.backend_pid, self._backend_start_time):
                return (
                    _linux_process_group(self.backend_pid) == group_id
                    and _linux_process_session(self.backend_pid) == session_id
                )
            # A guardian crash can leave only forked descendants.  A non-empty
            # group/session census is still anchored by the metadata identity
            # captured before the crash and is safe to terminate as one unit.
            return bool(_linux_process_group_members(group_id, session_id))

        def signal_group(signum):
            if not group_authorized():
                return False
            try:
                os.killpg(group_id, signum)
                return True
            except OSError:
                return False

        if os.name == "posix":
            if sys.platform.startswith("linux") and guardian_alive:
                if self._pidfd is not None and not _linux_process_identity_matches(process.pid, self._linux_start_time):
                    note("guardian process identity is unavailable")
                elif self._pidfd is not None:
                    try:
                        _linux_pidfd_send_signal(self._pidfd, signal.SIGTERM)
                    except OSError as error:
                        note("guardian pidfd termination failed: %s" % error)
            if not signal_group(signal.SIGTERM):
                if guardian_alive and not sys.platform.startswith("linux"):
                    try:
                        process.terminate()
                    except OSError as error:
                        note("guardian termination failed: %s" % error)
                elif guardian_alive and sys.platform.startswith("linux"):
                    note("guardian process-group identity is unavailable")
        elif guardian_alive:
            try:
                process.terminate()
            except OSError as error:
                note("guardian termination failed: %s" % error)

        if guardian_alive:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    if sys.platform.startswith("linux") and self._pidfd is not None:
                        try:
                            if _linux_process_identity_matches(process.pid, self._linux_start_time):
                                _linux_pidfd_send_signal(self._pidfd, signal.SIGKILL)
                        except OSError as error:
                            note("guardian pidfd kill failed: %s" % error)
                    if not signal_group(signal.SIGKILL) and not sys.platform.startswith("linux"):
                        try:
                            process.kill()
                        except OSError as error:
                            note("guardian kill failed: %s" % error)
                else:
                    try:
                        process.kill()
                    except OSError as error:
                        note("guardian kill failed: %s" % error)
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    note("guardian did not stop before the cleanup deadline")

        if sys.platform.startswith("linux") and self._backend_pidfd is not None:
            if self.backend_pid and _linux_process_identity_matches(self.backend_pid, self._backend_start_time):
                try:
                    _linux_pidfd_send_signal(self._backend_pidfd, signal.SIGTERM)
                except OSError:
                    # Group termination remains authoritative when the backend races exit.
                    pass

        if os.name == "posix" and group_authorized():
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                members = (
                    _linux_process_group_members(group_id, session_id)
                    if sys.platform.startswith("linux")
                    else ()
                )
                if not members:
                    break
                time.sleep(0.02)
            if sys.platform.startswith("linux") and _linux_process_group_members(group_id, session_id):
                signal_group(signal.SIGKILL)
                kill_deadline = time.monotonic() + timeout
                while time.monotonic() < kill_deadline:
                    if not _linux_process_group_members(group_id, session_id):
                        break
                    time.sleep(0.02)
                if _linux_process_group_members(group_id, session_id):
                    note("mihomo backend descendants did not stop")

        if process is not None and process.poll() is None:
            note("mihomo guardian did not stop")
        if self._pidfd is not None:
            try:
                os.close(self._pidfd)
            except OSError:
                pass
            self._pidfd = None
        if self._backend_pidfd is not None:
            try:
                os.close(self._backend_pidfd)
            except OSError:
                pass
            self._backend_pidfd = None
        _windows_close_job(self._windows_job)
        self._windows_job = None
        try:
            if self._guardian_metadata_path.exists() and not is_path_alias(self._guardian_metadata_path):
                self._guardian_metadata_path.unlink()
        except OSError:
            self._record_drain_error("mihomo guardian metadata cleanup failed")
        for thread in self._threads:
            thread.join(timeout=timeout)
        if any(thread.is_alive() for thread in self._threads):
            note("mihomo backend log drain did not stop")
        if self._drain_errors:
            note("mihomo backend log capture failed: %s" % self._drain_errors[0])
        if failures:
            raise RuntimeSessionError(failures[0])
