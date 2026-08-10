"""Checks that execute one real capability of a key upstream dependency."""

import io
import logging
import tempfile
from pathlib import Path

from ..errors import JerryProxyBusyError, JerryProxyError
from ..home import JerryProxyPaths
from ..lock import JerryProxyOperationLock, filelock_status
from .result import CheckResult, _error_result


def _check_console_rendering():
    """Render through the console and handler the startup guide uses.

    Rich is reached only when ``server`` prints its guide, so in a frozen build
    this import chain is otherwise first executed in front of a user. Exercising
    it here turns a missing hidden import or a failed width detection into a
    diagnostic instead of a broken first run.
    """

    try:
        from rich.console import Console
        from rich.logging import RichHandler
        from rich.markup import escape as rich_escape

        buffer = io.StringIO()
        console = Console(file=buffer, width=100, soft_wrap=True, no_color=True)
        handler = RichHandler(
            console=console,
            show_time=False,
            show_path=False,
            rich_tracebacks=False,
            markup=True,
        )
        record = logging.LogRecord(
            name="jerryproxy.self-check",
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg=rich_escape("proxy ready at http://127.0.0.1:7890 [not-a-tag]"),
            args=(),
            exc_info=None,
        )
        handler.emit(record)
        rendered = buffer.getvalue()
        if "http://127.0.0.1:7890" not in rendered:
            return CheckResult.fail("the console handler dropped the rendered message")
        if "[not-a-tag]" not in rendered:
            return CheckResult.fail("console markup escaping consumed literal bracket text")
        if console.width <= 0:
            return CheckResult.fail("console width detection produced an unusable width")
    except ImportError as error:
        # A frozen build that missed the hidden import fails exactly here.
        return _error_result(error)
    except (OSError, RuntimeError, ValueError) as error:
        # Rendering and width detection are host-dependent operations.
        return _error_result(error)
    return CheckResult.ok("console rendering, markup escaping, and width detection succeeded")


def _check_filelock():
    status = filelock_status()
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-filelock-self-check-") as temporary:
            paths = JerryProxyPaths(Path(temporary) / ".jerryproxy")
            with JerryProxyOperationLock(paths):
                try:
                    with JerryProxyOperationLock(paths):
                        return CheckResult.fail("filelock allowed a concurrent exclusive acquisition")
                except JerryProxyBusyError:
                    # A second acquisition must observe the real platform lock as busy.
                    pass
            with JerryProxyOperationLock(paths):
                pass
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Temporary-home creation and real lock operations may fail in the host environment.
        return _error_result(error)
    detail = "%s; exclusive acquire, contention, release, and reacquire succeeded" % status.detail
    if status.level == "WARN":
        return CheckResult.warn(detail)
    return CheckResult.ok(detail)
