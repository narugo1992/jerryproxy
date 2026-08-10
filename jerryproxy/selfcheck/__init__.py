"""Black-box integration diagnostics for a source or packaged JerryProxy CLI.

Self-check answers what a deterministic unit test cannot: whether the installed
product works on *this* host. Each module below owns one problem area, so a
failure names the area it came from rather than a line in one long file.

- :mod:`~jerryproxy.selfcheck.result` -- what a check returns, and the
  redaction and length boundary every diagnostic crosses before it is shown.
- :mod:`~jerryproxy.selfcheck.environment` -- interpreter, platform, and home.
- :mod:`~jerryproxy.selfcheck.resources` -- packaged catalog and registry.
- :mod:`~jerryproxy.selfcheck.subscription` -- classification, publication, and
  the public/secret node boundary.
- :mod:`~jerryproxy.selfcheck.runtime` -- projection, driver contract, and the
  loopback listener the product depends on.
- :mod:`~jerryproxy.selfcheck.dependencies` -- one real capability of each key
  upstream dependency.
- :mod:`~jerryproxy.selfcheck.backend` -- inventory and isolated lifecycle.
- :mod:`~jerryproxy.selfcheck.recovery` -- crash recovery driven by real
  hard-exiting children.
- :mod:`~jerryproxy.selfcheck.relay` -- bounded, integrity-checked relay probes.
- :mod:`~jerryproxy.selfcheck.fixtures` and
  :mod:`~jerryproxy.selfcheck.processes` -- synthetic backend archives and
  bounded child supervision shared by the mutating probes.
- :mod:`~jerryproxy.selfcheck.runner` -- assembly, rendering, and entry point.
"""

from .result import CheckResult, ansi_color_enabled
from .runner import build_checks, run_checks, run_self_check

__all__ = [
    "CheckResult",
    "ansi_color_enabled",
    "build_checks",
    "run_checks",
    "run_self_check",
]
