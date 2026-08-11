"""Check assembly, rendering, and the public self-check entry point."""

import os
import platform
import sys

from ..backend.relay import iter_builtin_relays
from ..config.meta import __VERSION__
from .backend import _check_backend_inventory, _check_isolated_backend_lifecycle
from .dependencies import _check_console_rendering, _check_filelock
from .environment import (
    _check_home_layout,
    _check_home_writable,
    _check_platform,
    _check_private_permissions,
    _check_runtime,
)
from .processes import _check_process_supervision, _ProcessSupervision
from .recovery import _check_activation_recovery, _check_install_recovery, _check_removal_recovery
from .relay import _check_relay, _check_relay_in_process
from .resources import (
    _check_backend_catalog,
    _check_backend_catalog_selection,
    _check_backend_registry,
)
from .result import (
    _ANSI_BOLD,
    _ANSI_CYAN,
    _ANSI_GREEN,
    _ANSI_RED,
    _ANSI_YELLOW,
    _bounded_diagnostic,
    _bounded_line,
    _paint,
)
from .runtime import (
    _check_loopback_listener,
    _check_runtime_driver_contract,
    _check_runtime_projection,
)
from .subscription import (
    _check_node_source_boundary,
    _check_provider_document,
    _check_subscription_parser,
    _check_subscription_state,
)


def build_checks(paths, relay_session_factory=None):
    supervision = _ProcessSupervision()
    checks = (
        ("Python runtime", _check_runtime),
        ("platform detection", _check_platform),
        ("home directory layout", lambda: _check_home_layout(paths)),
        ("home write access", lambda: _check_home_writable(paths)),
        ("private directory permissions", lambda: _check_private_permissions(paths)),
        ("backend registry", _check_backend_registry),
        ("packaged backend catalog", _check_backend_catalog),
        ("catalog platform selection", _check_backend_catalog_selection),
        ("subscription parser", _check_subscription_parser),
        ("provider document parser", _check_provider_document),
        ("subscription state", _check_subscription_state),
        ("node source boundary", _check_node_source_boundary),
        ("runtime projection", _check_runtime_projection),
        ("runtime driver contract", _check_runtime_driver_contract),
        ("loopback listener", _check_loopback_listener),
        ("console rendering", _check_console_rendering),
        ("filelock compatibility", _check_filelock),
        ("backend inventory", lambda: _check_backend_inventory(paths)),
        ("isolated backend lifecycle", _check_isolated_backend_lifecycle),
        ("recovery install rollback", lambda: _check_install_recovery(supervision)),
        ("recovery activation rollback", lambda: _check_activation_recovery("rollback", supervision)),
        ("recovery activation rollforward", lambda: _check_activation_recovery("rollforward", supervision)),
        ("recovery removal rollback", lambda: _check_removal_recovery("rollback", supervision)),
        ("recovery removal rollforward", lambda: _check_removal_recovery("rollforward", supervision)),
    )
    relay_checks = tuple(
        (
            "relay %s" % profile.name,
            (
                (lambda selected=profile: _check_relay_in_process(selected, supervision))
                if relay_session_factory is None
                else (lambda selected=profile: _check_relay(selected, relay_session_factory))
            ),
        )
        for profile in iter_builtin_relays()
    )
    return checks + relay_checks + (
        (
            "delayed process cleanup",
            lambda: _check_process_supervision(supervision),
        ),
    )


def run_checks(checks, output, color=False):
    counts = {"OK": 0, "WARN": 0, "SKIP": 0, "FAIL": 0, "ERR": 0}
    colors = {
        "OK": _ANSI_GREEN,
        "WARN": _ANSI_YELLOW,
        "SKIP": _ANSI_CYAN,
        "FAIL": _ANSI_RED,
        "ERR": _ANSI_RED,
    }
    total = len(checks)
    for index, (name, check) in enumerate(checks, start=1):
        label = "[%d/%d] %s" % (index, total, name)
        result = check()
        counts[result.level] += 1
        output(
            "%s: %s - %s"
            % (
                _paint(label, _ANSI_CYAN, color),
                _paint(result.level, colors[result.level], color),
                _bounded_line(result.detail),
            )
        )
        for diagnostic in result.diagnostics:
            for line in _bounded_diagnostic(diagnostic).splitlines():
                output("    %s" % _paint(line, colors[result.level], color))

    output(
        "%s: %s, %s, %s, %s, %s"
        % (
            _paint("Summary", _ANSI_BOLD, color),
            _paint("%d OK" % counts["OK"], _ANSI_GREEN, color),
            _paint("%d WARN" % counts["WARN"], _ANSI_YELLOW, color),
            _paint("%d SKIP" % counts["SKIP"], _ANSI_CYAN, color),
            _paint("%d FAIL" % counts["FAIL"], _ANSI_RED, color),
            _paint("%d ERR" % counts["ERR"], _ANSI_RED, color),
        )
    )
    if counts["FAIL"] or counts["ERR"]:
        output(_paint("Self-check FAILED", _ANSI_RED, color))
        return 1
    if counts["WARN"]:
        output(_paint("Self-check PASSED with warnings", _ANSI_YELLOW, color))
        return 0
    if counts["SKIP"]:
        output(_paint("Self-check PASSED with skips", _ANSI_CYAN, color))
        return 0
    output(_paint("Self-check PASSED", _ANSI_GREEN, color))
    return 0


def run_self_check(paths, output=print, color=False, relay_session_factory=None):
    output(_paint("JerryProxy self-check %s" % __VERSION__, _ANSI_CYAN, color))
    output(
        "%s: Python %s %s; JerryProxy %s; frozen=%s"
        % (
            _paint("Runtime", _ANSI_BOLD, color),
            platform.python_implementation(),
            platform.python_version(),
            __VERSION__,
            str(bool(getattr(sys, "frozen", False))).lower(),
        )
    )
    output(
        "%s: %s %s; machine=%s; os.name=%s"
        % (
            _paint("System", _ANSI_BOLD, color),
            platform.system() or "unknown",
            platform.release() or "unknown",
            platform.machine() or "unknown",
            os.name,
        )
    )
    output("%s: %s" % (_paint("Home", _ANSI_BOLD, color), paths.root))
    return run_checks(
        build_checks(paths, relay_session_factory=relay_session_factory),
        output,
        color=color,
    )
