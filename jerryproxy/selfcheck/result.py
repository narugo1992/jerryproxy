"""Check outcomes and the redaction boundary every diagnostic crosses."""

import os
import re
import traceback
from dataclasses import dataclass

_ANSI_BOLD = "\033[1m"
_ANSI_CYAN = "\033[1;36m"
_ANSI_GREEN = "\033[1;32m"
_ANSI_YELLOW = "\033[1;33m"
_ANSI_RED = "\033[1;31m"
_ANSI_RESET = "\033[0m"
_MAXIMUM_DETAIL_CHARACTERS = 2048
_MAXIMUM_DIAGNOSTIC_CHARACTERS = 64 * 1024
_MAXIMUM_DIAGNOSTIC_INPUT_CHARACTERS = 256 * 1024
_DIAGNOSTIC_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)
_DIAGNOSTIC_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


_DIAGNOSTIC_NAMED_SECRET = re.compile(
    r"\b(password|passwd|pwd|token|access[ _-]?token|secret|api[ _-]?key|public[ _-]?key|"
    r"private[ _-]?key|short[ _-]?id|uuid)(\s*(?::|=)\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)


_DIAGNOSTIC_BEARER = re.compile(
    r"\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]+",
    re.IGNORECASE,
)


_DIAGNOSTIC_PEM = re.compile(
    r"-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----",
    re.DOTALL,
)


_DIAGNOSTIC_SSH_KEY = re.compile(
    r"\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?"
)


@dataclass(frozen=True)
class CheckResult:
    """One completed self-check result at an explicit severity level."""

    level: str
    detail: str
    diagnostics: tuple = ()

    @classmethod
    def ok(cls, detail):
        return cls("OK", detail)

    @classmethod
    def warn(cls, detail):
        return cls("WARN", detail)

    @classmethod
    def skip(cls, detail):
        return cls("SKIP", detail)

    @classmethod
    def fail(cls, detail):
        return cls("FAIL", detail)

    @classmethod
    def err(cls, detail, diagnostics=()):
        return cls("ERR", detail, tuple(diagnostics))


def _paint(text, code, color):
    return "%s%s%s" % (code, text, _ANSI_RESET) if color else text


def _redact_diagnostic(value):
    text = str(value)
    text = _DIAGNOSTIC_PEM.sub("[REDACTED KEY]", text)
    text = _DIAGNOSTIC_SSH_KEY.sub("[REDACTED KEY]", text)
    text = _DIAGNOSTIC_URL.sub("[REDACTED URL]", text)
    text = _DIAGNOSTIC_BEARER.sub("[REDACTED TOKEN]", text)
    text = _DIAGNOSTIC_NAMED_SECRET.sub(
        lambda match: "%s%s[REDACTED]" % (match.group(1), match.group(2)),
        text,
    )
    return _DIAGNOSTIC_UUID.sub("[REDACTED UUID]", text)


def _bounded_line(value):
    text = " ".join(_redact_diagnostic(value).splitlines()).strip()
    if not text:
        text = _redact_diagnostic(repr(value))
    return text[:_MAXIMUM_DETAIL_CHARACTERS]


def _bounded_diagnostic(value):
    return _redact_diagnostic(value).strip()[:_MAXIMUM_DIAGNOSTIC_CHARACTERS]


def _error_result(error):
    message = _bounded_line(error)
    formatted = _bounded_diagnostic(traceback.format_exc())
    diagnostics = () if formatted.startswith("NoneType: None") else (formatted,)
    return CheckResult.err(
        "%s: %s" % (error.__class__.__name__, message),
        diagnostics=diagnostics,
    )


def ansi_color_enabled(stream, requested=None):
    """Resolve explicit flags and conventional color environment variables."""
    if requested is not None:
        return bool(requested)
    if "NO_COLOR" in os.environ:
        return False
    forced = os.environ.get("FORCE_COLOR")
    if forced is not None:
        return forced not in ("", "0")
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        # Output adapters may not expose a TTY or may reject the terminal probe.
        return False
