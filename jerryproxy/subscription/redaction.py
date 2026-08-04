"""Credential-safe diagnostic redaction for subscription and backend output."""

import base64
import re
from urllib.parse import urlsplit, urlunsplit

_UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_SHORT_ID = re.compile(r"(?i)(?:short[-_ ]?id|sid)=([0-9a-f]{4,32})")
_KEY = re.compile(r"(?i)(?:public[-_ ]?key|private[-_ ]?key|pbk|password|passwd|token)=([^&\s]+)")
_STRUCTURED_KEY = re.compile(
    r"(?i)([\"']?(?:public[-_ ]?key|private[-_ ]?key|pbk|password|passwd|token|short[-_ ]?id|sid)[\"']?\s*:\s*)"
    r"(?:[\"'][^\"']*[\"']|[^,}\]\s]+)"
)


def redact_url(value):  # type: (str) -> str
    """Keep only a URL's scheme, host, and port for diagnostics."""

    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED URL]"
    if not parsed.scheme or not parsed.netloc:
        return "[REDACTED URL]"
    # Short SS links and VMess links commonly put the complete credential
    # envelope in the authority/path.  urlsplit would call that envelope a
    # hostname, so never preserve it as diagnostic metadata.
    if parsed.scheme.lower() in ("ss", "vmess"):
        return "%s://[REDACTED]" % parsed.scheme.lower()
    try:
        host = parsed.hostname or "[host]"
        port = parsed.port
    except ValueError:
        return "[REDACTED URL]"
    netloc = host if ":" not in host else "[%s]" % host
    if port is not None:
        netloc = "%s:%d" % (netloc, port)
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def redact_text(value):  # type: (object) -> str
    """Redact URLs and credential-shaped values before bounding output."""

    text = str(value)
    for token in list(re.findall(r"(?i)\b(?:https?|ss|vmess|vless)://[^\s\"']+", text)):
        text = text.replace(token, redact_url(token))
    text = _UUID.sub("[REDACTED UUID]", text)
    text = _SHORT_ID.sub(lambda match: match.group(0).split("=", 1)[0] + "=[REDACTED]", text)
    text = _KEY.sub(lambda match: match.group(0).split("=", 1)[0] + "=[REDACTED]", text)
    text = _STRUCTURED_KEY.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = re.sub(r"(?i)\b(?:marker|nonce)\s*[=:]\s*[^&,}\]\s]+", "marker=[REDACTED]", text)
    text = text.replace("\r", "\\u000d").replace("\n", "\\u000a").replace("\t", "\\u0009")
    return text


def redact_bytes(value):  # type: (bytes) -> str
    """Redact a bounded byte payload without retaining arbitrary binary data."""

    if not value:
        return ""
    try:
        text = value.decode("utf-8", "replace")
    except AttributeError:
        text = str(value)
    return redact_text(text)


def encoded_secret_forms(value):  # type: (str) -> tuple
    """Return standard and URL-safe Base64 forms for dynamic redaction tests."""

    raw = value.encode("utf-8")
    return (
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii"),
    )
