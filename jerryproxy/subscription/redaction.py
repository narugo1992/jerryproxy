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
_URL_SCHEMES = "https?|ws|wss|ss|vmess|vless|socks(?:4|4a|5|5h)?|trojan|hysteria2?|tuic|anytls|ftp|ssh"
_BIDI_CONTROLS = frozenset(
    (0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
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
    for token in list(re.findall(r"(?i)\b(?:%s)://[^\s\"']+" % _URL_SCHEMES, text)):
        text = text.replace(token, redact_url(token))
    text = _UUID.sub("[REDACTED UUID]", text)
    text = _SHORT_ID.sub(lambda match: match.group(0).split("=", 1)[0] + "=[REDACTED]", text)
    text = _KEY.sub(lambda match: match.group(0).split("=", 1)[0] + "=[REDACTED]", text)
    text = _STRUCTURED_KEY.sub(lambda match: match.group(1) + "[REDACTED]", text)
    text = re.sub(r"(?i)\b(?:marker|nonce)\s*[=:]\s*[^&,}\]\s]+", "marker=[REDACTED]", text)
    text = text.replace("\r", "\\u000d").replace("\n", "\\u000a").replace("\t", "\\u0009")
    return text


def terminal_safe_text(value):  # type: (object) -> str
    """Escape terminal control, bidi, and line-separator characters visibly."""

    text = str(value)
    result = []
    for character in text:
        codepoint = ord(character)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in _BIDI_CONTROLS
            or codepoint in (0x2028, 0x2029)
        ):
            result.append("\\u%04x" % codepoint)
        else:
            result.append(character)
    return "".join(result)


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
