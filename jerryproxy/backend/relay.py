"""Constrained GitHub Release relay profiles and URL rendering."""

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote_to_bytes, urlparse, urlunparse

from ..errors import DownloadPolicyError

ALLOWED_PATTERNS = ("full_url_path", "host_path", "query_q")
RELAY_PROBE_URL = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"
RELAY_PROBE_SIZE = 21136402
RELAY_PROBE_BYTES = 1024 * 1024
RELAY_PROBE_SHA256 = "5366a9e6db1f1eb797366022ae2cc4982d97f5deefb7be6c7fe2a6004e420f2f"


@dataclass(frozen=True)
class RelayProfile:
    """One static or user-supplied relay endpoint."""

    name: str
    base_url: str
    pattern: str
    built_in: bool = False


@dataclass(frozen=True)
class DownloadSource:
    """One safe label and effective download URL."""

    label: str
    url: str


_BUILTIN_RELAYS = (
    RelayProfile("gh-proxy.com", "https://gh-proxy.com", "full_url_path", True),
    RelayProfile("cdn.akaere.online", "https://cdn.akaere.online", "full_url_path", True),
    RelayProfile("gh.geekertao.top", "https://gh.geekertao.top", "full_url_path", True),
)


def iter_builtin_relays():  # type: () -> tuple
    """Return built-in relay profiles in deterministic fallback order."""

    return _BUILTIN_RELAYS


def get_builtin_relay(name):  # type: (str) -> RelayProfile
    """Return one built-in relay by its hostname identifier."""

    for profile in _BUILTIN_RELAYS:
        if profile.name == name:
            return profile
    raise DownloadPolicyError("unknown backend download relay: %s" % name)


def _reject_unsafe_text(value, label):  # type: (str, str) -> None
    if not value or "\\" in value or any(ord(character) <= 32 or ord(character) == 127 for character in value):
        raise DownloadPolicyError("%s contains unsafe characters" % label)
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise DownloadPolicyError("%s contains invalid percent encoding" % label)
    decoded = unquote_to_bytes(value)
    if any(value <= 32 or value == 127 for value in decoded) or b"\\" in decoded:
        raise DownloadPolicyError("%s contains encoded unsafe characters" % label)


def custom_relay(base_url, pattern="full_url_path"):
    # type: (str, str) -> RelayProfile
    """Validate and construct one invocation-scoped custom relay."""

    if pattern not in ALLOWED_PATTERNS:
        raise DownloadPolicyError("unsupported relay URL pattern: %s" % pattern)
    _reject_unsafe_text(base_url, "relay URL")
    try:
        parsed = urlparse(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        # ValueError is expected for malformed bracket or port syntax.
        raise DownloadPolicyError("backend download relay URL is invalid")
    if parsed.scheme != "https" or not hostname:
        raise DownloadPolicyError("backend download relays require an HTTPS URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise DownloadPolicyError("backend download relays must not contain user information")
    if port is not None and (port < 1 or port > 65535):
        raise DownloadPolicyError("backend download relay URL is invalid")
    if parsed.query or parsed.fragment:
        raise DownloadPolicyError("backend download relays must not contain a query or fragment")
    canonical = urlunparse(("https", parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    return RelayProfile("custom relay", canonical, pattern, False)


def _parse_official_release_url(official_url):
    try:
        parsed = urlparse(official_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        # ValueError is expected for malformed bracket or port syntax.
        raise DownloadPolicyError("relay input must be a public GitHub Release asset URL")
    if (
        parsed.scheme != "https"
        or hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise DownloadPolicyError("relay input must be a public GitHub Release asset URL")
    parts = parsed.path.split("/")
    if len(parts) != 7 or not all(parts[index] for index in (1, 2, 5, 6)):
        raise DownloadPolicyError("relay input must be a public GitHub Release asset URL")
    if parts[3:5] != ["releases", "download"]:
        raise DownloadPolicyError("relay input must be a public GitHub Release asset URL")
    return parsed


def render_relay_url(profile, official_url):
    # type: (RelayProfile, str) -> str
    """Render one official GitHub Release asset URL through a relay."""

    parsed = _parse_official_release_url(official_url)
    base = profile.base_url.rstrip("/")
    if profile.pattern == "full_url_path":
        return "%s/%s" % (base, official_url)
    if profile.pattern == "host_path":
        return "%s/%s%s" % (base, parsed.hostname, parsed.path)
    if profile.pattern == "query_q":
        return "%s/?q=%s" % (base, quote(official_url, safe=""))
    raise DownloadPolicyError("unsupported relay URL pattern: %s" % profile.pattern)


def build_download_sources(
    official_url,
    relay=None,
    relay_url=None,
    relay_pattern=None,
):
    # type: (str, Optional[str], Optional[str], Optional[str]) -> tuple
    """Build the exact direct, named, automatic, or custom source sequence."""

    if relay is not None and relay_url is not None:
        raise DownloadPolicyError("--relay and --relay-url are mutually exclusive")
    if relay_pattern is not None and relay_url is None:
        raise DownloadPolicyError("--relay-pattern requires --relay-url")
    if relay_url is not None:
        profile = custom_relay(relay_url, relay_pattern or "full_url_path")
        return (DownloadSource(profile.name, render_relay_url(profile, official_url)),)
    if relay is None or relay == "direct":
        return (DownloadSource("direct", official_url),)
    if relay == "auto":
        return (DownloadSource("direct", official_url),) + tuple(
            DownloadSource(profile.name, render_relay_url(profile, official_url)) for profile in _BUILTIN_RELAYS
        )
    profile = get_builtin_relay(relay)
    return (DownloadSource(profile.name, render_relay_url(profile, official_url)),)
