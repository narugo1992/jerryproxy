"""Bounded subscription transport and Mihomo-owned NodeSet classification."""

import base64
import binascii
import copy
import hashlib
import ipaddress
import json
import re
import socket
import uuid
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.poolmanager import PoolManager
from urllib3.util.connection import create_connection

from ..errors import SubscriptionFetchError, SubscriptionParseError
from .audit import MIHOMO_PARSER_IDENTITY
from .interfaces import SubscriptionParser
from .model import ParsedSubscription

MAXIMUM_BODY_BYTES = 8 * 1024 * 1024
MAXIMUM_URL_BYTES = 16 * 1024
MAXIMUM_URI_BYTES = 16 * 1024
MAXIMUM_RECORDS = 4096
MAXIMUM_REDIRECTS = 3
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
SUPPORTED_SCHEMES = ("ss", "vmess", "vless")
_URI_LINE = re.compile(r"^(ss|vmess|vless)://[^\s]+$", re.IGNORECASE)
_VMESS_PORT = re.compile(r"^\d+$")
_VMESS_FIELDS = frozenset(
    (
        "v",
        "ps",
        "add",
        "address",
        "port",
        "id",
        "aid",
        "scy",
        "net",
        "type",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "fp",
        "allowInsecure",
        "security",
        "serviceName",
        "mode",
        "authority",
        "headerType",
        "quicSecurity",
        "key",
        "seed",
        "packetEncoding",
        "encryption",
    )
)
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 8192
_REALITY_SHORT_ID = re.compile(r"^[0-9a-fA-F]{0,16}$")
_REALITY_PUBLIC_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_REALITY_FINGERPRINTS = frozenset(("chrome", "firefox", "safari", "edge", "ios", "android", "random"))
_VLESS_NETWORKS = frozenset(("tcp", "grpc", "ws", "http", "h2", "quic", "kcp"))
_VLESS_SECURITY = frozenset(("none", "tls", "reality", "xtls"))
_VLESS_QUERY_KEYS = frozenset(("type", "security", "flow", "sni", "fp", "pbk", "sid"))


def _reject_duplicate_json_keys(pairs):  # type: (list) -> dict
    """Reject duplicate object members before any VMess value is consumed."""

    value = {}
    for key, item in pairs:
        if key in value:
            raise SubscriptionParseError("subscription JSON contains duplicate keys")
        value[key] = item
    return value


def _reject_nonfinite_json_constant(value):  # type: (str) -> None
    """Reject JSON extensions that are not valid interoperable numbers."""

    raise SubscriptionParseError("vmess URI contains a non-standard JSON number: %s" % value)


class _PinnedConnectionMixin(object):
    """Connect only to the address set validated immediately before a request."""

    def __init__(self, *args, **kwargs):
        self._pinned_addresses = tuple(kwargs.pop("pinned_addresses", ()))
        super(_PinnedConnectionMixin, self).__init__(*args, **kwargs)

    def _new_conn(self):
        if not self._pinned_addresses:
            raise NewConnectionError(self, "No validated subscription source address is available")
        extra = {}
        if self.source_address:
            extra["source_address"] = self.source_address
        if self.socket_options:
            extra["socket_options"] = self.socket_options
        last_error = None
        for address in self._pinned_addresses:
            try:
                return create_connection((str(address), self.port), self.timeout, **extra)
            except socket.timeout as error:
                raise ConnectTimeoutError(
                    self,
                    "Connection to %s timed out (connect timeout=%s)" % (self.host, self.timeout),
                ) from error
            except OSError as error:
                last_error = error
        raise NewConnectionError(self, "Failed to establish a connection: %s" % last_error)


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedPoolManager(PoolManager):
    def __init__(self, pinned_addresses, *args, **kwargs):
        self._pinned_addresses = tuple(pinned_addresses)
        super(_PinnedPoolManager, self).__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        }

    def _new_pool(self, scheme, host, port, request_context=None):
        context = dict(request_context or {})
        context["pinned_addresses"] = self._pinned_addresses
        return super(_PinnedPoolManager, self)._new_pool(scheme, host, port, context)


class _PinnedHTTPAdapter(HTTPAdapter):
    """Requests adapter carrying a per-request validated address set."""

    def __init__(self, pinned_addresses):
        self._pinned_addresses = tuple(pinned_addresses)
        super(_PinnedHTTPAdapter, self).__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = _PinnedPoolManager(
            self._pinned_addresses,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs
        )

    def update(self, pinned_addresses):
        self._pinned_addresses = tuple(pinned_addresses)
        self.close()
        self.init_poolmanager(self._pool_connections, self._pool_maxsize, self._pool_block)


@dataclass(frozen=True)
class FetchedSubscription(object):
    """Fetched bytes and the final validated request target."""

    body: bytes
    final_url: str


def validate_source_url(value, allow_http=False):  # type: (str, bool) -> str
    """Validate an absolute bearer URL without exposing its secret components."""

    if not isinstance(value, str) or not value or any(ord(char) <= 32 for char in value):
        raise SubscriptionFetchError("subscription URL is invalid")
    if len(value.encode("utf-8")) > MAXIMUM_URL_BYTES:
        raise SubscriptionFetchError("subscription URL exceeds the 16 KiB bound")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        # ValueError is expected for malformed URL authority or port syntax.
        raise SubscriptionFetchError("subscription URL is invalid") from error
    allowed_scheme = ("http", "https") if allow_http else ("https",)
    if parsed.scheme.lower() not in allowed_scheme or not hostname:
        raise SubscriptionFetchError("subscription URL must use HTTPS with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise SubscriptionFetchError("subscription URL must not contain user information")
    if parsed.fragment:
        raise SubscriptionFetchError("subscription URL must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise SubscriptionFetchError("subscription URL has an invalid port")
    if "\\" in value or any(ord(char) == 127 for char in value):
        raise SubscriptionFetchError("subscription URL contains unsafe characters")
    # Numeric loopback/link-local/private authorities are never accepted for a
    # user source.  Test harnesses may inject a session and use a service name.
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_private or address.is_link_local):
        raise SubscriptionFetchError("subscription URL target is not a public source")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, ""))


def _resolve_redirect(current, location, allow_http=False):  # type: (str, str, bool) -> str
    if not isinstance(location, str) or not location:
        raise SubscriptionFetchError("subscription redirect has no location")
    try:
        candidate = urljoin(current, location)
    except ValueError as error:
        # ValueError is expected for malformed redirect references.
        raise SubscriptionFetchError("subscription redirect is invalid") from error
    return validate_source_url(candidate, allow_http=allow_http)


def _resolve_public_hostname(hostname, port, resolver=None):
    """Reject hostnames whose complete DNS answer set is not public."""

    resolver = resolver or socket.getaddrinfo
    try:
        answers = resolver(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        # DNS failures are source transport failures, not parser failures.
        raise SubscriptionFetchError("subscription source hostname cannot be resolved") from error
    addresses = []
    for answer in answers:
        try:
            address = ipaddress.ip_address(answer[4][0])
        except (IndexError, KeyError, ValueError) as error:
            # A malformed resolver answer cannot establish a safe destination.
            raise SubscriptionFetchError("subscription source hostname resolution is invalid") from error
        addresses.append(address)
    if not addresses or len(set(addresses)) > 16 or any(not address.is_global for address in addresses):
        raise SubscriptionFetchError("subscription source target is not public")
    return tuple(dict.fromkeys(addresses))


def fetch_subscription(
    url,
    session=None,
    maximum_bytes=MAXIMUM_BODY_BYTES,
    timeout=None,
    allow_http=False,
    resolver=None,
):
    # type: (str, object, int, object, bool, object) -> FetchedSubscription
    """Fetch one bounded subscription body with explicit redirect handling."""

    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes <= 0
        or maximum_bytes > MAXIMUM_BODY_BYTES
    ):
        raise ValueError("maximum_bytes must be a positive integer no greater than the built-in bound")
    request_timeout = timeout or (CONNECT_TIMEOUT, READ_TIMEOUT)
    current = validate_source_url(url, allow_http=allow_http)
    client = session or requests.Session()
    original_client_state = {}
    for attribute in ("trust_env", "proxies", "cookies", "auth", "headers", "cert"):
        if hasattr(client, attribute):
            value = getattr(client, attribute)
            if attribute in ("proxies", "headers"):
                value = dict(value)
            elif attribute == "cookies" and hasattr(value, "copy"):
                value = copy.copy(value)
            original_client_state[attribute] = value
    if hasattr(client, "trust_env"):
        client.trust_env = False
    if hasattr(client, "proxies"):
        client.proxies = {}
    if hasattr(client, "cookies"):
        client.cookies.clear()
    if hasattr(client, "auth"):
        client.auth = None
    if hasattr(client, "headers"):
        client.headers = {"User-Agent": "JerryProxy-subscription/0.1"}
    if hasattr(client, "cert"):
        client.cert = None
    pinned_adapter = None
    original_adapters = None
    if isinstance(client, requests.Session):
        pinned_adapter = _PinnedHTTPAdapter(())
        original_adapters = (client.get_adapter("http://"), client.get_adapter("https://"))
        client.mount("http://", pinned_adapter)
        client.mount("https://", pinned_adapter)
    visited = set()
    try:
        for _redirect in range(MAXIMUM_REDIRECTS + 1):
            if current in visited:
                raise SubscriptionFetchError("subscription redirect loop detected")
            visited.add(current)
            parsed_current = urlsplit(current)
            addresses = _resolve_public_hostname(
                parsed_current.hostname,
                parsed_current.port or (443 if parsed_current.scheme == "https" else 80),
                resolver=resolver,
            )
            if pinned_adapter is not None:
                pinned_adapter.update(addresses)
            if hasattr(client, "cookies"):
                client.cookies.clear()
            try:
                response = client.get(
                    current,
                    allow_redirects=False,
                    stream=True,
                    timeout=request_timeout,
                    headers={"User-Agent": "JerryProxy-subscription/0.1"},
                    proxies={},
                )
            except requests.exceptions.Timeout as error:
                # Requests timeout is a bounded source transport failure.
                raise SubscriptionFetchError("subscription source timed out") from error
            except requests.exceptions.RequestException as error:
                # Other Requests failures are bounded transport failures.
                raise SubscriptionFetchError("subscription source request failed") from error
            try:
                if response.status_code in (301, 302, 303, 307, 308):
                    if len(visited) > MAXIMUM_REDIRECTS:
                        raise SubscriptionFetchError("subscription redirect limit exceeded")
                    current = _resolve_redirect(current, response.headers.get("Location"), allow_http=allow_http)
                    continue
                if response.status_code < 200 or response.status_code >= 300:
                    raise SubscriptionFetchError("subscription source returned HTTP %d" % response.status_code)
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError as error:
                        # ValueError is expected for a malformed Content-Length header.
                        raise SubscriptionFetchError("subscription source length is invalid") from error
                    if declared < 0 or declared > maximum_bytes:
                        raise SubscriptionFetchError("subscription source exceeds the size bound")
                chunks = []
                total = 0
                try:
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > maximum_bytes:
                            raise SubscriptionFetchError("subscription source exceeds the size bound")
                        chunks.append(chunk)
                except requests.exceptions.RequestException as error:
                    # Streaming failures are source transport failures.
                    raise SubscriptionFetchError("subscription source stream failed") from error
                if content_length is not None and total != declared:
                    raise SubscriptionFetchError("subscription source length did not match its declaration")
                return FetchedSubscription(b"".join(chunks), current)
            finally:
                response.close()
        raise SubscriptionFetchError("subscription redirect limit exceeded")
    finally:
        if original_adapters is not None:
            client.mount("http://", original_adapters[0])
            client.mount("https://", original_adapters[1])
        if pinned_adapter is not None:
            pinned_adapter.close()
        for attribute, value in original_client_state.items():
            if attribute == "cookies" and hasattr(client, "cookies"):
                client.cookies.clear()
                client.cookies.update(value)
            else:
                setattr(client, attribute, value)


def _decode_base64(value):  # type: (bytes) -> bytes
    compact = b"".join(value.split())
    if not compact or len(compact) % 4 == 1:
        raise SubscriptionParseError("subscription Base64 body is invalid")
    compact += b"=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        # Base64 decoder errors identify malformed subscription input.
        raise SubscriptionParseError("subscription Base64 body is invalid") from error


def _looks_like_uri_lines(value):  # type: (bytes) -> bool
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return bool(lines) and all(_URI_LINE.match(line) for line in lines)


def _display_for_uri(uri):  # type: (str) -> str
    scheme = uri.split(":", 1)[0].lower()
    try:
        parsed = urlsplit(uri)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        host = None
        port = None
    # SS short links and VMess links commonly carry the complete credential
    # envelope in the authority/path.  Without a proven host+port pair, never
    # echo that opaque value as a display endpoint.
    if scheme in ("ss", "vmess") and (not host or port is None):
        return "%s node" % scheme
    if host:
        return "%s://%s%s" % (scheme, host, ":%d" % port if port else "")
    return "%s node" % scheme


def _decode_uri_payload(value):  # type: (str) -> bytes
    """Decode a URL-safe or standard Base64 URI envelope without rendering it."""

    try:
        compact = unquote(value).encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError) as error:
        # Non-ASCII URI payloads cannot be valid Base64 envelopes.
        raise SubscriptionParseError("subscription URI payload is not ASCII Base64") from error
    compact = b"".join(compact.split())
    if not compact or len(compact) % 4 == 1:
        raise SubscriptionParseError("subscription URI payload is invalid Base64")
    compact += b"=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(compact, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        # Base64 decoder errors identify malformed protocol envelopes.
        raise SubscriptionParseError("subscription URI payload is invalid Base64") from error


def _validate_endpoint(hostname, port, label):  # type: (str, object, str) -> None
    if not hostname or port is None or not 1 <= port <= 65535:
        raise SubscriptionParseError("%s URI is missing a valid endpoint" % label)


def _validate_ss_uri(uri):  # type: (str) -> None
    payload = uri.split("://", 1)[1].split("#", 1)[0]
    if not payload:
        raise SubscriptionParseError("ss URI is empty")
    authority = None
    encoded = payload
    if "@" in payload:
        encoded, authority = payload.rsplit("@", 1)
    decoded = _decode_uri_payload(encoded)
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        # SS method/password envelopes are UTF-8 text by convention.
        raise SubscriptionParseError("ss URI payload is not UTF-8") from error
    credential_text = decoded_text.rsplit("@", 1)[0]
    method, separator, password = credential_text.partition(":")
    if not separator or not method or not password:
        raise SubscriptionParseError("ss URI payload is missing method and password")
    if authority is None:
        if "@" not in decoded_text:
            raise SubscriptionParseError("ss URI payload is missing its endpoint")
        _, authority = decoded_text.rsplit("@", 1)
    try:
        parsed = urlsplit("ss://%s" % authority)
        port = parsed.port
    except ValueError as error:
        # ValueError is expected for malformed SS authority or port syntax.
        raise SubscriptionParseError("ss URI endpoint is invalid") from error
    _validate_endpoint(parsed.hostname, port, "ss")


def _validate_json_shape(value, depth=0):  # type: (object, int) -> int
    """Bound VMess JSON structure before protocol fields are consumed."""

    if depth > _MAX_JSON_DEPTH:
        raise SubscriptionParseError("vmess URI JSON exceeds the depth or node bound")
    nodes = 1
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SubscriptionParseError("vmess URI JSON contains a non-string key")
            if isinstance(item, (dict, list)):
                raise SubscriptionParseError("vmess URI JSON contains a nested field")
            nodes += _validate_json_shape(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            nodes += _validate_json_shape(item, depth + 1)
    if nodes > _MAX_JSON_NODES:
        raise SubscriptionParseError("vmess URI JSON exceeds the depth or node bound")
    return nodes


def _validate_vmess_uri(uri):  # type: (str) -> None
    payload = uri.split("://", 1)[1].split("#", 1)[0]
    decoded = _decode_uri_payload(payload)
    try:
        value = json.loads(
            decoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        # JSON and UTF-8 errors identify malformed VMess envelopes.
        raise SubscriptionParseError("vmess URI payload is not valid JSON") from error
    if not isinstance(value, dict):
        raise SubscriptionParseError("vmess URI payload is not an object")
    unknown = set(value).difference(_VMESS_FIELDS)
    if unknown:
        raise SubscriptionParseError("vmess URI contains unknown fields")
    _validate_json_shape(value)
    address = value.get("add") or value.get("address")
    port = value.get("port")
    if isinstance(port, str) and _VMESS_PORT.match(port):
        port = int(port)
    if not isinstance(port, int) or isinstance(port, bool):
        raise SubscriptionParseError("vmess URI port is invalid")
    _validate_endpoint(address, port, "vmess")
    identity = value.get("id")
    try:
        uuid.UUID(str(identity))
    except (AttributeError, ValueError):
        # UUID parsing errors identify malformed VMess identities.
        raise SubscriptionParseError("vmess URI id is invalid")


def _validate_vless_fields(uri):  # type: (str) -> None
    """Validate the Reality envelope while leaving credentials opaque."""

    try:
        parsed = urlsplit(uri)
        username = parsed.username
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        # ValueError is expected for malformed URI authority syntax.
        raise SubscriptionParseError("subscription URI is invalid") from error
    _validate_endpoint(hostname, port, "vless")
    if not username:
        raise SubscriptionParseError("vless URI id is invalid")
    try:
        uuid.UUID(unquote(username))
    except (AttributeError, TypeError, ValueError):
        # VLESS identities are UUIDs in the URI envelope.
        raise SubscriptionParseError("vless URI id is invalid")
    query = dict()
    for part in parsed.query.split("&") if parsed.query else ():
        if not part:
            continue
        key, separator, value = part.partition("=")
        if not separator or not key or key in query:
            raise SubscriptionParseError("vless URI has an invalid query")
        if key not in _VLESS_QUERY_KEYS:
            raise SubscriptionParseError("vless URI contains an unknown query field")
        query[key] = value
    security = query.get("security", "none")
    if security not in _VLESS_SECURITY:
        raise SubscriptionParseError("unsupported vless security")
    if "type" in query and query["type"] not in _VLESS_NETWORKS:
        raise SubscriptionParseError("unsupported vless network")
    if security == "reality":
        required = ("type", "security", "flow", "sni", "fp", "pbk", "sid")
        if any(not query.get(key) for key in required):
            raise SubscriptionParseError("vless Reality URI is missing required fields")
        if query.get("type") not in _VLESS_NETWORKS:
            raise SubscriptionParseError("unsupported vless Reality network")
        if query.get("fp") not in _REALITY_FINGERPRINTS:
            raise SubscriptionParseError("unsupported vless Reality fingerprint")
        if not _REALITY_PUBLIC_KEY.match(query["pbk"]):
            raise SubscriptionParseError("vless Reality public key is invalid")
        if not _REALITY_SHORT_ID.match(query["sid"]) or len(query["sid"]) % 2:
            raise SubscriptionParseError("vless Reality short id is invalid")
        if query.get("flow") not in ("xtls-rprx-vision",):
            raise SubscriptionParseError("unsupported vless Reality flow")


def _validate_uri_line(line):  # type: (str) -> Tuple[str, str, str]
    if len(line.encode("utf-8")) > MAXIMUM_URI_BYTES:
        raise SubscriptionParseError("subscription URI record exceeds the 16 KiB bound")
    if not _URI_LINE.match(line) or any(ord(char) < 0x20 or ord(char) == 0x7F for char in line):
        raise SubscriptionParseError("subscription contains an invalid URI record")
    scheme = line.split(":", 1)[0].lower()
    if scheme == "vless":
        _validate_vless_fields(line)
    elif scheme == "ss":
        _validate_ss_uri(line)
    elif scheme == "vmess":
        _validate_vmess_uri(line)
    return scheme, _display_for_uri(line), line


def _parse_v2ray_subscription_body(body, format_hint="auto"):
    # type: (bytes, str) -> ParsedSubscription
    """Classify Base64/plain URI lines and preserve each accepted URI exactly."""

    if not isinstance(body, bytes):
        raise TypeError("subscription body must be bytes")
    if len(body) > MAXIMUM_BODY_BYTES:
        raise SubscriptionParseError("subscription body exceeds the size bound")
    if format_hint not in ("auto", "uri-lines", "mihomo-provider"):
        raise SubscriptionParseError("unsupported subscription format: %s" % format_hint)
    if format_hint == "mihomo-provider":
        raise SubscriptionParseError("mihomo provider YAML requires a native provider projection")
    candidates = []
    if format_hint in ("auto", "uri-lines"):
        if _looks_like_uri_lines(body):
            candidates.append(("uri-lines", body))
        if format_hint == "auto":
            try:
                decoded = _decode_base64(body)
            except SubscriptionParseError:
                decoded = None
            if decoded is not None and _looks_like_uri_lines(decoded):
                candidates.append(("base64-uri-lines", decoded))
    if not candidates:
        raise SubscriptionParseError("subscription body is neither Base64 nor URI lines")
    # Exact duplicate representations are allowed only when they decode to the
    # same URI set; the classified format remains explicit for state evidence.
    format_name, decoded_body = candidates[-1]
    try:
        text = decoded_body.decode("utf-8")
    except UnicodeDecodeError as error:
        # UnicodeDecodeError is expected for non-UTF-8 source bodies.
        raise SubscriptionParseError("subscription URI lines are not UTF-8") from error
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(_validate_uri_line(line))
        if len(records) > MAXIMUM_RECORDS:
            raise SubscriptionParseError("subscription contains too many nodes")
    if not records:
        raise SubscriptionParseError("subscription contains no supported nodes")
    # Keep the exact fetched representation for revision/rollback integrity;
    # Mihomo receives the decoded records through the private provider file.
    return ParsedSubscription(format_name, body, tuple(records))


class V2RaySubscriptionParser(SubscriptionParser):
    """Parse Base64/plain SS, VMess, and VLESS URI-line containers."""

    @property
    def name(self):  # type: () -> str
        return "v2ray-uri-lines"

    def parse(self, body, format_hint="auto"):  # type: (bytes, str) -> ParsedSubscription
        return _parse_v2ray_subscription_body(body, format_hint=format_hint)


class MihomoSubscriptionParser(SubscriptionParser):
    """Source-pinned Mihomo 1.19.29 adapter over the URI-line parser.

    Mihomo consumes the resulting private provider projection; validation and
    URI semantics remain owned by :class:`V2RaySubscriptionParser`.
    """

    @property
    def name(self):  # type: () -> str
        return "mihomo-1.19.29-v2ray-uri-lines"

    @property
    def backend(self):  # type: () -> str
        return "mihomo"

    @property
    def backend_version(self):  # type: () -> str
        return "1.19.29"

    @property
    def source_parser(self):  # type: () -> str
        return "v2ray-uri-lines"

    @property
    def identity(self):  # type: () -> dict
        return dict(MIHOMO_PARSER_IDENTITY)

    def parse(self, body, format_hint="auto"):  # type: (bytes, str) -> ParsedSubscription
        return _V2RAY_SUBSCRIPTION_PARSER.parse(body, format_hint=format_hint)


_V2RAY_SUBSCRIPTION_PARSER = V2RaySubscriptionParser()
MIHOMO_SUBSCRIPTION_PARSER = MihomoSubscriptionParser()
# NodeSet ingestion is owned by the qualified Mihomo projection.  The adapter
# delegates only the bounded URI-envelope validation; the provider bytes remain
# opaque and are parsed again by Mihomo at runtime.
DEFAULT_SUBSCRIPTION_PARSER = MIHOMO_SUBSCRIPTION_PARSER


def parse_subscription_body(body, format_hint="auto"):
    # type: (bytes, str) -> ParsedSubscription
    """Parse the built-in V2RAY_SUBSCRIPTION URI-line format."""

    return DEFAULT_SUBSCRIPTION_PARSER.parse(body, format_hint=format_hint)


def source_digest(body):  # type: (bytes) -> str
    """Return the immutable SHA-256 revision digest for source bytes."""

    return hashlib.sha256(body).hexdigest()


def resolve_hostname_for_diagnostic(hostname):  # type: (str) -> tuple
    """Resolve a host only for a caller-owned diagnostic, never for parsing."""

    try:
        return tuple(sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)}))
    except socket.gaierror:
        # DNS failure is expected in offline validation environments.
        return ()
