import base64
import socketserver
import threading

import pytest
import requests

import jerryproxy.subscription.transport as transport_module
from jerryproxy.errors import SubscriptionFetchError, SubscriptionParseError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.subscription import (
    MihomoSubscriptionParser,
    field_disposition_manifest,
    mihomo_parser_identity,
    subscription_field_disposition_manifest,
)
from jerryproxy.subscription.manager import SubscriptionManager
from jerryproxy.subscription.transport import (
    MAXIMUM_LABEL_CHARACTERS,
    fetch_subscription,
    parse_subscription_body,
)

SS = b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
VMESS = b"vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1NS01NTU1NTU1NTU1NTUiLCJuZXQiOiJ0Y3AiLCJwb3J0IjoiNDQzIiwicHMiOiJ2bWVzcyIsInRscyI6InRscyIsInYiOjJ9\n"
VLESS = b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&flow=xtls-rprx-vision#vless\n"


def test_plain_and_base64_uri_lines_are_classified_separately():
    plain = parse_subscription_body(SS + VMESS + VLESS, format_hint="uri-lines")
    encoded = base64.b64encode(plain.body).rstrip(b"=")
    decoded = parse_subscription_body(encoded)

    assert plain.format == "uri-lines"
    assert decoded.format == "base64-uri-lines"
    assert [item[0] for item in plain.records] == ["ss", "vmess", "vless"]
    # The SS record carries "#ss" as its fragment; VMess carries no fragment
    # and keeps the scheme fallback.
    assert plain.records[0][1] == "ss"
    assert plain.records[1][1] == "vmess node"


def test_mihomo_parser_is_source_pinned_but_reuses_uri_semantics():
    parser = MihomoSubscriptionParser()
    assert parser.name == "mihomo-1.19.29-v2ray-uri-lines"
    assert parser.identity == {
        "backend": "mihomo",
        "version": "1.19.29",
        "release_tag": "v1.19.29",
        "repository": "MetaCubeX/mihomo",
        "tag_commit": "e26714a181ac0e2fa803453c0a8e9a9ce94e31cb",
        "source_tree": "2487680d2def055568f3b50fcc61f931d70f6fa6",
        "parser_root": "config",
        "parser_root_tree": "650275c2bf3a465d2194d4b503e7049f9a452d0b",
        "parser_source_sha256": "cee079176a47ab45327972d72685ee8b816359f898079f6c8d83d026a6481afb",
        "source": "v2ray-uri-lines",
    }
    assert parser.parse(SS, format_hint="uri-lines").records[0][0] == "ss"
    assert mihomo_parser_identity() == parser.identity


def test_subscription_manager_uses_mihomo_adapter_by_default(tmp_path):
    manager = SubscriptionManager(JerryProxyPaths(tmp_path / ".jerryproxy"))
    assert manager.parser.name == "mihomo-1.19.29-v2ray-uri-lines"
    assert manager.parser.identity["tag_commit"].startswith("e26714a1")


def test_field_manifest_is_auditable_and_credential_free():
    manifest = field_disposition_manifest()
    assert manifest == subscription_field_disposition_manifest()
    assert manifest["identity"]["version"] == "1.19.29"
    assert manifest["protocols"] == {
        "ss": "opaque-forwarded-to-mihomo",
        "vmess": "opaque-forwarded-to-mihomo",
        "vless": "opaque-forwarded-to-mihomo",
    }
    assert manifest["provider"]["uri"] == "preserve"
    assert manifest["semantic_authority"]["owner"] == "mihomo"
    assert manifest["unsafe"]["credential_material"] == "private-only"
    rendered = repr(manifest)
    assert "password" not in rendered
    assert "11111111-1111-1111-1111-111111111111" not in rendered


@pytest.mark.parametrize("body", (SS, VMESS, VLESS))
def test_protocol_payloads_are_preserved_without_local_field_schema(body):
    if body.startswith(b"vmess://"):
        payload = body.split(b"://", 1)[1].strip()
        value = base64.b64decode(payload).replace(b'"port":"443"', b'"port":"x"')
        opaque = b"vmess://" + base64.b64encode(value) + b"\n"
    elif body.startswith(b"ss://"):
        opaque = body.replace(
            b"YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw",
            b"YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4x",
        )
    else:
        opaque = body.replace(b"&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", b"&pbk=bad")
    parsed = parse_subscription_body(opaque, format_hint="uri-lines")
    assert parsed.records[0][2] == opaque.decode("ascii").strip()


def test_explicit_uri_lines_does_not_decode_a_base64_body():
    encoded = base64.b64encode(SS)
    with pytest.raises(SubscriptionParseError, match="URI lines"):
        parse_subscription_body(encoded, format_hint="uri-lines")


def test_uri_record_bound_is_checked_before_protocol_payload_decoding():
    oversized = b"ss://" + (b"A" * (16 * 1024)) + b"\n"
    with pytest.raises(SubscriptionParseError, match="URI record exceeds"):
        parse_subscription_body(oversized, format_hint="uri-lines")


@pytest.mark.parametrize(
    "body",
    (
        b"http://not-a-supported-node\n",
        b"ss://\n",
        b"vmess://\n",
        b"vless://\n",
        b"ss://ok\x00bad\n",
    ),
)
def test_uri_container_rejects_only_generic_unsafe_records(body):
    with pytest.raises(SubscriptionParseError):
        parse_subscription_body(body, format_hint="uri-lines")


def test_vless_shape_is_deferred_to_mihomo():
    body = (
        b"vless://example.invalid:443?type=tcp&security=none&flow=none"
        b"\n"
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")
    assert parsed.records[0][2] == body.decode("ascii").strip()


def test_vless_unknown_query_fields_are_deferred_to_mihomo():
    body = (
        b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443?"
        b"type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&"
        b"fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00&"
        b"unknown=unexpected\n"
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")
    assert parsed.records[0][2] == body.decode("ascii").strip()


def test_ss_credentials_are_opaque_to_the_container_parser():
    for credentials in (b":password", b"aes-128-gcm:"):
        encoded = base64.b64encode(credentials + b"@example.invalid:443").rstrip(b"=")
        body = b"ss://" + encoded + b"\n"
        parsed = parse_subscription_body(body, format_hint="uri-lines")
        assert parsed.records[0][2] == body.decode("ascii").strip()


def test_vmess_unknown_and_nested_fields_are_deferred_to_mihomo():
    payload = base64.b64decode(VMESS.split(b"://", 1)[1].strip())
    unknown = payload.rstrip(b"}") + b',"unexpected":"value"}'
    nested = payload.rstrip(b"}") + b',"extra":{"nested":true}}'
    for value in (unknown, nested):
        body = b"vmess://" + base64.b64encode(value) + b"\n"
        parsed = parse_subscription_body(body, format_hint="uri-lines")
        assert parsed.records[0][2] == body.decode("ascii").strip()


def test_vmess_nonstandard_json_numbers_are_deferred_to_mihomo():
    payload = (
        b'{"add":"192.0.2.2","port":443,"id":"55555555-5555-5555-5555-555555555555",'
        b'"aid":NaN}'
    )
    body = b"vmess://" + base64.b64encode(payload) + b"\n"

    parsed = parse_subscription_body(body, format_hint="uri-lines")
    assert parsed.records[0][2] == body.decode("ascii").strip()


def test_fetch_rejects_private_dns_answers_before_request():
    class Session(object):
        def get(self, *args, **kwargs):
            raise AssertionError("request must not be attempted")

    def resolver(hostname, port, type=None):
        del hostname, port, type
        return [(2, 1, 6, "", ("127.0.0.1", 443))]

    with pytest.raises(SubscriptionFetchError, match="not public"):
        fetch_subscription(
            "https://provider.example/sub",
            session=Session(),
            resolver=resolver,
        )


def test_fetch_pins_the_validated_address_for_the_actual_requests_socket(monkeypatch):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(4096)
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
            )

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    seen = []
    original_create_connection = transport_module.create_connection

    def redirect_socket(address, timeout, *args, **kwargs):
        seen.append(address)
        return original_create_connection(("127.0.0.1", server.server_address[1]), timeout, *args, **kwargs)

    monkeypatch.setattr(transport_module, "create_connection", redirect_socket)
    try:
        response = fetch_subscription(
            "http://provider.example:%d/sub" % server.server_address[1],
            allow_http=True,
            resolver=lambda hostname, port, type=None: [(2, 1, 6, "", ("1.1.1.1", port))],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
    assert response.body == b"abc"
    assert seen == [("1.1.1.1", server.server_address[1])]


def test_fetch_rejects_a_url_above_the_shared_bound():
    with pytest.raises(SubscriptionFetchError, match="16 KiB bound"):
        fetch_subscription("https://provider.example/" + "a" * (16 * 1024))


def test_fetch_rejects_a_premature_declared_length_eof():
    class Response(object):
        status_code = 200
        headers = {"Content-Length": "4"}

        def iter_content(self, chunk_size):
            del chunk_size
            return iter((b"abc",))

        def close(self):
            pass

    class Session(object):
        trust_env = False

        def get(self, *args, **kwargs):
            del args, kwargs
            return Response()

    with pytest.raises(SubscriptionFetchError, match="length did not match"):
        fetch_subscription(
            "https://provider.example/sub",
            session=Session(),
            resolver=lambda hostname, port, type=None: [(2, 1, 6, "", ("1.1.1.1", port))],
        )


class _TransportResponse(object):
    def __init__(self, status_code=200, headers=None, chunks=()):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = tuple(chunks)
        self.closed = False

    def iter_content(self, chunk_size):
        del chunk_size
        return iter(self._chunks)

    def close(self):
        self.closed = True


class _TransportSession(object):
    def __init__(self, response=None, error=None):
        self.trust_env = True
        self.proxies = {"https": "http://proxy.invalid"}
        self.cookies = {"session": "secret"}
        self.auth = ("user", "password")
        self.headers = {"X-Test": "preserve"}
        self.cert = "client.pem"
        self.response = response
        self.error = error
        self.calls = 0

    def get(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.response


def _public_source_resolver(hostname, port, type=None):
    del hostname, type
    return [(2, 1, 6, "", ("1.1.1.1", port))]


def test_fetch_redirect_policy_and_session_state_restore():
    response = _TransportResponse(status_code=302, headers={"Location": "http://provider.example/next"})
    session = _TransportSession(response=response)
    with pytest.raises(SubscriptionFetchError, match="HTTPS"):
        fetch_subscription(
            "https://provider.example/sub",
            session=session,
            resolver=_public_source_resolver,
        )
    assert session.calls == 1
    assert session.trust_env is True
    assert session.proxies == {"https": "http://proxy.invalid"}
    assert session.cookies == {"session": "secret"}
    assert session.auth == ("user", "password")
    assert session.headers == {"X-Test": "preserve"}
    assert session.cert == "client.pem"
    assert response.closed is True


@pytest.mark.parametrize(
    "response, message",
    (
        (_TransportResponse(status_code=503), "HTTP 503"),
        (_TransportResponse(headers={"Content-Length": "not-a-number"}), "length is invalid"),
        (_TransportResponse(headers={"Content-Length": "4"}, chunks=(b"abc",)), "length did not match"),
    ),
)
def test_fetch_rejects_http_and_length_failures(response, message):
    session = _TransportSession(response=response)
    with pytest.raises(SubscriptionFetchError, match=message):
        fetch_subscription(
            "https://provider.example/sub",
            session=session,
            resolver=_public_source_resolver,
        )
    assert response.closed is True


def test_fetch_wraps_request_timeout_and_restores_state():
    session = _TransportSession(error=requests.exceptions.Timeout("timed out"))
    with pytest.raises(SubscriptionFetchError, match="timed out"):
        fetch_subscription(
            "https://provider.example/sub",
            session=session,
            resolver=_public_source_resolver,
        )
    assert session.trust_env is True
    assert session.proxies == {"https": "http://proxy.invalid"}
    assert session.cookies == {"session": "secret"}


def test_node_label_comes_from_the_fragment_so_nodes_are_distinguishable():
    """Three endpoints of one scheme must not collapse into one label."""

    body = (
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#tokyo-01\n"
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4yOjQ0Mw#osaka-02\n"
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4zOjQ0Mw#seoul-03\n"
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")

    assert [record[1] for record in parsed.records] == ["tokyo-01", "osaka-02", "seoul-03"]
    # The label is derived only; the record still carries the exact source URI.
    assert parsed.records[0][2].endswith("#tokyo-01")


def test_node_label_falls_back_to_the_scheme_without_a_usable_fragment():
    body = (
        b"vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1"
        b"NS01NTU1NTU1NTU1NTUiLCJuZXQiOiJ0Y3AiLCJwb3J0IjoiNDQzIiwicHMiOiJ2bWVzcyIsInRscyI6InRs"
        b"cyIsInYiOjJ9\n"
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#\n"
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4yOjQ0Mw#%20%09%20\n"
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4zOjQ0Mw#%FF%FE\n"
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")

    # VMess keeps its label inside a Base64 payload this layer must not decode;
    # empty, whitespace-only, and non-UTF-8 fragments are not usable labels.
    assert [record[1] for record in parsed.records] == [
        "vmess node",
        "ss node",
        "ss node",
        "ss node",
    ]


def test_node_label_decodes_utf8_and_folds_whitespace():
    body = b"ss://YWJj#%F0%9F%87%B0%F0%9F%87%B7%20%20Seoul%0A%09Premium\n"
    parsed = parse_subscription_body(body, format_hint="uri-lines")

    assert parsed.records[0][1] == "\U0001F1F0\U0001F1F7 Seoul Premium"


def test_node_label_never_exposes_credentials_or_control_sequences():
    body = (
        b"ss://YWJj#pbk%3DleakedPublicKey\n"
        b"ss://YWJk#password%3Dhunter2\n"
        b"ss://YWJl#node-11111111-1111-1111-1111-111111111111\n"
        b"ss://YWJm#%1B%5B31mred%1B%5B0m\n"
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")
    labels = [record[1] for record in parsed.records]

    assert labels[0] == "pbk=[REDACTED]"
    assert labels[1] == "password=[REDACTED]"
    assert labels[2] == "node-[REDACTED UUID]"
    # Terminal escapes are rendered visibly rather than emitted to the terminal.
    assert labels[3] == "\\u001b[31mred\\u001b[0m"
    assert not any("leakedPublicKey" in label or "hunter2" in label for label in labels)


def test_node_label_ignores_the_authority_and_query_entirely():
    """A label must never be built from credential-bearing URI components."""

    body = (
        b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443?"
        b"type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&"
        b"sid=0123456789abcdef#osaka\n"
    )
    parsed = parse_subscription_body(body, format_hint="uri-lines")

    assert parsed.records[0][1] == "osaka"
    # The opaque record still round-trips exactly for the backend.
    assert parsed.records[0][2] == body.decode("ascii").strip()


def test_node_label_is_bounded_far_below_the_stored_display_limit():
    body = b"ss://YWJj#" + b"x" * 4096 + b"\n"
    parsed = parse_subscription_body(body, format_hint="uri-lines")
    label = parsed.records[0][1]

    assert len(label) == MAXIMUM_LABEL_CHARACTERS
    assert len(label.encode("utf-8")) < 512
