import base64
import socketserver
import threading

import pytest

import jerryproxy.subscription.transport as transport_module
from jerryproxy.errors import SubscriptionFetchError, SubscriptionParseError
from jerryproxy.subscription.transport import fetch_subscription, parse_subscription_body

SS = b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
VMESS = b"vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1NS01NTU1NTU1NTU1IiwibmV0IjoidGNwIiwicG9ydCI6IjQ0MyIsInBzIjoidm1lc3MiLCJ0bHMiOiJ0bHMiLCJ2IjoyfQ==\n"
VLESS = b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443?security=reality&sni=www.example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&flow=xtls-rprx-vision#vless\n"


def test_plain_and_base64_uri_lines_are_classified_separately():
    plain = parse_subscription_body(SS + VMESS + VLESS, format_hint="uri-lines")
    encoded = base64.b64encode(plain.body).rstrip(b"=")
    decoded = parse_subscription_body(encoded)

    assert plain.format == "uri-lines"
    assert decoded.format == "base64-uri-lines"
    assert [item[0] for item in plain.records] == ["ss", "vmess", "vless"]
    assert plain.records[0][1] == "ss node"
    assert plain.records[1][1] == "vmess node"


def test_explicit_uri_lines_does_not_decode_a_base64_body():
    encoded = base64.b64encode(SS)
    with pytest.raises(SubscriptionParseError, match="URI lines"):
        parse_subscription_body(encoded, format_hint="uri-lines")


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
    with pytest.raises(SubscriptionFetchError, match="8192-byte bound"):
        fetch_subscription("https://provider.example/" + "a" * 8192)
