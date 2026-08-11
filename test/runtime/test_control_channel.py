"""The control query runs against a real loopback HTTP server.

Session tests inject a stand-in for this query, so without these the transport
itself -- authorization header, status handling, size bound, JSON validation --
would never execute. A local server is real execution, not a mock: it exercises
sockets, HTTP framing, and the bound.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jerryproxy.errors import RuntimeSessionError
from jerryproxy.runtime.mihomo import MihomoDriver


class _Controller(BaseHTTPRequestHandler):
    secret = "expected-secret"
    documents = {}
    oversize = False

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's required name
        if self.headers.get("Authorization") != "Bearer %s" % self.secret:
            self.send_response(401)
            self.end_headers()
            return
        if self.oversize:
            body = b'{"proxies": [' + b'{"name": "x"},' * 40000 + b'{"name": "y"}]}'
        else:
            document = self.documents.get(self.path)
            if document is None:
                self.send_response(404)
                self.end_headers()
                return
            body = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        del fmt, args


@pytest.fixture
def controller():
    """Run a loopback controller and yield its port plus a mutable handler."""

    server = HTTPServer(("127.0.0.1", 0), _Controller)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _documents(proxies, now, empty_fallback="COMPATIBLE"):
    return {
        "/providers/proxies/jerryproxy": {"proxies": [{"name": name} for name in proxies]},
        "/proxies/jerryproxy": {
            "now": now,
            "all": list(proxies) or ["COMPATIBLE"],
            "emptyFallback": empty_fallback,
        },
    }


def test_a_real_control_query_reports_an_accepted_node(controller):
    _Controller.documents = _documents(("tokyo",), "tokyo")
    _Controller.oversize = False

    loaded = MihomoDriver().loaded_nodes(controller, _Controller.secret, 5.0)

    assert loaded.accepted == ("tokyo",)
    assert loaded.selected == "tokyo"
    assert loaded.bypassing is False


def test_a_real_control_query_reports_a_bypassed_group(controller):
    _Controller.documents = _documents((), "COMPATIBLE")
    _Controller.oversize = False

    loaded = MihomoDriver().loaded_nodes(controller, _Controller.secret, 5.0)

    assert loaded.accepted == ()
    assert loaded.bypassing is True


def test_a_wrong_secret_is_a_startup_fault_rather_than_a_pass(controller):
    _Controller.documents = _documents(("tokyo",), "tokyo")
    _Controller.oversize = False

    with pytest.raises(RuntimeSessionError, match="answered 401"):
        MihomoDriver().loaded_nodes(controller, "wrong-secret", 5.0)


def test_an_unreachable_endpoint_is_a_startup_fault():
    """A closed port must fail, not be mistaken for an empty inventory."""

    # Bind and release a port so it is certainly local and certainly closed,
    # rather than guessing a number that something else might be serving.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    with pytest.raises(RuntimeSessionError, match="unreachable"):
        MihomoDriver().loaded_nodes(closed_port, "any-secret", 1.0)


def test_a_non_json_response_is_a_startup_fault(controller):
    _Controller.documents = {
        "/providers/proxies/jerryproxy": b"not json at all",
        "/proxies/jerryproxy": {"now": "tokyo", "all": ["tokyo"]},
    }
    _Controller.oversize = False

    with pytest.raises(RuntimeSessionError, match="not valid JSON"):
        MihomoDriver().loaded_nodes(controller, _Controller.secret, 5.0)


def test_an_oversized_response_is_bounded_rather_than_read_whole(controller):
    _Controller.documents = _documents(("tokyo",), "tokyo")
    _Controller.oversize = True

    with pytest.raises(RuntimeSessionError, match="exceeded its bound"):
        MihomoDriver().loaded_nodes(controller, _Controller.secret, 5.0)
    _Controller.oversize = False


def test_a_missing_inventory_field_is_a_startup_fault(controller):
    _Controller.documents = {
        "/providers/proxies/jerryproxy": {"unexpected": True},
        "/proxies/jerryproxy": {"now": "tokyo", "all": ["tokyo"]},
    }
    _Controller.oversize = False

    with pytest.raises(RuntimeSessionError, match="provider inventory"):
        MihomoDriver().loaded_nodes(controller, _Controller.secret, 5.0)
