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
    reload_status = 204
    reloads = 0

    def do_PUT(self):  # noqa: N802 - BaseHTTPRequestHandler's required name
        if self.headers.get("Authorization") != "Bearer %s" % self.secret:
            self.send_response(401)
        else:
            assert self.path == "/providers/proxies/jerryproxy"
            type(self).reloads += 1
            self.send_response(self.reload_status)
        self.end_headers()

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
        "/providers/proxies/jerryproxy": {"proxies": [
            {"name": name, "id": "12345678-1234-4234-8234-123456789abc", "provider-name": "jerryproxy"}
            for name in proxies
        ]},
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
    assert loaded.identities == ("12345678-1234-4234-8234-123456789abc",)


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


def test_reload_uses_authenticated_native_provider_endpoint(controller, monkeypatch):
    monkeypatch.setattr(_Controller, "reloads", 0)
    monkeypatch.setattr(_Controller, "reload_status", 204)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    assert MihomoDriver().reload_provider(controller, _Controller.secret, 1.0) is None
    assert _Controller.reloads == 1


@pytest.mark.parametrize("status", [200, 401, 403, 404, 503])
def test_reload_never_treats_rejected_or_ambiguous_status_as_success(controller, monkeypatch, status):
    monkeypatch.setattr(_Controller, "reload_status", status)
    with pytest.raises(RuntimeSessionError, match="answered %d" % status):
        MihomoDriver().reload_provider(controller, _Controller.secret, 1.0)


def test_reload_does_not_log_controller_credentials(controller):
    with pytest.raises(RuntimeSessionError, match="answered 401") as error:
        MihomoDriver().reload_provider(controller, "private-wrong-credential", 1.0)
    assert "private-wrong-credential" not in str(error.value)


@pytest.mark.parametrize("timeout", [0, -1, True, "5", float("inf"), float("nan")])
def test_reload_rejects_invalid_budgets_without_network(timeout):
    with pytest.raises(ValueError, match="control timeout"):
        MihomoDriver().reload_provider(1, "private-secret", timeout)


@pytest.mark.parametrize("payload, message", [
    (b"[]", "not a JSON object"),
    (b"\xff", "not valid JSON"),
])
def test_inventory_rejects_nonobject_and_invalid_utf8(controller, monkeypatch, payload, message):
    monkeypatch.setattr(_Controller, "documents", {"/providers/proxies/jerryproxy": payload})
    monkeypatch.setattr(_Controller, "oversize", False)
    with pytest.raises(RuntimeSessionError, match=message):
        MihomoDriver().loaded_nodes(controller, _Controller.secret, 1.0)


@pytest.mark.parametrize("entry", [
    None, "proxy", {}, {"name": 1}, {"name": "n"},
    {"name": "n", "id": "not-an-id"},
    {"name": "n", "id": 1},
    {"name": "n", "id": "12345678-1234-4234-8234-123456789abc"},
    {"name": "n", "id": "12345678-1234-4234-8234-123456789abc", "provider-name": "other"},
])
def test_inventory_rejects_unbound_or_malformed_entries(controller, monkeypatch, entry):
    docs = _documents(("n",), "n")
    docs["/providers/proxies/jerryproxy"]["proxies"] = [entry]
    monkeypatch.setattr(_Controller, "documents", docs)
    monkeypatch.setattr(_Controller, "oversize", False)
    with pytest.raises(RuntimeSessionError, match="provider identity"):
        MihomoDriver().loaded_nodes(controller, _Controller.secret, 1.0)


@pytest.mark.parametrize("now, all_nodes, fallback", [
    ("unrelated", ["n"], "COMPATIBLE"),
    ("n", ["n", "DIRECT"], "COMPATIBLE"),
    ("n", [], "COMPATIBLE"),
    ("n", "n", "COMPATIBLE"),
    ("n", ["n"], "n"),
])
def test_inventory_marks_selection_outside_single_provider_as_bypass(
    controller, monkeypatch, now, all_nodes, fallback,
):
    docs = _documents(("n",), now, fallback)
    docs["/proxies/jerryproxy"]["all"] = all_nodes
    monkeypatch.setattr(_Controller, "documents", docs)
    monkeypatch.setattr(_Controller, "oversize", False)
    assert MihomoDriver().loaded_nodes(controller, _Controller.secret, 1.0).bypassing


def test_inventory_requires_a_selected_name(controller, monkeypatch):
    monkeypatch.setattr(_Controller, "documents", _documents(("n",), None))
    monkeypatch.setattr(_Controller, "oversize", False)
    with pytest.raises(RuntimeSessionError, match="selected proxy"):
        MihomoDriver().loaded_nodes(controller, _Controller.secret, 1.0)


@pytest.mark.parametrize("name", ["DIRECT", "COMPATIBLE", "REJECT", "PASS", "REJECT-DROP"])
def test_provider_cannot_disguise_a_bypass_with_a_reserved_name(controller, monkeypatch, name):
    monkeypatch.setattr(_Controller, "documents", _documents((name,), name, empty_fallback=""))
    monkeypatch.setattr(_Controller, "oversize", False)
    loaded = MihomoDriver().loaded_nodes(controller, _Controller.secret, 1.0)
    assert loaded.accepted == (name,)
    assert loaded.bypassing
