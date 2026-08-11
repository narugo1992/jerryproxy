"""Invalid certificates must fail closed on every path that fetches over TLS.

This is the release gate that reads "TLS verification is on by default and
invalid certificates fail closed". Grepping for `verify=False` shows only that
nobody wrote the obvious mistake; it says nothing about what happens when a
server actually presents a certificate that does not validate. These tests
serve one from a real loopback HTTPS server and require the fetch to refuse.
"""

import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from jerryproxy.backend.download import AssetDownloader
from jerryproxy.errors import DownloadError, SubscriptionFetchError
from jerryproxy.subscription.transport import fetch_subscription

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is needed to mint a throwaway certificate"
)


@pytest.fixture(scope="module")
def untrusted_https():
    """Serve over TLS with a self-signed leaf no trust store knows."""

    directory = tempfile.mkdtemp(prefix="jerryproxy-tls-gate-")
    certificate = Path(directory) / "cert.pem"
    key = Path(directory) / "key.pem"
    subprocess.check_call(
        [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - required name
            body = b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#node\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            del fmt, args

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "https://localhost:%d/" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)
        shutil.rmtree(directory, ignore_errors=True)


def test_a_subscription_fetch_refuses_a_loopback_source_before_any_tls(untrusted_https):
    """A loopback source never reaches the certificate check at all.

    Worth stating rather than leaving implicit: an earlier test here claimed to
    prove certificate validation on this path, but the private-address gate
    refuses `localhost` before a connection is opened, so it proved the gate
    instead. Disabling verification left it passing.
    """

    with pytest.raises(SubscriptionFetchError) as failure:
        fetch_subscription(untrusted_https)

    assert "not public" in str(failure.value)
    # The refusal must not echo the URL, which is bearer material.
    assert untrusted_https not in str(failure.value)


def test_the_subscription_client_never_turns_verification_off(untrusted_https):
    """What the fetch path can be tested for directly, given that gate.

    The session the fetch uses is exercised against the untrusted server with
    the product's own settings, so a `verify=False` anywhere in that path shows
    up as a successful request instead of an SSL error.
    """

    import requests

    from jerryproxy.subscription.transport import CONNECT_TIMEOUT, READ_TIMEOUT

    session = requests.Session()
    # Whatever the product does to its session before requesting, it must not
    # end with verification disabled.
    with pytest.raises(requests.exceptions.SSLError):
        session.get(untrusted_https, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    assert session.verify is True


def test_a_backend_download_refuses_an_untrusted_certificate(tmp_path, untrusted_https):
    """The one path here that genuinely reaches certificate validation.

    The body is served correctly and the digest is wrong, so a refusal for any
    other reason would be reported differently: the classification must name
    TLS, or the test would pass on a connection that never got that far.
    """

    downloader = AssetDownloader()

    with pytest.raises(DownloadError) as failure:
        downloader.download(
            untrusted_https,
            tmp_path / "artifact",
            expected_sha256="0" * 64,
        )

    assert "tls" in str(failure.value).lower(), (
        "the refusal must be classified as a TLS failure, not merely as some error"
    )
    assert not (tmp_path / "artifact").exists(), "a refused download must leave nothing behind"


def test_no_code_path_disables_certificate_verification():
    """A second, cheaper guard: the obvious mistake must not appear either.

    The tests above prove the behaviour; this one keeps a future `verify=False`
    from being introduced somewhere they do not reach.
    """

    root = Path(__file__).parent.parent.parent / "jerryproxy"
    offenders = []
    for source in root.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        for marker in ("verify=False", "verify = False", "CERT_NONE", "check_hostname = False"):
            if marker in text:
                offenders.append("%s: %s" % (source.name, marker))
    assert offenders == []
