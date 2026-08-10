"""Serve one bounded Base64 URI-line subscription body built from the environment.

The body must contain the exact node URIs the test will select, and those are
generated per run, so it is assembled here rather than baked into the image.
"""

import base64
import binascii
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FEED_PATH = "/subscription"
# One already-Base64 body, because the runner drops an output that looks
# like a credential URI and a service container cannot be handed a value
# composed inside the job.
BODY_VARIABLE = "E2E_SUBSCRIPTION_BODY"


class _Handler(BaseHTTPRequestHandler):
    server_version = "jerryproxy-e2e-subscription"
    sys_version = ""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's required name
        if self.path != FEED_PATH:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = self.server.body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002 - signature is fixed upstream
        # The body carries node URIs; log the request line only.
        sys.stderr.write("subscription %s\n" % (format % args))


def main():  # type: () -> int
    encoded = os.environ.get(BODY_VARIABLE, "")
    if not encoded:
        sys.stderr.write("%s is required\n" % BODY_VARIABLE)
        return 2
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        sys.stderr.write("%s must be base64\n" % BODY_VARIABLE)
        return 2
    # Served exactly as received: a subscription body is Base64 URI lines, and
    # re-encoding here would hide a malformed value behind a valid-looking one.
    body = encoded.encode("ascii") + b"\n"
    records = len([line for line in decoded.splitlines() if line.strip()])
    port = int(os.environ.get("E2E_PORT", "8081"))
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    server.body = body
    sys.stderr.write("subscription listening on 0.0.0.0:%d with %d records\n" % (port, records))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
