"""Serve one bounded Base64 URI-line subscription body built from the environment.

The body must contain the exact node URIs the test will select, and those are
generated per run, so it is assembled here rather than baked into the image.
"""

import base64
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FEED_PATH = "/subscription"
NODE_VARIABLES = ("E2E_SS_NODE", "E2E_VMESS_NODE", "E2E_VLESS_NODE")


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
    lines = []
    for name in NODE_VARIABLES:
        value = os.environ.get(name, "")
        if not value:
            sys.stderr.write("%s is required\n" % name)
            return 2
        lines.append(value)
    body = base64.b64encode(("\n".join(lines) + "\n").encode("utf-8")) + b"\n"
    port = int(os.environ.get("E2E_PORT", "8081"))
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    server.body = body
    sys.stderr.write("subscription listening on 0.0.0.0:%d with %d records\n" % (port, len(lines)))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
