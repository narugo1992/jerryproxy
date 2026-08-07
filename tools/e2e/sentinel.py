"""The private oracle for the end-to-end lane.

This service has no published port and joins only ``private-net``, so the test
runner cannot reach it directly.  Its answer carries a per-run nonce supplied
through ``JERRYPROXY_E2E_MARKER`` at startup, which means a test can only learn
that answer by actually carrying traffic through a proxy that does sit on both
networks.  A constant baked into the image would prove nothing, because a test
could assert it without connecting to anything.

The nonce is never written to a node URI, a backend configuration, or this
service's own log.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER_PATH = "/jerryproxy-e2e-marker"
BANNER = "JERRYPROXY-E2E-SENTINEL-v1"


class _Handler(BaseHTTPRequestHandler):
    server_version = "jerryproxy-e2e-sentinel"
    sys_version = ""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's required name
        if self.path != MARKER_PATH:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = json.dumps(
            {"banner": BANNER, "marker": self.server.marker}, separators=(",", ":")
        ).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002 - signature is fixed upstream
        # Log the request line only.  The response carries the run nonce and
        # must never reach a captured log.
        sys.stderr.write("sentinel %s\n" % (format % args))


def main():  # type: () -> int
    marker = os.environ.get("JERRYPROXY_E2E_MARKER", "")
    if len(marker) < 32:
        sys.stderr.write("sentinel requires JERRYPROXY_E2E_MARKER of at least 32 characters\n")
        return 2
    port = int(os.environ.get("JERRYPROXY_E2E_SENTINEL_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    server.marker = marker
    sys.stderr.write("sentinel listening on 0.0.0.0:%d\n" % port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
