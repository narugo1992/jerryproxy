"""Bounded HTTPS backend asset downloader."""

import hashlib
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..errors import DownloadError, IntegrityError
from ..utils.fs import ensure_private_directory


class AssetDownloader(object):
    def __init__(self, timeout=60.0, maximum_bytes=256 * 1024 * 1024, opener=None):
        # type: (float, int, Any) -> None
        self.timeout = timeout
        self.maximum_bytes = maximum_bytes
        self.opener = opener or urlopen

    def download(self, url, destination, expected_sha256, expected_size=None):
        # type: (str, Path, str, int) -> Path
        if urlparse(url).scheme != "https":
            raise DownloadError("backend downloads require HTTPS: %s" % url)
        ensure_private_directory(destination.parent)
        temporary = destination.with_name(".%s.%s.part" % (destination.name, os.getpid()))
        if temporary.exists():
            temporary.unlink()
        request = Request(url, headers={"User-Agent": "JerryProxy-backend-downloader"})
        digest = hashlib.sha256()
        total = 0
        descriptor = -1
        try:
            try:
                response = self.opener(request, timeout=self.timeout)
            except HTTPError as error:
                # HTTPError is expected for missing/rejected upstream release assets.
                raise DownloadError("backend download failed: HTTP %s" % error.code)
            except URLError as error:
                # URLError is expected for DNS, TLS, proxy, and connection failures.
                raise DownloadError("backend download failed: %s" % error.reason)
            with response:
                final_url = response.geturl()
                if urlparse(final_url).scheme != "https":
                    raise DownloadError("backend download redirected away from HTTPS")
                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        # ValueError is expected when an upstream server sends a malformed length.
                        raise DownloadError("backend download has an invalid Content-Length")
                    if declared_size > self.maximum_bytes:
                        raise DownloadError("backend asset exceeds the download safety limit")
                descriptor = os.open(
                    str(temporary),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = -1
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        total += len(block)
                        if total > self.maximum_bytes:
                            raise DownloadError("backend asset exceeds the download safety limit")
                        digest.update(block)
                        stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
            if expected_size is not None and total != expected_size:
                raise IntegrityError("backend asset size mismatch: expected %d, got %d" % (expected_size, total))
            actual_sha256 = digest.hexdigest()
            if actual_sha256.lower() != expected_sha256.lower():
                raise IntegrityError(
                    "backend asset SHA-256 mismatch: expected %s, got %s"
                    % (expected_sha256.lower(), actual_sha256.lower())
                )
            os.replace(str(temporary), str(destination))
            return destination
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()
