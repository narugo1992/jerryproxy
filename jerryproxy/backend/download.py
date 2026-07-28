"""Bounded HTTPS backend asset downloader."""

import hashlib
import os
from urllib.parse import urlparse

import requests
from tqdm import tqdm

from ..errors import DownloadError, IntegrityError
from ..utils.fs import ensure_private_directory


class AssetDownloader(object):
    """Stream verified assets with requests and a byte-oriented tqdm status."""

    def __init__(
        self,
        timeout=60.0,
        maximum_bytes=256 * 1024 * 1024,
        session=None,
        progress_factory=None,
        progress=True,
    ):
        # type: (float, int, Any, Callable, bool) -> None
        self.timeout = timeout
        self.maximum_bytes = maximum_bytes
        self.session = session or requests.Session()
        self.progress_factory = progress_factory or tqdm
        self.progress = progress

    def download(self, url, destination, expected_sha256, expected_size=None):
        # type: (str, Path, str, int) -> Path
        if urlparse(url).scheme != "https":
            raise DownloadError("backend downloads require HTTPS: %s" % url)
        ensure_private_directory(destination.parent)
        temporary = destination.with_name(".%s.%s.part" % (destination.name, os.getpid()))
        if temporary.exists():
            temporary.unlink()
        digest = hashlib.sha256()
        total = 0
        descriptor = -1
        progress = self.progress_factory(
            total=expected_size,
            desc="Connecting %s" % destination.name,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            dynamic_ncols=True,
            leave=True,
            disable=not self.progress,
        )
        try:
            try:
                response = self.session.get(
                    url,
                    allow_redirects=True,
                    headers={"User-Agent": "JerryProxy-backend-downloader"},
                    stream=True,
                    timeout=self.timeout,
                )
            except requests.exceptions.RequestException as error:
                # RequestException covers expected DNS, TLS, proxy, connection, and timeout failures.
                raise DownloadError("backend download failed: %s" % error)
            with response:
                final_url = response.url
                if urlparse(final_url).scheme != "https":
                    raise DownloadError("backend download redirected away from HTTPS")
                try:
                    response.raise_for_status()
                except requests.exceptions.HTTPError as error:
                    # HTTPError is expected for missing or rejected upstream release assets.
                    status_code = error.response.status_code if error.response is not None else response.status_code
                    raise DownloadError("backend download failed: HTTP %s" % status_code)
                content_length = response.headers.get("Content-Length")
                declared_size = None
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        # ValueError is expected when an upstream server sends a malformed length.
                        raise DownloadError("backend download has an invalid Content-Length")
                    if declared_size < 0:
                        raise DownloadError("backend download has an invalid Content-Length")
                    if declared_size > self.maximum_bytes:
                        raise DownloadError("backend asset exceeds the download safety limit")
                if progress.total is None and declared_size is not None:
                    progress.total = declared_size
                    progress.refresh()
                progress.set_description("Downloading %s" % destination.name, refresh=True)
                descriptor = os.open(
                    str(temporary),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = -1
                    try:
                        for block in response.iter_content(chunk_size=1024 * 1024):
                            if not block:
                                continue
                            total += len(block)
                            if total > self.maximum_bytes:
                                raise DownloadError("backend asset exceeds the download safety limit")
                            digest.update(block)
                            stream.write(block)
                            progress.update(len(block))
                    except requests.exceptions.RequestException as error:
                        # Stream failures include interrupted and malformed chunked responses.
                        raise DownloadError("backend download failed while streaming: %s" % error)
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
            progress.set_description("Downloaded %s" % destination.name, refresh=True)
            return destination
        except (DownloadError, IntegrityError):
            progress.set_description("Download failed %s" % destination.name, refresh=True)
            raise
        finally:
            progress.close()
            if descriptor >= 0:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()
