"""Bounded HTTPS backend asset downloader."""

import hashlib
import os
import sys
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from tqdm import tqdm

from ..errors import DownloadError, DownloadPolicyError, DownloadTransportError, IntegrityError
from ..utils.fs import ensure_private_directory
from .durable import flush_descriptor, flush_directory


def _write_status(message):  # type: (str) -> None
    print(message, file=sys.stderr)


class AssetDownloader(object):
    """Stream verified assets with requests and a byte-oriented tqdm status."""

    def __init__(
        self,
        timeout=60.0,
        maximum_bytes=256 * 1024 * 1024,
        session=None,
        progress_factory=None,
        progress=True,
        maximum_redirects=5,
        status_reporter=None,
    ):
        # type: (float, int, Any, Callable, bool, int, Callable) -> None
        if not isinstance(maximum_redirects, int) or isinstance(maximum_redirects, bool) or maximum_redirects < 0:
            raise ValueError("maximum_redirects must be a non-negative integer")
        self.timeout = timeout
        self.maximum_bytes = maximum_bytes
        self.session = session or requests.Session()
        self.progress_factory = progress_factory or tqdm
        self.progress = progress
        self.maximum_redirects = maximum_redirects
        self.status_reporter = status_reporter if status_reporter is not None else (_write_status if progress else None)

    @staticmethod
    def _validate_https_url(url):  # type: (str) -> None
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            # ValueError is expected for malformed bracket or port syntax.
            raise DownloadPolicyError("backend download URL is invalid")
        if parsed.scheme != "https" or not hostname:
            raise DownloadPolicyError("backend downloads require HTTPS with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise DownloadPolicyError("backend download URLs must not contain user information")
        if port is not None and (port < 1 or port > 65535):
            raise DownloadPolicyError("backend download URL has an invalid port")

    def _request(self, url):
        try:
            return self.session.get(
                url,
                allow_redirects=False,
                headers={"User-Agent": "JerryProxy-backend-downloader"},
                stream=True,
                timeout=self.timeout,
            )
        except (
            requests.exceptions.InvalidURL,
            requests.exceptions.InvalidSchema,
            requests.exceptions.MissingSchema,
            requests.exceptions.URLRequired,
        ):
            # These Requests exceptions identify an invalid effective request URL.
            raise DownloadPolicyError("backend download URL is invalid")
        except requests.exceptions.ProxyError:
            # ProxyError is the documented Requests proxy transport failure.
            raise DownloadTransportError("backend download failed: proxy", "proxy")
        except requests.exceptions.SSLError:
            # SSLError is the documented Requests TLS transport failure.
            raise DownloadTransportError("backend download failed: tls", "tls")
        except requests.exceptions.Timeout:
            # Timeout covers documented connect and read timeout failures.
            raise DownloadTransportError("backend download failed: timeout", "timeout")
        except requests.exceptions.ConnectionError:
            # ConnectionError covers expected DNS and connection failures.
            raise DownloadTransportError("backend download failed: connect", "connect")
        except requests.exceptions.RequestException:
            # Remaining RequestException subclasses are bounded request transport failures.
            raise DownloadTransportError("backend download failed: request", "request")

    def _open_response(self, url):
        self._validate_https_url(url)
        current_url = url
        visited = set()
        redirect_statuses = (301, 302, 303, 307, 308)
        for redirect_count in range(self.maximum_redirects + 1):
            identity = urldefrag(current_url)[0]
            if identity in visited:
                raise DownloadPolicyError("backend download redirect loop detected")
            visited.add(identity)
            response = self._request(current_url)
            if response.status_code not in redirect_statuses:
                return response
            try:
                location = response.headers.get("Location")
                if not location:
                    raise DownloadPolicyError("backend download redirect has no Location")
                if redirect_count >= self.maximum_redirects:
                    raise DownloadPolicyError("backend download redirect limit exceeded")
                try:
                    next_url = urldefrag(urljoin(current_url, location))[0]
                except ValueError:
                    # ValueError is expected for a malformed redirect Location URL.
                    raise DownloadPolicyError("backend download URL is invalid")
                self._validate_https_url(next_url)
            finally:
                response.close()
            current_url = next_url

    def download_sources(self, sources, destination, expected_sha256, expected_size=None):
        # type: (tuple, Path, str, int) -> Path
        """Try an explicit bounded source sequence on transport failures only."""

        failures = []
        for source in sources:
            try:
                downloaded = self.download(source.url, destination, expected_sha256, expected_size)
            except DownloadTransportError as error:
                failures.append("%s (%s)" % (source.label, error.category))
                if self.status_reporter is not None:
                    self.status_reporter("Backend download source %s failed: %s." % (source.label, error.category))
            else:
                if failures and self.status_reporter is not None:
                    self.status_reporter(
                        "Backend download source selected: %s after %d transport failure(s)."
                        % (source.label, len(failures))
                    )
                return downloaded
        raise DownloadTransportError(
            "backend download sources exhausted: %s" % ", ".join(failures),
            "exhausted",
        )

    def download(self, url, destination, expected_sha256, expected_size=None):
        # type: (str, Path, str, int) -> Path
        self._validate_https_url(url)
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
            response = self._open_response(url)
            with response:
                if response.status_code < 200 or response.status_code >= 300:
                    raise DownloadTransportError(
                        "backend download failed: HTTP %s" % response.status_code,
                        "http_%s" % response.status_code,
                    )
                content_length = response.headers.get("Content-Length")
                declared_size = None
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        # ValueError is expected when an upstream server sends a malformed length.
                        raise DownloadPolicyError("backend download has an invalid Content-Length")
                    if declared_size < 0:
                        raise DownloadPolicyError("backend download has an invalid Content-Length")
                    if declared_size > self.maximum_bytes:
                        raise DownloadPolicyError("backend asset exceeds the download safety limit")
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
                                raise DownloadPolicyError("backend asset exceeds the download safety limit")
                            digest.update(block)
                            stream.write(block)
                            progress.update(len(block))
                    except requests.exceptions.RequestException:
                        # Stream failures include interrupted and malformed chunked responses.
                        raise DownloadTransportError(
                            "backend download failed while streaming",
                            "stream",
                        )
                    stream.flush()
                    flush_descriptor(stream.fileno(), "backend download cache file")
            if expected_size is not None and total != expected_size:
                raise IntegrityError("backend asset size mismatch: expected %d, got %d" % (expected_size, total))
            actual_sha256 = digest.hexdigest()
            if actual_sha256.lower() != expected_sha256.lower():
                raise IntegrityError(
                    "backend asset SHA-256 mismatch: expected %s, got %s"
                    % (expected_sha256.lower(), actual_sha256.lower())
                )
            os.replace(str(temporary), str(destination))
            flush_directory(destination.parent)
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
