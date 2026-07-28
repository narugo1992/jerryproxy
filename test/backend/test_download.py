import hashlib
import io
import os
from urllib.error import HTTPError, URLError

import pytest

from jerryproxy.backend.download import AssetDownloader
from jerryproxy.errors import DownloadError, IntegrityError


class FakeResponse(object):
    def __init__(self, payload, final_url="https://objects.example.test/asset", headers=None):
        self.stream = io.BytesIO(payload)
        self.final_url = final_url
        self.headers = {"Content-Length": str(len(payload))} if headers is None else headers

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        return False

    def read(self, size):
        return self.stream.read(size)

    def geturl(self):
        return self.final_url


def test_download_verifies_digest_and_size(tmp_path):
    payload = b"verified backend"

    def opener(request, timeout):
        assert request.full_url == "https://example.test/backend.gz"
        return FakeResponse(payload)

    target = tmp_path / "backend.gz"
    digest = hashlib.sha256(payload).hexdigest()
    AssetDownloader(opener=opener).download(
        "https://example.test/backend.gz",
        target,
        digest,
        expected_size=len(payload),
    )
    assert target.read_bytes() == payload


def test_download_rejects_digest_mismatch(tmp_path):
    payload = b"wrong backend"
    downloader = AssetDownloader(opener=lambda request, timeout: FakeResponse(payload))
    target = tmp_path / "backend.gz"
    with pytest.raises(IntegrityError):
        downloader.download("https://example.test/backend.gz", target, "0" * 64)
    assert not target.exists()


def test_download_rejects_non_https(tmp_path):
    with pytest.raises(DownloadError):
        AssetDownloader().download("http://example.test/backend.gz", tmp_path / "x", "0" * 64)


def test_download_rejects_non_https_redirect(tmp_path):
    payload = b"backend"
    downloader = AssetDownloader(
        opener=lambda request, timeout: FakeResponse(payload, final_url="http://mirror.test/backend")
    )
    with pytest.raises(DownloadError):
        downloader.download(
            "https://example.test/backend.gz",
            tmp_path / "x",
            hashlib.sha256(payload).hexdigest(),
        )


@pytest.mark.parametrize(
    ("error_kind", "message"),
    [
        ("http", "HTTP 404"),
        ("url", "network unavailable"),
    ],
)
def test_download_translates_transport_errors(tmp_path, error_kind, message):
    if error_kind == "http":
        error = HTTPError("https://example.test/backend.gz", 404, "Not Found", {}, None)
    else:
        error = URLError("network unavailable")

    def opener(request, timeout):
        raise error

    with pytest.raises(DownloadError, match=message):
        AssetDownloader(opener=opener).download(
            "https://example.test/backend.gz",
            tmp_path / "backend.gz",
            "0" * 64,
        )


def test_download_rejects_invalid_content_length(tmp_path):
    response = FakeResponse(b"backend", headers={"Content-Length": "invalid"})
    with pytest.raises(DownloadError, match="invalid Content-Length"):
        AssetDownloader(opener=lambda request, timeout: response).download(
            "https://example.test/backend.gz",
            tmp_path / "backend.gz",
            hashlib.sha256(b"backend").hexdigest(),
        )


def test_download_rejects_declared_oversize_before_writing(tmp_path):
    target = tmp_path / "backend.gz"
    response = FakeResponse(b"data", headers={"Content-Length": "5"})
    with pytest.raises(DownloadError, match="safety limit"):
        AssetDownloader(maximum_bytes=4, opener=lambda request, timeout: response).download(
            "https://example.test/backend.gz",
            target,
            hashlib.sha256(b"data").hexdigest(),
        )
    assert not target.exists()


def test_download_rejects_streamed_oversize_and_cleans_partial_file(tmp_path):
    target = tmp_path / "backend.gz"
    response = FakeResponse(b"12345", headers={})
    with pytest.raises(DownloadError, match="safety limit"):
        AssetDownloader(maximum_bytes=4, opener=lambda request, timeout: response).download(
            "https://example.test/backend.gz",
            target,
            hashlib.sha256(b"12345").hexdigest(),
        )
    assert not target.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_download_rejects_expected_size_mismatch(tmp_path):
    payload = b"backend"
    target = tmp_path / "backend.gz"
    with pytest.raises(IntegrityError, match="size mismatch"):
        AssetDownloader(opener=lambda request, timeout: FakeResponse(payload)).download(
            "https://example.test/backend.gz",
            target,
            hashlib.sha256(payload).hexdigest(),
            expected_size=len(payload) + 1,
        )
    assert not target.exists()


def test_download_replaces_a_stale_partial_file(tmp_path):
    payload = b"fresh backend"
    target = tmp_path / "backend.gz"
    partial = target.with_name(".%s.%s.part" % (target.name, os.getpid()))
    partial.write_bytes(b"stale")

    AssetDownloader(opener=lambda request, timeout: FakeResponse(payload)).download(
        "https://example.test/backend.gz",
        target,
        hashlib.sha256(payload).hexdigest(),
    )

    assert target.read_bytes() == payload
    assert not partial.exists()
