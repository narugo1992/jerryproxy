import hashlib
import io

import pytest

from jerryproxy.backend.download import AssetDownloader
from jerryproxy.errors import DownloadError, IntegrityError


class FakeResponse(object):
    def __init__(self, payload, final_url="https://objects.example.test/asset"):
        self.stream = io.BytesIO(payload)
        self.final_url = final_url
        self.headers = {"Content-Length": str(len(payload))}

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
