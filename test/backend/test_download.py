import hashlib
import os

import pytest
import requests

from jerryproxy.backend.download import AssetDownloader
from jerryproxy.errors import DownloadError, IntegrityError


class FakeResponse(object):
    def __init__(
        self,
        payload=b"",
        final_url="https://objects.example.test/asset",
        headers=None,
        status_code=200,
        chunks=None,
        stream_error=None,
    ):
        self.payload = payload
        self.url = final_url
        self.headers = {"Content-Length": str(len(payload))} if headers is None else headers
        self.status_code = status_code
        self.chunks = list(chunks) if chunks is not None else [payload]
        self.stream_error = stream_error

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError("HTTP %d" % self.status_code, response=self)

    def iter_content(self, chunk_size):
        assert chunk_size == 1024 * 1024
        for chunk in self.chunks:
            yield chunk
        if self.stream_error is not None:
            raise self.stream_error


class FakeSession(object):
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        return self.response


class FakeProgress(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.total = kwargs["total"]
        self.descriptions = [kwargs["desc"]]
        self.updates = []
        self.refresh_count = 0
        self.closed = False

    def refresh(self):
        self.refresh_count += 1

    def set_description(self, description, refresh=True):
        self.descriptions.append(description)
        if refresh:
            self.refresh()

    def update(self, amount):
        self.updates.append(amount)

    def close(self):
        self.closed = True


class FakeProgressFactory(object):
    def __init__(self):
        self.instances = []

    def __call__(self, **kwargs):
        progress = FakeProgress(**kwargs)
        self.instances.append(progress)
        return progress


def make_downloader(response=None, error=None, **kwargs):
    session = FakeSession(response=response, error=error)
    return AssetDownloader(session=session, progress=False, **kwargs), session


def test_download_verifies_digest_size_and_requests_streaming_contract(tmp_path):
    payload = b"verified backend"
    response = FakeResponse(payload)
    downloader, session = make_downloader(response)
    target = tmp_path / "backend.gz"
    digest = hashlib.sha256(payload).hexdigest()

    downloader.download(
        "https://example.test/backend.gz",
        target,
        digest,
        expected_size=len(payload),
    )

    assert target.read_bytes() == payload
    assert session.calls == [
        (
            "https://example.test/backend.gz",
            {
                "allow_redirects": True,
                "headers": {"User-Agent": "JerryProxy-backend-downloader"},
                "stream": True,
                "timeout": 60.0,
            },
        )
    ]


def test_download_rejects_digest_mismatch(tmp_path):
    payload = b"wrong backend"
    downloader, _ = make_downloader(FakeResponse(payload))
    target = tmp_path / "backend.gz"

    with pytest.raises(IntegrityError):
        downloader.download("https://example.test/backend.gz", target, "0" * 64)

    assert not target.exists()


def test_download_rejects_non_https_without_a_request(tmp_path):
    downloader, session = make_downloader()

    with pytest.raises(DownloadError):
        downloader.download("http://example.test/backend.gz", tmp_path / "x", "0" * 64)

    assert session.calls == []


def test_download_rejects_non_https_redirect(tmp_path):
    payload = b"backend"
    downloader, _ = make_downloader(FakeResponse(payload, final_url="http://mirror.test/backend"))

    with pytest.raises(DownloadError):
        downloader.download(
            "https://example.test/backend.gz",
            tmp_path / "x",
            hashlib.sha256(payload).hexdigest(),
        )


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (FakeResponse(status_code=404), None, "HTTP 404"),
        (None, requests.exceptions.ConnectionError("network unavailable"), "network unavailable"),
        (None, requests.exceptions.Timeout("connection timed out"), "connection timed out"),
    ],
)
def test_download_translates_request_failures(tmp_path, response, error, message):
    downloader, _ = make_downloader(response=response, error=error)

    with pytest.raises(DownloadError, match=message):
        downloader.download(
            "https://example.test/backend.gz",
            tmp_path / "backend.gz",
            "0" * 64,
        )


@pytest.mark.parametrize("content_length", ["invalid", "-1"])
def test_download_rejects_invalid_content_length(tmp_path, content_length):
    response = FakeResponse(b"backend", headers={"Content-Length": content_length})
    downloader, _ = make_downloader(response)

    with pytest.raises(DownloadError, match="invalid Content-Length"):
        downloader.download(
            "https://example.test/backend.gz",
            tmp_path / "backend.gz",
            hashlib.sha256(b"backend").hexdigest(),
        )


def test_download_rejects_declared_oversize_before_writing(tmp_path):
    target = tmp_path / "backend.gz"
    response = FakeResponse(b"data", headers={"Content-Length": "5"})
    downloader, _ = make_downloader(response, maximum_bytes=4)

    with pytest.raises(DownloadError, match="safety limit"):
        downloader.download(
            "https://example.test/backend.gz",
            target,
            hashlib.sha256(b"data").hexdigest(),
        )

    assert not target.exists()


def test_download_rejects_streamed_oversize_and_cleans_partial_file(tmp_path):
    target = tmp_path / "backend.gz"
    response = FakeResponse(b"12345", headers={})
    downloader, _ = make_downloader(response, maximum_bytes=4)

    with pytest.raises(DownloadError, match="safety limit"):
        downloader.download(
            "https://example.test/backend.gz",
            target,
            hashlib.sha256(b"12345").hexdigest(),
        )

    assert not target.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_download_translates_stream_interrupt_and_cleans_partial_file(tmp_path):
    target = tmp_path / "backend.gz"
    response = FakeResponse(
        headers={},
        chunks=[b"partial"],
        stream_error=requests.exceptions.ChunkedEncodingError("connection interrupted"),
    )
    downloader, _ = make_downloader(response)

    with pytest.raises(DownloadError, match="failed while streaming"):
        downloader.download("https://example.test/backend.gz", target, "0" * 64)

    assert not target.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_download_rejects_expected_size_mismatch(tmp_path):
    payload = b"backend"
    target = tmp_path / "backend.gz"
    downloader, _ = make_downloader(FakeResponse(payload))

    with pytest.raises(IntegrityError, match="size mismatch"):
        downloader.download(
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
    downloader, _ = make_downloader(FakeResponse(payload))

    downloader.download(
        "https://example.test/backend.gz",
        target,
        hashlib.sha256(payload).hexdigest(),
    )

    assert target.read_bytes() == payload
    assert not partial.exists()


def test_download_progress_reports_connection_bytes_and_completion(tmp_path):
    payload = b"abcdef"
    response = FakeResponse(payload, chunks=[b"ab", b"cdef"])
    session = FakeSession(response=response)
    factory = FakeProgressFactory()
    target = tmp_path / "backend.gz"
    downloader = AssetDownloader(session=session, progress_factory=factory, progress=True)

    downloader.download(
        "https://example.test/backend.gz",
        target,
        hashlib.sha256(payload).hexdigest(),
    )

    progress = factory.instances[0]
    assert progress.total == len(payload)
    assert progress.updates == [2, 4]
    assert progress.descriptions == [
        "Connecting backend.gz",
        "Downloading backend.gz",
        "Downloaded backend.gz",
    ]
    assert progress.kwargs["unit"] == "B"
    assert progress.kwargs["unit_scale"] is True
    assert progress.kwargs["disable"] is False
    assert progress.closed


def test_download_progress_reports_failure_and_closes(tmp_path):
    response = FakeResponse(status_code=503)
    session = FakeSession(response=response)
    factory = FakeProgressFactory()
    downloader = AssetDownloader(session=session, progress_factory=factory, progress=True)

    with pytest.raises(DownloadError, match="HTTP 503"):
        downloader.download(
            "https://example.test/backend.gz",
            tmp_path / "backend.gz",
            "0" * 64,
        )

    progress = factory.instances[0]
    assert progress.descriptions[-1] == "Download failed backend.gz"
    assert progress.closed
