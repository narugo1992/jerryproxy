import hashlib
import os

import pytest
import requests

import jerryproxy.backend.download as download_module
from jerryproxy.backend.download import AssetDownloader
from jerryproxy.backend.relay import DownloadSource
from jerryproxy.errors import (
    DownloadError,
    DownloadPolicyError,
    DownloadTransportError,
    IntegrityError,
)


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
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.close()
        return False

    def close(self):
        self.closed = True

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
                "allow_redirects": False,
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


def test_download_rejects_url_user_information_without_a_request(tmp_path):
    downloader, session = make_downloader()

    with pytest.raises(DownloadPolicyError, match="user information"):
        downloader.download("https://user:secret@example.test/backend.gz", tmp_path / "x", "0" * 64)

    assert session.calls == []


@pytest.mark.parametrize(
    "url",
    ["https://example.test:99999/backend.gz", "https://example.test:0/backend.gz", "https://["],
)
def test_download_rejects_an_invalid_url_without_a_request(tmp_path, url):
    downloader, session = make_downloader()

    with pytest.raises(DownloadPolicyError, match="invalid"):
        downloader.download(url, tmp_path / "x", "0" * 64)

    assert session.calls == []


@pytest.mark.parametrize("maximum_redirects", [-1, 1.5, True])
def test_downloader_rejects_an_invalid_redirect_budget(maximum_redirects):
    with pytest.raises(ValueError, match="non-negative integer"):
        AssetDownloader(maximum_redirects=maximum_redirects)


def test_download_rejects_non_https_redirect_before_contact(tmp_path):
    response = FakeResponse(status_code=302, headers={"Location": "http://mirror.test/backend"})
    downloader, session = make_downloader(response)

    with pytest.raises(DownloadPolicyError, match="HTTPS"):
        downloader.download("https://example.test/backend.gz", tmp_path / "x", "0" * 64)

    assert [call[0] for call in session.calls] == ["https://example.test/backend.gz"]
    assert response.closed


def test_download_rejects_a_malformed_redirect_location(tmp_path):
    response = FakeResponse(status_code=302, headers={"Location": "https://["})
    downloader, session = make_downloader(response)

    with pytest.raises(DownloadPolicyError, match="invalid"):
        downloader.download("https://example.test/backend.gz", tmp_path / "x", "0" * 64)

    assert [call[0] for call in session.calls] == ["https://example.test/backend.gz"]
    assert response.closed


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (FakeResponse(status_code=404), None, "HTTP 404"),
        (None, requests.exceptions.ProxyError("secret proxy URL"), "proxy"),
        (None, requests.exceptions.SSLError("certificate details"), "tls"),
        (None, requests.exceptions.ConnectionError("network unavailable"), "connect"),
        (None, requests.exceptions.Timeout("connection timed out"), "timeout"),
        (None, requests.exceptions.RequestException("request details"), "request"),
    ],
)
def test_download_translates_request_failures(tmp_path, response, error, message):
    downloader, _ = make_downloader(response=response, error=error)

    with pytest.raises(DownloadTransportError, match=message):
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
    response = FakeResponse(payload, chunks=[b"", b"ab", b"cdef"])
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


def test_download_closes_raw_descriptor_when_fdopen_fails(tmp_path, monkeypatch):
    payload = b"backend"
    downloader, _ = make_downloader(FakeResponse(payload))
    closed = []
    real_close = download_module.os.close

    def fail_fdopen(descriptor, mode):
        raise OSError("fdopen unavailable")

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(download_module.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(download_module.os, "close", close)

    with pytest.raises(OSError, match="fdopen unavailable"):
        downloader.download(
            "https://example.test/backend.gz",
            tmp_path / "backend.gz",
            hashlib.sha256(payload).hexdigest(),
        )

    assert len(closed) == 1
    assert not list(tmp_path.glob(".*.part"))


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


class SequenceSession(object):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, requests.exceptions.RequestException):
            raise response
        return response


def test_download_follows_bounded_relative_https_redirects(tmp_path):
    payload = b"redirected backend"
    redirect = FakeResponse(
        status_code=302,
        final_url="https://example.test/backend.gz",
        headers={"Location": "/objects/backend.gz"},
    )
    final = FakeResponse(payload, final_url="https://example.test/objects/backend.gz")
    session = SequenceSession([redirect, final])
    downloader = AssetDownloader(session=session, progress=False)

    downloader.download(
        "https://example.test/backend.gz",
        tmp_path / "backend.gz",
        hashlib.sha256(payload).hexdigest(),
    )

    assert [call[0] for call in session.calls] == [
        "https://example.test/backend.gz",
        "https://example.test/objects/backend.gz",
    ]
    assert redirect.closed
    assert final.closed


@pytest.mark.parametrize(
    ("response", "maximum_redirects", "message"),
    [
        (FakeResponse(status_code=302, headers={}), 5, "no Location"),
        (
            FakeResponse(status_code=302, headers={"Location": "/backend.gz"}),
            5,
            "redirect loop",
        ),
        (
            FakeResponse(status_code=302, headers={"Location": "/next.gz"}),
            0,
            "redirect limit",
        ),
    ],
)
def test_download_rejects_invalid_redirect_sequences(tmp_path, response, maximum_redirects, message):
    session = SequenceSession([response])
    downloader = AssetDownloader(session=session, progress=False, maximum_redirects=maximum_redirects)

    with pytest.raises(DownloadPolicyError, match=message):
        downloader.download("https://example.test/backend.gz", tmp_path / "backend.gz", "0" * 64)

    assert response.closed


def test_download_sources_falls_back_only_after_transport_failure(tmp_path):
    payload = b"fallback backend"
    session = SequenceSession([FakeResponse(status_code=503), FakeResponse(payload)])
    messages = []
    downloader = AssetDownloader(session=session, progress=False, status_reporter=messages.append)
    sources = (
        DownloadSource("first", "https://first.example/backend.gz"),
        DownloadSource("second", "https://second.example/backend.gz"),
    )

    downloader.download_sources(
        sources,
        tmp_path / "backend.gz",
        hashlib.sha256(payload).hexdigest(),
        expected_size=len(payload),
    )

    assert [call[0] for call in session.calls] == [item.url for item in sources]
    assert messages == [
        "Backend download source first failed: http_503.",
        "Backend download source selected: second after 1 transport failure(s).",
    ]
    assert all("https://" not in message for message in messages)


def test_download_sources_reports_default_fallback_status_on_stderr(tmp_path, capsys):
    payload = b"fallback backend"
    session = SequenceSession([FakeResponse(status_code=503), FakeResponse(payload)])
    downloader = AssetDownloader(session=session, progress_factory=FakeProgressFactory(), progress=True)
    sources = (
        DownloadSource("first", "https://first.example/backend.gz"),
        DownloadSource("second", "https://second.example/backend.gz"),
    )

    downloader.download_sources(
        sources,
        tmp_path / "backend.gz",
        hashlib.sha256(payload).hexdigest(),
        expected_size=len(payload),
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "Backend download source first failed: http_503.",
        "Backend download source selected: second after 1 transport failure(s).",
    ]
    assert "https://" not in captured.err


def test_download_sources_never_hides_integrity_failure(tmp_path):
    session = SequenceSession([FakeResponse(b"wrong"), FakeResponse(b"unused")])
    downloader = AssetDownloader(session=session, progress=False)
    sources = (
        DownloadSource("first", "https://first.example/backend.gz"),
        DownloadSource("second", "https://second.example/backend.gz"),
    )

    with pytest.raises(IntegrityError):
        downloader.download_sources(sources, tmp_path / "backend.gz", "0" * 64)

    assert [call[0] for call in session.calls] == [sources[0].url]


def test_download_sources_never_falls_back_after_an_invalid_redirect_url(tmp_path):
    redirect = FakeResponse(status_code=302, headers={"Location": "https://*/asset"})
    session = SequenceSession(
        [
            redirect,
            requests.exceptions.InvalidURL("invalid redirect URL"),
            FakeResponse(b"must not be requested"),
        ]
    )
    downloader = AssetDownloader(session=session, progress=False)
    sources = (
        DownloadSource("first", "https://first.example/backend.gz"),
        DownloadSource("second", "https://second.example/backend.gz"),
    )

    with pytest.raises(DownloadPolicyError, match="URL is invalid"):
        downloader.download_sources(sources, tmp_path / "backend.gz", "0" * 64)

    assert [call[0] for call in session.calls] == [
        sources[0].url,
        "https://*/asset",
    ]
    assert redirect.closed


def test_download_sources_reports_sanitized_exhaustion(tmp_path):
    session = SequenceSession([FakeResponse(status_code=503), FakeResponse(status_code=404)])
    messages = []
    downloader = AssetDownloader(session=session, progress=False, status_reporter=messages.append)
    sources = (
        DownloadSource("first", "https://first.example/backend.gz"),
        DownloadSource("second", "https://second.example/backend.gz"),
    )

    with pytest.raises(DownloadTransportError, match=r"first \(http_503\), second \(http_404\)"):
        downloader.download_sources(sources, tmp_path / "backend.gz", "0" * 64)

    assert [call[0] for call in session.calls] == [item.url for item in sources]
    assert messages == [
        "Backend download source first failed: http_503.",
        "Backend download source second failed: http_404.",
    ]
    assert all("https://" not in message for message in messages)
