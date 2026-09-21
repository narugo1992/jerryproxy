"""Only explicitly transient source failures may drive persistent recovery."""

import socket
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest
import requests

from jerryproxy.errors import SubscriptionFetchError, SubscriptionTransportError
from jerryproxy.subscription.transport import fetch_subscription

from .test_transport import _public_source_resolver, _TransportResponse, _TransportSession


def fetch(session, resolver=_public_source_resolver):
    return fetch_subscription("https://provider.example/private?token=secret", session=session, resolver=resolver)


@pytest.mark.parametrize("error", [
    requests.exceptions.Timeout("secret"), requests.exceptions.ConnectionError("secret"),
])
def test_connection_failure_is_retryable_without_remote_diagnostics(error):
    with pytest.raises(SubscriptionTransportError) as failure:
        fetch(_TransportSession(error=error))
    assert "secret" not in str(failure.value)
    assert failure.value.retry_after == 0


@pytest.mark.parametrize("error", [
    requests.exceptions.SSLError("secret"), requests.exceptions.InvalidURL("secret"),
    requests.exceptions.RequestException("secret"),
])
def test_tls_and_unclassified_request_errors_remain_terminal(error):
    with pytest.raises(SubscriptionFetchError) as failure:
        fetch(_TransportSession(error=error))
    assert not isinstance(failure.value, SubscriptionTransportError)
    assert "secret" not in str(failure.value)


def test_dns_failure_is_retryable_but_private_answers_are_terminal():
    def unavailable(*args, **kwargs):
        raise socket.gaierror("secret")

    with pytest.raises(SubscriptionTransportError):
        fetch(_TransportSession(), resolver=unavailable)
    with pytest.raises(SubscriptionFetchError) as failure:
        fetch(_TransportSession(), resolver=lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))])
    assert not isinstance(failure.value, SubscriptionTransportError)


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_transient_http_status_preserves_retry_after_and_closes_response(status):
    response = _TransportResponse(status_code=status, headers={"Retry-After": "450"})
    with pytest.raises(SubscriptionTransportError) as failure:
        fetch(_TransportSession(response))
    assert failure.value.retry_after == 450
    assert response.closed


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 501, 505])
def test_other_http_failures_are_terminal(status):
    with pytest.raises(SubscriptionFetchError) as failure:
        fetch(_TransportSession(_TransportResponse(status_code=status)))
    assert not isinstance(failure.value, SubscriptionTransportError)


@pytest.mark.parametrize("header, expected", [
    (None, 0), ("", 0), ("-1", 0), ("1.5", 0), ("secret", 0), ("9" * 1024, 0),
    ("999999", 86400), (" 25 ", 25), ("0", 0),
    ("Wed, 01 Jan 2020 00:00:00 GMT", 0),
    ("Wed, 01 Jan 2020 00:00:00", 0),
])
def test_retry_after_is_bounded_and_invalid_values_are_discarded(header, expected):
    with pytest.raises(SubscriptionTransportError) as failure:
        fetch(_TransportSession(_TransportResponse(status_code=503, headers={"Retry-After": header})))
    assert failure.value.retry_after == expected
    assert "secret" not in str(failure.value)


def test_retry_after_http_date_is_respected():
    date = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=600), usegmt=True)
    with pytest.raises(SubscriptionTransportError) as failure:
        fetch(_TransportSession(_TransportResponse(status_code=429, headers={"Retry-After": date})))
    assert 595 <= failure.value.retry_after <= 600


@pytest.mark.parametrize("error, retryable", [
    (requests.exceptions.ConnectionError("secret"), True),
    (requests.exceptions.Timeout("secret"), True),
    (requests.exceptions.ChunkedEncodingError("secret"), True),
    (requests.exceptions.SSLError("secret"), False),
    (requests.exceptions.RequestException("secret"), False),
])
def test_stream_failures_retain_the_same_security_boundary(error, retryable):
    class Interrupted(_TransportResponse):
        def iter_content(self, chunk_size):
            raise error

    response = Interrupted()
    with pytest.raises(SubscriptionFetchError) as failure:
        fetch(_TransportSession(response))
    assert isinstance(failure.value, SubscriptionTransportError) is retryable
    assert response.closed
    assert "secret" not in str(failure.value)


@pytest.mark.parametrize("maximum", [0, -1, True, "1", 8 * 1024 * 1024 + 1])
def test_body_bound_is_validated_before_transport(maximum):
    session = _TransportSession()
    with pytest.raises(ValueError, match="maximum_bytes"):
        fetch_subscription("https://provider.example/sub", session=session, maximum_bytes=maximum)
    assert session.calls == 0


@pytest.mark.parametrize("headers, chunks", [
    ({"Content-Length": "-1"}, ()), ({"Content-Length": "99999999"}, ()),
    ({}, (b"012345",)),
])
def test_oversized_response_is_terminal_not_a_transport_retry(headers, chunks):
    response = _TransportResponse(headers=headers, chunks=chunks)
    with pytest.raises(SubscriptionFetchError, match="size bound") as failure:
        fetch_subscription("https://provider.example/sub", session=_TransportSession(response),
                           resolver=_public_source_resolver, maximum_bytes=4)
    assert not isinstance(failure.value, SubscriptionTransportError)
    assert response.closed


def test_empty_stream_chunks_are_ignored():
    response = _TransportResponse(chunks=(b"", b"ok", b""))
    assert fetch(_TransportSession(response)).body == b"ok"


@pytest.mark.parametrize("loop", [True, False])
def test_redirect_loops_and_excessive_hops_are_terminal(loop):
    class Redirecting(_TransportSession):
        def get(self, url, **kwargs):
            self.calls += 1
            return _TransportResponse(status_code=302, headers={
                "Location": url if loop else "https://provider.example/hop%d" % self.calls,
            })

    with pytest.raises(SubscriptionFetchError, match="redirect") as failure:
        fetch(Redirecting())
    assert not isinstance(failure.value, SubscriptionTransportError)


def test_malformed_resolver_answer_is_terminal():
    with pytest.raises(SubscriptionFetchError, match="resolution is invalid") as failure:
        fetch(_TransportSession(), resolver=lambda *args, **kwargs: [(2, 1, 6, "", ("secret", 443))])
    assert not isinstance(failure.value, SubscriptionTransportError)
