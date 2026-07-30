"""Probe configured GitHub Release relays from one local JSON file."""

import argparse
import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from urllib.parse import urlparse

import requests

from jerryproxy.backend.relay import (
    ALLOWED_PATTERNS,
    RELAY_PROBE_BYTES,
    RELAY_PROBE_SHA256,
    RELAY_PROBE_SIZE,
    RELAY_PROBE_URL,
    custom_relay,
    render_relay_url,
)
from jerryproxy.errors import DownloadPolicyError

PATTERNS = ALLOWED_PATTERNS
PATTERN_DESCRIPTIONS = {
    "full_url_path": "https://{relay}/{url}",
    "host_path": "https://{relay}/{host_path}",
    "query_q": "https://{relay}/?q={url_encoded}",
}
RECOMMENDATIONS = (
    "manual_named_candidate",
    "manual_transport_only",
    "manual_transport_verified",
    "named_profile_candidate",
)
PINNED_PROBE = {
    "backend": "xray",
    "range_bytes": RELAY_PROBE_BYTES,
    "size": RELAY_PROBE_SIZE,
    "slice_sha256": RELAY_PROBE_SHA256,
    "url": RELAY_PROBE_URL,
}
DEFAULT_ATTEMPTS = 3
MAXIMUM_ATTEMPTS = 5
MAXIMUM_TARGETS = 500
MAXIMUM_RANGE_BYTES = 1024 * 1024
MAXIMUM_TARGET_BYTES = 1024 * 1024
MAXIMUM_REDIRECTS = 5
MAXIMUM_DESCRIPTION_LENGTH = 500
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HOSTNAME = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class RelayHealthError(RuntimeError):
    """Raised when relay-health input or output cannot be handled safely."""


def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path):
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except OSError as error:
        raise RelayHealthError("cannot read %s: %s" % (path, error))
    except ValueError as error:
        raise RelayHealthError("invalid JSON in %s: %s" % (path, error))


def _write_json(path, value):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(".%s.tmp" % path.name)
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        temporary.replace(path)
    except OSError as error:
        raise RelayHealthError("cannot write %s: %s" % (path, error))


def _validate_hostname(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise RelayHealthError("target hostname must be a non-empty string")
    try:
        parsed = urlparse("https://%s" % value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise RelayHealthError("target hostname is invalid")
    if (
        value != value.lower()
        or _HOSTNAME.fullmatch(value) is None
        or hostname != value.lower()
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RelayHealthError("target hostname is not a plain lowercase hostname: %s" % value)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise RelayHealthError("target hostname must use ASCII or punycode: %s" % value)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        # ValueError is expected for the required DNS hostname form.
        pass
    else:
        raise RelayHealthError("target hostname must not be an IP literal: %s" % value)
    return value


def _validate_description(value, identifier):
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > MAXIMUM_DESCRIPTION_LENGTH
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
        or any(character in value for character in "|<>`[]")
    ):
        raise RelayHealthError("target description must be bounded plain ASCII text: %s" % identifier)
    return value


def _validate_probe(value):
    if not isinstance(value, dict):
        raise RelayHealthError("probe must be an object")
    url = value.get("url")
    try:
        parsed = urlparse(url) if isinstance(url, str) else None
        hostname = parsed.hostname if parsed is not None else None
        port = parsed.port if parsed is not None else None
    except ValueError:
        raise RelayHealthError("probe URL must be a public GitHub Release HTTPS URL")
    if (
        parsed is None
        or parsed.scheme != "https"
        or hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or "/releases/download/" not in parsed.path
    ):
        raise RelayHealthError("probe URL must be a public GitHub Release HTTPS URL")
    size = value.get("size")
    range_bytes = value.get("range_bytes")
    digest = value.get("slice_sha256")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise RelayHealthError("probe size must be a positive integer")
    if (
        not isinstance(range_bytes, int)
        or isinstance(range_bytes, bool)
        or range_bytes <= 0
        or range_bytes > min(size, MAXIMUM_RANGE_BYTES)
    ):
        raise RelayHealthError("probe range_bytes is outside the allowed range")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise RelayHealthError("probe slice_sha256 must be a lowercase SHA-256 digest")
    probe = {
        "backend": str(value.get("backend") or "fixed GitHub Release asset"),
        "range_bytes": range_bytes,
        "size": size,
        "slice_sha256": digest,
        "url": url,
    }
    if probe != PINNED_PROBE:
        raise RelayHealthError("probe must match the repository-reviewed pinned asset")
    return probe


def load_targets(path):
    """Read and validate one local relay-health target document."""

    try:
        if path.stat().st_size > MAXIMUM_TARGET_BYTES:
            raise RelayHealthError("relay-health target document exceeds the size limit")
    except OSError as error:
        raise RelayHealthError("cannot inspect %s: %s" % (path, error))
    document = _read_json(path)
    if not isinstance(document, dict):
        raise RelayHealthError("relay-health targets must be an object")
    allowed_patterns = document.get("allowed_patterns")
    if allowed_patterns != PATTERN_DESCRIPTIONS:
        raise RelayHealthError("allowed_patterns must match the supported relay URL forms")
    probe = _validate_probe(document.get("probe"))
    raw_targets = document.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets or len(raw_targets) > MAXIMUM_TARGETS:
        raise RelayHealthError("targets must be a non-empty bounded array")
    targets = []
    seen = set()
    for raw_target in raw_targets:
        if not isinstance(raw_target, dict):
            raise RelayHealthError("every target must be an object")
        hostname = _validate_hostname(raw_target.get("hostname"))
        identifier = raw_target.get("id")
        if identifier != hostname:
            raise RelayHealthError("target id must equal hostname: %s" % hostname)
        if identifier in seen:
            raise RelayHealthError("duplicate target id: %s" % identifier)
        seen.add(identifier)
        enabled = raw_target.get("enabled")
        if not isinstance(enabled, bool):
            raise RelayHealthError("target enabled must be a boolean: %s" % identifier)
        recommendation = raw_target.get("recommendation")
        if recommendation not in RECOMMENDATIONS:
            raise RelayHealthError("target recommendation is invalid: %s" % identifier)
        description = _validate_description(raw_target.get("description"), identifier)
        patterns = raw_target.get("patterns")
        if (
            not isinstance(patterns, list)
            or not patterns
            or len(patterns) != len(set(patterns))
            or any(pattern not in PATTERNS for pattern in patterns)
        ):
            raise RelayHealthError("target patterns are invalid: %s" % identifier)
        targets.append(
            {
                "description": description,
                "enabled": enabled,
                "hostname": hostname,
                "id": identifier,
                "note": str(raw_target.get("note") or ""),
                "patterns": list(patterns),
                "recommendation": recommendation,
            }
        )
    return document, probe, targets


def _render_url(hostname, pattern, official_url):
    try:
        profile = custom_relay("https://%s" % hostname, pattern)
        return render_relay_url(profile, official_url)
    except DownloadPolicyError as error:
        raise RelayHealthError(str(error))


def _failure(pattern, started, reason, transport="ok", http_code=0, response=None):
    final_host = ""
    redirects = 0
    if response is not None:
        final_host = urlparse(response.url).hostname or ""
        redirects = len(response.history)
    return {
        "checked_at_utc": _utc_now(),
        "chunk_count": 0,
        "content_range_ok": False,
        "downloaded_bytes": 0,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "failure_reason": reason,
        "final_host": final_host,
        "first_chunk_seconds": None,
        "http_code": http_code,
        "pattern": pattern,
        "redirect_count": redirects,
        "response_seconds": None,
        "slice_sha256_ok": False,
        "status": "fail",
        "stream_seconds": None,
        "stream_throughput_kib_per_second": None,
        "streamed_bytes": 0,
        "transport_class": transport,
    }


def _probe_url(session, url, pattern, probe, timeout):
    started = time.monotonic()
    headers = {
        "Range": "bytes=0-%d" % (probe["range_bytes"] - 1),
        "User-Agent": "JerryProxy-relay-health",
    }
    response = None
    try:
        response = session.get(url, headers=headers, stream=True, timeout=timeout)
        response_at = time.monotonic()
        if len(response.history) > MAXIMUM_REDIRECTS:
            return _failure(pattern, started, "redirect_limit", response=response)
        redirect_urls = [item.url for item in response.history] + [response.url]
        if any(urlparse(item).scheme != "https" for item in redirect_urls):
            return _failure(pattern, started, "https_downgrade", response=response)
        if response.status_code != 206:
            return _failure(
                pattern,
                started,
                "http_%d" % response.status_code,
                http_code=response.status_code,
                response=response,
            )
        expected_range = "bytes 0-%d/%d" % (probe["range_bytes"] - 1, probe["size"])
        content_range_ok = response.headers.get("Content-Range") == expected_range
        body = bytearray()
        chunk_count = 0
        first_chunk_at = None
        first_chunk_size = 0
        for block in response.iter_content(chunk_size=64 * 1024):
            if not block:
                continue
            remaining = probe["range_bytes"] + 1 - len(body)
            accepted = block[:remaining]
            received_at = time.monotonic()
            body.extend(accepted)
            chunk_count += 1
            if first_chunk_at is None:
                first_chunk_at = received_at
                first_chunk_size = len(accepted)
            if len(body) > probe["range_bytes"]:
                break
        downloaded_bytes = len(body)
        exact_length = downloaded_bytes == probe["range_bytes"]
        digest_ok = exact_length and hashlib.sha256(bytes(body)).hexdigest() == probe["slice_sha256"]
        completed_at = time.monotonic()
        elapsed_seconds = max(completed_at - started, 0.001)
        first_chunk_seconds = first_chunk_at - started if first_chunk_at is not None else None
        streamed_bytes = max(downloaded_bytes - first_chunk_size, 0)
        stream_seconds = (
            max(completed_at - first_chunk_at, 0.001)
            if first_chunk_at is not None and streamed_bytes
            else None
        )
        stream_throughput = (
            streamed_bytes / 1024.0 / stream_seconds if stream_seconds is not None else None
        )
        if not content_range_ok:
            reason = "content_range_mismatch"
        elif not exact_length:
            reason = "length_mismatch"
        elif not digest_ok:
            reason = "integrity_mismatch"
        else:
            reason = "ok"
        status = reason if reason in ("ok", "integrity_mismatch") else "fail"
        if status == "ok":
            status = "pass"
        return {
            "checked_at_utc": _utc_now(),
            "chunk_count": chunk_count,
            "content_range_ok": content_range_ok,
            "downloaded_bytes": downloaded_bytes,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "failure_reason": reason,
            "final_host": urlparse(response.url).hostname or "",
            "first_chunk_seconds": (
                round(first_chunk_seconds, 3) if first_chunk_seconds is not None else None
            ),
            "http_code": response.status_code,
            "pattern": pattern,
            "redirect_count": len(response.history),
            "response_seconds": round(response_at - started, 3),
            "slice_sha256_ok": digest_ok,
            "status": status,
            "stream_seconds": round(stream_seconds, 3) if stream_seconds is not None else None,
            "stream_throughput_kib_per_second": (
                round(stream_throughput, 1) if stream_throughput is not None else None
            ),
            "streamed_bytes": streamed_bytes,
            "transport_class": "ok",
        }
    except requests.exceptions.TooManyRedirects:
        return _failure(pattern, started, "redirect_limit", "TooManyRedirects")
    except requests.exceptions.ProxyError:
        return _failure(pattern, started, "proxy", "ProxyError")
    except requests.exceptions.SSLError:
        return _failure(pattern, started, "tls", "SSLError")
    except requests.exceptions.Timeout:
        return _failure(pattern, started, "timeout", "Timeout")
    except requests.exceptions.ConnectionError:
        return _failure(pattern, started, "connect", "ConnectionError")
    except requests.exceptions.RequestException:
        return _failure(pattern, started, "request", "RequestException")
    finally:
        if response is not None:
            response.close()


def _aggregate_samples(pattern, samples):
    successes = [sample for sample in samples if sample["status"] == "pass"]
    failure_counts = {}
    for sample in samples:
        if sample["status"] != "pass":
            reason = sample["failure_reason"]
            failure_counts[reason] = failure_counts.get(reason, 0) + 1
    if any(sample["status"] == "integrity_mismatch" for sample in samples):
        status = "integrity_mismatch"
    elif len(successes) == len(samples):
        status = "pass"
    elif successes:
        status = "degraded"
    else:
        status = "fail"
    first_chunk_values = [sample["first_chunk_seconds"] * 1000.0 for sample in successes]
    response_values = [sample["response_seconds"] * 1000.0 for sample in successes]
    throughput_values = [sample["stream_throughput_kib_per_second"] for sample in successes]
    return {
        "attempts": len(samples),
        "checked_at_utc": _utc_now(),
        "failure_reason": (
            "ok"
            if not failure_counts
            else ", ".join("%s=%d" % item for item in sorted(failure_counts.items()))
        ),
        "final_hosts": sorted(set(sample["final_host"] for sample in samples if sample["final_host"])),
        "max_redirect_count": max(sample["redirect_count"] for sample in samples),
        "median_first_chunk_ms": (
            round(median(first_chunk_values), 1) if first_chunk_values else None
        ),
        "median_response_ms": round(median(response_values), 1) if response_values else None,
        "median_stream_throughput_kib_per_second": (
            round(median(throughput_values), 1) if throughput_values else None
        ),
        "pattern": pattern,
        "samples": samples,
        "status": status,
        "success_rate_percent": round(len(successes) * 100.0 / len(samples), 1),
        "successes": len(successes),
    }


def _probe_repeated(session, url, pattern, probe, timeout, attempts):
    samples = [_probe_url(session, url, pattern, probe, timeout) for _ in range(attempts)]
    return _aggregate_samples(pattern, samples)


def probe_pattern(session, target, pattern, probe, timeout, attempts):
    """Run one short window of bounded relay Range samples."""

    url = _render_url(target["hostname"], pattern, probe["url"])
    return _probe_repeated(session, url, pattern, probe, timeout, attempts)


def _target_status(patterns, enabled):
    if not enabled:
        return "not_checked"
    if any(item["status"] == "integrity_mismatch" for item in patterns):
        return "integrity_mismatch"
    if all(item["status"] == "pass" for item in patterns):
        return "pass"
    if any(item["status"] in ("pass", "degraded") for item in patterns):
        return "degraded"
    return "fail"


def run(targets_path, output_path, timeout, vantage, attempts=DEFAULT_ATTEMPTS):
    """Probe every target/pattern over a short sample window and write a snapshot."""

    if (
        not isinstance(attempts, int)
        or isinstance(attempts, bool)
        or attempts <= 0
        or attempts > MAXIMUM_ATTEMPTS
    ):
        raise RelayHealthError("relay-health attempts are outside the allowed range")
    started_at = _utc_now()
    document, probe, targets = load_targets(targets_path)
    try:
        raw_document = targets_path.read_bytes()
    except OSError as error:
        raise RelayHealthError("cannot read %s: %s" % (targets_path, error))
    results = []
    pattern_checks = 0
    sample_checks = 0
    sample_passes = 0
    stable_pattern_passes = 0
    with requests.Session() as session:
        session.max_redirects = MAXIMUM_REDIRECTS
        direct_control = _probe_repeated(session, probe["url"], "direct", probe, timeout, attempts)
        for target in targets:
            patterns = []
            if target["enabled"]:
                for pattern in target["patterns"]:
                    observation = probe_pattern(session, target, pattern, probe, timeout, attempts)
                    patterns.append(observation)
                    pattern_checks += 1
                    sample_checks += observation["attempts"]
                    sample_passes += observation["successes"]
                    stable_pattern_passes += observation["status"] == "pass"
            results.append(
                {
                    "hostname": target["hostname"],
                    "id": target["id"],
                    "patterns": patterns,
                    "recommendation": target["recommendation"],
                    "status": _target_status(patterns, target["enabled"]),
                }
            )
    statuses = {}
    for result in results:
        statuses[result["status"]] = statuses.get(result["status"], 0) + 1
    output = {
        "completed_at_utc": _utc_now(),
        "direct_control": direct_control,
        "official_asset": probe,
        "results": results,
        "source_audit": document.get("source_audit"),
        "source_issue": document.get("source_issue"),
        "started_at_utc": started_at,
        "summary": {
            "endpoint_statuses": statuses,
            "endpoints": len(results),
            "pattern_checks": pattern_checks,
            "sample_checks": sample_checks,
            "sample_passes": sample_passes,
            "stable_pattern_passes": stable_pattern_passes,
        },
        "targets_sha256": hashlib.sha256(raw_document).hexdigest(),
        "vantage": vantage,
    }
    _write_json(output_path, output)
    return output


def _validate_aggregate(observation, expected_pattern):
    if not isinstance(observation, dict) or observation.get("pattern") != expected_pattern:
        raise RelayHealthError("relay-health results contain an invalid aggregate observation")
    samples = observation.get("samples")
    if not isinstance(samples, list) or not samples or len(samples) > MAXIMUM_ATTEMPTS:
        raise RelayHealthError("relay-health aggregate samples are invalid")
    for sample in samples:
        if not isinstance(sample, dict) or sample.get("pattern") != expected_pattern:
            raise RelayHealthError("relay-health results contain an invalid sample")
        if sample.get("status") not in ("pass", "fail", "integrity_mismatch"):
            raise RelayHealthError("relay-health results contain an invalid sample status")
        if not isinstance(sample.get("failure_reason"), str) or not isinstance(sample.get("final_host"), str):
            raise RelayHealthError("relay-health results contain invalid sample text")
        elapsed = sample.get("elapsed_seconds")
        chunk_count = sample.get("chunk_count")
        first_chunk = sample.get("first_chunk_seconds")
        redirects = sample.get("redirect_count")
        response_seconds = sample.get("response_seconds")
        stream_seconds = sample.get("stream_seconds")
        streamed_bytes = sample.get("streamed_bytes")
        throughput = sample.get("stream_throughput_kib_per_second")
        if (
            not isinstance(elapsed, (int, float))
            or isinstance(elapsed, bool)
            or elapsed < 0
            or not isinstance(chunk_count, int)
            or isinstance(chunk_count, bool)
            or chunk_count < 0
            or (
                first_chunk is not None
                and (
                    not isinstance(first_chunk, (int, float))
                    or isinstance(first_chunk, bool)
                    or first_chunk < 0
                )
            )
            or not isinstance(redirects, int)
            or isinstance(redirects, bool)
            or redirects < 0
            or (
                response_seconds is not None
                and (
                    not isinstance(response_seconds, (int, float))
                    or isinstance(response_seconds, bool)
                    or response_seconds < 0
                )
            )
            or not isinstance(streamed_bytes, int)
            or isinstance(streamed_bytes, bool)
            or streamed_bytes < 0
            or (
                stream_seconds is not None
                and (
                    not isinstance(stream_seconds, (int, float))
                    or isinstance(stream_seconds, bool)
                    or stream_seconds <= 0
                )
            )
            or (
                throughput is not None
                and (not isinstance(throughput, (int, float)) or isinstance(throughput, bool) or throughput < 0)
            )
        ):
            raise RelayHealthError("relay-health results contain invalid sample metrics")
        if sample["status"] == "pass" and (
            first_chunk is None
            or response_seconds is None
            or chunk_count < 2
            or stream_seconds is None
            or streamed_bytes <= 0
            or throughput is None
        ):
            raise RelayHealthError("relay-health passing sample has incomplete stream metrics")
    expected = _aggregate_samples(expected_pattern, samples)
    fields = (
        "attempts",
        "failure_reason",
        "final_hosts",
        "max_redirect_count",
        "median_first_chunk_ms",
        "median_response_ms",
        "median_stream_throughput_kib_per_second",
        "pattern",
        "samples",
        "status",
        "success_rate_percent",
        "successes",
    )
    if any(observation.get(field) != expected[field] for field in fields):
        raise RelayHealthError("relay-health aggregate does not match its samples")
    return expected


def gate_results(path):
    """Validate one published snapshot and reject integrity security events."""

    document = _read_json(path)
    if not isinstance(document, dict):
        raise RelayHealthError("relay-health results must be an object")
    direct_control = document.get("direct_control")
    results = document.get("results")
    summary = document.get("summary")
    if (
        not isinstance(direct_control, dict)
        or not isinstance(results, list)
        or not results
        or not isinstance(summary, dict)
        or document.get("official_asset") != PINNED_PROBE
    ):
        raise RelayHealthError("relay-health results are incomplete")
    direct_expected = _validate_aggregate(direct_control, "direct")
    target_statuses = {}
    pattern_checks = 0
    sample_checks = 0
    sample_passes = 0
    stable_pattern_passes = 0
    integrity_mismatch = direct_expected["status"] == "integrity_mismatch"
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("patterns"), list):
            raise RelayHealthError("relay-health results contain an invalid target")
        target_status = result.get("status")
        for observation in result["patterns"]:
            pattern = observation.get("pattern") if isinstance(observation, dict) else None
            if pattern not in PATTERNS:
                raise RelayHealthError("relay-health results contain an invalid pattern observation")
            expected = _validate_aggregate(observation, pattern)
            pattern_checks += 1
            sample_checks += expected["attempts"]
            sample_passes += expected["successes"]
            stable_pattern_passes += expected["status"] == "pass"
            integrity_mismatch = integrity_mismatch or expected["status"] == "integrity_mismatch"
        expected_target_status = _target_status(result["patterns"], bool(result["patterns"]))
        if target_status != expected_target_status:
            raise RelayHealthError("relay-health results contain an invalid target status")
        target_statuses[target_status] = target_statuses.get(target_status, 0) + 1
        integrity_mismatch = integrity_mismatch or target_status == "integrity_mismatch"
    if integrity_mismatch:
        raise RelayHealthError("relay-health integrity mismatch detected")
    if (
        summary.get("endpoints") != len(results)
        or summary.get("pattern_checks") != pattern_checks
        or summary.get("sample_checks") != sample_checks
        or summary.get("sample_passes") != sample_passes
        or summary.get("stable_pattern_passes") != stable_pattern_passes
        or summary.get("endpoint_statuses") != target_statuses
    ):
        raise RelayHealthError("relay-health result summary does not match its observations")
    return summary


def main(argv=None):
    """CLI entry point for local relay-health probing."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=Path("relay_health_targets.json"))
    parser.add_argument("--output", type=Path, default=Path("relay_health_latest.json"))
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--vantage", default="local")
    parser.add_argument("--gate-results", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.gate_results is not None:
        try:
            summary = gate_results(arguments.gate_results)
        except RelayHealthError as error:
            parser.error(str(error))
        print(json.dumps(summary, sort_keys=True))
        return 0
    if arguments.timeout <= 0 or arguments.timeout > 120:
        parser.error("--timeout must be greater than zero and at most 120 seconds")
    if arguments.attempts <= 0 or arguments.attempts > MAXIMUM_ATTEMPTS:
        parser.error("--attempts must be between 1 and %d" % MAXIMUM_ATTEMPTS)
    try:
        result = run(
            arguments.targets,
            arguments.output,
            arguments.timeout,
            arguments.vantage,
            arguments.attempts,
        )
    except RelayHealthError as error:
        parser.error(str(error))
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
