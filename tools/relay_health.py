"""Probe configured GitHub Release relays from one local JSON file."""

import argparse
import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

PATTERNS = ("full_url_path", "host_path", "query_q")
MAXIMUM_TARGETS = 500
MAXIMUM_RANGE_BYTES = 1024 * 1024
MAXIMUM_TARGET_BYTES = 1024 * 1024
MAXIMUM_REDIRECTS = 5
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
    return {
        "backend": str(value.get("backend") or "fixed GitHub Release asset"),
        "range_bytes": range_bytes,
        "size": size,
        "slice_sha256": digest,
        "url": url,
    }


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
    if not isinstance(allowed_patterns, dict) or set(allowed_patterns) != set(PATTERNS):
        raise RelayHealthError("allowed_patterns must declare the three supported pattern names")
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
                "enabled": enabled,
                "hostname": hostname,
                "id": identifier,
                "note": str(raw_target.get("note") or ""),
                "patterns": list(patterns),
                "recommendation": str(raw_target.get("recommendation") or "unclassified"),
            }
        )
    return document, probe, targets


def _render_url(hostname, pattern, official_url):
    parsed = urlparse(official_url)
    if pattern == "full_url_path":
        return "https://%s/%s" % (hostname, official_url)
    if pattern == "host_path":
        return "https://%s/%s%s" % (hostname, parsed.hostname, parsed.path)
    if pattern == "query_q":
        return "https://%s/?q=%s" % (hostname, quote(official_url, safe=""))
    raise RelayHealthError("unsupported relay pattern: %s" % pattern)


def _failure(pattern, started, reason, transport="ok", http_code=0, response=None):
    final_host = ""
    redirects = 0
    if response is not None:
        final_host = urlparse(response.url).hostname or ""
        redirects = len(response.history)
    return {
        "checked_at_utc": _utc_now(),
        "content_range_ok": False,
        "downloaded_bytes": 0,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "failure_reason": reason,
        "final_host": final_host,
        "http_code": http_code,
        "pattern": pattern,
        "redirect_count": redirects,
        "slice_sha256_ok": False,
        "status": "fail",
        "transport_class": transport,
    }


def probe_pattern(session, target, pattern, probe, timeout):
    """Run one bounded Range request and return a sanitized observation."""

    started = time.monotonic()
    url = _render_url(target["hostname"], pattern, probe["url"])
    headers = {
        "Range": "bytes=0-%d" % (probe["range_bytes"] - 1),
        "User-Agent": "JerryProxy-relay-health",
    }
    response = None
    try:
        response = session.get(url, headers=headers, stream=True, timeout=timeout)
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
        for block in response.iter_content(chunk_size=64 * 1024):
            if not block:
                continue
            remaining = probe["range_bytes"] + 1 - len(body)
            body.extend(block[:remaining])
            if len(body) > probe["range_bytes"]:
                break
        downloaded_bytes = len(body)
        exact_length = downloaded_bytes == probe["range_bytes"]
        digest_ok = exact_length and hashlib.sha256(bytes(body)).hexdigest() == probe["slice_sha256"]
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
            "content_range_ok": content_range_ok,
            "downloaded_bytes": downloaded_bytes,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "failure_reason": reason,
            "final_host": urlparse(response.url).hostname or "",
            "http_code": response.status_code,
            "pattern": pattern,
            "redirect_count": len(response.history),
            "slice_sha256_ok": digest_ok,
            "status": status,
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


def _target_status(patterns, enabled):
    if not enabled:
        return "not_checked"
    if any(item["status"] == "integrity_mismatch" for item in patterns):
        return "integrity_mismatch"
    passed = sum(item["status"] == "pass" for item in patterns)
    if passed == len(patterns):
        return "pass"
    if passed:
        return "degraded"
    return "fail"


def run(targets_path, output_path, timeout, vantage):
    """Probe every enabled target/pattern pair and write one latest snapshot."""

    started_at = _utc_now()
    document, probe, targets = load_targets(targets_path)
    try:
        raw_document = targets_path.read_bytes()
    except OSError as error:
        raise RelayHealthError("cannot read %s: %s" % (targets_path, error))
    results = []
    pattern_checks = 0
    pattern_passes = 0
    with requests.Session() as session:
        session.max_redirects = MAXIMUM_REDIRECTS
        for target in targets:
            patterns = []
            if target["enabled"]:
                for pattern in target["patterns"]:
                    observation = probe_pattern(session, target, pattern, probe, timeout)
                    patterns.append(observation)
                    pattern_checks += 1
                    pattern_passes += observation["status"] == "pass"
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
        "official_asset": probe,
        "results": results,
        "source_audit": document.get("source_audit"),
        "source_issue": document.get("source_issue"),
        "started_at_utc": started_at,
        "summary": {
            "endpoint_statuses": statuses,
            "endpoints": len(results),
            "exact_pattern_passes": pattern_passes,
            "pattern_checks": pattern_checks,
        },
        "targets_sha256": hashlib.sha256(raw_document).hexdigest(),
        "vantage": vantage,
    }
    _write_json(output_path, output)
    return output


def main(argv=None):
    """CLI entry point for local relay-health probing."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=Path("relay_health_targets.json"))
    parser.add_argument("--output", type=Path, default=Path("relay_health_latest.json"))
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--vantage", default="local")
    arguments = parser.parse_args(argv)
    if arguments.timeout <= 0 or arguments.timeout > 120:
        parser.error("--timeout must be greater than zero and at most 120 seconds")
    try:
        result = run(arguments.targets, arguments.output, arguments.timeout, arguments.vantage)
    except RelayHealthError as error:
        parser.error(str(error))
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
