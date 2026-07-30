"""Render local relay-health JSON files as one GitHub Wiki Markdown page."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from tabulate import tabulate

STATUS = {
    "pass": ("🟢", "Pass"),
    "degraded": ("🟡", "Degraded"),
    "fail": ("🔴", "Fail"),
    "integrity_mismatch": ("🛑", "Integrity mismatch"),
    "not_checked": ("⚪", "Not checked"),
}
PROFILE_LABELS = {
    "manual_named_candidate": "Named candidate",
    "manual_transport_only": "Transport only",
    "manual_transport_verified": "Transport verified",
    "named_profile_candidate": "Built-in candidate",
}
PATTERN_LABELS = {
    "full_url_path": ("🧭", "Full URL path", "https://relay/https://github.com/owner/repo/..."),
    "host_path": ("🔗", "GitHub host + path", "https://relay/github.com/owner/repo/..."),
    "query_q": ("🔎", "Encoded q query", "https://relay/?q=https%3A%2F%2Fgithub.com%2F..."),
}


class RelayHealthRenderError(RuntimeError):
    """Raised when a local health snapshot cannot be rendered."""


def _read_json(path):
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except OSError as error:
        raise RelayHealthRenderError("cannot read %s: %s" % (path, error))
    except ValueError as error:
        raise RelayHealthRenderError("invalid JSON in %s: %s" % (path, error))


def _status(value):
    symbol, label = STATUS.get(value, ("⚪", "Unknown"))
    return "%s %s" % (symbol, label)


def _profile_label(value):
    try:
        return PROFILE_LABELS[value]
    except (KeyError, TypeError):
        raise RelayHealthRenderError("target recommendation is invalid")


def _pattern(value):
    try:
        symbol, label, _ = PATTERN_LABELS[value]
    except (KeyError, TypeError):
        raise RelayHealthRenderError("pattern is invalid")
    return "%s %s" % (symbol, label)


def _description(value):
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
        or any(character in value for character in "|<>`[]")
    ):
        raise RelayHealthRenderError("target description is invalid")
    return value


def _measurement(value, suffix):
    if value is None:
        return "-"
    try:
        return "%.1f %s" % (float(value), suffix)
    except (TypeError, ValueError):
        raise RelayHealthRenderError("measurement is invalid")


def _stability(observation):
    try:
        attempts = int(observation["attempts"])
        successes = int(observation["successes"])
        rate = float(observation["success_rate_percent"])
    except (KeyError, TypeError, ValueError):
        raise RelayHealthRenderError("stability measurement is invalid")
    if attempts <= 0 or successes < 0 or successes > attempts:
        raise RelayHealthRenderError("stability measurement is invalid")
    return "%d/%d (%.1f%%)" % (successes, attempts, rate)


def _final_hosts(value):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RelayHealthRenderError("final hosts are invalid")
    return ", ".join(value) or "-"


def _freshness(completed_at):
    try:
        checked = datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "unknown"
    age = (datetime.now(timezone.utc) - checked).total_seconds()
    if age < 0:
        return "clock skew"
    if age <= 8 * 60 * 60:
        return "fresh"
    return "stale"


def render(targets_path, results_path):
    """Return a Markdown projection of one local target and result pair."""

    targets = _read_json(targets_path)
    results = _read_json(results_path)
    raw_targets = targets.get("targets") if isinstance(targets, dict) else None
    raw_results = results.get("results") if isinstance(results, dict) else None
    if not isinstance(raw_targets, list) or not isinstance(raw_results, list):
        raise RelayHealthRenderError("targets and results must contain arrays")
    direct_control = results.get("direct_control")
    if not isinstance(direct_control, dict) or direct_control.get("status") not in STATUS:
        raise RelayHealthRenderError("results must contain a valid direct control observation")
    try:
        targets_sha256 = hashlib.sha256(targets_path.read_bytes()).hexdigest()
    except OSError as error:
        raise RelayHealthRenderError("cannot read %s: %s" % (targets_path, error))
    if results.get("targets_sha256") != targets_sha256:
        raise RelayHealthRenderError("results do not match the local target document")
    target_ids = [item.get("id") for item in raw_targets]
    result_ids = [item.get("id") for item in raw_results]
    if target_ids != result_ids:
        raise RelayHealthRenderError("result targets do not match the configured target order")
    target_map = {item["id"]: item for item in raw_targets}
    directory_rows = []
    measurement_rows = []
    for result in raw_results:
        target = target_map[result["id"]]
        relay_link = "[%s](https://%s)" % (result["hostname"], result["hostname"])
        directory_rows.append(
            [
                relay_link,
                _profile_label(target.get("recommendation")),
                _status(result.get("status")),
                _description(target.get("description")),
            ]
        )
        patterns = result.get("patterns")
        if not isinstance(patterns, list):
            raise RelayHealthRenderError("result patterns are invalid")
        for observation in patterns:
            if not isinstance(observation, dict):
                raise RelayHealthRenderError("pattern observation is invalid")
            measurement_rows.append(
                [
                    relay_link,
                    _pattern(observation.get("pattern")),
                    _status(observation.get("status")),
                    _stability(observation),
                    _measurement(observation.get("median_response_ms"), "ms"),
                    _measurement(observation.get("median_first_chunk_ms"), "ms"),
                    _measurement(
                        observation.get("median_stream_throughput_kib_per_second"),
                        "KiB/s",
                    ),
                    observation.get("failure_reason", "unknown"),
                    _final_hosts(observation.get("final_hosts")),
                ]
            )
    summary = results.get("summary", {})
    completed_at = results.get("completed_at_utc", "unknown")
    vantage = str(results.get("vantage", "unknown"))
    if vantage.startswith("GitHub-hosted"):
        scope_warning = "GitHub-hosted runner observation; not a mainland-China reachability measurement."
    else:
        scope_warning = "Local observation (%s); not a nationwide or multi-carrier measurement." % vantage
    status_legend = [[symbol, label, key] for key, (symbol, label) in STATUS.items()]
    pattern_legend = [
        [symbol, label, key, example]
        for key, (symbol, label, example) in PATTERN_LABELS.items()
    ]
    summary_rows = [
        ["Checked at", completed_at],
        ["Freshness", _freshness(completed_at)],
        ["Vantage", vantage],
        ["Direct GitHub control", _status(direct_control.get("status"))],
        ["Direct control stability", _stability(direct_control)],
        [
            "Direct control median response",
            _measurement(direct_control.get("median_response_ms"), "ms"),
        ],
        [
            "Direct control median first chunk",
            _measurement(direct_control.get("median_first_chunk_ms"), "ms"),
        ],
        [
            "Direct control median stream speed",
            _measurement(
                direct_control.get("median_stream_throughput_kib_per_second"),
                "KiB/s",
            ),
        ],
        ["Direct control reason", direct_control.get("failure_reason", "unknown")],
        ["Relays", summary.get("endpoints", 0)],
        [
            "Stable patterns",
            "%s / %s"
            % (summary.get("stable_pattern_passes", 0), summary.get("pattern_checks", 0)),
        ],
        [
            "Successful relay samples",
            "%s / %s" % (summary.get("sample_passes", 0), summary.get("sample_checks", 0)),
        ],
    ]
    return "\n".join(
        [
            "# Relay Health",
            "",
            "> **%s**" % scope_warning,
            "",
            "Public relay availability is best-effort and can change at any time. JerryProxy still verifies",
            "backend archive size and official SHA-256 before installation.",
            "Stability is the success count in this run's short sample window. Response latency covers",
            "request start through response headers; first-chunk latency continues through the first",
            "non-empty streamed chunk. Stream speed uses only",
            "the remaining bytes through the end of a successful 1 MiB sample, excluding startup delay.",
            "It is not a sustained-bandwidth measurement.",
            "",
            tabulate(summary_rows, headers=["Property", "Value"], tablefmt="github"),
            "",
            "## Status legend",
            "",
            tabulate(
                status_legend,
                headers=["Symbol", "Meaning", "Machine status"],
                tablefmt="github",
            ),
            "",
            "## Pattern legend",
            "",
            tabulate(
                pattern_legend,
                headers=["Symbol", "Meaning", "Machine pattern", "Example"],
                tablefmt="github",
                disable_numparse=True,
            ),
            "",
            "## Relay directory",
            "",
            tabulate(
                directory_rows,
                headers=["Relay", "Profile", "Current status", "Description"],
                tablefmt="github",
                disable_numparse=True,
            ),
            "",
            "## Pattern measurements",
            "",
            tabulate(
                measurement_rows,
                headers=[
                    "Relay",
                    "Pattern",
                    "Status",
                    "Stability",
                    "Median response",
                    "Median first chunk",
                    "Median stream speed",
                    "Reason",
                    "Final hosts",
                ],
                tablefmt="github",
                disable_numparse=True,
            ),
            "",
            "Source configuration: [relay-health Gist](https://gist.github.com/narugo1992/78fb0ee6135fcdf4f0e5c7ec38f2fd59).",
            "",
        ]
    )


def main(argv=None):
    """CLI entry point for local Wiki Markdown generation."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=Path("relay_health_targets.json"))
    parser.add_argument("--results", type=Path, default=Path("relay_health_latest.json"))
    parser.add_argument("--output", type=Path, default=Path("Relay-Health.md"))
    arguments = parser.parse_args(argv)
    try:
        markdown = render(arguments.targets, arguments.results)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(markdown, encoding="utf-8")
    except (OSError, RelayHealthRenderError) as error:
        parser.error(str(error))
    print("Rendered %s" % arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
