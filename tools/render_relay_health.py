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
    rows = []
    for result in raw_results:
        target = target_map[result["id"]]
        if not result.get("patterns"):
            rows.append(
                [
                    "[%s](https://%s)" % (result["hostname"], result["hostname"]),
                    target.get("recommendation", "unclassified"),
                    "-",
                    _status(result.get("status")),
                    "not_checked",
                    "-",
                    "-",
                ]
            )
            continue
        for observation in result["patterns"]:
            rows.append(
                [
                    "[%s](https://%s)" % (result["hostname"], result["hostname"]),
                    target.get("recommendation", "unclassified"),
                    observation.get("pattern", "unknown"),
                    _status(observation.get("status")),
                    observation.get("failure_reason", "unknown"),
                    observation.get("final_host") or "-",
                    "%.3f s" % float(observation.get("elapsed_seconds", 0)),
                ]
            )
    summary = results.get("summary", {})
    completed_at = results.get("completed_at_utc", "unknown")
    vantage = str(results.get("vantage", "unknown"))
    if vantage.startswith("GitHub-hosted"):
        scope_warning = "GitHub-hosted runner observation; not a mainland-China reachability measurement."
    else:
        scope_warning = "Local observation (%s); not a nationwide or multi-carrier measurement." % vantage
    legend = [[symbol, label, key] for key, (symbol, label) in STATUS.items()]
    summary_rows = [
        ["Checked at", completed_at],
        ["Freshness", _freshness(completed_at)],
        ["Vantage", vantage],
        ["Relays", summary.get("endpoints", 0)],
        ["Passing patterns", "%s / %s" % (summary.get("exact_pattern_passes", 0), summary.get("pattern_checks", 0))],
    ]
    return "\n".join(
        [
            "# Relay Health",
            "",
            "> **%s**" % scope_warning,
            "",
            "Public relay availability is best-effort and can change at any time. JerryProxy still verifies",
            "backend archive size and official SHA-256 before installation.",
            "",
            tabulate(summary_rows, headers=["Property", "Value"], tablefmt="github"),
            "",
            "## Legend",
            "",
            tabulate(legend, headers=["Symbol", "Meaning", "Machine status"], tablefmt="github"),
            "",
            "## Results",
            "",
            tabulate(
                rows,
                headers=["Relay", "Profile", "Pattern", "Status", "Reason", "Final host", "Time"],
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
