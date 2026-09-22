"""Require complete statement/branch coverage of functions touched by a diff."""

import argparse
import ast
import json
import re
import subprocess
from pathlib import Path


def changed_lines(patch):
    """Read destination line numbers from a zero-context Git diff."""
    result = {}
    path = None
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            result[path] = set()
        elif line.startswith("@@") and path is not None:
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start = int(match.group(1))
            count = int(match.group(2) or 1)
            result[path].update(range(start, start + max(1, count)))
    return result


def audit(report, changes, root=Path(".")):
    """Return checked function count and uncovered function diagnostics."""
    if report.get("meta", {}).get("branch_coverage") is not True:
        raise ValueError("branch-enabled coverage JSON is required")
    files = {path.replace("\\", "/"): value for path, value in report["files"].items()}
    checked = 0
    failures = []
    for path, lines in sorted(changes.items()):
        if not path.endswith(".py"):
            continue
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            end = max(getattr(child, "end_lineno", None) or getattr(child, "lineno", 0)
                      for child in ast.walk(node))
            if not any(node.lineno <= line <= end for line in lines):
                continue
            checked += 1
            label = "%s:%d %s" % (path, node.lineno, node.name)
            if path not in files:
                failures.append(label + ": coverage is missing")
                continue
            record = files[path]
            missing = [line for line in record["missing_lines"] if node.lineno <= line <= end]
            branches = [arc for arc in record["missing_branches"] if node.lineno <= arc[0] <= end]
            if missing or branches:
                failures.append("%s: lines=%s branches=%s" % (label, missing, branches))
    return checked, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()
    patch = subprocess.check_output(
        ["git", "diff", "--unified=0", args.base, "--", "jerryproxy"], universal_newlines=True,
    )
    checked, failures = audit(json.loads(args.report.read_text(encoding="utf-8")), changed_lines(patch))
    for failure in failures:
        print(failure)
    print("%d modified functions checked; %d incomplete" % (checked, len(failures)))
    return 1 if failures or not checked else 0


if __name__ == "__main__":
    raise SystemExit(main())
