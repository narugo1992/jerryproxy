"""The affected-function gate cannot accept partial or missing evidence."""

import pytest

from tools.changed_coverage import audit, changed_lines


@pytest.mark.parametrize("fault", ["none", "branch", "line", "file", "disabled"])
def test_audit_requires_the_entire_changed_function(tmp_path, fault):
    (tmp_path / "sample.py").write_text("def choose(value):\n    if value:\n        return 1\n    return 0\n")
    patch = "+++ b/sample.py\n@@ -1,0 +3 @@\n+        return 1\n"
    record = {"missing_lines": [4] if fault == "line" else [],
              "missing_branches": [[2, 4]] if fault == "branch" else []}
    report = {"meta": {"branch_coverage": fault != "disabled"},
              "files": {} if fault == "file" else {"sample.py": record}}
    if fault == "disabled":
        with pytest.raises(ValueError, match="branch-enabled"):
            audit(report, changed_lines(patch), tmp_path)
    else:
        count, failures = audit(report, changed_lines(patch), tmp_path)
        assert count == 1
        assert bool(failures) == (fault != "none")


def test_deleted_lines_still_audit_the_surviving_function(tmp_path):
    (tmp_path / "sample.py").write_text("def choose(value):\n    return value\n")
    changes = changed_lines("+++ b/sample.py\n@@ -2 +1,0 @@\n-    obsolete()\n")
    report = {"meta": {"branch_coverage": True},
              "files": {"sample.py": {"missing_lines": [2], "missing_branches": []}}}
    count, failures = audit(report, changes, tmp_path)
    assert count == 1 and len(failures) == 1


def test_audit_skips_non_python_and_untouched_functions(tmp_path):
    (tmp_path / "sample.py").write_text("def untouched():\n    return 1\n\nvalue = 2\n")
    report = {"meta": {"branch_coverage": True}, "files": {}}
    patch = "--- a/sample.py\n+++ b/sample.py\n@@ -4 +4 @@\n+value = 2\n"
    assert audit(report, dict(changed_lines(patch), **{"README.md": {1}}), tmp_path) == (0, [])


@pytest.mark.parametrize("missing,empty", [(False, False), (True, False), (False, True)])
def test_command_exit_status_reports_incomplete_or_absent_functions(tmp_path, monkeypatch, capsys, missing, empty):
    import json
    import runpy
    import sys

    import tools.changed_coverage as module

    (tmp_path / "sample.py").write_text("def choose():\n    return 1\n")
    report = {"meta": {"branch_coverage": True},
              "files": {"sample.py": {"missing_lines": [2] if missing else [], "missing_branches": []}}}
    report_path = tmp_path / "coverage.json"
    report_path.write_text(json.dumps(report))
    patch = "" if empty else "+++ b/sample.py\n@@ -2 +2 @@\n+    return 1\n"
    monkeypatch.setattr(module.subprocess, "check_output", lambda *args, **kwargs: patch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["changed_coverage", str(report_path), "--base", "review-base"])
    monkeypatch.delitem(sys.modules, "tools.changed_coverage")
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("tools.changed_coverage", run_name="__main__")
    assert caught.value.code == int(missing or empty)
    assert "modified functions checked" in capsys.readouterr().out
