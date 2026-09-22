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
