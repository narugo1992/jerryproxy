"""Execute catalog PR discovery and publication scripts without GitHub writes.

An open, specifically identified catalog review gets a comment and blocks a
new refresh. Ordinary PRs must not match a title or marker in isolation.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = yaml.safe_load(
    (Path(__file__).resolve().parents[1] / ".github/workflows/catalog.yml").read_text(encoding="utf-8")
)
TITLE = "chore(catalog): refresh backend release catalogs"
MARKER = "<!-- jerryproxy:backend-catalog-refresh -->"


def _pr(number=72, title=TITLE, body=MARKER, branch="automation/backend-catalog-123", author="app/github-actions"):
    return dict(number=number, title=title, body=body, headRefName=branch, author=dict(login=author))


def _run(script, tmp_path, records=(), fail=False):
    if not shutil.which("bash") or not shutil.which("jq"):
        pytest.skip("workflow scripts require Bash and jq")
    env = dict(os.environ, GITHUB_OUTPUT=str(tmp_path / "output"), RECORDS=json.dumps(records))
    env.update(RUNNER_TEMP=str(tmp_path), PR_NUMBER="72", RUN_URL="https://example.test/run/1", BRANCH="test-branch")
    mock = 'gh() { printf "%s" "$RECORDS"; }; export -f gh\n'
    if fail:
        mock = "gh() { return 1; }; export -f gh\n"
    return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", mock + script], env=env, capture_output=True)


@pytest.mark.parametrize(
    "records,expected",
    [
        ([], ""),
        ([_pr()], "72"),
        ([_pr(title="Unrelated change")], ""),
        ([_pr(body="Ordinary prose about catalog updates")], ""),
        ([_pr(title="chore: refresh backend catalogs", body="legacy")], "72"),
        ([_pr(title="chore: refresh backend catalogs", body="legacy", author="someone")], ""),
        ([_pr(title="chore: refresh backend catalogs", body="legacy", branch="feature")], ""),
        ([_pr(number=66), _pr(number=72), _pr(number=67)], "72"),
    ],
)
def test_catalog_discovery(tmp_path, records, expected):
    pending = WORKFLOW["jobs"]["pending"]
    result = _run(pending["steps"][0]["run"], tmp_path, records)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "output").read_text() == "number=%s\n" % expected
    assert pending["steps"][1]["if"] == "steps.find.outputs.number != ''"
    assert WORKFLOW["jobs"]["update"]["needs"] == "pending"
    assert WORKFLOW["jobs"]["update"]["if"] == "needs.pending.outputs.number == ''"


def test_discovery_failure_cannot_allow_creation(tmp_path):
    result = _run(WORKFLOW["jobs"]["pending"]["steps"][0]["run"], tmp_path, fail=True)
    assert result.returncode != 0
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "job,step_name,expected_command,filename",
    [
        ("pending", "Remind the existing review", "pr comment 72", "catalog-comment.md"),
        ("update", "Open maintainer-review pull request", "pr create", "catalog-pr.md"),
    ],
)
def test_publication_uses_file_body(tmp_path, job, step_name, expected_command, filename):
    step = next(item for item in WORKFLOW["jobs"][job]["steps"] if item.get("name") == step_name)
    script = 'gh() { printf "%s\\n" "$*"; }; export -f gh\n' + step["run"]
    result = _run(script, tmp_path)
    assert result.returncode == 0, result.stderr
    command = result.stdout.decode()
    assert expected_command in command
    assert "--body-file " + str(tmp_path / filename) in command
    body = (tmp_path / filename).read_text()
    if job == "update":
        assert "--title " + TITLE in command
        assert MARKER in body.splitlines()
    else:
        assert "https://example.test/run/1" in body
        assert "branch was not updated" in body
