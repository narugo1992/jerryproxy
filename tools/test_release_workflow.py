"""A tag publishes prepared release notes only after asset upload succeeds."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize(
    "state,upload_failure,expected",
    [
        ("true", False, "edit"),
        ("true", True, "failure"),
        ("false", False, "failure"),
        ("", False, "create"),
        ("query-failure", False, "failure"),
    ],
)
def test_prepared_release_publication(tmp_path, state, upload_failure, expected):
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text())
    script = workflow["jobs"]["release"]["steps"][-1]["run"]
    env = dict(
        os.environ,
        TAG="v0.2.0",
        GITHUB_REPOSITORY="example/repo",
        STATE=state,
        UPLOAD_FAILURE=str(int(upload_failure)),
        CALLS=str(tmp_path / "calls"),
    )
    mock = """
    git() { return 0; }
    gh() {
      echo "$*" >> "$CALLS"
      if [ "$2" = list ]; then
        [ "$STATE" != query-failure ] || return 1
        if [ -z "$STATE" ]; then echo '[]'; else
          printf '[{"tagName":"v0.2.0","isDraft":%s}]' "$STATE"
        fi
      elif [ "$2" = upload ]; then
        return "$UPLOAD_FAILURE"
      fi
    }
    """
    result = subprocess.run(["bash", "-c", mock + script], env=env, capture_output=True)
    calls = (tmp_path / "calls").read_text()
    if expected == "failure":
        assert result.returncode != 0
        assert "release edit" not in calls
        assert "release create" not in calls
    elif expected == "edit":
        assert result.returncode == 0, result.stderr
        assert calls.index("release upload") < calls.index("release edit")
        assert "release create" not in calls
        assert "--notes" not in calls
    else:
        assert result.returncode == 0, result.stderr
        assert "release create" in calls
        assert "--verify-tag" in calls
