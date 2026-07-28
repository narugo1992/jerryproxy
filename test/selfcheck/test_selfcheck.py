from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import run_checks, run_self_check


def test_self_check_validates_an_empty_private_home(tmp_path):
    lines = []

    exit_code = run_self_check(JerryProxyPaths(tmp_path), output=lines.append)

    assert exit_code == 0
    assert "Summary: 7 OK, 0 FAIL" in lines
    assert lines[-1] == "Self-check PASSED"
    assert not list(tmp_path.glob(".self-check-*"))
    for name in ("active", "backends", "bin", "downloads", "locks", "logs", "providers", "runtimes"):
        assert (tmp_path / name).is_dir()


def test_check_runner_continues_and_reports_actionable_failures():
    visited = []
    lines = []

    def first():
        visited.append("first")
        return "ready"

    def broken():
        visited.append("broken")
        raise OSError("read-only state directory")

    def final():
        visited.append("final")
        return "still ran"

    exit_code = run_checks(
        (("first", first), ("writable state", broken), ("final", final)),
        output=lines.append,
    )

    assert exit_code == 1
    assert visited == ["first", "broken", "final"]
    assert "[2/3] writable state: FAIL - OSError: read-only state directory" in lines
    assert "Summary: 2 OK, 1 FAIL" in lines
    assert lines[-1] == "Self-check FAILED"
