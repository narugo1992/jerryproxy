from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import ansi_color_enabled, run_checks, run_self_check


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


def test_check_runner_uses_ansi_status_colors_when_enabled():
    lines = []

    exit_code = run_checks(
        (("ready", lambda: "available"),),
        output=lines.append,
        color=True,
    )

    assert exit_code == 0
    assert "\033[1;36m[1/1] ready\033[0m" in lines[0]
    assert "\033[1;32mOK\033[0m" in lines[0]
    assert lines[-1] == "\033[1;32mSelf-check PASSED\033[0m"


def test_color_detection_honors_environment_and_explicit_override(monkeypatch):
    class Terminal(object):
        def isatty(self):
            return True

    terminal = Terminal()
    monkeypatch.setenv("NO_COLOR", "1")
    assert ansi_color_enabled(terminal) is False
    assert ansi_color_enabled(terminal, requested=True) is True

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ansi_color_enabled(object()) is True


def test_color_detection_falls_back_when_stream_has_no_usable_tty(monkeypatch):
    class BrokenTerminal(object):
        def isatty(self):
            raise OSError("terminal unavailable")

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert ansi_color_enabled(object()) is False
    assert ansi_color_enabled(BrokenTerminal()) is False


def test_self_check_reports_corrupt_active_inventory_without_stopping_other_checks(tmp_path):
    paths = JerryProxyPaths(tmp_path)
    paths.ensure()
    (paths.active / "mihomo.json").write_text("{not-json", encoding="ascii")
    lines = []

    exit_code = run_self_check(paths, output=lines.append)

    assert exit_code == 1
    assert any("backend inventory: FAIL" in line for line in lines)
    assert lines[-1] == "Self-check FAILED"
