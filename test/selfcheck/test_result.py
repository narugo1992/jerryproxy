

from jerryproxy.selfcheck import ansi_color_enabled
from jerryproxy.selfcheck import result as selfcheck_module


def test_error_result_redacts_exception_message_and_traceback():
    secret = "https://alice:secret@example.com/provider?token=query-secret#fragment-secret"

    try:
        raise RuntimeError("request failed for %s password=hunter2" % secret)
    except RuntimeError as error:
        result = selfcheck_module._error_result(error)

    rendered = "%s\n%s" % (result.detail, "\n".join(result.diagnostics))
    assert result.level == "ERR"
    assert "[REDACTED" in rendered
    assert "alice" not in rendered
    assert "query-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "hunter2" not in rendered


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
