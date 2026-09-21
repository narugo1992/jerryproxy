"""Foreground termination must unwind recovery and retain cleanup ownership."""

import os
import signal
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(os.name != "posix", reason="POSIX signal delivery to a child process")
@pytest.mark.parametrize("phase", ["startup", "running"])
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_real_signal_cancels_recovery_and_removes_private_lease(tmp_path, phase, signum):
    script = r'''
import sys
import time
from pathlib import Path
import jerryproxy.cli.server as server_module
from jerryproxy.cli import cli
from jerryproxy.runtime import HealthSnapshot, RecoveryPolicy
from test.runtime.test_session import _record, _session

root = Path(sys.argv[1])
phase = sys.argv[2]
record = _record(nodes=1)
class Probe:
    calls = 0
    def check(self, *args):
        self.calls += 1
        return HealthSnapshot((), int(phase == "running" and self.calls == 1), 1, 0)
def sleep(delay):
    if delay >= 1:
        (root / "waiting").write_text("ready")
        time.sleep(30)
    else:
        time.sleep(delay)
session = _session(root, record, Probe(), authenticate=True, sleeper=sleep,
                   policy=RecoveryPolicy(retry_policy="fixed", health_interval=0.01, confirmation_delay=0.01))
def factory(paths, **options):
    session.log_sink = options["log_sink"]
    session.event_sink = options["event_sink"]
    return session
server_module.RuntimeSession = factory
cli.main(args=["--home", str(root / ".jerryproxy"), "server", "--subscription", "main",
               "--node", record.nodes[0].node_id, "--no-install-missing", "--log-format", "jsonl"])
'''
    process = subprocess.Popen([sys.executable, "-c", script, str(tmp_path), phase],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / "waiting").exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert (tmp_path / "waiting").exists(), "server did not enter recovery backoff"
        process.send_signal(signum)
        output, errors = process.communicate(timeout=5)
        assert process.returncode == 128 + signum, errors.decode("utf-8", "replace")
        assert b'"event":"session.stopped"' in output
        assert not list((tmp_path / ".jerryproxy").rglob("access.json"))
        assert not list((tmp_path / ".jerryproxy").rglob("config.yaml"))
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_repeated_signal_cannot_interrupt_cleanup_and_prior_handlers_are_restored(tmp_path, monkeypatch, cleanup_fails):
    from click.testing import CliRunner

    import jerryproxy.cli.server as server_module
    from jerryproxy.cli import cli
    from jerryproxy.errors import RuntimeSessionError

    before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    stopped = []

    class Runtime:
        process = None

        def __init__(self, paths, **options):
            pass

        def start(self, *args, **kwargs):
            self.process = object()
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        def stop(self):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            stopped.append(True)
            self.process = None
            if cleanup_fails:
                raise RuntimeSessionError("cleanup failed")

    monkeypatch.setattr(server_module, "RuntimeSession", Runtime)
    result = CliRunner().invoke(cli, ["--home", str(tmp_path), "server", "--subscription", "main",
                                     "--node", "a" * 32, "--no-install-missing", "--log-format", "jsonl"])
    assert result.exit_code == (1 if cleanup_fails else 128 + signal.SIGTERM), result.output
    assert stopped == [True]
    assert {number: signal.getsignal(number) for number in before} == before
    if cleanup_fails:
        assert isinstance(result.exception, RuntimeSessionError)
        assert str(result.exception) == "cleanup failed"
