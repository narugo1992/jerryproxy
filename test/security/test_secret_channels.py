"""Every secret the product holds, against every channel that can emit text.

This is the release gate that reads "no subscription URL, raw URI, UUID,
password, key, short ID, controller secret, or node host appears in CLI output,
logs, descriptors, tests, issues, or release artifacts". A spot check cannot
answer it: the claim is universal, so the test enumerates both sides and asserts
each cell, and fails when either side grows without coverage.

The assertions are stated in the negative on purpose. Checking that a redaction
marker is present passes just as happily when the value beside it was never
redacted; checking that the value is absent cannot.
"""

import base64
import binascii
import json
import re

import pytest

from jerryproxy.errors import RuntimeSessionError
from jerryproxy.home import JerryProxyPaths
from jerryproxy.runtime import HealthSnapshot, LoadedNodes, RecoveryPolicy, RuntimeSession
from jerryproxy.runtime.mihomo import MihomoDriver
from jerryproxy.subscription.manager import SubscriptionManager

#: One distinctive value per sensitive field the product can hold. Distinctive
#: so a match is unambiguous, and one per *field* rather than per format, so a
#: field that gains a second representation is still covered by name.
SECRETS = {
    "subscription_url": "https://provider.invalid/sub?token=SUBSCRIPTIONTOKENAAA",
    "ss_password": "SSPASSWORDBBBBBBBBBBB",
    "vmess_uuid": "11111111-2222-3333-4444-555555555555",
    "reality_public_key": "REALITYPUBLICKEYCCCCCCCCCCCCCCCCCCCCCCCC",
    "reality_short_id": "0123456789abcdef",
    "trojan_password": "TROJANPASSWORDDDDDDD",
    "provider_password": "PROVIDERPASSWORDEEEE",
    "node_host": "node-host.invalid",
    "provider_host": "provider-host.invalid",
}

URI_BODY = (
    "ss://%s@%s:8443#tokyo\n"
    "vmess://%s\n"
    "trojan://%s@%s:443?sni=%s#osaka\n"
    # No fragment, so the label falls back. That branch is the one place a host
    # could reach a label, and a fixture where every record has a fragment never
    # exercises it -- a mutation that derived the label from the authority went
    # undetected until this line existed.
    "ss://%s@%s:9443\n"
) % (
    # SIP002 keeps the credential in userinfo; the host is separately sensitive.
    "YWVzLTI1Ni1nY206U1NQQVNTV09SREJCQkJCQkJCQkJC",
    SECRETS["node_host"],
    # A VMess payload hides everything inside Base64, which is exactly why the
    # public projection must not echo any part of it.
    "eyJhZGQiOiAibm9kZS1ob3N0LmludmFsaWQiLCAiaWQiOiAiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwgInBvcnQiOiAiNDQzIiwgInBzIjogIm9zYWthIiwgInYiOiAyfQ",
    SECRETS["trojan_password"],
    SECRETS["node_host"],
    SECRETS["node_host"],
    "YWVzLTI1Ni1nY206U1NQQVNTV09SREJCQkJCQkJCQkJC",
    SECRETS["node_host"],
)

PROVIDER_BODY = (
    "proxies:\n"
    "  - {name: tokyo, type: ss, server: %s, port: 8443, cipher: aes-256-gcm, password: %s}\n"
    "  - {name: osaka, type: vless, server: %s, port: 443, uuid: %s, tls: true,"
    " reality-opts: {public-key: %s, short-id: %s}}\n"
) % (
    SECRETS["provider_host"],
    SECRETS["provider_password"],
    SECRETS["provider_host"],
    SECRETS["vmess_uuid"],
    SECRETS["reality_public_key"],
    SECRETS["reality_short_id"],
)


class _Probe(object):
    def check(self, port, username, password):
        del port, username, password
        return HealthSnapshot(targets=(), passed=1, required=1, started_at=0.0)


class _Child(object):
    def __init__(self):
        self.returncode = None

    def poll(self):
        return self.returncode


class _Process(object):
    def __init__(self, *args, **kwargs):
        del args, kwargs
        self.process = _Child()

    def start(self):
        return self.process

    def wait_ready(self, port):
        del port

    def stop(self):
        self.process.returncode = 0


def _inspector(port, secret, path, timeout):
    del port, secret, timeout
    if path.startswith("/providers/proxies/"):
        return {"proxies": [{"name": "n"}]}
    return {"now": "n", "all": ["n"], "emptyFallback": "COMPATIBLE"}


def _manager(tmp_path, body, source_url=None):
    paths = JerryProxyPaths(tmp_path / ".jerryproxy")
    paths.ensure()
    manager = SubscriptionManager(paths)
    if source_url is None:
        record = manager.add("main", None, body=body.encode("utf-8"))
    else:
        record = manager.add("main", None, body=body.encode("utf-8"))
    return paths, manager, record


def _leaks(text):
    """Return every secret that survived into this text, by field name."""

    return sorted(name for name, value in SECRETS.items() if value in text)


@pytest.mark.parametrize("label, body", (("uri-lines", URI_BODY), ("provider", PROVIDER_BODY)))
def test_no_secret_reaches_the_public_subscription_view(tmp_path, label, body):
    """Channel: the sanitized record every renderer and JSON caller reads."""

    del label
    unused_paths, manager, record = _manager(tmp_path, body)

    rendered = json.dumps(record.public(include_nodes=True), sort_keys=True)

    assert _leaks(rendered) == []
    # And the reloaded record, since a renderer usually reads that one.
    assert _leaks(json.dumps(manager.get("main").public(include_nodes=True), sort_keys=True)) == []


@pytest.mark.parametrize("label, body", (("uri-lines", URI_BODY), ("provider", PROVIDER_BODY)))
def test_no_secret_reaches_cli_human_output(tmp_path, label, body):
    """Channel: everything the commands print to a terminal."""

    del label
    from click.testing import CliRunner

    from jerryproxy.cli import cli

    source = tmp_path / "body"
    source.write_text(body, encoding="utf-8")
    runner = CliRunner()
    home = str(tmp_path / "home")

    printed = []
    for arguments in (
        ["subscription", "add", "main", "--file", str(source)],
        ["subscription", "list"],
        ["subscription", "show", "main"],
        ["subscription", "validate", "main"],
        ["node", "list"],
        ["node", "list", "main"],
    ):
        result = runner.invoke(cli, ["--home", home] + arguments)
        assert result.exit_code == 0, result.output
        printed.append(result.output)

    assert _leaks("\n".join(printed)) == []


@pytest.mark.parametrize("label, body", (("uri-lines", URI_BODY), ("provider", PROVIDER_BODY)))
def test_no_secret_reaches_cli_json_output(tmp_path, label, body):
    """Channel: the machine-readable surface automation consumes."""

    del label
    from click.testing import CliRunner

    from jerryproxy.cli import cli

    source = tmp_path / "body"
    source.write_text(body, encoding="utf-8")
    runner = CliRunner()
    home = str(tmp_path / "home")
    runner.invoke(cli, ["--home", home, "subscription", "add", "main", "--file", str(source)])

    emitted = []
    for arguments in (
        ["subscription", "list", "--json"],
        ["subscription", "show", "main", "--json"],
        ["node", "list", "--json"],
    ):
        result = runner.invoke(cli, ["--home", home] + arguments)
        assert result.exit_code == 0, result.output
        json.loads(result.output)
        emitted.append(result.output)

    assert _leaks("\n".join(emitted)) == []


def test_no_secret_reaches_a_subscription_error_message(tmp_path):
    """Channel: exception text, which reaches the terminal on any failure."""

    from click.testing import CliRunner

    from jerryproxy.cli import cli

    runner = CliRunner()
    home = str(tmp_path / "home")
    messages = []

    # A URL source: the URL is bearer material and must not appear even when
    # the fetch is what failed.
    result = runner.invoke(
        cli, ["--home", home, "subscription", "add", "main", "--url-stdin"],
        input=SECRETS["subscription_url"] + "\n",
    )
    messages.append(result.output + str(result.exception))

    # A body whose every record is unusable: the aggregate names schemes only.
    unusable = tmp_path / "unusable"
    unusable.write_text(
        "wireguard://%s@%s:51820#x\n" % (SECRETS["trojan_password"], SECRETS["node_host"]),
        encoding="utf-8",
    )
    result = runner.invoke(
        cli, ["--home", home, "subscription", "add", "bad", "--file", str(unusable)]
    )
    messages.append(result.output + str(result.exception))

    assert _leaks("\n".join(messages)) == []


@pytest.mark.parametrize("label, body", (("uri-lines", URI_BODY), ("provider", PROVIDER_BODY)))
def test_no_secret_reaches_the_runtime_log_access_file_or_envelope(tmp_path, label, body):
    """Channels: the session's log sink, its on-disk log, the access file, and
    the public envelope the startup guide renders from."""

    del label
    paths, manager, record = _manager(tmp_path, body)
    executable = tmp_path / "mihomo"
    executable.write_bytes(b"fake")

    class _Backend(object):
        def which(self, name, version):
            del name, version

            class _Installed(object):
                pass

            installed = _Installed()
            installed.executable = executable
            return installed

    lines = []
    session = RuntimeSession(
        paths,
        manager=_Backend(),
        subscription_manager=manager,
        health_probe=_Probe(),
        authenticate=True,
        driver=MihomoDriver(process_factory=_Process, inspector=_inspector),
        recovery_policy=RecoveryPolicy(startup_retry_delays=(0.0,), recovery_deadline=10.0),
        sleeper=lambda delay: None,
        log_sink=lambda owner, level, message: lines.append("%s %s %s" % (owner, level, message)),
    )
    session.start("main", node_id=record.nodes[0].node_id, install_missing=False)
    try:
        channels = {
            "log sink": "\n".join(lines),
            "public envelope": json.dumps(session.public_info(), sort_keys=True),
            "access file": session.access_path.read_text(encoding="utf-8")
            if session.access_path.exists()
            else "",
            "runtime log": session.log_path.read_text(encoding="utf-8")
            if session.log_path.exists()
            else "",
        }
        # The session's own generated credentials belong to the same gate.
        generated = {
            "proxy password": session.password,
            "control secret": session.control_secret,
        }
        for channel, text in sorted(channels.items()):
            assert _leaks(text) == [], "%s leaked" % channel
            for name, value in sorted(generated.items()):
                if channel == "access file" and name == "proxy password":
                    # The private access file is the one place a local client is
                    # meant to read the proxy credential from.
                    continue
                assert value not in text, "%s leaked the %s" % (channel, name)
    finally:
        session.stop()


def test_no_secret_reaches_a_runtime_refusal_message(tmp_path):
    """Channel: the message a refused session shows, which names a protocol."""

    paths, manager, record = _manager(tmp_path, URI_BODY)
    executable = tmp_path / "mihomo"
    executable.write_bytes(b"fake")

    class _Backend(object):
        def which(self, name, version):
            del name, version

            class _Installed(object):
                pass

            installed = _Installed()
            installed.executable = executable
            return installed

    class _Bypassing(MihomoDriver):
        def loaded_nodes(self, control_port, control_secret, timeout):
            del control_port, control_secret, timeout
            return LoadedNodes(accepted=(), selected="COMPATIBLE", bypassing=True)

    session = RuntimeSession(
        paths,
        manager=_Backend(),
        subscription_manager=manager,
        health_probe=_Probe(),
        driver=_Bypassing(process_factory=_Process),
        recovery_policy=RecoveryPolicy(startup_retry_delays=(0.0,), recovery_deadline=5.0),
        sleeper=lambda delay: None,
    )

    with pytest.raises(RuntimeSessionError) as failure:
        session.start("main", node_id=record.nodes[0].node_id, install_missing=False)
    session.stop()

    assert _leaks(str(failure.value)) == []


def test_no_secret_reaches_the_private_state_public_projection(tmp_path):
    """Channel: the stored record's own public view, read by every list path."""

    unused_paths, manager, unused_record = _manager(tmp_path, PROVIDER_BODY)

    rendered = json.dumps([r.public(include_nodes=True) for r in manager.list()], sort_keys=True)

    assert _leaks(rendered) == []


def test_the_matrix_covers_every_secret_and_every_channel():
    """The gate is universal, so neither side may grow without coverage.

    Without this, adding a secret to `SECRETS` and forgetting to exercise it, or
    adding a channel and forgetting to assert it, leaves the suite green while
    the claim it stands for is no longer true.
    """

    import inspect

    # Every declared secret is actually planted in a fixture, counting the ones
    # that appear only inside a Base64 payload -- a value that is declared but
    # never present is a cell nothing checked. This caught exactly that: the
    # Shadowsocks password was declared one character shorter than the one the
    # SIP002 userinfo decodes to, so no assertion could ever have matched it.
    planted = URI_BODY + PROVIDER_BODY + SECRETS["subscription_url"]
    # Decode the Base64 that URI formats hide credentials inside, taken from the
    # positions the formats define rather than by scanning for anything that
    # looks like Base64 -- a greedy scan swallowed the `//` and produced binary
    # noise, which silently matched nothing.
    for chunk in re.findall(r"://([A-Za-z0-9+/=_-]{16,})(?:@|\s|$)", URI_BODY):
        padded = chunk + "=" * (-len(chunk) % 4)
        try:
            planted += base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
    unplanted = sorted(name for name, value in SECRETS.items() if value not in planted)
    assert unplanted == [], "declared but never planted: %s" % unplanted

    # Every channel is bound to the test that asserts it, and that test must
    # exist and actually call `_leaks`. Checking that the channel's *name*
    # appears in the module is circular -- the name is in the table being
    # checked, so it always matches, and a channel could be listed with nothing
    # behind it. Verified: adding an unasserted channel used to pass here.
    channel_tests = {
        "public subscription view": "test_no_secret_reaches_the_public_subscription_view",
        "cli human output": "test_no_secret_reaches_cli_human_output",
        "cli json output": "test_no_secret_reaches_cli_json_output",
        "subscription error message": "test_no_secret_reaches_a_subscription_error_message",
        "runtime log": "test_no_secret_reaches_the_runtime_log_access_file_or_envelope",
        "access file": "test_no_secret_reaches_the_runtime_log_access_file_or_envelope",
        "public envelope": "test_no_secret_reaches_the_runtime_log_access_file_or_envelope",
        "log sink": "test_no_secret_reaches_the_runtime_log_access_file_or_envelope",
        "runtime refusal message": "test_no_secret_reaches_a_runtime_refusal_message",
        "stored state projection": "test_no_secret_reaches_the_private_state_public_projection",
    }
    module = inspect.getmodule(test_the_matrix_covers_every_secret_and_every_channel)
    for channel, name in sorted(channel_tests.items()):
        test = getattr(module, name, None)
        assert test is not None, "%s names a test that does not exist" % channel
        assert "_leaks(" in inspect.getsource(test), "%s has a test that asserts nothing" % channel

    # And no leak test is missing from the table, so adding a channel's test
    # without registering it here is caught from the other side too.
    tested = {
        name
        for name in dir(module)
        if name.startswith("test_no_secret_")
    }
    assert tested == set(channel_tests.values()), (
        "these leak tests are not bound to a channel: %s" % sorted(tested - set(channel_tests.values()))
    )
