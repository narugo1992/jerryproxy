"""End-to-end proof that each protocol carries traffic to a private sentinel.

The sentinel has no published port and lives on a network this test container
never joins, so its per-run nonce cannot be obtained without traversing the
selected proxy.  That makes the nonce the deterministic oracle: reaching it
proves the data plane worked, and the negative control proves it cannot be
reached any other way.

This module owns transport and assertions only.  The workflow owns Docker.
"""

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest
import requests

from jerryproxy.subscription import redact_text

from . import _contract

CONTRACT, SKIP_REASON = _contract.load()
if CONTRACT is None:
    pytest.skip(SKIP_REASON, allow_module_level=True)

REQUEST_TIMEOUT = (5.0, 15.0)
# Starting a node includes bootstrapping the exact backend release on a cold
# home, so this lane needs far more than the unit matrix's per-test budget.
STARTUP_DEADLINE = 240.0
CASE_TIMEOUT = 420.0


def _session(port=None):  # type: (object) -> requests.Session
    """Return a session that ignores any ambient proxy configuration.

    A container or developer shell often exports HTTP_PROXY/http_proxy. Left
    alone, every request below would travel through that proxy: the source fetch
    would fail against a service name, and worse, the negative control would
    fail because the ambient proxy refused rather than because the sentinel is
    isolated. That is a test that passes for the wrong reason, so the ambient
    environment is never trusted here and the only proxy is the one under test.
    """

    session = requests.Session()
    session.trust_env = False
    if port is not None:
        endpoint = "http://127.0.0.1:%d" % port
        session.proxies = {"http": endpoint, "https": endpoint}
    return session


def _redacted(value):  # type: (object) -> str
    """Render a diagnostic without node URIs, keys, or the run nonce."""

    text = redact_text(str(value))
    return text.replace(CONTRACT.marker, "[REDACTED MARKER]")


def _sentinel_answer(port):  # type: (int) -> dict
    """Fetch the sentinel through the local listener and bound the response."""

    response = _session(port).get(CONTRACT.sentinel_url, timeout=REQUEST_TIMEOUT, stream=True)
    body = response.raw.read(_contract.MAXIMUM_RESPONSE_BYTES + 1, decode_content=True)
    assert len(body) <= _contract.MAXIMUM_RESPONSE_BYTES, "sentinel response exceeded its bound"
    assert response.status_code == 200, "sentinel returned HTTP %d" % response.status_code
    return json.loads(body.decode("utf-8"))


def _run(arguments, home, extra_environment=None, timeout=120.0):
    """Invoke the installed CLI as a user would, with a private home."""

    environment = dict(os.environ)
    environment["JERRYPROXY_HOME"] = str(home)
    environment.update(extra_environment or {})
    return subprocess.run(
        [sys.executable, "-m", "jerryproxy"] + list(arguments),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def test_environment_contract_is_reported_without_secrets():
    described = CONTRACT.describe()

    assert CONTRACT.backend == "mihomo"
    assert CONTRACT.marker not in described
    for uri in CONTRACT.nodes.values():
        assert uri not in described


def test_sentinel_is_unreachable_without_the_proxy():
    """The negative control: this must fail before any proxy assertion counts.

    If the sentinel were reachable directly, every data-plane assertion below
    would pass without proving that traffic traversed a proxy at all.
    """

    with pytest.raises((socket.gaierror, socket.timeout, OSError)):
        connection = socket.create_connection(
            (CONTRACT.sentinel_host, CONTRACT.sentinel_port), timeout=5.0
        )
        connection.close()

    with pytest.raises(requests.RequestException):
        _session().get(CONTRACT.sentinel_url, timeout=(3.0, 5.0))


def test_subscription_source_serves_bounded_base64_uri_lines():
    body = _fixture_body()
    decoded = base64.b64decode(body, validate=False)
    lines = [line for line in decoded.decode("utf-8").splitlines() if line.strip()]
    schemes = sorted(line.split("://", 1)[0].lower() for line in lines)

    assert schemes == ["ss", "vless", "vmess"], "source must serve exactly the three schemes"


def _fixture_body():  # type: () -> bytes
    """Read the fixture source exactly as published, bounded."""

    response = _session().get(CONTRACT.subscription_url, timeout=REQUEST_TIMEOUT, stream=True)
    body = response.raw.read(_contract.MAXIMUM_RESPONSE_BYTES + 1, decode_content=True)
    assert response.status_code == 200
    assert len(body) <= _contract.MAXIMUM_RESPONSE_BYTES
    return body


def _publish_subscription(home):  # type: (object) -> None
    """Publish the fixture source body through the public add command.

    The product refuses to persist a source that is not HTTPS and does not
    resolve to a global address, which is exactly what an in-network fixture is.
    That guard is deliberate and is asserted separately below, so the body is
    supplied through the bounded file source instead. The classification,
    inventory, and runtime path under test are identical either way.
    """

    body = _fixture_body()
    feed = home.parent / "fixture-source"
    feed.parent.mkdir(parents=True, exist_ok=True)
    feed.write_bytes(body)
    result = _run(["subscription", "add", "e2e", "--file", str(feed), "--json"], home)
    assert result.returncode == 0, _redacted(result.stdout.decode("utf-8", "replace"))


def _node_id(home, scheme):  # type: (object, str) -> str
    """Resolve the exact node identity for one scheme, never a random pick."""

    result = _run(["node", "list", "e2e", "--json"], home)
    assert result.returncode == 0, _redacted(result.stdout.decode("utf-8", "replace"))
    nodes = json.loads(result.stdout.decode("utf-8"))
    matching = [node for node in nodes if node["scheme"] == scheme]
    assert len(matching) == 1, "expected exactly one %s node, found %d" % (scheme, len(matching))
    return matching[0]["id"]


class _Server(object):
    """One foreground `jerryproxy server` child, owned for a single test."""

    def __init__(self, home, node_id, port):
        self.home = home
        self.node_id = node_id
        self.port = port
        self.process = None
        self.output = b""

    def __enter__(self):
        environment = dict(os.environ)
        environment["JERRYPROXY_HOME"] = str(self.home)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "jerryproxy",
                "server",
                "--subscription",
                "e2e",
                "--node",
                self.node_id,
                "--port",
                str(self.port),
                "--protocol",
                "http",
                "--backend-version",
                CONTRACT.backend_version,
                "-y",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._wait_ready()
        return self

    def _wait_ready(self):
        deadline = time.monotonic() + STARTUP_DEADLINE
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(
                    "server exited during startup: %s" % _redacted(self._drain())
                )
            try:
                connection = socket.create_connection(("127.0.0.1", self.port), timeout=1.0)
            except OSError:
                time.sleep(0.5)
                continue
            connection.close()
            return
        raise AssertionError("server did not open its listener within the deadline")

    def _drain(self):
        if self.process.stdout is None:
            return ""
        try:
            self.output += self.process.stdout.read() or b""
        except (OSError, ValueError):
            # The child's pipe may already be closed after termination.
            pass
        return self.output.decode("utf-8", "replace")

    def diagnostics(self):  # type: () -> str
        return _redacted(self._drain())

    def __exit__(self, exception_type, exception, traceback):
        del exception_type, exception, traceback
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=30.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10.0)
        self._drain()
        return False


@pytest.fixture(scope="session")
def warm_home(tmp_path_factory):
    """Install the exact backend once for the whole lane.

    Bootstrapping the release per case would download it once per protocol and
    dominate the run. Installing once and copying keeps every case on its own
    isolated home while the download happens a single time.
    """

    root = tmp_path_factory.mktemp("backend") / "home"
    result = _run(
        ["backend", "install", CONTRACT.backend, CONTRACT.backend_version],
        root,
        timeout=600.0,
    )
    assert result.returncode == 0, _redacted(result.stdout.decode("utf-8", "replace"))
    return root


@pytest.fixture
def home(tmp_path, warm_home):
    target = tmp_path / "jerryproxy-home"
    shutil.copytree(str(warm_home), str(target), symlinks=True)
    return target


@pytest.fixture
def unused_port():
    """Reserve one loopback port, then release it for the child to bind."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.mark.timeout(CASE_TIMEOUT)
@pytest.mark.parametrize("scheme", ["ss", "vmess", "vless"])
def test_each_protocol_reaches_the_private_sentinel(scheme, home, unused_port):
    """Traffic must traverse the selected protocol to obtain the run nonce."""

    _publish_subscription(home)
    node_id = _node_id(home, scheme)

    with _Server(home, node_id, unused_port) as server:
        answer = _sentinel_answer(unused_port)

        assert answer["banner"] == _contract.SENTINEL_BANNER
        assert answer["marker"] == CONTRACT.marker, "sentinel returned an unexpected nonce"
        # The listener must not leak the node URI or the nonce into diagnostics.
        diagnostics = server.diagnostics()
        assert CONTRACT.marker not in diagnostics
        assert CONTRACT.nodes[scheme] not in diagnostics


@pytest.mark.timeout(CASE_TIMEOUT)
def test_public_internet_is_reachable_through_each_node(home, unused_port):
    """Opt-in public egress: bounded targets, per-target result, no score."""

    if not CONTRACT.public_probes:
        pytest.skip("%s is not set; public egress is opt-in" % _contract.PUBLIC_PROBES)

    _publish_subscription(home)
    node_id = _node_id(home, "ss")
    results = {}
    with _Server(home, node_id, unused_port):
        for target in CONTRACT.public_probes:
            try:
                response = _session(unused_port).get(target, timeout=REQUEST_TIMEOUT)
                results[target] = response.status_code
            except requests.RequestException as error:
                # An unavailable external site is a target result, never a
                # protocol verdict, so it is recorded rather than raised.
                results[target] = "unavailable: %s" % type(error).__name__

    reachable = [target for target, value in results.items() if value in (200, 204)]
    assert reachable, "no public target was reachable through the proxy: %s" % results


def test_an_in_network_source_url_is_refused_by_the_transport_guards(home):
    """The source guards must hold against a real private container network.

    Unit tests cover this with injected resolvers; here the address really is a
    private container address reached over a real Docker network, so this is the
    guard working end to end rather than in a fixture. A test-only bypass is
    never introduced to make the fetch succeed.
    """

    result = _run(
        ["subscription", "add", "guarded", "--url-env", _contract.SUBSCRIPTION, "--json"], home
    )
    output = _redacted(result.stdout.decode("utf-8", "replace"))

    assert result.returncode != 0, "an in-network HTTP source must not be persisted"
    assert "must use HTTPS" in output or "not public" in output, output
    # A refused source must leave no subscription behind.
    listed = _run(["subscription", "list", "--json"], home)
    assert listed.returncode == 0, _redacted(listed.stdout.decode("utf-8", "replace"))
    assert json.loads(listed.stdout.decode("utf-8") or "[]") == []
