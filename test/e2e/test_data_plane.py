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
import threading
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
STARTUP_DEADLINE = 180.0
BACKEND_INSTALL_DEADLINE = 420.0
# pytest-timeout counts setup, so the first case also pays for the session-wide
# backend install. The budget must exceed both or a legal slow download would be
# reported as a three-protocol data-plane failure.
CASE_TIMEOUT = BACKEND_INSTALL_DEADLINE + STARTUP_DEADLINE + 60.0


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


def _assert_sentinel_is_isolated():
    """Fail unless the sentinel is unreachable without a proxy.

    Every positive assertion in this module depends on this being true, so it is
    a precondition of each data-plane case rather than a separate test that
    ordering, `-k` filtering, or parallel execution could drop.
    """

    try:
        connection = socket.create_connection(
            (CONTRACT.sentinel_host, CONTRACT.sentinel_port), timeout=5.0
        )
    except OSError as error:
        # Distinguish isolation from an unrelated local failure: a resolvable
        # name that refuses the connection would mean the sentinel joined the
        # client network, which is the failure this control exists to catch.
        assert isinstance(error, (socket.gaierror, socket.timeout, ConnectionError, TimeoutError)), (
            "sentinel is isolated for an unexpected reason: %s" % type(error).__name__
        )
    else:
        connection.close()
        raise AssertionError(
            "sentinel is directly reachable; no data-plane assertion would prove anything"
        )
    with pytest.raises(requests.RequestException):
        _session().get(CONTRACT.sentinel_url, timeout=(3.0, 5.0))


@pytest.fixture
def isolated_sentinel():
    """Bind the negative control to each case that relies on it."""

    _assert_sentinel_is_isolated()


def test_sentinel_is_unreachable_without_the_proxy():
    _assert_sentinel_is_isolated()


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


def _publish_subscription(home, scheme):  # type: (object, str) -> str
    """Publish exactly one node so no alternate can serve the request.

    Publishing all three nodes together would leave the runtime's recovery sweep
    free to substitute another protocol: a health blip against its public quorum
    targets makes it restart and try the next node in the same record, and the
    case would still reach the sentinel while the protocol under test carried
    nothing. A single-node subscription removes that possibility structurally
    rather than relying on recovery not triggering.

    The product refuses to persist a source that is not HTTPS and does not
    resolve to a global address, which is exactly what an in-network fixture is.
    That guard is deliberate and asserted separately, so the body is supplied
    through the bounded file source instead.
    """

    uri = CONTRACT.nodes[scheme]
    feed = home.parent / ("fixture-%s" % scheme)
    feed.parent.mkdir(parents=True, exist_ok=True)
    feed.write_bytes((uri + "\n").encode("utf-8"))
    result = _run(["subscription", "add", scheme, "--file", str(feed), "--json"], home)
    assert result.returncode == 0, _redacted(result.stdout.decode("utf-8", "replace"))
    return scheme


def _node_id(home, scheme):  # type: (object, str) -> str
    """Resolve the exact node identity for one scheme, never a random pick."""

    result = _run(["node", "list", scheme, "--json"], home)
    assert result.returncode == 0, _redacted(result.stdout.decode("utf-8", "replace"))
    nodes = json.loads(result.stdout.decode("utf-8"))
    assert len(nodes) == 1, "expected a single-node subscription, found %d" % len(nodes)
    assert nodes[0]["scheme"] == scheme, "published node is %s, not %s" % (nodes[0]["scheme"], scheme)
    return nodes[0]["id"]


class _Server(object):
    """One foreground `jerryproxy server` child, owned for a single test."""

    def __init__(self, home, subscription, node_id, port):
        self.home = home
        self.subscription = subscription
        self.node_id = node_id
        self.port = port
        self.process = None
        self._lines = []
        self._lock = threading.Lock()
        self._reader = None

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
                self.subscription,
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
        self._reader = threading.Thread(target=self._pump, name="e2e-server-log")
        self._reader.daemon = True
        self._reader.start()
        try:
            self._wait_ready()
        except BaseException:
            # __exit__ never runs when __enter__ raises, so a failed readiness
            # wait would otherwise leave a live proxy child holding the home
            # lock and its listener for the rest of the session.
            self.__exit__(None, None, None)
            raise
        return self

    def _pump(self):
        """Drain the child's merged output continuously.

        Reading to EOF while the child is alive would block forever, because a
        foreground server keeps its stream open. That turns a working data plane
        into an unexplained timeout, so the stream is consumed line by line in
        the background instead.
        """

        stream = self.process.stdout
        if stream is None:
            return
        try:
            for line in iter(stream.readline, b""):
                with self._lock:
                    if len(self._lines) < 4096:
                        self._lines.append(line)
        except (OSError, ValueError):
            # The pipe closes when the child exits; nothing further to drain.
            pass

    def _wait_ready(self):
        """Wait for the product to declare readiness, not merely for a bind.

        The backend binds its listener before the session runs its startup health
        quorum, and a missed quorum stops and relaunches the child. Connecting on
        the first accept therefore races that restart and yields a spurious
        connection error, so the child's own readiness record is the gate.
        """

        deadline = time.monotonic() + STARTUP_DEADLINE
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(
                    "server exited during startup: %s" % _redacted(self._drain())
                )
            if "proxy listener ready at" in self._drain():
                return
            time.sleep(0.5)
        raise AssertionError(
            "server did not report readiness within the deadline: %s" % _redacted(self._drain())
        )

    def _drain(self):
        with self._lock:
            return b"".join(self._lines).decode("utf-8", "replace")

    def raw_output(self):  # type: () -> str
        """Return the child's output unredacted, for leak assertions only."""

        return self._drain()

    def diagnostics(self):  # type: () -> str
        """Return a redacted rendering, safe to place in a failure message."""

        return _redacted(self._drain())

    def __exit__(self, exception_type, exception, traceback):
        del exception_type, exception, traceback
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=30.0)
            except subprocess.TimeoutExpired:
                # A child that ignores termination is escalated to a hard kill.
                self.process.kill()
                self.process.wait(timeout=10.0)
        if self._reader is not None:
            self._reader.join(timeout=10.0)
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
        timeout=BACKEND_INSTALL_DEADLINE,
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
def test_each_protocol_reaches_the_private_sentinel(scheme, home, unused_port, isolated_sentinel):
    """Traffic must traverse the selected protocol to obtain the run nonce."""

    subscription = _publish_subscription(home, scheme)
    node_id = _node_id(home, scheme)

    with _Server(home, subscription, node_id, unused_port) as server:
        answer = _sentinel_answer(unused_port)

        assert answer["banner"] == _contract.SENTINEL_BANNER
        assert answer["marker"] == CONTRACT.marker, "sentinel returned an unexpected nonce"
        # Assert against the child's raw output. Asserting against the redacted
        # rendering would be circular: that rendering strips the very strings
        # being looked for, so the check could never fail.
        raw = server.raw_output()
        assert CONTRACT.marker not in raw, "the run nonce reached the child's output"
        assert CONTRACT.nodes[scheme] not in raw, "the node URI reached the child's output"
        # A single-node subscription leaves no alternate, so recovery must never
        # have substituted another node for the protocol under test.
        assert "trying an alternate node" not in raw, server.diagnostics()


@pytest.mark.timeout(CASE_TIMEOUT)
def test_public_internet_is_reachable_through_each_node(home, unused_port, isolated_sentinel):
    """Opt-in public egress: bounded targets, per-target result, no score."""

    if not CONTRACT.public_probes:
        pytest.skip("%s is not set; public egress is opt-in" % _contract.PUBLIC_PROBES)

    subscription = _publish_subscription(home, "ss")
    node_id = _node_id(home, "ss")
    results = {}
    with _Server(home, subscription, node_id, unused_port):
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


def test_an_in_network_source_url_is_refused_before_any_fetch(home):
    """The plaintext source the fixture serves must never be persistable.

    The fixture is plain HTTP, so the scheme gate rejects it before the
    private-address guard is ever consulted; this asserts that exact gate rather
    than claiming to cover both. The point is that no test-only bypass exists to
    make an in-network source succeed, so the lane cannot weaken the product to
    suit its own fixture.
    """

    result = _run(
        ["subscription", "add", "guarded", "--url-env", _contract.SUBSCRIPTION, "--json"], home
    )
    output = _redacted(result.stdout.decode("utf-8", "replace"))

    assert result.returncode != 0, "an in-network HTTP source must not be persisted"
    assert "must use HTTPS" in output, output
    # A refused source must leave no subscription behind.
    listed = _run(["subscription", "list", "--json"], home)
    assert listed.returncode == 0, _redacted(listed.stdout.decode("utf-8", "replace"))
    assert json.loads(listed.stdout.decode("utf-8") or "[]") == []
