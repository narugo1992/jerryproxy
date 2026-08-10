"""Subscription classification, publication, and node boundary checks."""

import json
import os
import tempfile
from pathlib import Path

from ..errors import JerryProxyError
from ..home import JerryProxyPaths
from ..subscription import parse_subscription_body
from ..subscription.interfaces import NodeSource, ProxyNode, SubscriptionParser
from ..subscription.manager import SubscriptionManager
from .result import CheckResult, _error_result


def _check_subscription_parser():
    """Exercise the packaged URI classifier without reading private state."""

    fixture = (
        b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#ss\n"
        b"vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJhaWQiOiIwIiwiaWQiOiI1NTU1NTU1NS01NTU1LTU1NTUtNTU1NS01NTU1NTU1NTU1NTUiLCJuZXQiOiJ0Y3AiLCJwb3J0IjoiNDQzIiwicHMiOiJ2bWVzcyIsInRscyI6InRscyIsInYiOjJ9\n"
        b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&flow=xtls-rprx-vision#vless\n"
        b"trojan://password@example.invalid:443?sni=www.example.com#trojan\n"
        b"hysteria2://password@example.invalid:443?sni=www.example.com#hysteria2\n"
        # Measured to be dropped by the qualified backend, so it must be reported
        # as skipped rather than counted as a node.
        b"wireguard://key@example.invalid:51820#wireguard\n"
    )
    try:
        parsed = parse_subscription_body(fixture, format_hint="uri-lines")
    except (ValueError, JerryProxyError) as error:
        # The product parser is an installed-resource capability, not a unit
        # test proxy; a malformed packaged fixture is a diagnostic error.
        return _error_result(error)
    schemes = tuple(item[0] for item in parsed.records)
    if schemes != ("ss", "vmess", "vless", "trojan", "hysteria2"):
        return CheckResult.fail("subscription parser classified an unexpected scheme set")
    if parsed.skipped != (("wireguard", 1),):
        return CheckResult.fail("subscription parser did not report the unsupported record")
    if any("@" in item[1] or "=" in item[1] for item in parsed.records):
        return CheckResult.fail("subscription parser produced a credential-shaped display")
    return CheckResult.ok(
        "URI parser accepted %d encrypted schemes safely and reported 1 unsupported record"
        % len(parsed.records)
    )


_SUBSCRIPTION_PROBE_BODY = (
    b"ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw#probe-ss\n"
    b"vless://11111111-1111-1111-1111-111111111111@example.invalid:443"
    b"?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    b"&sid=0123456789abcdef#probe-vless\n"
)


_SUBSCRIPTION_PROBE_SECRETS = (
    "YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjQ0Mw",
    "11111111-1111-1111-1111-111111111111",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0123456789abcdef",
    "example.invalid",
)


class _ProbeParser(SubscriptionParser):
    """A distinct parser adapter injected through the public seam.

    It delegates classification to the packaged parser but reports its own
    identity, so a publication or reload that quietly fell back to the built-in
    adapter is visible instead of passing unnoticed.
    """

    def __init__(self):
        self.parses = 0

    @property
    def name(self):  # type: () -> str
        return "self-check-probe"

    @property
    def identity(self):  # type: () -> dict
        return {"parser": self.name}

    def parse(self, body, format_hint="auto"):  # type: (bytes, str) -> object
        self.parses += 1
        return parse_subscription_body(body, format_hint=format_hint)


def _check_subscription_state():
    """Publish and reload a subscription in a private home through an adapter.

    The parser item next to this one exercises pure classification. This item
    exercises what only a real host can answer: whether publication survives an
    atomic rename on this filesystem, whether the private modes hold, and
    whether a reload revalidates the keyed fingerprint over bytes that actually
    went to disk and came back.
    """

    parser = _ProbeParser()
    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-subscription-self-check-") as temporary:
            paths = JerryProxyPaths(Path(temporary) / ".jerryproxy")
            paths.ensure()
            manager = SubscriptionManager(paths, parser=parser)
            published = manager.add("self-check", None, body=_SUBSCRIPTION_PROBE_BODY)
            if parser.parses == 0:
                return CheckResult.fail("publication bypassed the injected subscription parser")
            published_ids = tuple(node.node_id for node in published.nodes)
            if len(published_ids) != 2:
                return CheckResult.fail(
                    "publication accepted %d nodes from a two-node probe" % len(published_ids)
                )

            before_reload = parser.parses
            reloaded = manager.get("self-check")
            if parser.parses == before_reload:
                return CheckResult.fail("reload bypassed the injected subscription parser")
            if tuple(node.node_id for node in reloaded.nodes) != published_ids:
                return CheckResult.fail("reloaded node identities differ from the published ones")

            listed = tuple(record.name for record in manager.list())
            if listed != ("self-check",):
                return CheckResult.fail("inventory did not list exactly the published subscription")

            leaked = _private_mode_violations(paths.root)
            if leaked:
                return CheckResult.fail(
                    "published subscription state is world-readable: %s" % ", ".join(leaked)
                )
    except (JerryProxyError, OSError, RuntimeError, ValueError) as error:
        # Temporary-home creation, publication, and reload are real host operations.
        return _error_result(error)
    return CheckResult.ok(
        "publication and reload through an injected parser kept 2 node identities and private modes"
    )


def _private_mode_violations(root):  # type: (Path) -> list
    """Names below the home whose POSIX mode is readable outside the owner."""

    if os.name != "posix":
        # Windows expresses this through ACLs rather than mode bits, and the
        # home layout check already owns that boundary.
        return []
    violations = []
    for current, directories, files in os.walk(str(root)):
        for name in list(directories) + list(files):
            target = os.path.join(current, name)
            if os.path.islink(target):
                continue
            if os.stat(target).st_mode & 0o077:
                violations.append(os.path.relpath(target, str(root)))
    return violations[:5]


def _check_node_source_boundary():
    """Confirm a node source publishes nothing a bearer credential lives in.

    ``public()`` and ``secret_uri()`` are the whole separation between what a
    renderer may show and what only the runtime may hold, so the check asserts
    that the credential material is *absent* from every public projection
    rather than that some redaction marker is present.
    """

    try:
        with tempfile.TemporaryDirectory(prefix="jerryproxy-nodesource-self-check-") as temporary:
            paths = JerryProxyPaths(Path(temporary) / ".jerryproxy")
            paths.ensure()
            record = SubscriptionManager(paths).add(
                "self-check", None, body=_SUBSCRIPTION_PROBE_BODY
            )
            if not isinstance(record, NodeSource):
                return CheckResult.fail("a subscription record is not a NodeSource")
            nodes = record.iter_nodes()
            if len(nodes) != 2 or not all(isinstance(node, ProxyNode) for node in nodes):
                return CheckResult.fail("the node source did not yield two ProxyNode records")

            public_text = json.dumps(
                [record.public(include_nodes=True)] + [node.public() for node in nodes],
                sort_keys=True,
            )
            for secret in _SUBSCRIPTION_PROBE_SECRETS:
                if secret in public_text:
                    return CheckResult.fail(
                        "the public node projection exposed credential material"
                    )
            for node in nodes:
                if node.secret_uri() not in _SUBSCRIPTION_PROBE_BODY.decode("ascii"):
                    return CheckResult.fail(
                        "the runtime boundary did not return the exact source URI"
                    )
    except (JerryProxyError, OSError, RuntimeError, ValueError, UnicodeError) as error:
        # Publication and projection are real operations against this host.
        return _error_result(error)
    return CheckResult.ok(
        "the public projection withheld %d credential values that the runtime boundary still returns"
        % len(_SUBSCRIPTION_PROBE_SECRETS)
    )
