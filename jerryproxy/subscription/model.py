"""Immutable public and private value objects for subscription state."""

from dataclasses import dataclass, field
from typing import Optional, Tuple

from .interfaces import NodeSource, ProxyNode


@dataclass(frozen=True)
class NodeRecord(ProxyNode):
    """One accepted opaque node with a public stable identity.

    ``uri`` is intentionally private to the runtime boundary.  Public
    renderers use :meth:`public`, which never exposes bearer credentials.
    """

    node_id: str
    scheme: str
    display: str
    uri: str = field(repr=False)
    occurrence: int = 0
    fingerprint: str = field(default="", repr=False)

    def public(self):  # type: () -> dict
        """Return the credential-free node representation."""

        return {
            "id": self.node_id,
            "scheme": self.scheme,
            "display": self.display,
            "occurrence": self.occurrence,
        }

    def secret_uri(self):  # type: () -> str
        """Return the exact source URI only at the runtime boundary."""

        return self.uri


@dataclass(frozen=True)
class SingleNodeSource(NodeSource):
    """A future direct-node input represented through the same source seam."""

    node: ProxyNode

    def iter_nodes(self):  # type: () -> Tuple[ProxyNode, ...]
        return (self.node,)


@dataclass(frozen=True)
class SubscriptionRecord(NodeSource):
    """One current subscription generation."""

    name: str
    subscription_id: str
    revision: str
    format: str
    enabled: bool
    updated_at: str
    nodes: Tuple[NodeRecord, ...]
    source_url: Optional[str] = field(default=None, repr=False)
    body: bytes = field(default=b"", repr=False)

    @property
    def node_count(self):  # type: () -> int
        return len(self.nodes)

    def public(self, include_nodes=True):  # type: (bool) -> dict
        """Return a sanitized record suitable for CLI or JSON output."""

        value = {
            "name": self.name,
            "id": self.subscription_id,
            "revision": self.revision,
            "format": self.format,
            "enabled": self.enabled,
            "updated_at": self.updated_at,
            "node_count": self.node_count,
        }
        if include_nodes:
            value["nodes"] = [node.public() for node in self.nodes]
        return value

    def iter_nodes(self):  # type: () -> Tuple[NodeRecord, ...]
        """Return the stable node sequence consumed by a runtime session."""

        return self.nodes


@dataclass(frozen=True)
class ParsedSubscription(object):
    """Bounded, classified source body before state publication."""

    format: str
    body: bytes
    records: Tuple[Tuple[str, str, str], ...]
