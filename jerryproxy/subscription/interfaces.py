"""Small extension contracts for proxy nodes and subscription readers.

The first release only provides a V2RAY_SUBSCRIPTION URI-line reader.  These
interfaces keep that implementation replaceable without making the runtime
learn about every subscription container or protocol dialect.
"""

from abc import ABCMeta, abstractmethod


class ProxyNode(object, metaclass=ABCMeta):
    """Credential-bearing node contract consumed by a runtime driver.

    Implementations expose a sanitized public view and keep the exact source
    URI behind ``secret_uri``.  Runtime code must use that method instead of
    assuming a particular node model or URI encoding.
    """

    @abstractmethod
    def public(self):  # type: () -> dict
        """Return a credential-free representation for human/JSON output."""

    @abstractmethod
    def secret_uri(self):  # type: () -> str
        """Return the exact credential-bearing URI for the selected driver."""


class NodeSource(object, metaclass=ABCMeta):
    """Source-independent collection of nodes available to a session."""

    @abstractmethod
    def iter_nodes(self):  # type: () -> tuple
        """Return nodes in the source's stable order."""


class SubscriptionParser(object, metaclass=ABCMeta):
    """Parser adapter for one family of subscription containers."""

    @property
    @abstractmethod
    def name(self):  # type: () -> str
        """Return the parser's stable implementation name."""

    @property
    def identity(self):  # type: () -> dict
        """Return credential-free parser provenance metadata."""

        return {"source": self.name}

    @abstractmethod
    def parse(self, body, format_hint="auto"):  # type: (bytes, str) -> object
        """Classify bounded bytes into a :class:`ParsedSubscription`."""
