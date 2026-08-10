"""Runtime-driver contracts shared by the foreground session supervisor."""

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeProjection(object):
    """Private files a driver asks the session to publish for one node."""

    config: bytes
    provider: bytes = None


@dataclass(frozen=True)
class LoadedNodes(object):
    """What a running backend actually accepted from the published node.

    A backend may parse fewer nodes than were handed to it and still start.
    Mihomo, for one, substitutes a direct-routing placeholder for an empty
    selector group, so a listener can be ready and healthy while nothing is
    proxied at all.  This is the backend-neutral answer to "is traffic really
    going through the node", which the session turns into policy.
    """

    accepted: tuple
    """Names the backend parsed out of the published node source."""

    selected: str
    """What the backend would route through right now."""

    bypassing: bool
    """The selection is a direct or reject placeholder rather than a node."""


class RuntimeDriver(object, metaclass=ABCMeta):
    """Backend-specific projection and process lifecycle contract.

    Drivers own backend configuration syntax and process semantics.  The
    session still owns the home-wide lock, private path publication,
    credentials, health policy, recovery order, and redacted user output.
    """

    @property
    @abstractmethod
    def name(self):  # type: () -> str
        """Return the canonical backend identity."""

    @abstractmethod
    def projection(
        self,
        provider_path,
        node,
        port,
        username,
        password,
        listener_protocol,
        backend_log_level,
        bind_address="127.0.0.1",
        control_port=None,
        control_secret=None,
    ):
        # type: (object, object, int, str, str, str, str, str, int, str) -> RuntimeProjection
        """Build an opaque-node projection without exposing it to the session.

        ``control_port`` and ``control_secret`` are allocated by the session for
        its own private inspection channel.  A driver that projects one must
        keep it on loopback regardless of the listener's bind address, and must
        never place the secret anywhere but the private config.
        """

    @abstractmethod
    def loaded_nodes(self, control_port, control_secret, timeout):
        # type: (int, str, float) -> LoadedNodes
        """Report what the running backend accepted from the published node.

        Drivers own the backend's inspection protocol; the session owns what to
        do about the answer.  Raise :class:`~jerryproxy.errors.JerryProxyError`
        when the answer cannot be obtained, rather than reporting a guess.
        """

    @abstractmethod
    def create_process(self, executable, config_path, session_root, log_path, backend_log_level, log_sink=None):
        # type: (object, object, object, object, str, object) -> object
        """Create (but do not start) the backend child wrapper."""

    @abstractmethod
    def wait_ready(self, process, port, timeout):
        # type: (object, int, float) -> None
        """Wait for the driver's listener readiness boundary."""

    @abstractmethod
    def stop(self, process, timeout=None):
        # type: (object, object) -> None
        """Stop one child and drain its bounded output."""
