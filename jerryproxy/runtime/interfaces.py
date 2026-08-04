"""Runtime-driver contracts shared by the foreground session supervisor."""

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeProjection(object):
    """Private files a driver asks the session to publish for one node."""

    config: bytes
    provider: bytes = None


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
    ):
        # type: (object, object, int, str, str, str, str, str) -> RuntimeProjection
        """Build an opaque-node projection without exposing it to the session."""

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
