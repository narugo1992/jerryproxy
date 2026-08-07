"""Domain exceptions exposed by JerryProxy."""


class JerryProxyError(RuntimeError):
    """Base class for expected user-facing JerryProxy failures."""


class UnsupportedPlatformError(JerryProxyError):
    """Raised when no backend asset exists for the current platform."""


class UnsupportedBackendError(JerryProxyError):
    """Raised when a backend name is not registered."""


class BackendCatalogError(JerryProxyError):
    """Raised when the packaged backend catalog is missing or invalid."""


class DownloadError(JerryProxyError):
    """Raised when an upstream asset cannot be downloaded safely."""


class DownloadTransportError(DownloadError):
    """Raised when one download source is unavailable for transport reasons."""

    def __init__(self, message, category="transport"):
        # type: (str, str) -> None
        super(DownloadTransportError, self).__init__(message)
        self.category = category


class DownloadPolicyError(DownloadError):
    """Raised when a download URL or response violates a safety policy."""


class IntegrityError(JerryProxyError):
    """Raised when a downloaded or local asset fails integrity checks."""


class DurabilityError(JerryProxyError):
    """Raised when durable managed-state publication cannot be completed."""


class ArchiveError(JerryProxyError):
    """Raised when an archive is unsupported or unsafe to extract."""


class BackendAlreadyInstalledError(JerryProxyError):
    """Raised when an immutable backend version already exists."""


class BackendNotInstalledError(JerryProxyError):
    """Raised when an installed backend version cannot be found."""


class BackendActiveError(JerryProxyError):
    """Raised when an active backend version cannot be removed."""


class JerryProxyBusyError(JerryProxyError):
    """Raised when another process owns the JerryProxy home lock."""


class CleanupScopeError(JerryProxyError):
    """Raised when a cleanup target is invalid or escapes its managed area."""


class RemovalCleanupError(JerryProxyError):
    """Raised when removal committed but its private quarantine remains."""


class SubscriptionError(JerryProxyError):
    """Base class for subscription ingestion and runtime-source failures."""


class SubscriptionFetchError(SubscriptionError):
    """Raised when a subscription source cannot be fetched safely."""


class SubscriptionParseError(SubscriptionError):
    """Raised when a subscription body is malformed or unsupported."""


class SubscriptionStateError(SubscriptionError):
    """Raised when persisted subscription state is invalid or incomplete."""


class SubscriptionNodesMismatchError(SubscriptionStateError):
    """Raised when a stored node projection differs from its source bytes.

    This is recoverable drift rather than tampering: the keyed home
    fingerprint already proved this home wrote that node content, so a fresh
    parse of the same digest-protected bytes simply no longer reproduces the
    stored projection.  Refreshing the saved source rebuilds it.  Node content
    this home never wrote fails the fingerprint check and raises
    :class:`IntegrityError` instead, which no repair path accepts.
    """


class RuntimeSessionError(JerryProxyError):
    """Raised when a foreground backend session cannot start or stop safely."""
