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
