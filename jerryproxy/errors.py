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


class BackendBusyError(JerryProxyError):
    """Raised when another backend operation owns the installation lock."""
