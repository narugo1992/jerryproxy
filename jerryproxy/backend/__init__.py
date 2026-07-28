"""Backend discovery, installation, activation, and version management."""

from .catalog import BackendCatalog
from .manager import BackendManager
from .registry import get_backend, iter_backend_platforms, iter_backends

__all__ = [
    "BackendCatalog",
    "BackendManager",
    "get_backend",
    "iter_backend_platforms",
    "iter_backends",
]
