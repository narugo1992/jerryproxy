"""Backend discovery, installation, activation, and version management."""

from .manager import BackendManager
from .registry import get_backend, iter_backends

__all__ = ["BackendManager", "get_backend", "iter_backends"]
