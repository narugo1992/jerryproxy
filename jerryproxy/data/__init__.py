"""Read immutable JSON resources shipped with JerryProxy."""

import json
import pkgutil
from pathlib import Path

BACKEND_CATALOG_NAMES = ("mihomo", "sing-box", "v2ray", "xray")
MAXIMUM_DATA_RESOURCE_BYTES = 16 * 1024 * 1024


def backend_catalog_resource_names():  # type: () -> tuple
    """Return the stable backend ids with packaged JSON resources."""
    return BACKEND_CATALOG_NAMES


def read_backend_catalog_bytes(name, directory=None):  # type: (str, Optional[Path]) -> bytes
    """Read one whitelisted packaged backend JSON resource as bytes."""
    if name not in BACKEND_CATALOG_NAMES:
        raise ValueError("unknown backend catalog resource: %s" % name)
    resource_name = "%s.json" % name
    if directory is None:
        payload = pkgutil.get_data(__name__, resource_name)
        if payload is None:
            raise FileNotFoundError("packaged backend catalog resource is missing: %s" % resource_name)
    else:
        payload = (Path(directory) / resource_name).read_bytes()
    if len(payload) > MAXIMUM_DATA_RESOURCE_BYTES:
        raise ValueError("packaged backend catalog resource exceeds the safety limit: %s" % resource_name)
    return payload


def read_backend_catalog_json(name, directory=None):  # type: (str, Optional[Path]) -> dict
    """Decode one packaged backend catalog as a top-level JSON object."""
    payload = read_backend_catalog_bytes(name, directory=directory)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("packaged backend catalog is not valid UTF-8 JSON: %s" % error)
    if not isinstance(value, dict):
        raise ValueError("packaged backend catalog must contain a JSON object: %s" % name)
    return value


__all__ = [
    "BACKEND_CATALOG_NAMES",
    "backend_catalog_resource_names",
    "read_backend_catalog_bytes",
    "read_backend_catalog_json",
]
