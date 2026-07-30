"""Non-initializing shell completion for backend command modules."""

from click.shell_completion import CompletionItem

from ..backend import BackendCatalog, BackendManager, iter_backends
from ..backend.platform import detect_platform
from ..errors import JerryProxyError
from ..home import JerryProxyPaths


def _items(values, incomplete):  # type: (Iterable[str], str) -> list
    return [CompletionItem(value) for value in values if value.startswith(incomplete)]


def _paths(context):  # type: (click.Context) -> JerryProxyPaths
    root = context.find_root()
    configured = (root.obj or {}).get("home")
    if configured is None:
        configured = root.params.get("home")
    return JerryProxyPaths.from_value(str(configured) if configured is not None else None)


def _inventory(context, name=None):
    # type: (click.Context, Optional[str]) -> Optional[BackendInventory]
    try:
        return BackendManager(_paths(context)).inventory(name)
    except (OSError, JerryProxyError, ValueError):
        # Completion tolerates busy, inaccessible, unsupported, or invalid state.
        return None


def _cached_versions(context, name=None):
    # type: (click.Context, Optional[str]) -> dict
    try:
        return BackendManager(_paths(context)).list_cached_versions(name)
    except (OSError, JerryProxyError, ValueError):
        # Completion tolerates busy, inaccessible, unsupported, or invalid state.
        return {}


def _installed_names(context):  # type: (click.Context) -> tuple
    inventory = _inventory(context)
    if inventory is None:
        return ()
    return tuple(sorted({item.name for item in inventory.installed}))


def _cached_names(context):  # type: (click.Context) -> tuple
    cached = _cached_versions(context)
    return tuple(sorted(name for name, versions in cached.items() if versions))


def _installed_versions(context, name):
    # type: (click.Context, Optional[str]) -> tuple
    if name is None:
        return ()
    inventory = _inventory(context, name)
    if inventory is None:
        return ()
    return tuple(item.version for item in inventory.installed)


def _catalog_versions(name):  # type: (Optional[str]) -> tuple
    if name is None:
        return ()
    try:
        return tuple(
            item.version
            for item in BackendCatalog.load().compatible_versions(name, detect_platform())
        )
    except (JerryProxyError, ValueError):
        # Unsupported backend or platform values have no catalog candidates.
        return ()


def supported_backend(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    return _items((spec.name for spec in iter_backends()), incomplete)


def installed_backend(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    return _items(_installed_names(context), incomplete)


def cached_backend(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    return _items(_cached_names(context), incomplete)


def catalog_version(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    return _items(_catalog_versions(context.params.get("name")), incomplete)


def installed_version(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    return _items(_installed_versions(context, context.params.get("name")), incomplete)


def cached_version(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    versions = _cached_versions(context, context.params.get("name"))
    scoped_versions = next(iter(versions.values()), ())
    return _items(scoped_versions, incomplete)


def list_query(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    query = tuple(context.params.get("query") or ())
    if not query:
        values = ("known",) + _installed_names(context)
    elif query[0] == "known" and len(query) == 1:
        values = tuple(spec.name for spec in iter_backends())
    elif query[0] == "known" and len(query) == 2:
        values = _catalog_versions(query[1])
    else:
        values = ()
    return _items(values, incomplete)
