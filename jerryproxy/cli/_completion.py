"""Side-effect-free shell completion for backend command modules."""

from click.shell_completion import CompletionItem

from ..backend import BackendCatalog, get_backend, iter_backends
from ..backend.platform import detect_platform
from ..backend.registry import version_sort_key
from ..errors import JerryProxyError
from ..home import JerryProxyPaths, is_path_alias
from ..lock import JerryProxyOperationLock


def _items(values, incomplete):  # type: (Iterable[str], str) -> list
    return [CompletionItem(value) for value in values if value.startswith(incomplete)]


def _paths(context):  # type: (click.Context) -> JerryProxyPaths
    root = context.find_root()
    configured = (root.obj or {}).get("home")
    if configured is None:
        configured = root.params.get("home")
    return JerryProxyPaths.from_value(str(configured) if configured is not None else None)


def _directory_names(context, area, backend=None):
    # type: (click.Context, str, Optional[str]) -> tuple
    paths = _paths(context)
    root = getattr(paths, area)
    if backend is not None:
        root = root / backend
    try:
        with JerryProxyOperationLock(paths, initialize=False):
            if not root.is_dir() or is_path_alias(root):
                return ()
            children = tuple(root.iterdir())
            names = []
            for child in children:
                if child.is_dir() and not is_path_alias(child):
                    names.append(child.name)
            return tuple(names)
    except (OSError, JerryProxyError):
        # Completion tolerates a missing, busy, inaccessible, or invalid existing home.
        return ()


def _installed_names(context):  # type: (click.Context) -> tuple
    supported = {spec.name for spec in iter_backends()}
    return tuple(sorted(name for name in _directory_names(context, "backends") if name in supported))


def _cached_names(context):  # type: (click.Context) -> tuple
    supported = {spec.name for spec in iter_backends()}
    return tuple(sorted(name for name in _directory_names(context, "downloads") if name in supported))


def _local_versions(context, area, name):
    # type: (click.Context, str, Optional[str]) -> tuple
    if name is None:
        return ()
    try:
        spec = get_backend(name)
    except JerryProxyError:
        # An unsupported partial backend name has no local-version candidates.
        return ()
    versions = []
    for child_name in _directory_names(context, area, spec.name):
        try:
            normalized = spec.normalize_version(child_name)
            version_sort_key(normalized)
        except ValueError:
            # Unmanaged directory names are not completion candidates.
            continue
        if normalized == child_name:
            versions.append(normalized)
    return tuple(sorted(versions, key=version_sort_key, reverse=True))


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
    return _items(_local_versions(context, "backends", context.params.get("name")), incomplete)


def cached_version(context, parameter, incomplete):
    # type: (click.Context, click.Parameter, str) -> list
    return _items(_local_versions(context, "downloads", context.params.get("name")), incomplete)


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
