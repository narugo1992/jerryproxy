"""The ``backend clean`` command."""

import click
from InquirerPy.base.control import Choice

from .. import _common, _completion

_HELP = """Delete selected disposable data without removing installed backends.

\b
Forms:
  jerryproxy backend clean
    Select a cleanup scope in guided mode, then confirm.
  jerryproxy backend clean NAME [VERSION]
    Clean cache for one backend or exact cached version.
  jerryproxy backend clean --cache|--logs|--providers|--runtimes
    Clean one or more explicit global disposable areas.
  jerryproxy backend clean -A
    Clean every disposable area.

Backend and VERSION scopes apply only to cache. A scoped form implies cache
even when --cache is omitted. -A cannot be combined with individual areas.
Every destructive form asks for final confirmation; -y/--yes skips only that
confirmation and never selects a missing scope.

Clean may empty cache, logs, providers, and generated runtimes. It never
touches installed backends, current commands, active manifests, or locks. All
targets remain confined below JerryProxy home and share the home-wide lock.

\b
Examples:
  jerryproxy backend clean --cache -y
  jerryproxy backend clean mihomo 1.19.29 --cache
  jerryproxy backend clean --logs --runtimes
  jerryproxy backend clean -A -y
"""


def _display_area(area):  # type: (str) -> str
    return "cache" if area == "downloads" else area


@click.command("clean", help=_HELP, short_help="Clean disposable JerryProxy data.")
@click.argument("name", required=False, shell_complete=_completion.cached_backend)
@click.argument("version", required=False, shell_complete=_completion.cached_version)
@click.option("--cache", is_flag=True, help="Clean verified release archives (the default area).")
@click.option("--logs", is_flag=True, help="Clean all JerryProxy and backend logs.")
@click.option("--providers", is_flag=True, help="Clean all stored subscription provider data.")
@click.option("--runtimes", is_flag=True, help="Clean all generated runtime data.")
@click.option("-A", "--all", "all_areas", is_flag=True, help="Clean cache, logs, providers, and runtimes.")
@click.option("-y", "--yes", is_flag=True, help="Skip the destructive-operation confirmation.")
@click.pass_context
def backend_clean(context, name, version, cache, logs, providers, runtimes, all_areas, yes):
    # type: (click.Context, Optional[str], Optional[str], bool, bool, bool, bool, bool, bool) -> None
    """Reclaim selected disposable data below the JerryProxy home."""

    manager = _common.manager(context)
    selected = [
        area
        for area, enabled in (
            ("downloads", cache),
            ("logs", logs),
            ("providers", providers),
            ("runtimes", runtimes),
        )
        if enabled
    ]
    guided = name is None and version is None and not selected and not all_areas
    if guided:
        cleanup_scope = str(
            _common.select(
                "Select data to clean:",
                [
                    Choice("cache-version", name="One cached backend version"),
                    Choice("cache-backend", name="All cache for one backend"),
                    Choice("cache", name="All backend release cache"),
                    Choice("logs", name="All logs"),
                    Choice("providers", name="All subscription provider data"),
                    Choice("runtimes", name="All generated runtime data"),
                    Choice("all", name="All disposable JerryProxy data"),
                ],
            )
        )
        if cleanup_scope in ("cache-version", "cache-backend"):
            cached = manager.list_cached_versions()
            names = {backend_name for backend_name, versions in cached.items() if versions}
            name = _common.select_backend("Select a backend cache:", names)
            if cleanup_scope == "cache-version":
                version = str(
                    _common.select(
                        "Select a cached version:",
                        [Choice(item, name=item) for item in cached[name]],
                    )
                )
            selected = ["downloads"]
        elif cleanup_scope == "all":
            all_areas = True
        elif cleanup_scope == "cache":
            selected = ["downloads"]
        else:
            selected = [cleanup_scope]
    if all_areas and selected:
        raise click.UsageError("-A/--all cannot be combined with individual cleanup areas")
    if name is not None and (all_areas or any(area != "downloads" for area in selected)):
        raise click.UsageError("backend-scoped cleanup can only target cache")
    if all_areas:
        selected = ["downloads", "logs", "providers", "runtimes"]
    elif not selected:
        selected = ["downloads"]

    if version is not None:
        scope = "%s %s cache" % (name, version)
    elif name is not None:
        scope = "%s cache" % name
    else:
        scope = ", ".join(_display_area(area) for area in selected)
    if not _common.confirm_dangerous_operation("Clean %s?" % scope, yes):
        click.echo("Cancelled.")
        return

    result = manager.clean(name=name, version=version, areas=tuple(selected))
    click.echo(
        "Cleaned %s: %d target(s), %s reclaimed"
        % (
            ", ".join(_display_area(area) for area in result.areas),
            result.targets_removed,
            _common.format_size(result.bytes_reclaimed),
        )
    )
