"""The ``backend uninstall`` command."""

import click

from .. import _common, _completion

_HELP = """Uninstall one or all installed versions of a backend after confirmation.

\b
Forms:
  jerryproxy backend uninstall
    Select backend and version in guided mode, then confirm.
  jerryproxy backend uninstall NAME VERSION
    Uninstall one exact version.
  jerryproxy backend uninstall NAME -A
    Uninstall every version of NAME and deactivate it.

An exact current version is protected unless --deactivate is explicit.
--cache also removes the matching release cache; with -A it covers all cache
for NAME. Every destructive form asks for final confirmation. -y/--yes skips
only that confirmation and never infers a missing backend, version, or -A.

Uninstall stages installed files, matching cache, and current state in one
recoverable transaction under the home-wide lock. It never removes another
backend or unrelated disposable data.

\b
Examples:
  jerryproxy backend uninstall mihomo 1.19.28
  jerryproxy backend uninstall mihomo 1.19.29 --deactivate --cache
  jerryproxy backend uninstall mihomo -A --cache -y
"""


@click.command("uninstall", help=_HELP, short_help="Uninstall backend versions safely.")
@click.argument("name", required=False, shell_complete=_completion.installed_backend)
@click.argument("version", required=False, shell_complete=_completion.installed_version)
@click.option("-A", "--all", "all_versions", is_flag=True, help="Uninstall every version of this backend.")
@click.option("--deactivate", is_flag=True, help="Also deactivate this exact current version.")
@click.option("--cache", is_flag=True, help="Also remove the matching cached release archive.")
@click.option("-y", "--yes", is_flag=True, help="Skip the destructive-operation confirmation.")
@click.pass_context
def backend_uninstall(context, name, version, all_versions, deactivate, cache, yes):
    # type: (click.Context, Optional[str], Optional[str], bool, bool, bool, bool) -> None
    """Uninstall one or every immutable version of one backend."""

    manager = _common.manager(context)
    guided = name is None or (version is None and not all_versions)
    if name is None:
        installed_names = {item.name for item in manager.list_installed()}
        name = _common.select_backend("Select a backend to uninstall:", installed_names)
    if version is not None and all_versions:
        raise click.UsageError("provide VERSION or -A/--all, but not both")
    if version is None and not all_versions:
        selected = _common.select_installed_version(manager, name, allow_all=True)
        if selected == "__all__":
            all_versions = True
        else:
            version = selected
    if guided and not cache:
        cache = _common.prompt_confirm("Also remove the matching cached release?", default=False)
    if all_versions and deactivate:
        raise click.UsageError("--deactivate only applies to one exact VERSION")
    if guided and not all_versions:
        current = manager.current(name)
        if current is not None and current.version == version:
            deactivate = True
    target = "%s (all installed versions)" % name if all_versions else "%s %s" % (name, version)
    extras = " and matching cache" if cache else ""
    if not _common.confirm_dangerous_operation("Uninstall %s%s?" % (target, extras), yes):
        click.echo("Cancelled.")
        return

    if all_versions:
        result = manager.uninstall_all(name, cache=cache)
    else:
        result = manager.uninstall(name, version, deactivate=deactivate, cache=cache)
    versions = ", ".join(result.versions) if result.versions else "none"
    click.echo("Uninstalled %s version(s): %s" % (len(result.versions), versions))
    if cache:
        click.echo(
            "Cleaned cache: %d target(s), %s reclaimed"
            % (result.cleanup.targets_removed, _common.format_size(result.cleanup.bytes_reclaimed))
        )

