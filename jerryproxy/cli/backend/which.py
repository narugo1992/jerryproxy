"""The ``backend which`` command."""

import json

import click

from .. import _common, _completion

_HELP = """Print the immutable executable path for a current or exact backend version.

\b
Forms:
  jerryproxy backend which
    Select an installed backend in guided mode, then locate its
    current version.
  jerryproxy backend which NAME
    Print the validated executable for NAME's current version.
  jerryproxy backend which NAME VERSION
    Print the validated executable for one exact installed version.

The printed path points into the immutable backends directory, not the
current symlink or Windows copy. JerryProxy rechecks the executable SHA-256
under the home-wide lock and never executes it or makes a network request.
Missing, malformed, or tampered state exits nonzero.

Without --json, stdout contains only the path for shell composition. --json
returns backend, version, executable, and current link/mode when applicable.

\b
Examples:
  jerryproxy backend which mihomo
  jerryproxy backend which mihomo 1.19.29
  jerryproxy backend which mihomo --json
"""


@click.command("which", help=_HELP, short_help="Print a validated backend executable path.")
@click.argument("name", required=False, shell_complete=_completion.installed_backend)
@click.argument("version", required=False, shell_complete=_completion.installed_version)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_which(context, name, version, as_json):
    # type: (click.Context, Optional[str], Optional[str], bool) -> None
    """Print one integrity-verified installed executable path."""

    manager = _common.manager(context)
    if name is None:
        installed_names = {item.name for item in manager.list_installed()}
        name = _common.select_backend("Select an installed backend:", installed_names)
    selected = manager.which(name, version)
    record = {
        "backend": selected.name,
        "version": selected.version,
        "executable": str(selected.executable),
        "link": str(selected.link) if hasattr(selected, "link") else None,
        "mode": selected.link_mode if hasattr(selected, "link_mode") else None,
    }
    if as_json:
        click.echo(json.dumps(record, indent=2, sort_keys=True))
        return
    click.echo(record["executable"])
