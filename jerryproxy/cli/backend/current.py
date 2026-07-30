"""The ``backend current`` command."""

import json

import click

from ...backend import get_backend
from .. import _common, _completion

_HELP = """Show the version currently selected for one or every backend.

\b
Forms:
  jerryproxy backend current
    Show every backend that currently has a selected version.
  jerryproxy backend current NAME
    Show the current version of one backend.

This command validates the managed current manifest, immutable executable,
and symlink or recorded Windows copy while holding the home-wide lock. It
does not execute a backend or make a network request. An empty global query
succeeds; a named backend with no current version exits nonzero.

Human output is a compact BACKEND, VERSION, and MODE table. --json always
returns an array so global and targeted queries share one machine shape.

\b
Examples:
  jerryproxy backend current
  jerryproxy backend current mihomo
  jerryproxy backend current mihomo --json
"""


def _record(item):
    return {
        "backend": item.name,
        "version": item.version,
        "mode": item.link_mode,
        "executable": str(item.executable),
        "link": str(item.link),
    }


@click.command("current", help=_HELP, short_help="Show current backend versions.")
@click.argument("name", required=False, shell_complete=_completion.installed_backend)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_current(context, name, as_json):
    # type: (click.Context, Optional[str], bool) -> None
    """Show the current version of one or every installed backend."""

    manager = _common.manager(context)
    if name is None:
        current = manager.list_active()
    else:
        selected = manager.current(name)
        if selected is None:
            raise click.ClickException("%s has no current version" % get_backend(name).name)
        current = [selected]
    records = [_record(item) for item in current]
    if as_json:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    if not records:
        click.echo("No current backend.")
        return
    _common.echo_table(
        ["BACKEND", "VERSION", "MODE"],
        [[record["backend"], record["version"], record["mode"]] for record in records],
    )

