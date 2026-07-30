"""The ``backend use`` command."""

import click

from .. import _common, _completion

_HELP = """Select one already installed backend version as the current command.

\b
Forms:
  jerryproxy backend use
    Select an installed backend and version in guided mode.
  jerryproxy backend use NAME
    Select an installed version of NAME in guided mode.
  jerryproxy backend use NAME VERSION
    Select one exact installed version without prompting.

Use never installs, updates, or downloads a backend. The target executable is
revalidated and probed before JerryProxy atomically replaces the current link
and manifest. A failed validation or activation leaves the previous current
backend usable.

\b
Examples:
  jerryproxy backend use mihomo 1.19.29
  jerryproxy backend use sing-box
"""


@click.command("use", help=_HELP, short_help="Select an installed backend version.")
@click.argument("name", required=False, shell_complete=_completion.installed_backend)
@click.argument("version", required=False, shell_complete=_completion.installed_version)
@click.pass_context
def backend_use(context, name, version):
    # type: (click.Context, Optional[str], Optional[str]) -> None
    """Atomically use one exact already installed backend version."""

    manager = _common.manager(context)
    if name is None:
        installed_names = {item.name for item in manager.list_installed()}
        name = _common.select_backend("Select an installed backend:", installed_names)
    if version is None:
        version = _common.select_installed_version(manager, name)
    current = manager.use(name, version)
    click.echo("Current: %s %s" % (current.name, current.version))
    click.echo("Link: %s (%s)" % (current.link, current.link_mode))
