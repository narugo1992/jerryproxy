"""Assemble the ``backend`` command group and its leaf commands."""

import click
from InquirerPy.base.control import Choice

from .. import _common
from .clean import backend_clean
from .current import backend_current
from .install import backend_install
from .list import backend_list
from .uninstall import backend_uninstall
from .use import backend_use
from .verify import backend_verify
from .which import backend_which

_BACKEND_GROUP_HELP = """Manage installed proxy backend versions and packaged releases.

Run this group without a subcommand for guided operation selection. Complete
subcommands remain deterministic for scripts when every required target and
option is supplied.

\b
Command map:
  list       Inspect installed versions or the packaged release catalog.
  install    Download, verify, install, and optionally activate a release.
  current    Show the version currently selected for each backend.
  use        Select an already installed exact version.
  which      Print a validated immutable executable path.
  verify     Recompute installed executable fingerprints.
  uninstall  Remove installed versions after confirmation.
  clean      Reclaim disposable cache, log, provider, or runtime data.

Catalog commands are offline and reflect the JerryProxy package version.
Upgrade JerryProxy to obtain a newer catalog snapshot.
"""


@click.group(
    "backend",
    invoke_without_command=True,
    help=_BACKEND_GROUP_HELP,
    short_help="Manage backend versions and packaged releases.",
)
@click.pass_context
def backend_group(context):  # type: (click.Context) -> None
    """Manage installed proxy backend versions and packaged releases."""

    if context.invoked_subcommand is not None:
        return
    action = str(
        _common.select(
            "Select a backend operation:",
            [
                Choice("list-known", name="Browse known packaged releases"),
                Choice("install", name="Install or update a backend"),
                Choice("list", name="Show installed versions"),
                Choice("current", name="Show current versions"),
                Choice("use", name="Use an installed version"),
                Choice("which", name="Locate an installed executable"),
                Choice("verify", name="Verify installed backends"),
                Choice("uninstall", name="Uninstall backend versions"),
                Choice("clean", name="Clean disposable backend data"),
            ],
        )
    )
    command_name = "list" if action == "list-known" else action
    arguments = ["known"] if action == "list-known" else []
    command = backend_group.get_command(context, command_name)
    if command is None:
        raise click.ClickException("interactive backend operation is unavailable: %s" % action)
    with command.make_context(command_name, arguments, parent=context) as command_context:
        command.invoke(command_context)


backend_group.add_command(backend_list)
backend_group.add_command(backend_install)
backend_group.add_command(backend_current)
backend_group.add_command(backend_use)
backend_group.add_command(backend_which)
backend_group.add_command(backend_verify)
backend_group.add_command(backend_uninstall)
backend_group.add_command(backend_clean)


__all__ = ["backend_group"]
