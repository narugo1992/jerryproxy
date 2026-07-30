"""The root ``home`` command."""

import click

from . import _common


@click.command("home")
@click.pass_context
def home_command(context):  # type: (click.Context) -> None
    """Print the active JerryProxy home directory."""

    click.echo(str(_common.paths(context).root))

