"""Assemble the public JerryProxy command tree."""

from pathlib import Path

import click

from ..config.meta import __VERSION__
from ..errors import JerryProxyError
from .backend import backend_group
from .doctor import doctor_command
from .home import home_command
from .self_check import self_check_command

#: Click context settings used by the root command.
CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__VERSION__, prog_name="jerryproxy")
@click.option(
    "--home",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Override JERRYPROXY_HOME and ~/.jerryproxy.",
)
@click.pass_context
def cli(context, home):  # type: (click.Context, Path) -> None
    """Manage proxy backends and JerryProxy runtimes."""

    context.ensure_object(dict)
    context.obj["home"] = str(home) if home is not None else None


cli.add_command(home_command)
cli.add_command(doctor_command)
cli.add_command(self_check_command)
cli.add_command(backend_group)


def main():  # type: () -> int
    """Run the console entry point with concise domain-error handling."""

    try:
        cli(standalone_mode=False)
        return 0
    except click.ClickException as error:
        error.show()
        return error.exit_code
    except JerryProxyError as error:
        click.echo("Error: %s" % error, err=True)
        return 1


__all__ = ["CONTEXT_SETTINGS", "cli", "main"]
