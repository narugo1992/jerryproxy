"""The root ``self-check`` command."""

import click

from ..selfcheck import ansi_color_enabled, run_self_check
from . import _common


@click.command("self-check")
@click.option(
    "--color/--no-color",
    default=None,
    help="Override automatic ANSI color detection.",
)
@click.pass_context
def self_check_command(context, color):  # type: (click.Context, bool) -> None
    """Check local state plus bounded availability of built-in relays.

    Relay checks stream and verify a fixed 1 MiB Range from a pinned GitHub
    Release asset with a 5-second network timeout. Response-header latency,
    latency to the first chunk, and subsequent stream speed are reported
    separately. Relay failures are WARN results; only local FAIL or ERR
    results produce a nonzero exit code.
    """

    use_color = ansi_color_enabled(click.get_text_stream("stdout"), requested=color)

    def output(message):
        click.echo(message, color=use_color)

    if run_self_check(_common.paths(context), output=output, color=use_color):
        raise click.ClickException("self-check failed; inspect the diagnostics above")

