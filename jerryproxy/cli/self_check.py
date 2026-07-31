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

    Backend install, use, verify, and uninstall are exercised in isolated
    temporary homes. Spawned child processes hard-exit during install,
    activation, and removal transactions so rollback and rollforward recovery
    are verified without changing the configured JerryProxy home.

    Relay checks stream and verify a fixed 1 MiB Range from a pinned GitHub
    Release asset with 5-second connect/read timeouts. A parent process enforces
    a 30-second total probe deadline across startup, redirects, response
    headers, empty chunks, and streaming. Response-header latency, latency to
    the first chunk, and subsequent stream speed are reported separately. Relay
    failures are WARN results. A platform or runtime without a meaningful
    prerequisite reports a cyan SKIP. WARN and SKIP keep a zero exit code; only
    FAIL or ERR produce a nonzero exit code. ERR results include bounded,
    redacted traceback or child-process diagnostics when available.
    """

    use_color = ansi_color_enabled(click.get_text_stream("stdout"), requested=color)

    def output(message):
        click.echo(message, color=use_color)

    if run_self_check(_common.paths(context), output=output, color=use_color):
        raise click.ClickException("self-check failed; inspect the diagnostics above")
