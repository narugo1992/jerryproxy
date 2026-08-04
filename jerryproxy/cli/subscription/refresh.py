"""The ``subscription refresh`` command."""

import click

from . import _common

_HELP = """Refresh one subscription from its privately retained URL.

The old valid generation remains intact when fetching, classification, or
publication fails. The URL is never rendered.
"""


@click.command("refresh", help=_HELP, short_help="Refresh a subscription.")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Emit sanitized JSON.")
@click.pass_context
def subscription_refresh(context, name, as_json):
    # type: (click.Context, str, bool) -> None
    """Refresh one subscription."""

    _common.emit_record(_common.subscriptions(context).refresh(name), as_json)
