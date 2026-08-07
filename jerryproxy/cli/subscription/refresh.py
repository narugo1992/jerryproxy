"""The ``subscription refresh`` command."""

import click

from . import _common

_HELP = """Refresh one subscription from its privately retained URL.

The old valid generation remains intact when fetching, classification, or
publication fails. The URL is never rendered.

Refreshing also repairs a subscription whose stored nodes no longer match its
source bytes, which can happen after a JerryProxy upgrade changes how the same
bytes are classified. The stored nodes are discarded and rebuilt from the
refetched source, so node identities may change; use `node list NAME` to read
the current ones. A subscription with no saved URL must be replaced instead.

Use `refresh NAME` for scripts. Omitting NAME opens a selector in a real TTY;
JSON and non-interactive calls require NAME.
"""


@click.command("refresh", help=_HELP, short_help="Refresh a subscription.")
@click.argument("name", required=False)
@click.option("--json", "as_json", is_flag=True, help="Emit sanitized JSON.")
@click.pass_context
def subscription_refresh(context, name, as_json):
    # type: (click.Context, str, bool) -> None
    """Refresh one subscription."""

    name = _common.require_name(context, name, as_json, "refresh")
    _common.emit_record(_common.subscriptions(context).refresh(name), as_json)
