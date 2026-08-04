"""The ``subscription show`` command."""

import click

from . import _common

_HELP = """Show one subscription's sanitized metadata and node identities.

The source URL, source bytes, credentials, UUIDs, Reality keys, and short IDs
are intentionally absent from both human and JSON output.

Use `show NAME` for scripts. Omitting NAME opens a sanitized subscription
selector in a real TTY; JSON and non-interactive calls require NAME.
"""


@click.command("show", help=_HELP, short_help="Show one subscription.")
@click.argument("name", required=False)
@click.option("--json", "as_json", is_flag=True, help="Emit sanitized JSON.")
@click.pass_context
def subscription_show(context, name, as_json):
    # type: (click.Context, str, bool) -> None
    """Show one subscription."""

    name = _common.require_name(context, name, as_json, "show")
    _common.emit_record(_common.subscriptions(context).get(name), as_json)
