"""The ``subscription validate`` command."""

import click

from . import _common

_HELP = """Validate one stored subscription's immutable source and NodeSet shape without fetching or mutating.

Use `validate NAME` for scripts. Omitting NAME opens a selector in a real TTY;
JSON and non-interactive calls require NAME.
"""


@click.command("validate", help=_HELP, short_help="Validate a subscription.")
@click.argument("name", required=False)
@click.option("--json", "as_json", is_flag=True, help="Emit sanitized JSON.")
@click.pass_context
def subscription_validate(context, name, as_json):
    # type: (click.Context, str, bool) -> None
    """Validate one subscription."""

    name = _common.require_name(context, name, as_json, "validate")
    _common.emit_record(_common.subscriptions(context).validate(name), as_json, include_nodes=False)
