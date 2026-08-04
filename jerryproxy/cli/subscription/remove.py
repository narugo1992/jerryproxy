"""The ``subscription remove`` command."""

import click

from . import _common

_HELP = """Remove one subscription after an explicit dangerous-operation confirmation.

Use -y/--yes only when NAME is complete. Removal never prints or accepts a
source URL and leaves no provider projection behind.

Omit NAME only for an interactive selector followed by the normal confirmation.
JSON requires both an explicit NAME and `-y/--yes`; non-interactive commands
never infer a destructive target.
"""


@click.command("remove", help=_HELP, short_help="Remove a subscription.")
@click.argument("name", required=False)
@click.option("-y", "--yes", is_flag=True, help="Skip the destructive confirmation.")
@click.option("--json", "as_json", is_flag=True, help="Emit sanitized JSON.")
@click.pass_context
def subscription_remove(context, name, yes, as_json):
    # type: (click.Context, str, bool, bool) -> None
    """Remove one subscription."""

    if as_json and not yes:
        raise click.UsageError("--json requires -y/--yes for destructive commands")
    name = _common.require_name(context, name, as_json, "remove")
    if not _common.confirm_dangerous_operation("Remove subscription %s?" % name, yes):
        raise click.ClickException("subscription removal cancelled")
    record = _common.subscriptions(context).remove(name)
    if as_json:
        import json

        click.echo(json.dumps({"name": record.name, "id": record.subscription_id, "removed": True}, sort_keys=True))
    else:
        click.echo("Removed subscription %s." % record.name)
