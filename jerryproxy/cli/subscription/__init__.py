"""Assemble subscription ingestion and inventory commands."""

import click
from InquirerPy.base.control import Choice

from .. import _common as cli_common
from .add import subscription_add
from .list import subscription_list
from .refresh import subscription_refresh
from .remove import subscription_remove
from .replace import subscription_replace
from .show import subscription_show
from .validate import subscription_validate

_HELP = """Store and inspect one bearer subscription without exposing its URL or node credentials.

The subscription group owns bounded source fetching, Base64/plain URI
classification, immutable revision publication, and credential-free inventory.
Run `jerryproxy subscription` without a subcommand for a guided operation menu.
For scripts, use a complete leaf command such as
`add NAME --url-env V2RAY_SUBSCRIPTION`; omitted names are selected only in a
real TTY and are rejected for JSON/non-interactive execution.
All human tables use deterministic tabulate output; `--json` never prints source
URLs, provider bytes, credentials, UUIDs, Reality keys, or short IDs.
"""


@click.group(
    "subscription",
    invoke_without_command=True,
    help=_HELP,
    short_help="Manage private subscription sources.",
)
@click.pass_context
def subscription_group(context):  # type: (click.Context) -> None
    """Manage private subscription sources."""

    if context.invoked_subcommand is not None:
        return
    action = str(
        cli_common.select(
            "Select a subscription operation:",
            [
                Choice("add", name="Add a subscription source"),
                Choice("replace", name="Replace a subscription source"),
                Choice("list", name="List stored subscriptions"),
                Choice("show", name="Show one sanitized subscription"),
                Choice("refresh", name="Refresh a stored remote source"),
                Choice("validate", name="Validate stored subscription state"),
                Choice("remove", name="Remove a subscription"),
            ],
        )
    )
    command = subscription_group.get_command(context, action)
    if command is None:
        raise click.ClickException("interactive subscription operation is unavailable: %s" % action)
    with command.make_context(action, [], parent=context) as command_context:
        command.invoke(command_context)


subscription_group.add_command(subscription_add)
subscription_group.add_command(subscription_replace)
subscription_group.add_command(subscription_list)
subscription_group.add_command(subscription_show)
subscription_group.add_command(subscription_refresh)
subscription_group.add_command(subscription_validate)
subscription_group.add_command(subscription_remove)

__all__ = ["subscription_group"]
