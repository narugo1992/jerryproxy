"""Assemble subscription ingestion and inventory commands."""

import click

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
Use `add NAME --url-env V2RAY_SUBSCRIPTION` for the normal bootstrap path.
All human tables use deterministic tabulate output; `--json` never prints source
URLs, provider bytes, credentials, UUIDs, Reality keys, or short IDs.
"""


@click.group("subscription", help=_HELP, short_help="Manage private subscription sources.")
@click.pass_context
def subscription_group(context):  # type: (click.Context) -> None
    """Manage private subscription sources."""

    del context


subscription_group.add_command(subscription_add)
subscription_group.add_command(subscription_replace)
subscription_group.add_command(subscription_list)
subscription_group.add_command(subscription_show)
subscription_group.add_command(subscription_refresh)
subscription_group.add_command(subscription_validate)
subscription_group.add_command(subscription_remove)

__all__ = ["subscription_group"]
