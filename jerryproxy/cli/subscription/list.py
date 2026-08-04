"""The ``subscription list`` command."""

import json

import click
from tabulate import tabulate

from . import _common

_HELP = """List current subscriptions without exposing bearer URLs or node credentials.

An absent home is an empty read and is never initialized. Use --json for a
deterministic array; human output is rendered with tabulate.
"""


@click.command("list", help=_HELP, short_help="List stored subscriptions.")
@click.option("--json", "as_json", is_flag=True, help="Emit a sanitized JSON array.")
@click.pass_context
def subscription_list(context, as_json):
    # type: (click.Context, bool) -> None
    """List current subscriptions."""

    records = _common.subscriptions(context).list()
    values = [record.public(include_nodes=False) for record in records]
    if as_json:
        click.echo(json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    if not values:
        click.echo("No subscriptions stored.")
        return
    click.echo(
        tabulate(
            [
                [
                    value["name"],
                    value["id"],
                    value["format"],
                    value["node_count"],
                    "yes" if value["enabled"] else "no",
                ]
                for value in values
            ],
            headers=["NAME", "ID", "FORMAT", "NODES", "ENABLED"],
            tablefmt="plain",
            disable_numparse=True,
        )
    )
