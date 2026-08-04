"""The ``node list`` command."""

import json

import click
from tabulate import tabulate

from .. import _common

_HELP = """List sanitized nodes from one subscription or from all current subscriptions.

The optional SUBSCRIPTION argument is an exact case-sensitive name. Human
output uses tabulate and JSON output is a deterministic array. No source URL,
credential, UUID, Reality key, short ID, or provider byte is emitted.
"""


@click.command("list", help=_HELP, short_help="List subscription nodes.")
@click.argument("subscription", required=False)
@click.option("--json", "as_json", is_flag=True, help="Emit a sanitized JSON array.")
@click.pass_context
def node_list(context, subscription, as_json):
    # type: (click.Context, Optional[str], bool) -> None
    """List sanitized node identities."""

    manager = _common.subscriptions(context)
    records = [manager.get(subscription)] if subscription else list(manager.list())
    rows = []
    values = []
    for record in records:
        for node in record.nodes:
            value = node.public()
            value["subscription"] = record.name
            values.append(value)
            rows.append([record.name, value["id"], value["scheme"], value["display"]])
    if as_json:
        click.echo(json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    if not rows:
        click.echo("No subscription nodes stored.")
        return
    click.echo(
        tabulate(
            rows,
            headers=["SUBSCRIPTION", "NODE", "SCHEME", "ENDPOINT"],
            tablefmt="plain",
            disable_numparse=True,
        )
    )
