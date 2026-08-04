"""Assemble node inventory commands."""

import click

from .list import node_list

_HELP = """Inspect credential-free node identities produced by stored subscriptions.

Node IDs are opaque lower-case hexadecimal identities. They are safe to use in
automation; node credentials and exact URI records never appear in output.
"""


@click.group("node", help=_HELP, short_help="Inspect subscription nodes.")
@click.pass_context
def node_group(context):  # type: (click.Context) -> None
    """Inspect subscription nodes."""

    del context


node_group.add_command(node_list)

__all__ = ["node_group"]
