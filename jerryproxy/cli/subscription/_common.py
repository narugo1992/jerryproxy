"""Private source and output helpers for subscription commands."""

import os
import sys
from pathlib import Path

import click
from InquirerPy import inquirer
from tabulate import tabulate

from ...subscription.transport import MAXIMUM_BODY_BYTES
from .. import _common as cli_common

SOURCE_ENVIRONMENT = "V2RAY_SUBSCRIPTION"


def subscriptions(context):  # type: (click.Context) -> object
    return cli_common.subscriptions(context)


def confirm_dangerous_operation(message, assume_yes):  # type: (str, bool) -> bool
    return cli_common.confirm_dangerous_operation(message, assume_yes)


def emit_record(record, as_json, include_nodes=True):  # type: (object, bool, bool) -> None
    value = record.public(include_nodes=include_nodes)
    if as_json:
        import json

        click.echo(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    click.echo("Subscription: %s" % record.name)
    click.echo("Revision: %s" % record.revision)
    click.echo("Format: %s" % record.format)
    click.echo("Enabled: %s" % ("yes" if record.enabled else "no"))
    click.echo("Nodes: %d" % record.node_count)
    if include_nodes:
        emit_nodes(record.nodes)


def emit_nodes(nodes):  # type: (tuple) -> None
    click.echo(
        tabulate(
            [[node.node_id, node.scheme, node.display] for node in nodes],
            headers=["NODE", "SCHEME", "ENDPOINT"],
            tablefmt="plain",
            disable_numparse=True,
        )
    )


def read_bounded_stdin(maximum_bytes):  # type: (int) -> bytes
    data = sys.stdin.buffer.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise click.UsageError("stdin source exceeds the 8 MiB bound")
    return data


def read_url_stdin():  # type: () -> str
    data = sys.stdin.buffer.readline(8193)
    if len(data) > 8192 and not data.endswith(b"\n"):
        raise click.UsageError("subscription URL exceeds the 8192-byte bound")
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        # Invalid UTF-8 is expected malformed secret input.
        raise click.UsageError("subscription URL is not UTF-8") from error
    if not value:
        raise click.UsageError("subscription URL is empty")
    return value


def read_source(url_env, file_path, body_stdin, url_stdin, interactive=True):
    # type: (bool, object, bool, bool, bool) -> tuple
    selected = sum(bool(item) for item in (url_env, file_path, body_stdin, url_stdin))
    if selected > 1:
        raise click.UsageError("source options are mutually exclusive")
    if url_env:
        value = os.environ.get(SOURCE_ENVIRONMENT)
        if not value:
            raise click.UsageError("environment variable %s is missing" % SOURCE_ENVIRONMENT)
        return "url", value, None
    if url_stdin:
        return "url", read_url_stdin(), None
    if body_stdin:
        return "body", None, read_bounded_stdin(MAXIMUM_BODY_BYTES)
    if file_path is not None:
        file_path = Path(file_path)
        try:
            body = file_path.read_bytes()
        except OSError as error:
            # Source file failures are user-visible input failures.
            raise click.UsageError("cannot read subscription source file") from error
        if len(body) > MAXIMUM_BODY_BYTES:
            raise click.UsageError("subscription source file exceeds the 8 MiB bound")
        return "body", None, body
    if not interactive or not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise click.UsageError("provide --url-env V2RAY_SUBSCRIPTION, --url-stdin, --file, or --body-stdin")
    try:
        value = inquirer.secret(message="Subscription URL:", validate=lambda item: bool(item.strip())).execute()
    except EOFError as error:
        # InquirerPy raises EOFError when a secret prompt has no input stream.
        raise click.UsageError("interactive subscription input unavailable") from error
    except KeyboardInterrupt:
        raise click.UsageError("subscription input cancelled")
    if not value:
        raise click.UsageError("subscription URL is empty")
    return "url", value.strip(), None
