"""Private source and output helpers for subscription commands."""

import os
import sys
from pathlib import Path

import click
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from tabulate import tabulate

from ...subscription.transport import MAXIMUM_BODY_BYTES
from .. import _common as cli_common

SOURCE_ENVIRONMENT = "V2RAY_SUBSCRIPTION"
def discover_source_environments():  # type: () -> tuple
    """Return matching current environment names without exposing values."""

    return (SOURCE_ENVIRONMENT,) if SOURCE_ENVIRONMENT in os.environ else ()


def _validate_environment_name(name):  # type: (str) -> str
    """Accept only the canonical, present, nonempty source environment."""

    if name != SOURCE_ENVIRONMENT:
        raise click.UsageError("environment name must be V2RAY_SUBSCRIPTION")
    if not os.environ.get(name):
        raise click.UsageError("environment variable %s is missing or empty" % name)
    return name


def subscriptions(context):  # type: (click.Context) -> object
    return cli_common.subscriptions(context)


def require_name(context, name, as_json, operation):  # type: (click.Context, object, bool, str) -> str
    """Resolve an omitted subscription name only through an interactive TUI."""

    if name is not None:
        return name
    if as_json or not cli_common.interactive_available():
        raise click.UsageError(
            "NAME is required for subscription %s in non-interactive mode; "
            "provide the exact subscription name" % operation
        )
    return cli_common.select_subscription(context, "Select a subscription to %s:" % operation)


def prompt_name(name, as_json, operation):  # type: (object, bool, str) -> str
    """Collect a new subscription name when an add/replace command is guided."""

    if name is not None:
        return name
    if as_json or not cli_common.interactive_available():
        raise click.UsageError(
            "NAME is required for subscription %s in non-interactive mode; "
            "provide the exact subscription name" % operation
        )
    return cli_common.prompt_text("Subscription name:")


def _prompt_environment():  # type: () -> str
    names = discover_source_environments()
    if not names:
        raise click.UsageError("no matching subscription environment variables are set")
    status = "set; value hidden" if os.environ.get(SOURCE_ENVIRONMENT) else "empty"
    choices = [Choice(SOURCE_ENVIRONMENT, name="%s (%s)" % (SOURCE_ENVIRONMENT, status))]
    selected = str(cli_common.select("Select a subscription environment:", choices))
    selected = _validate_environment_name(selected)
    return os.environ[selected]


def _prompt_source():  # type: () -> tuple
    selected = str(
        cli_common.select(
            "Select how to load the subscription source:",
            [
                Choice("env", name="Environment variable (discover matching names)"),
                Choice("url", name="Enter a subscription URL directly"),
                Choice("file", name="Read a local subscription body file"),
                Choice("body-stdin", name="Read a bounded body from stdin"),
            ],
        )
    )
    if selected == "env":
        return "url", _prompt_environment(), None
    if selected == "url":
        try:
            value = inquirer.secret(
                message="Subscription URL:",
                validate=lambda item: bool(item.strip()),
            ).execute()
        except EOFError as error:
            # InquirerPy raises EOFError when a secret prompt has no input stream.
            raise click.UsageError("interactive subscription input unavailable") from error
        except KeyboardInterrupt:
            raise click.UsageError("subscription input cancelled")
        if not value:
            raise click.UsageError("subscription URL is empty")
        return "url", str(value).strip(), None
    if selected == "file":
        file_path = cli_common.prompt_text("Subscription body file:")
        path = Path(file_path)
        try:
            body = path.read_bytes()
        except OSError as error:
            # Source file failures are user-visible input failures.
            raise click.UsageError("cannot read subscription source file") from error
        if len(body) > MAXIMUM_BODY_BYTES:
            raise click.UsageError("subscription source file exceeds the 8 MiB bound")
        return "body", None, body
    click.echo("Paste the bounded subscription body, then finish stdin (Ctrl-D/Ctrl-Z).")
    return "body", None, read_bounded_stdin(MAXIMUM_BODY_BYTES)


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
    maximum = 16 * 1024
    data = sys.stdin.buffer.readline(maximum + 2)
    if data.endswith(b"\n"):
        data = data[:-1]
        if data.endswith(b"\r"):
            data = data[:-1]
    if len(data) > maximum:
        raise click.UsageError("subscription URL exceeds the 16 KiB bound")
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        # Invalid UTF-8 is expected malformed secret input.
        raise click.UsageError("subscription URL is not UTF-8") from error
    if not value:
        raise click.UsageError("subscription URL is empty")
    return value


def read_source(url_env, file_path, body_stdin, url_stdin, interactive=True):
    # type: (object, object, bool, bool, bool) -> tuple
    selected = sum(bool(item) for item in (url_env, file_path, body_stdin, url_stdin))
    if selected > 1:
        raise click.UsageError("source options are mutually exclusive")
    if url_env:
        selected = _validate_environment_name(str(url_env))
        value = os.environ[selected]
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
    if not interactive or not cli_common.interactive_available():
        raise click.UsageError("provide --url-env V2RAY_SUBSCRIPTION, --url-stdin, --file, or --body-stdin")
    return _prompt_source()
