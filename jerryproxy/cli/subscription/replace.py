"""The ``subscription replace`` command."""

import click

from . import _common

_HELP = """Replace one subscription generation while retaining its public subscription identity.

\b
The source forms and secret-handling rules are identical to
`subscription add`. The previous valid generation remains
selected until transport, classification and publication all succeed.
Replacement does not rename the subscription.

Omit NAME only in a real TTY to enter the guided name prompt. JSON and other
non-interactive invocations must provide the exact existing NAME.
When no source option is supplied in guided mode, the same environment, direct
URL, file, and bounded-stdin source wizard is used; environment values remain
hidden and custom names complete against current matching variables.
"""


@click.command("replace", help=_HELP, short_help="Replace a subscription source.")
@click.argument("name", required=False)
@click.option(
    "--url-env",
    "url_env",
    metavar="ENV_NAME",
    help="Read a subscription URL from ENV_NAME (for example V2RAY_SUBSCRIPTION).",
)
@click.option("--url-stdin", is_flag=True, help="Read one bounded URL from stdin.")
@click.option(
    "--file",
    "file_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Read body from a file.",
)
@click.option("--body-stdin", is_flag=True, help="Read a bounded body from stdin.")
@click.option(
    "--format",
    "format_hint",
    type=click.Choice(["auto", "uri-lines"]),
    default="auto",
    show_default=True,
    help="Classify the source as Base64 or plaintext URI lines.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit sanitized JSON.")
@click.pass_context
def subscription_replace(context, name, url_env, url_stdin, file_path, body_stdin, format_hint, as_json):
    # type: (click.Context, str, Optional[str], bool, Optional[str], bool, str, bool) -> None
    """Replace one subscription source."""

    name = _common.prompt_name(name, as_json, "replace")
    source_kind, source_url, body = _common.read_source(
        url_env, file_path, body_stdin, url_stdin, interactive=not as_json
    )
    manager = _common.subscriptions(context)
    if source_kind == "url":
        record = manager.replace(name, source_url, format_hint=format_hint)
    else:
        record = manager.replace(name, body=body, format_hint=format_hint)
    _common.emit_record(record, as_json)
