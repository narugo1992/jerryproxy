"""The ``subscription add`` command."""

import click

from . import _common

_HELP = """Add one bounded V2RAY_SUBSCRIPTION source and publish its sanitized node inventory.

\b
Forms:
  jerryproxy subscription add [NAME] --url-env V2RAY_SUBSCRIPTION
  jerryproxy subscription add [NAME] --url-stdin
  jerryproxy subscription add [NAME] --file BODY
  jerryproxy subscription add [NAME] --body-stdin

If NAME is omitted in a real TTY, InquirerPy asks for it before reading the
source. JSON output, redirected stdin/stdout, and other non-interactive calls
must provide NAME explicitly; the command never invents a state-file name.
When no source option is supplied in guided mode, the wizard offers the exact
`V2RAY_SUBSCRIPTION` environment variable (value hidden), direct secret URL
input, a file path, or bounded stdin. Other environment names are rejected.

The URL is bearer material. It is never placed in argv, output, logs, or child
environment. A URL source is retained only in owner-private state so an
explicit refresh can reuse it; it is never public evidence or CLI output.
Base64-wrapped and plaintext URI lines
for SS, VMess, and VLESS are accepted; provider/native profiles are outside
this first implementation slice. Use --json for deterministic automation.
"""


@click.command("add", help=_HELP, short_help="Add a subscription source.")
@click.argument("name", required=False)
@click.option(
    "--url-env",
    "url_env",
    type=click.Choice([_common.SOURCE_ENVIRONMENT]),
    metavar="V2RAY_SUBSCRIPTION",
    help="Read a subscription URL from the exact V2RAY_SUBSCRIPTION environment variable.",
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
def subscription_add(context, name, url_env, url_stdin, file_path, body_stdin, format_hint, as_json):
    # type: (click.Context, str, Optional[str], bool, Optional[str], bool, str, bool) -> None
    """Add and publish one subscription."""

    name = _common.prompt_name(name, as_json, "add")
    source_kind, source_url, body = _common.read_source(
        url_env, file_path, body_stdin, url_stdin, interactive=not as_json
    )
    manager = _common.subscriptions(context)
    if source_kind == "url":
        record = manager.add(name, source_url, format_hint=format_hint)
    else:
        record = manager.add(name, None, body=body, format_hint=format_hint)
    _common.emit_record(record, as_json)
