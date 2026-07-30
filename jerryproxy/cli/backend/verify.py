"""The ``backend verify`` command."""

import json

import click

from .. import _common, _completion

_HELP = """Recompute installed backend executable fingerprints without running them.

\b
Forms:
  jerryproxy backend verify
    Verify every locally installed backend version.
  jerryproxy backend verify NAME
    Verify every installed version of one backend.
  jerryproxy backend verify NAME VERSION
    Verify one exact installed version only.

Verification hashes immutable executable bytes under the home-wide lock. It
does not execute a backend, read the release catalog, or make a network
request. Exact verification ignores unrelated installed versions. Missing or
tampered state exits nonzero.

Human output is a fingerprint table. --json returns an array containing the
backend, version, executable path, and expected executable SHA-256.

\b
Examples:
  jerryproxy backend verify
  jerryproxy backend verify mihomo
  jerryproxy backend verify mihomo 1.19.29 --json
"""


@click.command("verify", help=_HELP, short_help="Verify installed executable fingerprints.")
@click.argument("name", required=False, shell_complete=_completion.installed_backend)
@click.argument("version", required=False, shell_complete=_completion.installed_version)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_verify(context, name, version, as_json):
    # type: (click.Context, Optional[str], Optional[str], bool) -> None
    """Verify installed executable fingerprints without network access."""

    verified = _common.manager(context).verify(name=name, version=version)
    records = [
        {
            "backend": item.name,
            "version": item.version,
            "executable": str(item.executable),
            "executable_sha256": item.executable_sha256,
        }
        for item in verified
    ]
    if as_json:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    if not records:
        click.echo("No backend versions installed.")
        return
    _common.echo_table(
        ["BACKEND", "VERSION", "EXECUTABLE SHA256"],
        [[record["backend"], record["version"], record["executable_sha256"]] for record in records],
    )
