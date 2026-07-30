"""The ``backend install`` command."""

import click
from click.core import ParameterSource
from InquirerPy.base.control import Choice

from ...backend.relay import ALLOWED_PATTERNS, iter_builtin_relays
from .. import _common, _completion

_HELP = """Install a verified backend through GitHub or a release relay.

\b
Forms:
  jerryproxy backend install
    Select backend, version, transport, and activation in guided mode.
  jerryproxy backend install NAME
    Install the newest compatible stable release in the packaged
    catalog.
  jerryproxy backend install NAME VERSION
    Install one exact catalog release for this host.

Complete NAME forms do not prompt. Installation activates the selected
version by default; --no-activate installs it without changing the current
command. Existing verified installations are reused, while different bytes
for an installed version are rejected.

\b
Relay MODE values for --relay MODE:
  direct
    Request the official GitHub Release asset only. Select this mode
    when no relay contact is acceptable. There is no fallback.
  auto
    Try exactly this order: direct GitHub, gh-proxy.com,
    cdn.akaere.online, then gh.geekertao.top. Continue only after
    a transport failure. This is the default; a custom --relay-url
    is never included.
  gh-proxy.com
    Request only https://gh-proxy.com/URL. Do not try direct GitHub or
    another relay if it fails.
  cdn.akaere.online
    Request only https://cdn.akaere.online/URL. Do not try direct
    GitHub or another relay if it fails.
  gh.geekertao.top
    Request only https://gh.geekertao.top/URL. Do not try direct
    GitHub or another relay if it fails.

\b
Custom relay options:
  --relay-url HTTPS_BASE_URL
    Use one custom relay for this install only. Its base must use
    HTTPS, may include a path prefix, and must not contain
    credentials, a query, or a fragment. A custom relay has no
    automatic fallback.
  --relay-pattern PATTERN
    Select how the official asset URL is appended to HTTPS_BASE_URL.
    It defaults to full_url_path and accepts exactly these values:
    full_url_path
      BASE/https://github.com/OWNER/REPO/releases/download/TAG/ASSET
      Use when the relay expects the complete official URL as a path
      suffix.
    host_path
      BASE/github.com/OWNER/REPO/releases/download/TAG/ASSET
      Use when the relay expects the official host and path without
      https://.
    query_q
      BASE/?q=<percent-encoded-official-URL>
      Use when the relay expects the complete official URL in a q
      parameter.
    BASE means --relay-url after its trailing slash is removed. URL is
    the public official asset URL from JerryProxy's catalog.

\b
Fallback and verification:
  Auto continues after DNS/connection, proxy, TLS, timeout,
  HTTP-status, or response-stream transport failure. URL/redirect
  policy, response-size, integrity, extraction, and filesystem
  failures stop immediately. Every source must deliver the complete
  official byte size and SHA-256.

\b
Privacy boundary:
  A relay can observe the client IP and public release-asset path.
  JerryProxy never sends GitHub credentials, private assets,
  subscription URLs, provider data, or GitHub release API requests
  through a relay.

\b
Constraints:
  --relay and --relay-url are mutually exclusive.
  --relay-pattern requires --relay-url.

\b
Examples:
  jerryproxy backend install mihomo --relay auto
  jerryproxy backend install mihomo --relay gh-proxy.com
  jerryproxy backend install mihomo \\
    --relay-url https://relay.example/prefix
  jerryproxy backend install mihomo \\
    --relay-url https://relay.example --relay-pattern host_path
"""


def _select_transport():  # type: () -> tuple
    choices = [
        Choice("auto", name="Auto (default): GitHub, then three built-in relays"),
        Choice("direct", name="Direct GitHub"),
    ]
    choices.extend(Choice(profile.name, name=profile.name) for profile in iter_builtin_relays())
    choices.append(Choice("__custom__", name="Custom HTTPS relay"))
    selected = str(_common.select("Select download transport:", choices))
    if selected != "__custom__":
        return selected, None, None
    relay_url = _common.prompt_text("Custom relay URL:")
    pattern = str(
        _common.select(
            "Select relay URL pattern:",
            [Choice(value, name=value) for value in ALLOWED_PATTERNS],
        )
    )
    return None, relay_url, pattern


@click.command("install", help=_HELP, short_help="Install or update a verified backend version.")
@click.argument("name", required=False, shell_complete=_completion.supported_backend)
@click.argument("version", required=False, shell_complete=_completion.catalog_version)
@click.option("--activate/--no-activate", default=True, show_default=True)
@click.option(
    "--relay",
    type=click.Choice(["direct", "auto"] + [item.name for item in iter_builtin_relays()]),
    metavar="MODE",
    default="auto",
    show_default=True,
    help="Select one MODE from the complete list above.",
)
@click.option(
    "--relay-url",
    metavar="HTTPS_BASE_URL",
    help=(
        "Use one custom HTTPS relay with no fallback. A path prefix is "
        "allowed; credentials, query, and fragment are rejected."
    ),
)
@click.option(
    "--relay-pattern",
    type=click.Choice(list(ALLOWED_PATTERNS)),
    metavar="PATTERN",
    help=(
        "PATTERN: full_url_path | host_path | query_q. Requires "
        "--relay-url; default: full_url_path. See request forms above."
    ),
)
@click.pass_context
def backend_install(context, name, version, activate, relay, relay_url, relay_pattern):
    # type: (click.Context, Optional[str], Optional[str], bool, Optional[str], Optional[str], Optional[str]) -> None
    """Install one verified backend release through the selected transport."""

    relay_is_default = context.get_parameter_source("relay") == ParameterSource.DEFAULT
    activate_is_default = context.get_parameter_source("activate") == ParameterSource.DEFAULT
    if relay_url is not None and relay_is_default:
        relay = None
    if relay is not None and relay_url is not None:
        raise click.UsageError("--relay and --relay-url are mutually exclusive")
    if relay_pattern is not None and relay_url is None:
        raise click.UsageError("--relay-pattern requires --relay-url")
    manager = _common.manager(context)
    if name is None:
        name = _common.select_backend("Select a backend to install:")
        version = _common.select_catalog_version(manager, name)
        if relay_is_default and relay_url is None:
            relay, relay_url, relay_pattern = _select_transport()
        if activate_is_default:
            activate = _common.prompt_confirm(
                "Activate this version after installation?",
                default=activate,
            )
    asset = manager.resolve_artifact(name, version)
    click.echo("Selected %s %s for %s" % (asset.backend, asset.version, manager.platform_info.key))
    click.echo("Official asset: %s" % asset.name)
    click.echo("SHA-256: %s" % asset.sha256)
    transport = relay or ("custom relay (%s)" % (relay_pattern or "full_url_path") if relay_url else "direct")
    click.echo("Transport: %s" % transport)
    installed = manager.install(
        name,
        version,
        activate=activate,
        relay=relay,
        relay_url=relay_url,
        relay_pattern=relay_pattern,
    )
    click.echo("Installed: %s %s" % (installed.name, installed.version))
    click.echo("Executable: %s" % installed.executable)
    if activate:
        current = manager.current(installed.name)
        click.echo("Current link: %s (%s)" % (current.link, current.link_mode))
