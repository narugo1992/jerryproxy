"""JerryProxy command-line interface."""

import json
from pathlib import Path

import click
from click.core import ParameterSource
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from tabulate import tabulate

from .backend import BackendManager, get_backend, iter_backends
from .backend.relay import ALLOWED_PATTERNS, iter_builtin_relays
from .config.meta import __VERSION__
from .errors import JerryProxyError
from .home import JerryProxyPaths
from .lock import filelock_status
from .selfcheck import ansi_color_enabled, run_self_check

#: Click context settings used by the root command.
CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def _echo_table(headers, rows):  # type: (list, list) -> None
    """Render a compact human-readable table through tabulate."""
    click.echo(tabulate(rows, headers=headers, tablefmt="plain", disable_numparse=True))


def _paths(context):  # type: (click.Context) -> JerryProxyPaths
    return JerryProxyPaths.from_value(context.obj.get("home"))


def _manager(context):  # type: (click.Context) -> BackendManager
    return BackendManager(_paths(context))


def _confirm_dangerous_operation(message, assume_yes):  # type: (str, bool) -> bool
    """Confirm a destructive command through the same TUI used by v2raycli."""
    if assume_yes:
        return True
    try:
        return bool(inquirer.confirm(message=message, default=False).execute())
    except EOFError:
        # InquirerPy raises EOFError when no interactive input stream is available.
        raise click.ClickException("interactive confirmation unavailable; rerun with --yes")
    except KeyboardInterrupt:
        # InquirerPy reports an interrupted prompt as a cancelled operation.
        return False


def _select(message, choices):  # type: (str, list) -> object
    """Run one guided InquirerPy selection for an incomplete command."""
    try:
        return inquirer.select(message=message, choices=choices).execute()
    except EOFError:
        # InquirerPy raises EOFError when an incomplete command has no terminal input.
        raise click.ClickException("interactive selection unavailable; provide complete command arguments")
    except KeyboardInterrupt:
        # InquirerPy reports an interrupted selection as a cancelled command.
        raise click.ClickException("interactive selection cancelled")


def _prompt_confirm(message, default=False):  # type: (str, bool) -> bool
    """Collect a non-destructive boolean preference during guided mode."""
    try:
        return bool(inquirer.confirm(message=message, default=default).execute())
    except EOFError:
        # InquirerPy raises EOFError when an incomplete command has no terminal input.
        raise click.ClickException("interactive selection unavailable; provide complete command options")
    except KeyboardInterrupt:
        # InquirerPy reports an interrupted preference prompt as a cancelled command.
        raise click.ClickException("interactive selection cancelled")


def _prompt_text(message):  # type: (str) -> str
    """Collect one required text value during guided mode."""

    try:
        value = str(inquirer.text(message=message).execute()).strip()
    except EOFError:
        # InquirerPy raises EOFError when an incomplete command has no terminal input.
        raise click.ClickException("interactive selection unavailable; provide complete command options")
    except KeyboardInterrupt:
        # InquirerPy reports an interrupted preference prompt as a cancelled command.
        raise click.ClickException("interactive selection cancelled")
    if not value:
        raise click.ClickException("interactive selection returned an empty value")
    return value


def _select_install_transport():  # type: () -> tuple
    choices = [
        Choice("auto", name="Auto (default): GitHub, then three built-in relays"),
        Choice("direct", name="Direct GitHub"),
    ]
    choices.extend(Choice(profile.name, name=profile.name) for profile in iter_builtin_relays())
    choices.append(Choice("__custom__", name="Custom HTTPS relay"))
    selected = str(_select("Select download transport:", choices))
    if selected != "__custom__":
        return selected, None, None
    relay_url = _prompt_text("Custom relay URL:")
    pattern = str(
        _select(
            "Select relay URL pattern:",
            [Choice(value, name=value) for value in ALLOWED_PATTERNS],
        )
    )
    return None, relay_url, pattern


def _select_backend(message, names=None):  # type: (str, Optional[Iterable[str]]) -> str
    allowed = set(names) if names is not None else None
    choices = [
        Choice(spec.name, name="%s - %s" % (spec.name, spec.description))
        for spec in iter_backends()
        if allowed is None or spec.name in allowed
    ]
    if not choices:
        raise click.ClickException("no backend matches this interactive operation")
    return str(_select(message, choices))


def _select_catalog_version(manager, name):  # type: (BackendManager, str) -> Optional[str]
    versions = manager.available(name)
    if not versions:
        raise click.ClickException("no compatible stable version is available for %s" % name)
    choices = [Choice("", name="Latest compatible (%s)" % versions[0].version)]
    choices.extend(Choice(item.version, name=item.version) for item in versions)
    selected = str(_select("Select a stable version:", choices))
    return selected or None


def _select_installed_version(manager, name, allow_all=False):
    # type: (BackendManager, str, bool) -> str
    inventory = manager.inventory(name)
    installed = inventory.installed
    if not installed:
        raise click.ClickException("no installed versions found for %s" % name)
    active = inventory.active[0] if inventory.active else None
    choices = []
    if allow_all:
        choices.append(Choice("__all__", name="All installed versions"))
    choices.extend(
        Choice(
            item.version,
            name="%s%s" % (item.version, " (active)" if active and active.version == item.version else ""),
        )
        for item in installed
    )
    return str(_select("Select an installed version:", choices))


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__VERSION__, prog_name="jerryproxy")
@click.option(
    "--home",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help="Override JERRYPROXY_HOME and ~/.jerryproxy.",
)
@click.pass_context
def cli(context, home):  # type: (click.Context, Path) -> None
    """Manage proxy backends and JerryProxy runtimes."""

    context.ensure_object(dict)
    context.obj["home"] = str(home) if home is not None else None


@cli.command("home")
@click.pass_context
def home_command(context):  # type: (click.Context) -> None
    """Print the active JerryProxy home directory."""

    click.echo(str(_paths(context).root))


@cli.command("doctor")
@click.pass_context
def doctor_command(context):  # type: (click.Context) -> None
    """Inspect local platform, home, installed versions, and active links."""

    manager = _manager(context)
    click.echo("JerryProxy %s" % __VERSION__)
    click.echo("Home: %s" % manager.paths.root)
    click.echo("Platform: %s" % manager.platform_info.key)
    click.echo("Backend catalog: %s" % manager.catalog.generated_at)
    catalog_summary = manager.catalog.summary(manager.platform_info)
    compatible = sum(1 for value in catalog_summary.values() if value["latest"] is not None)
    click.echo("Catalog compatibility: %d/%d backends" % (compatible, len(catalog_summary)))
    lock_status = filelock_status()
    click.echo("File lock: %s - %s" % (lock_status.level, lock_status.detail))
    _echo_table(
        ["BACKEND", "RELEASES", "COMPATIBLE", "LATEST"],
        [
            [name, value["releases"], value["available"], value["latest"] or "unavailable"]
            for name, value in sorted(catalog_summary.items())
        ],
    )
    inventory = manager.inventory()
    click.echo("Installed backends: %d" % len(inventory.installed))
    active = inventory.active
    click.echo("Active backends: %d" % len(active))
    if active:
        _echo_table(
            ["BACKEND", "VERSION", "MODE", "LINK"],
            [[item.name, item.version, item.link_mode, item.link] for item in active],
        )


@cli.command("self-check")
@click.option(
    "--color/--no-color",
    default=None,
    help="Override automatic ANSI color detection.",
)
@click.pass_context
def self_check_command(context, color):  # type: (click.Context, bool) -> None
    """Check local state plus bounded availability of built-in relays.

    Relay checks stream and verify a fixed 1 MiB Range from a pinned GitHub
    Release asset with a 5-second network timeout. Response-header latency,
    latency to the first chunk, and subsequent stream speed are reported
    separately.
    Relay failures are WARN results; only local FAIL or ERR results produce a
    nonzero exit code.
    """

    use_color = ansi_color_enabled(click.get_text_stream("stdout"), requested=color)

    def output(message):
        click.echo(message, color=use_color)

    if run_self_check(_paths(context), output=output, color=use_color):
        raise click.ClickException("self-check failed; inspect the diagnostics above")


@cli.group("backend", invoke_without_command=True)
@click.pass_context
def backend_group(context):  # type: (click.Context) -> None
    """Install, inspect, switch, and remove backend versions."""

    if context.invoked_subcommand is not None:
        return
    action = str(
        _select(
            "Select a backend operation:",
            [
                Choice("available", name="Browse available releases"),
                Choice("install", name="Install or update a backend"),
                Choice("list", name="Show installed and active versions"),
                Choice("switch", name="Switch the active version"),
                Choice("verify", name="Verify installed backends"),
                Choice("remove", name="Remove installed backends"),
                Choice("clean", name="Clean disposable backend data"),
            ],
        )
    )
    command = backend_group.get_command(context, action)
    if command is None:
        raise click.ClickException("interactive backend operation is unavailable: %s" % action)
    with command.make_context(action, [], parent=context) as command_context:
        command.invoke(command_context)


def _format_size(size):  # type: (int) -> str
    value = float(size)
    for suffix in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or suffix == "GiB":
            return "%.1f %s" % (value, suffix)
        value /= 1024.0


def _available_record(manager, version, artifact):
    return {
        "backend": version.backend,
        "version": version.version,
        "published_at": version.published_at,
        "platform": artifact.platform,
        "asset": artifact.name,
        "url": artifact.url,
        "size": artifact.size,
        "sha256": artifact.sha256,
        "verification": artifact.verification,
        "catalog_generated_at": manager.catalog.generated_at,
    }


@backend_group.command("available")
@click.argument("name", required=False)
@click.argument("version", required=False)
@click.option("--all-platforms", is_flag=True, help="List stable releases with any verified platform asset.")
@click.option("--limit", type=click.IntRange(min=0), default=20, show_default=True, help="Maximum rows; 0 means all.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_available(context, name, version, all_platforms, limit, as_json):
    # type: (click.Context, Optional[str], Optional[str], bool, int, bool) -> None
    """Browse supported backends, stable versions, or one exact artifact."""

    manager = _manager(context)
    if name is None:
        if all_platforms:
            raise click.UsageError("--all-platforms requires a backend NAME")
        records = []
        for spec in manager.supported():
            versions = manager.available(spec.name)
            records.append(
                {
                    "backend": spec.name,
                    "upstream": spec.repository,
                    "description": spec.description,
                    "latest": versions[0].version if versions else None,
                    "available_versions": len(versions),
                    "catalog_releases": len(manager.catalog.versions(spec.name)),
                    "platform": manager.platform_info.asset_key,
                    "catalog_generated_at": manager.catalog.generated_at,
                }
            )
        if as_json:
            click.echo(json.dumps(records, indent=2, sort_keys=True))
            return
        click.echo("Catalog snapshot: %s" % manager.catalog.generated_at)
        _echo_table(
            ["BACKEND", "LATEST", "AVAILABLE", "CATALOG", "HOST", "UPSTREAM"],
            [
                [
                    record["backend"],
                    record["latest"] or "unavailable",
                    record["available_versions"],
                    record["catalog_releases"],
                    record["platform"],
                    record["upstream"],
                ]
                for record in records
            ],
        )
        return
    backend_name = get_backend(name).name
    if version is not None:
        if all_platforms:
            raise click.UsageError("--all-platforms cannot be combined with VERSION")
        artifact = manager.resolve_artifact(backend_name, version)
        catalog_version = next(
            item for item in manager.catalog.versions(backend_name) if item.version == artifact.version
        )
        record = _available_record(manager, catalog_version, artifact)
        if as_json:
            click.echo(json.dumps(record, indent=2, sort_keys=True))
            return
        click.echo("Catalog snapshot: %s" % manager.catalog.generated_at)
        click.echo("Backend: %s" % artifact.backend)
        click.echo("Version: %s" % artifact.version)
        click.echo("Host: %s" % manager.platform_info.key)
        click.echo("Catalog target: %s" % artifact.platform)
        click.echo("Asset: %s" % artifact.name)
        click.echo("Size: %d (%s)" % (artifact.size, _format_size(artifact.size)))
        click.echo("SHA-256: %s" % artifact.sha256)
        click.echo("URL: %s" % artifact.url)
        click.echo("Selection: exact OS/architecture match; integrity source: %s" % artifact.verification)
        return

    records = []
    if all_platforms:
        for version in manager.catalog.versions(backend_name):
            verified = [artifact for artifact in version.artifacts.values() if artifact.verified]
            if verified:
                records.append(
                    {
                        "backend": backend_name,
                        "version": version.version,
                        "published_at": version.published_at,
                        "platforms": len(verified),
                        "catalog_generated_at": manager.catalog.generated_at,
                    }
                )
    else:
        for version in manager.available(backend_name):
            records.append(_available_record(manager, version, version.artifact_for(manager.platform_info)))
    if limit:
        records = records[:limit]
    if as_json:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    click.echo("Catalog snapshot: %s" % manager.catalog.generated_at)
    if not records:
        click.echo("No verified stable versions available.")
        return
    if all_platforms:
        _echo_table(
            ["VERSION", "PLATFORMS", "PUBLISHED"],
            [[record["version"], record["platforms"], record["published_at"]] for record in records],
        )
        return
    _echo_table(
        ["VERSION", "TARGET", "SIZE", "ASSET", "SHA256"],
        [
            [
                record["version"],
                record["platform"],
                _format_size(record["size"]),
                record["asset"],
                record["sha256"][:12],
            ]
            for record in records
        ],
    )


@backend_group.command("list")
@click.argument("name", required=False)
@click.option("--active", "active_only", is_flag=True, help="Show only active backend versions.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_list(context, name, active_only, as_json):
    # type: (click.Context, Optional[str], bool, bool) -> None
    """List installed versions and their active-link state."""

    manager = _manager(context)
    inventory = manager.inventory(name)
    active_items = inventory.active
    active_by_name = {item.name: item for item in active_items}
    installed = inventory.installed
    records = []
    for item in installed:
        active = active_by_name.get(item.name)
        selected = active is not None and active.version == item.version
        records.append(
            {
                "active": selected,
                "backend": item.name,
                "version": item.version,
                "mode": active.link_mode if selected else None,
                "executable": str(item.executable),
                "link": str(active.link) if selected else None,
            }
        )
    if active_only:
        records = [record for record in records if record["active"]]
    if as_json:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    if not records:
        click.echo("No active backend." if active_only else "No backend versions installed.")
        return
    _echo_table(
        ["ACTIVE", "BACKEND", "VERSION", "MODE", "EXECUTABLE", "LINK"],
        [
            [
                "*" if record["active"] else "",
                record["backend"],
                record["version"],
                record["mode"] or "",
                record["executable"],
                record["link"] or "",
            ]
            for record in records
        ],
    )


_BACKEND_INSTALL_HELP = """Install a verified backend through GitHub or a release relay.

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


@backend_group.command(
    "install",
    help=_BACKEND_INSTALL_HELP,
    short_help="Install via direct GitHub or a release relay.",
)
@click.argument("name", required=False)
@click.argument("version", required=False)
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
    if relay_url is not None and relay_is_default:
        relay = None
    if relay is not None and relay_url is not None:
        raise click.UsageError("--relay and --relay-url are mutually exclusive")
    if relay_pattern is not None and relay_url is None:
        raise click.UsageError("--relay-pattern requires --relay-url")
    manager = _manager(context)
    if name is None:
        name = _select_backend("Select a backend to install:")
        version = _select_catalog_version(manager, name)
        if relay_is_default and relay_url is None:
            relay, relay_url, relay_pattern = _select_install_transport()
        activate = _prompt_confirm("Activate this version after installation?", default=activate)
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
        active = manager.current(installed.name)
        click.echo("Active link: %s (%s)" % (active.link, active.link_mode))


@backend_group.command("verify")
@click.argument("name", required=False)
@click.pass_context
def backend_verify(context, name):  # type: (click.Context, str) -> None
    """Verify installed executable fingerprints without network access."""

    verified = _manager(context).verify(name=name)
    if not verified:
        click.echo("No backend versions installed.")
        return
    _echo_table(
        ["BACKEND", "VERSION", "EXECUTABLE SHA256"],
        [[item.name, item.version, item.executable_sha256] for item in verified],
    )


@backend_group.command("switch")
@click.argument("name", required=False)
@click.argument("version", required=False)
@click.pass_context
def backend_switch(context, name, version):
    # type: (click.Context, Optional[str], Optional[str]) -> None
    """Atomically activate an installed backend version."""

    manager = _manager(context)
    if name is None:
        installed_names = {item.name for item in manager.list_installed()}
        name = _select_backend("Select an installed backend:", installed_names)
    if version is None:
        version = _select_installed_version(manager, name)
    active = manager.switch(name, version)
    click.echo("Active: %s %s" % (active.name, active.version))
    click.echo("Link: %s (%s)" % (active.link, active.link_mode))


@backend_group.command("remove")
@click.argument("name", required=False)
@click.argument("version", required=False)
@click.option("-A", "--all", "all_versions", is_flag=True, help="Remove every installed version of this backend.")
@click.option("--force", is_flag=True, help="Also deactivate this exact version.")
@click.option("--downloads", is_flag=True, help="Also remove matching cached release downloads.")
@click.option("-y", "--yes", is_flag=True, help="Skip the destructive-operation confirmation.")
@click.pass_context
def backend_remove(context, name, version, all_versions, force, downloads, yes):
    # type: (click.Context, Optional[str], Optional[str], bool, bool, bool, bool) -> None
    """Remove one or all immutable installed backend versions."""

    manager = _manager(context)
    guided = name is None or (version is None and not all_versions)
    if name is None:
        installed_names = {item.name for item in manager.list_installed()}
        name = _select_backend("Select a backend to remove:", installed_names)
    if version is not None and all_versions:
        raise click.UsageError("provide VERSION or -A/--all, but not both")
    if version is None and not all_versions:
        selected = _select_installed_version(manager, name, allow_all=True)
        if selected == "__all__":
            all_versions = True
        else:
            version = selected
    if guided and not downloads:
        downloads = _prompt_confirm("Also remove matching cached downloads?", default=False)
    if all_versions and force:
        raise click.UsageError("--force only applies to one exact VERSION")
    if guided and not all_versions:
        active = manager.current(name)
        if active is not None and active.version == version:
            force = True
    target = "%s (all installed versions)" % name if all_versions else "%s %s" % (name, version)
    extras = " and matching downloads" if downloads else ""
    if not _confirm_dangerous_operation("Remove %s%s?" % (target, extras), yes):
        click.echo("Cancelled.")
        return

    if all_versions:
        result = manager.remove_all(name, downloads=downloads)
    else:
        result = manager.remove(name, version, force=force, downloads=downloads)
    versions = ", ".join(result.versions) if result.versions else "none"
    click.echo("Removed %s installed version(s): %s" % (len(result.versions), versions))
    if downloads:
        click.echo(
            "Cleaned downloads: %d target(s), %s reclaimed"
            % (result.cleanup.targets_removed, _format_size(result.cleanup.bytes_reclaimed))
        )


@backend_group.command("clean")
@click.argument("name", required=False)
@click.argument("version", required=False)
@click.option("--downloads", is_flag=True, help="Clean verified release archives (the default area).")
@click.option("--logs", is_flag=True, help="Clean all JerryProxy and backend logs.")
@click.option("--providers", is_flag=True, help="Clean all stored subscription provider data.")
@click.option("--runtimes", is_flag=True, help="Clean all generated runtime data.")
@click.option("-A", "--all", "all_areas", is_flag=True, help="Clean downloads, logs, providers, and runtimes.")
@click.option("-y", "--yes", is_flag=True, help="Skip the destructive-operation confirmation.")
@click.pass_context
def backend_clean(context, name, version, downloads, logs, providers, runtimes, all_areas, yes):
    # type: (click.Context, Optional[str], Optional[str], bool, bool, bool, bool, bool, bool) -> None
    """Reclaim selected disposable data below the JerryProxy home."""

    manager = _manager(context)
    selected = [
        area
        for area, enabled in (
            ("downloads", downloads),
            ("logs", logs),
            ("providers", providers),
            ("runtimes", runtimes),
        )
        if enabled
    ]
    guided = name is None and version is None and not selected and not all_areas
    if guided:
        cleanup_scope = str(
            _select(
                "Select data to clean:",
                [
                    Choice("downloads-version", name="One cached backend version"),
                    Choice("downloads-backend", name="All downloads for one backend"),
                    Choice("downloads", name="All backend downloads"),
                    Choice("logs", name="All logs"),
                    Choice("providers", name="All subscription provider data"),
                    Choice("runtimes", name="All generated runtime data"),
                    Choice("all", name="All disposable JerryProxy data"),
                ],
            )
        )
        if cleanup_scope in ("downloads-version", "downloads-backend"):
            cached = manager.list_cached_versions()
            names = {backend_name for backend_name, versions in cached.items() if versions}
            name = _select_backend("Select a backend cache:", names)
            if cleanup_scope == "downloads-version":
                version = str(
                    _select(
                        "Select a cached version:",
                        [Choice(item, name=item) for item in cached[name]],
                    )
                )
            selected = ["downloads"]
        elif cleanup_scope == "all":
            all_areas = True
        else:
            selected = [cleanup_scope]
    if all_areas and selected:
        raise click.UsageError("-A/--all cannot be combined with individual cleanup areas")
    if name is not None and (all_areas or any(area != "downloads" for area in selected)):
        raise click.UsageError("backend-scoped cleanup can only target downloads")
    if all_areas:
        selected = ["downloads", "logs", "providers", "runtimes"]
    elif not selected:
        selected = ["downloads"]

    if version is not None:
        scope = "%s %s downloads" % (name, version)
    elif name is not None:
        scope = "%s downloads" % name
    else:
        scope = ", ".join(selected)
    if not _confirm_dangerous_operation("Clean %s?" % scope, yes):
        click.echo("Cancelled.")
        return

    result = manager.clean(name=name, version=version, areas=selected)
    click.echo(
        "Cleaned %s: %d target(s), %s reclaimed"
        % (", ".join(result.areas), result.targets_removed, _format_size(result.bytes_reclaimed))
    )


def main():  # type: () -> int
    """Console-script entry point with concise expected-error rendering."""

    try:
        cli.main(standalone_mode=False)
    except JerryProxyError as error:
        # JerryProxyError is the documented domain boundary for expected user failures.
        click.echo("Error: %s" % error, err=True)
        return 1
    except click.ClickException as error:
        # ClickException is the documented parse/usage error emitted by Click commands.
        error.show()
        return error.exit_code
    return 0
