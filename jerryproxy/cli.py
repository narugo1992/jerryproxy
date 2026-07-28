"""JerryProxy command-line interface."""

import json
import sys
from pathlib import Path

import click
from tabulate import tabulate

from .backend import BackendManager, get_backend, iter_backends
from .config.meta import __VERSION__
from .errors import JerryProxyError
from .home import JerryProxyPaths
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
    _echo_table(
        ["BACKEND", "RELEASES", "COMPATIBLE", "LATEST"],
        [
            [name, value["releases"], value["available"], value["latest"] or "unavailable"]
            for name, value in sorted(catalog_summary.items())
        ],
    )
    click.echo("Installed backends: %d" % len(manager.list_installed()))
    active = manager.list_active()
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
    """Run isolated local checks and report every detected failure."""

    use_color = ansi_color_enabled(click.get_text_stream("stdout"), requested=color)

    def output(message):
        click.echo(message, color=use_color)

    if run_self_check(_paths(context), output=output, color=use_color):
        raise click.ClickException("self-check failed; inspect the diagnostics above")


@cli.group("backend")
def backend_group():  # type: () -> None
    """Install, inspect, switch, and remove backend versions."""


@backend_group.command("supported")
def backend_supported():  # type: () -> None
    """List backend drivers built into this JerryProxy release."""

    _echo_table(
        ["BACKEND", "UPSTREAM", "DESCRIPTION"],
        [[spec.name, spec.repository, spec.description] for spec in iter_backends()],
    )


def _format_size(size):  # type: (int) -> str
    value = float(size)
    for suffix in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or suffix == "GiB":
            return "%.1f %s" % (value, suffix)
        value /= 1024.0
    return "%d B" % size


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
        "catalog_generated_at": manager.catalog.generated_at,
    }


@backend_group.command("available")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_available(context, as_json):
    # type: (click.Context, bool) -> None
    """Summarize backend availability for the current host."""

    manager = _manager(context)
    records = []
    for spec in manager.supported():
        versions = manager.available(spec.name)
        records.append(
            {
                "backend": spec.name,
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
        ["BACKEND", "LATEST", "AVAILABLE", "CATALOG", "HOST"],
        [
            [
                record["backend"],
                record["latest"] or "unavailable",
                record["available_versions"],
                record["catalog_releases"],
                record["platform"],
            ]
            for record in records
        ],
    )


@backend_group.command("versions")
@click.argument("name")
@click.option("--all-platforms", is_flag=True, help="List stable releases with any verified platform asset.")
@click.option("--limit", type=click.IntRange(min=0), default=20, show_default=True, help="Maximum rows; 0 means all.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_versions(context, name, all_platforms, limit, as_json):
    # type: (click.Context, str, bool, int, bool) -> None
    """List installable stable versions for one backend."""

    manager = _manager(context)
    backend_name = get_backend(name).name
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


@backend_group.command("artifact")
@click.argument("name")
@click.argument("version", required=False)
@click.pass_context
def backend_artifact(context, name, version):
    # type: (click.Context, str, str) -> None
    """Explain the exact artifact automatically selected for this host."""

    manager = _manager(context)
    artifact = manager.resolve_artifact(name, version)
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


@backend_group.command("list")
@click.argument("name", required=False)
@click.pass_context
def backend_list(context, name):  # type: (click.Context, str) -> None
    """List installed backend versions and mark active versions."""

    manager = _manager(context)
    active_versions = {item.name: item.version for item in manager.list_active()}
    installed = manager.list_installed(name=name)
    if not installed:
        click.echo("No backend versions installed.")
        return
    _echo_table(
        ["ACTIVE", "BACKEND", "VERSION", "EXECUTABLE"],
        [
            ["*" if active_versions.get(item.name) == item.version else "", item.name, item.version, item.executable]
            for item in installed
        ],
    )


@backend_group.command("install")
@click.argument("name")
@click.argument("version", required=False)
@click.option("--activate/--no-activate", default=True, show_default=True)
@click.pass_context
def backend_install(context, name, version, activate):
    # type: (click.Context, str, str, bool) -> None
    """Download, verify, install, and optionally activate a backend release."""

    manager = _manager(context)
    asset = manager.resolve_artifact(name, version)
    click.echo("Selected %s %s for %s" % (asset.backend, asset.version, manager.platform_info.key))
    click.echo("Official asset: %s" % asset.name)
    click.echo("SHA-256: %s" % asset.sha256)
    installed = manager.install(name, version, activate=activate)
    click.echo("Installed: %s %s" % (installed.name, installed.version))
    click.echo("Executable: %s" % installed.executable)
    if activate:
        active = manager.current(installed.name)
        click.echo("Active link: %s (%s)" % (active.link, active.link_mode))


@backend_group.command("update")
@click.argument("name")
@click.pass_context
def backend_update(context, name):  # type: (click.Context, str) -> None
    """Install and activate the newest compatible catalog release."""

    installed = _manager(context).update(name)
    click.echo("Updated and active: %s %s" % (installed.name, installed.version))


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
@click.argument("name")
@click.argument("version")
@click.pass_context
def backend_switch(context, name, version):  # type: (click.Context, str, str) -> None
    """Atomically activate an installed backend version."""

    active = _manager(context).switch(name, version)
    click.echo("Active: %s %s" % (active.name, active.version))
    click.echo("Link: %s (%s)" % (active.link, active.link_mode))


@backend_group.command("current")
@click.argument("name", required=False)
@click.pass_context
def backend_current(context, name):  # type: (click.Context, str) -> None
    """Show one or all active backend versions."""

    manager = _manager(context)
    active = [manager.current(name)] if name else manager.list_active()
    active = [item for item in active if item is not None]
    if not active:
        click.echo("No active backend.")
        return
    _echo_table(
        ["BACKEND", "VERSION", "MODE", "LINK"],
        [[item.name, item.version, item.link_mode, item.link] for item in active],
    )


@backend_group.command("remove")
@click.argument("name")
@click.argument("version")
@click.option("--force", is_flag=True, help="Also deactivate this exact version.")
@click.pass_context
def backend_remove(context, name, version, force):
    # type: (click.Context, str, str, bool) -> None
    """Remove one immutable installed backend version."""

    _manager(context).remove(name, version, force=force)
    click.echo("Removed: %s %s" % (name, version))


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


if __name__ == "__main__":
    sys.exit(main())
