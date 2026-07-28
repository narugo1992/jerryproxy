"""JerryProxy command-line interface."""

import sys
from pathlib import Path

import click

from .backend import BackendManager, get_backend, iter_backends
from .config.meta import __VERSION__
from .errors import JerryProxyError
from .home import JerryProxyPaths
from .selfcheck import run_self_check

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


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
    click.echo("Installed backends: %d" % len(manager.list_installed()))
    active = manager.list_active()
    click.echo("Active backends: %d" % len(active))
    for item in active:
        click.echo("  %s %s -> %s (%s)" % (item.name, item.version, item.link, item.link_mode))


@cli.command("self-check")
@click.pass_context
def self_check_command(context):  # type: (click.Context) -> None
    """Run isolated local checks and report every detected failure."""

    if run_self_check(_paths(context), output=click.echo):
        raise click.ClickException("self-check failed; inspect the diagnostics above")


@cli.group("backend")
def backend_group():  # type: () -> None
    """Install, inspect, switch, and remove backend versions."""


@backend_group.command("supported")
def backend_supported():  # type: () -> None
    """List backend drivers built into this JerryProxy release."""

    click.echo("BACKEND  UPSTREAM              DESCRIPTION")
    for spec in iter_backends():
        click.echo("%-8s %-21s %s" % (spec.name, spec.repository, spec.description))


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
    click.echo("ACTIVE  BACKEND  VERSION  EXECUTABLE")
    for item in installed:
        active_marker = "*" if active_versions.get(item.name) == item.version else ""
        click.echo("%-6s  %-7s  %-7s  %s" % (active_marker, item.name, item.version, item.executable))


@backend_group.command("install")
@click.argument("name")
@click.argument("version")
@click.option("--activate/--no-activate", default=True, show_default=True)
@click.pass_context
def backend_install(context, name, version, activate):
    # type: (click.Context, str, str, bool) -> None
    """Download, verify, install, and optionally activate a backend release."""

    manager = _manager(context)
    spec = get_backend(name)
    asset_name = spec.expected_asset_name(manager.platform_info, version)
    click.echo("Resolving %s %s for %s" % (name, version, manager.platform_info.key))
    click.echo("Expected official asset: %s" % asset_name)
    installed = manager.install(name, version, activate=activate)
    click.echo("Installed: %s %s" % (installed.name, installed.version))
    click.echo("Executable: %s" % installed.executable)
    if activate:
        active = manager.current(installed.name)
        click.echo("Active link: %s (%s)" % (active.link, active.link_mode))


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
    for item in active:
        click.echo("%s %s %s %s" % (item.name, item.version, item.link_mode, item.link))


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
