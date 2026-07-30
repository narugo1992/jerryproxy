"""The root ``doctor`` command."""

import click

from ..config.meta import __VERSION__
from ..lock import filelock_status
from . import _common


@click.command("doctor")
@click.pass_context
def doctor_command(context):  # type: (click.Context) -> None
    """Inspect local backend, catalog, and lock state."""

    manager = _common.manager(context)
    click.echo("JerryProxy %s" % __VERSION__)
    click.echo("Home: %s" % manager.paths.root)
    click.echo("Platform: %s" % manager.platform_info.key)
    click.echo("Backend catalog: %s" % manager.catalog.generated_at)
    catalog_summary = manager.catalog.summary(manager.platform_info)
    compatible = sum(1 for value in catalog_summary.values() if value["latest"] is not None)
    click.echo("Catalog compatibility: %d/%d backends" % (compatible, len(catalog_summary)))
    lock_status = filelock_status()
    click.echo("File lock: %s - %s" % (lock_status.level, lock_status.detail))
    _common.echo_table(
        ["BACKEND", "RELEASES", "COMPATIBLE", "LATEST"],
        [
            [name, value["releases"], value["compatible"], value["latest"] or "unavailable"]
            for name, value in sorted(catalog_summary.items())
        ],
    )
    inventory = manager.inventory()
    click.echo("Installed backends: %d" % len(inventory.installed))
    active = inventory.active
    click.echo("Active backends: %d" % len(active))
    if active:
        _common.echo_table(
            ["BACKEND", "VERSION", "MODE", "LINK"],
            [[item.name, item.version, item.link_mode, item.link] for item in active],
        )

