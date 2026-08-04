"""Shared private helpers for JerryProxy command modules."""

import click
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from tabulate import tabulate

from ..backend import BackendManager, iter_backends
from ..home import JerryProxyPaths
from ..subscription import SubscriptionManager


def echo_table(headers, rows):  # type: (list, list) -> None
    """Render a compact human-readable table through tabulate."""

    click.echo(tabulate(rows, headers=headers, tablefmt="plain", disable_numparse=True))


def paths(context):  # type: (click.Context) -> JerryProxyPaths
    return JerryProxyPaths.from_value(context.obj.get("home"))


def manager(context):  # type: (click.Context) -> BackendManager
    return BackendManager(paths(context))


def subscriptions(context):  # type: (click.Context) -> SubscriptionManager
    """Return the public subscription manager for the selected home."""

    return SubscriptionManager(paths(context))


def confirm_dangerous_operation(message, assume_yes):  # type: (str, bool) -> bool
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


def select(message, choices):  # type: (str, list) -> object
    """Run one guided InquirerPy selection for an incomplete command."""

    try:
        return inquirer.select(message=message, choices=choices).execute()
    except EOFError:
        # InquirerPy raises EOFError when an incomplete command has no terminal input.
        raise click.ClickException("interactive selection unavailable; provide complete command arguments")
    except KeyboardInterrupt:
        # InquirerPy reports an interrupted selection as a cancelled command.
        raise click.ClickException("interactive selection cancelled")


def prompt_confirm(message, default=False):  # type: (str, bool) -> bool
    """Collect a non-destructive boolean preference during guided mode."""

    try:
        return bool(inquirer.confirm(message=message, default=default).execute())
    except EOFError:
        # InquirerPy raises EOFError when an incomplete command has no terminal input.
        raise click.ClickException("interactive selection unavailable; provide complete command options")
    except KeyboardInterrupt:
        # InquirerPy reports an interrupted preference prompt as a cancelled command.
        raise click.ClickException("interactive selection cancelled")


def prompt_text(message):  # type: (str) -> str
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


def select_backend(message, names=None):  # type: (str, Optional[Iterable[str]]) -> str
    allowed = set(names) if names is not None else None
    choices = [
        Choice(spec.name, name="%s - %s" % (spec.name, spec.description))
        for spec in iter_backends()
        if allowed is None or spec.name in allowed
    ]
    if not choices:
        raise click.ClickException("no backend matches this interactive operation")
    return str(select(message, choices))


def select_catalog_version(selected_manager, name):
    # type: (BackendManager, str) -> Optional[str]
    versions = selected_manager.compatible_versions(name)
    if not versions:
        raise click.ClickException("no compatible stable version is known for %s" % name)
    choices = [Choice("", name="Latest compatible (%s)" % versions[0].version)]
    choices.extend(Choice(item.version, name=item.version) for item in versions)
    selected = str(select("Select a stable version:", choices))
    return selected or None


def select_installed_version(selected_manager, name, allow_all=False):
    # type: (BackendManager, str, bool) -> str
    inventory = selected_manager.inventory(name)
    installed = inventory.installed
    if not installed:
        raise click.ClickException("no installed versions found for %s" % name)
    current = inventory.active[0] if inventory.active else None
    choices = []
    if allow_all:
        choices.append(Choice("__all__", name="All installed versions"))
    choices.extend(
        Choice(
            item.version,
            name="%s%s" % (item.version, " (current)" if current and current.version == item.version else ""),
        )
        for item in installed
    )
    return str(select("Select an installed version:", choices))


def format_size(size):  # type: (int) -> str
    value = float(size)
    for suffix in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or suffix == "GiB":
            return "%.1f %s" % (value, suffix)
        value /= 1024.0
