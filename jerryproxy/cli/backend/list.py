"""The ``backend list`` command."""

import json

import click
from click.core import ParameterSource

from ...backend import get_backend
from .. import _common, _completion

_HELP = """List installed versions or releases known to this JerryProxy build.

\b
Forms:
  jerryproxy backend list [NAME]
    List every locally installed version, or versions for NAME.
  jerryproxy backend list known [NAME] [VERSION]
    List packaged backend families, releases for NAME, or the exact
    verified artifact for NAME VERSION.

\b
Local inventory:
  The local form reads only managed state below JerryProxy home. Use
  --paths to add immutable executable and current-link paths. It never
  reads the packaged release catalog or makes a network request.

\b
Packaged catalog:
  The known form is offline and never checks GitHub. It reads stable
  release metadata shipped with this JerryProxy version.
  --all-platforms applies only to NAME release lists. --limit 0 shows
  every row; JSON returns every record unless --limit was explicitly
  supplied.

\b
Output:
  Human output uses compact tables. --json returns arrays for overview
  and release lists; exact artifact lookup returns one object. A
  targeted missing or invalid query exits nonzero.

\b
Examples:
  jerryproxy backend list
  jerryproxy backend list mihomo --paths
  jerryproxy backend list known
  jerryproxy backend list known mihomo --limit 10
  jerryproxy backend list known mihomo 1.19.29 --json
"""


def _known_record(manager, version, artifact):
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


def _parse_query(query):  # type: (tuple) -> tuple
    if not query:
        return "installed", None, None
    if query[0] != "known":
        if len(query) != 1:
            raise click.UsageError("local list accepts at most one backend NAME")
        return "installed", query[0], None
    if len(query) > 3:
        raise click.UsageError("list known accepts at most NAME and VERSION")
    name = query[1] if len(query) >= 2 else None
    version = query[2] if len(query) == 3 else None
    return "known", name, version


def _list_inventory(manager, name, show_paths, as_json):
    inventory = manager.inventory(name)
    current_by_name = {item.name: item for item in inventory.active}
    records = []
    for item in inventory.installed:
        current = current_by_name.get(item.name)
        selected = current is not None and current.version == item.version
        records.append(
            {
                "current": selected,
                "backend": item.name,
                "version": item.version,
                "mode": current.link_mode if selected else None,
                "executable": str(item.executable),
                "link": str(current.link) if selected else None,
            }
        )
    if as_json:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    if not records:
        click.echo("No backend versions installed.")
        return
    if show_paths:
        _common.echo_table(
            ["CURRENT", "BACKEND", "VERSION", "MODE", "EXECUTABLE", "LINK"],
            [
                [
                    "*" if record["current"] else "",
                    record["backend"],
                    record["version"],
                    record["mode"] or "",
                    record["executable"],
                    record["link"] or "",
                ]
                for record in records
            ],
        )
        return
    _common.echo_table(
        ["CURRENT", "BACKEND", "VERSION", "MODE"],
        [
            ["*" if record["current"] else "", record["backend"], record["version"], record["mode"] or ""]
            for record in records
        ],
    )


def _list_known(manager, name, version, all_platforms, limit, limit_explicit, as_json):
    if name is None:
        if all_platforms:
            raise click.UsageError("--all-platforms requires a backend NAME")
        if limit_explicit:
            raise click.UsageError("--limit requires a backend NAME")
        records = []
        for spec in manager.supported():
            versions = manager.compatible_versions(spec.name)
            records.append(
                {
                    "backend": spec.name,
                    "upstream": spec.repository,
                    "description": spec.description,
                    "latest": versions[0].version if versions else None,
                    "compatible_versions": len(versions),
                    "catalog_versions": len(manager.catalog.versions(spec.name)),
                    "platform": manager.platform_info.asset_key,
                    "catalog_generated_at": manager.catalog.generated_at,
                }
            )
        if as_json:
            click.echo(json.dumps(records, indent=2, sort_keys=True))
            return
        click.echo("Packaged catalog snapshot: %s" % manager.catalog.generated_at)
        _common.echo_table(
            ["BACKEND", "LATEST", "COMPATIBLE", "CATALOG", "HOST", "UPSTREAM"],
            [
                [
                    record["backend"],
                    record["latest"] or "unavailable",
                    record["compatible_versions"],
                    record["catalog_versions"],
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
        if limit_explicit:
            raise click.UsageError("--limit cannot be combined with VERSION")
        artifact = manager.resolve_artifact(backend_name, version)
        catalog_version = next(
            item for item in manager.catalog.versions(backend_name) if item.version == artifact.version
        )
        record = _known_record(manager, catalog_version, artifact)
        if as_json:
            click.echo(json.dumps(record, indent=2, sort_keys=True))
            return
        click.echo("Packaged catalog snapshot: %s" % manager.catalog.generated_at)
        click.echo("Backend: %s" % artifact.backend)
        click.echo("Version: %s" % artifact.version)
        click.echo("Host: %s" % manager.platform_info.key)
        click.echo("Catalog target: %s" % artifact.platform)
        click.echo("Asset: %s" % artifact.name)
        click.echo("Size: %d (%s)" % (artifact.size, _common.format_size(artifact.size)))
        click.echo("SHA-256: %s" % artifact.sha256)
        click.echo("URL: %s" % artifact.url)
        click.echo("Selection: exact OS/architecture match; integrity source: %s" % artifact.verification)
        return
    records = []
    if all_platforms:
        for catalog_version in manager.catalog.versions(backend_name):
            verified = [artifact for artifact in catalog_version.artifacts.values() if artifact.verified]
            if verified:
                records.append(
                    {
                        "backend": backend_name,
                        "version": catalog_version.version,
                        "published_at": catalog_version.published_at,
                        "platforms": len(verified),
                        "catalog_generated_at": manager.catalog.generated_at,
                    }
                )
    else:
        for catalog_version in manager.compatible_versions(backend_name):
            records.append(
                _known_record(manager, catalog_version, catalog_version.artifact_for(manager.platform_info))
            )
    total = len(records)
    effective_limit = limit if limit_explicit or not as_json else 0
    if effective_limit:
        records = records[:effective_limit]
    if as_json:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    click.echo("Packaged catalog snapshot: %s" % manager.catalog.generated_at)
    if not records:
        click.echo("No verified stable versions known.")
        return
    if all_platforms:
        _common.echo_table(
            ["VERSION", "PLATFORMS", "PUBLISHED"],
            [[record["version"], record["platforms"], record["published_at"]] for record in records],
        )
    else:
        _common.echo_table(
            ["VERSION", "TARGET", "SIZE", "ASSET", "SHA256"],
            [
                [
                    record["version"],
                    record["platform"],
                    _common.format_size(record["size"]),
                    record["asset"],
                    record["sha256"][:12],
                ]
                for record in records
            ],
        )
    if len(records) < total:
        click.echo("Showing %d of %d; use --limit 0 for all." % (len(records), total))


@click.command("list", help=_HELP, short_help="List installed or known backend versions.")
@click.argument("query", nargs=-1, shell_complete=_completion.list_query)
@click.option("--paths", "show_paths", is_flag=True, help="Include executable and current-link paths.")
@click.option("--all-platforms", is_flag=True, help="List stable releases with any verified platform asset.")
@click.option(
    "--limit",
    type=click.IntRange(min=0),
    default=20,
    show_default=True,
    help="Maximum rows; 0 means all.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def backend_list(context, query, show_paths, all_platforms, limit, as_json):
    # type: (click.Context, tuple, bool, bool, int, bool) -> None
    """List local installations or stable releases known to JerryProxy."""

    mode, name, version = _parse_query(query)
    limit_explicit = context.get_parameter_source("limit") != ParameterSource.DEFAULT
    if mode == "installed":
        if all_platforms or limit_explicit:
            raise click.UsageError("--all-platforms and --limit require the 'list known' form")
        _list_inventory(_common.manager(context), name, show_paths, as_json)
        return
    if show_paths:
        raise click.UsageError("--paths applies only to the local 'list [NAME]' form")
    _list_known(
        _common.manager(context),
        name,
        version,
        all_platforms,
        limit,
        limit_explicit,
        as_json,
    )
