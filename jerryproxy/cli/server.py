"""The synchronous foreground ``server`` command."""

import json

import click

from ..backend.relay import ALLOWED_PATTERNS, iter_builtin_relays
from ..errors import BackendNotInstalledError, RuntimeSessionError
from ..runtime import QUALIFIED_VERSION, RecoveryPolicy, RuntimeSession
from . import _common

_BACKENDS = ("mihomo", "sing-box", "xray", "v2ray")
_HELP = """Run one authenticated loopback proxy synchronously in the foreground.

The server command selects one stored subscription and one explicit node, then
launches the exact Mihomo backend through BackendManager. It never changes the
backend active link, starts a daemon, or exposes a controller. Press Ctrl+C to
stop and remove the session projection. After readiness it probes a quorum of
stable global HTTPS targets through the authenticated listener. Two consecutive
failed quorums trigger the fixed recovery policy: restart the current node once,
try eligible alternate nodes in public-ID order, then refresh the stored source
once when policy permits. Automatic failover never rewrites the saved node
preference. The bearer URL, credentials, UUIDs, Reality keys, and backend raw
output are never printed.

\b
Forms:
  jerryproxy server --subscription NAME --node NODE_ID
  jerryproxy server --subscription NAME --node NODE_ID
    --install-missing -y
  jerryproxy server --subscription NAME --health-interval 300
    --recovery-deadline 120

`--relay auto` is the default when the exact Mihomo release is missing. Relay
options affect only backend bootstrap and never subscription fetching. Health
and recovery waits are bounded; a failed recovery exits after cleanup.
"""


@click.command("server", help=_HELP, short_help="Run a foreground loopback proxy.")
@click.option(
    "--subscription",
    "subscriptions",
    multiple=True,
    help="Exact subscription name; repeat is rejected in this slice.",
)
@click.option(
    "--backend",
    type=click.Choice(_BACKENDS),
    default="mihomo",
    show_default=True,
    help="Runtime core; only Mihomo is enabled in this slice.",
)
@click.option("--backend-version", default=QUALIFIED_VERSION, show_default=True, help="Exact qualified Mihomo version.")
@click.option("--node", "node_id", help="Exact 32-lowercase-hex node identity.")
@click.option(
    "--install-missing/--no-install-missing",
    default=True,
    show_default=True,
    help="Bootstrap the exact backend when absent.",
)
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR"]), default="INFO", show_default=True)
@click.option(
    "--backend-log-level",
    type=click.Choice(["OFF", "DEBUG", "INFO", "WARN", "ERROR"]),
    default="WARN",
    show_default=True,
)
@click.option("--log-format", type=click.Choice(["human", "jsonl"]), default="human", show_default=True)
@click.option(
    "--relay",
    type=click.Choice(["direct", "auto"] + [item.name for item in iter_builtin_relays()]),
    default="auto",
    show_default=True,
    help="Backend release transport.",
)
@click.option("--relay-url", help="Invocation-scoped HTTPS relay base URL.")
@click.option(
    "--relay-pattern",
    type=click.Choice(list(ALLOWED_PATTERNS)),
    help="URL path pattern used with --relay-url.",
)
@click.option(
    "--health-interval",
    type=click.IntRange(60, 3600),
    default=300,
    show_default=True,
    help="Seconds between authenticated global health quorums while foregrounded.",
)
@click.option(
    "--recovery-deadline",
    type=click.IntRange(10, 600),
    default=120,
    show_default=True,
    help="One wall-clock budget for restart, alternate nodes, refresh, and cleanup.",
)
@click.option(
    "--refresh-on-recovery/--no-refresh-on-recovery",
    default=True,
    show_default=True,
    help="Allow one source refresh after the configured node sweep is exhausted.",
)
@click.option("-y", "--yes", is_flag=True, help="Approve exact backend bootstrap without prompting.")
@click.pass_context
def server_command(
    context,
    subscriptions,
    backend,
    backend_version,
    node_id,
    install_missing,
    log_level,
    backend_log_level,
    log_format,
    relay,
    relay_url,
    relay_pattern,
    health_interval,
    recovery_deadline,
    refresh_on_recovery,
    yes,
):
    # type: (click.Context, tuple, str, str, Optional[str], bool, str, str, str, str, Optional[str], Optional[str], int, int, bool, bool) -> None
    """Run one synchronous foreground session."""

    del log_level
    if len(subscriptions) > 1:
        raise click.UsageError("repeatable --subscription is not supported by this first runtime slice")
    if backend != "mihomo":
        raise click.UsageError("only Mihomo is implemented by the V2RAY_SUBSCRIPTION runtime slice")
    if backend_version != QUALIFIED_VERSION:
        raise click.UsageError("Mihomo must use the qualified version %s" % QUALIFIED_VERSION)
    if relay_url is not None and relay != "auto":
        raise click.UsageError("--relay and --relay-url are mutually exclusive")
    if relay_pattern is not None and relay_url is None:
        raise click.UsageError("--relay-pattern requires --relay-url")
    manager = _common.manager(context)
    if install_missing:
        try:
            manager.which("mihomo", backend_version)
        except BackendNotInstalledError:
            if not _common.confirm_dangerous_operation(
                "Install verified Mihomo %s and run it in the foreground?" % backend_version,
                yes,
            ):
                raise click.ClickException("backend bootstrap cancelled")
    runtime = RuntimeSession(
        _common.paths(context),
        manager=manager,
        backend_version=backend_version,
        relay=relay,
        relay_url=relay_url,
        relay_pattern=relay_pattern,
        backend_log_level=backend_log_level,
        recovery_policy=RecoveryPolicy(
            health_interval=health_interval,
            recovery_deadline=recovery_deadline,
            refresh_on_failure=refresh_on_recovery,
        ),
    )
    try:
        runtime.start(subscriptions[0] if subscriptions else None, node_id=node_id, install_missing=install_missing)
        info = runtime.public_info()
        if log_format == "jsonl":
            click.echo(json.dumps({"event": "session.ready", "data": info}, sort_keys=True, separators=(",", ":")))
        else:
            click.echo("JerryProxy session ready")
            click.echo(
                "Endpoint: %s:%d (%s)"
                % (info["listener"]["address"], info["listener"]["port"], info["listener"]["kind"])
            )
            click.echo("Access file: %s" % info["access_file"])
        exit_code = runtime.wait()
        if exit_code and exit_code != 130:
            raise click.ClickException("Mihomo exited with status %d" % exit_code)
    except KeyboardInterrupt:
        runtime.stop()
    except (RuntimeSessionError, BackendNotInstalledError):
        runtime.stop()
        raise
    finally:
        if runtime.process is not None:
            runtime.stop()
