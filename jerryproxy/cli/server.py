"""The synchronous foreground ``server`` command."""

import json
import logging
from urllib.parse import quote

import click
from click.core import ParameterSource
from InquirerPy.base.control import Choice
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape as rich_escape

from ..backend.relay import ALLOWED_PATTERNS, iter_builtin_relays
from ..errors import BackendNotInstalledError, RuntimeSessionError
from ..runtime import QUALIFIED_VERSION, RecoveryPolicy, RuntimeSession
from ..runtime.mihomo import LISTENER_PROTOCOLS, reserve_loopback_port
from ..subscription.redaction import redact_text, terminal_safe_text
from . import _common

_BACKENDS = ("mihomo", "sing-box", "xray", "v2ray")
_LOG_PRIORITIES = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_DEFAULT_PORT = 17777


def _proxy_url(protocol, address, port, username=None, password=None):
    scheme = "socks5h" if protocol == "socks5" else "http"
    if username is None and password is None:
        return "%s://%s:%d" % (scheme, address, port)
    return "%s://%s:%s@%s:%d" % (
        scheme,
        quote(username, safe=""),
        quote(password, safe=""),
        address,
        port,
    )


def _port_available(port, bind_address="127.0.0.1"):  # type: (int, str) -> bool
    try:
        reserve_loopback_port(preferred=port, strict=True, bind_address=bind_address)
    except RuntimeSessionError:
        return False
    return True


def _select_interactive_port(bind_address="127.0.0.1"):  # type: (str) -> tuple
    """Prompt for a strict port, automatic allocation, or a validated custom port."""

    if _port_available(_DEFAULT_PORT, bind_address):
        recommended = _DEFAULT_PORT
        prompt = (
            "Enter the local proxy port (press Enter for %d; type auto for automatic allocation): "
            % recommended
        )
    else:
        recommended = reserve_loopback_port(bind_address=bind_address)
        prompt = (
            "Default port %d is busy. Enter the local proxy port (press Enter for %d; "
            "type auto for automatic allocation): "
            % (_DEFAULT_PORT, recommended)
        )
    value = _common.prompt_text(prompt, default=str(recommended)).strip().lower()
    if value == "auto":
        return None, False
    try:
        custom = int(value)
    except (TypeError, ValueError) as error:
        # The guided text field must still fail clearly if a non-numeric value is returned.
        raise click.ClickException("port must be an integer from 1 to 65535 or auto") from error
    if not 1 <= custom <= 65535:
        raise click.ClickException("port must be an integer from 1 to 65535 or auto")
    if not _port_available(custom, bind_address):
        raise click.ClickException("requested listener port is unavailable: %d" % custom)
    return custom, True


_HELP = """Run one local loopback proxy synchronously in the foreground.

The server command selects one stored subscription and one explicit node, then
launches the exact Mihomo backend through BackendManager. It never changes the
backend active link, starts a daemon, or exposes a controller. Press Ctrl+C to
stop and remove the session projection. After readiness it probes a quorum of
stable global HTTPS targets through the selected local listener. Two consecutive
failed quorums trigger the fixed recovery policy: restart the current node once,
try eligible alternate nodes in public-ID order, then refresh the stored source
once when policy permits. Automatic failover never rewrites the saved node
preference. The bearer URL, UUIDs, Reality keys, and backend raw output are
never printed as one unredacted blob.

\b
Forms:
  jerryproxy server
  jerryproxy server --subscription NAME --node NODE_ID
  jerryproxy server --subscription NAME --node NODE_ID
    --install-missing -y

`--relay auto` is the default when the exact Mihomo release is missing. Relay
options affect only backend bootstrap and never subscription fetching. Health
and recovery waits use the bounded built-in policy and a failed recovery exits
after cleanup.

\b
Interactive forms:
  jerryproxy server
    Select an enabled subscription and node through InquirerPy.
    Confirm backend bootstrap when Mihomo is not installed.
  jerryproxy server --subscription NAME
    Select NAME's node when running in a real TTY.

Non-interactive forms must provide both `--subscription NAME` and `--node
NODE_ID`. JSONL output and `-y/--yes` never infer missing targets; they fail
with a usage error instead. Selection labels contain only subscription format,
node count, node scheme, endpoint display, and the stable node ID.

The listener defaults to an unauthenticated mixed proxy on `127.0.0.1`; use
`--protocol` to select mixed, HTTP, or SOCKS5, `--auth` for generated local
credentials, and `--bind-all` only when LAN exposure is intentional. JerryProxy
messages have no owner prefix; backend output is merged into one stream and
each backend line is labeled only with the core name (`[mihomo]`, `[v2ray]`,
and so on). The stream never distinguishes the child's original stdout and
stderr. Backend lines are forwarded live only after terminal-safety handling
and credential redaction; the backend name is the sole owner label.

Human startup output is emitted through the JerryProxy log stream as one
readable readiness summary, one copyable proxy URL, and a short
environment-variable guide. The private runtime log filename contains its UTC
start time to the second. The same URL is assigned to `HTTP_PROXY`,
`HTTPS_PROXY`, and `ALL_PROXY`; credentials are included in that guide only
when `--auth` is enabled.
"""


@click.command("server", help=_HELP, short_help="Run a foreground proxy.")
@click.option(
    "--subscription",
    "subscriptions",
    multiple=True,
    help="Exact subscription name; omit it only for guided TTY selection.",
)
@click.option(
    "--backend",
    type=click.Choice(_BACKENDS),
    default="mihomo",
    show_default=True,
    help="Runtime core; only Mihomo is enabled in this slice.",
)
@click.option("--backend-version", default=QUALIFIED_VERSION, show_default=True, help="Exact qualified Mihomo version.")
@click.option(
    "--port",
    type=click.IntRange(1, 65535),
    help="Exact listener port; omit it for automatic allocation or the guided input prompt.",
)
@click.option(
    "--protocol",
    type=click.Choice(LISTENER_PROTOCOLS),
    default="mixed",
    show_default=True,
    metavar="PROTOCOL",
    help="Local listener: mixed (HTTP+SOCKS5), http, or socks5.",
)
@click.option(
    "--node",
    "node_id",
    help="Exact 32-lowercase-hex node identity; omit it only for guided TTY selection.",
)
@click.option(
    "--auth/--no-auth",
    "authenticate",
    default=False,
    show_default=True,
    help="Require generated local proxy credentials; default is an open loopback listener.",
)
@click.option(
    "--bind-all",
    is_flag=True,
    help="Bind the listener to 0.0.0.0 and allow LAN access; combine with --auth on untrusted networks.",
)
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
    default="INFO",
    show_default=True,
    help="Set backend verbosity; merged backend lines are forwarded live after redaction, or suppressed with OFF.",
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
    help="Seconds between global health quorums through the selected local listener.",
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
    port,
    protocol,
    node_id,
    authenticate,
    bind_all,
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
    # type: (click.Context, tuple, str, str, Optional[int], str, Optional[str], bool, bool, bool, str, str, str, str, Optional[str], Optional[str], int, int, bool, bool) -> None
    """Run one synchronous foreground session."""

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
    guided_targets = not subscriptions or node_id is None
    subscription_name = subscriptions[0] if subscriptions else None
    if subscription_name is None:
        if yes or not _common.interactive_available():
            raise click.UsageError(
                "--subscription NAME is required in non-interactive mode; "
                "-y/--yes cannot infer a subscription"
            )
        subscription_name = _common.select_subscription(
            context,
            "Select an enabled subscription:",
            enabled_only=True,
        )
    if node_id is None:
        if yes or not _common.interactive_available():
            raise click.UsageError(
                "--node NODE_ID is required in non-interactive mode; "
                "-y/--yes cannot infer a node"
            )
        node_id = _common.select_subscription_node(
            context,
            subscription_name,
            "Select a node for %s:" % subscription_name,
        )
    if guided_targets and context.get_parameter_source("protocol") == ParameterSource.DEFAULT and not yes:
        protocol = str(
            _common.select(
                "Select a local proxy protocol:",
                [
                    Choice("mixed", name="mixed - HTTP and SOCKS5"),
                    Choice("http", name="http - HTTP proxy clients"),
                    Choice("socks5", name="socks5 - SOCKS5 clients"),
                ],
            )
        )
    strict_port = port is not None
    bind_address = "0.0.0.0" if bind_all else "127.0.0.1"
    if port is None and guided_targets and not yes:
        port, strict_port = _select_interactive_port(bind_address=bind_address)
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
    rich_handler = None
    if log_format == "human":
        rich_handler = RichHandler(
            # Rich measures the actual terminal or pipe width at render time.
            console=Console(stderr=True, soft_wrap=True),
            show_path=False,
            markup=True,
            rich_tracebacks=False,
        )

    def log_sink(source, level, message, emphasize=False, preserve_local_auth=False):
        if source == "jerryproxy" and _LOG_PRIORITIES[level] < _LOG_PRIORITIES[log_level]:
            return
        if log_format == "jsonl":
            payload = {
                "event": "log",
                "level": level,
                "message": terminal_safe_text(redact_text(message)),
            }
            if source != "jerryproxy":
                payload["source"] = source
            click.echo(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")), err=True)
            return
        if preserve_local_auth:
            safe_message = rich_escape(terminal_safe_text(message))
        else:
            safe_message = rich_escape(terminal_safe_text(redact_text(message)))
        if emphasize:
            safe_message = "[bold underline cyan]%s[/bold underline cyan]" % safe_message
        if source == "jerryproxy":
            rendered_message = safe_message
        else:
            safe_source = rich_escape("[%s]" % source)
            rendered_message = "[bold cyan]%s[/bold cyan] %s" % (safe_source, safe_message)
        record = logging.LogRecord(
            source,
            _LOG_PRIORITIES[level],
            __file__,
            0,
            rendered_message,
            (),
            None,
        )
        rich_handler.emit(record)

    def startup_log(message, emphasize=False, preserve_local_auth=False):
        log_sink(
            "jerryproxy",
            "INFO",
            message,
            emphasize=emphasize,
            preserve_local_auth=preserve_local_auth,
        )

    def startup_warning(message):
        log_sink("jerryproxy", "WARN", message, emphasize=True)

    runtime = RuntimeSession(
        _common.paths(context),
        manager=manager,
        backend_version=backend_version,
        relay=relay,
        relay_url=relay_url,
        relay_pattern=relay_pattern,
        preferred_port=port,
        strict_port=strict_port,
        listener_protocol=protocol,
        authenticate=authenticate,
        bind_address=bind_address,
        log_level=log_level,
        backend_log_level=backend_log_level,
        log_sink=log_sink,
        recovery_policy=RecoveryPolicy(
            health_interval=health_interval,
            recovery_deadline=recovery_deadline,
            refresh_on_failure=refresh_on_recovery,
        ),
    )
    try:
        runtime.start(subscription_name, node_id=node_id, install_missing=install_missing)
        info = runtime.public_info()
        if not isinstance(info, dict):
            raise RuntimeSessionError("runtime returned an invalid public session envelope")
        # Access and runtime-log paths are private implementation details even
        # when a future driver accidentally includes them in its envelope.
        info = dict(info)
        info.pop("access_file", None)
        info.pop("log_file", None)
        if bind_all:
            startup_warning("listener is exposed on all interfaces; use --auth on untrusted networks")
        if log_format == "jsonl":
            click.echo(json.dumps({"event": "session.ready", "data": info}, sort_keys=True, separators=(",", ":")))
        else:
            listener = info["listener"]
            address = listener["address"]
            port = listener["port"]
            listener_protocol = listener.get("protocol", "mixed")
            proxy_url = _proxy_url(
                listener_protocol,
                address,
                port,
                runtime.username if authenticate else None,
                runtime.password if authenticate else None,
            )
            startup_log(
                "JerryProxy is ready: %s %s, %s proxy at %s:%d; authentication is %s."
                % (
                    info.get("backend", "mihomo"),
                    info.get("backend_version", backend_version),
                    listener_protocol,
                    address,
                    port,
                    "enabled" if authenticate else "disabled",
                )
            )
            startup_log("Proxy URL: %s" % proxy_url, emphasize=True, preserve_local_auth=True)
            guide = [
                "Shell guide: copy these commands into the shell where you want to use the proxy.",
            ]
            if authenticate:
                guide.append(
                    "Authentication is enabled; use username '%s' and password '%s' when prompted."
                    % (runtime.username, runtime.password)
                )
            guide.extend(
                (
                    "  export HTTP_PROXY='%s'" % proxy_url,
                    "  export HTTPS_PROXY='%s'" % proxy_url,
                    "  export ALL_PROXY='%s'" % proxy_url,
                )
            )
            if listener_protocol == "socks5":
                guide.append("SOCKS5 uses the `socks5h` URL so DNS lookups also go through the proxy.")
            guide.append("When finished, run: unset HTTP_PROXY HTTPS_PROXY ALL_PROXY")
            startup_log("\n".join(guide), preserve_local_auth=authenticate)
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
