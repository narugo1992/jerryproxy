"""The environment contract this lane receives, and nothing else.

The workflow owns Docker: it builds images, generates credentials, starts the
two-network topology, and injects the values below.  This module reads only
environment variables and never imports a Docker library, runs the Docker CLI,
reads Compose files, or inspects container metadata.

Every value here is bearer-like test input, so failures report variable names
and sanitized classifications rather than values.
"""

import os
import re
from urllib.parse import urlsplit

ENFORCE = "JERRYPROXY_E2E_ENFORCE"
SUBSCRIPTION = "V2RAY_SUBSCRIPTION"
SENTINEL_HOST = "JERRYPROXY_E2E_SENTINEL_HOST"
SENTINEL_PORT = "JERRYPROXY_E2E_SENTINEL_PORT"
MARKER = "JERRYPROXY_E2E_MARKER"
BACKEND = "JERRYPROXY_E2E_BACKEND"
BACKEND_VERSION = "JERRYPROXY_E2E_BACKEND_VERSION"
PUBLIC_PROBES = "JERRYPROXY_E2E_PUBLIC_PROBES"
NODE_VARIABLES = {
    "ss": "JERRYPROXY_E2E_SS_NODE",
    "vmess": "JERRYPROXY_E2E_VMESS_NODE",
    "vless": "JERRYPROXY_E2E_VLESS_NODE",
}

REQUIRED = (
    SUBSCRIPTION,
    SENTINEL_HOST,
    SENTINEL_PORT,
    MARKER,
    BACKEND,
    BACKEND_VERSION,
) + tuple(sorted(NODE_VARIABLES.values()))

SENTINEL_PATH = "/jerryproxy-e2e-marker"
SENTINEL_BANNER = "JERRYPROXY-E2E-SENTINEL-v1"
MAXIMUM_RESPONSE_BYTES = 64 * 1024
_MARKER = re.compile(r"^[0-9a-f]{32,64}$")
_SERVICE_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ContractError(Exception):
    """Raised when the injected environment does not satisfy the contract."""


def enforced():  # type: () -> bool
    """Return whether the workflow declared this run mandatory."""

    return os.environ.get(ENFORCE) == "1"


def _present(name):  # type: (str) -> str
    value = os.environ.get(name)
    if not value or value.strip() != value or not value:
        raise ContractError("%s is missing or not exactly one bounded token" % name)
    return value


def _node_uri(name, scheme):  # type: (str, str) -> str
    value = _present(name)
    if any(character.isspace() for character in value):
        raise ContractError("%s must not contain whitespace" % name)
    if not value.lower().startswith("%s://" % scheme):
        raise ContractError("%s must be a %s:// URI" % (name, scheme))
    return value


def _subscription_url():  # type: () -> str
    """Require the in-network fixture source, never a real provider.

    A developer machine commonly exports a real ``V2RAY_SUBSCRIPTION``, and this
    lane must never fetch it: real provider subscriptions are excluded from the
    harness.  Requiring a bare Compose service name makes that structural rather
    than a matter of care, and a real provider URL simply skips the lane.
    """

    value = _present(SUBSCRIPTION)
    parsed = urlsplit(value)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ContractError("%s must be the in-network HTTP fixture source" % SUBSCRIPTION)
    if not _SERVICE_HOST.match(parsed.hostname):
        raise ContractError(
            "%s must target a Compose service name; a real provider subscription is never used"
            % SUBSCRIPTION
        )
    return value


def _sentinel_host():  # type: () -> str
    """Require a private service-owned target, never a host-published address."""

    value = _present(SENTINEL_HOST).lower()
    if not _SERVICE_HOST.match(value):
        raise ContractError("%s must be a Compose service name" % SENTINEL_HOST)
    if value in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"):
        raise ContractError("%s must not be a loopback or host-published address" % SENTINEL_HOST)
    return value


def _sentinel_port():  # type: () -> int
    value = _present(SENTINEL_PORT)
    if not value.isdigit():
        raise ContractError("%s must be a decimal TCP port" % SENTINEL_PORT)
    port = int(value)
    if not 1 <= port <= 65535:
        raise ContractError("%s is outside the TCP port range" % SENTINEL_PORT)
    return port


def _marker():  # type: () -> str
    """Require a per-run nonce rather than a constant baked into the fixture."""

    value = _present(MARKER)
    if not _MARKER.match(value):
        raise ContractError("%s must be 32-64 lowercase hexadecimal characters" % MARKER)
    return value


def _public_probes():  # type: () -> tuple
    value = os.environ.get(PUBLIC_PROBES, "").strip()
    if not value:
        return ()
    targets = tuple(item.strip() for item in value.split(",") if item.strip())
    for target in targets:
        if not target.startswith("https://"):
            raise ContractError("%s entries must be bounded HTTPS URLs" % PUBLIC_PROBES)
    return targets


class Contract(object):
    """One validated view of the injected environment."""

    def __init__(self):
        self.subscription_url = _subscription_url()
        self.sentinel_host = _sentinel_host()
        self.sentinel_port = _sentinel_port()
        self.marker = _marker()
        self.backend = _present(BACKEND)
        self.backend_version = _present(BACKEND_VERSION)
        self.nodes = {
            scheme: _node_uri(name, scheme) for scheme, name in sorted(NODE_VARIABLES.items())
        }
        self.public_probes = _public_probes()

    @property
    def sentinel_url(self):  # type: () -> str
        return "http://%s:%d%s" % (self.sentinel_host, self.sentinel_port, SENTINEL_PATH)

    def describe(self):  # type: () -> str
        """Return a credential-free description for diagnostics."""

        return "backend=%s %s sentinel=%s:%d schemes=%s public_probes=%d" % (
            self.backend,
            self.backend_version,
            self.sentinel_host,
            self.sentinel_port,
            ",".join(sorted(self.nodes)),
            len(self.public_probes),
        )


def load():  # type: () -> Contract
    """Return the validated contract, or explain why the lane cannot run.

    A missing or malformed environment is a local convenience skip, but never
    when the workflow declared the run mandatory: a broken CI setup must not be
    reported as a harmless skip.
    """

    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        reason = "environment contract incomplete: %s" % ", ".join(sorted(missing))
        if enforced():
            raise ContractError("%s while %s=1" % (reason, ENFORCE))
        return None, reason
    try:
        return Contract(), None
    except ContractError as error:
        # Malformed values are a setup defect, not a protocol failure.
        if enforced():
            raise
        return None, str(error)
