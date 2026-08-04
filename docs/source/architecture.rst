Architecture
============

JerryProxy separates backend distribution from backend runtime behavior:

.. code-block:: text

   CLI
    ├── Self-check (local diagnostics plus bounded built-in relay probes)
    ├── Home-wide filelock (managed-state serialization)
    ├── Backend registry (identity and exact asset names)
    ├── Static catalog reader (packaged stable releases, offline)
    ├── Catalog selector (strict platform and integrity validation)
    ├── Downloader (HTTPS, size, SHA-256)
    ├── Archive extractor (bounded and traversal-safe)
    ├── Removal transaction (private journal and alias-safe disposal)
    ├── Backend manager (versions, links, rollback)
    ├── Subscription manager (V2RAY_SUBSCRIPTION URI slice)
    │     ├── NodeSource/ProxyNode model contracts
    │     └── injected SubscriptionParser adapters
    └── Runtime drivers
          ├── RuntimeDriver contract
          ├── MihomoDriver (foreground URI NodeSet)
          ├── SingBoxDriver (planned)
          ├── XrayDriver (planned)
          └── V2RayDriver (planned)

The first Mihomo runtime slice is implemented for Base64/plain SS, VMess, and
VLESS URI lines from the exact ``V2RAY_SUBSCRIPTION`` source format. It writes a
private file provider below the session's Mihomo safe path, exposes an open
loopback listener on ``127.0.0.1`` by default, and performs a global health
quorum with deterministic restart/failover and one policy-controlled source
refresh. ``server --auth`` enables generated local credentials and
``server --bind-all`` explicitly selects ``0.0.0.0``. Xray, V2Ray, and sing-box
runtime drivers remain optional compatibility work; all four binaries can already be installed and
version-switched by the generic manager.

When the exact Mihomo release is absent, ``server`` bootstraps it automatically
by default. A guided terminal asks for confirmation with Yes as the default;
``-y/--yes`` accepts the bootstrap without prompting and
``--no-install-missing`` disables it. Backend stdout/stderr are merged into one
bounded live stream, redacted, and logged with the core name (for example
``[mihomo]``), without a stdout/stderr distinction; the backend log level
defaults to ``INFO``.

Catalog maintenance is intentionally outside this runtime graph. The
repository-only ``tools.backend_catalog`` module reads official release
metadata and writes the four flat files below ``jerryproxy/data``. Wheels,
source distributions, and frozen executables include those files but exclude
the maintenance tool. Runtime reads go through ``jerryproxy.data`` only. Users
receive catalog updates by upgrading JerryProxy, never through an in-process
catalog updater.

Relay-health monitoring is outside the runtime graph for the same reason. The
maintainer-owned Gist is the relay-host and pattern source of truth; ``make
relay_health_sync`` downloads it to an ignored local JSON file. The reviewed
official probe asset and expected Range digest remain pinned by the repository
tool. Each enabled pattern receives three streamed 1 MiB samples with a
ten-second network timeout. Response-header latency and first-chunk latency
remain separate from the speed of subsequent chunks, while the short-window
success count represents stability. The ``tools.relay_health`` and
``tools.render_relay_health`` modules
consume only local JSON paths. GitHub Actions probes and renders without
publisher credentials, then uses separate identity-checked jobs for Gist and
Wiki publication. A final gate rejects incomplete publication or an integrity
mismatch. No health configuration or observation is imported by
``jerryproxy`` or packaged in its wheel.

The runtime self-check uses the same repository-pinned asset evidence only to
probe the three built-in relay profiles. It performs one fixed 1 MiB streamed
sample per relay with a five-second network timeout. Relay failures are
availability warnings; local requirement and operational errors retain the
``FAIL`` and ``ERR`` exit semantics.

Every current managed-state operation uses one upstream ``filelock.FileLock``
below the selected JerryProxy home. Catalog-only queries do not initialize or
lock the home. Backend list, doctor, and self-check consume a single inventory
snapshot so installed and active state cannot come from different lock epochs.
Lock acquisition also recovers private removal journals before exposing managed
state. The removal module is an internal manager/lock boundary, not a supported
extension API.

The lock is deliberately home-wide rather than backend-scoped. Subscription
publication, node inventory, backend installation and activation, runtime lease
and configuration publication, health recovery, cleanup, and read-only state
queries all use ``<home>/locks/jerryproxy.lock``. A foreground session keeps
that lock from selection through child teardown, so a subscription refresh
cannot race backend replacement or runtime projection cleanup.

The current protocol slice is implemented behind extension seams. A
``SubscriptionParser`` turns one bounded source container into the generic
``ParsedSubscription`` model; ``V2RaySubscriptionParser`` is the only shipped
adapter today. ``ProxyNode`` and ``NodeSource`` are the common model contracts
for both subscription-backed nodes and a future single-node input. A
``RuntimeDriver`` owns only backend-specific projection and child lifecycle;
``RuntimeSession`` remains responsible for lock ownership, secret-bearing
state, health policy, failover, and redacted output. Adding a new subscription
container or runtime core therefore adds an adapter/driver instead of a second
selection or locking path.

Backend protocol schemas remain owned by the external cores. Python may build
top-level configs and bounded subscription containers, but must not become a
second implementation of VMess, VLESS, REALITY, or other protocol fields.
