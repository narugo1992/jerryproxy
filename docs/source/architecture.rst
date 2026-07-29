Architecture
============

JerryProxy separates backend distribution from backend runtime behavior:

.. code-block:: text

   CLI
    ├── Self-check (isolated local runtime and state diagnostics)
    ├── Home-wide filelock (managed-state serialization)
    ├── Backend registry (identity and exact asset names)
    ├── Static catalog reader (packaged stable releases, offline)
    ├── Catalog selector (strict platform and integrity validation)
    ├── Downloader (HTTPS, size, SHA-256)
    ├── Archive extractor (bounded and traversal-safe)
    ├── Removal transaction (private journal and alias-safe disposal)
    ├── Backend manager (versions, links, rollback)
    ├── Subscription manager (planned)
    └── Runtime drivers (planned)
          ├── MihomoDriver
          ├── SingBoxDriver
          ├── XrayDriver
          └── V2RayDriver

The first runtime implementation will target Mihomo. Making it the shipped
default remains gated on the documented compatibility/security PoC. Xray and
V2Ray runtime drivers remain optional compatibility work. sing-box is also an
optional runtime candidate for native profiles; all four binaries can already
be installed and version-switched by the generic manager.

Catalog maintenance is intentionally outside this runtime graph. The
repository-only ``tools.backend_catalog`` module reads official release
metadata and writes the four flat files below ``jerryproxy/data``. Wheels,
source distributions, and frozen executables include those files but exclude
the maintenance tool. Runtime reads go through ``jerryproxy.data`` only. Users
receive catalog updates by upgrading JerryProxy, never through an in-process
catalog updater.

Every current managed-state operation uses one upstream ``filelock.FileLock``
below the selected JerryProxy home. Catalog-only queries do not initialize or
lock the home. Backend list, doctor, and self-check consume a single inventory
snapshot so installed and active state cannot come from different lock epochs.
Lock acquisition also recovers private removal journals before exposing managed
state. The removal module is an internal manager/lock boundary, not a supported
extension API.

Backend protocol schemas remain owned by the external cores. Python may build
top-level configs and bounded subscription containers, but must not become a
second implementation of VMess, VLESS, REALITY, or other protocol fields.
