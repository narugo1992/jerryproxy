Architecture
============

JerryProxy separates backend distribution from backend runtime behavior:

.. code-block:: text

   CLI
    ├── Backend registry (identity and exact asset names)
    ├── Release client (read-only upstream metadata)
    ├── Downloader (HTTPS, size, SHA-256)
    ├── Archive extractor (bounded and traversal-safe)
    ├── Backend manager (versions, links, rollback)
    ├── Subscription manager (planned)
    └── Runtime drivers (planned)
          ├── MihomoDriver
          ├── XrayDriver
          └── V2RayDriver

The first runtime implementation will target Mihomo. Making it the shipped
default remains gated on the documented compatibility/security PoC. Xray and
V2Ray runtime drivers remain optional compatibility work; their binaries can
already be installed and version-switched by the generic manager.

Backend protocol schemas remain owned by the external cores. Python may build
top-level configs and bounded subscription containers, but must not become a
second implementation of VMess, VLESS, REALITY, or other protocol fields.
