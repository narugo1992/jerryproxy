Backend manager
===============

The backend manager keeps every version immutable below
``~/.jerryproxy/backends/<name>/<version>/`` and exposes the selected version
at ``~/.jerryproxy/bin/<name>``.

JerryProxy ships four flat, stable-only catalog resources for Mihomo, sing-box,
V2Ray, and Xray. Catalog loading is local and network-free; the runtime never
queries a release API. Upgrade the JerryProxy package to receive refreshed
resources:

.. code-block:: shell

   python -m pip install -U jerryproxy

Inspect the catalog and the exact asset selected for the current host before
installing:

.. code-block:: shell

   jerryproxy backend supported
   jerryproxy backend available
   jerryproxy backend versions mihomo --limit 5
   jerryproxy backend versions mihomo --all-platforms --limit 5
   jerryproxy backend artifact mihomo
   jerryproxy backend install mihomo
   jerryproxy backend install mihomo 1.19.29
   jerryproxy backend install mihomo 1.19.28 --no-activate
   jerryproxy backend switch mihomo 1.19.28
   jerryproxy backend current mihomo
   jerryproxy backend list mihomo
   jerryproxy backend install sing-box 1.13.14
   jerryproxy backend update mihomo
   jerryproxy backend verify

Activation uses an atomic relative symbolic link on Unix-like systems. Windows
without symlink privilege receives an atomic verified executable copy; the
active manifest records the selected version and ``link_mode`` so this
fallback is not mistaken for a real link.

Automatic installation accepts only an exact catalog asset with verified
upstream SHA-256 evidence. The catalog prefers the digest returned directly by
GitHub's release API. Official checksum text is used only as a maintenance-time
fallback for legacy assets whose API metadata has no digest; JerryProxy does
not download backend archives to calculate catalog fingerprints. Archive
extraction rejects absolute paths, parent traversal, archive symlinks, and
special files.

The catalog updater exists only in the repository ``tools`` package. It is not
included in the JerryProxy wheel and is never called by the library or CLI.
Maintainers run ``make catalog_update``; users run ``pip install -U
jerryproxy``. The four JSON files are immutable package data and have no
format-version or migration mechanism.

The built-in registry currently covers Mihomo, sing-box, V2Ray, and Xray.
Mihomo amd64 defaults to its conservative v1 CPU build. For mainstream Linux
architectures, sing-box 1.13+ selects the explicit glibc or musl archive
detected for the host. Older unqualified releases are classified as glibc
only, while architectures for which upstream publishes only an unqualified
build retain a portable platform key. A musl host is never silently mapped to
an old glibc build. Unsupported platform pairs fail closed instead of selecting
an asset by fuzzy filename matching.
