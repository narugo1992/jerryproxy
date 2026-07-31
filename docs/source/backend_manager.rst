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

   jerryproxy backend list known
   jerryproxy backend list known mihomo --limit 5
   jerryproxy backend list known mihomo --all-platforms --limit 5
   jerryproxy backend list known mihomo 1.19.29
   jerryproxy backend install mihomo
   jerryproxy backend install mihomo 1.19.29
   jerryproxy backend install mihomo 1.19.28 --no-activate
   jerryproxy backend use mihomo 1.19.28
   jerryproxy backend current mihomo
   jerryproxy backend which mihomo
   jerryproxy backend list mihomo --paths
   jerryproxy backend install sing-box 1.13.14
   jerryproxy backend verify

Release relay transport
-----------------------

``--relay auto`` is the default. It tries direct GitHub first, then the three
built-in release relays in a fixed order. Use ``--relay direct`` when no relay
contact is acceptable. A named relay is a single-source request and does not
silently contact the other candidates:

.. code-block:: shell

   jerryproxy backend install mihomo --relay auto
   jerryproxy backend install mihomo --relay direct
   jerryproxy backend install mihomo --relay gh-proxy.com

Automatic fallback advances only after a transport failure such as DNS, TLS,
proxy, timeout, streaming, or HTTP failure. Redirect-policy, response-size,
integrity, and local-filesystem failures are terminal. The installed manifest
always records the official catalog URL, and the complete archive must match
the official size and SHA-256 regardless of transport.

Use ``--relay-url`` for one invocation-scoped custom HTTPS relay. The optional
``--relay-pattern`` selects one of three constrained URL shapes and defaults to
``full_url_path``:

.. list-table:: Custom relay URL patterns
   :header-rows: 1

   * - Pattern
     - Effective request form
   * - ``full_url_path``
     - ``BASE/https://github.com/OWNER/REPO/releases/download/...``
   * - ``host_path``
     - ``BASE/github.com/OWNER/REPO/releases/download/...``
   * - ``query_q``
     - ``BASE/?q=<percent-encoded-official-URL>``

.. code-block:: shell

   jerryproxy backend install mihomo \
     --relay-url https://relay.example/prefix \
     --relay-pattern host_path

``--relay`` and ``--relay-url`` are mutually exclusive.
``--relay-pattern`` requires ``--relay-url``. The same details are available
at the point of use through ``jerryproxy backend install --help``.

The backend command surface has eight operations: ``list``, ``install``,
``current``, ``use``, ``which``, ``verify``, ``uninstall``, and ``clean``.
``list [NAME]`` shows local immutable installations. ``list known`` uses
positional depth for the packaged catalog: no target shows known backends,
``NAME`` shows compatible stable versions, and ``NAME VERSION`` shows the
exact host artifact and full SHA-256 evidence. Catalog queries never access the
network and always identify the packaged snapshot timestamp. ``install NAME``
is also the update operation because it resolves and activates the newest
compatible packaged release when ``VERSION`` is omitted.

With ``--json``, those three depths have explicit machine shapes:
``list known --json`` returns an array of backend overview records,
``list known NAME --json`` returns every matching release record unless an
explicit ``--limit`` is supplied, and ``list known NAME VERSION --json``
returns one exact artifact object. The exact object includes the asset name,
URL, byte size, platform, full SHA-256 digest, and verification source.

``current [NAME]`` reports the selected versions without mixing that query into
the local inventory view. ``which NAME`` prints only the integrity-verified
immutable executable for the current version, while ``which NAME VERSION``
selects an exact installed version. Add ``--paths`` to ``list`` only when the
executable and current-link paths are needed.

Neither local nor packaged-catalog list initializes or repairs a home. An
absent or empty home produces an empty local inventory without creating
directories. If managed state already exists, the local form acquires the
home-wide lock and validates the complete top-level layout and lock-path
permissions. Every acquired home lock still performs mandatory recovery of an
already journaled interrupted uninstall before returning the inventory
snapshot.

Interactive and automated use
-----------------------------

Running ``jerryproxy backend`` opens an ``InquirerPy`` operation menu. A
backend command with a missing target also guides the remaining choices:

.. code-block:: shell

   jerryproxy backend
   jerryproxy backend install
   jerryproxy backend use
   jerryproxy backend which
   jerryproxy backend uninstall
   jerryproxy backend clean

Supplying the complete positional target and options skips selection prompts,
so the same commands remain deterministic for scripts. Read-only commands
whose no-argument meaning is already complete keep that behavior:
``list``, ``current``, and ``verify`` operate across all installed backends,
while ``list known`` shows the packaged catalog.

Removal and cleanup
-------------------

Destructive commands always show one final ``InquirerPy`` confirmation unless
``-y/--yes`` is explicit. Uninstall one inactive version, explicitly
deactivate and uninstall one current version, or uninstall every version of one
backend:

.. code-block:: shell

   jerryproxy backend uninstall mihomo 1.19.29
   jerryproxy backend uninstall mihomo 1.19.29 --deactivate
   jerryproxy backend uninstall mihomo -A
   jerryproxy backend uninstall mihomo -A --cache

``--cache`` includes the matching verified release archive in the same
home-wide transaction. Uninstallation first moves every selected cache, immutable
version, active link, and active manifest into a private
``runtimes/.remove-*`` quarantine using atomic renames. A private
``journal.json`` with no format-version field is persisted before the first
rename. Any staging failure restores moved paths in reverse order before
physical deletion begins. If the process terminates, the next home-wide lock
acquisition restores a staging journal or finishes disposal for a committed
journal. Invalid, ambiguous, aliased, or identity-mismatched recovery state
fails closed with ``IntegrityError``. Once all public paths are absent the
logical removal is committed and the quarantine is deleted. A quarantine
deletion failure is reported as ``RemovalCleanupError``;
the consistent public state remains committed and ``clean --runtimes`` can
retry disposal. In non-interactive automation, add ``-y`` only after specifying
the complete target.

Cleanup can target one cached backend version, one backend cache, selected
global areas, all cache, or every disposable area:

.. code-block:: shell

   jerryproxy backend clean mihomo 1.19.29
   jerryproxy backend clean mihomo
   jerryproxy backend clean --cache
   jerryproxy backend clean --logs --runtimes
   jerryproxy backend clean -A

``clean -A`` empties cache, logs, providers, and runtimes. The managed cache is
stored internally below ``downloads``.
It never deletes ``backends``, ``bin``, ``active``, or ``locks``. Backend and
version scopes apply only to cache because the other state areas do not
yet have a stable per-backend ownership layout. Empty targets are idempotent.
Managed symlink and Windows reparse-point components, including junctions, are
rejected instead of followed. Download cleanup shares the same home-wide
operation lock as installation and removal. Cleanup revalidates each target's
complete managed ancestor chain immediately before deletion and rejects aliases
inside removal trees so a path swap after target collection fails closed.
Recursive disposal repeatedly checks path identity and never delegates managed
trees to an implementation that can traverse a Windows junction. POSIX cleanup
targets remain pinned, move atomically to a random private name below the same
pinned parent, and are rechecked before parent-relative unlink or directory
removal. A hard exit can leave that tombstone only in the selected disposable
area; repeating cleanup inventories and removes it. Journaled install/removal
transactions and activation candidates already have private operation names,
so their disposal does not create a second unrecorded tombstone in protected
state. Windows targets remain pinned with ``OPEN_REPARSE_POINT`` and are deleted
with ``SetFileInformationByHandle``, so replacing a parent with a junction
cannot redirect the final operation. The one journal-recorded active-command
symlink is unlinked directly without following its target.

One-shot POSIX substitution before isolation is detected and preserved. POSIX
does not provide a portable unlink-by-open-file-descriptor primitive; a
malicious same-UID process that continuously replaces the transient private
name after its final identity check is outside the supported threat boundary.

On POSIX systems without ``O_PATH`` (including supported macOS releases), an
unreadable file or a socket may be impossible to pin safely. Cleanup fails
closed and preserves that target instead of falling back to a pathname-only
deletion.

Managed-state access is serialized by the upstream ``filelock.FileLock`` at
``~/.jerryproxy/locks/jerryproxy.lock``. The default timeout is zero, so a
second command fails immediately instead of waiting behind a download. The lock
file may remain after release; JerryProxy does not inspect owner metadata or
attempt stale-lock recovery. Installation holds this lock from cache validation
and download through extraction, publication, probing, and optional activation.

Activation publishes a relative symbolic link atomically on supported POSIX
systems. Windows without symlink privilege receives an atomic verified
executable copy; the active manifest records the selected version and
``link_mode`` so this fallback is not mistaken for a real link. The command
and manifest are separate paths, so the pair is not continuously atomic to an
external observer. A hard exit may expose an intermediate pair until the next
home-lock acquisition rolls the journal backward or forward and converges.

Automatic installation accepts only an exact catalog asset with verified
upstream SHA-256 evidence. The catalog prefers the digest returned directly by
GitHub's release API. Official checksum text is used only as a maintenance-time
fallback for legacy assets whose API metadata has no digest; JerryProxy does
not download backend archives to calculate catalog fingerprints. Archive
extraction rejects absolute paths, parent traversal, archive symlinks, and
special files.

Backend archives stream through ``requests``. A ``tqdm`` byte progress bar on
stderr reports ``Connecting``, ``Downloading``, transfer speed/ETA,
``Downloaded``, or ``Download failed`` without changing stdout or JSON output.
Requests uses the host's standard proxy and CA environment configuration, so a
configured bootstrap proxy works without a JerryProxy-specific transport
setting while direct downloads remain usable when no proxy is configured.

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

Runtime state management is supported on Linux, macOS, and Windows. The
packaged catalogs retain official FreeBSD and OpenBSD assets for offline
inspection, but installation and activation on BSD fail closed until equivalent
atomic primitives and native CI exist. NFS, SMB, FUSE, or another filesystem
that rejects the required no-replace or exchange operation also fails closed.
