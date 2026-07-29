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

   jerryproxy backend available
   jerryproxy backend available mihomo --limit 5
   jerryproxy backend available mihomo --all-platforms --limit 5
   jerryproxy backend available mihomo 1.19.29
   jerryproxy backend install mihomo
   jerryproxy backend install mihomo 1.19.29
   jerryproxy backend install mihomo 1.19.28 --no-activate
   jerryproxy backend switch mihomo 1.19.28
   jerryproxy backend list mihomo --active
   jerryproxy backend install sing-box 1.13.14
   jerryproxy backend verify

The backend command surface has seven operations: ``available``, ``install``,
``list``, ``switch``, ``verify``, ``remove``, and ``clean``. ``available``
uses positional depth instead of separate discovery commands: no target shows
the supported backends, ``NAME`` shows stable versions, and ``NAME VERSION``
shows the exact host artifact and full SHA-256 evidence. ``install NAME`` is
also the update operation because it resolves and activates the newest
compatible packaged release when ``VERSION`` is omitted.

With ``--json``, those three depths have explicit machine shapes:
``available --json`` returns an array of backend overview records,
``available NAME --json`` returns an array of release records (possibly
empty), and ``available NAME VERSION --json`` returns one exact artifact
object. The exact object includes the asset name, URL, byte size, platform,
full SHA-256 digest, and verification source.

Interactive and automated use
-----------------------------

Running ``jerryproxy backend`` opens an ``InquirerPy`` operation menu. A
backend command with a missing target also guides the remaining choices:

.. code-block:: shell

   jerryproxy backend
   jerryproxy backend install
   jerryproxy backend switch
   jerryproxy backend remove
   jerryproxy backend clean

Supplying the complete positional target and options skips selection prompts,
so the same commands remain deterministic for scripts. Read-only commands
whose no-argument meaning is already complete keep that behavior:
``available`` shows the catalog, while ``list`` and ``verify`` operate across
all installed backends. Add ``--active`` to ``list`` to show only selected
versions.

Removal and cleanup
-------------------

Destructive commands always show one final ``InquirerPy`` confirmation unless
``-y/--yes`` is explicit. Remove one inactive version, force removal of one
active version, or remove every version of one backend:

.. code-block:: shell

   jerryproxy backend remove mihomo 1.19.29
   jerryproxy backend remove mihomo 1.19.29 --force
   jerryproxy backend remove mihomo -A
   jerryproxy backend remove mihomo -A --downloads

``--downloads`` includes the matching verified release cache in the same
home-wide transaction. Removal first moves every selected cache, immutable
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
global areas, all downloads, or every disposable area:

.. code-block:: shell

   jerryproxy backend clean mihomo 1.19.29
   jerryproxy backend clean mihomo
   jerryproxy backend clean --downloads
   jerryproxy backend clean --logs --runtimes
   jerryproxy backend clean -A

``clean -A`` empties ``downloads``, ``logs``, ``providers``, and ``runtimes``.
It never deletes ``backends``, ``bin``, ``active``, or ``locks``. Backend and
version scopes apply only to downloads because the other state areas do not
yet have a stable per-backend ownership layout. Empty targets are idempotent.
Managed symlink and Windows reparse-point components, including junctions, are
rejected instead of followed. Download cleanup shares the same home-wide
operation lock as installation and removal. Cleanup revalidates each target's
complete managed ancestor chain immediately before deletion and rejects aliases
inside removal trees so a path swap after target collection fails closed.
Recursive disposal repeatedly checks path identity and never delegates managed
trees to an implementation that can traverse a Windows junction. POSIX targets
remain pinned by an open descriptor through their final unlink or directory
removal, preventing a removed inode from being recycled between identity
checks. Windows targets remain pinned with ``OPEN_REPARSE_POINT`` and are
deleted with ``SetFileInformationByHandle``, so replacing a parent with a
junction cannot redirect the final operation. The one journal-recorded
active-command symlink is unlinked directly without following its target.

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
