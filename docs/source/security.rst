Security model
==============

Backend binaries and subscription URLs are high-value inputs.

Current enforced backend invariants:

* exact upstream repository, tag, platform, and asset name;
* verified upstream SHA-256 required before automatic install, preferring the
  digest supplied directly by GitHub's release API and using official checksum
  text only for legacy assets without that field;
* bounded HTTPS download and bounded extraction;
* release relays accept only public official GitHub Release asset URLs, never
  authenticated API requests, private assets, subscription URLs, or arbitrary
  headers;
* relay selection changes transport only: exact catalog identity, complete
  size, and official SHA-256 verification remain mandatory, and fallback never
  hides a policy or integrity failure;
* self-check relay probes accept only the three built-in profiles and one
  repository-pinned public Xray release asset; each probe streams at most one
  bounded 1 MiB Range with a five-second connect/read timeout and a
  parent-enforced 30-second total deadline covering process startup, redirects,
  response headers, empty chunks, and streaming; it verifies HTTPS, HTTP 206,
  ``Content-Range``, byte count, and the pinned slice SHA-256;
* relay probe diagnostics use fixed sanitized messages and never display the
  effective URL, redirects, signed query values, or response body;
* streamed ``requests`` downloads with byte-oriented ``tqdm`` status on
  stderr, preserving stdout for structured output;
* archive traversal, symlink, and special-file rejection;
* private staging, executable fingerprint verification, and a bounded native
  version probe before atomic immutable publication;
* activation-time executable re-verification and probing while holding the
  home-wide lock, preserving the previous version on failure;
* one cross-platform ``filelock.FileLock`` serializes managed-state reads and
  mutations across all backends in a configured JerryProxy home;
* destructive removal and cleanup require an ``InquirerPy`` confirmation or
  an explicit ``-y/--yes`` automation override;
* cleanup accepts only fixed managed areas, rejects symlink and Windows
  reparse-point traversal throughout each removal tree, and revalidates the
  full managed ancestor chain immediately before deletion; it never treats
  installed backends, active state, or locks as disposable;
* removal persists a private transaction journal before its first rename;
  every later home-lock acquisition restores interrupted staging or finishes
  interrupted committed disposal, while malformed or ambiguous journals fail
  closed;
* managed recursive deletion repeatedly checks path identity and never follows
  symlinks or Windows junctions; POSIX cleanup pins each target, atomically
  isolates it under a random private name in the same pinned parent, verifies
  the moved identity, and uses parent-relative deletion; Windows opens the final
  object with ``OPEN_REPARSE_POINT`` and deletes through its native handle; only
  the exact journal-recorded active-command symlink may be unlinked as
  transaction payload;
* managed home subdirectories are rejected when replaced by symlinks or
  Windows reparse-point aliases such as junctions, both before and immediately
  after creation, before permission repair or state mutation can affect their
  targets;
* an aliased operation lock file is rejected before ``filelock`` can open or
  truncate an external target;
* failed forced removal restores the previous active link and manifest;
  rollback artifacts remain available if that restoration itself fails;
* single-version and all-version removal first move every selected install,
  matching download cache, and active-state path into one private quarantine;
  staging failures roll back in reverse order before any physical deletion;
* private home directories and private JSON manifests on POSIX.

The lock lives at ``~/.jerryproxy/locks/jerryproxy.lock`` and uses the upstream
``filelock`` public API directly. JerryProxy does not add PID metadata, inspect
lock-file contents, delete a lock file as stale, or implement a second locking
backend. A persistent lock file is normal; OS lock ownership decides whether an
operation is busy.

Python 3.7-3.9 require legacy ``filelock`` release lines affected by
CVE-2025-68146. JerryProxy reports this as ``WARN`` in self-check and doctor,
keeps the lock parent private on POSIX, and recommends Python 3.10+ with a fresh
JerryProxy installation. Python 3.10+ uses ``filelock>=3.30`` with upstream
fork-ownership protection. JerryProxy does not claim to patch legacy dependency
lines locally.

Standalone artifacts use Python 3.7 to preserve the documented legacy OS
compatibility baseline and therefore bundle the legacy ``filelock`` line. Users
who prioritize the upstream lock hardening should use the Python 3.10+ pip
installation. This compatibility statement is a risk disclosure, not a claim
that private-directory permissions repair the dependency vulnerability.

On POSIX platforms without ``O_PATH``, some sockets and unreadable files cannot
be pinned for identity-safe deletion. JerryProxy reports an error and preserves
the target; it does not weaken the deletion boundary to make cleanup succeed.

A hard exit after ordinary POSIX cleanup isolation can leave a
``.jerryproxy-remove-*`` tombstone, but only inside ``downloads``, ``logs``,
``providers``, or ``runtimes``. The next cleanup of that area inventories and
removes the tombstone. Activation candidates and journaled install/removal
transactions already use private operation names and never create a second
unrecorded tombstone in ``backends``, ``bin``, or ``active``. A one-shot path
substitution before isolation is detected and preserved. POSIX has no portable
unlink-by-open-file-descriptor operation, so a malicious same-UID process that
continuously guesses and replaces the transient private name after its final
identity check is outside this threat boundary.

Managed runtime state currently supports Linux, macOS, and Windows. Catalogs
may still describe official FreeBSD and OpenBSD release assets for offline
inspection, but BSD installation and activation are rejected until equivalent
atomic filesystem operations and native CI are available. Required no-replace
and exchange operations fail closed on NFS, SMB, FUSE, or any other filesystem
that does not implement them. The command and active manifest are published as
two separately atomic paths; crash recovery converges their pair under the next
home lock, but an external observer can see an intermediate pair before then.

Current URI-runtime invariants:

* subscription URLs never appear in argv or displayed logs;
* the generated Mihomo provider, access descriptor, and session files are
  owner-only below ``JERRYPROXY_HOME``;
* the foreground listener binds to loopback and is unauthenticated by default;
  ``server --auth`` explicitly enables generated local credentials;
* backend process output is drained as one merged stream, decoded only for
  bounded diagnostics, redacted before persistence or terminal forwarding,
  and labeled only with the backend name (for example ``[mihomo]``);
  JerryProxy-owned records have no owner prefix;
* health recovery uses bounded restart/alternate/refresh steps and preserves
  the saved node preference;
* managed downloads enforce time, size, and redirect policy.

JerryProxy does not bundle external backends. Their upstream licenses and
security policies remain independently applicable.
