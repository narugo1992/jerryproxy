Security model
==============

Backend binaries and subscription URLs are high-value inputs.

Current enforced backend invariants:

* exact upstream repository, tag, platform, and asset name;
* verified upstream SHA-256 required before automatic install, preferring the
  digest supplied directly by GitHub's release API and using official checksum
  text only for legacy assets without that field;
* bounded HTTPS download and bounded extraction;
* streamed ``requests`` downloads with byte-oriented ``tqdm`` status on
  stderr, preserving stdout for structured output;
* archive traversal, symlink, and special-file rejection;
* private staging, executable fingerprint verification, and a bounded native
  version probe before atomic immutable publication;
* activation-time executable re-verification and probing while holding the
  backend lock, preserving the previous version on failure;
* destructive removal and cleanup require an ``InquirerPy`` confirmation or
  an explicit ``-y/--yes`` automation override;
* cleanup accepts only fixed managed areas, rejects symlink traversal, and
  never treats installed backends, active state, or locks as disposable;
* managed home subdirectories are rejected when replaced by symlinks, before
  permission repair or cleanup can affect their targets;
* private home directories and private JSON manifests on POSIX.

Planned runtime invariants:

* subscription URLs never appear in argv or displayed logs;
* generated provider/controller files are owner-only;
* controllers bind to loopback/private IPC and require a random secret;
* runtime descriptors validate process creation identity, not PID alone;
* backend output is redacted before display or persistence;
* managed downloads enforce time, size, and redirect policy.

JerryProxy does not bundle external backends. Their upstream licenses and
security policies remain independently applicable.
