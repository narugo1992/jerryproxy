Security model
==============

Backend binaries and subscription URLs are high-value inputs.

Current enforced backend invariants:

* exact upstream repository, tag, platform, and asset name;
* GitHub-provided SHA-256 digest required before automatic install;
* bounded HTTPS download and bounded extraction;
* archive traversal, symlink, and special-file rejection;
* private staging followed by atomic immutable install;
* atomic activation that preserves the previous version on failure;
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
