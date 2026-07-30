# CLAUDE.md

`AGENTS.md` is a symbolic link to this file. Never edit or replace both files
independently.

## Project contract

JerryProxy is a Python 3.7+ command-line application that manages external
proxy backend binaries and will provide an out-of-the-box runtime experience.
The package must not implement evolving proxy protocols in Python and must not
bundle Mihomo, sing-box, Xray, V2Ray, or other backend binaries in its wheel.

The canonical technical identifiers are all `jerryproxy`:

- repository: `narugo1992/jerryproxy`;
- PyPI distribution and Python import: `jerryproxy`;
- command: `jerryproxy`;
- default home: `~/.jerryproxy`;
- environment prefix: `JERRYPROXY_`.

## Current WIP boundary

The backend version manager, official release resolution, verified downloads,
safe extraction, manifests, and active-link switching exist. Proxy runtime,
subscription, controller, and historical `v2raycli` compatibility features are
planned. README and docs must keep that boundary truthful.

## Engineering discipline

- Write requirements, boundaries, inputs, outputs, and verification criteria
  before implementing behavior.
- Prefer the smallest coherent change that advances the documented product.
- Do not introduce a second architecture beside the existing backend catalog,
  installer, manager, and future runtime-driver boundaries.
- Every behavior change requires focused tests. Security-boundary changes need
  adversarial failure tests.
- Never claim completion without fresh test/build/docs evidence.
- Keep workflow issue numbers, roadmap phases, and temporary implementation
  labels out of code identifiers and public APIs.
- Use English in source, identifiers, docstrings, logs, CLI output, and project
  documents. Respond to collaborators in the language they use.

## Python 3.7 compatibility

Source must import and execute on CPython 3.7. Do not use:

- PEP 585 built-in generics such as `list[str]`;
- PEP 604 unions such as `Path | None`;
- structural pattern matching;
- `tomllib`, `ExceptionGroup`, or other newer-only standard-library APIs;
- dependencies whose selected version excludes Python 3.7.

Use `typing.List`, `typing.Optional`, `typing.Union`, type comments where
necessary, ABCs rather than newer protocols, and JSON rather than TOML/YAML for
generated state. Validate with `python3.7 -m pytest` whenever the interpreter is
available.

## Exception policy

Catch the smallest documented exception class. Broad `except Exception` is
prohibited. Every catch must include a short comment naming the expected
failure source. Never swallow unexpected failures or downgrade integrity,
authentication, extraction, process, or permission errors to warnings.

## Backend supply-chain invariants

- Backend release catalogs are four flat, static resources under
  `jerryproxy/data/`: `mihomo.json`, `sing-box.json`, `v2ray.json`, and
  `xray.json`. They contain official stable releases only and use no catalog
  format-version or migration mechanism.
- Runtime catalog reads must go through `from jerryproxy.data import ...`.
  Runtime modules must not open those JSON paths directly.
- Catalog refresh logic belongs only in the repository `tools` package. It is
  maintainer tooling, is excluded from the JerryProxy wheel, and must never be
  invoked by the library or CLI at runtime. Users refresh available resources
  by upgrading JerryProxy with `pip install -U jerryproxy`.
- Prefer SHA-256 digests returned directly by the GitHub release API. For old
  assets without that field, maintenance tooling may reuse unchanged recorded
  evidence or read official upstream checksum text files. It must not download
  backend archives to calculate catalog fingerprints itself.
- Backend versions install into immutable
  `~/.jerryproxy/backends/<name>/<version>/` directories.
- Active commands live at `~/.jerryproxy/bin/<name>` (`.exe` on Windows).
- Use relative symbolic links where supported. A Windows copy fallback is
  allowed only when the active manifest records `link_mode: copy`.
- Exact upstream tags and exact platform assets are required. Do not select an
  asset through fuzzy substring matching.
- Automatic upstream installation requires a valid SHA-256 digest in release
  metadata. HTTPS alone is not integrity evidence.
- Keep download and extraction size bounds. Reject path traversal, archive
  symlinks, device files, duplicate executables, and unexpected layouts.
- Backend archive transport uses streamed `requests` responses and a `tqdm`
  byte progress/status display on stderr. Preserve system proxy/CA behavior,
  keep stdout machine-readable, and retain deterministic injection points for
  unit tests.
- Complete CLI installs default to `--relay auto`: direct GitHub first, then
  the built-in relays in their documented fixed order, advancing only after a
  transport failure. `--relay direct` prohibits relay fallback, and an
  invocation-scoped `--relay-url` replaces the implicit default without an
  option conflict.
- Backend release relays may transport only public official GitHub Release
  asset URLs. Automatic fallback is the CLI default, begins with direct GitHub,
  and catches transport failures only; integrity, redirect-policy, size-bound,
  and local filesystem failures are terminal. Manifests retain the official
  catalog URL rather than the effective relay URL.
- Keep `urllib3` below 2 while Python 3.7/OpenSSL 1.1.0 standalone build
  compatibility remains a target; use the latest patched 1.26 release floor.
- Serialize all managed-state reads and mutations for one logical home through
  the upstream `filelock.FileLock` at `<home>/locks/jerryproxy.lock`, using the
  public API only and a default timeout of zero.
- Never add PID/UUID owner metadata, inspect lock contents, infer stale
  ownership from the path, delete the lock file on release, access `filelock`
  private state, or implement a second platform lock.
- Keep the full install workflow under one acquisition, including cache
  validation, download, hashing, extraction, publication, probing, and optional
  activation. Composed operations must call private locked helpers instead of
  recursively acquiring a second lock.
- Read operations use the same home-wide lock. CLI list, doctor, and self-check
  must consume one `BackendInventory` snapshot for installed and active state.
- Python 3.7-3.9 use the newest compatible legacy `filelock` lines. Report that
  known limitation as `WARN`, recommend Python 3.10+, and do not attempt a local
  security repair. Python 3.10+ must use `filelock>=3.30` so fork ownership is
  handled by the upstream dependency.
- Install through a private staging directory and atomically rename only after
  validation succeeds.
- Never overwrite an installed version with different bytes.
- A failed install, switch, or forced active-version removal must leave the
  previous active backend usable. If rollback itself fails, preserve every
  remaining recovery artifact instead of deleting the evidence.
- Removal stages selected downloads, installed versions, and active state into
  one private `runtimes/.remove-*` quarantine through atomic renames. A staging
  journal with no format-version field must be persisted before the first rename.
  A staging failure must roll back in reverse order before physical deletion.
  Every later home-lock acquisition must recover an interrupted staging journal
  by restoring it, or finish disposal for an interrupted committed journal.
  Invalid, ambiguous, aliased, or identity-mismatched journals fail closed with
  `IntegrityError`. Once all public paths are absent, quarantine deletion
  failure is a `RemovalCleanupError`; retain the quarantine for explicit runtime
  cleanup.
- Do not auto-update or execute a newly downloaded backend without an explicit
  user operation and a tested version policy.
- Backend cleanup may empty only `downloads`, `logs`, `providers`, and
  `runtimes`. It must never treat `backends`, `bin`, `active`, or `locks` as
  disposable. Backend/version-scoped cleanup applies only to downloads.
- Cleanup and backend removal must reject managed symlink and Windows
  reparse-point components, including junctions, share the home-wide lock with
  downloads/install/removal, remain idempotent for missing cleanup targets, and
  never escape the configured JerryProxy home. Revalidate each cleanup target's
  complete managed ancestor chain and removal tree before deletion. Recursive
  removal must use alias-aware JerryProxy code rather than `shutil.rmtree`, and
  must recheck object identity throughout traversal. POSIX removal must retain
  an open identity handle and use parent-relative deletion; Windows removal
  must retain a non-following native handle and delete through that handle.
  Pathname replacement must not redirect the final deletion system call. A
  transaction may safely unlink only its journal-recorded active-command
  symlink; arbitrary aliases within a quarantine remain integrity failures.
- Home initialization must reject symlinked or Windows reparse-point managed
  subdirectories before and immediately after creation, before applying
  permissions or mutating through them. It must also reject an aliased lock file
  before `filelock` opens it. The configured home root itself may be an alias.
- Destructive removal and cleanup require an `InquirerPy` confirmation. The
  `-y/--yes` bypass exists for complete non-interactive commands and must not
  infer a missing backend, version, or cleanup scope.
- Keep complete backend commands deterministic for automation. Missing targets
  may enter guided `InquirerPy` selection, while established no-argument
  read-only commands retain their all-backend meaning.
- Keep the public backend command surface to `available`, `install`, `list`,
  `switch`, `verify`, `remove`, and `clean`. Catalog discovery uses
  `available [NAME] [VERSION]`; do not reintroduce separate supported-backend,
  version-list, or artifact commands.
- `install NAME` is the single install/update entry point. Active-state queries
  use `list [NAME] --active`; do not reintroduce separate update or current
  commands.
- Keep `available --json`, `available NAME --json`, and
  `available NAME VERSION --json` as overview-array, release-array, and exact
  artifact-object shapes respectively. Keep `list NAME` scoped to that
  backend; unrelated active state must not affect the query.

## Secrets and state

- Default state is rooted only at `~/.jerryproxy`, with `--home` and
  `JERRYPROXY_HOME` as explicit overrides.
- POSIX directories are `0700`; credential/state files are `0600`.
- Subscription URLs are bearer credentials. Never print them or pass them on a
  command line. Redact URL userinfo, queries, fragments, UUIDs, passwords,
  public keys, and short IDs from captured backend output.
- Controller endpoints bind to loopback or private local IPC and use a random
  private secret.
- Do not commit real subscriptions, backend caches, generated configs, runtime
  descriptors, release tokens, or logs.

## Architecture boundaries

- `jerryproxy.backend.registry`: built-in backend identity and exact asset
  naming.
- `jerryproxy.data`: the only reader for packaged static catalog resources.
- `jerryproxy.backend.catalog`: strict offline catalog validation and artifact
  selection. It performs no release API request.
- `jerryproxy.backend.download`: bounded HTTPS and digest verification.
- `jerryproxy.backend.archive`: safe extraction only.
- `jerryproxy.backend.removal`: private crash recovery and alias-aware removal
  primitives. It exposes no supported user-facing API.
- `jerryproxy.backend.manager`: immutable installation, activation, rollback,
  and removal.
- `jerryproxy.lock`: direct home-wide `filelock` integration and compatibility
  status. It must not grow a second lock implementation.
- Future runtime drivers own generated configuration and backend control APIs.
- Future subscription management may fetch and inventory containers, but must
  not normalize protocol-specific credentials/settings into a second core.
- Relay-health target configuration lives in the maintainer Gist, not in this
  repository or package. `make relay_health_sync` downloads one ignored local
  JSON file. The tool must pin the reviewed official probe asset and constrain
  every Gist-controlled display classification before probing or rendering.
  `tools.relay_health` and `tools.render_relay_health` operate only on local
  files; Gist result upload and Wiki Git publication belong only to separate
  credential-scoped jobs in the repository workflow. Publishers must verify
  the `narugo1992` identity before mutation. The workflow owns only the
  generated `Relay-Health.md` page; the Wiki `Home.md` navigation page is
  maintained separately. Relay-health code must not enter `jerryproxy`.

Do not allow remotely downloaded Python plugins in the initial architecture.
Backend drivers execute high-privilege lifecycle operations and must remain
built in until a separate trust model is designed.

## Testing and commands

```shell
make unittest
make unittest RANGE_DIR=./backend
make unittest MIN_COVERAGE=97
make lint
make rst_auto
make rst_auto RANGE_DIR=backend
make docs
make package
make build
make build_linux
make relay_health_sync
make relay_health_check
make relay_health_wiki
make relay_health_gate
make check
python3.7 -m pytest test -m unittest
```

Unit tests must be deterministic and network-free. Test behavior through public
commands, entry points, classes, and functions; do not call private helpers only
to increase coverage. Prefer real execution with temporary directories, files,
archives, subprocesses, loopback services, and operating-system behavior.
Mocking is permitted only when the real boundary is nondeterministic,
credentialed, destructive, platform-inaccessible, or required to reproduce a
specific failure atomically. Keep each mock at the narrow external boundary and
assert the resulting public behavior. Model GitHub responses locally because
unit tests must not depend on external network availability. Real backend
integration tests belong in an explicit credential-free integration lane and
must pin versions and asset digests.

The product unit-test boundary is the `jerryproxy` package. Do not create a
`test/tools` package, import repository maintenance modules from tests, or
unit-test scripts below `tools/`. Validate maintenance tools through their
dedicated Make targets and repository workflows instead.

Self-check has exactly four levels: `OK` is green, `WARN` is yellow, and
`FAIL`/`ERR` are red. Only `FAIL` and `ERR` contribute a nonzero exit status.

Every unit-test matrix cell must produce its own `coverage.xml` and upload it to
Codecov with the shared `python` aggregation flag and a unique environment
upload name. Upload failures fail trusted CI jobs. Fork pull requests must skip
the upload because GitHub intentionally withholds repository secrets; their
tests and local coverage gate still run normally. The statement-coverage floor
is 97% locally and in every matrix cell. Never print or persist
`CODECOV_TOKEN`.
The `test` tree is a Python package: every directory below `test/` must contain
an `__init__.py`, including newly added test-area directories.

Standalone CI is a two-stage contract. Linux must build through
`make build_linux` inside the digest-pinned official Python 3.7.11 Docker image
declared in the Makefile; do not silently replace it with a hosted-runner build
or an unpinned image tag. Windows and macOS use pinned hosted runners with
Python 3.7. Verification must run on a separate clean runner, download the
first-stage artifact, avoid source checkout and dependency installation, and
exercise the packaged binary through `self-check --color` plus public read-only
commands. The same Linux artifact must pass in digest-pinned Ubuntu 18.04,
Ubuntu 20.04, Debian 10, Oracle Linux 7, CentOS 7, Amazon Linux 2, and openSUSE
Leap 15.0 containers. Each job must verify both distribution ID and version;
the build ELF gate must reject external glibc symbol requirements newer than
2.17. Do not substitute unit tests, ELF inspection, or build-container
execution for clean compatibility-container verification.
The standalone builds use Python 3.7 and therefore bundle the legacy `filelock`
line. Documentation and self-check must disclose that risk and direct users who
prioritize upstream lock hardening to the Python 3.10+ pip installation.
Document EOL compatibility targets as binary regression environments, never as
a claim of continuing distribution security maintenance.

Generated API documentation is a repository contract. Python source under
`jerryproxy/` is the source of truth; `docs/source/api_doc.rst` and
`docs/source/api_doc/` are generated English-only outputs and must not be
edited by hand. Before committing public Python module, class, function, or
data-object changes, run `make rst_auto` and include every intentional RST
change in the same commit. Use `make rst_auto RANGE_DIR=<package>` for focused
iteration, then run the unrestricted target before commit. Removing or moving a
source module also requires removing any obsolete generated page. Docs CI must
force regeneration and fail when tracked or untracked generated output differs.

## Documentation policy

- README begins with a prominent WIP boundary until proxy runtime works.
- Keep current behavior and roadmap items separate.
- Every public command, state file, environment variable, and security default
  needs documentation before stable release.
- Generated Python API pages are part of the English Sphinx toctree and must
  remain reproducible through `make rst_auto`.
- Do not use copied Tom and Jerry artwork. Any mouse/cheese visual identity
  must be original; logo assets are not part of the initial scaffold.

## Repository identity and releases

The repository owner, primary maintainer, release authority, and PyPI Trusted
Publisher owner is `narugo1992`. Preserve accurate authorship for all
contributors; never falsify or rewrite contributor attribution.

For owner-maintenance operations in the configured development environment,
every `gh` command must be invoked with:

```shell
GH_TOKEN=$(gh auth token --user narugo1992) gh ...
```

Before any remote mutation, verify `gh api user` reports `narugo1992`. Repository
local Git author and committer identity must be `narugo1992` for maintainer
commits. Releases, backend catalog changes, workflow permissions, and package
publishing require `narugo1992` approval.

Never commit a backend binary, secret, token, real subscription, or generated
provider file. PyPI releases use Trusted Publishing instead of a long-lived
token.
