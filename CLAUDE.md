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
safe extraction, manifests, active-link switching, bounded
`V2RAY_SUBSCRIPTION` ingestion for Base64/plain SS/VMess/VLESS URI lines, and a
Mihomo `1.19.29` foreground session now exist. The listener is loopback-only
and open by default; authentication is explicit opt-in. The session keeps
subscription state below `JERRYPROXY_HOME`, probes the global health quorum,
restarts the current node once, sweeps deterministic alternates, and may refresh
the retained source once without rewriting the saved preference. Native profiles,
the other runtime cores, controller, measurement/ranking system, and historical
`v2raycli` compatibility remain planned. README and docs must keep that boundary
truthful.

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
- Runtime backend state management supports Linux, macOS, and Windows. Catalogs
  may retain official BSD assets for offline inspection, but BSD install/use
  must fail closed until equivalent atomic primitives and native CI exist.
  Filesystems that reject required no-replace or exchange operations must also
  fail closed; do not emulate them with pathname existence checks or multi-step
  swaps.
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
- Serialize every managed-state read and mutation for one logical home through
  the same home-wide upstream `filelock.FileLock` at
  `<home>/locks/jerryproxy.lock`, using the public API only and a default
  timeout of zero. The lock is a JerryProxy-home boundary, not a backend-local
  lock: backend installation, subscription fetch/publication, node inventory,
  runtime lease/config publication, health recovery, cleanup, and read-only
  inventory all contend on this one path.
- Never add PID/UUID owner metadata, inspect lock contents, infer stale
  ownership from the path, delete the lock file on release, access `filelock`
  private state, or implement a second platform lock.
- Keep the full install workflow under one acquisition, including cache
  validation, download, hashing, extraction, publication, probing, and optional
  activation. Composed operations must call private locked helpers instead of
  recursively acquiring a second lock.
- A foreground `RuntimeSession` owns this same home-wide lock from subscription
  selection through lease/config/access publication, backend launch, health and
  recovery, log draining, and final child/artifact cleanup. It must release the
  lock only after no child and no secret-bearing runtime path remain. Runtime
  code uses private locked manager/store helpers; it must not reacquire a second
  `FileLock` while the session is active.
- Read operations use the same home-wide lock. CLI list, doctor, and self-check
  must consume one `BackendInventory` snapshot for installed and active state.
  A completely absent or empty home has no managed state to lock and must
  produce an empty inventory without creating directories. Once any managed
  path exists, inventory reads must acquire the existing lock, validate the
  complete top-level layout and lock-path permissions without repairing them,
  and fail closed on partial state. Mandatory recovery of an already journaled
  removal transaction still runs on every acquired lock; it is not layout
  repair.
- Self-check must probe each built-in relay with one streamed, fixed 1 MiB Range
  from the repository-pinned public Xray asset. Use a five-second Requests
  timeout, require an HTTPS redirect chain, HTTP 206, exact `Content-Range`,
  exact byte count, and the pinned slice SHA-256. Report response-header latency,
  first-chunk latency, and post-startup stream speed separately. Relay availability and content failures
  are `WARN`; they never create a nonzero exit code without a separate `FAIL` or
  `ERR`. Never display effective URLs or response-controlled diagnostics.
- Python 3.7-3.9 use the newest compatible legacy `filelock` lines. Report that
  known limitation as `WARN`, recommend Python 3.10+, and do not attempt a local
  security repair. Python 3.10+ must use `filelock>=3.30` so fork ownership is
  handled by the upstream dependency.
- Install through a private staging directory and atomically rename only after
  validation succeeds.
- Never overwrite an installed version with different bytes.
- A failed install, use, or active-version uninstall must leave the
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
  must recheck object identity throughout traversal. POSIX cleanup must retain
  an open identity handle, atomically move ordinary targets to a random private
  name below the same pinned parent, verify the moved identity, and delete
  parent-relative. A hard exit may retain that private tombstone only inside a
  disposable cleanup area; the next cleanup of that area must inventory and
  remove it. Journaled transaction and activation candidate namespaces must not
  create a second unrecorded tombstone. Windows removal must retain a
  non-following native handle and delete through that handle. One-shot
  substitution before the POSIX isolation check must be detected and preserved.
  Continuous malicious same-UID replacement of a transient private name after
  its final identity check is outside the supported threat boundary and must be
  disclosed. A transaction may safely unlink only its journal-recorded
  active-command symlink; arbitrary aliases within a quarantine remain
  integrity failures.
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
- Keep the public backend command surface to `list`, `install`, `current`,
  `use`, `which`, `verify`, `uninstall`, and `clean`. Catalog discovery uses
  `list known [NAME] [VERSION]`; `known` is a reserved first query token, not a
  separate command. Do not expose `available`, `switch`, `remove`, compatibility
  aliases, or separate supported-backend, version-list, or artifact commands.
- `install NAME` is the single install/update entry point. Active-state queries
  use `current [NAME]`; do not introduce a separate update command. `use NAME
  VERSION` activates an already installed exact version and never installs or
  downloads it. `which NAME [VERSION]` returns only a manager-validated
  immutable executable path and never executes it.
- Keep `list known --json`, `list known NAME --json`, and `list known NAME
  VERSION --json` as overview-array, release-array, and exact artifact-object
  shapes respectively. Unspecified JSON limits return all records. Human
  truncation must report the shown and total counts. Keep `list NAME` scoped to
  that backend; unrelated active state must not affect the query.
- Human `list [NAME]` output is compact by default; executable and active-link
  paths require `--paths`. Read-only `list`, `current`, `which`, and `verify`
  commands keep stdout deterministic and support documented JSON output.
- Public destructive vocabulary is `uninstall --deactivate --cache` and `clean
  --cache`; do not expose `remove`, `--force`, or `--downloads`. Internal state
  directories may retain the `downloads` name.

## CLI structure and maintenance

- All Click command implementation belongs under `jerryproxy/cli/`. Do not add
  `jerryproxy/cli.py`, `jerryproxy/_cli*.py`, or command implementations in
  unrelated package modules. The repository-level `jerryproxy_cli.py` may only
  remain as the minimal PyInstaller launcher.
- Mirror the public command tree in the Python package tree. A leaf subcommand
  is one same-named `.py` module. A command with children is one same-named
  package, and that package's `__init__.py` assembles only its immediate child
  commands. `jerryproxy/cli/__init__.py` alone assembles the root command.
- Keep Click and InquirerPy ownership inside `jerryproxy/cli/`; product library
  modules must not import either CLI framework. Define each public leaf callback
  in its same-named module and each command-group callback in that group's
  `__init__.py`; package initializers only assemble their direct children.
- Every new CLI family must provide two deliberate entry modes. A short or
  incomplete command may enter an `InquirerPy` guided TUI only when stdin and
  stdout are real TTYs; the TUI must select from manager-owned, credential-free
  records and then invoke the same public operation as the explicit form.
  Complete command-line options must execute deterministically without prompts.
  JSON output, redirected/non-TTY execution, and `-y/--yes` must reject missing
  required targets rather than guessing a subscription, node, backend, version,
  or cleanup scope. `-y/--yes` bypasses confirmation only; it never selects a
  target. Help text and tests must document and verify both modes.
- Source-ingestion commands must make the source method explicit in guided
  mode: offer matching environment variables, direct secret input, a bounded
  file source, and bounded stdin where the command supports them. Discover
  environment names from the current process using narrow subscription-related
  keyword patterns, show names and set/hidden status only, and provide
  completion for custom environment-name input. Never print or log the bearer
  value. Review every new CLI interaction for discoverability, safe defaults,
  compact labels, keyboard flow, and parity between guided and explicit forms.
- Keep private cross-command helpers inside `jerryproxy/cli/` in clearly private
  modules such as `_common.py` and `_completion.py`. Leaf modules own their
  command-specific behavior; do not recreate a monolithic dispatcher or expose
  private compatibility aliases from package initializers.
- Keep shell completion non-initializing: it may read the static packaged
  catalog and manager-validated inventory or cache snapshots from an already
  initialized home under the operation lock, but must not access the network,
  create or repair the layout, interpret managed directories directly, or
  bypass path-alias checks. The normal mandatory recovery of an already
  journaled removal transaction still applies. Cover the supported Bash, Zsh,
  and Fish protocols, including Click choice completion for public option
  values such as relay modes.
- The project is unpublished. CLI redesigns must remove obsolete commands,
  options, modules, aliases, and tests cleanly instead of retaining backward-
  compatibility shims without an explicit release requirement.
- Every command help page begins with one sentence that states its purpose,
  then documents forms, behavior boundaries, interaction, output, important
  options, and examples as applicable. Verify the actual Click-rendered
  `--help` at 72, 80, 100, and 120 columns; readable source docstrings alone are
  not evidence. Human tabular output must use `tabulate`, never hand-built
  column formatting.

## Secrets and state

- Default state is rooted only at `~/.jerryproxy`, with `--home` and
  `JERRYPROXY_HOME` as explicit overrides.
- POSIX directories are `0700`; credential/state files are `0600`.
- Subscription URLs are bearer credentials. Never print them or pass them on a
  command line. Redact URL userinfo, queries, fragments, UUIDs, passwords,
  public keys, and short IDs from captured backend output.
- The local proxy listener is loopback-only and has no authentication by
  default. `server --auth` is explicit opt-in; its one-time human startup
  guide may print the generated local username, password, and proxy URL, while
  JSON output and persistent JerryProxy/backend logs must not contain those
  credentials. Controller endpoints still use a random private secret.
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
- `jerryproxy.subscription` owns bounded source transport, URI classification,
  private revision publication, and sanitized node inventory. It must not
  normalize protocol-specific credentials/settings into a second core.
- `jerryproxy.subscription.interfaces` owns the stable `ProxyNode`,
  `NodeSource`, and `SubscriptionParser` contracts. A subscription parser is
  an injected adapter; adding a new container must not add protocol branches to
  the runtime session or duplicate credential-bearing node models. A future
  single-node input must implement `NodeSource` rather than create a second
  runtime selection path.
- `jerryproxy.runtime` owns the current Mihomo projection, loopback listener,
  one merged named backend output stream, connectivity quorum, and the
  bounded foreground recovery policy. Future runtime drivers own other cores,
  native profiles, and backend control APIs.
- `jerryproxy.runtime.interfaces` owns the `RuntimeDriver` and
  `RuntimeProjection` contracts. Drivers own backend config syntax and child
  lifecycle; `RuntimeSession` owns the home-wide lock, private publication,
  credentials, health/recovery policy, and sanitized output. No driver may
  acquire a second home lock.
- Relay-health target configuration lives in the maintainer Gist, not in this
  repository or package. `make relay_health_sync` downloads one ignored local
  JSON file. The tool must pin the reviewed official probe asset and constrain
  every Gist-controlled display classification before probing or rendering.
  `tools.relay_health` and `tools.render_relay_health` operate only on local
  files; Gist result upload and Wiki Git publication belong only to separate
  credential-scoped jobs in the repository workflow. Publishers must verify
  the `narugo1992` identity before mutation. The workflow owns only the
  generated `Relay-Health.md` page; the Wiki `Home.md` navigation page is
  maintained separately and its hash must remain unchanged across publication.
  Relay health uses three streamed 1 MiB samples per pattern with a ten-second
  Requests timeout, records response-header latency, first-chunk latency, and
  post-startup stream speed separately, and summarizes short-window stability.
  Relay-health code must not enter `jerryproxy`.

Do not allow remotely downloaded Python plugins in the initial architecture.
Backend drivers execute high-privilege lifecycle operations and must remain
built in until a separate trust model is designed.

## Self-check integration discipline

`jerryproxy self-check` is the installed-product integration diagnostic for an
unknown host. It complements deterministic unit tests; it must not duplicate
private branch coverage or replace the normal test matrix.

- Print the JerryProxy version, Python implementation and version, frozen-build
  state, operating system, release, machine architecture, `os.name`, and the
  selected home before check items run. Do not print hostnames, credentials, or
  subscription material.
- Give each major business capability its own check item. Keep resource access,
  catalog selection, locking, isolated backend lifecycle, install recovery,
  activation rollback, activation rollforward, removal rollback, removal
  rollforward, inventory, and each relay probe independently identifiable.
- Resource-file checks must call the packaged Python API that owns the resource.
  They must not open package-data paths directly. Verify existing data
  consistency contracts through that API, but do not invent a schema or
  migration mechanism for data that has no such contract.
- A key upstream dependency check must execute one small real capability, not
  merely import the package or compare a version string. In particular,
  `filelock` must demonstrate exclusive acquisition, contention, release, and
  reacquisition; Requests relay checks must perform their bounded streamed
  verification.
- Business probes must use public managers, transactions, and packaged resource
  APIs where practical. Run mutating probes only in private temporary homes,
  use local synthetic backend archives, disable backend execution, perform no
  upstream backend download, and leave the configured user home untouched.
- Interface contracts must have at least one behavior test: parser injection
  must cover publication and reload through the same adapter, node sources must
  expose only the sanitized public view plus an explicit runtime secret URI
  boundary, and a runtime driver must be replaceable without changing session
  lock ownership or recovery semantics.
- Recovery diagnostics must use spawned child processes that terminate through
  a real hard exit after durable transaction milestones. The parent must
  reacquire the normal home-wide lock and verify rollback or rollforward,
  active-command usability, and removal of recovery evidence. Keep every child
  and network wait bounded by explicit per-operation and total timeouts. A
  timed-out child must be terminated, escalated to a hard kill if necessary,
  joined, and reported as ERR rather than left running. Prefer `spawn` on every
  platform so bounded process startup does not fork from its supervising
  thread; use `fork` only when `spawn` is unavailable.
- Process startup itself belongs to the same total deadline as child execution.
  Run the blocking start call in a daemon supervision thread. A new child must
  wait behind a parent authorization gate and must exit on cancellation, so a
  start call that returns after the deadline cannot enter business code or
  remain as an unmanaged child. Aggregate every delayed-start cleanup in one
  per-run supervisor and report a final independent check item; pending cleanup
  or a child still alive after kill is ``ERR``.
- Production relay checks must run in dedicated child processes. The parent
  enforces one 30-second wall-clock deadline across child startup, redirects,
  response headers, empty chunks, and streaming. Deterministic unit tests may
  inject a session factory and run the transport probe inline. A deadline is
  ``WARN`` only after the child is confirmed stopped; an unstoppable child is
  ``ERR``.
- Child result transport must be file-based or otherwise provably bounded and
  nonblocking. The parent must stop or join the child before reading its result
  and must never perform an unbounded pipe receive after a readiness signal.
  Result files require strict schema, type, size, and encoding validation.
- Redirect unexpected child stderr to a private capture before business code
  runs, and redirect raw file descriptor 2 away from the caller terminal.
  Buffer complete bounded lines across writes, redact them before persistence,
  and only then apply the capture limit. Capture files must be mode ``0600``
  where POSIX modes apply, created exclusively without following an existing
  alias, bounded before reading, redacted again before rendering, and read only
  after the child is stopped.
- Child cleanup is an independent best-effort sequence: bounded join,
  terminate, bounded join, hard kill when still alive, and final bounded join.
  A failure in one stage must be recorded but must never suppress later cleanup
  stages. Treat an unreadable liveness state as alive and attempt the hard kill.
- Report `SKIP` in cyan when a system, Python runtime, packaging mode, or failed
  prerequisite makes a check meaningless or impossible. A skip is neither a
  success claim nor an error and never changes the exit code. Do not use SKIP to
  hide a check that started and then failed.
- `OK`, `WARN`, and `SKIP` output stays to one line per item. `FAIL` and `ERR`
  must state the failed invariant or exception. `ERR` and abnormal child exits
  should include bounded, redacted traceback or child-log lines when available.
  Unexpected process crashes may retain a captured, bounded runtime traceback.
  Never expose effective relay URLs, URL queries, provider contents, tokens,
  UUIDs, keys, or backend output that has not passed the normal redaction
  boundary.
- Apply diagnostic redaction at both exception/child-log capture and final
  rendering boundaries, before length limits. Redact complete URLs, named
  passwords and tokens, UUIDs, public/private key material, and short IDs.
- Only `FAIL` and `ERR` produce a nonzero final exit code. `WARN` and `SKIP`
  retain zero. Keep this rule covered through the public command and renderer.
- Unit tests for self-check must cover status rendering, colors, exit semantics,
  prerequisite skips, diagnostic detail, bounded timeouts, isolation from the
  configured home, and at least one real spawn-based recovery path. Standalone
  CI must continue to execute the packaged binary's `self-check --color` so
  frozen multiprocessing and packaged resources receive end-to-end evidence.

## Testing and commands

```shell
make unittest
make unittest RANGE_DIR=./backend
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

Self-check has exactly five levels: `OK` is green, `WARN` is yellow, `SKIP` is
cyan, and `FAIL`/`ERR` are red. Only `FAIL` and `ERR` contribute a nonzero exit
status.

Every unit-test matrix cell must produce its own `coverage.xml` and upload it to
Codecov with the shared `python` aggregation flag and a unique environment
upload name. Upload failures fail trusted CI jobs. Fork pull requests must skip
the upload because GitHub intentionally withholds repository secrets; their
tests and local coverage reports still run normally. Coverage reported by a
single CI matrix cell is informational and has no per-cell minimum. Codecov's
cross-platform aggregated result is the authoritative coverage signal.
The Makefile and test workflows must not define or accept a local coverage
minimum such as `MIN_COVERAGE`, `--cov-fail-under`, or an equivalent hard gate;
coverage thresholds are reviewed only from the final Codecov aggregate.
Development should pursue the highest practical coverage, especially at
security and recovery boundaries. Never print or persist `CODECOV_TOKEN`.
Do not use `pragma: no cover` (or equivalent source pragmas) to hide executable
branches. Platform-only code must remain visible in the aggregate result and
be exercised by its native CI lane where applicable. Never omit an entire mixed
platform module to improve the reported result.
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
- Foreground `server` startup guidance is emitted through the same structured
  JerryProxy log path as runtime events. Human mode uses Rich styling to make
  the proxy URL, environment variables, endpoint, and explicit authentication
  details conspicuous; it must not use ad-hoc direct printing for those lines.
  Human startup prints one readiness summary, one proxy URL, and a compact
  multi-line shell guide. `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` must
  contain the same URL, including a `socks5h` URL for a SOCKS5 listener. Do not
  print access-file or log-file paths in that guide; runtime log filenames
  include the UTC startup timestamp to the second plus a unique session id.
  Rich console width must be detected from the active terminal or pipe; do not
  hard-code a display width. Keep the guide as one multi-line log record so
  its lines do not repeat a log prefix, while runtime events remain one record
  per event. JerryProxy-owned records have no owner prefix; backend records use
  the backend name (`[mihomo]`, `[v2ray]`, and so on) and merge stdout/stderr
  into that one owner stream. Backend lines are decoded only for bounded
  diagnostics, redacted for credentials, made terminal-safe, and forwarded
  live; `OFF` drains without forwarding or persisting backend content.
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
