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
- Install through a private staging directory and atomically rename only after
  validation succeeds.
- Never overwrite an installed version with different bytes.
- A failed install or switch must leave the previous active backend usable.
- Do not auto-update or execute a newly downloaded backend without an explicit
  user operation and a tested version policy.

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
- `jerryproxy.backend.manager`: immutable installation, activation, rollback,
  and removal.
- Future runtime drivers own generated configuration and backend control APIs.
- Future subscription management may fetch and inventory containers, but must
  not normalize protocol-specific credentials/settings into a second core.

Do not allow remotely downloaded Python plugins in the initial architecture.
Backend drivers execute high-privilege lifecycle operations and must remain
built in until a separate trust model is designed.

## Testing and commands

```shell
make unittest
make unittest RANGE_DIR=./backend
make unittest MIN_COVERAGE=90
make lint
make rst_auto
make rst_auto RANGE_DIR=backend
make docs
make package
make build
make build_linux
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

Every unit-test matrix cell must produce its own `coverage.xml` and upload it to
Codecov with the shared `python` aggregation flag and a unique environment
upload name. Upload failures fail trusted CI jobs. Fork pull requests must skip
the upload because GitHub intentionally withholds repository secrets; their
tests and local coverage gate still run normally. The statement-coverage floor
is 90% locally and in every matrix cell. Never print or persist
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
