# JerryProxy

JerryProxy is a Python 3.7+ command-line application for installing, verifying,
switching, and eventually orchestrating multiple external proxy backends. The
PyPI distribution, Python import, GitHub repository, CLI command, and default
home directory all use the same name: `jerryproxy`.

> **Work in progress:** the backend version manager is implemented in this
> repository. Subscription ingestion, proxy runtime generation, authenticated
> Mihomo control, and the compatibility layer for the historical `v2raycli`
> command surface are planned but are not yet implemented.

## Current status

Implemented now:

- a pure-Python package and CLI compatible with Python 3.7+;
- one cross-platform state root at `~/.jerryproxy`, overridable with
  `JERRYPROXY_HOME` or `--home`;
- built-in backend definitions for Mihomo, Xray, and V2Ray;
- exact official GitHub release-asset selection for the current OS/CPU;
- mandatory GitHub-provided SHA-256 digest verification;
- bounded HTTPS downloads and safe ZIP/TAR/GZip extraction;
- immutable installations under
  `~/.jerryproxy/backends/<backend>/<version>/`;
- atomic version activation at `~/.jerryproxy/bin/<backend>`;
- relative symbolic links on supported systems and an atomic executable-copy
  fallback where Windows symlink privileges are unavailable;
- an active-version manifest that records the selected version and link mode;
- a lightweight packaged-CLI self-check with isolated failure diagnostics;
- two-stage standalone validation that builds on Python 3.7 and executes the
  downloaded artifact on a separate clean runner for each supported OS;
- deterministic offline unit tests, Sphinx documentation, packaging checks,
  and Linux/Windows/macOS CI definitions.

Not implemented yet:

- subscription download, bounded inventory, and credential redaction;
- generated Mihomo provider/listener/controller configuration;
- `run`, `start`, `stop`, `status`, `list`, `select`, `test`, and `refresh`
  runtime commands;
- safe foreground/detached process supervision and runtime descriptors;
- the legacy `V2RAY_*` environment and option compatibility layer;
- Xray/V2Ray runtime drivers beyond binary installation and activation;
- PyPI publication, signed standalone executables, and Read the Docs hosting.

## Why JerryProxy exists

Mihomo can directly consume heterogeneous HTTP subscriptions and already owns
protocol conversion, provider refresh, node health, routing, DNS, TUN, and a
REST control API. It does not provide an end-user command such as
`mihomo run --subscription ...`, nor does it install and pin its own binary.

JerryProxy is intended to own that missing user and lifecycle layer without
reimplementing VMess, VLESS, REALITY, Shadowsocks, or other protocol schemas in
Python.

## Installation

The project is not published on PyPI yet. For development:

```shell
git clone https://github.com/narugo1992/jerryproxy.git
cd jerryproxy
python -m pip install -e .
python -m pip install -r requirements-test.txt
```

When published, the intended entry point will be:

```shell
pip install jerryproxy
```

The same CLI is available through either form:

```shell
jerryproxy --help
python -m jerryproxy --help
```

## Backend manager quick start

Inspect built-in backend drivers and the selected home:

```shell
jerryproxy home
jerryproxy backend supported
jerryproxy doctor
jerryproxy self-check
```

Install and activate one exact upstream version:

```shell
jerryproxy backend install mihomo 1.19.29
jerryproxy backend current mihomo
```

Install another version without activating it, then switch atomically:

```shell
jerryproxy backend install mihomo 1.19.28 --no-activate
jerryproxy backend switch mihomo 1.19.28
jerryproxy backend list mihomo
```

On Unix-like systems the active command is a relative symbolic link:

```text
~/.jerryproxy/bin/mihomo
  -> ../backends/mihomo/1.19.28/mihomo
```

On Windows the command normally ends in `.exe`. If symbolic-link creation is
not permitted, JerryProxy atomically copies the verified executable and records
`link_mode: copy` in `~/.jerryproxy/active/mihomo.json`.

Remove an inactive version:

```shell
jerryproxy backend remove mihomo 1.19.29
```

Removing the active version fails closed unless `--force` is explicit.

## Directory layout

```text
~/.jerryproxy/
├── active/          # Active-version manifests
├── backends/        # Immutable backend versions
├── bin/             # Active backend links/copies
├── downloads/       # Verified release archives
├── locks/           # Concurrent operation locks
├── logs/            # Future wrapper/core logs
├── providers/       # Future private subscription provider files
└── runtimes/        # Future runtime descriptors and generated configs
```

The entire tree is private (`0700`) on POSIX systems. JSON state and secret
files are written atomically as `0600`. Windows ACL hardening is part of the
runtime security roadmap; the current design keeps every path beneath the
current user's profile.

## Self-check

`jerryproxy self-check` actively validates the packaged Python runtime, host
platform mapping, private home layout and write access, POSIX directory modes,
backend registry, and installed/active backend inventory. Each check is
isolated: a failure prints its check name, exception type, and message, while
the remaining checks continue. The final summary exits nonzero when any check
fails.

The check is local and network-free. It does not download or start a backend:

```shell
jerryproxy --home ./test_self_check self-check
```

## Backend supply-chain rules

JerryProxy does not bundle or import backend implementations. The manager:

1. requests one exact upstream release tag;
2. selects one exact asset name for the detected OS and architecture;
3. rejects assets without a valid `sha256:` digest in GitHub metadata;
4. downloads over HTTPS with size bounds;
5. verifies size and SHA-256 before extraction;
6. rejects archive traversal, symlinks, and special files;
7. installs into an immutable version directory;
8. changes the active backend only after installation succeeds.

Official upstream repositories currently registered:

| Backend | Upstream | Planned role |
|---|---|---|
| Mihomo | `MetaCubeX/mihomo` | Preferred default candidate pending compatibility/security PoC |
| Xray | `XTLS/Xray-core` | Optional Xray-family specialist backend |
| V2Ray | `v2fly/v2ray-core` | Legacy compatibility backend |

The backend binaries keep their upstream licenses. They are downloaded from
upstream after installation and are not conveyed inside the Apache-2.0
JerryProxy wheel.

## Planned user experience

The intended stable workflow is:

```shell
export JERRYPROXY_SUBSCRIPTION='https://provider.example/subscription'

jerryproxy run
jerryproxy status
jerryproxy list
jerryproxy select 3
jerryproxy test
jerryproxy refresh
jerryproxy stop
```

`run` will ensure a tested backend exists, install the pinned default when
needed, create private state, load the subscription without exposing its URL,
and report the loopback HTTP/SOCKS endpoint.

## Roadmap

- [x] Establish the Python 3.7+ package, CLI, tests, docs, and CI skeleton.
- [x] Implement versioned backend storage and active-link switching.
- [x] Implement exact release-asset resolution and digest-verified downloads.
- [x] Implement safe archive extraction and immutable manifests.
- [x] Add lightweight self-check and clean-runner standalone artifact gates.
- [ ] Add a signed/tested backend catalog and configurable trusted mirrors.
- [ ] Add offline archive installation with an explicit digest.
- [ ] Implement managed subscription fetch and private file providers.
- [ ] Implement the Mihomo runtime driver and authenticated controller client.
- [ ] Implement runtime locks, descriptors, foreground/detached operation.
- [ ] Preserve documented `v2raycli` inputs through deprecated aliases.
- [ ] Add native HTTP-provider mode as an explicit alternative.
- [ ] Add Xray and V2Ray runtime drivers only for concrete compatibility gaps.
- [ ] Publish PyPI alpha and standalone cross-platform executables.
- [ ] Add upgrade/rollback integration tests against real pinned backends.

See [the documentation](docs/source/index.rst) for architecture and security
details. The complete implementation plan is also tracked in the repository's
initial planning issue.

## Development

The repository exposes the same commands locally and in CI:

```shell
make help
make unittest
make lint
make docs
make package
make build
make check
```

Every main-branch push and pull request runs the following independent gates:

- unit tests on Linux, Windows, and macOS for every supported Python version
  from 3.7 through 3.14 (24 matrix cells, with no excluded combinations);
- strict Sphinx HTML documentation with warnings treated as errors;
- staged sdist and wheel builds, followed by clean artifact-only installation
  smoke tests on Python 3.7 and 3.14;
- two-stage standalone validation on `ubuntu-22.04`, `windows-2022`, and
  `macos-15-intel`: Stage 1 builds with Python 3.7 and uploads the binary;
  Stage 2 starts a clean runner without checkout, Python setup, or dependency
  installation, downloads that exact artifact, verifies its digests, extracts
  the release archive, runs `self-check`, and exercises the packaged CLI
  commands from the extracted binary.

Read [CLAUDE.md](CLAUDE.md) before changing architecture, backend metadata,
download/extraction code, credential handling, or release workflows.

## License

JerryProxy is licensed under the Apache License 2.0. External backends remain
independent programs under their respective upstream licenses.
