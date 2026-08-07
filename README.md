# JerryProxy

JerryProxy is a Python 3.7+ command-line application for installing, verifying,
switching, and eventually orchestrating multiple external proxy backends. The
PyPI distribution, Python import, GitHub repository, CLI command, and default
home directory all use the same name: `jerryproxy`.

> **Work in progress:** the first runtime slice is implemented: bounded
> `V2RAY_SUBSCRIPTION` ingestion for Base64/plain SS, VMess, and VLESS URI
> lines, sanitized home-local state, and a synchronous Mihomo 1.19.29
> foreground server with bounded health diagnostics. The CLI binds an open
> listener to `127.0.0.1` by default; `--auth` enables generated local
> credentials and `--bind-all` explicitly selects `0.0.0.0`. Native profiles,
> other core drivers, and the historical `v2raycli` compatibility layer remain
> planned.

## Current status

Implemented now:

- a pure-Python package and CLI compatible with Python 3.7+;
- one cross-platform state root at `~/.jerryproxy`, overridable with
  `JERRYPROXY_HOME` or `--home`;
- built-in backend definitions for Mihomo, sing-box, Xray, and V2Ray;
- four packaged, stable-only offline backend catalogs;
- exact official GitHub release-asset selection for the current OS/CPU without
  a runtime release API request;
- mandatory upstream SHA-256 verification, preferring digests supplied
  directly by GitHub's release API;
- streamed backend downloads through `requests`, with a `tqdm` byte progress
  bar showing connection, transfer speed/ETA, completion, and failure status;
- direct, ordered automatic, named built-in, and invocation-scoped custom
  GitHub Release relay transports for backend bootstrap;
- bounded HTTPS downloads and safe ZIP/TAR/GZip extraction;
- immutable installations under
  `~/.jerryproxy/backends/<backend>/<version>/`;
- crash-recoverable version activation at `~/.jerryproxy/bin/<backend>`;
- relative symbolic links on supported systems and an atomic executable-copy
  fallback where Windows symlink privileges are unavailable;
- an active-version manifest that records the selected version and link mode;
- one fail-fast, home-wide process lock backed directly by the cross-platform
  `filelock` package;
- guided `InquirerPy` backend menus for short commands while complete command
  arguments remain suitable for scripts and automation;
- confirmed single-version or whole-backend removal, with optional matching
  download-cache cleanup;
- scoped cleanup for downloads, logs, providers, and generated runtime data;
- a packaged-CLI self-check with isolated local diagnostics plus bounded,
  integrity-checked availability probes for the three built-in relays;
- bounded `V2RAY_SUBSCRIPTION` source ingestion with private state below
  `JERRYPROXY_HOME`, stable sanitized node IDs, and SS/VMess/VLESS URI support;
- a synchronous Mihomo 1.19.29 foreground server with an open loopback
  listener by default, one merged bounded live backend output stream labeled by
  core name (for example `[mihomo]`) with no stdout/stderr split, and bounded
  health diagnostics;
- two-stage standalone validation that builds Linux in a pinned Python 3.7
  Docker image and executes every downloaded artifact in clean environments;
- deterministic offline unit tests, Sphinx documentation, packaging checks,
  and Linux/Windows/macOS CI definitions.

Not implemented yet:

- native Mihomo/Clash profiles and runtime drivers for sing-box, Xray, and
  V2Ray;
- durable measurement/ranking, controller APIs, TUN/LAN integration, and
  background service wrappers;
- the historical `v2raycli` option compatibility layer;
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

Backend catalogs are static package resources. Upgrade JerryProxy itself to
refresh the known release inventory:

```shell
python -m pip install -U jerryproxy
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
jerryproxy doctor
jerryproxy self-check
jerryproxy backend list known
jerryproxy backend list known mihomo --limit 5
jerryproxy backend list known mihomo 1.19.29
```

The backend command surface has eight operations: `list`, `install`, `current`,
`use`, `which`, `verify`, `uninstall`, and `clean`. `list [NAME]` shows local
installations. The positional depth of `list known` selects the packaged
catalog view: no target shows known backends, a backend shows compatible stable
versions, and a backend plus version shows the exact host artifact and full
SHA-256 evidence. Catalog queries are offline and identify the packaged
snapshot timestamp; upgrade JerryProxy to refresh them.
Local and catalog list queries never initialize or repair a home. An absent or
empty home is reported as an empty local inventory without creating
`~/.jerryproxy`; an existing managed home is locked and fully validated,
including top-level layout and lock-path permissions. As with every acquired
home lock, an already journaled interrupted uninstall is recovered before the
snapshot is returned.

With `--json`, the same three depths have explicit machine shapes:
`list known --json` returns an array of backend overview records,
`list known NAME --json` returns every matching release record unless an
explicit `--limit` is supplied, and `list known NAME VERSION --json` returns
one exact artifact object.

Run `jerryproxy backend` for a guided operation menu. Commands whose target is
omitted, such as `backend install`, `backend use`, `backend which`, and
`backend uninstall`, as well as the scope-free form of
`backend clean`, use `InquirerPy` to collect the missing choices. Supplying the
complete target and options keeps the command deterministic and suitable for
shell scripts.

Install and activate the newest verified stable version for this host:

```shell
jerryproxy backend install mihomo
jerryproxy backend current mihomo
jerryproxy backend which mihomo
```

Install and activate one exact catalog version:

```shell
jerryproxy backend install mihomo 1.19.29
jerryproxy backend current mihomo
```

Automatic transport fallback is the default. It tries GitHub first and contacts
the built-in relays only if the preceding source has a transport failure. Use
`--relay direct` when no relay contact is acceptable, or select one relay
explicitly:

```shell
jerryproxy backend install mihomo --relay auto
jerryproxy backend install mihomo --relay gh-proxy.com
```

`auto` is the default and tries direct GitHub, then `gh-proxy.com`,
`cdn.akaere.online`, and `gh.geekertao.top`. It advances only after a
transport failure; an integrity, redirect-policy, response-size, or
local-filesystem failure stops immediately. Named relay mode contacts only
that relay.

A relay that is not built in can be used for one invocation. JerryProxy
supports the three common GitHub Release URL shapes:

| Pattern | Effective request form |
|---|---|
| `full_url_path` | `BASE/https://github.com/OWNER/REPO/releases/download/...` |
| `host_path` | `BASE/github.com/OWNER/REPO/releases/download/...` |
| `query_q` | `BASE/?q=<percent-encoded-official-URL>` |

```shell
jerryproxy backend install mihomo \
  --relay-url https://relay.example/prefix \
  --relay-pattern host_path
```

Relay transport never changes the catalog identity recorded in the installed
manifest. The complete downloaded archive must still match the official byte
size and SHA-256 before extraction. A public relay can observe the client IP
and public release-asset path; JerryProxy never sends GitHub credentials,
private assets, subscription URLs, or release API calls through it. Run
`jerryproxy backend install --help` for the full mode and pattern semantics.

Update to the newest packaged stable version and verify installed executable
fingerprints:

```shell
jerryproxy backend install mihomo
jerryproxy backend verify
```

Install another version without activating it, then select it for use:

```shell
jerryproxy backend install mihomo 1.19.28 --no-activate
jerryproxy backend use mihomo 1.19.28
jerryproxy backend current mihomo
jerryproxy backend list mihomo
jerryproxy backend list mihomo --paths
```

On Unix-like systems the active command is a relative symbolic link:

```text
~/.jerryproxy/bin/mihomo
  -> ../backends/mihomo/1.19.28/mihomo
```

On Windows the command normally ends in `.exe`. If symbolic-link creation is
not permitted, JerryProxy atomically copies the verified executable and records
`link_mode: copy` in `~/.jerryproxy/active/mihomo.json`.

The command link/copy and active manifest are separate paths. Each publication
is atomic, but their pair is not continuously atomic to an external observer.
A hard exit can expose an intermediate pair until the next JerryProxy command
acquires the home lock and rolls the activation backward or forward to the
journal-selected state.

Uninstall an inactive version:

```shell
jerryproxy backend uninstall mihomo 1.19.29
```

Every uninstall and cleanup asks for a final destructive-operation confirmation.
Use `-y/--yes` only in automation where the complete target is already known.
Uninstalling one current version also requires `--deactivate`; selecting that
version through guided mode makes deactivation part of the confirmed
operation.

Uninstallation atomically stages matching cache, installed versions, and current
state in a private `runtimes/.remove-*` quarantine. A private journal is written
before the first move. If the process stops during staging, the next home-wide
lock acquisition restores the original paths in reverse order. If it stops
after commit, the next acquisition finishes quarantine disposal. Invalid or
ambiguous recovery state fails closed instead of guessing. If final quarantine
disposal fails, the CLI reports the committed removal and the retained data can
be retried with `backend clean --runtimes -y`.

Uninstall every installed Mihomo version, deactivate it, and also discard its
cached release archives:

```shell
jerryproxy backend uninstall mihomo -A --cache
```

Clean one cached release, all cache for one backend, or selected global
data areas:

```shell
jerryproxy backend clean mihomo 1.19.29
jerryproxy backend clean mihomo
jerryproxy backend clean --cache
jerryproxy backend clean --logs --runtimes
jerryproxy backend clean -A
```

`clean -A` empties cache, logs, providers, and runtimes. The managed cache is
stored internally below `downloads`. Cleanup never removes installed versions,
current links, manifests, or operation locks; use `backend uninstall` for
installations.

## Directory layout

```text
~/.jerryproxy/
├── active/          # Active-version manifests
├── backends/        # Immutable backend versions
├── bin/             # Active backend links/copies
├── downloads/       # Verified release archives
├── locks/           # Home-wide jerryproxy.lock
├── logs/            # Redacted JerryProxy/backend stream summaries
├── subscriptions/  # Private current subscription records
├── nodes/           # Reserved private node-management namespace
├── leases/          # Private foreground sessions and generated configs
├── config/          # Private runtime configuration namespace
├── runtimes/        # Private backend transaction/recovery namespace
└── providers/       # Disposable provider projections
```

The entire tree is private (`0700`) on POSIX systems. JSON state and secret
files are written atomically as `0600`. Windows ACL hardening is part of the
runtime security roadmap; the current design keeps every path beneath the
current user's profile.

Every read of existing managed state and every mutation uses one `filelock.FileLock` at
`~/.jerryproxy/locks/jerryproxy.lock`. Contention fails immediately with an
actionable busy error. The lock file may remain on disk after release; JerryProxy
does not store owner PIDs in it, inspect its contents, delete it as stale, or
replace `filelock` with platform-specific locking code.
The configured home root may itself be an alias, but managed subdirectories and
the operation lock file must not be symlinks or Windows reparse-point aliases
such as junctions. They are rejected before state access so one physical state
tree cannot be mutated under unrelated locks.

## Self-check

`jerryproxy self-check` actively validates the packaged Python runtime, host
platform mapping, private home layout and write access, POSIX directory modes,
backend registry, packaged catalog access and selection, `filelock`
compatibility, and one lock-consistent installed/active backend inventory. It
also exercises a complete synthetic backend lifecycle plus install, activation,
and removal hard-exit recovery in isolated temporary JerryProxy homes without
changing the configured home. It then streams one fixed 1 MiB Range from
a pinned public Xray release through each built-in relay. The probe separates
response-header latency, first-chunk latency, and the speed of the remaining
chunks, uses a five-second connect/read timeout, and has a parent-enforced
30-second wall-clock deadline covering process startup, redirects, response
headers, empty chunks, and streaming. It requires HTTPS, HTTP 206, the exact
`Content-Range`, byte count, and pinned slice SHA-256. Results use five levels:
green `OK`, yellow `WARN`, cyan `SKIP`, red `FAIL`, and red `ERR`. Relay
unavailability or invalid content is `WARN`; an inapplicable prerequisite is
`SKIP`; only `FAIL` and `ERR` make the command exit nonzero.

Python 3.7-3.9 install the newest `filelock` lines still compatible with those
interpreters. Those legacy lines are affected by CVE-2025-68146, so self-check
and `doctor` report `WARN` while operations remain available. Upgrade to Python
3.10+ and reinstall or upgrade JerryProxy when possible. Python 3.10+ installs
`filelock>=3.30`, which includes the upstream fork-ownership protection.

Standalone executables are intentionally built with Python 3.7 for legacy Linux,
Windows, and macOS compatibility, so their bundled `filelock` is also on the
legacy warning line. Users who prioritize the upstream lock hardening over that
binary compatibility should use the Python 3.10+ pip installation.

The check never downloads a complete backend, starts a backend, or mutates the
configured backend state. A fully successful run transfers 3 MiB across the
three relay checks. A final supervision item also verifies that any process
whose startup returned after its deadline was cancelled and reaped; pending or
surviving children are `ERR`. `requests` retains the host's standard proxy and
CA behavior:

```shell
jerryproxy --home ./test_self_check self-check
```

ANSI colors are enabled automatically on terminals. `NO_COLOR` disables them,
`FORCE_COLOR=1` enables them for redirected output, and `--color` or
`--no-color` provides an explicit per-command override.

## Standalone Linux compatibility

`make build_linux` creates the x86-64 Linux executable entirely inside a
digest-pinned official Python 3.7.11 Docker image based on Debian 9 (glibc
2.24). The build container is an isolated compatibility toolchain; users do
not need Docker or Python to run the resulting executable.

CI downloads the first-stage archive on checkout-free runners and executes the
same binary in seven digest-pinned containers: Ubuntu 18.04, Ubuntu 20.04,
Debian 10, Oracle Linux 7, CentOS 7, Amazon Linux 2, and openSUSE Leap 15.0.
Each job verifies the distribution identity, ANSI self-check, and public
read-only backend commands without installing Python, JerryProxy, or any
dependencies. The two Enterprise Linux 7 environments also enforce the
current glibc 2.17 compatibility boundary.

Several historical targets are upstream-EOL. Their presence in this matrix is
a binary-compatibility regression check for the staged JerryProxy artifact,
not a claim that the distribution still receives vendor security maintenance.

## Backend supply-chain rules

JerryProxy does not bundle or import backend implementations. The installed
release reads its four catalogs locally and never queries GitHub's release API
at runtime. The manager:

1. validates the packaged stable-release catalog;
2. selects one exact recorded asset for the detected OS and architecture;
3. rejects assets without accepted upstream SHA-256 evidence;
4. downloads over HTTPS through `requests` with size bounds and visible
   `tqdm` connection/byte progress on stderr;
5. verifies size and SHA-256 before extraction;
6. rejects archive traversal, symlinks, and special files;
7. installs into an immutable version directory;
8. holds the single home-wide `filelock` across cache validation, download,
   extraction, publication, probing, and optional activation;
9. changes the active backend only after installation succeeds.

Runtime backend state management currently supports Linux, macOS, and Windows.
The packaged catalogs retain official FreeBSD and OpenBSD release assets for
offline inspection, but JerryProxy does not install or activate them until
equivalent atomic filesystem primitives and native CI exist. NFS, SMB, FUSE,
or another filesystem that rejects the required no-replace or exchange
primitive fails closed.

The progress bar is written to stderr, so stdout remains stable for ordinary
CLI output and machine-readable JSON. `requests` honors the host's standard
proxy and CA environment configuration while direct connections remain the
default when no proxy is configured.

Official upstream repositories currently registered:

| Backend | Upstream | Planned role |
|---|---|---|
| Mihomo | `MetaCubeX/mihomo` | Preferred default candidate pending compatibility/security PoC |
| sing-box | `SagerNet/sing-box` | Optional backend for native sing-box profiles |
| Xray | `XTLS/Xray-core` | Optional Xray-family specialist backend |
| V2Ray | `v2fly/v2ray-core` | Legacy compatibility backend |

The backend binaries keep their upstream licenses. They are downloaded from
upstream after installation and are not conveyed inside the Apache-2.0
JerryProxy wheel.

Catalog maintenance is repository work, not a user command. A weekly workflow
runs `tools.backend_catalog`, accepts only official non-draft stable releases,
prefers GitHub API digests, and reads official checksum text only for legacy
assets where the API has no digest. It never downloads backend archives to
calculate catalog fingerprints. The updater is not included in the wheel.

Relay-health monitoring is also repository infrastructure, not JerryProxy
runtime behavior. Its 57-site configuration lives in a dedicated
[Gist](https://gist.github.com/narugo1992/78fb0ee6135fcdf4f0e5c7ec38f2fd59).
`make relay_health_sync` downloads that configuration to an ignored local JSON
file. The repository tool pins the official Xray probe asset and its expected
1 MiB digest, so the Gist controls relay hosts and URL patterns but cannot
replace the integrity reference. `make relay_health_check` records a direct
GitHub control plus three 1 MiB samples per enabled relay pattern. Each sample
uses a ten-second network timeout and records response-header latency, the first
non-empty chunk latency, post-startup stream speed, and chunk count. The
short-window success count provides the stability measure.
`make relay_health_wiki` renders the local JSON, and `make relay_health_gate`
rejects malformed results or an integrity mismatch.

The scheduled workflow probes and renders before any remote mutation, then
uses separate jobs to publish the result JSON to the Gist and the generated
Markdown to the dedicated
[Relay Health](https://github.com/narugo1992/jerryproxy/wiki/Relay-Health)
Wiki page. A final credential-free gate verifies every stage and marks an
integrity security event as failed after publishing the evidence. Neither tool
module reads or writes Gists. The manually maintained Wiki Home page remains a
stable navigation entry and is never overwritten by the workflow.
Publication uses separate `RELAY_HEALTH_GIST_TOKEN` and
`RELAY_HEALTH_WIKI_TOKEN` repository secrets in separate jobs. Each publisher
verifies that its token belongs to `narugo1992`; the probe, render, and gate
steps receive neither token. The workflow owns only `Relay-Health.md` in the
initialized `jerryproxy.wiki.git` repository and verifies that the manually
maintained `Home.md` hash is unchanged before and after publication.

## Foreground user experience

The current synchronous workflow is:

```shell
export V2RAY_SUBSCRIPTION='https://provider.example/subscription'

jerryproxy subscription add main --url-env V2RAY_SUBSCRIPTION
jerryproxy node list main
jerryproxy server --subscription main --node NODE_ID
```

`server` ensures the exact Mihomo backend exists, creates private state, loads
the subscription without exposing its URL, reports the loopback HTTP/SOCKS
endpoint, and keeps the process in the foreground. If the exact backend is
missing, installation is enabled by
default; guided confirmation defaults to **Yes** (press Enter), while `-y`
accepts it without prompting and `--no-install-missing` disables bootstrap.
The listener is open on loopback by default; `--auth` adds generated local
credentials and `--bind-all` selects `0.0.0.0`. The same proxy URL is placed in
`HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` by the human startup guide; a
SOCKS5 listener uses a `socks5h` URL. Backend stdout/stderr are merged into one
bounded live stream, redacted, and labeled only with the backend name
(`[mihomo]`), never separate stdout/stderr labels; `--backend-log-level`
defaults to `INFO`. Two consecutive
failed global health quorums trigger one same-node restart, deterministic
alternate-node attempts, and one optional subscription refresh within the
configured recovery deadline. Automatic recovery never rewrites the saved node
preference.

Nodes are listed with the label their provider put in the URI fragment, so
several endpoints of one protocol stay distinguishable. That fragment is
generic URI syntax rather than protocol semantics, so reading it keeps protocol
interpretation with the backend; a record without a usable fragment, such as
VMess with its Base64 payload, shows its scheme instead. Labels are decoded,
redacted, made terminal-safe, and truncated, and they are never used to select
a node — `--node NODE_ID` remains the exact selector.

A stored subscription can also drift: after an upgrade changes how the same
source bytes are classified, the persisted nodes stop matching those bytes.
That state is recoverable rather than hostile, because the keyed home
fingerprint already proved JerryProxy wrote that node content for that
subscription itself. Reads check that fingerprint before they check the
projection, so tampering is never mistaken for drift. `server`
therefore refreshes that subscription's saved URL exactly once, revalidates,
and continues. It stops and names the next command when the subscription has
no saved URL, when the refresh fails, or when the rebuilt nodes are still
inconsistent; it never retries in a loop. The guided node menu repairs the same
way before it renders, and the guided subscription menu still lists a drifted
record so it can be selected and repaired at all. `subscription refresh NAME`
performs the repair on demand. Rebuilt nodes receive new identities, so an
explicit `--node NODE_ID` may need `node list NAME` again. Read-only commands
stay strict and name the repair command instead of showing an inconsistent
projection. A projection that fails the fingerprint check is reported as
tampering and is never repaired automatically.

## Roadmap

- [x] Establish the Python 3.7+ package, CLI, tests, docs, and CI skeleton.
- [x] Implement versioned backend storage and active-link switching.
- [x] Implement exact release-asset resolution and digest-verified downloads.
- [x] Implement safe archive extraction and immutable manifests.
- [x] Add lightweight self-check and clean-runner standalone artifact gates.
- [x] Add tested stable-only offline backend catalogs and weekly maintenance.
- [x] Add guided backend operations and confirmed scoped cleanup/removal.
- [ ] Add offline archive installation with an explicit digest.
- [x] Implement managed `V2RAY_SUBSCRIPTION` fetch, private state, and URI
  inventory for SS/VMess/VLESS.
- [x] Implement the Mihomo foreground driver, loopback listener, merged named
  backend stream, and bounded health recovery.
- [ ] Implement durable controller operations, measurements, and service
  integration.
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
make build_linux
make catalog_check
make catalog_update
make relay_health_sync
make relay_health_check
make relay_health_wiki
make relay_health_gate
make check
```

Every main-branch push and pull request runs the following independent gates:

- unit tests on Linux, Windows, and macOS for every supported Python version
  from 3.7 through 3.14 (24 matrix cells, with no excluded combinations); every
  cell uploads its own named and flagged coverage report for Codecov aggregation;
- strict Sphinx HTML documentation with warnings treated as errors;
- staged sdist and wheel builds, followed by clean artifact-only installation
  smoke tests on Python 3.7 and 3.14;
- weekly catalog maintenance plus real four-backend lifecycle jobs on Linux,
  Windows, and macOS;
- two-stage standalone validation: Linux is built in the pinned Python 3.7.11
  Docker toolchain, while Windows and macOS build on `windows-2022` and
  `macos-15-intel`; Stage 2 starts without checkout or dependency installation,
  verifies the downloaded archives, tests Linux on the seven-distribution
  compatibility matrix documented above, and exercises every packaged CLI
  through `self-check --color` and public read-only commands.

Read [CLAUDE.md](CLAUDE.md) before changing architecture, backend metadata,
download/extraction code, credential handling, or release workflows.

## License

JerryProxy is licensed under the Apache License 2.0. External backends remain
independent programs under their respective upstream licenses.
