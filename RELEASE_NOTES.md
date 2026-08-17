# JerryProxy 0.1.0

JerryProxy 0.1.0 is the first public release. It is an alpha-quality `0.x`
release: the Python API, CLI details, and managed-state formats may change
without a compatibility promise.

## What ships

- A Python 3.7+ package and the `jerryproxy` command, with the same behavior
  available through `python -m jerryproxy`.
- A home-wide, lock-serialized backend manager for Mihomo, sing-box, Xray, and
  V2Ray. It selects exact platform assets from packaged stable catalogs,
  verifies upstream SHA-256 digests, extracts archives with traversal and file
  type guards, installs immutable versions, switches active versions
  atomically, and supports rollback, uninstall, and scoped cleanup.
- A foreground Mihomo 1.19.29 runtime. It accepts Base64/plain URI-line
  subscriptions through `V2RAY_SUBSCRIPTION` and Mihomo/Clash proxy-provider
  YAML. The supported measured protocol spellings are `ss`, `vmess`, `vless`,
  `trojan`, `hysteria2`, `hy2`, `tuic`, and `anytls`.
- Mixed-protocol handling that retains supported nodes, reports unsupported
  scheme names as bounded aggregates, and never retains unsupported credential
  material. Provider entries remain opaque and are published to Mihomo without
  Python-side protocol conversion.
- A loopback-first foreground listener, optional generated local credentials,
  backend control-channel verification, global health quorum, bounded restart
  and alternate-node recovery, and one saved-source refresh for recoverable
  subscription drift.
- Package, standalone, security, catalog, archive, documentation, and
  cross-platform CI gates. The attached standalone archives are verified on
  Linux, Windows, and macOS; `SHA256SUMS` covers exactly the five release
  assets.

## Installation

Install from PyPI:

```shell
python -m pip install jerryproxy
```

The GitHub release also provides standalone archives for Linux, Windows, and
macOS. Backend binaries are not bundled in the wheel or standalone archives;
JerryProxy downloads the selected official asset when a backend is installed.
Upgrade the package to receive refreshed backend catalogs:

```shell
python -m pip install --upgrade jerryproxy
```

## First-run example

```shell
export V2RAY_SUBSCRIPTION='https://provider.example/subscription'
jerryproxy subscription add main --url-env V2RAY_SUBSCRIPTION
jerryproxy node list main
jerryproxy server --subscription main --node NODE_ID
```

The public proxy listener binds to `127.0.0.1` by default. `--auth` enables
generated per-session credentials, and `--bind-all` explicitly exposes the
proxy listener on `0.0.0.0`. The backend control channel remains loopback-only.

## Known limitations

- Only the Mihomo 1.19.29 foreground driver is a usable proxy runtime in this
  release. sing-box, Xray, and V2Ray can be installed, activated, verified,
  and removed by the generic manager, but do not have runtime drivers here.
- Detached/background runtime, native Mihomo profiles, public controller
  operations, durable measurement or ranking, TUN/LAN integration, service
  wrappers, and historical `v2raycli` compatibility are not implemented.
- VLESS data-plane evidence covers the measured Reality/Vision combination.
  VLESS Encryption and XHTTP variants do not have a release fixture and must
  not be treated as generally verified by this release.
- Provider YAML is limited to proxy-provider documents. Full-configuration
  fields such as `scripts`, `hooks`, `plugins`, `controller`, `tun`, and
  `listeners` are rejected.
- Python 3.7-3.9 use the newest compatible legacy `filelock` line and report a
  self-check warning for the upstream limitation. Python 3.10+ is recommended.
- FreeBSD and OpenBSD assets remain available for offline catalog inspection,
  but installation and activation are fail-closed until equivalent native
  filesystem primitives and CI coverage exist.
- Standalone artifacts have SHA-256 checksums but are not signed. Verify the
  attached `SHA256SUMS` file before use.

## Security and privacy

Subscription URLs are bearer credentials. JerryProxy does not put them in
argv, human or JSON output, persistent logs, runtime access files, or release
artifacts. Node labels are display-only and are derived from a URI fragment or
provider `name`, then redacted, terminal-safe filtered, and bounded. Backend
output is drained through one bounded, redacted stream. The generated runtime
provider and session state is kept below the selected JerryProxy home with
owner-only permissions on supported POSIX systems.

The release gates include a complete secret-channel matrix and a TLS
fail-closed test. As with any same-user local process boundary, continuous
interference between a reserved port and a backend bind remains outside the
supported threat model; the release does not claim to authenticate a peer
against that race.

## Compatibility and support boundary

The package targets CPython 3.7 and newer on Linux, macOS, and Windows. The
catalog may contain official assets for other operating systems, but the
manager rejects unsupported installation paths. This release is intended for
evaluation and controlled use while the runtime and controller roadmap is
completed.

JerryProxy is distributed under the Apache License 2.0. External backend
licenses remain applicable to the binaries users download from their upstream
projects.
