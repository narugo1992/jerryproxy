Persistent recovery implementation contract
===========================================

This is the acceptance contract for the ongoing implementation, not a claim
that these behaviors are already available. It implements the maintainer's
Chinese design document, revision 8, dated 2026-09-21.

Inputs and boundaries
---------------------

The caller explicitly selects one subscription and one initial node. Recovery
must never leave that subscription, change its saved preference, interpret
protocol credentials, or replace the existing runtime-driver boundary.
Healthy sessions keep their current node; exploration and exit-IP changes
are permitted only during recovery. There is no automatic failback.

Startup and periodic outages use the same recovery path. Transient outages
have no session lifetime limit. Each probe, reload, refresh, cleanup and retry
round remains bounded. A round deadline preserves pending candidates rather
than repeatedly starving the tail of a large subscription.

Selection policies
------------------

* ``none`` stops after confirmed failure without restarting or refreshing.
* ``fixed`` retries only the initial node identity.
* ``random`` visits a shuffled pool without replacement before another sweep.
* ``adaptive`` uses session-local, aging success estimates and recovery-only
  exploration; all eligible nodes must eventually receive an attempt.
* ``fallback`` composes the closed stages ``current``, ``adaptive`` and
  ``random``. The default is ``current:1,adaptive:3,random:all``. Stage names
  must be unique; counts are positive bounded integers or ``all``. Current
  permits only one attempt. Candidates are deduplicated across stages.

Retry timing uses capped exponential backoff with jitter, separate node
cooldowns and refresh throttling. A brief success does not reset escalation;
only a stable healthy period does. No tight loop is allowed for exhausted,
unchanged, disabled or cooling-down pools.

Execution and outputs
---------------------

The session keeps its home-wide lock, listener port and optional credentials
through degradation. Mihomo uses atomic private single-provider publication
and authenticated bounded reloads. Exact candidate acceptance, selection and
absence of direct bypass must be checked before connectivity can establish
readiness. Ambiguous control state, authentication, integrity, TLS, permission
and unsafe cleanup failures remain terminal. Confirmed child exit must not be
confused with inability to stop a child.

Cache age requests a refresh but does not disqualify verified cached nodes.
Temporary refresh failure preserves the last good revision. Successful refresh
prunes removed identities and statistics; removing the fixed identity produces
an actionable error. Refresh receives the remaining budget and respects its
own minimum interval, backoff and server Retry-After. Retry-After is bounded
to one day; malformed values are discarded. Refresh starts no more often than
once per 300 seconds by default, doubles its delay after consecutive transport
failures up to one hour, and resets after success. Mandatory worker cleanup has
separate bounded stop intervals and must complete even after the network
budget expires; inability to prove cleanup is terminal.

Sanitized events expose starting, degraded, retrying, ready and stopped states,
actual retry delays, skip reasons and current health. No event falsely reports
readiness or exposes secrets. Threads, children, statistics and recent logs
remain bounded for an indefinitely running session. Ctrl-C and SIGTERM must
cancel probes, refreshes and backoff and complete safe cleanup. The CLI owns
SIGINT and SIGTERM handlers only during the foreground session. The first
signal requests unwinding; repeated signals are ignored until cleanup has
finished, then prior handlers are restored. Successful cancellation exits
with 128 plus the signal number. Cleanup failure remains a terminal error.

Lifecycle events use a separate optional event callback. JSONL emits these
events on stdout and ordinary logs on stderr, independent of log-level
filtering. The session writes the same bounded event summary to its private
log. Each event includes a closed reason code, attempt and round counters,
candidate count, last healthy effective node, loaded node, attempted node,
current quorum and actual next delay. Startup emits ready only after access
publication; recovery emits ready only after acceptance and quorum. Stopped
is emitted only after child and artifact cleanup succeeds, while the home
lock still protects the event log write. Refresh events preserve the current
state and distinguish stale cache, unchanged content, updated content and
transient transport failure. Repeated stop is
idempotent. A closed output stream does not interrupt service.

Connectivity checks allocate at most three workers. If a request outlives a
check's budget, subsequent checks report it as unfinished and allocate no new
workers until that batch finishes. Late results do not establish readiness for
a later check. This bounds worker accumulation but does not by itself prove
that every network wait is cancellable; cancellation remains a separate gate.

Runtime logs retain recent diagnostics within a 4 MiB file. Both producers
serialize writes under the existing shared lock. On overflow they discard
the oldest portion, retain complete recent lines from the final half and
append the new redacted line through the same validated descriptor. No
rotation paths are created. A crash during this in-place compaction can lose
diagnostic history; it cannot modify managed configuration or credentials.

Verification required before merge
----------------------------------

Tests are written before behavior. Deterministic scenarios cover startup
offline then online, outages longer than 120 seconds, all nodes unavailable,
one working alternate, subscription scope, fixed identity, no healthy
switching, hundreds of candidates, cooldowns, unchanged and failing refresh,
old usable cache, removed fixed identity, flapping and cancellation at each
blocking boundary. Adversarial reload tests cover empty and malicious
providers, stale accepted content, authorization and rollback failures.

Real qualified-backend data-plane tests cover every allowed protocol and
container, including hot switches with stable listener and credentials.
Long-run tests verify bounded workers, logs and statistics. Existing secret
matrices must include new output channels. Explicit and guided CLI behavior
must agree; rendered help is checked at 72, 80, 100 and 120 columns.

All changed or affected functions require 100 percent branch coverage,
including native platform evidence when necessary, without exclusion pragmas
or a whole-repository average substituting for the affected-area audit.
Python 3.7 compatibility, normal test gates, generated API documentation,
documentation build and package build must pass. The PR body is English;
completion requires review and CI evidence that the full scope is merge-ready.
