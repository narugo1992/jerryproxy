Persistent recovery implementation contract
===========================================

This contract defines persistent recovery and its merge acceptance criteria.
It implements the maintainer's
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

Fast recovery defaults
----------------------

For subscriptions with up to 20 nodes, the first recovery sweep uses a
three-second health budget per candidate. After six seconds on cached
candidates, the next between-attempt check gives a source refresh an
independent ten-second budget. An in-flight bounded reload/probe completes
before this check; six seconds is a scheduling threshold, not a hard wall.
Refresh is checked between attempts and rounds, never only against the
remaining round budget. Its default minimum interval is 60 seconds, with
transport backoff and Retry-After still enforced. Changed source content is
eligible immediately without an extra round backoff. An exhausted fast sweep
falls back to normal probe budgets so slow usable nodes are not excluded.
Healthy sessions retain the existing check interval and never explore.

These defaults target fast restoration rather than an optimal-node search.
Verification compares 1, 5, 10 and 20-node replacement and partial-outage
scenarios, including slow usable nodes, unchanged/failed refresh, deadline
exhaustion and CLI/guided default and override parity. Simulated timing is
not a public-network latency guarantee. Safety and cleanup remain terminal
boundaries. Advanced timing options must not add guided questions.

``--fast-probe-timeout`` (3), ``--cache-retry-budget`` (6),
``--refresh-timeout`` (10) and ``--refresh-interval`` (60) are advanced
overrides in seconds. Both complete commands and guided selection use these
defaults without extra prompts. An unchanged or temporarily unavailable
subscription keeps the existing pool and bounded retry cadence. A recent
refresh can defer the next fetch; server Retry-After can defer it further.
These are not restoration-time guarantees.

Default selection evidence
~~~~~~~~~~~~~~~~~~~~~~~~~~

A deterministic comparison used the real session scheduler/private provider
publication with injected network time: 1/5/10/20 nodes, five ordering seeds,
one working node, two-second fetches, and 1/3/5/8-second successful probes.
The reference replayed the recovery loop at ``7f40af8`` with its 300-second
refresh interval. Controller and process latency were not simulated; results
start at confirmed recovery, excluding failure detection.

For complete replacement with a one-second working node, the 3-second default
reduced sample P95 from 405 to 42 simulated seconds (maximum 54). For partial
failure with a three-second working node, sample P95 was 35 seconds, versus
223 with a two-second fast budget and 55 with a five-second fast budget.
Three seconds is the smallest compared budget that accepts this moderately
slow route on the first sweep. It is a workload choice, not a universal optimum.
For five-second working nodes the fast sweep adds work: sample P95 was 245
seconds versus 105 in the reference. Normal-budget retries preserve recovery
in this case; users of consistently slow routes can increase the fast budget.

``test/runtime/test_fast_recovery.py`` pins the default first-sweep bound for
1--20 nodes with 1/3-second successful probes over five seeds, prompt complete
replacement, independent refresh even at round exhaustion, throttling and
normal-budget fallback. These model checks supplement the real protocol
data-plane suite; they do not replace it or imply public-network percentiles.

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
readiness. Each control request has an absolute wall deadline covering response
headers and body, including slow trickles. A standard-library buffered reader
clamps each underlying socket read to the remaining time; no deadline worker
is allocated. Failed control verification isolates the child before rebuilding.
Local integrity, permission and unconfirmed cleanup failures remain terminal.
Health probes reject invalid certificates and explicit HTTP 407 responses, but
these are target failures: a passing quorum keeps the current node; a failed
quorum enters the configured recovery policy. CONNECT 407 refusals are recognized
only through the pinned Requests/urllib3/standard-library exception chain and
the locally generated status prefix; arbitrary exception messages are never
searched or logged. Other proxy connection failures remain retryable. A real
loopback proxy refusal verifies classification across the health process
boundary. Confirmed child exit must not be confused with inability to stop a child.

Cache age requests a refresh but does not disqualify verified cached nodes.
Temporary refresh failure preserves the last good revision. Successful refresh
prunes removed identities and statistics; a missing fixed identity waits for
a later refresh to restore it, without selecting another node. Recovery refresh receives an independent budget and respects its
own minimum interval, backoff and server Retry-After. Retry-After is bounded
to one day; malformed values are discarded. Refresh starts no more often than
once per 60 seconds by default, doubles its delay after consecutive source
failures up to one hour, and resets after success. Mandatory worker cleanup has
separate bounded stop intervals and must complete even after the network
budget expires; inability to prove cleanup is terminal. A standalone
subscription operation retains its original home lock while cleanup remains
unconfirmed. The same manager, used on its owning thread, may release that
retained lock on its next operation only after the supervisor confirms both worker termination and
artifact removal. A runtime session similarly refuses to announce stopped
or release its own lock while subscription cleanup is pending. No cleanup
thread releases a thread-owned FileLock or acquires a second home lock.
The subscription caller waits on a starter-owned completion event rather than
an interruptible thread join, which can incorrectly report a live starter as
stopped on older CPython versions. The cleanup supervisor also confirms actual
starter exit before removing the private worker directory.
Acquired operation locks remain strongly referenced until explicit exit, so
discarding a failed owner cannot release an unconfirmed operation through
garbage collection. Discarding such an owner forfeits in-process cleanup
recovery; the home stays locked until the process exits.

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

Default network checks run in one disposable spawned process with at most
three request threads. The parent includes process startup in the check
budget, terminates the process on timeout or interruption, and confirms exit
before accepting another batch. Credentials travel through multiprocessing
IPC rather than command arguments or files. Results use a bounded, validated
JSON envelope with closed diagnostic codes. Cleanup retains a separate bounded
budget and fails closed on uncertain process ownership. Injected transports
run in-process for deterministic testing. Library scripts that launch default
probes must use the standard ``if __name__ == "__main__"`` entry guard
required by multiprocessing spawn; the CLI already provides that guard.
The installed ``self-check`` exercises the actual spawned health worker against
a temporary loopback HTTP server. It requires a successful round trip and
confirmed cleanup; standalone artifact CI runs this check on each target OS.

Injected in-process checks allocate at most three workers. If a request outlives
a check's budget, subsequent checks report it as unfinished and allocate no new
workers until that batch finishes. Late results do not establish readiness for
a later check. Cancellation prevents pending targets from starting. Completion
is tracked with worker-owned events instead of interruptible joins; cleanup
must confirm all workers have exited before releasing the home lock. An
unconfirmed worker makes cleanup fail closed. This bounds worker accumulation but does not by itself prove
that an arbitrary injected transport can be cancelled. Default network
transports instead use the disposable process described above. Native platform
and packaged-executable verification run in the repository CI matrix.

Runtime logs retain recent diagnostics within a 4 MiB file. Both producers
serialize writes under the existing shared lock. Descriptors use binary mode
on Windows so byte bounds and compaction offsets are not changed by newline
translation. On overflow they discard
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

Availability-first recovery contract
------------------------------------

Node and remote-network failures belong to the recovery policy rather than a
session-wide fatal exception. A failed certificate check still rejects that
connection; certificate validation is never disabled. Other healthy targets
may satisfy quorum, otherwise recovery tries other permitted nodes. Explicit
``none`` remains the opt-out; ``fixed`` waits for its selected identity instead
of choosing another when that identity disappears from a refreshed source.

An unusable startup candidate, failed control verification, stale reload, or
exited backend must be isolated and cleaned up before a replacement backend
can be verified. The session retains its home lock, ports and credentials.
Repeated outages use bounded attempts, candidate cooldowns and capped backoff;
there is no default total retry limit, including when the host is offline.
Readiness means verified routing and a passing health quorum, not merely a
living process or open port.

Remote subscription failures must never publish rejected bytes. Refused TLS,
authentication, unsafe responses and malformed provider content retain the
previous valid cache and delay the next source attempt. Local-state integrity,
worker-envelope corruption, permissions, and unconfirmed child cleanup remain
fatal boundaries: continuing recovery must not release ownership while an old
child or untrusted secret-bearing artifact remains.

Verification requires startup and periodic failure recovery, strict TLS
negative controls, preserved listener identity, subscription replacement and
fixed-identity absence, backend restart and control failure isolation,
long-outage resource bounds, safe interruption, and adversarial cleanup and
integrity failures. Changed executable functions require complete measured
branch coverage; release checks also exercise real backend data-plane paths.


To reproduce the affected-function audit after a branch-enabled pytest run::

    python -m pytest test -m unittest --cov=jerryproxy --cov-branch --cov-report=json
    python -m tools.changed_coverage coverage.json --base origin/main

The audit checks every surviving function touched by additions or deletions,
including branches outside the changed lines. Missing files and statement-only
coverage are failures. Native CI retains coverage JSON beside its test reports;
mocked OS failure outcomes supplement, rather than replace, native platform runs.
