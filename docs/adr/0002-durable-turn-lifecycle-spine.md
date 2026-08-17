# ADR-0002: Durable turn lifecycle spine

- Status: Accepted and implemented for the default-off local scheduler pilot;
  not approved for production
- Date: 2026-08-16
- Decision owner: Buzz architecture

## Context

Buzz currently has capable transport, queue, ACP, persona, and workspace components, but the durable meaning of a user turn is distributed across those components. A responsive teammate experience needs one small authority for accepting a turn, publishing its visible receipt, tracking background execution, recovering after restart, and publishing exactly one terminal result. That authority must not become another agent framework or absorb transport, model, UI, credential, or workspace responsibilities.

## Decision

`crates/buzz-lifecycle` is the provider- and transport-neutral lifecycle nucleus. It owns only:

- idempotent turn admission and immutable request bindings;
- ordered lifecycle events;
- the active-turn projection;
- receipt and terminal-result outboxes; and
- expiry and restart recovery inputs.

An admitted turn is bound to owner, agent, requester, channel, client nonce, input digest, receipt time, and expiry. Reusing a nonce with different immutable bindings fails closed. Exact replay returns the original turn without another event or receipt.

The lifecycle is:

`accepted -> queued -> running <-> waiting -> completed | failed | cancelled | expired | rejected`

Projection reads are bounded hot-path queries, not event-log reconstruction.
Active turns use keyset pagination by `(accepted_at_ms, turn_id)` and ordered
event tails require an explicit bounded page size. Append-only history remains
the audit source, while SQLite projections serve interactive state without
materializing the complete history.

Only named lifecycle operations are public. Terminal transitions are exactly once: an identical replay is idempotent and a conflicting terminal result is rejected. The receipt is committed in the same SQLite immediate transaction as admission. The terminal outbox item is committed in the same transaction as terminal state. Delivery is retried separately and never defines whether the state change happened.

The crate has no dependency on ACP, Nostr, Desktop, Hermes, Kubernetes, OCI, the workspace controller, or a model provider. Those systems are adapters or consumers. `buzz-workspace-controller` continues to own disposable-workspace authority and must not be folded into the turn ledger.

SQLite WAL with `synchronous=FULL`, foreign keys, a bounded busy timeout, and one connection per operation is the Slice 1 durability boundary. Async adapters must call it through `spawn_blocking` or a bounded blocking worker; they must not perform SQLite work on the ACP reactor.

The initial `buzz-acp` adapter is feature-gated by `durable-turn-lifecycle`, which is off by default. It verifies signed Nostr events, translates their identity into an admission request, and exposes lifecycle operations off the async reactor. The retry/dead-letter path emits an explicit typed disposition and preserves triggering event IDs plus a content digest. Three runtime database selectors are explicit and mutually exclusive: `BUZZ_ACP_LIFECYCLE_SHADOW_DB`, `BUZZ_ACP_LIFECYCLE_AUTHORITATIVE_DB`, and `BUZZ_ACP_LIFECYCLE_SCHEDULER_DB`. The first observes the legacy queue, the second exercises the existing queue-backed authority, and the third runs the executable local scheduler pilot described below. The scheduler path must be non-empty and absolute. All selectors remain unset by default and are not enabled in installed Buzz.

Queue-backed authoritative admission uses the atomic admission-plus-dispatch operation. Restart ownership uses an expiring `(owner, agent, instance)` runtime lease. Startup recovery is idempotent per runtime instance, clears prior execution identity, retains persisted scheduling metadata, and classifies interrupted `running` turns as uncertain rather than automatically replaying them. Queue insertion is acknowledged under the active lease; acknowledged work is suppressed for that runtime but becomes recoverable under a replacement lease after a crash. The periodic reconciler is a distinct operation that can read only already recovery-marked, unacknowledged or newly due rows; it never applies restart classification to ordinary live queued/running work. This older path does not persist the input body: its adapter retrieves the original signed event by immutable Nostr event ID and verifies signature, author, channel, digest, and timestamp before queue reconstruction.

### Scheduler pilot contract

The scheduler pilot is a separate authority, not an option layered over the
legacy `EventQueue`. Its compatibility envelope is deliberately narrow:

- exactly one ACP worker slot for each `(owner, agent)` scheduler scope;
- queue-only handling for messages that arrive while a turn is active;
- queue deduplication, with no merged steer/interrupt batches;
- no agent heartbeat competing for the only worker slot; and
- no lazy-pool sleep/wake dependency on the legacy queue.

Startup must reject an incompatible configuration rather than silently widen
this envelope. Multiple independently identified agents may each use their own
scope; the one-agent restriction is per ACP harness/scheduler scope, not a
limit on the Buzz fleet.

At ingress, a signed event, its immutable dispatch classification, lane, source,
and opaque signed-event JSON commit in one immediate transaction. The lifecycle
crate does not parse Nostr; the ACP adapter verifies the signed envelope before
admission and verifies it again after claim. Exact replay is resolved before
capacity and never creates a second runnable item. A scheduler claim atomically
selects one due lane head, advances fairness state, binds a claim epoch and
execution ID, and returns the opaque input plus dispatch. Nothing is inserted
into or reconstructed from `EventQueue`.

Direct owner and other permitted human input enters the `User` lane. Only an
author cryptographically verified as a same-owner agent enters the `Agent` lane;
an allowlist entry alone does not make an author an agent. `Background` remains
reserved for future internal routines and is not inferred from ordinary relay
messages during this pilot.

An idle ACP worker is reserved before the durable claim. A new claim begins in
the `reserved` phase, where no provider prompt has been authorized. The harness
fences the transition to `launched` before invoking the ACP prompt. On restart,
an interrupted `reserved` claim is safe to return to runnable work; an
interrupted `launched` claim becomes `hold_uncertain` and is never replayed
automatically. Both recovery paths clear only the matching active scheduler
projection so unrelated queued work can continue.

Completion, retry, cancellation, panic, and timeout settle through the claim's
epoch and execution ID. A stale or replaced worker cannot release or finish a
newer claim. Success and non-retryable failure atomically terminalize the claim;
a retryable failure atomically returns it to `waiting` with the next dispatch
time; explicit cancellation terminalizes it as `cancelled`. Triggering event IDs
remain diagnostics, not settlement authority.

Activation is a local canary procedure, not a production rollout: build with
the feature, use a fresh absolute scheduler database, set only the scheduler
selector, satisfy the compatibility envelope,
run the scheduler-focused tests, and then exercise an isolated relay/channel
before any shared deployment. Rollback is fail-closed. Stop the pilot and
inspect its bounded scheduler snapshot before unsetting the scheduler selector.
Legacy processing may resume only when no active, pending, or uncertain pilot
work remains; otherwise reconcile or explicitly terminalize those turns first.
Do not point shadow or queue-authoritative mode at the scheduler database, and
do not let legacy relay replay silently duplicate unreconciled pilot work.

The adapter currently derives a fixed 30-day expiry from each signed event
timestamp. That is a bounded local-pilot behavior, not an approved production
retention policy.

Durable relay publication uses lease-scoped claimed outbox rows and authenticated REST `POST /events`, followed by response validation and marker reconciliation. The existing WebSocket publisher remains reserved for ephemeral typing/observer traffic. Receipt and terminal messages use persisted stream messages with stable client markers until Buzz relay and Desktop jointly support a dedicated durable lifecycle kind. Publication is additionally gated by the default-off harness-owned final-reply mode; legacy agents continue to own their tool-sent final messages. Harness-owned final text is capped at 64 KiB and stored in the terminal envelope so publication can survive a crash.

## Consequences

The visible-first turn contract can be built on a transactional receipt outbox without coupling conversational latency to model work. A reconnecting UI can load the active projection and then tail ordered events. Background workers can bind their execution IDs without becoming authoritative for the user turn.

This slice does not change current Buzz behavior, provision infrastructure, call model APIs, or introduce EntAIngled Desktop, Fabric, Matter, Wave, LangGraph, or another orchestration framework.

The scheduler pilot does not claim multi-slot ACP execution, merged
steer/interrupt recovery, durable background routines, automatic uncertain-work
replay, installed-runtime activation, or production readiness. Persisting
signed input also expands the local data surface: retention, deletion, backup,
and at-rest protection must be decided before production use.

## Harness-research constraints

The DeepSeek Harness review did not justify a framework migration. It did add
two constraints to subsequent slices:

- scheduler, UI, and recovery hot paths must use bounded indexed projections;
  they must never synchronously reconstruct state from the complete event log;
- staged model-visible tool exposure belongs in the model-owning adapter (for
  example `buzz-agent` before provider schema translation), not in this crate
  or in generic ACP framing.

Code-mode/PTC tool indirection remains deferred until a matched Buzz benchmark
shows a latency or task-success improvement.

## Adapt versus spin-out checkpoint

Continue adapting Buzz through the pilot only while all of these remain true:

- the lifecycle crate stays independent of transport and model code;
- the ACP integration can be expressed as narrow adapters rather than branching throughout the reactor;
- admission-to-receipt latency and foreground reply latency can be measured independently of worker duration;
- restart recovery does not depend on reconstructing hidden in-memory queue state; and
- terminal publication can be driven from one durable outbox without duplicate legacy authorities.

Reassess a standalone harness if any two conditions fail, or if integrating the turn contract requires invasive changes across more than three existing crates. That checkpoint decides from measured coupling rather than from Buzz's current size or age.

## Deferred production gates

- Add an external capability fence across authoritative cancellation and the
  actual ACP/provider launch. The local `reserved -> launched` ledger marker
  cannot make that external side effect atomic.
- Validate the receipt and terminal outbox against a live relay, including
  ambiguous-submit recovery and durable visible-first delivery.
- Restore and prove legacy steer-membership removal/cancellation behavior before
  widening beyond the queue-only compatibility envelope.
- Reproduce the passing complete Bash-backed ACP suite and the deterministic
  five-boundary process-crash matrix in supported project CI. The current
  evidence is a local supported-Linux container run, recorded in the
  [checkpoint manifest](../durable-scheduler-checkpoint-validation.md).
- Promote the implemented default-off local process-generation capability
  pilot only after its remote transport, workload isolation, durable
  revocation/replay, claim-binding, and remaining consumer gates are closed;
  see [ADR-0003](0003-capability-broker-boundary.md).
- Generalize the one-active-claim projection before permitting more than one
  ACP worker slot per agent identity.
- Restore exact retry and merged-steer/interrupt grouping semantics after restart; never automatically replay `hold_uncertain` work.
- Extend process-level crash injection beyond the completed store boundaries to
  relay receipt publication, recovery insertion, ACP bind/prompt panic, and
  runtime lease loss.
- Add end-to-end latency, cancellation, reconnect, retry, and crash-injection tests.
- Choose signed-input/final-text retention, deletion, compaction, backup, and
  at-rest protection policy before treating the ledger as production authority.
