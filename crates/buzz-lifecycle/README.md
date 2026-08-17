# Buzz lifecycle

Status: **standalone local lifecycle nucleus with default-off ACP shadow,
queue-authority, and scheduler-pilot adapters**.

This crate owns durable user-turn admission, ordered lifecycle events, receipt
and terminal outboxes, and authoritative active-turn projections. It deliberately
does not depend on ACP, Nostr, Buzz Desktop, Hermes, a model provider, a worker,
or the workspace controller.

The intended boundary is:

```text
inbound adapter -> LifecycleStore -> worker adapter
                       |
                       +-> receipt/terminal outbox
                       +-> snapshot + ordered event tail
```

SQLite runs in WAL mode with foreign keys, full synchronous durability, a busy
timeout, and `BEGIN IMMEDIATE` for mutations. A duplicate `(owner, agent,
client_nonce)` with the same immutable binding returns the original turn. The
same nonce with a different requester, digest, channel, or expiry fails closed.

No accepted turn is deleted. Authoritative adapters can atomically write the
turn, `accepted` event, receipt outbox, dispatch intent, and `queued` transition.
Exact replay also repairs an older `accepted` row instead of stranding it. A
terminal transition writes exactly one terminal event and a self-contained
terminal outbox envelope in one transaction. Worker terminalization requires the
execution fence once a turn has been bound to an attempt.

Interactive projections are bounded. `active_turns_page` and
`active_turns_for_agent_page` use stable keyset cursors rather than loading all
active rows, while `events_after` remains a bounded ordered tail. Consumers
must page from the projection; they must not rebuild current state by replaying
the complete event history on an interactive thread.

The scheduler uses a deterministic three-lane policy:
`User`, `Agent`, and `Background`, FIFO within each lane, with bounded
anti-starvation promotion thresholds. Schema v5 stores only a fixed-size
scheduler projection and immutable dispatch classification; it does not add a
second scheduler event log. `run_scheduler_snapshot` returns three aggregate
lane diagnostics, active-run state, fairness counters, and an owner event-tail
watermark in one SQLite read transaction. Capacity admission, selection,
running transition, fairness advancement, and active-claim creation share one
immediate transaction. Release-to-waiting and terminal settlement require the
matching epoch and execution ID.

The default-off ACP scheduler pilot extends that contract with opaque input and
claim phases. Scheduled admission commits the verified adapter payload beside
its dispatch so claim does not depend on a relay fetch. A claim returns that
opaque payload and dispatch while remaining transport-neutral. It starts
`reserved`; ACP marks it `launched` immediately before provider work. Restart
may safely requeue `reserved`, while `launched` becomes `hold_uncertain` and is
never replayed automatically.

Outbox publishers use expiring claims. A stale publisher cannot mark another
publisher's record delivered, relay event identity is retained, and retry times
only move forward. Runtime recovery is similarly guarded by one renewable lease
per `(owner, agent)`. Recovery clears stale execution IDs, keeps delayed work
delayed, and holds interrupted `running` work as `hold_uncertain`; it never
blindly repeats potentially side-effecting work. A recovered input is marked
queue-acknowledged only after insertion succeeds. The same runtime suppresses
that acknowledged replay, while a replacement lease owner can recover it after
a crash. A bounded periodic pass advances delayed work when due, retries failed
rehydration, and expires overdue turns.

## Local validation

```bash
cargo test -p buzz-lifecycle
cargo clippy -p buzz-lifecycle --all-targets -- -D warnings
cargo fmt -p buzz-lifecycle -- --check
```

Production integration remains default-off. The async Buzz adapter now proves
normal-input relay rehydration, overload rejection, projection replay,
lease-checked bind-before-spawn, and fenced result updates without blocking the
main relay reactor. Lease-checked admission, rejection, expiry, recovery queue
acknowledgement, and takeover replay are also covered. Exact retry/merge recovery
and live marked-delivery validation are still production gates. The adapter can
query one recovery input by immutable event ID and validates
its signature, author, channel, digest, and original timestamp before returning
it. The default-off authority injects only due normal/zero-retry recovery inputs;
other delivery modes remain held for explicit reconciliation.

`buzz-acp` now contains that first async boundary behind its default-off
`durable-turn-lifecycle` feature. It translates signed Nostr identity into an
admission request and runs ledger operations on blocking workers. The ACP result
path exposes typed success, retry, merged-retry, failure, cancellation, removal,
and heartbeat dispositions. Successful visible assistant output and failure
envelopes are content-digested.

Setting `BUZZ_ACP_LIFECYCLE_SHADOW_DB` while running a feature-enabled build
starts a bounded 256-command FIFO shadow worker. Verified signed admission and
dispatch intent now commit atomically; merged-event execution binding and
terminal/retry results are projected in order. Shadow queue rejection or ledger
failure is logged but does not alter the legacy live queue; this is deliberately
not production authority yet.

Setting `BUZZ_ACP_LIFECYCLE_AUTHORITATIVE_DB` in a feature-enabled build selects
a mutually exclusive pilot path. It acquires a renewable `(owner, agent)` lease,
recovers before channel subscription, rejects overload with a durable tombstone,
does not enqueue exact duplicates, binds every batch before worker spawn, and
persists retry/merge schedules with each waiting transition. A periodic,
lease-fenced reconciler expires overdue work and retries eligible recovery until
queue insertion is durably acknowledged. Lease loss, ledger
failure or bind failure stops the runtime instead of continuing with split
authority. A prompt panic is durably failed under the active execution fence
before shutdown. This path remains off in installed and production Buzz.

`BUZZ_ACP_LIFECYCLE_SCHEDULER_DB` selects a third, mutually exclusive local
pilot in a feature-enabled build. The selector must be a non-empty absolute
path. The executable pilot does not insert admitted work into `EventQueue`;
the lifecycle scheduler is the only pending-work authority. The pilot requires
`BUZZ_ACP_AGENTS=1`, `BUZZ_ACP_MULTIPLE_EVENT_HANDLING=queue`,
`BUZZ_ACP_DEDUP=queue`, `BUZZ_ACP_HEARTBEAT_INTERVAL=0`, and
`BUZZ_ACP_LAZY_POOL=false`.
It reserves that worker before claiming a turn, carries claim epoch/execution
metadata through the prompt task, and applies every terminal, waiting, cancel,
and panic result through claim-fenced settlement. New messages remain separate
durable turns rather than merged batches. These restrictions are startup errors,
not best-effort recommendations.

### Scheduler pilot activation and rollback

Do not enable this experimental mode in an installed or shared runtime. Its
local activation gate is:

1. build `buzz-acp` with `--features durable-turn-lifecycle`;
2. use a fresh absolute database path and set only
   `BUZZ_ACP_LIFECYCLE_SCHEDULER_DB` among the three lifecycle selectors;
3. set the five compatibility-envelope values above;
4. run the lifecycle scheduler and ACP scheduler-pilot focused tests;
5. inspect a bounded scheduler snapshot before and after an isolated
   relay/channel canary; and
6. verify completion, retry, cancellation, lease loss, and restart behavior.

To roll back, stop the scheduler pilot first. Return to legacy mode only after
the snapshot has no active, pending, or `hold_uncertain` work. If work remains,
keep the legacy consumer stopped until
each turn is reconciled or explicitly terminalized; otherwise relay replay can
duplicate work. Then unset the scheduler selector and restart with no lifecycle
selector. Preserve the database for inspection; never reuse it as the shadow or
queue-authoritative database. Unsetting a selector is not state migration or
reconciliation.

`BUZZ_ACP_CAPTURE_VISIBLE_FINAL=true` selects the separate harness-owned reply
contract. It changes the prompt instruction, captures at most 64 KiB of final
ACP assistant text, and stores it inside the terminal envelope. With pilot
authority also enabled, a one-second background outbox worker reconciles stable
client markers, publishes through authenticated REST, validates the relay event
ID, and records delivery under the active runtime lease. Legacy tool-sent reply
mode remains unchanged and never auto-publishes ACP assistant text. Captured
final text is plaintext local chat data; do not enable this mode in production
until retention and at-rest protection are decided.

Merged ACP attempts use atomic multi-turn running, waiting, and terminal
transactions. Result application is fenced to the execution ID bound at
dispatch, so a stale attempt cannot terminalize a replacement attempt.

The scheduler pilot does **not** establish multi-agent pool scheduling,
steer/interrupt merging, durable background routines, automatic replay of
uncertain work, live final publication, retention policy, at-rest protection,
or production readiness.

Its adapter currently derives a fixed 30-day expiry from each signed event
timestamp. That implementation detail is not an approved production retention
policy. Remaining production gates include external capability fencing across
cancellation and ACP/provider launch, live relay validation of the receipt and
terminal outbox, legacy steer-membership restoration, and the complete
bash-backed ACP suite in supported Linux CI. The current ACP MCP bootstrap also
places long-lived `BUZZ_PRIVATE_KEY`/`BUZZ_AUTH_TAG` material in arbitrary child
MCP environments; production requires harness-side brokered signing or a
short-lived execution capability instead.

```bash
cargo test -p buzz-acp --features durable-turn-lifecycle durable_lifecycle
cargo test -p buzz-acp --features durable-turn-lifecycle durable_result_bridge_tests
cargo clippy -p buzz-acp --features durable-turn-lifecycle --all-targets -- -D warnings
```
