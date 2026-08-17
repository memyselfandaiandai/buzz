# Slice 3 local validation

Validated on FINAL-FORM on 2026-08-17 from the isolated worktree branch
`feat/durable-turn-lifecycle-spine`.

## Passing gates

```text
cargo fmt -p buzz-lifecycle -p buzz-sdk -p buzz-acp -- --check
PASS

cargo test -p buzz-lifecycle --no-fail-fast
PASS: 48 passed default (57 with --features cards-automations-skills), retention + launch-fence suites green; 0 failed

cargo test -p buzz-lifecycle --test retention --no-fail-fast
PASS: 1 passed, 0 failed (TTL/size watermarks, tombstone kept, never blocks)

cargo test -p buzz-lifecycle --test launch_fence --no-fail-fast
PASS: 1 passed, 0 failed (cancel-wins, monotonic epoch, single-use activation)

cargo test -p buzz-lifecycle --features cards-automations-skills --no-fail-fast
PASS: 16 lib + 9 vertical_slice (human_cards/automations/spend_guard/skill_curator, v8 roundtrip), 0 failed

cargo test -p buzz-acp --features durable-turn-lifecycle durable_lifecycle --no-fail-fast
PASS: 7 passed, 0 failed

cargo test -p buzz-acp --features durable-turn-lifecycle durable_result_bridge_tests --no-fail-fast
PASS: 4 passed, 0 failed

cargo test -p buzz-acp --features durable-turn-lifecycle error_outcome_emission_tests --no-fail-fast
PASS: 26 passed, 0 failed

cargo test -p buzz-sdk marked_message_only_adds_bounded_client_marker --no-fail-fast
PASS: 1 passed, 0 failed

cargo clippy -p buzz-lifecycle --all-targets -- -D warnings
PASS

cargo clippy -p buzz-sdk --all-targets -- -D warnings
PASS

cargo clippy -p buzz-acp --features durable-turn-lifecycle --all-targets -- -D warnings
PASS

cargo clippy -p buzz-acp --all-targets -- -D warnings
PASS

git diff --check
PASS
```

The focused tests cover exact duplicate admission, atomic admission plus dispatch
intent, legacy accepted-row repair, immutable-binding conflicts, signature
verification, owner and agent projection isolation, ordered event tails,
execution-fenced terminal transitions, self-contained terminal envelopes, leased
outbox claims, monotonic retry schedules, expiry, concurrent replay, and
off-reactor SQLite calls. Durable overload rejection writes an exactly-once
terminal tombstone without raw input. Lease-checked tests prove admission,
capacity rejection, expiry reconciliation, multi-event bind, and terminal
updates are all-or-nothing. Stale runtimes cannot accept, reject, requeue, or
finish work; retry metadata advances atomically; and waiting clears the prior
execution fence. A version-1 fixture proves the schema upgrade reaches
the current version with claim and recovery structures present. Restart tests cover runtime lease contention,
idempotent recovery without same-state event/version inflation, delayed work,
execution clearing, stale-result rejection, explicit queue acknowledgement,
same-instance duplicate suppression, takeover recovery, due-time advancement,
live-reconciler isolation from ordinary queued/running work, and persistent
`hold_uncertain` classification for formerly running work. Atomic
merged-turn transitions, rollback, stable output digests, typed retry/dead-letter
dispositions, ordered bounded shadow-worker processing, and the lease-checked
authoritative result bridge remain covered. The default-off authoritative ACP
path acquires and renews its lease, recovers before live subscription, checks
queue capacity before durable admission, binds before prompt spawn, persists
retry/merge scheduling, periodically expires overdue work, retries recoverable
queue insertion, and stops on lease or authority failure. Lease-scoped outbox
tests cover claim, retry, delivery, takeover fencing, marker construction,
failure sanitization, and a complete in-process REST delivery path.
Harness-owned final capture is default-off, bounded to 64 KiB, and stores the
captured final transactionally; an empty captured final fails closed instead of
becoming `completed`.
The active-turn projection now uses bounded keyset pages. Its focused test uses
multiple rows with the same acceptance timestamp to prove the `(accepted_at_ms,
turn_id)` cursor returns every row once without full-history replay.

## Post-review scheduler and tool-exposure continuation

After the DeepSeek Harness comparison, the local lifecycle slice added:

- schema v5 lane classification and one fixed-size `run_scheduler_state`
  projection;
- a pure `User > Agent > Background` selector with configurable agent and
  background promotion thresholds;
- bounded keyset pages for the active-turn projection;
- constant-cardinality scheduler diagnostics and an owner event-tail watermark;
- a default-off `buzz-agent` `BUZZ_AGENT_TOOL_EXPOSURE=anchored` experiment that
  narrows only the first model request and restores the complete catalog on the
  next round.

The scheduler tests exhaust lane-presence and promotion-boundary combinations,
prove background and agent service under continuous contention, and limit a
user delay to two simultaneous promotions. The snapshot tests include 4,096
additional lifecycle events and prove the projection remains exactly three lane
records without replaying history. The staged-tool tests prove default-full
behavior, first-request-only narrowing, next-round/later-turn promotion, full
registry dispatch, invalid-config rejection, stable catalog hashing, and
bounded telemetry names.

The store continuation now includes atomic per-lane capacity admission,
single-active scheduler claim, and claim-fenced release/terminal settlement.
The ACP adapter now exercises those operations in an executable, default-off
local scheduler pilot. That does not establish production readiness, a matched
model benchmark, or Hermes tool-catalog control.
The relay adapter also has a focused acknowledgement test proving durable REST
submission is not considered successful unless `accepted=true` and the returned
event ID exactly matches the signed event.

## Executable scheduler pilot and validation boundary

The local ACP gate is explicit and default-off under
`BUZZ_ACP_LIFECYCLE_SCHEDULER_DB`, mutually exclusive with the shadow and
queue-authoritative database selectors. The scheduler path must be non-empty
and absolute. Its locked compatibility envelope is
`BUZZ_ACP_AGENTS=1`, `BUZZ_ACP_MULTIPLE_EVENT_HANDLING=queue`,
`BUZZ_ACP_DEDUP=queue`, `BUZZ_ACP_HEARTBEAT_INTERVAL=0`, and
`BUZZ_ACP_LAZY_POOL=false` (or unset). Admitted pilot work never enters
`EventQueue`; its depth remains zero in the focused round-trip test.

The durable contract for that gate is:

- scheduled admission commits an opaque signed input with its dispatch, lane,
  source, receipt, and runnable turn;
- one atomic claim returns the opaque input and dispatch while binding an epoch
  and execution ID in `reserved` phase;
- the harness fences `launched` before invoking ACP;
- restart requeues `reserved` but quarantines `launched` as
  `hold_uncertain`, without leaving the active scheduler slot wedged;
- completion, retry, cancellation, panic, timeout, and stale-result rejection
  settle only through the matching claim identity; and
- queued work is read through bounded scheduler projections and claims, never
  reconstructed from the lifecycle event log.

The following commands were rerun on FINAL-FORM on 2026-08-17 after the ACP
runtime wiring landed:

```text
cargo test -p buzz-acp --features durable-turn-lifecycle scheduler --no-fail-fast
PASS: 12 passed, 0 failed

cargo test -p buzz-acp --features durable-turn-lifecycle pre_launch_failure_releases_reserved_claim_for_a_fresh_fenced_retry --no-fail-fast
PASS: 1 passed, 0 failed

cargo test -p buzz-acp --features durable-turn-lifecycle corrupt_migrated_opaque_input_is_quarantined_once_without_launch_or_queue --no-fail-fast
PASS: 1 passed, 0 failed

cargo clippy -p buzz-acp --features durable-turn-lifecycle --lib -- -D warnings
PASS

cargo check -p buzz-acp --no-default-features
PASS
```

These focused tests cover the strict mode/path envelope, human-versus-verified
sibling classification, atomic opaque-input admission and claim, zero
`EventQueue` use, reserved-before-launch release, claim-fenced retry,
cancellation and stale settlement, and one-time quarantine of corrupt migrated
opaque input without launch. They also cover graceful-shutdown completion and
confirmed cancellation, timeout-to-`hold_uncertain`, stale completion after
takeover, and removed-channel cancellation while still reserved. Store tests
separately cover reserved-versus-launched takeover recovery and bounded
scheduler projection/claim behavior. A startup regression also proves the
active claim is recovered ahead of a backlog larger than the generic recovery
page.
This is green local implementation evidence, not a production-readiness claim.

Activation must use a fresh local database and an isolated relay/channel.
Build with `--features durable-turn-lifecycle`, set only the scheduler database
selector among the three modes, and satisfy all five envelope settings.
Rollback must stop the pilot and inspect the scheduler snapshot first. Legacy
processing may resume only after active, pending, and uncertain work is empty or
explicitly reconciled. Then unset the scheduler selector and restart without a
lifecycle selector. Preserve the pilot database for inspection and never reuse
it for shadow or queue-authoritative mode; changing selectors is not state
migration or reconciliation.

The lifecycle store now exposes a per-(owner,agent) retention policy (default 30d / 500MiB soft / 1GiB hard, slider 7-90d / 256MiB-2GiB, tombstone kept, VACUUM after prune, never blocks admission) and an inert→ledger→epoch→single-use launch fence (cancel-wins). Both are default-off local policy; production still needs approved backup/at-rest protection and a remote signer/transport decision before activation.

## Broad-suite environment limitation

The latest full ACP library-suite attempt used:

```text
cargo test -p buzz-acp --features durable-turn-lifecycle --lib --no-fail-fast
OBSERVED: 760 passed, 32 failed
```

All 32 failures were in helpers that require WSL `/bin/bash`. FINAL-FORM
currently reports:

```text
WSL ERROR: CreateProcessCommon:818: execvpe(/bin/bash) failed: No such file or directory
```

The representative test
`acp::tests::agent_request_not_consumed_via_send_request` was run in the untouched
base checkout at commit `4b057a5f0d135120460c2c102698c3a9ff525754` and fails with the same WSL error.
This demonstrates a pre-existing host test-harness limitation, not a regression
introduced by the lifecycle feature. A Linux/WSL environment with `/bin/bash`
remains the deterministic gate for the complete ACP suite.

## Deliberately not claimed

- The feature, `BUZZ_ACP_LIFECYCLE_SHADOW_DB`, `BUZZ_ACP_LIFECYCLE_AUTHORITATIVE_DB`, and `BUZZ_ACP_LIFECYCLE_SCHEDULER_DB` remain disabled in the installed/live ACP runtime.
- Shadow mode observes the legacy queue; it does not gate admission or delivery.
- The claimed REST outbox publisher runs only when both pilot authority and `BUZZ_ACP_CAPTURE_VISIBLE_FINAL=true`; it was validated against an in-process bridge, not a live relay.
- The default-off authoritative path is a local pilot gate, not a production-readiness claim.
- The scheduler-pilot contract does not claim multi-slot execution, merged
  steer/interrupt semantics, durable background routines, or automatic replay
  of `hold_uncertain` work.
- The local `reserved -> launched` ledger fence is not an external capability
  fence. Cancellation can still race the actual ACP/provider launch until that
  side effect participates in an authoritative activation protocol.
- Receipt and final-message outbox behavior has not passed live-relay ambiguous
  submission, reconnect, retry, and recovery validation.
- The queue-only envelope disables legacy steer/merge, but legacy
  steer-membership removal and cancellation behavior has not been restored or
  proven for scheduler authority.
- The complete bash-backed ACP suite has not passed on this Windows host; it
  remains a supported Linux CI gate.
- The current ACP MCP bootstrap forwards long-lived `BUZZ_PRIVATE_KEY` and
  `BUZZ_AUTH_TAG` material through `session/new` child environment
  configuration. Production activation is blocked until signing is mediated by
  the harness or replaced with a narrowly scoped short-lived capability.
- Automatic rehydration currently handles only due, normal, zero-retry work. Retry and merged-steer/interrupt schedules remain held until their exact grouping semantics can be restored.
- A prompt-task panic atomically fails the bound execution under the active lease and then stops authoritative ACP; automatic side-effecting replay remains forbidden.
- No live relay, live final-reply publication, crash-injection process test, or installed Buzz runtime was exercised.
- Opaque signed input and harness-owned final text are local chat data retained
  in SQLite when their respective pilot paths are enabled; production still
  needs deletion, retention, compaction, backup, and at-rest protection policy.
- No OCI, Kubernetes, model-provider, credential, or deployment operation occurred.
## Keyless scheduler contention gate

Run the deterministic SQLite-only load gate explicitly:

```text
cargo test -p buzz-lifecycle --test scheduler_load -- --ignored --nocapture
```

It uses no relay, model, API, or external service. Eight contended writers
exercise scheduled admission, reserved-to-launched settlement, lease renewal
and takeover fencing, bounded expiry across multiple passes, and fixed-size
scheduler snapshots. Elapsed timings are descriptive local evidence only;
correctness assertions, never machine-speed thresholds, determine success.
