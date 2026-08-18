# Durable scheduler checkpoint validation

Date: 2026-08-16

This manifest records local validation of the default-off lifecycle scheduler
and ACP pilot. It is checkpoint evidence, not production approval. It does not
claim that the executable local capability-broker pilot is production-ready or
safe for remote workers.

## Supported Linux environment

- Docker Desktop Linux containers on WSL2 kernel
  `6.6.114.1-microsoft-standard-WSL2`, `x86_64`.
- Debian 12 (bookworm).
- Image `rust:1.95-bookworm`, immutable image ID and pulled digest
  `sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1`.
- `rustc 1.95.0`, `cargo 1.95.0`, Bash 5.2.15, Git 2.39.5,
  build-essential 12.9, CMake 3.25.1, pkg-config 1.8.1, and
  libssl-dev 3.0.20.
- The worktree was mounted read-only. Cargo registry, Git dependency, and
  target data used the separate `buzz_linux_cargo_registry`,
  `buzz_linux_git_db`, and `buzz_linux_target` Docker volumes. No relay, model
  provider, paid API, OCI resource, or installed Buzz runtime was used.

## Passing commands and results

```text
cargo test --locked -p buzz-acp --features durable-turn-lifecycle --lib
815 passed; 0 failed; 0 ignored

cargo test --locked -p buzz-lifecycle
53 passed; 0 failed; 1 ignored

cargo test --locked -p buzz-lifecycle --test scheduler_load -- --ignored --nocapture
1 passed; 320 turns settled under contended writers
admissions 1.240 s; claim and settlement 6.397 s; snapshot 0.533 ms

cargo clippy --locked -p buzz-lifecycle -p buzz-acp \
  --features buzz-acp/durable-turn-lifecycle --all-targets -- -D warnings
passed

cargo check --locked -p buzz-lifecycle -p buzz-acp \
  --features buzz-acp/durable-turn-lifecycle --all-targets
passed

cargo fmt -p buzz-lifecycle -p buzz-acp -- --check
passed

git diff --check
passed
```

Load timings are descriptive observations, not acceptance thresholds.

The earlier Windows-only failure was a host harness limitation: its WSL target
did not provide `/bin/bash`. The same complete ACP library suite, including all
previously blocked shell/process cases, now passes 815/815 in the supported
Linux container above. Direct Windows Bash availability is unchanged, but it
is no longer an unresolved local validation gap.

## Completed process-crash matrix

`crates/buzz-lifecycle/tests/crash_reopen.rs` now self-spawns the integration
test binary, synchronizes through the public store API and an external SQLite
write lock, kills the child at each boundary, and reopens the database. The
table-driven harness proves:

1. before claim commit: the turn remains queued and is claimable once;
2. after `Reserved` commit but before launch: restart rehydrates one fresh
   execution;
3. after `Launched` commit but before a result: restart preserves
   `hold_uncertain` and does not auto-dispatch;
4. after a result arrives but before terminal commit: rollback remains
   `Launched`, then recovery preserves `hold_uncertain`; and
5. after terminal commit but before acknowledgement: exact admission replay is
   idempotent, the terminal outbox is delivered once, and duplicate
   acknowledgement is harmless.

The focused ACP test
`scheduler_recovery_and_quarantine_never_touch_event_queue_or_lose_provider_slot`
also proves that recoverable `Reserved`, quarantined `Launched`, and corrupt
opaque-input cases return the sole checked-out provider slot without launching
a task and leave legacy `EventQueue` pending, queued, and in-flight depth at
zero.

Current local commands:

```text
cargo test -p buzz-lifecycle --test crash_reopen \
  durable_boundaries_survive_process_crash_and_reopen -- --nocapture
1 passed; 0 failed

cargo test -p buzz-lifecycle --no-fail-fast
54 passed; 0 failed; 2 ignored

cargo test -p buzz-acp --features durable-turn-lifecycle \
  scheduler_recovery_and_quarantine_never_touch_event_queue_or_lose_provider_slot
1 passed; 0 failed
```

Reproduction in supported project CI remains a production gate; this local
result does not make the scheduler or capability broker production-ready.

## Final complete-tree Linux validation

The complete current worktree was revalidated in the supported environment
above after the capability protocol, broker, CLI consumer, ACP projection, and
dev-MCP consumer slices converged. The source remained mounted read-only; only
the named Cargo and target caches and the disposable container filesystem were
writable.

```text
cargo test --locked -p buzz-acp --all-features
849 passed; 0 failed; 0 ignored
  837 library tests
  3 credential-mode startup integration tests
  9 pool-lifecycle integration tests

cargo test --locked -p buzz-signing-capability
15 passed; 0 failed; 0 ignored

cargo test --locked -p buzz-capability-client
17 passed; 0 failed; 0 ignored

cargo test --locked -p buzz-cli
347 passed; 0 failed; 1 ignored documentation example

cargo test --locked -p buzz-dev-mcp
108 passed; 0 failed; 0 ignored

cargo test --locked -p buzz-lifecycle
54 passed; 0 failed; 2 ignored

cargo test --locked -p buzz-lifecycle --test scheduler_load \
  -- --ignored --nocapture
1 passed; 320 turns settled under contended writers
admissions 1.459 s; claim and settlement 6.552 s; snapshot 0.637 ms

cargo test --locked -p buzz-lifecycle --test crash_reopen \
  durable_boundaries_survive_process_crash_and_reopen -- --nocapture
1 passed; all five process-crash boundaries observed
```

The ACP all-features run executed the actual supported-Linux Bash child,
grandchild, session, timeout, and shutdown fixtures. Four additional exact
canaries then passed individually: broker projection through a portable
grandchild, session-new/prompt secret redaction, MCP base projection without
long-lived credentials, and dev-MCP shell projection with credential aliases
removed.

```text
cargo clippy --locked --all-features --all-targets \
  -p buzz-acp -p buzz-agent -p buzz-cli -p buzz-dev-mcp -p buzz-sdk \
  -p buzz-lifecycle -p buzz-signing-capability \
  -p buzz-capability-client -- -D warnings
passed

cargo check --locked --all-features --all-targets \
  -p buzz-acp -p buzz-agent -p buzz-cli -p buzz-dev-mcp -p buzz-sdk \
  -p buzz-lifecycle -p buzz-signing-capability \
  -p buzz-capability-client
passed

cargo fmt --all -- --check
passed

git diff --check
passed on the host checkout
```

The linked-worktree `.git` file contains a host-side pointer that is not valid
inside the read-only Linux bind mount, so the content-independent Git diff
check ran against the same bytes in the host checkout. The final 81-file diff
inventory contained no generated build/database/log/binary artifacts and no
high-confidence private-key or provider-token pattern. Three absolute-machine
path matches were intentional fake Windows-path normalization fixtures under
`buzz-acp` tests; no developer or workspace path was embedded.

## Production gates still open

- Add an external capability fence across authoritative cancellation and the
  actual ACP/provider launch; the SQLite `Reserved` to `Launched` marker cannot
  make that external side effect atomic.
- Reproduce the completed five-boundary process-crash matrix in supported
  project CI.
- Validate receipt and terminal outbox publication against a live relay,
  including ambiguous submission, reconnect, retry, and recovery.
- Promote the working local process-generation capability pilot only after its
  remaining production boundaries are closed. ACP child/MCP key projection,
  the loopback broker, shared client, broker-aware Buzz CLI/dev-MCP subset, and
  process-generation issue/activate/revoke lifecycle are locally complete. See
  [ADR-0003](adr/0003-capability-broker-boundary.md). Remote transport and
  workload isolation, claim-bound launch fencing, durable registry/replay,
  installed-runtime CI, brokered NIP-42, narrower query resources, and Git,
  Blossom/media, engram/memory consumers remain open.
- Restore and prove exact membership cancellation, retry, and merged
  steer/interrupt semantics before widening beyond the one-slot queue-only
  compatibility envelope.
- Define approved retention, deletion, compaction, backup, and at-rest
  protection for signed inputs and captured final text.
- Run an isolated installed-runtime canary before any shared or production
  activation. All lifecycle selectors remain unset by default.

## Addendum 2026-08-17 — Remote-ready at-rest + scheduler bridge (docs-only lock)

This addendum locks the transport, at-rest placement, retention caps, and
launch-fence choices that future remote/Kubernetes slices must not re-decide.
No `buzz-acp`/`buzz-lifecycle` behavior changes in this slice beyond comments;
the store already implements the invariant locally.

### Transport — WebSocket (locked)

Service-authenticated transport is **WebSocket (tokio-tungstenite)**. The broker
binds localhost (`127.0.0.1:0`) and upgrades each connection to WebSocket;
Tailscale is an **endpoint provider** that makes the local-broker port reachable
as `ws://100.x.y.z:<port>` over the Tailnet. The broker has no Tailscale baked-in
code. This supersedes the earlier "Tailscale-bound TCP" draft. mTLS remains a
documented fallback only if Tailnet is unavailable.

### At-rest store — same lifecycle SQLite WAL on device persistent path (locked)

The lifecycle DB is the same `crates/buzz-lifecycle` SQLite WAL already used
for the scheduler: `SCHEMA_VERSION = 8`, `journal_mode=WAL`,
`synchronous=FULL`, foreign keys, bounded busy timeout, one connection per
operation via `spawn_blocking`. The remote-ready invariant places it on the
**device persistent path** (`Tauri app_data_dir`, e.g. desktop
`.../buzz/lifecycle.db`) rather than an ephemeral env-var-only location. The
file is **encrypted at rest if the OS supports it** (OS file protection /
DPAPI / Keychain / full-disk encryption); the store does not add a second
at-rest cipher. Backup/restore verification stays a production gate.

### Retention caps — 30d / 500 MiB soft / 1 GiB hard, tombstones kept, VACUUM (locked)

Per-`(owner,agent)` policy in `retention_policies` (v8):
default **30 days / 500 MiB soft / 1 GiB hard**, slider **7–90 days /
256 MiB–2 GiB** (`CHECK(soft_bytes BETWEEN 268435456 AND 2147483648 AND hard_bytes >= soft_bytes)` and `RetentionPolicy::validate`), **tombstones** (`rejected` state) **kept**, `enforce_retention` prunes oldest `completed/failed/cancelled/expired` first by TTL then by soft-watermark size, **never blocks admission**, and runs `VACUUM` iff `pruned > 0` (via a fresh connection after commit). Proven by `crates/buzz-lifecycle/tests/retention.rs` (`retention_caps_evict_oldest_terminal_with_ttl_and_size_and_never_block_admission`) and `RetentionUsage`/`RetentionEnforceResult`.

### Launch fence — lifecycle v8, cancel-wins, IMMEDIATE epoch bump, single-use (locked)

The cancellation/launch race is already closed in `lifecycle v8` via
`launch_fences` + `activation_capabilities`:
`create_inert_turn` (ensures fence row, admits inert `Accepted`) →
`mint_activation_capability` (`next_epoch = current + 1`, fence **not** bumped on mint) →
`cancel_turn_with_fence` **or** `activate_with_capability` bumps `launch_epoch` by `+1` in the **same `IMMEDIATE` transaction** as the state transition and marks competing capabilities `consumed=1` (`WHERE launch_epoch <= next_epoch`). Capability is **single-use**; late `activate` after `cancel` (or after terminal) returns `AlreadyConsumed`/`CancelledConflict` — **cancel-wins**, monotonic `launch_epoch`. Proven by `crates/buzz-lifecycle/tests/launch_fence.rs` (`launch_fence_cancel_wins_over_concurrent_activate`) and `store.rs:ensure_launch_fence_tx` / `mint_activation_capability` / `cancel_turn_with_fence` / `activate_with_capability`.

### What this slice does not change

- No ACP/MCP runtime wires the persistent path or Tailscale by default; all selectors remain **default-off** and the pilot remains local-only.
- Production still needs: backup/restore verification, OS at-rest encryption proof per target, installed-runtime crash/reconnect/cancel canary, live-relay receipt/terminal outbox validation, and CI reproduction of the five-boundary crash matrix.

### Updated production gates (narrowed)

- ~~Define approved retention, deletion, compaction, backup, and at-rest protection~~ — **Retention policy and at-rest placement are locked above; remaining gate is backup/restore verification + OS at-rest encryption proof per target.**
- ~~Add an external capability fence across authoritative cancellation and the actual ACP/provider launch~~ — **Covered by lifecycle v8 launch fence above; remaining gate is wiring the fence through the actual remote provider launch path and its installed-runtime test.**
