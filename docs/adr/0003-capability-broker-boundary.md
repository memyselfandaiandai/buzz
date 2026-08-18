# ADR-0003: Capability-broker boundary for managed agents

- Status: Accepted and implemented for the default-off local process-generation
  pilot (Slices A-D4); not approved for production or remote workers
- Date: 2026-08-16
- Decision owner: Buzz architecture

## Context and threat model

The legacy ACP path gives a managed child `BUZZ_PRIVATE_KEY`,
`NOSTR_PRIVATE_KEY` when present, and `BUZZ_AUTH_TAG`. It can also copy relay
credentials into `session/new` MCP server environment entries. A compromised,
misconfigured, or merely over-capable ACP child or MCP server can therefore
retain the long-lived signer, sign outside the current session, impersonate the
agent after cancellation, and disclose the owner's authorization tag. Process
environment inheritance and diagnostic output add further accidental-disclosure
paths.

The goal is not to make an untrusted child trusted. The goal is to keep
long-lived key material inside a trusted signing boundary and give each child a
short-lived bearer capability for a bounded, structured set of operations. The
broker is a credential authority, not an agent, scheduler, lifecycle ledger, or
artifact-acceptance authority.

The following remain trusted and can still cause identity-wide harm if
compromised:

- the harness process that owns or can reach the long-lived signer;
- the broker implementation and its cryptographic executor;
- the host account, kernel, debugger, and any process able to read broker
  memory; and
- the control path that issues, activates, and revokes capabilities.

## Decision

`crates/buzz-signing-capability` is the transport-neutral protocol and policy
core. It accepts only versioned, structured operations; it exposes no raw-key
export, arbitrary-digest signing, arbitrary URL fetch, shell, or generic signing
operation. `buzz-acp` may project a process-generation capability into a child only
through a typed, fixed environment allowlist.

Credential mode is explicit:

- `BUZZ_CREDENTIAL_MODE` unset or `legacy-env` preserves current behavior.
- `BUZZ_CREDENTIAL_MODE=broker-v1` selects the compiled local pilot when the
  `signing-capability-broker` feature is present.
- Any other value fails closed.
- A feature-off build rejects `broker-v1`; a feature-on build enforces the local
  compatibility envelope before starting any ACP child. Installed and default
  behavior is unchanged.

There is no implicit fallback from a requested `broker-v1` session to
`legacy-env`. A process must use one credential mode for its lifetime; changing
mode requires a restart.

### Protocol v1

A request envelope contains:

- `version`, exactly `1`;
- opaque `capability_id` and secret `token`;
- unique `request_id` for idempotency and replay fencing;
- request-specific `deadline_unix_ms`; and
- one structured `operation`.

A response repeats the protocol version and request ID and contains either a
typed result or a stable, non-sensitive error class. Raw executor errors are not
part of the protocol. The token is generated from 256 random bits, serialized
only for transport, redacted from `Debug`, stored by the registry only as a
SHA-256 digest, and compared in constant time.

The fixed ACP child projection is:

| Variable | Meaning |
|---|---|
| `BUZZ_CAPABILITY_ENDPOINT` | Broker endpoint selected by trusted harness configuration |
| `BUZZ_CAPABILITY_ID` | Opaque capability identifier |
| `BUZZ_CAPABILITY_TOKEN` | Secret bearer token |
| `BUZZ_PUBLIC_KEY` | Non-secret agent identity |
| `BUZZ_RELAY_URL` | Capability-bound relay |
| `BUZZ_CAPABILITY_EXPIRES_AT` | Positive absolute expiry |

Before applying that projection, ACP removes inherited `BUZZ_PRIVATE_KEY`,
`BUZZ_ACP_PRIVATE_KEY`, `NOSTR_PRIVATE_KEY`, `BUZZ_AUTH_TAG`, and every unrecognized
`BUZZ_CAPABILITY_*` variable. Extra environment entries cannot override those
reserved names. Endpoint and relay schemes, public-key shape, expiry, empty
values, and control characters are validated before spawn. Local-v1 uses a single
WebSocket request and response over an ephemeral
`ws://127.0.0.1:<nonzero-port>` connection; WebSocket framing (tokio-tungstenite)
replaces NDJSON. This loopback transport is not a remote security boundary.

### Local process-generation lifecycle

The executable local pilot implements this order:

1. Connect the trusted harness, discover and subscribe the startup channel set,
   then derive the fixed relay, operation, event-kind, HTTP, and channel scope.
2. For each ACP process generation, issue one inactive capability with a hard
   lifetime no greater than two hours and bounded operation, byte, concurrency,
   and replay budgets. The registry returns the raw bearer token
   once; logs and durable session records receive only non-secret metadata.
3. Spawn the ACP child with only the fixed projection above. Do not put
   long-lived relay credentials in the child or any `session/new` MCP server
   environment.
4. Send `session/new` with credential mode, the six fixed capability/public
   fields, and optional public display/Git-origin metadata. Activate only after
   `session/new` and MCP configuration succeed. An inactive capability cannot
   authorize work.
5. For every broker call, send a fresh request ID, a deadline no later than the
   capability expiry, and one structured operation. An exact completed replay
   returns the cached response; conflicting reuse revokes the capability.
6. Revoke on failed session creation, cancellation-driven process rotation,
   child exit/drop/panic, respawn, or harness shutdown. Expiry, clock rollback,
   and an unresolved authorization permit also fail closed. Revocation is
   permanent for that capability.

The pilot deliberately supports only one ACP session per process generation.
`max_turns_per_session` must be zero. A second session request fails with a
protocol error and causes process rotation; owner rotation and startup-channel
membership changes restart the harness so it derives a fresh scope. Presence,
heartbeat, core/semantic memory, and lazy-pool operation are disabled by the
compatibility envelope. Standalone `models`, `auth-methods`, and `authenticate`
helpers fail closed in broker mode.

Issue and activate remain separate so a child whose `session/new` fails never
becomes a signer. Activation does not replace the scheduler's external
provider-launch fence: broker activation and provider launch are still separate
side effects until a common authoritative fence exists.

### Structured operation inventory

| Protocol operation | Scope enforced by the local core | Integration status |
|---|---|---|
| `identity_metadata` | Capability relay and public metadata | Broker, shared client, Buzz CLI, and dev-MCP pilot wired |
| `nostr_event_sign` | Relay, event-kind allowlist, optional exact channel, bounded content/tags; caller `auth` tags forbidden | Broker and Buzz CLI subset wired for kinds 9, 45001, 45003, 40008, 40003, 9005, and 45002 |
| `nip98_sign` | Relay plus exact HTTP method/path or segment-prefix rule | Broker and Buzz CLI subset wired only for `POST /query` and `POST /events`, with a required body digest |
| `nip42_sign` | Relay plus bounded challenge | Protocol shape only; harness relay authentication still uses the trusted in-process key |
| `blossom_sign` | Relay, `get` or `upload`, digest/MIME shape | Protocol shape exists; media/Blossom consumer and executor are not wired |
| `engram_coordinate` | Relay, peer/owner allowlist, bounded slug | Protocol shape exists; engram fetch/build/decrypt consumers and executor are not wired |
| `engram_decrypt` | Relay, peer/owner allowlist, bounded signed-event input | Protocol shape exists; engram validation/decryption executor is not wired |
| `engram_build_event` | Relay, owner allowlist, bounded slug/value | Protocol shape exists; encryption/signing executor and memory consumer are not wired |
| `git_nip98_sign` | Relay plus canonical repository method/path | Protocol shape exists; Git credential/Smart-HTTP consumer and executor are not wired |
| `git_object_sign` | Relay, commit/tag discriminator, expected key ID, bounded canonical payload | Protocol shape exists; NIP-GS/Git signing consumer and executor are not wired |

An operation appearing in this table does not mean the local broker can execute
it. Its trusted executor accepts only `identity_metadata`, `nostr_event_sign`,
and `nip98_sign`. `buzz-capability-client` exposes typed methods for those three
operations. The broker-aware Buzz CLI surface is intentionally limited to
messages get/thread/search/send/send-diff/edit/delete/vote, channels
list/get/search, and feed get. Unsupported CLI operations fail before broker or
relay I/O. `buzz-dev-mcp` installs the broker-aware CLI without a key file or
Git credential helper, scrubs credential aliases from shell children, and
blocks protected relay media. Engram, Git, Blossom, NIP-42, protected media,
and every other consumer remain outside local-v1.

### Local embedded broker protections

The completed local pilot provides:

- inactive issue, explicit activation, permanent revocation, and both absolute
  and monotonic-style expiry, with a hard lifetime ceiling of 2 hours 15
  minutes;
- operation, cumulative canonical-byte, in-flight, and exact-replay budgets;
- relay, event-kind, HTTP method/path, channel, and peer/owner scopes;
- bounded canonical payloads, response size, tags, paths, challenges, MIME
  values, slugs, and Git objects;
- exact replay caching, conflict-triggered revocation, request deadlines, and
  stable error classes;
- fail-closed revocation when a permit is dropped with an uncertain outcome,
  the trusted clock moves backwards, or the registry mutex is poisoned; and
- structural/redacted debug output for tokens and content-bearing operations.

It does **not** provide:

- service-authenticated remote transport or a separate signer process; local
  WebSocket is loopback-only and bearer-token authenticated;
- a durable registry, audit log, restart-safe revocation ledger, or recovery
  protocol;
- OS/process isolation from the harness, host administrator, debugger, or
  memory-reading malware;
- proof that a bearer token was used by the intended child rather than another
  local process that stole it;
- binding to the lifecycle claim epoch/execution ID, or atomicity with
  cancellation and provider launch; or
- automatic secret rotation, deletion, backup, or incident response.

The `POST /query` authorization proves relay, method, path, body digest, expiry,
and budgets, but it does not structurally constrain the query body to a narrower
read resource. That broader query authority is acceptable only inside the
documented local pilot and remains a production scope gate.

The current registry is in-memory and process-local. Restart loses its active
state; production must either durably preserve safe revocation/replay state or
invalidate every issued token and require fresh, authoritative issuance.

### Local v1 and remote/Kubernetes isolation

The implemented local pilot embeds the broker beside ACP on one trusted host.
That removes long-lived credentials from ordinary child environments and
constrains a stolen session token, but it is not a sandbox boundary. The
endpoint should bind only to a broker-owned local transport or loopback, reject
ambient credentials, and never expose operator/debug methods through the child
capability.

A remote or Kubernetes worker must not receive a local-v1 capability whose
endpoint or bearer token is reachable by unrelated workloads. Before remote
activation, add service-authenticated transport (for example a Tailscale- or
mTLS-bound broker), network policy, session/agent/claim binding, bounded clock
skew, restart-safe revocation/replay behavior, and auditable issuance and use.
The long-lived signer remains on the authoritative control plane. Browser,
workspace, and MCP containers receive only the scoped token, never tenancy-wide
OCI credentials or long-lived Buzz identity material. Kubernetes isolation is
defense in depth; it does not widen the capability policy.

## Acceptance matrix

| Gate | Local-v1 acceptance | Remote/Kubernetes addition | Current state |
|---|---|---|---|
| Mode selection | Exact `legacy-env`/`broker-v1`; invalid fails; requested broker never falls back | Deployment pins one mode and exposes no mixed secret path | Complete for default-off local pilot; feature-off/helper paths fail closed |
| Secret projection | Child/MCP environment lacks all long-lived key/auth variables and unknown capability variables | Pod spec, logs, crash dumps, and sidecars pass the same canary | Complete locally, including portable hostile-child and serialized MCP canaries |
| Scope | Wrong relay, operation, kind, method/path, channel, or peer is denied | Capability also binds authoritative session, agent, and claim | Slice A local policy complete; claim binding pending |
| Lifecycle | Inactive through spawn/session configuration; activate after successful `session/new`; revoke/rotate on failure, cancel, exit, respawn, and shutdown | Restart-safe revocation and control-plane reconciliation | Complete for one-capability-per-process local pilot |
| Replay | Exact retry is cached; conflicting request ID revokes; budgets are enforced | Durable replay ledger or fail-closed token invalidation after restart | Slice A in-memory behavior complete |
| Execution | Trusted executor exposes no raw-key or generic-sign API | Service identity, isolated signer, authenticated transport, audit | Local executor complete for identity, scoped Nostr events, and NIP-98 only |
| Consumers | Broker-aware CLI/dev-MCP subset uses structured calls only; unsupported operations fail closed | Network policy permits only required broker route | Local message/channel/feed subset complete; Git, Blossom, engram, NIP-42, media, and memory pending |
| Cancellation/launch | Revocation is checked before use | External launch capability fence closes cancellation race | Pending production gate |
| Operations | Unit, projection, portable secret-canary, scope, expiry, replay, and process-generation lifecycle tests pass | Installed-runtime crash/reconnect/cancel and abuse tests pass | Local A-D4 gates pass; installed canary and supported CI remain open |

## Activation and rollback

Legacy remains the installed default. The only supported broker activation is a
local source-build canary compiled with `signing-capability-broker`, with
`BUZZ_CREDENTIAL_MODE=broker-v1` and the strict compatibility envelope:

- `BUZZ_ACP_NO_PRESENCE=true`;
- `BUZZ_ACP_NO_MEMORY=true` and `BUZZ_ACP_MEMORY_PROVIDER=none`;
- `BUZZ_ACP_HEARTBEAT_INTERVAL=0`;
- `BUZZ_ACP_MAX_TURNS_PER_SESSION=0`; and
- `BUZZ_ACP_LAZY_POOL=false`.

For an isolated canary:

1. Use one test agent, relay/channel, and fresh broker instance.
2. Verify secret canaries are absent from the ACP child, every MCP server,
   process diagnostics, and observer events.
3. Exercise each enabled structured operation, denial scope, exact replay,
   cancellation before activation, cancellation after activation, child crash,
   and broker restart.
4. Confirm session completion or cancellation revokes the capability and later
   requests fail without reaching the executor.
5. Expand consumers or remote workers only after their specific acceptance row
   passes.

Rollback is fail-closed: stop new issuance, revoke all live capabilities, stop
broker-mode children, reconcile in-flight lifecycle claims, and preserve
non-secret audit evidence. Then unset `BUZZ_CREDENTIAL_MODE` and restart. An
explicit return to `legacy-env` restores compatibility but also restores the
legacy long-lived-credential threat; it is not a security-equivalent fallback.
Never keep a broker child running while silently switching its consumer to
legacy credentials.

## Consequences and non-claims

Slices A-D4 establish a coherent least-authority vocabulary and a working local
process-generation pilot. ACP removes long-lived Buzz signing credentials from
the managed child and its MCP servers without changing the default legacy path;
the shared client, broker-aware Buzz CLI subset, dev-MCP shim/shell, and ACP
issue/activate/revoke lifecycle operate end to end on one trusted host.

This does not protect against a compromised trusted host or same-account token
theft, broker NIP-42 relay authentication, engram/memory, Git, Blossom/protected
media, broader `POST /query` authority, restart loss of the in-memory registry,
or the cancellation/provider-launch race. It does not authorize installed
production, OCI, remote, or Kubernetes activation. Consumers must continue to
migrate operation by operation; a partially migrated consumer may never receive
both a capability and long-lived signer material.

This boundary complements, but does not replace, the lifecycle scheduler in
[ADR-0002](0002-durable-turn-lifecycle-spine.md) and the remote workspace
authority in [ADR-0001](0001-buzz-workspace-controller-boundary.md).

## Addendum 2026-08-17 — Remote-ready at-rest + scheduler bridge (docs-only lock)

No code change beyond this addendum and comments. The invariants below are the
remote-ready contract; future slices wire through them, they do not re-decide
them. Evidence lives in
[../durable-scheduler-checkpoint-validation.md](../durable-scheduler-checkpoint-validation.md) (Addendum 2026-08-17).

### Locked invariants

1. **Transport is WebSocket (tokio-tungstenite).** The broker binds localhost
   (`127.0.0.1:0`) and upgrades each connection to WebSocket. Tailscale is an
   **endpoint provider**, not baked into the transport — it makes the
   local-broker port reachable at `ws://100.x.y.z:<port>` over the Tailnet.
   The broker has no Tailscale code and no `is_tailscale_ipv4` / `100.x`
   constant. This supersedes the earlier "Transport is Tailscale" draft.
   mTLS remains a documented fallback if Tailnet is unavailable.

2. **At-rest store is the same lifecycle SQLite WAL on the device persistent path.**
   `crates/buzz-lifecycle` SQLite WAL (`SCHEMA_VERSION 8`, `journal_mode=WAL`,
   `synchronous=FULL`, foreign keys, bounded busy timeout, one connection per
   operation via `spawn_blocking`) placed on the **device persistent path**
   (`Tauri app_data_dir`, e.g. `.../buzz/lifecycle.db`), not an ephemeral
   `BUZZ_ACP_LIFECYCLE_*_DB` env-var-only location. Encrypted at rest **if the OS
   supports it** (OS file protection / DPAPI / Keychain / full-disk encryption);
   the lifecycle crate does not add a second cipher. Backup/restore verification
   remains a production gate.

3. **Retention caps — 30d / 500 MiB soft / 1 GiB hard, tombstones kept, VACUUM.**
   Per-`(owner,agent)` `retention_policies` (v8, `schema.rs:306`):
   default **30 days / 500 MiB soft / 1 GiB hard**, slider **7–90 days /
   256 MiB–2 GiB**, `hard_bytes >= soft_bytes`, `retention_days BETWEEN 7 AND 90`.
   `enforce_retention` prunes oldest terminal states first by TTL then by
   soft-watermark size, **never blocks admission**, keeps `rejected` tombstones,
   and `VACUUM`s (fresh connection post-commit) iff `pruned > 0`. Proven by
   `tests/retention.rs` (`retention_caps_evict_oldest_terminal_with_ttl_and_size_and_never_block_admission`).

4. **Launch fence — lifecycle v8, `create_inert_turn -> mint -> IMMEDIATE epoch bump -> single-use`, cancel-wins.**
   Tables `launch_fences` + `activation_capabilities` (v8) already close the
   cancellation/launch race locally:
   `create_inert_turn` (ensures fence, admits inert `Accepted`) →
   `mint_activation_capability` (`next_epoch = current + 1`, fence not bumped on mint) →
   `cancel_turn_with_fence` **or** `activate_with_capability` bumps
   `launch_epoch +1` in the **same `IMMEDIATE` transaction** as the state
   transition and marks competing caps `consumed=1` (`launch_epoch <= next_epoch`);
   capability is single-use; late `activate` after `cancel`/terminal returns
   `AlreadyConsumed`/`CancelledConflict` — **cancel-wins**, monotonic epoch.
   Proven by `tests/launch_fence.rs` (`launch_fence_cancel_wins_over_concurrent_activate`)
   and `store.rs:ensure_launch_fence_tx` / `mint_activation_capability` /
   `cancel_turn_with_fence` / `activate_with_capability`. Remote slices must wire
   the **actual provider launch** through this fence; the SQLite marker alone is
   not the external side-effect fence.

### Acceptance matrix update (remote-ready row deltas)

- **Transport:** Remote row now reads **"WebSocket (tokio-tungstenite); Tailscale is
  an endpoint provider that advertises the broker's 100.x address"** (locked above),
  not "Tailscale Tailnet, ACL-gated" or "Tailscale- or mTLS-bound (to be decided)".
- **At-rest / retention / compaction / backup:** Retention/compaction shape locked
  above; remaining gate narrows to **backup/restore verification + OS at-rest encryption proof per target**.
- **Cancellation/launch:** Local `cancel-wins` fence locked in v8 above; remaining gate narrows to **wiring the fence through the real remote provider launch** and its installed-runtime test.

### Non-change note

No ACP/MCP runtime is wired to the persistent path or to Tailscale by default in
this slice. All selectors remain default-off; the pilot remains local-only.
Production still requires backup/restore verification, per-target OS at-rest proof,
installed-runtime crash/reconnect/cancel canary, live-relay receipt/terminal outbox
validation, and CI reproduction of the five-boundary crash matrix.
