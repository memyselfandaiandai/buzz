# ADR-0001: Buzz provider-neutral workspace controller

- Status: Accepted
- Date: 2026-08-14
- Decision owner: Buzz architecture

## Context

Buzz needs durable authority and lifecycle control for disposable workspaces without making any execution provider authoritative. The existing `buzz-backend-kubernetes` crate performs Kubernetes provider operations. The untracked `deploy/oci-agent-desktop` package is a local enforcement and contract-test fixture, not a production controller or deployment.

## Decision

The canonical controller package is `crates/buzz-workspace-controller`. It is a Buzz-owned, provider-neutral service/library. It must not depend on EntAIngled Desktop, Fabric, Matter, or Wave. OCI and Kubernetes are subordinate disposable execution planes reached only through adapters.

Ownership is divided as follows:

- **Buzz / FINAL-FORM authority:** issues signed task capabilities and independently signs terminal artifact acceptance or rejection. A workspace cannot expand its authority or accept its own output.
- **Workspace controller:** authenticates authority, applies policy, owns durable admission/JTI consumption, scoped reservations, lifecycle transitions, cancellation, artifact accounting, receipt persistence, reconciliation, and cleanup orchestration.
- **`buzz-backend-kubernetes`:** remains a narrow Kubernetes provider. It may implement a future controller adapter but owns no capability, acceptance, or reservation decisions.
- **Credential broker:** exchanges bounded controller grants for short-lived provider credentials. It is not authoritative for admission or artifact acceptance.
- **Workers:** execute only derived, role-minimized authority; report signed results and observe cancellation. They do not receive controller/provider root credentials.

The controller ledger is authoritative for admission, JTI use, ownership, reservation, cancellation intent, lifecycle state, terminal acceptance/rejection, artifact accounting, and cleanup completion. Provider adapters are authoritative only for observed provider-resource existence and identity. FINAL-FORM's signed receipt is authoritative for artifact acceptance. Reconciliation combines those sources without letting provider observations mint authority.

## Lifecycle and recovery

The normal lifecycle is:

`prepared -> admitted -> creating -> active -> terminal -> cleaning -> cleaned`

Additional durable states are `rejected`, `cancelled`, `expired`, and `recovery_error`. Every transition is idempotent and recorded transactionally. Normal JTI/workspace preparation and reservation admission commit in one immediate transaction; a standalone `prepared` intent is persisted only for explicit crash recovery. Capacity denial becomes durable `rejected` and is never later reconciled into execution. Before a provider create, the ledger must durably reach `creating`; after uncertain outcomes, restart reconciliation queries or idempotently creates by exact operation and ownership identity. Before delete, it durably reaches `cleaning`; deletion is ownership-bound and idempotent. A crash must not release a reservation while a workload may still exist. Cancellation, expiry, and terminal intent cannot be overwritten by recovery diagnostics, and cancellation cannot transition to terminal acceptance. Replayed JTI values never create another workspace. Session rows are retained permanently, so the unique logical workspace ID is a non-reusable tombstone even after cleanup.

Schema-v4 authority is explicit. Rows created by an older schema are not made executable by migration defaults: non-final legacy rows are atomically quarantined in `recovery_error`, cancellation is requested, outstanding launch authority is revoked, and uncertain reservations remain charged until owned cleanup. New rows carry authority version 4.

Terminal state requires a persisted, session-bound FINAL-FORM acceptance or rejection receipt. Artifact paths, hashes, and aggregate bytes are transactionally accounted against the signed limit before terminal acceptance is recorded.

## Provider launch fencing

Provider creation produces only an inert workload. Inert means it cannot receive
task input or delegated credentials and cannot execute task commands. Creation is
not activation authority.

Cancellation and launch authorization both serialize through SQLite immediate
transactions. Provider creation returns its own opaque UID/generation, which is
then bound into the ledger; the controller does not synthesize provider identity.
A successful authorization increments a monotonic session launch epoch and
persists a maximum-300-second, single-use capability bound to session, workspace,
provider UID/generation, task-input digest, canonical execution-spec digest,
expiry, and epoch. Provider projection requires exact ownership and generation
preconditions.

Provider `activated` is not sufficient to execute. The provider must first
atomically claim that exact activation for one consumer boot and execution-spec
digest. The execution/task-material linearization point is then ledger
capability redemption: one immediate transaction rechecks cancellation and every
binding, persists the provider claim plus a material receipt, consumes the
capability, and advances `creating -> active`. Only its exact
`TaskMaterialGrant` can enter the local worker runner. The worker's claim
transaction remains open through physical process creation, so cancellation or
expiry cannot commit between durable execution claim and `Command::spawn()`.
Cancellation committed first prevents execution; cancellation committed later
remains continuously enforced. Terminal results first presented after
authoritative cancellation are rejected.

Unknown creation and activation outcomes are recovered by observing exact
provider identity and authorization bindings. Exact duplicate projection and a
same-consumer retry are idempotent; stale epoch, second-consumer replay, workload
replacement, or binding mismatch fails closed. These guarantees are locally
modeled with separate SQLite ledger/provider databases only.

## Concurrency scope

Each session namespace normally permits exactly one Job. Signed `max_concurrency` is enforced by the durable controller ledger at the capability's explicit scope: `agent`, `tenant`, or `issuer`. Effective capacity is the lower of the signed limit and deployment policy for that same scope. Reservations remain charged through uncertain, terminal, cancelled, expired, and cleaning states until authoritative cleanup reaches `cleaned`. No two-workspace pilot value is compiled into the protocol; policy supports the planned 6–20 range and other positive limits.

## Trust rotation

A mutable ConfigMap is never a root of trust. Production images will contain a stable root public key. That root authenticates a versioned, signed runtime verification keyset with key IDs, roles, validity windows, revocations, and rollback protection. Role-specific derived runtime envelopes are accepted only under a currently valid key from that authenticated keyset. Building images or selecting the operational root/keyset is outside the current local-adapter slice.

## Legacy fixture quarantine

`deploy/oci-agent-desktop/kubernetes/session.template.json` and its monolithic runtime fixture remain explicit legacy contract tests. The new controller service must not load, render, deploy, or treat them as production-equivalent. New provider adapters consume controller-owned typed plans instead.

## Consequences and deferred gates

This slice uses SQLite WAL and fake/local adapters only. It performs no OCI, live Kubernetes, Drive, Composio, credential, deployment, or Terraform mutation. Provider launch fencing is **locally modeled and tested**, not production-proven. Production readiness remains not established until the invariant is exercised through a real Kubernetes UID/resourceVersion adapter and worker startup/task-material gate, Windows containment uses a Job Object or equivalent assignment-before-execution mechanism, and real adapter recovery, key rotation, split ARM64 images, active Chromium sandbox proof, private-network/bootstrap design, live cluster evidence, and required static/security tools are exercised.
