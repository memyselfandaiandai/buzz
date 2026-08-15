# Buzz workspace controller

Status: **durable provider-neutral core plus fake adapter**. A separate
`buzz-workspace-kubernetes` crate now exercises Kubernetes Job CAS wire
operations, but it is not yet connected as this controller's production
`WorkspaceAdapter`. Production readiness is **not established**.

The canonical architecture decision is
[`docs/adr/0001-buzz-workspace-controller-boundary.md`](../../docs/adr/0001-buzz-workspace-controller-boundary.md).
This crate is Buzz-owned and has no dependency on EntAIngled Desktop, Fabric,
Matter, or Wave. It does not contact Kubernetes, OCI, Drive, Composio, a
credential service, or any network endpoint.

## Durable ledger

`Ledger` opens a SQLite database with WAL, foreign keys, full synchronous mode,
a busy timeout, and explicit `BEGIN IMMEDIATE` transactions. Schema version 5
contains:

- `controller_schema`: singleton migration version;
- `sessions`: unique JTI, capability digest, session and workspace ownership,
  agent/tenant/issuer scope, durable provider scope plus provider object
  name/namespace/UID/generation/immutable-spec digest, signed and deployment
  concurrency bounds, durable
  reservation bit, cancellation, lifecycle, terminal decision plus receipt/result
  digests and canonical transfer-digest set, artifact totals, cleanup claim,
  monotonic launch epoch, authority-schema generation, version, and timestamps;
- `launch_authorizations`: one exact activation binding per session/epoch,
  including token, workspace, provider-generated UID/generation, task-input and
  execution-spec digests, provider execution-claim token, consumer boot ID,
  material receipt, expiry, and issued/redeemed/revoked status;
- `artifacts`: globally unique transfer receipt digest plus per-session canonical
  logical path, SHA-256, and byte count;
- `transitions`: append-only lifecycle event journal.

Opening a pre-v5 database adds the launch-fencing columns and tables, but never
promotes defaulted values into execution authority. Every non-final legacy row
is atomically quarantined in `recovery_error`, cancellation is requested,
unredeemed launch authority is revoked, and uncertain capacity remains reserved.
Because unsupported legacy rows cannot emit a trustworthy provider identity, this
slice intentionally provides no automatic ownership-bound cleanup for them;
operator-led provider and ledger remediation is required. Schema v5 durably
binds each session to its adapter-provided provider scope; historical v4 and
older rows retain their old authority version and cannot emit provider identity. New rows are stamped
authority version 5. Future row-authority versions fail before admission replay,
lifecycle transitions, artifact/terminal accounting, cleanup, provider binding,
authorization issuance/redemption, or task-material claim mutation. The migration
is idempotent and regression tested directly from schema-v1 and schema-v4 rows.

Normal preparation, JTI/workspace consumption, and reservation admission commit
in one immediate transaction. A standalone `prepared` state is persisted only by
the explicit crash failpoint/recovery path. Capacity denial durably transitions
to `rejected`, so it cannot later execute. Capacity is counted at one scope:
`agent`, `tenant`, or capability `issuer`. The v2 local capability fixture signs
both the scope kind and its subject; agent and issuer subjects are bound back to
their signed identity claims. Admission uses the minimum effective bound across
both the incoming capability and every active reservation at that scope, where
each bound is `min(signed_max_concurrency, deployment_max_concurrency)`.
Values such as 2 for
a pilot are deployment policy, not protocol constants; tests exercise 6 and 20.
A session Namespace contains one Job, so the Namespace Job quota is always one.
The reservation remains conservative through terminal, cancelled, expired,
cleaning, and recovery-error states and is released only by owned `cleaned`.
Cancellation, expiry, and terminal intent are preserved when recovery diagnostics
are recorded and are reconciled toward cleanup, never back to execution.
Session rows are never deleted. The unique `workspace_id` is therefore a
permanent tombstone: even after `cleaned`, a different session cannot reuse the
same logical workspace identity.

## Lifecycle

Main path:

```text
prepared -> admitted -> creating -> active -> terminal -> cleaning -> cleaned
```

Exceptional states:

```text
prepared -> rejected
prepared|admitted|creating|active -> cancelled
prepared|admitted|creating|active -> expired
admitted|creating|active|terminal|cancelled|expired|cleaning -> recovery-error
recovery-error -> creating|active|terminal|cancelled|expired|cleaning
cancelled|expired -> cleaning -> cleaned
```

Transitions are transactional and idempotent when the same target is repeated.
Invalid edges fail closed. Cleanup verifies exact session owner and workspace and
uses a durable cleanup claim. Terminal records accept or reject decisions and a
unique, validated receipt digest; cryptographic receipt/capability verification
must happen in the controller authority layer before these durable methods are
called.

## Provider launch fence

The local fence is a four-step protocol:

1. `provision_inert` records `creating` and creates an inert provider workload.
   Inert state has no task material, delegated credentials, or command launch.
2. `authorize_launch` runs in a SQLite `BEGIN IMMEDIATE` transaction, the same
   serialization mechanism used by cancellation. If cancellation committed
   first, authorization fails. If authorization commits first, it increments the
   session launch epoch and persists one capability bound to session, workspace,
   provider name/namespace/UID/generation/immutable-spec digest, task-input digest,
   expiry, and epoch. Create/delete operation keys and activation tokens use
   domain-separated length-prefixed SHA-256 authority tuples. The maximum
   local activation TTL is 300 seconds.
3. `activate_launch` projects that exact authorization to the provider using
   ownership and generation preconditions. Fake provider `activated` means only
   that the authorization was projected; it still cannot receive task material
   or execute substantive work.
4. `redeem_launch` is the **execution/task-material linearization point**. The
   provider first atomically claims the exact activation for one consumer boot
   and execution-spec digest. One immediate ledger transaction then rechecks
   cancellation, expiry, epoch, token, every binding, the provider claim, and
   single-use status; marks the capability redeemed; and transitions
   `creating -> active`. Only the returned `TaskMaterialGrant`, carrying both
   the provider claim and ledger material receipt, can enter the worker runner.

Cancellation revokes every unredeemed authorization in its authority
transaction. Therefore cancellation after authorization or concurrent with
provider activation may leave an `activated` fake workload, but redemption and
task execution fail closed and reconciliation deletes it. Cancellation after
redemption is continuously polled by the worker. A new terminal result is
rejected after authoritative cancellation.

Expired unredeemed capabilities can be replaced only by a higher epoch. Stale,
replayed, tampered, replaced-UID/generation, second-consumer, and
duplicate-reconciler paths fail closed or converge idempotently. Provider UID
and generation are observed from provider creation and bound into the ledger;
they are never synthesized from controller inputs. If provider creation or
activation succeeds but its response is lost, recovery observes the exact
persisted binding and does not duplicate the provider mutation.

## Fake provider and recovery

`FakeKubernetes` is a separate SQLite database, intentionally outside the ledger
transaction. It models `absent -> inert -> activated -> deleted` keyed by exact
session, workspace, owner, capability digest, provider scope, operation keys,
provider-generated UID/generation, launch epoch, task digest, execution-spec
digest, and one-use provider execution claim. Cleanup confirms exact absence before
`cleaned` releases capacity. `Controller` records intent before provider
mutation and reconciles after restart. An ABA test replaces UID/generation and
proves cleanup fails closed while the reservation remains charged.

This is a deterministic **local model**, not production cryptographic authority.
The local token and provider records are stored in test SQLite databases; there
is no signed activation envelope, admission webhook, credential broker, or real
worker task-material delivery path. `buzz-workspace-kubernetes` now has mocked
wire tests for suspended Job creation, UID/resourceVersion JSON Patch CAS,
digest-only activation and one-use claim, exact owned observation, and
preconditioned delete requests. It intentionally exposes no Job start operation
until a post-redemption controller release contract exists. It does not yet
implement this crate's synchronous adapter boundary or prove live-cluster
behavior. Production P1 remains open until this invariant is proven end-to-end.

Deterministic tests inject failpoint errors and reopen fresh database handles
after:

- prepared;
- admitted;
- creating;
- fake provider create;
- provider activation response loss and restart recovery;
- one-use provider and ledger redemption;
- terminal receipt;
- cleaning;
- fake provider delete;
- cleaned.

These tests model persisted boundary uncertainty but do **not** abruptly kill an
OS process with open SQLite handles. After reopening both databases,
reconciliation proves one workload mutation,
one reservation, persistent JTI replay rejection, owned deletion only, and one
final reservation release.

## Local worker cancellation

`run_cancellable_process` requires the exact redeemed `TaskMaterialGrant`. Its
immediate writer transaction validates and durably consumes the one-use execution
claim **before** invoking physical `Command::spawn()`. Real-time expiry is checked
before claim consumption and again after the callback. A second short SQLite
immediate transaction is held as a cancellation-serialization lock through command
construction, the final real-time expiry sample, and `Command::spawn()`: cancellation
either commits first and prevents spawn, or commits after physical start and is
handled by continuous cancellation polling. The start transaction contains no writes
and is dropped after spawn, so no fallible database commit follows process creation.
An OS spawn failure leaves the durable claim consumed and non-retryable. An abrupt
controller crash after a successful spawn may still leave an executing child without
containment-backed recovery; this is explicitly unapproved rather than described as
fail-closed. The worker polls cancellation continuously after successful
spawn. Windows uses a new process group plus `taskkill /T /F`; Unix creates a new
session and terminates the process group, escalating from `SIGTERM` to `SIGKILL`.
Loss of the authoritative cancellation channel is fail-closed: the process tree
is terminated before the ledger error is returned. Tests cover real-time expiry
before claim, cancellation committing after the durable claim but before spawn,
and a spawn failure whose retry is rejected as `ExecutionReplay`.

The Windows path still does not use a Job Object and Unix does not prove parent-death
cleanup. Neither platform proves assignment-before-execution containment, descendant
non-escape, or abrupt-controller-crash cleanup; those remain production gates distinct
from durable claim-before-process ordering.

The `buzz-workspace-controller` binary currently exposes only local fixture
commands for multi-process and process-tree tests. It is not a production
network service.

## Root-of-trust rotation

Production images must bake a stable offline root public key. Runtime verifier
keys are distributed only in a signed keyset containing key IDs, role, validity
window, generation, and revocation data. Workers authenticate that keyset with
the baked root before accepting controller-derived runtime evidence. A mutable
ConfigMap may transport the signed keyset but is never itself trusted.

## Tests

```bash
cargo test -p buzz-workspace-controller --test ledger
cargo test -p buzz-workspace-controller --test launch_fencing
cargo test -p buzz-workspace-controller --test recovery
cargo test -p buzz-workspace-controller --test process_concurrency
cargo test -p buzz-workspace-controller --test worker_cancellation
cargo test -p buzz-workspace-controller
cargo clippy -p buzz-workspace-controller --all-targets -- -D warnings
cargo fmt -p buzz-workspace-controller -- --check
```

Controller provider behavior and worker commands remain fake/local. No result here is live
Kubernetes, OCI, image, sandbox, cgroup, network-policy, PVC, credential, or
external acceptance evidence.
