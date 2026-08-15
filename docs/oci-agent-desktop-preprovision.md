# OCI disposable agent desktops: pre-provision design

Status: **design plus local enforcement prototype; not approval to provision**.

## Authority

FINAL-FORM owns agent identity, memory, credentials, conversations, approvals,
task authority, and artifact acceptance. A disposable workspace may execute a
bounded task and return claims; it cannot expand scope or accept its own result.
Buzz is provider-agnostic. OCI, Kubernetes, desktop shells, model routers, and
agent runtimes are integrations rather than protocol authorities.

## Intended flow

1. FINAL-FORM signs a single-use execution capability over exact identity,
   project/workspace/task/input bindings, time window, operation, cancellation
   token digest, and resource bounds.
2. A separate trusted disposable-workspace controller verifies the signature and
   bindings, checks cancellation, and atomically consumes the JTI before any
   Kubernetes request.
3. The controller maps verified CPU, memory, wall-time, storage, and concurrency
   limits into an exact Job/PVC/ResourceQuota graph and validates the complete
   graph against a closed-world policy.
4. The authority-bearing agent and Chromium run in separate containers with
   distinct UIDs and no shared process namespace. Chromium receives no raw
   capability or signature. Only derived bounded configuration or one-time
   broker handles may cross that boundary.
5. Worker-side wrappers verify their observable launch evidence and fail closed
   on mismatch. They do not claim to impose Kubernetes CPU or memory limits from
   inside an already-running container.
6. Storage operations pass through a future FINAL-FORM broker. A broker transfer
   receipt proves transfer; only a separate FINAL-FORM acceptance receipt can
   promote an artifact.
7. Cleanup is bound to namespace plus session ID and supports verified terminal
   result or expiration modes with idempotent ownership checks.

## What exists in this checkout

- A local provider-neutral controller module that verifies capabilities against
  trusted ephemeral test keys, creates signed role-specific derived runtime
  envelopes, and atomically admits JTI/ownership/concurrency state in an
  in-memory fake ledger after closed-world rendering and before any future API
  call.
- A closed-world local manifest and adversarial validator.
- A defense-in-depth local worker wrapper test against a pinned runtime public
  key and observable per-container CPU/memory evidence.
- Signed FINAL-FORM terminal cleanup and fake signed worker-result,
  broker-transfer, and acceptance-chain verification.
- A separate, well-tested `buzz-backend-kubernetes` namespace-management change
  for ordinary remote-agent Pods.

The existing Kubernetes backend does **not** create the controller's Job/PVC
workload and must not be described as integrated with it.

## What does not exist

- Kubernetes API integration for the disposable-workspace controller.
- Durable controller/broker ledger or curator service.
- Split agent/browser images or a real Chromium sandbox startup test.
- Private broker route or real storage adapter.
- Drive, Composio, or OCI connection.
- Multi-host placement/capacity behavior.

The protocol and storage smoke scripts are contract simulations in one process.
They do not validate worker authority, broker enforcement, curator behavior,
browser isolation, or provider integration.

## Deferred infrastructure facts

The Terraform seed currently describes one A1 host and assigns a public IP for
bootstrap, contrary to the intended no-public-IP target. That contradiction,
ARM64 images, capacity, availability domains, IAM, quotas, budgets, private
routing, and two-session pressure must be resolved before tenant planning. A
6-to-20 desktop deployment requires a separately reviewed multi-host capacity
and cost design.

Implementation source: [`deploy/oci-agent-desktop/`](../deploy/oci-agent-desktop/README.md).
