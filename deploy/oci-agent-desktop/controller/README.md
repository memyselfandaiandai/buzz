# Provider-neutral disposable-workspace controller

Status: **quarantined legacy local contract fixture only**. This module does not
call Kubernetes, Drive, Composio, OCI, or any external service and is not loaded
by the canonical controller crate.

The controller is separate from `buzz-backend-kubernetes`. That existing backend
continues to manage ordinary remote-agent Pods; it is not repurposed into the
disposable-workspace protocol.

## Enforced locally

`controller.mjs` verifies an Ed25519 signed envelope before rendering any
resource plan. Verification covers the trusted key role, issuer, audience,
session/task/agent/project/workspace bindings, signed concurrency scope kind and
subject, exact input hash, time window,
maximum TTL, operation, numeric limits, cancellation state, and one-use JTI.
`InMemoryControllerLedger` is a fake server-side ledger used only by the local
slice. After side-effect-free rendering and closed-world validation, one
synchronous admission operation checks cancellation/replay/concurrency, consumes
the JTI, reserves concurrency, and records session ownership. This still occurs
before any future Kubernetes create call.

A valid capability maps its bounds into a closed-world Kubernetes manifest:

- CPU and memory are split deterministically across distinct agent and browser
  containers, while `ResourceQuota` caps their exact aggregate;
- wall time becomes the Job's `activeDeadlineSeconds`;
- storage bytes become the PVC request and storage quota;
- this fixture enforces concurrency in memory at the signed agent, tenant, or
  issuer scope; the separate canonical crate durably enforces the lower of the
  signed maximum and deployment policy; each session Namespace contains one Job
  and its `ResourceQuota` therefore allows exactly one Job;
- the browser uses a distinct UID and process boundary, receives no raw
  capability, task payload, or signature, and has no `--no-sandbox` flag;
- agent and browser receive separate controller-signed derived-runtime envelopes
  and verify them against a runtime public key expected to be baked into each
  future image;
- no Secret or service-account token is mounted;
- the local fake slice is default-deny and has no egress policy.

`manifest-policy.mjs` applies exact inventory and security checks, while the
controller additionally binds validation to the SHA-256 of the expected
manifest. Unknown, duplicate, appended, or modified objects fail closed.

`verify-derived-runtime.mjs` is a defense-in-depth wrapper. It authenticates the
role-specific derived envelope, compares the container's observable CPU/memory
launch evidence, enforces the signed expiry/wall timer, and spawns the child only
on an exact match. It does not and cannot impose Kubernetes CPU or memory limits
from inside an already-running container; the trusted controller is responsible
for those limits. Terminal-result cleanup separately requires a signed
FINAL-FORM acceptance or rejection receipt bound to the session.

The result-chain test uses only fake signed envelopes. It verifies distinct
worker-result, broker-transfer, and FINAL-FORM acceptance signatures and exact
cross-record bindings. It performs no storage transfer.

## Local tests

```powershell
node --test .\deploy\oci-agent-desktop\controller\controller.test.mjs
node --test .\deploy\oci-agent-desktop\kubernetes\closed-world-validator.test.mjs
node --test .\deploy\oci-agent-desktop\kubernetes\renderer-lifecycle.test.mjs
```

## Not yet validated

- No Kubernetes API create/delete call is implemented in this controller.
- The in-memory ledger is synchronously atomic in one process, but is not durable,
  multi-process safe, or transactionally coupled to a Kubernetes API adapter.
  Its `delete-approved` result is only a contract simulation: `markCleaned` does
  not prove provider deletion and must never be treated as production cleanup.
- The separate agent and browser images have not been built.
- Chromium sandbox startup has not been exercised in the intended container
  security context.
- Cancellation is checked before creation; continuous cancellation delivery and
  process-group termination are not integrated.
- No broker, curator, Drive adapter, Composio adapter, or private transfer plane
  exists.
- No disposable-cluster, ARM64 runtime, or OCI test has run for this slice.
