# OCI agent desktop pre-provision package

Status: **local enforcement prototype; OCI provisioning is prohibited**.

Buzz is the provider-agnostic orchestration platform. This package explores a
disposable graphical execution plane without moving identity, memory,
credentials, conversations, approvals, or artifact acceptance away from
FINAL-FORM. OCI, Kubernetes, desktop shells, model routers, and providers are
replaceable integrations; none defines the protocol.

## Current evidence boundary

The narrow `buzz-backend-kubernetes` `manage_namespace` change is independently
well tested and remains separate from this workspace protocol. Protocol and
storage smokes are contract simulations. They are not broker, curator, worker,
or provider integration tests.

The first provider-neutral controller slice now verifies signed authority before
rendering, atomically admits one-use JTI/workspace/concurrency state in an
in-memory fake ledger after side-effect-free validation and before any future API
call, maps signed limits into a local Job/PVC/ResourceQuota manifest, splits agent
and browser containers, issues signed role-specific derived runtime envelopes,
validates a closed-world resource graph, requires signed FINAL-FORM terminal
receipts for terminal cleanup, and verifies a fake signed
result/transfer/acceptance chain. It does not call Kubernetes or any external
service.

## Validation seed, not fleet design

The Terraform source describes one Ubuntu ARM64 `VM.Standard.A1.Flex` host with
2 OCPUs, 12 GB RAM, 100 GB boot volume, and single-node k3s. It currently sets
`assign_public_ip = true` for bootstrap, which conflicts with the intended
no-public-IP target and must be resolved before any plan or apply.

The two-session statement is not yet enforced or capacity-tested. A useful
6-to-20 desktop deployment needs a separate multi-host placement, failure,
quota, isolation, and cost plan.

## Package map

- `controller/`: provider-neutral local authority verification, fake JTI ledger,
  closed-world manifest creation, worker evidence wrapper, cleanup planning, and
  fake signed acceptance-chain tests.
- `protocol/`: execution capability/result schemas and a one-process contract
  simulation.
- `storage/`: storage schemas, policy seed, and a one-process contract
  simulation; no broker or adapter exists.
- `kubernetes/`: static fixture renderer, closed-world validator, adversarial
  fixtures, deferred live scripts, and cleanup helper.
- `runtime/`: legacy combined ARM64 desktop image definition. It is not the split
  controller runtime and still contains `--no-sandbox`.
- `build/`: ARM64 provider and image-index checks.
- `terraform/`: source only. Do not run tenant plan/apply without approval.

## Safe local validation

```powershell
node --test .\deploy\oci-agent-desktop\controller\controller.test.mjs
node --test .\deploy\oci-agent-desktop\kubernetes\closed-world-validator.test.mjs
node --test .\deploy\oci-agent-desktop\kubernetes\renderer-lifecycle.test.mjs
node .\deploy\oci-agent-desktop\protocol\protocol-smoke.mjs
node .\deploy\oci-agent-desktop\storage\storage-broker-smoke.mjs
node .\deploy\oci-agent-desktop\kubernetes\render-session.mjs --out "$env:TEMP\buzz-session.json"
node .\deploy\oci-agent-desktop\kubernetes\validate-session.mjs "$env:TEMP\buzz-session.json"
cargo test --locked -p buzz-backend-kubernetes
```

The two smoke commands are simulations. The Node test suites are local
controller/validator enforcement evidence. None is production runtime evidence.

## Closed gates

Do not run or claim:

- Drive, Composio, or OCI connectivity;
- production broker, curator, or durable-ledger behavior;
- Kubernetes workload creation or cleanup;
- large ARM64 desktop/backend builds;
- Chromium sandbox operation in the split runtime;
- disposable-cluster tests;
- Terraform tenant plan, apply, or destroy;
- two-session capacity or 6-to-20 fleet behavior.

These require separate implementation, approval, and real integration evidence.
