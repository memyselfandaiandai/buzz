# Buzz Kubernetes workspace fencing

Status: **wire-tested integration slice, not a production adapter**.

`buzz-workspace-kubernetes` provides Kubernetes `batch/v1 Job` fencing primitives for disposable workspaces. It uses a real `kube::Client` request path while tests supply deterministic mock HTTP services.

## Implemented boundary

- `create_inert` accepts only a Job template with `spec.suspend=true`, rejects caller selectors/manual selectors, replaces caller-controlled root Job and Pod-template metadata with a minimal trusted Job annotation envelope, clears caller status, binds session/workspace/owner/capability/provider scope/create and delete operations, hashes the exact canonical suspended `JobSpec`, and returns UID, initial generation `1`, and the JobSpec digest only from the validated Kubernetes response.
- Production `KubernetesJobControl` construction accepts one `kube::Config` and namespace, derives an opaque non-secret scope digest from the actual cluster URL/TLS authority plus namespace, and constructs the client internally. The mock-client constructor exists only under `cfg(test)`. Scope drift fails before any Kubernetes request, and response name/namespace drift fails closed.
- `AlreadyExists` recovery adopts only an exact suspended, non-terminating Job with the complete identity envelope, exact sanitized `JobSpec`, durable JobSpec fence, and no activation or claim metadata.
- `activate` reads the current Job and applies a JSON Patch that tests UID, generation, opaque resourceVersion, and suspended state before projecting launch epoch, activation-token digest, task digest, and execution-spec digest. The response must retain the durable JobSpec fence.
- `claim_execution` leaves the Job suspended while recording a deterministic provider-claim digest and one consumer boot ID. The receipt binds the complete activation envelope, including cleanup authority, plus Job name, provider UID, generation, and durable JobSpec digest. Same-consumer retry recomputes the receipt; a different consumer fails closed. Raw activation and claim tokens never enter Kubernetes metadata.
- `observe_owned` distinguishes exact owned suspended, activated, claimed, deleting, and exact object-qualified typed-NotFound absent states; generic typed 404s, replacement, provider-scope/location/spec-fence drift, prior-run status, unexpectedly runnable state, unknown reserved annotations, and partial/noncanonical activation or claim metadata fail closed.
- `request_delete_owned` verifies exact ownership, durable delete authority, location, JobSpec fence, and suspended identity, then sends Kubernetes delete preconditions for UID and observed resourceVersion with `Foreground` propagation. Acceptance is not absence; only a later typed `Absent` observation after foreground deletion is cleanup evidence for the Job and its owned dependents.

## Tests

```bash
cargo test -p buzz-workspace-kubernetes
cargo clippy -p buzz-workspace-kubernetes --all-targets -- -D warnings
cargo fmt --all -- --check
```

The 38 deterministic tests cover request bodies and state responses for create,
typed create-conflict adoption, exact location and canonical JobSpec fencing,
fixed control-scope, owner, durable delete-authority, and reserved-namespace rejection,
digest-only activation, exact activation/claim response-shape validation, one-use claim,
provider-fence-bound claim retry/competition, terminating-state rejection,
suspended/activated/claimed/deleting/absent observation, malformed-control-state
rejection, Config-derived non-secret control scope, caller-selector rejection,
prior-run status and noninitial-generation rejection, advanced mutation resourceVersion,
exact object-qualified absence, foreground cleanup, and cleanup absence.

## Explicit production gaps

This crate does **not** yet:

- implement `buzz_workspace_controller::WorkspaceAdapter`;
- expose any Job start/unsuspend operation before a controller post-redemption release contract exists;
- connect the controller's durable redemption and cancellation transactions to a future provider release;
- supply a production Job template, worker task-material protocol, credentials, or signed runtime authority;
- implement adapter-level reconciliation across every controller lifecycle state;
- contact a live Kubernetes API server or OCI cluster;
- prove that real API-server defaulting preserves the submitted canonical JobSpec comparison; current mock create responses echo the sanitized spec, so live defaulting may fail closed until normalization is validated;
- prove API response-loss recovery, controller crash recovery, Pod startup, cancellation delivery, artifact return, networking, sandboxing, ARM64 images, or cleanup in a live environment.

Production readiness therefore remains **FAIL**. The next slice must bridge this
asynchronous control surface to the provider-neutral controller while keeping the
Job suspended, then define a post-redemption release contract that cannot race
cancellation or expiry before exercising the complete bridge against a disposable
cluster.
