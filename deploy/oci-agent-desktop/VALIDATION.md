# Validation record

Date: 2026-08-15. Host: FINAL-FORM Windows. External mutation: none.

Authoritative overall verdict: **FAIL for runtime enforcement and production
readiness**. Narrow provider tests and contract simulations retain only their
stated scope.

## Independently passing local gates

| Gate | Scope and evidence |
| --- | --- |
| Kubernetes provider regression | `cargo test -p buzz-backend-kubernetes`: 156 unit tests and 4 wire-fixture tests passed. Strict package Clippy with warnings denied also passed. |
| Pre-created namespace behavior | `manage_namespace: false` makes no namespace API request. This does not integrate the provider with the disposable-workspace graph. |
| Provider formatting/lints | Rust formatting and Clippy with warnings denied passed. |
| Durable controller core | `cargo test --locked -p buzz-workspace-controller`: 34 tests passed (1 unit and 33 integration). SQLite WAL/`BEGIN IMMEDIATE` atomic admission, schema-v1-to-v4 quarantine, durable rejection/replay blocking, permanent workspace-ID tombstones, mixed-limit and 6/20 scoped capacity, lifecycle, exact artifact/terminal bindings, launch fencing, worker cancellation, and cleanup reservation release are exercised. Strict package Clippy, `cargo fmt --all -- --check`, and the repository no-`unsafe` source rule passed. All adapters remain fake/local. |
| Provider launch fence | 13 deterministic launch-fencing tests model `absent -> inert -> activated -> deleted`, provider-generated UID/generation identity persisted by the ledger, ledger-serialized cancellation/authorization, maximum-300-second single-use capabilities, monotonic epoch rotation, exact session/workspace/UID/generation/task-digest/execution-spec/expiry bindings, a provider-side exactly-once execution claim, worker grant validation, stale/replay/replacement rejection, duplicate reconcilers, commit boundaries, and a committed activation whose response is lost. This is locally modeled and tested; no live Kubernetes or production worker path was exercised. |
| Multi-process admission | 32 independent processes admitted exactly 20 at one scope; two agent scopes admitted exactly 6 each; 16 processes racing one JTI admitted exactly once. The filesystem barrier does not prove explicit lock contention. |
| Fake recovery | Seven recovery tests cover provision/cleanup failpoint reopen, cancellation, provider ABA replacement, permanent cleaned-workspace tombstones, and exact ownership without duplicate fake workloads or lost reservations. These are failpoint errors with reopened handles, not abrupt OS process kills with open SQLite handles. |
| Local cancellation tracer | Six worker tests cover exact-spec redemption, pre-cancel non-spawn, one grant/one spawn, cross-process cancellation, cancellation-channel loss, and parent/descendant heartbeat termination. A deterministic unit test proves cancellation cannot commit between the durable execution claim and physical `Command::spawn()` because the SQLite writer transaction is held across both. Windows still uses `taskkill /T`, not race-free Job Object assignment. |
| Controller enforcement slice | 14 local controller tests reject malformed, tampered, wrong-issuer/audience/bound, expired, cancelled, replayed, over-concurrency, bad-runtime, bad-manifest, bad-cleanup, and bad-receipt inputs; valid limits map into a local manifest. Admission is atomic only inside one in-memory fake ledger process. Together with 8 closed-world and 5 renderer tests, the combined Node run passed 27/27. |
| Browser authority separation contract | Controller manifest uses separate agent/browser containers and UIDs, no shared PID namespace, no raw capability/Secret, no `--no-sandbox` argument, and separate controller-signed derived envelopes. Images were not built or run. |
| Worker evidence wrapper | Local process test authenticates a signed role envelope, checks observable per-container CPU/memory evidence, enforces expiry/wall timer, launches only on match, and fails closed on mismatch. It cannot impose Kubernetes limits from inside a running container. |
| Closed-world static validation | Eight adversarial validator tests and five renderer tests reject appended/mutated workloads and NetworkPolicies, duplicates, exact container-inventory escapes, root/unmasked-proc/capability additions, projected service-account tokens, unapproved volume sources, renderer injection, arbitrary namespace, invalid session, and excessive TTL. No admission controller was exercised. |
| Cleanup contract | Terminal cleanup requires a signed FINAL-FORM acceptance/rejection bound to the session; expiration and idempotent ownership behavior pass locally. No Kubernetes delete was called. |
| Fake acceptance chain | Distinct worker, broker, and FINAL-FORM signatures and cross-record bindings verify in memory. No broker or storage transfer exists. |
| Protocol smoke | One-process contract simulation passed. Not runtime enforcement. |
| Storage smoke | One-process contract simulation passed. Not broker, ledger, adapter, or curator enforcement. |
| Sprig index | Exact immutable index contains a Linux ARM64 child. |
| Dockerfile definition | The existing monolithic image BuildKit definition check passed for Linux ARM64; no image was built. A separate browser image does not exist yet. |
| Terraform source | A prior Terraform 1.12 formatting and ephemeral provider init/validate pass is retained as historical evidence. Terraform is unavailable on the 2026-08-15 verification host, so it was not rerun; no tenant plan/apply ran. |
| PowerShell syntax | All six scripts parse; live scripts were not executed. |
| Workflow/static security | Workflow YAML and 9 project JSON files parse. `actionlint`, `gitleaks`, `shellcheck`, `hadolint`, `trivy`, and `syft` were unavailable; a scoped high-confidence private-key/token pattern scan passed without printing file content. |
| Patch whitespace | `git diff --check` passed. |

## Repository-wide gate status

- `cargo test --workspace` is **FAIL** outside this controller slice: 736 tests
  passed before/alongside 32 existing `buzz-acp` failures reporting
  `AgentExited` and steering expectation mismatches on this Windows host. The
  controller package itself remained 34/34 green.
- The required `just ci` umbrella gate is **BLOCKED** because `just` is not
  installed and this checkout's Hermit bootstrap cannot find
  `/pkg/hermit@stable/hermit`. `pnpm` and Flutter are also unavailable.
- `cargo audit` and `cargo deny` are **BLOCKED** because neither Cargo
  subcommand is installed.
- Unix-only process-group code could not be cross-compiled because only the
  `x86_64-pc-windows-msvc` Rust target is installed. The source uses stable safe
  APIs and contains no `unsafe`, but Linux CI evidence is still required.

## RED evidence retained for this slice

Before implementation:

- static validator accepted an appended privileged Job and an additional
  unrestricted NetworkPolicy;
- renderer accepted JSON injection, arbitrary namespace, invalid session, and a
  one-year expiration;
- controller module and worker verifier did not exist.

The added tests failed on those boundaries before the corresponding
implementation was added.

## Runtime and external gates still closed

1. Production authority verifier integration in the canonical Rust crate,
   including a formal signed scope/schema/canonicalization profile.
2. Actual Kubernetes API integration with durable operation keys, observed UID/
   resourceVersion compare-and-swap fencing, authoritative absence, abrupt
   process-kill tests, and an end-to-end inert startup/task-material gate. Launch
   fencing is locally modeled and tested only; production P1 remains open until
   the invariant is proven against the real adapter and worker startup path.
3. Split agent/browser ARM64 images and Chromium sandbox startup test.
4. Race-free Windows Job Object containment and live worker cancellation delivery.
5. Real broker, curator, streaming limits, abrupt crash recovery, or adapter behavior.
6. Drive or Composio connection and mutation tests.
7. `build/build-aarch64-backend.ps1` and `runtime/build-arm64.ps1`.
8. `kubernetes/validate-provider-live-disposable.ps1` and
   `kubernetes/validate-live-disposable.ps1`.
9. OCI tenant facts, capacity, service limits, image IDs, IAM, budgets, or any
   Terraform plan/apply/destroy.
10. Live simultaneous pressure and the separate 6-to-20 multi-host plan; local
    ledger tests do not establish deployment capacity.

None of these gaps authorizes provisioning or an external connection.
