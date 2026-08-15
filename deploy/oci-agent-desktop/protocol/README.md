# FINAL-FORM to disposable-worker protocol

Status: **contract plus local simulation; not production runtime enforcement**.

This is an execution protocol, not an identity delegation protocol. The
requirements below describe the intended authority boundary. The legacy desktop
runtime does not yet enforce them end to end.

FINAL-FORM creates a narrowly scoped task envelope, hashes the exact task
input, signs a short-lived capability, and sends it to one named session. A
production trusted controller must verify the signature, audience, session,
task hash, allowed operation, limits, cancellation state, expiration, and
one-use JTI before creating resources. The local enforcement slice under
[`../controller/`](../controller/README.md) exercises those checks with an
in-memory fake ledger and performs no Kubernetes operation.

The worker returns a result manifest containing status, timing, resource use,
artifact paths and SHA-256 hashes. Returning a manifest does not accept or
commit anything. FINAL-FORM independently verifies the hashes and then records
an explicit `accepted` or `rejected` decision. Only an accepted result may be
promoted into authoritative project state.

The worker never receives long-lived provider credentials, Mem0/database
credentials, unrestricted Hermes credentials, tenancy-wide OCI credentials,
or write authority over FINAL-FORM state. Any third-party credential needed by
a task must be minted or brokered as a short-lived capability scoped to that
single task and destination.

Workspace and checkpoint storage uses a separate signed capability and receipt
chain under [`../storage/`](../storage/README.md). The worker-facing tools stay
provider-neutral; a Composio or direct Drive adapter remains behind the
FINAL-FORM broker.

## Transport and cancellation

The transport may be an authenticated Tailscale path, but transport identity
does not replace the signed capability. FINAL-FORM sends cancellation by the
task/session ID plus a random cancellation token. Only the SHA-256 digest of
that token appears in the signed claims. The worker must terminate the process
group, finalize a cancelled manifest, and make the workspace eligible for
session cleanup.

## Canonical signing

The simulation signs UTF-8 deterministic JSON with recursively sorted object
keys, ordered arrays, and no insignificant whitespace. Production must adopt a
versioned, cross-language canonicalization profile and test vectors before keys
are used across runtimes. Production keys remain on FINAL-FORM.
`protocol-smoke.mjs` generates an ephemeral Ed25519 key and simulates signing,
verification, fixture execution, artifact hashing, explicit acceptance, and
cleanup in one process. It does **not** prove controller, worker, broker,
curator, or Kubernetes enforcement.
