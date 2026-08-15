# Brokered workspace storage

Status: **provider-neutral design and contract simulation only**. No enforcing
broker, durable ledger, curator service, Drive adapter, Composio adapter, or
bulk transfer plane exists in this package.

This design gives disposable workers useful Google Drive access without giving
them Google, Composio, or FINAL-FORM credentials. Drive is an archive and
checkpoint backend, not a live filesystem and not authoritative project state.

## Boundary

```text
OCI worker
  -> short-lived signed storage capability
  -> FINAL-FORM storage MCP gateway
  -> broker policy and durable ledger
  -> Composio adapter or direct Google Drive adapter
  -> Google Drive
```

The gateway may be horizontally stateless: each request authenticates its
capability and all durable facts live in the broker ledger. The system as a
whole is intentionally stateful. It retains OAuth connections, Drive file-ID
mappings, byte reservations, idempotency records, transfer receipts, and
FINAL-FORM acceptance decisions.

One durable Google connection could eventually serve many jobs. A worker must
receive a short-lived job capability, not a new OAuth connection. The current
v1 simulation still exposes a Drive-specific root file ID; a production
provider-neutral contract must replace it with an opaque `storage_binding_id`
whose provider/account/root mapping exists only in FINAL-FORM.

## Worker tools

The worker-facing MCP surface is deliberately semantic and small:

- `checkout_workspace`
- `list_workspace_files`
- `stage_artifact`
- `commit_checkpoint`
- `get_checkpoint_status`
- `restore_checkpoint`
- `finish_workspace`

Workers never receive raw Drive or Composio tools. Authentication management,
arbitrary proxy calls, remote shell/workbench, sharing, permission changes,
permanent deletion, unrestricted Drive search, and artifact acceptance are
denied by `curator-policy.json`.

MCP is the control plane, not the bulk data plane. Upload and download tools
return one-time broker transfer handles. Bytes stream over authenticated HTTPS
on the private Tailscale path; they are not base64-encoded into MCP JSON. The
broker uses resumable upstream transfers, verifies SHA-256 and size, and emits
a signed transfer receipt.

## Drive and Composio rules

- Drive paths and names are presentation only. The broker ledger maps stable
  project/workspace/checkpoint IDs to Drive file IDs.
- `latest.json` may be a convenience copy, never the authoritative pointer.
- Unaccepted results remain under a workspace. Acceptance creates a project
  reference to the immutable checkpoint; it does not duplicate the bytes.
- OAuth refresh tokens stay in Composio or FINAL-FORM/BWS. Workers never see
  them, a Composio project API key, connected-account IDs, or Google tokens.
- A production OAuth client must not depend on external Testing-mode refresh
  tokens. Token durability is an explicit pilot gate.
- The broker reserves bytes before a transfer and reconciles actual bytes
  afterward. Drive does not enforce these logical quotas.

Composio is only a candidate replaceable adapter behind the gateway. Workers
must not connect directly to its hosted session MCP unless that path is proven
to enforce the same operation, identity, root, byte, concurrency, expiry,
idempotency, and receipt rules. The recommended first concrete bulk adapter is
the direct Google Drive API behind a thin provider-neutral interface; it remains
disabled and unimplemented in this slice.

## Receipts and authority

Three independent records close a successful job:

1. The worker result manifest describes claimed outputs.
2. The broker transfer receipt proves the stored object's bytes and hash.
3. FINAL-FORM signs an acceptance or rejection receipt after independent
   verification.

Only the third record may promote a checkpoint into authoritative project
state. A worker and the storage broker cannot accept their own result.

## Curator

The target curator would run policy before and after operations and periodically
reconcile abandoned partial uploads, expired capabilities, orphaned sessions,
reservation drift, rate failures, provider errors, and receipt mismatches.
`curator-policy.json` is configuration seed data only; there is no curator
implementation or validated deletion behavior.

`storage-broker-smoke.mjs` simulates the signed boundary, allowlist, workspace
binding, reservation, idempotency, transfer receipt, acceptance, and expiry in
one process without contacting storage. It reads and asserts curator policy seed
values but does not execute escalation or reconciliation. It does **not** prove
atomic persistence, crash recovery, streaming limits, adapter behavior, curator
behavior, or runtime enforcement.
