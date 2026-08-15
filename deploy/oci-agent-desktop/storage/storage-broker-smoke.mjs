import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

const canonical = value => JSON.stringify(sort(value));
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])]));
  }
  return value;
}
const sha256 = value => createHash("sha256").update(value).digest("hex");
const mustReject = (fn, pattern) => assert.throws(fn, pattern);

const [policy, capabilitySchema, transferSchema, acceptanceSchema] = await Promise.all([
  readFile(new URL("./curator-policy.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("./storage-capability.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("./broker-transfer-receipt.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("./acceptance-receipt.schema.json", import.meta.url), "utf8").then(JSON.parse)
]);
assert.equal(policy.version, 1);
assert(capabilitySchema.required.includes("root_file_id"));
assert(capabilitySchema.required.includes("policy_sha256"));
assert(transferSchema.required.includes("backend_object_id"));
assert(acceptanceSchema.required.includes("decision"));
assert(!policy.logical_tools.allow.includes("accept_artifact"));
assert(policy.logical_tools.deny_capability_classes.includes("authentication_management"));
assert(policy.logical_tools.deny_capability_classes.includes("raw_provider_proxy"));
assert.equal(policy.responses.cross_workspace_access, "revoke_and_quarantine");
assert.equal(policy.responses.accepted_artifact, "retain");

const now = Date.now();
const claims = {
  version: 1,
  issuer: "final-form",
  audience: "buzz-storage-broker",
  jti: randomUUID(),
  task_id: randomUUID(),
  session_id: randomUUID(),
  agent_id: "buzz-storage-smoke",
  project_id: "buzz-pilot",
  workspace_id: randomUUID(),
  storage_binding_id: "entaingled-agent-storage",
  root_file_id: "drive-root-fixture-id",
  issued_at: new Date(now).toISOString(),
  not_before: new Date(now - 1000).toISOString(),
  expires_at: new Date(now + 60_000).toISOString(),
  allowed_operations: ["checkout_workspace", "stage_artifact", "commit_checkpoint", "get_checkpoint_status", "finish_workspace"],
  limits: {
    max_operations: 8,
    max_read_bytes: 8192,
    max_write_bytes: 8192,
    max_object_bytes: 4096,
    max_concurrent_transfers: 2
  },
  policy_sha256: sha256(canonical(policy)),
  cancellation_token_sha256: sha256(randomBytes(32))
};

const finalForm = generateKeyPairSync("ed25519");
const broker = generateKeyPairSync("ed25519");
const claimsBytes = Buffer.from(canonical(claims));
const capabilitySignature = sign(null, claimsBytes, finalForm.privateKey);
assert(verify(null, claimsBytes, finalForm.publicKey, capabilitySignature));

const ledger = {
  operations: 0,
  reservedWriteBytes: 0,
  actualWriteBytes: 0,
  inFlight: 0,
  revoked: false,
  idempotency: new Map()
};

function authorize(request, at = Date.now()) {
  assert(!ledger.revoked, "capability revoked");
  assert.equal(claims.policy_sha256, sha256(canonical(policy)), "policy digest mismatch");
  assert(at >= Date.parse(claims.not_before), "capability not active");
  assert(at < Date.parse(claims.expires_at), "capability expired");
  assert.equal(request.task_id, claims.task_id, "cross-task access");
  assert.equal(request.session_id, claims.session_id, "cross-session access");
  assert.equal(request.workspace_id, claims.workspace_id, "cross-workspace access");
  assert.equal(request.root_file_id, claims.root_file_id, "wrong Drive root");
  assert(claims.allowed_operations.includes(request.operation), "operation denied");
  assert(!request.logical_path.startsWith("/") && !request.logical_path.startsWith("\\"), "absolute path denied");
  assert(!request.logical_path.split(/[\\/]/).includes(".."), "path traversal denied");

  const prior = ledger.idempotency.get(request.idempotency_key);
  if (prior) return prior;

  assert(ledger.operations < claims.limits.max_operations, "operation budget exceeded");
  assert(ledger.inFlight < claims.limits.max_concurrent_transfers, "transfer concurrency exceeded");
  const bytes = request.bytes ?? 0;
  assert(bytes <= claims.limits.max_object_bytes, "object too large");
  assert(ledger.reservedWriteBytes + bytes <= claims.limits.max_write_bytes, "write budget exceeded");

  const grant = { transfer_id: randomUUID(), reserved_bytes: bytes };
  ledger.operations += 1;
  ledger.reservedWriteBytes += bytes;
  ledger.inFlight += 1;
  ledger.idempotency.set(request.idempotency_key, grant);
  return grant;
}

const artifact = Buffer.from("BUZZ_BROKERED_STORAGE_OK\n");
const request = {
  task_id: claims.task_id,
  session_id: claims.session_id,
  workspace_id: claims.workspace_id,
  root_file_id: claims.root_file_id,
  operation: "stage_artifact",
  logical_path: "artifacts/result.txt",
  bytes: artifact.length,
  idempotency_key: randomUUID()
};
const grant = authorize(request);
const repeated = authorize(request);
assert.deepEqual(repeated, grant, "idempotent retry changed the transfer grant");
assert.equal(ledger.operations, 1, "idempotent retry consumed operation budget");
assert.equal(ledger.reservedWriteBytes, artifact.length, "idempotent retry reserved bytes twice");

mustReject(() => authorize({ ...request, idempotency_key: randomUUID(), operation: "manage_connections" }), /operation denied/);
mustReject(() => authorize({ ...request, idempotency_key: randomUUID(), workspace_id: randomUUID() }), /cross-workspace access/);
mustReject(() => authorize({ ...request, idempotency_key: randomUUID(), logical_path: "../escape" }), /path traversal denied/);
mustReject(() => authorize({ ...request, idempotency_key: randomUUID(), bytes: claims.limits.max_object_bytes + 1 }), /object too large/);
mustReject(() => authorize(request, Date.parse(claims.expires_at) + 1), /capability expired/);

const transferredHash = sha256(artifact);
ledger.inFlight -= 1;
ledger.actualWriteBytes += artifact.length;
const transferReceipt = {
  version: 1,
  issuer: "final-form-storage-broker",
  receipt_id: randomUUID(),
  capability_jti: claims.jti,
  task_id: claims.task_id,
  session_id: claims.session_id,
  workspace_id: claims.workspace_id,
  storage_binding_id: claims.storage_binding_id,
  backend_object_id: "drive-object-fixture-id",
  operation: "upload",
  logical_path: request.logical_path,
  bytes: artifact.length,
  sha256: transferredHash,
  media_type: "text/plain",
  started_at: new Date(now).toISOString(),
  finished_at: new Date().toISOString(),
  status: "verified"
};
const transferBytes = Buffer.from(canonical(transferReceipt));
const transferSignature = sign(null, transferBytes, broker.privateKey);
assert(verify(null, transferBytes, broker.publicKey, transferSignature));
assert.equal(transferReceipt.sha256, sha256(artifact));

const resultManifest = {
  task_id: claims.task_id,
  session_id: claims.session_id,
  workspace_id: claims.workspace_id,
  artifacts: [{ path: request.logical_path, bytes: artifact.length, sha256: transferredHash }]
};
const acceptanceReceipt = {
  version: 1,
  issuer: "final-form",
  receipt_id: randomUUID(),
  task_id: claims.task_id,
  session_id: claims.session_id,
  agent_id: claims.agent_id,
  workspace_id: claims.workspace_id,
  manifest_sha256: sha256(canonical(resultManifest)),
  transfer_receipt_sha256s: [sha256(transferBytes)],
  decision: "accepted",
  decided_at: new Date().toISOString(),
  accepted_checkpoint_id: transferredHash
};
const acceptanceBytes = Buffer.from(canonical(acceptanceReceipt));
const acceptanceSignature = sign(null, acceptanceBytes, finalForm.privateKey);
assert(verify(null, acceptanceBytes, finalForm.publicKey, acceptanceSignature));
assert.notEqual(sha256(transferBytes), sha256(acceptanceBytes), "broker receipt cannot stand in for acceptance");

console.log("storage broker smoke simulation: capability, policy seed, reservation, receipts, acceptance PASS; no curator executed");
