import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const canonical = value => JSON.stringify(sort(value));
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])]));
  }
  return value;
}
const sha256 = value => createHash("sha256").update(value).digest("hex");

const work = await mkdtemp(join(tmpdir(), "buzz-protocol-"));
try {
  const taskInput = canonical({ url: "https://example.invalid/fixture", instruction: "write deterministic fixture" });
  const cancellationToken = randomBytes(32).toString("base64url");
  const now = Date.now();
  const claims = {
    version: 1,
    issuer: "final-form",
    audience: "buzz-worker:local-smoke",
    jti: randomUUID(),
    task_id: randomUUID(),
    session_id: randomUUID(),
    agent_id: "buzz-validation",
    issued_at: new Date(now).toISOString(),
    not_before: new Date(now - 1000).toISOString(),
    expires_at: new Date(now + 60_000).toISOString(),
    task: { operation: "write_fixture", input_sha256: sha256(taskInput) },
    limits: { cpu_millicores: 500, memory_mib: 512, wall_seconds: 30, artifact_bytes: 4096 },
    cancellation_token_sha256: sha256(cancellationToken)
  };

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bytes = Buffer.from(canonical(claims));
  const signature = sign(null, bytes, privateKey);

  assert(verify(null, bytes, publicKey, signature), "capability signature failed");
  assert.equal(claims.audience, "buzz-worker:local-smoke");
  assert(Date.parse(claims.not_before) <= Date.now());
  assert(Date.parse(claims.expires_at) > Date.now());
  assert.equal(claims.task.input_sha256, sha256(taskInput));

  const artifactPath = join(work, "result.txt");
  const artifactBody = "BUZZ_DISPOSABLE_WORKER_OK\n";
  assert(Buffer.byteLength(artifactBody) <= claims.limits.artifact_bytes);
  await writeFile(artifactPath, artifactBody, { flag: "wx" });
  const returned = await readFile(artifactPath);
  const manifest = {
    version: 1,
    task_id: claims.task_id,
    session_id: claims.session_id,
    agent_id: claims.agent_id,
    status: "succeeded",
    started_at: new Date(now).toISOString(),
    finished_at: new Date().toISOString(),
    worker_claims_sha256: sha256(bytes),
    artifacts: [{ path: "result.txt", bytes: returned.length, sha256: sha256(returned), media_type: "text/plain" }]
  };

  // Returning a result is not acceptance. FINAL-FORM verifies every artifact.
  const decision = manifest.artifacts.every(a => a.path === "result.txt" && a.sha256 === sha256(returned))
    ? { decision: "accepted", task_id: manifest.task_id, manifest_sha256: sha256(canonical(manifest)) }
    : { decision: "rejected", task_id: manifest.task_id };
  assert.equal(decision.decision, "accepted");
  console.log("protocol smoke simulation: signature, bounds, execution, hashes, acceptance PASS; local temp cleanup only");
} finally {
  await rm(work, { recursive: true, force: true });
}
