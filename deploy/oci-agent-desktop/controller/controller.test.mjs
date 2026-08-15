import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  DisposableWorkspaceController,
  InMemoryControllerLedger,
  canonicalJson,
  sha256Hex,
  signEnvelope,
  validateControllerManifest,
  verifyArtifactChain,
  verifyDerivedRuntime,
} from "./controller.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const NOW = new Date("2026-08-13T12:00:00.000Z");
const IDS = {
  jti: "11111111-1111-4111-8111-111111111111",
  task: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  project: "44444444-4444-4444-8444-444444444444",
  workspace: "55555555-5555-4555-8555-555555555555",
};
const AGENT_IMAGE = `example.invalid/buzz-agent@sha256:${"a".repeat(64)}`;
const BROWSER_IMAGE = `example.invalid/buzz-browser@sha256:${"b".repeat(64)}`;

function keyPair(role, keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { role, keyId, privateKey, publicKey };
}

const finalForm = keyPair("final-form", "final-form-k1");
const worker = keyPair("worker", "worker-k1");
const broker = keyPair("broker", "broker-k1");
const controllerRuntime = keyPair("controller-runtime", "controller-runtime-k1");
const runtimeTrust = new Map([[controllerRuntime.keyId, { publicKey: controllerRuntime.publicKey, role: controllerRuntime.role }]]);

function capability(overrides = {}) {
  const payload = {
    version: 2,
    issuer: "final-form",
    audience: "buzz-disposable-workspace-controller",
    jti: IDS.jti,
    task_id: IDS.task,
    session_id: IDS.session,
    agent_id: "agent-alpha",
    project_id: IDS.project,
    workspace_id: IDS.workspace,
    concurrency_scope: { kind: "agent", subject: "agent-alpha" },
    issued_at: "2026-08-13T11:59:00.000Z",
    not_before: "2026-08-13T11:59:30.000Z",
    expires_at: "2026-08-13T13:00:00.000Z",
    task: { operation: "browser_task", input_sha256: "c".repeat(64) },
    limits: {
      cpu_millicores: 2000,
      memory_mib: 8192,
      wall_seconds: 3600,
      storage_bytes: 21474836480,
      max_concurrency: 2,
      artifact_bytes: 1073741824,
    },
    cancellation_token_sha256: "d".repeat(64),
    ...overrides,
  };
  return signEnvelope(payload, finalForm.privateKey, finalForm.keyId);
}

function newController(ledger = new InMemoryControllerLedger(), overrides = {}) {
  return new DisposableWorkspaceController({
    audience: "buzz-disposable-workspace-controller",
    now: () => new Date(NOW),
    ledger,
    trustedKeys: new Map([[finalForm.keyId, { publicKey: finalForm.publicKey, role: finalForm.role }]]),
    agentImage: AGENT_IMAGE,
    browserImage: BROWSER_IMAGE,
    runtimeSigningKey: controllerRuntime.privateKey,
    runtimeKeyId: controllerRuntime.keyId,
    ...overrides,
  });
}

function expectedBindings() {
  return {
    taskId: IDS.task,
    sessionId: IDS.session,
    agentId: "agent-alpha",
    projectId: IDS.project,
    workspaceId: IDS.workspace,
    inputSha256: "c".repeat(64),
  };
}

function terminalReceipt(sessionId = IDS.session, transferDigests = []) {
  return signEnvelope({
    version: 1,
    receipt_kind: "final-form-acceptance",
    session_id: sessionId,
    result_envelope_sha256: "9".repeat(64),
    transfer_envelope_sha256: transferDigests,
    decision: "accepted",
  }, finalForm.privateKey, finalForm.keyId);
}

function resourceQuota(manifest) {
  return manifest.items.find(object => object.kind === "ResourceQuota");
}

function job(manifest) {
  return manifest.items.find(object => object.kind === "Job");
}

function sumMillicores(containers) {
  return containers.reduce((sum, container) => sum + Number.parseInt(container.resources.limits.cpu.replace(/m$/, ""), 10), 0);
}

function sumMib(containers) {
  return containers.reduce((sum, container) => sum + Number.parseInt(container.resources.limits.memory.replace(/Mi$/, ""), 10), 0);
}

test("invalid envelope fails before workload creation", () => {
  const controller = newController();
  assert.throws(() => controller.createWorkspace({ envelope: { payload: capability().payload }, expected: expectedBindings() }), /envelope|signature/i);
  assert.equal(controller.renderCount, 0);
});

test("tampered signature fails before workload creation", () => {
  const controller = newController();
  const envelope = capability();
  envelope.payload.limits.cpu_millicores = 2500;
  assert.throws(() => controller.createWorkspace({ envelope, expected: expectedBindings() }), /signature/i);
  assert.equal(controller.renderCount, 0);
});

test("malformed validly signed capability fails closed", () => {
  const wrongType = capability({ limits: { ...capability().payload.limits, cpu_millicores: "2000" } });
  assert.throws(() => newController().createWorkspace({ envelope: wrongType, expected: expectedBindings() }), /cpu|limits|integer/i);
  const unknownClaim = capability({ unexpected_authority: true });
  assert.throws(() => newController().createWorkspace({ envelope: unknownClaim, expected: expectedBindings() }), /capability fields|keys differ/i);
});

test("wrong audience and authority bindings fail before workload creation", () => {
  for (const [field, value] of [
    ["issuer", "other-authority"],
    ["audience", "other-controller"],
    ["taskId", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
    ["sessionId", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"],
    ["agentId", "other-agent"],
    ["projectId", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"],
    ["workspaceId", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"],
    ["inputSha256", "e".repeat(64)],
  ]) {
    const controller = newController();
    const expected = expectedBindings();
    let envelope = capability();
    if (field === "issuer" || field === "audience") envelope = capability({ [field]: value });
    else expected[field] = value;
    assert.throws(() => controller.createWorkspace({ envelope, expected }), /issuer|audience|binding/i, field);
    assert.equal(controller.renderCount, 0, field);
  }
});

test("expired and not-yet-valid capabilities fail", () => {
  assert.throws(() => newController().createWorkspace({ envelope: capability({ expires_at: "2026-08-13T11:59:59.000Z" }), expected: expectedBindings() }), /expired/i);
  assert.throws(() => newController().createWorkspace({ envelope: capability({ not_before: "2026-08-13T12:00:01.000Z" }), expected: expectedBindings() }), /not yet valid/i);
});

test("cancelled and replayed JTI fail server-side", () => {
  const cancelledLedger = new InMemoryControllerLedger();
  cancelledLedger.cancel(IDS.jti);
  assert.throws(() => newController(cancelledLedger).createWorkspace({ envelope: capability(), expected: expectedBindings() }), /cancelled/i);

  const controller = newController();
  controller.createWorkspace({ envelope: capability(), expected: expectedBindings() });
  assert.throws(() => controller.createWorkspace({ envelope: capability(), expected: expectedBindings() }), /replay|consumed/i);
  assert.equal(controller.renderCount, 1);
});

test("admission commits JTI, workspace ownership, and concurrency atomically", () => {
  const ledger = new InMemoryControllerLedger();
  const invalidController = newController(ledger, { agentImage: "example.invalid/buzz-agent:latest" });
  assert.throws(() => invalidController.createWorkspace({ envelope: capability(), expected: expectedBindings() }), /digest pinned/i);

  const controller = newController(ledger);
  const oneLimit = { ...capability().payload.limits, max_concurrency: 1 };
  controller.createWorkspace({ envelope: capability({ limits: oneLimit }), expected: expectedBindings() });

  const secondIds = {
    jti: "66666666-6666-4666-8666-666666666666",
    session: "77777777-7777-4777-8777-777777777777",
    workspace: "88888888-8888-4888-8888-888888888888",
  };
  const secondEnvelope = capability({
    jti: secondIds.jti,
    session_id: secondIds.session,
    workspace_id: secondIds.workspace,
    limits: oneLimit,
  });
  const secondExpected = {
    ...expectedBindings(),
    sessionId: secondIds.session,
    workspaceId: secondIds.workspace,
  };
  assert.throws(() => controller.createWorkspace({ envelope: secondEnvelope, expected: secondExpected }), /concurrency/i);
  assert.equal(controller.renderCount, 1);

  const first = controller.cleanupWorkspace({ namespace: "buzz-333333333333", sessionId: IDS.session, mode: "terminal-result", terminalAcceptance: terminalReceipt() });
  assert.equal(first.status, "delete-approved");
  const second = controller.createWorkspace({ envelope: secondEnvelope, expected: secondExpected });
  assert.equal(second.namespace, "buzz-777777777777");
});

test("valid signed limits map exactly into Job, PVC, and ResourceQuota", () => {
  const created = newController().createWorkspace({ envelope: capability(), expected: expectedBindings() });
  const quota = resourceQuota(created.manifest);
  const workload = job(created.manifest);
  const containers = workload.spec.template.spec.containers;
  const pvc = created.manifest.items.find(object => object.kind === "PersistentVolumeClaim");
  assert.equal(quota.spec.hard["limits.cpu"], "2000m");
  assert.equal(quota.spec.hard["limits.memory"], "8192Mi");
  assert.equal(quota.spec.hard["requests.storage"], "21474836480");
  assert.equal(quota.spec.hard["count/jobs.batch"], "1");
  assert.equal(workload.spec.activeDeadlineSeconds, 3600);
  assert.equal(pvc.spec.resources.requests.storage, "21474836480");
  assert.equal(sumMillicores(containers), 2000);
  assert.equal(sumMib(containers), 8192);
  assert.equal(created.namespace, "buzz-333333333333");
});

test("browser has a separate UID/process boundary and receives no raw authority", () => {
  const created = newController().createWorkspace({ envelope: capability(), expected: expectedBindings() });
  const pod = job(created.manifest).spec.template.spec;
  const agent = pod.containers.find(container => container.name === "agent");
  const browser = pod.containers.find(container => container.name === "browser");
  assert.equal(pod.shareProcessNamespace, false);
  assert.notEqual(agent.securityContext.runAsUser, browser.securityContext.runAsUser);
  assert(!browser.volumeMounts?.some(mount => mount.name === "derived-agent-runtime"));
  assert(browser.volumeMounts?.some(mount => mount.name === "derived-browser-runtime"));
  const browserConfigMap = created.manifest.items.find(object => object.kind === "ConfigMap" && object.metadata.name === "derived-browser-runtime");
  const browserRuntime = JSON.parse(browserConfigMap.data["config.json"]);
  assert.equal(browserRuntime.payload.role, "browser");
  assert(!JSON.stringify(browserRuntime).includes("capability"));
  assert(!JSON.stringify(browserRuntime).includes("task_id"));
  assert(!JSON.stringify(browserRuntime).includes("input_sha256"));
  assert(!JSON.stringify(browser).includes("capability"));
  assert(!JSON.stringify(browser).includes("signature"));
  assert(!JSON.stringify(created.manifest).includes(capability().signature));
  assert(!JSON.stringify(browser).includes("--no-sandbox"));
  assert(browser.args.includes("--disable-setuid-sandbox") === false);
});

test("worker defense-in-depth verification fails on environment mismatch", () => {
  const created = newController().createWorkspace({ envelope: capability(), expected: expectedBindings() });
  assert.equal(verifyDerivedRuntime(created.derivedRuntime, created.runtimeEvidence.agent, "agent", runtimeTrust), true);
  assert.equal(verifyDerivedRuntime(created.browserRuntime, created.runtimeEvidence.browser, "browser", runtimeTrust), true);
  assert.throws(() => verifyDerivedRuntime(created.derivedRuntime, { ...created.runtimeEvidence.agent, cpu_millicores: created.runtimeEvidence.agent.cpu_millicores + 1 }, "agent", runtimeTrust), /runtime.*mismatch/i);
  assert.throws(() => verifyDerivedRuntime(created.browserRuntime, { ...created.runtimeEvidence.browser, memory_mib: created.runtimeEvidence.browser.memory_mib + 1 }, "browser", runtimeTrust), /runtime.*mismatch/i);
});

test("closed-world controller validation rejects appended workloads and policies", () => {
  const created = newController().createWorkspace({ envelope: capability(), expected: expectedBindings() });
  const workloadAttack = structuredClone(created.manifest);
  workloadAttack.items.push({ apiVersion: "batch/v1", kind: "Job", metadata: { name: "escape", namespace: created.namespace }, spec: { template: { spec: { hostNetwork: true, containers: [] } } } });
  assert.throws(() => validateControllerManifest(workloadAttack, created.plan), /inventory|unexpected/i);

  const policyAttack = structuredClone(created.manifest);
  policyAttack.items.push({ apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "allow-all", namespace: created.namespace }, spec: { podSelector: {}, policyTypes: ["Egress"], egress: [{}] } });
  assert.throws(() => validateControllerManifest(policyAttack, created.plan), /inventory|network/i);
});

test("cleanup is ownership-bound, mode-aware, fail-closed, and idempotent", () => {
  const ledger = new InMemoryControllerLedger();
  const controller = newController(ledger);
  const created = controller.createWorkspace({ envelope: capability(), expected: expectedBindings() });
  assert.throws(() => controller.cleanupWorkspace({ namespace: created.namespace, sessionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", mode: "terminal-result" }), /ownership/i);
  assert.throws(() => controller.cleanupWorkspace({ namespace: created.namespace, sessionId: IDS.session, mode: "expiration" }), /not expired/i);
  assert.throws(() => controller.cleanupWorkspace({ namespace: created.namespace, sessionId: IDS.session, mode: "terminal-result", terminalResult: true }), /signed|acceptance/i);
  assert.throws(() => controller.cleanupWorkspace({ namespace: created.namespace, sessionId: IDS.session, mode: "terminal-result", terminalAcceptance: terminalReceipt(IDS.session, ["invalid"]) }), /transfer digests/i);
  const terminalAcceptance = terminalReceipt(IDS.session, ["a".repeat(64), "b".repeat(64)]);
  const first = controller.cleanupWorkspace({ namespace: created.namespace, sessionId: IDS.session, mode: "terminal-result", terminalAcceptance });
  assert.equal(first.status, "delete-approved");
  assert.equal(first.preconditions.session_id, IDS.session);
  const second = controller.cleanupWorkspace({ namespace: created.namespace, sessionId: IDS.session, mode: "terminal-result", terminalAcceptance });
  assert.equal(second.status, "already-cleaned");
});

test("fake signed result, broker receipt, and FINAL-FORM acceptance verify end to end", () => {
  const capEnvelope = capability();
  const capabilitySha256 = sha256Hex(canonicalJson(capEnvelope));
  const artifact = { path: "artifacts/result.txt", bytes: 5, sha256: sha256Hex("hello"), media_type: "text/plain" };
  const resultEnvelope = signEnvelope({
    version: 2,
    task_id: IDS.task,
    session_id: IDS.session,
    agent_id: "agent-alpha",
    project_id: IDS.project,
    workspace_id: IDS.workspace,
    capability_sha256: capabilitySha256,
    status: "succeeded",
    artifacts: [artifact],
  }, worker.privateKey, worker.keyId);
  const resultSha256 = sha256Hex(canonicalJson(resultEnvelope));
  const transferEnvelope = signEnvelope({
    version: 2,
    task_id: IDS.task,
    session_id: IDS.session,
    agent_id: "agent-alpha",
    project_id: IDS.project,
    workspace_id: IDS.workspace,
    capability_sha256: capabilitySha256,
    result_envelope_sha256: resultSha256,
    operation: "fake-upload",
    artifact,
  }, broker.privateKey, broker.keyId);
  const transferSha256 = sha256Hex(canonicalJson(transferEnvelope));
  const acceptanceEnvelope = signEnvelope({
    version: 2,
    task_id: IDS.task,
    session_id: IDS.session,
    agent_id: "agent-alpha",
    project_id: IDS.project,
    workspace_id: IDS.workspace,
    result_envelope_sha256: resultSha256,
    transfer_envelope_sha256: [transferSha256],
    decision: "accepted",
  }, finalForm.privateKey, finalForm.keyId);
  const trust = new Map([
    [finalForm.keyId, { publicKey: finalForm.publicKey, role: finalForm.role }],
    [worker.keyId, { publicKey: worker.publicKey, role: worker.role }],
    [broker.keyId, { publicKey: broker.publicKey, role: broker.role }],
  ]);
  assert.equal(verifyArtifactChain({ capabilityEnvelope: capEnvelope, resultEnvelope, transferEnvelopes: [transferEnvelope], acceptanceEnvelope, trust }), true);
  const wrongOperation = signEnvelope({ ...transferEnvelope.payload, operation: "fake-delete" }, broker.privateKey, broker.keyId);
  const wrongOperationAcceptance = signEnvelope({
    ...acceptanceEnvelope.payload,
    transfer_envelope_sha256: [sha256Hex(canonicalJson(wrongOperation))],
  }, finalForm.privateKey, finalForm.keyId);
  assert.throws(() => verifyArtifactChain({ capabilityEnvelope: capEnvelope, resultEnvelope, transferEnvelopes: [wrongOperation], acceptanceEnvelope: wrongOperationAcceptance, trust }), /operation/i);

  const oversizedArtifact = { ...artifact, bytes: capEnvelope.payload.limits.artifact_bytes + 1 };
  const oversizedResult = signEnvelope({ ...resultEnvelope.payload, artifacts: [oversizedArtifact] }, worker.privateKey, worker.keyId);
  const oversizedResultSha256 = sha256Hex(canonicalJson(oversizedResult));
  const oversizedTransfer = signEnvelope({
    ...transferEnvelope.payload,
    result_envelope_sha256: oversizedResultSha256,
    artifact: oversizedArtifact,
  }, broker.privateKey, broker.keyId);
  const oversizedAcceptance = signEnvelope({
    ...acceptanceEnvelope.payload,
    result_envelope_sha256: oversizedResultSha256,
    transfer_envelope_sha256: [sha256Hex(canonicalJson(oversizedTransfer))],
  }, finalForm.privateKey, finalForm.keyId);
  assert.throws(() => verifyArtifactChain({ capabilityEnvelope: capEnvelope, resultEnvelope: oversizedResult, transferEnvelopes: [oversizedTransfer], acceptanceEnvelope: oversizedAcceptance, trust }), /artifact.*limit/i);

  const tampered = structuredClone(transferEnvelope);
  tampered.payload.artifact.bytes = 6;
  assert.throws(() => verifyArtifactChain({ capabilityEnvelope: capEnvelope, resultEnvelope, transferEnvelopes: [tampered], acceptanceEnvelope, trust }), /signature|digest/i);
});

test("worker verifier launches only after runtime evidence matches", () => {
  const testNow = new Date();
  const freshEnvelope = capability({
    issued_at: new Date(testNow.getTime() - 60_000).toISOString(),
    not_before: new Date(testNow.getTime() - 30_000).toISOString(),
    expires_at: new Date(testNow.getTime() + 3_600_000).toISOString(),
  });
  const created = newController(new InMemoryControllerLedger(), { now: () => testNow }).createWorkspace({ envelope: freshEnvelope, expected: expectedBindings() });
  const dir = mkdtempSync(join(tmpdir(), "buzz-runtime-verifier-"));
  const config = join(dir, "runtime.json");
  const trustKey = join(dir, "controller-runtime.pub.pem");
  const marker = join(dir, "launched.txt");
  writeFileSync(config, JSON.stringify(created.derivedRuntime));
  writeFileSync(trustKey, controllerRuntime.publicKey.export({ type: "spki", format: "pem" }));
  const verifier = join(here, "verify-derived-runtime.mjs");
  const environment = {
    ...process.env,
    BUZZ_CPU_MILLICORES: `${created.runtimeEvidence.agent.cpu_millicores}`,
    BUZZ_MEMORY_MIB: `${created.runtimeEvidence.agent.memory_mib}`,
  };
  try {
    const command = [verifier, "--role", "agent", "--trust-key", trustKey, "--config", config, "--", process.execPath, "-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'ok')`];
    const valid = spawnSync(process.execPath, command, { encoding: "utf8", env: environment });
    assert.equal(valid.status, 0, valid.stderr || valid.stdout);
    assert.equal(existsSync(marker), true);
    rmSync(marker);
    const invalid = spawnSync(process.execPath, command, { encoding: "utf8", env: { ...environment, BUZZ_CPU_MILLICORES: "1" } });
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stderr, /runtime environment mismatch/i);
    assert.equal(existsSync(marker), false, "agent command must not launch after failed verification");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
