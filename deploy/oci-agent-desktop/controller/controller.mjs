import { createHash, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { validateClosedWorldManifest } from "../kubernetes/manifest-policy.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST_IMAGE = /@sha256:[a-f0-9]{64}$/;
const MAX_TTL_SECONDS = 7200;

function fail(message) {
  throw new Error(message);
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  }
  if (typeof value === "number" && (!Number.isSafeInteger(value) || !Number.isFinite(value))) fail("canonical JSON requires safe integers");
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(sorted(value));
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function signingBytes(envelope) {
  return Buffer.from(canonicalJson({ alg: envelope.alg, key_id: envelope.key_id, payload: envelope.payload }));
}

export function signEnvelope(payload, privateKey, keyId) {
  const envelope = { alg: "Ed25519", key_id: keyId, payload: structuredClone(payload) };
  envelope.signature = cryptoSign(null, signingBytes(envelope), privateKey).toString("base64url");
  return envelope;
}

function verifyEnvelope(envelope, trust, role) {
  if (!envelope || typeof envelope !== "object") fail("signed envelope is required");
  const keys = Object.keys(envelope).sort();
  if (!isDeepStrictEqual(keys, ["alg", "key_id", "payload", "signature"])) fail("invalid signed envelope fields");
  if (envelope.alg !== "Ed25519" || typeof envelope.signature !== "string") fail("invalid envelope signature metadata");
  const trusted = trust.get(envelope.key_id);
  if (!trusted || trusted.role !== role) fail(`untrusted ${role} signing key`);
  let signature;
  try {
    signature = Buffer.from(envelope.signature, "base64url");
  } catch {
    fail("invalid signature encoding");
  }
  if (!cryptoVerify(null, signingBytes(envelope), trusted.publicKey, signature)) fail("signature verification failed");
  return envelope.payload;
}

function requireExactKeys(value, expected, where) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${where} must be an object`);
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (!isDeepStrictEqual(keys, wanted)) fail(`${where} fields are invalid`);
}

function requireUuid(value, where) {
  if (typeof value !== "string" || !UUID.test(value)) fail(`${where} must be a UUID`);
}

function requireSha(value, where) {
  if (typeof value !== "string" || !SHA256.test(value)) fail(`${where} must be SHA-256`);
}

function parseTimestamp(value, where) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) fail(`${where} must be canonical RFC3339 UTC`);
  return timestamp;
}

function requireInteger(value, minimum, maximum, where) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`${where} is outside policy`);
}

function validateCapability(payload, expected, audience, now) {
  requireExactKeys(payload, [
    "version", "issuer", "audience", "jti", "task_id", "session_id", "agent_id", "project_id", "workspace_id", "concurrency_scope",
    "issued_at", "not_before", "expires_at", "task", "limits", "cancellation_token_sha256",
  ], "capability");
  if (payload.version !== 2 || payload.issuer !== "final-form") fail("invalid capability issuer or version");
  if (payload.audience !== audience) fail("capability audience mismatch");
  requireUuid(payload.jti, "jti");
  for (const [name, value] of [["task_id", payload.task_id], ["session_id", payload.session_id], ["project_id", payload.project_id], ["workspace_id", payload.workspace_id]]) requireUuid(value, name);
  if (typeof payload.agent_id !== "string" || payload.agent_id.length < 1 || payload.agent_id.length > 128) fail("agent binding invalid");
  requireExactKeys(payload.concurrency_scope, ["kind", "subject"], "concurrency scope");
  if (!new Set(["agent", "tenant", "issuer"]).has(payload.concurrency_scope.kind)) fail("concurrency scope kind is invalid");
  if (typeof payload.concurrency_scope.subject !== "string" || payload.concurrency_scope.subject.length < 1 || payload.concurrency_scope.subject.length > 128) fail("concurrency scope subject is invalid");
  if (payload.concurrency_scope.kind === "agent" && payload.concurrency_scope.subject !== payload.agent_id) fail("agent concurrency scope binding mismatch");
  if (payload.concurrency_scope.kind === "issuer" && payload.concurrency_scope.subject !== payload.issuer) fail("issuer concurrency scope binding mismatch");
  requireExactKeys(payload.task, ["operation", "input_sha256"], "task");
  if (!new Set(["browser_task", "write_fixture"]).has(payload.task.operation)) fail("task operation is not allowed");
  requireSha(payload.task.input_sha256, "task input");
  requireSha(payload.cancellation_token_sha256, "cancellation token");
  requireExactKeys(payload.limits, ["cpu_millicores", "memory_mib", "wall_seconds", "storage_bytes", "max_concurrency", "artifact_bytes"], "limits");
  requireInteger(payload.limits.cpu_millicores, 200, 64000, "CPU limit");
  requireInteger(payload.limits.memory_mib, 512, 262144, "memory limit");
  requireInteger(payload.limits.wall_seconds, 1, MAX_TTL_SECONDS, "wall-time limit");
  requireInteger(payload.limits.storage_bytes, 1048576, 1099511627776, "storage limit");
  requireInteger(payload.limits.max_concurrency, 1, 64, "concurrency limit");
  requireInteger(payload.limits.artifact_bytes, 0, payload.limits.storage_bytes, "artifact limit");

  const issued = parseTimestamp(payload.issued_at, "issued_at");
  const notBefore = parseTimestamp(payload.not_before, "not_before");
  const expires = parseTimestamp(payload.expires_at, "expires_at");
  const current = now.getTime();
  if (issued > notBefore || notBefore > expires) fail("capability timestamp order invalid");
  if (notBefore > current) fail("capability is not yet valid");
  if (expires <= current) fail("capability is expired");
  if ((expires - notBefore) / 1000 > MAX_TTL_SECONDS) fail("capability TTL exceeds policy");
  if (payload.limits.wall_seconds > (expires - current) / 1000) fail("wall-time exceeds remaining capability lifetime");

  const bindings = {
    taskId: payload.task_id,
    sessionId: payload.session_id,
    agentId: payload.agent_id,
    projectId: payload.project_id,
    workspaceId: payload.workspace_id,
    inputSha256: payload.task.input_sha256,
  };
  if (!isDeepStrictEqual(bindings, expected)) fail("authority binding mismatch");
  return payload;
}

export class InMemoryControllerLedger {
  #cancelled = new Set();
  #consumed = new Map();
  #workspaces = new Map();
  #activeByScope = new Map();

  cancel(jti) {
    this.#cancelled.add(jti);
  }

  isCancelled(jti) {
    return this.#cancelled.has(jti);
  }

  admit(record) {
    if (this.#cancelled.has(record.jti)) fail("capability is cancelled");
    if (this.#consumed.has(record.jti)) fail("capability JTI is already consumed; replay rejected");
    if (this.#workspaces.has(record.sessionId)) fail("workspace session is already registered");
    const active = this.#activeByScope.get(record.concurrencyScope) ?? 0;
    if (active >= record.maxConcurrency) fail("signed workspace concurrency limit is exhausted");

    this.#consumed.set(record.jti, record.capabilityDigest);
    this.#workspaces.set(record.sessionId, { ...record, cleaned: false });
    this.#activeByScope.set(record.concurrencyScope, active + 1);
  }

  workspace(sessionId) {
    return this.#workspaces.get(sessionId);
  }

  markCleaned(sessionId) {
    const record = this.#workspaces.get(sessionId);
    if (!record) fail("workspace ownership record not found");
    if (record.cleaned) return;
    const active = this.#activeByScope.get(record.concurrencyScope) ?? 0;
    if (active < 1) fail("workspace concurrency ledger is inconsistent");
    record.cleaned = true;
    if (active === 1) this.#activeByScope.delete(record.concurrencyScope);
    else this.#activeByScope.set(record.concurrencyScope, active - 1);
  }
}

function splitLimit(total, minimum) {
  const agent = Math.max(minimum, Math.floor(total / 4));
  if (agent >= total) fail("workspace limit cannot support separate agent and browser containers");
  return { agent, browser: total - agent };
}

function secureContainer({ name, image, uid, cpu, memory, volumeMounts = [], command, args = [], env = [] }) {
  return {
    name,
    image,
    imagePullPolicy: "IfNotPresent",
    command,
    args,
    env,
    resources: {
      requests: { cpu: `${cpu}m`, memory: `${memory}Mi` },
      limits: { cpu: `${cpu}m`, memory: `${memory}Mi` },
    },
    securityContext: {
      runAsNonRoot: true,
      runAsUser: uid,
      runAsGroup: uid,
      allowPrivilegeEscalation: false,
      privileged: false,
      readOnlyRootFilesystem: true,
      capabilities: { drop: ["ALL", "NET_RAW"] },
    },
    volumeMounts,
  };
}

function buildManifest(payload, options) {
  if (!DIGEST_IMAGE.test(options.agentImage) || !DIGEST_IMAGE.test(options.browserImage)) fail("controller images must be digest pinned");
  const namespace = `buzz-${payload.session_id.replaceAll("-", "").slice(0, 12)}`;
  const cpu = splitLimit(payload.limits.cpu_millicores, 100);
  const memory = splitLimit(payload.limits.memory_mib, 256);
  const capabilitySha256 = sha256Hex(canonicalJson(options.envelope));
  const agentRuntimePayload = {
    version: 1,
    role: "agent",
    task_id: payload.task_id,
    session_id: payload.session_id,
    agent_id: payload.agent_id,
    project_id: payload.project_id,
    workspace_id: payload.workspace_id,
    capability_sha256: capabilitySha256,
    operation: payload.task.operation,
    input_sha256: payload.task.input_sha256,
    expires_at: payload.expires_at,
    limits: structuredClone(payload.limits),
    assigned: { cpu_millicores: cpu.agent, memory_mib: memory.agent },
  };
  const browserRuntimePayload = {
    version: 1,
    role: "browser",
    session_id: payload.session_id,
    expires_at: payload.expires_at,
    wall_seconds: payload.limits.wall_seconds,
    assigned: { cpu_millicores: cpu.browser, memory_mib: memory.browser },
  };
  const derivedRuntime = signEnvelope(agentRuntimePayload, options.runtimeSigningKey, options.runtimeKeyId);
  const browserRuntime = signEnvelope(browserRuntimePayload, options.runtimeSigningKey, options.runtimeKeyId);
  const runtimeEvidence = {
    agent: {
      derived_runtime_sha256: sha256Hex(canonicalJson(derivedRuntime)),
      cpu_millicores: cpu.agent,
      memory_mib: memory.agent,
    },
    browser: {
      derived_runtime_sha256: sha256Hex(canonicalJson(browserRuntime)),
      cpu_millicores: cpu.browser,
      memory_mib: memory.browser,
    },
  };
  const labels = {
    "buzz.final-form/managed": "true",
    "buzz.final-form/session-id": payload.session_id,
  };
  const agent = secureContainer({
    name: "agent",
    image: options.agentImage,
    uid: 10001,
    cpu: cpu.agent,
    memory: memory.agent,
    command: ["/usr/local/bin/verify-derived-runtime"],
    args: ["--role", "agent", "--trust-key", "/etc/buzz-controller/controller-runtime.pub", "--config", "/run/buzz-derived/config.json", "--", "/usr/local/bin/buzz-acp"],
    env: [
      { name: "BUZZ_CPU_MILLICORES", valueFrom: { resourceFieldRef: { containerName: "agent", resource: "limits.cpu", divisor: "1m" } } },
      { name: "BUZZ_MEMORY_MIB", valueFrom: { resourceFieldRef: { containerName: "agent", resource: "limits.memory", divisor: "1Mi" } } },
    ],
    volumeMounts: [
      { name: "workspace", mountPath: "/workspace" },
      { name: "derived-agent-runtime", mountPath: "/run/buzz-derived", readOnly: true },
      { name: "agent-tmp", mountPath: "/tmp" },
    ],
  });
  const browser = secureContainer({
    name: "browser",
    image: options.browserImage,
    uid: 10002,
    cpu: cpu.browser,
    memory: memory.browser,
    command: ["/usr/local/bin/verify-derived-runtime"],
    args: ["--role", "browser", "--trust-key", "/etc/buzz-controller/controller-runtime.pub", "--config", "/run/buzz-derived/config.json", "--", "chromium", "--no-first-run", "--disable-dev-shm-usage", "--disable-background-networking", "--user-data-dir=/home/browser/profile", "about:blank"],
    env: [
      { name: "BUZZ_CPU_MILLICORES", valueFrom: { resourceFieldRef: { containerName: "browser", resource: "limits.cpu", divisor: "1m" } } },
      { name: "BUZZ_MEMORY_MIB", valueFrom: { resourceFieldRef: { containerName: "browser", resource: "limits.memory", divisor: "1Mi" } } },
    ],
    volumeMounts: [
      { name: "derived-browser-runtime", mountPath: "/run/buzz-derived", readOnly: true },
      { name: "browser-profile", mountPath: "/home/browser/profile" },
      { name: "browser-tmp", mountPath: "/tmp" },
    ],
  });

  const items = [
    {
      apiVersion: "v1", kind: "Namespace",
      metadata: {
        name: namespace,
        annotations: { "buzz.final-form/expires-at": payload.expires_at },
        labels: { ...labels, "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest" },
      },
    },
    {
      apiVersion: "v1", kind: "ResourceQuota", metadata: { name: "workspace-limits", namespace },
      spec: { hard: {
        "limits.cpu": `${payload.limits.cpu_millicores}m`,
        "limits.memory": `${payload.limits.memory_mib}Mi`,
        "requests.cpu": `${payload.limits.cpu_millicores}m`,
        "requests.memory": `${payload.limits.memory_mib}Mi`,
        "requests.storage": `${payload.limits.storage_bytes}`,
        persistentvolumeclaims: "1",
        "count/jobs.batch": "1",
      } },
    },
    { apiVersion: "v1", kind: "ServiceAccount", metadata: { name: "workspace-agent", namespace }, automountServiceAccountToken: false },
    {
      apiVersion: "v1", kind: "ConfigMap", metadata: { name: "derived-agent-runtime", namespace, annotations: { "buzz.final-form/derived-runtime-sha256": runtimeEvidence.agent.derived_runtime_sha256 } },
      immutable: true,
      data: { "config.json": canonicalJson(derivedRuntime) },
    },
    {
      apiVersion: "v1", kind: "ConfigMap", metadata: { name: "derived-browser-runtime", namespace, annotations: { "buzz.final-form/derived-runtime-sha256": runtimeEvidence.browser.derived_runtime_sha256 } },
      immutable: true,
      data: { "config.json": canonicalJson(browserRuntime) },
    },
    {
      apiVersion: "v1", kind: "PersistentVolumeClaim", metadata: { name: "workspace", namespace },
      spec: { accessModes: ["ReadWriteOnce"], resources: { requests: { storage: `${payload.limits.storage_bytes}` } } },
    },
    {
      apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: { name: "default-deny", namespace },
      spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] },
    },
    {
      apiVersion: "batch/v1", kind: "Job", metadata: { name: "workspace", namespace, labels },
      spec: {
        backoffLimit: 0,
        activeDeadlineSeconds: payload.limits.wall_seconds,
        ttlSecondsAfterFinished: Math.min(600, payload.limits.wall_seconds),
        template: {
          metadata: { labels: { ...labels, "app.kubernetes.io/name": "buzz-workspace" } },
          spec: {
            serviceAccountName: "workspace-agent",
            automountServiceAccountToken: false,
            shareProcessNamespace: false,
            restartPolicy: "Never",
            terminationGracePeriodSeconds: 60,
            securityContext: { runAsNonRoot: true, seccompProfile: { type: "RuntimeDefault" }, fsGroup: 10001 },
            containers: [agent, browser],
            initContainers: [],
            volumes: [
              { name: "workspace", persistentVolumeClaim: { claimName: "workspace" } },
              { name: "derived-agent-runtime", configMap: { name: "derived-agent-runtime", optional: false, defaultMode: 256 } },
              { name: "derived-browser-runtime", configMap: { name: "derived-browser-runtime", optional: false, defaultMode: 256 } },
              { name: "agent-tmp", emptyDir: { sizeLimit: "1Gi" } },
              { name: "browser-profile", emptyDir: { sizeLimit: "2Gi" } },
              { name: "browser-tmp", emptyDir: { sizeLimit: "1Gi" } },
            ],
          },
        },
      },
    },
  ];
  const manifest = { apiVersion: "v1", kind: "List", items };
  const inventory = items.map(object => `${object.apiVersion}|${object.kind}|${object.metadata.namespace ?? "<cluster>"}|${object.metadata.name}`);
  const networkPolicies = new Map(items.filter(object => object.kind === "NetworkPolicy").map(object => [object.metadata.name, structuredClone(object.spec)]));
  const plan = {
    namespace,
    sessionId: payload.session_id,
    inventory,
    networkPolicies,
    workloadContainers: new Map([
      [`batch/v1|Job|${namespace}|workspace`, { containers: ["agent", "browser"], initContainers: [], ephemeralContainers: [] }],
    ]),
    allowedVolumeSources: new Set(["persistentVolumeClaim", "configMap", "emptyDir"]),
    allowedSecretVolumes: new Set(),
    expectedManifestSha256: sha256Hex(canonicalJson(manifest)),
  };
  return { namespace, manifest, plan, derivedRuntime, browserRuntime, runtimeEvidence };
}

export function validateControllerManifest(manifest, plan) {
  validateClosedWorldManifest(manifest, plan);
  if (sha256Hex(canonicalJson(manifest)) !== plan.expectedManifestSha256) fail("controller manifest differs from the verified closed-world plan");
  const job = manifest.items.find(object => object.kind === "Job");
  const containers = job?.spec?.template?.spec?.containers ?? [];
  if (containers.length !== 2 || containers.map(container => container.name).join(",") !== "agent,browser") fail("controller workload container inventory differs");
  const [agent, browser] = containers;
  if (agent.securityContext.runAsUser === browser.securityContext.runAsUser) fail("agent and browser must use distinct UIDs");
  if ((browser.volumeMounts ?? []).some(mount => mount.name === "derived-agent-runtime")) fail("browser must not receive agent authority configuration");
  if (!(browser.volumeMounts ?? []).some(mount => mount.name === "derived-browser-runtime")) fail("browser must receive only its bounded derived runtime");
  if (canonicalJson(browser).includes("capability") || canonicalJson(browser).includes("signature") || canonicalJson(browser).includes("--no-sandbox")) fail("browser contains forbidden authority or sandbox configuration");
  if (manifest.items.some(object => object.kind === "Secret")) fail("raw capability Secrets are forbidden from workspace manifests");
  return true;
}

export function verifyDerivedRuntime(derivedRuntime, evidence, role, trustedKeys) {
  if (!new Set(["agent", "browser"]).has(role)) fail("derived runtime role is invalid");
  const payload = verifyEnvelope(derivedRuntime, trustedKeys, "controller-runtime");
  if (payload.role !== role) fail("derived runtime role mismatch");
  const expected = {
    derived_runtime_sha256: sha256Hex(canonicalJson(derivedRuntime)),
    cpu_millicores: payload.assigned?.cpu_millicores,
    memory_mib: payload.assigned?.memory_mib,
  };
  if (!isDeepStrictEqual(evidence, expected)) fail("runtime environment mismatch");
  return true;
}

export class DisposableWorkspaceController {
  constructor({ audience, now = () => new Date(), ledger, trustedKeys, agentImage, browserImage, runtimeSigningKey, runtimeKeyId }) {
    this.audience = audience;
    this.now = now;
    this.ledger = ledger;
    this.trustedKeys = trustedKeys;
    this.agentImage = agentImage;
    this.browserImage = browserImage;
    this.runtimeSigningKey = runtimeSigningKey;
    this.runtimeKeyId = runtimeKeyId;
    this.renderCount = 0;
  }

  createWorkspace({ envelope, expected }) {
    const payload = verifyEnvelope(envelope, this.trustedKeys, "final-form");
    validateCapability(payload, expected, this.audience, this.now());
    if (this.ledger.isCancelled(payload.jti)) fail("capability is cancelled");
    const capabilityDigest = sha256Hex(canonicalJson(envelope));
    const created = buildManifest(payload, {
      envelope,
      agentImage: this.agentImage,
      browserImage: this.browserImage,
      runtimeSigningKey: this.runtimeSigningKey,
      runtimeKeyId: this.runtimeKeyId,
    });
    validateControllerManifest(created.manifest, created.plan);
    this.ledger.admit({
      jti: payload.jti,
      sessionId: payload.session_id,
      namespace: created.namespace,
      expiresAt: payload.expires_at,
      capabilityDigest,
      concurrencyScope: `${payload.concurrency_scope.kind}:${payload.concurrency_scope.subject}`,
      maxConcurrency: payload.limits.max_concurrency,
    });
    this.renderCount += 1;
    return created;
  }

  cleanupWorkspace({ namespace, sessionId, mode, terminalAcceptance }) {
    const record = this.ledger.workspace(sessionId);
    if (!record || record.namespace !== namespace) fail("cleanup ownership mismatch");
    if (record.cleaned) return { status: "already-cleaned", namespace, sessionId };
    if (mode === "terminal-result") {
      validateTerminalAcceptance(terminalAcceptance, this.trustedKeys, sessionId);
    } else if (mode === "expiration") {
      if (this.now().getTime() < Date.parse(record.expiresAt)) fail("workspace is not expired");
    } else {
      fail("cleanup mode is invalid");
    }
    this.ledger.markCleaned(sessionId);
    return {
      status: "delete-approved",
      namespace,
      preconditions: {
        session_id: sessionId,
        managed_label: "true",
        capability_sha256: record.capabilityDigest,
      },
    };
  }
}

function validateTerminalAcceptance(envelope, trust, sessionId) {
  if (!envelope) fail("terminal cleanup requires a signed FINAL-FORM acceptance receipt");
  const acceptance = verifyEnvelope(envelope, trust, "final-form");
  requireExactKeys(acceptance, ["version", "receipt_kind", "session_id", "result_envelope_sha256", "transfer_envelope_sha256", "decision"], "terminal acceptance");
  if (acceptance.version !== 1 || acceptance.receipt_kind !== "final-form-acceptance") fail("terminal cleanup requires a signed FINAL-FORM acceptance receipt");
  if (acceptance.session_id !== sessionId) fail("terminal acceptance session binding mismatch");
  requireSha(acceptance.result_envelope_sha256, "terminal result digest");
  if (!Array.isArray(acceptance.transfer_envelope_sha256) || acceptance.transfer_envelope_sha256.some(digest => !SHA256.test(digest))) fail("terminal transfer digests are invalid");
  if (!new Set(["accepted", "rejected"]).has(acceptance.decision)) fail("terminal acceptance decision is invalid");
  return acceptance;
}

function matchingBindings(payload, expected, where) {
  for (const field of ["task_id", "session_id", "agent_id", "project_id", "workspace_id"]) {
    if (payload[field] !== expected[field]) fail(`${where} authority binding mismatch`);
  }
}

function validateArtifact(artifact) {
  requireExactKeys(artifact, ["path", "bytes", "sha256", "media_type"], "artifact");
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(artifact.path);
  } catch {
    fail("artifact path encoding is unsafe");
  }
  const unsafePath = path => typeof path !== "string" || path.startsWith("/") || path.includes("\\") || path.includes(":") || path.split("/").some(segment => !segment || segment === "." || segment === "..");
  if (unsafePath(artifact.path) || unsafePath(decodedPath)) fail("artifact path is unsafe");
  requireInteger(artifact.bytes, 0, Number.MAX_SAFE_INTEGER, "artifact bytes");
  requireSha(artifact.sha256, "artifact digest");
  if (typeof artifact.media_type !== "string" || artifact.media_type.length === 0) fail("artifact media type missing");
}

export function verifyArtifactChain({ capabilityEnvelope, resultEnvelope, transferEnvelopes, acceptanceEnvelope, trust }) {
  const capability = verifyEnvelope(capabilityEnvelope, trust, "final-form");
  const result = verifyEnvelope(resultEnvelope, trust, "worker");
  const acceptance = verifyEnvelope(acceptanceEnvelope, trust, "final-form");
  requireExactKeys(result, ["version", "task_id", "session_id", "agent_id", "project_id", "workspace_id", "capability_sha256", "status", "artifacts"], "result receipt");
  requireExactKeys(acceptance, ["version", "task_id", "session_id", "agent_id", "project_id", "workspace_id", "result_envelope_sha256", "transfer_envelope_sha256", "decision"], "acceptance receipt");
  if (result.version !== 2 || acceptance.version !== 2) fail("receipt version is invalid");
  if (!new Set(["succeeded", "failed", "cancelled"]).has(result.status)) fail("result status is invalid");
  if (!new Set(["accepted", "rejected"]).has(acceptance.decision)) fail("acceptance decision is invalid");
  const capabilitySha256 = sha256Hex(canonicalJson(capabilityEnvelope));
  const resultSha256 = sha256Hex(canonicalJson(resultEnvelope));
  matchingBindings(result, capability, "result");
  if (result.capability_sha256 !== capabilitySha256) fail("result capability digest mismatch");
  if (!Array.isArray(result.artifacts) || result.artifacts.length === 0) fail("result artifacts missing");
  result.artifacts.forEach(validateArtifact);
  if (new Set(result.artifacts.map(artifact => artifact.path)).size !== result.artifacts.length) fail("duplicate artifact path");
  const artifactLimit = capability.limits?.artifact_bytes;
  requireInteger(artifactLimit, 0, Number.MAX_SAFE_INTEGER, "artifact byte limit");
  let artifactBytes = 0;
  for (const artifact of result.artifacts) {
    if (artifact.bytes > artifactLimit - artifactBytes) fail("artifact byte limit exceeded");
    artifactBytes += artifact.bytes;
  }
  const transferDigests = [];
  if (!Array.isArray(transferEnvelopes) || transferEnvelopes.length !== result.artifacts.length) fail("transfer receipt count mismatch");
  for (const [index, envelope] of transferEnvelopes.entries()) {
    const transfer = verifyEnvelope(envelope, trust, "broker");
    requireExactKeys(transfer, ["version", "task_id", "session_id", "agent_id", "project_id", "workspace_id", "capability_sha256", "result_envelope_sha256", "operation", "artifact"], "transfer receipt");
    if (transfer.version !== 2 || transfer.operation !== "fake-upload") fail("transfer operation is invalid");
    matchingBindings(transfer, capability, "transfer");
    if (transfer.capability_sha256 !== capabilitySha256 || transfer.result_envelope_sha256 !== resultSha256) fail("transfer digest binding mismatch");
    validateArtifact(transfer.artifact);
    if (!isDeepStrictEqual(transfer.artifact, result.artifacts[index])) fail("transfer artifact binding mismatch");
    transferDigests.push(sha256Hex(canonicalJson(envelope)));
  }
  matchingBindings(acceptance, capability, "acceptance");
  if (acceptance.result_envelope_sha256 !== resultSha256) fail("acceptance result digest mismatch");
  if (!isDeepStrictEqual(acceptance.transfer_envelope_sha256, transferDigests)) fail("acceptance transfer digest mismatch");
  if (!new Set(["accepted", "rejected"]).has(acceptance.decision)) fail("acceptance decision invalid");
  return true;
}
