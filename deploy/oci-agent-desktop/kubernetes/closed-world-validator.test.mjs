import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const render = join(here, "render-session.mjs");
const validate = join(here, "validate-session.mjs");

async function renderedManifest() {
  const dir = await mkdtemp(join(tmpdir(), "buzz-closed-world-"));
  const path = join(dir, "session.json");
  const run = spawnSync(process.execPath, [render, "--out", path, "--session", "11111111-1111-4111-8111-111111111111"], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  return { dir, path, manifest: JSON.parse(await readFile(path, "utf8")) };
}

async function fixture(name) {
  return JSON.parse(await readFile(join(here, "fixtures", name), "utf8"));
}

async function expectRejected(mutator) {
  const { dir, path, manifest } = await renderedManifest();
  try {
    await mutator(manifest);
    await writeFile(path, JSON.stringify(manifest));
    const run = spawnSync(process.execPath, [validate, path], { encoding: "utf8" });
    assert.notEqual(run.status, 0, `validator accepted adversarial manifest: ${run.stdout}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("rejects an appended privileged workload", async () => {
  await expectRejected(async manifest => {
    const object = await fixture("appended-privileged-job.json");
    object.metadata.namespace = manifest.items[0].metadata.name;
    manifest.items.push(object);
  });
});

test("rejects an additional policy that widens egress", async () => {
  await expectRejected(async manifest => {
    const object = await fixture("widening-network-policy.json");
    object.metadata.namespace = manifest.items[0].metadata.name;
    manifest.items.push(object);
  });
});

test("rejects duplicate named objects", async () => {
  await expectRejected(async manifest => {
    manifest.items.push(structuredClone(manifest.items.find(item => item.kind === "Job")));
  });
});

test("rejects mutation of the named egress policy", async () => {
  await expectRejected(async manifest => {
    const policy = manifest.items.find(item => item.kind === "NetworkPolicy" && item.metadata.name === "desktop-egress");
    policy.spec.egress = [{ to: [{ ipBlock: { cidr: "0.0.0.0/0" } }] }];
  });
});

test("inspects every init and ephemeral container", async () => {
  await expectRejected(async manifest => {
    const pod = manifest.items.find(item => item.kind === "Job").spec.template.spec;
    const malicious = {
      name: "escape",
      image: `example.invalid/escape@sha256:${"f".repeat(64)}`,
      securityContext: {
        privileged: true,
        allowPrivilegeEscalation: true,
        readOnlyRootFilesystem: false,
        capabilities: { drop: [] },
      },
    };
    pod.initContainers = [structuredClone(malicious)];
    pod.ephemeralContainers = [structuredClone(malicious)];
  });
});

test("rejects root, unmasked proc, and any re-added capability", async () => {
  await expectRejected(async manifest => {
    const container = manifest.items.find(item => item.kind === "Job").spec.template.spec.containers[0];
    container.securityContext.runAsNonRoot = false;
    container.securityContext.procMount = "Unmasked";
    container.securityContext.capabilities.add = ["CHOWN"];
  });
});

test("rejects projected service-account tokens and unapproved volume sources", async () => {
  await expectRejected(async manifest => {
    const pod = manifest.items.find(item => item.kind === "Job").spec.template.spec;
    pod.volumes.push({
      name: "token",
      projected: { sources: [{ serviceAccountToken: { path: "token", audience: "escape" } }] },
    });
    pod.containers[0].volumeMounts.push({ name: "token", mountPath: "/var/run/escape" });
  });
});

test("rejects an additional container even when its security context is restricted", async () => {
  await expectRejected(async manifest => {
    const pod = manifest.items.find(item => item.kind === "Job").spec.template.spec;
    const sidecar = structuredClone(pod.containers[0]);
    sidecar.name = "unexpected-sidecar";
    pod.containers.push(sidecar);
  });
});
