import { readFile } from "node:fs/promises";
import { legacySessionPolicy, validateClosedWorldManifest } from "./manifest-policy.mjs";

const file = process.argv[2];
if (!file) throw new Error("usage: node validate-session.mjs RENDERED_SESSION.json");
const manifest = JSON.parse(await readFile(file, "utf8"));
validateClosedWorldManifest(manifest, legacySessionPolicy(manifest));

const role = manifest.items.find(object => object.kind === "Role");
if (!role) throw new Error("missing Role");
const forbidden = new Set(["*", "bind", "escalate", "impersonate", "patch", "update"]);
for (const rule of role.rules ?? []) {
  if ((rule.verbs ?? []).some(verb => forbidden.has(verb))) throw new Error(`forbidden RBAC verb in Role/${role.metadata.name}`);
  if ((rule.resources ?? []).includes("namespaces")) throw new Error("namespace mutation is forbidden");
}

const job = manifest.items.find(object => object.kind === "Job");
if (!job || job.spec?.activeDeadlineSeconds > 7200 || job.spec?.ttlSecondsAfterFinished > 600) throw new Error("Job lifecycle exceeds policy");
if (!(job.spec?.template?.spec?.volumes ?? []).some(volume => volume.persistentVolumeClaim?.claimName === "workspace")) throw new Error("workspace PVC mount missing");
console.log("session manifest closed-world isolation PASS");
