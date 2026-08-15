import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const ref = process.argv[2];
if (!ref || !/@sha256:[a-f0-9]{64}$/.test(ref)) throw new Error("usage: node verify-image-platform.mjs IMAGE@sha256:DIGEST");
const proc = spawnSync(process.platform === "win32" ? "docker.exe" : "docker", ["buildx", "imagetools", "inspect", "--raw", ref], { encoding: "utf8" });
if (proc.status !== 0) throw new Error(proc.stderr || `docker exited ${proc.status}`);
const index = JSON.parse(proc.stdout);
const arm64 = (index.manifests ?? []).find(m => m.platform?.os === "linux" && m.platform?.architecture === "arm64");
assert(arm64, `${ref} has no linux/arm64 descriptor`);
assert(/^sha256:[a-f0-9]{64}$/.test(arm64.digest));
console.log(`${ref}\nlinux/arm64 ${arm64.digest}\nimage platform gate PASS`);
