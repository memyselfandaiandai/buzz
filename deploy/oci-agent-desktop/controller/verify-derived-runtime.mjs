#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalJson, sha256Hex, verifyDerivedRuntime } from "./controller.mjs";

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  if (argv.length < 8 || argv[0] !== "--role" || !argv[1] || argv[2] !== "--trust-key" || !argv[3] || argv[4] !== "--config" || !argv[5] || argv[6] !== "--") {
    fail("usage: verify-derived-runtime --role agent|browser --trust-key FILE --config FILE -- COMMAND [ARG ...]");
  }
  if (!new Set(["agent", "browser"]).has(argv[1])) fail("runtime role is invalid");
  if (!argv[7]) fail("verified child command is required");
  return { role: argv[1], trustKey: argv[3], config: argv[5], command: argv[7], args: argv.slice(8) };
}

function integerEnvironment(name) {
  const raw = process.env[name];
  if (!/^(0|[1-9][0-9]*)$/.test(raw ?? "")) fail(`${name} must be a non-negative integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) fail(`${name} is outside the safe integer range`);
  return value;
}

async function main() {
  const parsed = parseArguments(process.argv.slice(2));
  const derivedRuntime = JSON.parse(await readFile(parsed.config, "utf8"));
  const publicKey = createPublicKey(await readFile(parsed.trustKey, "utf8"));
  const trustedKeys = new Map([[derivedRuntime.key_id, { publicKey, role: "controller-runtime" }]]);
  const evidence = {
    derived_runtime_sha256: sha256Hex(canonicalJson(derivedRuntime)),
    cpu_millicores: integerEnvironment("BUZZ_CPU_MILLICORES"),
    memory_mib: integerEnvironment("BUZZ_MEMORY_MIB"),
  };
  verifyDerivedRuntime(derivedRuntime, evidence, parsed.role, trustedKeys);

  const expiresAt = Date.parse(derivedRuntime.payload.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) fail("derived runtime is expired");
  const wallSeconds = parsed.role === "agent" ? derivedRuntime.payload.limits?.wall_seconds : derivedRuntime.payload.wall_seconds;
  if (!Number.isSafeInteger(wallSeconds) || wallSeconds < 1) fail("derived runtime wall limit is invalid");
  const lifetimeMs = Math.min(wallSeconds * 1000, expiresAt - Date.now());

  const child = spawn(parsed.command, parsed.args, {
    stdio: "inherit",
    shell: false,
    windowsHide: true,
    env: process.env,
  });
  let forceTimer;
  const deadlineTimer = setTimeout(() => {
    if (!child.killed) child.kill("SIGTERM");
    forceTimer = setTimeout(() => {
      if (!child.killed) child.kill("SIGKILL");
    }, 5_000);
  }, lifetimeMs);
  const forward = signal => {
    if (!child.killed) child.kill(signal);
  };
  process.on("SIGTERM", forward);
  process.on("SIGINT", forward);
  const result = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(deadlineTimer);
  if (forceTimer) clearTimeout(forceTimer);
  process.off("SIGTERM", forward);
  process.off("SIGINT", forward);
  if (result.signal) process.kill(process.pid, result.signal);
  process.exitCode = result.code ?? 1;
}

main().catch(error => {
  console.error(`worker verification failed: ${error.message}`);
  process.exitCode = 1;
});
