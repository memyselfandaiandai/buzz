import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const renderer = fileURLToPath(new URL("./render-session.mjs", import.meta.url));
const session = "33333333-3333-4333-8333-333333333333";

function render(extra = []) {
  const dir = mkdtempSync(join(tmpdir(), "buzz-render-policy-"));
  const out = join(dir, "session.json");
  const result = spawnSync(process.execPath, [renderer, "--out", out, "--session", session, ...extra], { encoding: "utf8" });
  return {
    result,
    manifest: result.status === 0 ? JSON.parse(readFileSync(out, "utf8")) : undefined,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("renderer treats agent text as data rather than JSON syntax", () => {
  const attempted = render(["--agent", "agent-alpha\",\"injected\":\"true"]);
  try {
    assert.equal(attempted.result.status, 0, attempted.result.stderr);
    const namespace = attempted.manifest.items.find(object => object.kind === "Namespace");
    assert.equal(namespace.metadata.annotations.injected, undefined);
    assert.equal(namespace.metadata.annotations["buzz.final-form/agent-id"], "agent-alpha\",\"injected\":\"true");
  } finally {
    attempted.cleanup();
  }
});

test("renderer rejects namespace override instead of creating arbitrary names", () => {
  const attempted = render(["--namespace", "production"]);
  try {
    assert.notEqual(attempted.result.status, 0);
    assert.match(attempted.result.stderr, /namespace.*generated|override/i);
  } finally {
    attempted.cleanup();
  }
});

test("renderer rejects invalid session identifiers", () => {
  const dir = mkdtempSync(join(tmpdir(), "buzz-render-invalid-"));
  const out = join(dir, "session.json");
  try {
    const result = spawnSync(process.execPath, [renderer, "--out", out, "--session", "not-a-uuid"], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /session.*uuid/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("renderer rejects expiration beyond the bounded two-hour fixture TTL", () => {
  const attempted = render(["--expires", "2099-01-01T00:00:00.000Z"]);
  try {
    assert.notEqual(attempted.result.status, 0);
    assert.match(attempted.result.stderr, /ttl|two.hour|7200/i);
  } finally {
    attempted.cleanup();
  }
});

test("renderer generates the namespace from the session ID", () => {
  const attempted = render();
  try {
    assert.equal(attempted.result.status, 0, attempted.result.stderr);
    const namespace = attempted.manifest.items.find(object => object.kind === "Namespace");
    assert.equal(namespace.metadata.name, "buzz-333333333333");
  } finally {
    attempted.cleanup();
  }
});
