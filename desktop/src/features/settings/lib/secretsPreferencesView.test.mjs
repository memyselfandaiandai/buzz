import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  configureBwsThenTest,
  formatLeaseCountdown,
  leaseSecondsRemaining,
} from "./secretsPreferencesView.ts";

test("lease countdown rounds up and never becomes negative", () => {
  const now = Date.parse("2026-08-20T12:00:00.000Z");
  assert.equal(leaseSecondsRemaining("2026-08-20T12:01:00.001Z", now), 61);
  assert.equal(leaseSecondsRemaining("2026-08-20T11:59:59.000Z", now), 0);
  assert.equal(leaseSecondsRemaining("not-a-date", now), 0);
});

test("lease countdown formatting is compact and explicit at expiry", () => {
  assert.equal(formatLeaseCountdown(0), "expired");
  assert.equal(formatLeaseCountdown(45), "45s");
  assert.equal(formatLeaseCountdown(125), "2m 5s");
});

test("BWS submitted token is released before connectivity starts", async () => {
  const request = {
    accessToken: "test-machine-token",
    projectId: "00000000-0000-0000-0000-000000000001",
    bindings: [],
  };
  let submittedRequest;
  const result = await configureBwsThenTest(
    request,
    async (submitted) => {
      submittedRequest = submitted;
      assert.equal(submitted.accessToken, "test-machine-token");
      return { binding_keys: [] };
    },
    async () => {
      assert.equal(submittedRequest.accessToken, undefined);
      return { ok: true };
    },
  );
  assert.equal(request.accessToken, undefined);
  assert.deepEqual(result, {
    status: { binding_keys: [] },
    testResult: { ok: true },
  });
});

test("BWS submitted token is released when configuration fails", async () => {
  const request = {
    accessToken: "test-machine-token",
    projectId: "00000000-0000-0000-0000-000000000001",
    bindings: [],
  };
  await assert.rejects(
    configureBwsThenTest(
      request,
      async () => {
        throw new Error("generic failure");
      },
      async () => ({ ok: true }),
    ),
    /generic failure/,
  );
  assert.equal(request.accessToken, undefined);
});

test("provider switch and BWS clear erase the uncontrolled token input", () => {
  const source = readFileSync(
    new URL("../ui/SecretsPreferencesCard.tsx", import.meta.url),
    "utf8",
  );
  const selectBackend = source.slice(
    source.indexOf("const selectBackend"),
    source.indexOf("const saveBws"),
  );
  const clearBws = source.slice(
    source.indexOf("const clearBws"),
    source.indexOf("const runTest"),
  );
  assert.doesNotMatch(source, /useState\([^)]*accessToken/i);
  assert.doesNotMatch(source, /const accessToken =/);
  assert.match(source, /useRef<HTMLInputElement>\(null\)/);
  for (const handler of [selectBackend, clearBws]) {
    assert.ok(
      handler.indexOf('accessTokenRef.current.value = "";') <
        handler.indexOf("setBusy(true)"),
    );
    assert.ok(
      handler.lastIndexOf('accessTokenRef.current.value = "";') >
        handler.indexOf("finally"),
    );
  }
});

test("BWS UI configures exact logical-key bindings without rendering UUID metadata", () => {
  const source = readFileSync(
    new URL("../ui/SecretsPreferencesCard.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /logicalKey/);
  assert.match(source, /secretId/);
  assert.match(source, /bindings/);
  assert.doesNotMatch(source, /status\.bws_project_id/);
  assert.doesNotMatch(source, /status\.bws_token_source/);
  assert.doesNotMatch(source, /status\.bws_cli_available/);
});

test("secret backend status exposes binding keys but no provider internals or counts", () => {
  const source = readFileSync(
    new URL("../../../shared/api/secretsPreferences.ts", import.meta.url),
    "utf8",
  );
  const status = source.slice(
    source.indexOf("export interface SecretBackendStatus"),
    source.indexOf("export interface SecretBackendTestResult"),
  );
  assert.match(status, /backend: SecretBackendKind/);
  assert.match(status, /binding_keys: string\[\]/);
  for (const forbidden of [
    "bws_cli_available",
    "bws_token_configured",
    "bws_token_source",
    "bws_project_id",
    "binding_count",
  ]) {
    assert.doesNotMatch(status, new RegExp(forbidden));
  }
});

test("provider status remains available when optional audit loading fails", () => {
  const source = readFileSync(
    new URL("../ui/SecretsPreferencesCard.tsx", import.meta.url),
    "utf8",
  );
  const load = source.slice(
    source.indexOf("const load = useCallback"),
    source.indexOf("useEffect(() =>"),
  );
  assert.doesNotMatch(load, /Promise\.all/);
  assert.ok(
    load.indexOf("setStatus(nextStatus)") <
      load.indexOf("getSecretAccessOverview()"),
  );
  assert.match(load, /try\s*{/);
  assert.match(load, /catch\s*{/);
});
