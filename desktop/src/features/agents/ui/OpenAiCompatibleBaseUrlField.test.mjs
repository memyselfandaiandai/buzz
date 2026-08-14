import assert from "node:assert/strict";
import test from "node:test";

import { openAiCompatibleBaseUrlError } from "./OpenAiCompatibleBaseUrlField.tsx";

test("OpenAI-compatible base URL accepts only absolute HTTP(S) URLs", () => {
  assert.equal(openAiCompatibleBaseUrlError("http://localhost:11434/v1"), null);
  assert.equal(
    openAiCompatibleBaseUrlError(" https://models.example/v1/ "),
    null,
  );
  assert.equal(openAiCompatibleBaseUrlError(""), "Base URL is required.");
  assert.equal(
    openAiCompatibleBaseUrlError("ftp://models.example/v1"),
    "Enter a valid HTTP or HTTPS URL.",
  );
  assert.equal(
    openAiCompatibleBaseUrlError("localhost:11434/v1"),
    "Enter a valid HTTP or HTTPS URL.",
  );
});
