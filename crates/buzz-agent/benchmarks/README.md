# Keyless tool-exposure evaluation

This protocol compares Buzz Agent's default `full` catalog with the opt-in
`anchored` first-request catalog without making a model or paid API call. It
uses the existing real-subprocess test convention: the actual `buzz-agent`
binary, the actual fake MCP binary over stdio, and a loopback HTTP server that
replays the same two canned OpenAI-compatible responses in both arms.

Run it from the repository root:

```bash
cargo test -p buzz-agent --test keyless_tool_exposure_eval -- --nocapture
```

The line prefixed `KEYLESS_TOOL_EXPOSURE_EVAL=` is a JSON result manifest. It
records process-start-to-initialize latency, MCP session setup latency,
prompt-to-first-provider-request latency, turn wall time, success, provider and
executed-tool-call counts, and the exact digest, byte size, and count of every
model-visible tool schema. Timings are descriptive diagnostics, not test
thresholds, because process scheduling and debug-build state vary by host.

The deterministic acceptance gate is:

- both arms finish the identical replay successfully in two provider requests;
- both execute exactly one tool call through the same complete MCP registry;
- `full` exposes the same complete catalog on both requests;
- `anchored` exposes only the shell anchor first, then exactly the same complete
  catalog and digest as `full`;
- the anchored first-request schema is smaller on the wire;
- no credential other than a local sentinel is present and all HTTP is bound to
  `127.0.0.1`.

This evaluator intentionally does not claim a model-quality or production
latency win. A later paid A/B must hold model, prompt, task corpus, provider,
machine, and tool registry constant and predeclare success scoring. Run it only
after explicit approval for provider usage.

Scheduler projection and claim latency are not included here: they belong to
the lifecycle store's separate keyless load gate and cannot be measured through
the agent wire protocol without coupling this test to lifecycle internals. Run
the existing gate separately with:

```bash
cargo test -p buzz-lifecycle --test scheduler_load -- --ignored --nocapture
```

Join its result with this evaluator by commit SHA rather than adding lifecycle
replay to the agent-wire evaluator.
