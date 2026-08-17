//! Keyless matched evaluation of `full` and `anchored` tool exposure.
//!
//! This is deliberately an integration test rather than a benchmark framework:
//! it drives the real `buzz-agent` and fake MCP subprocesses over their wire
//! protocols while a loopback HTTP server replays identical provider output.
//! No provider account, API key, or network access is used.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const TOOL_COUNT: usize = 12;

#[derive(Debug)]
struct CapturedRequest {
    body: Value,
    received_at: Instant,
}

struct ReplayLlm {
    url: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

async fn spawn_replay_llm(responses: Vec<Value>) -> ReplayLlm {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captures = Arc::clone(&captured);

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let responses = Arc::clone(&responses);
            let captures = Arc::clone(&captures);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 8192];
                while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                    }
                    if buffer.len() > 4_000_000 {
                        return;
                    }
                }

                let header_end = buffer
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let headers = String::from_utf8_lossy(&buffer[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buffer.len() < header_end + content_length {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                    }
                }

                let body = match serde_json::from_slice::<Value>(
                    &buffer[header_end..header_end + content_length],
                ) {
                    Ok(body) => body,
                    Err(_) => return,
                };
                captures.lock().await.push(CapturedRequest {
                    body,
                    received_at: Instant::now(),
                });

                let response = responses
                    .lock()
                    .await
                    .pop_front()
                    .unwrap_or_else(|| json!({ "error": "replay exhausted" }));
                let response = serde_json::to_string(&response).unwrap();
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response,
                );
                let _ = socket.write_all(wire.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    ReplayLlm { url, captured }
}

struct Harness {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    next_id: i64,
    spawned_at: Instant,
}

impl Harness {
    async fn spawn(base_url: &str, exposure: &str) -> Self {
        let spawned_at = Instant::now();
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_buzz-agent"));
        command
            .env("BUZZ_AGENT_PROVIDER", "openai")
            .env("OPENAI_COMPAT_API_KEY", "keyless-local-replay")
            .env("OPENAI_COMPAT_MODEL", "fake-model")
            .env("OPENAI_COMPAT_BASE_URL", base_url)
            .env("BUZZ_AGENT_TOOL_EXPOSURE", exposure)
            .env("BUZZ_AGENT_LLM_TIMEOUT_SECS", "5")
            .env("BUZZ_AGENT_TOOL_TIMEOUT_SECS", "5")
            .env("BUZZ_AGENT_MAX_ROUNDS", "4")
            .env("BUZZ_AGENT_MCP_INIT_TIMEOUT_SECS", "2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().expect("spawn buzz-agent");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
            spawned_at,
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.write(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .await;
        id
    }

    async fn write(&mut self, message: Value) {
        let mut line = serde_json::to_string(&message).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        let bytes = tokio::time::timeout(Duration::from_secs(15), self.stdout.read_line(&mut line))
            .await
            .expect("agent response timeout")
            .expect("read agent response");
        assert!(bytes > 0, "agent exited before responding");
        serde_json::from_str(&line).expect("agent emitted non-JSON stdout")
    }

    async fn receive_id(&mut self, expected_id: i64) -> Value {
        loop {
            let message = self.receive().await;
            if message.get("method") == Some(&json!("session/request_permission")) {
                self.write(json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "outcome": { "outcome": "selected", "optionId": "allow" }
                    },
                }))
                .await;
                continue;
            }
            if message["id"] == json!(expected_id) {
                return message;
            }
        }
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
        let _ = self.child.start_kill();
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaObservation {
    request_index: usize,
    visible_tool_count: usize,
    exact_schema_digest: String,
    serialized_tools_bytes: usize,
    same_as_previous: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunResult {
    exposure: String,
    success: bool,
    startup_to_initialize_us: u128,
    session_setup_us: u128,
    prompt_to_first_provider_request_us: u128,
    turn_wall_us: u128,
    provider_requests: usize,
    executed_tool_calls: usize,
    full_catalog_count: usize,
    full_catalog_digest: String,
    schema_transitions: Vec<SchemaObservation>,
}

fn openai_tool_call() -> Value {
    json!({
        "id": "replay-tool",
        "object": "chat.completion",
        "model": "fake-model",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": { "name": "fake__tool_0", "arguments": "{}" },
                }],
            },
            "finish_reason": "tool_calls",
        }],
    })
}

fn openai_text() -> Value {
    json!({
        "id": "replay-text",
        "object": "chat.completion",
        "model": "fake-model",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": "done" },
            "finish_reason": "stop",
        }],
    })
}

fn exact_schema_digest(tools: &Value) -> String {
    let bytes = serde_json::to_vec(tools).unwrap();
    hex::encode(Sha256::digest(bytes))
}

fn tool_call_results(request: &Value) -> usize {
    request["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|message| message["role"] == "tool")
        .count()
}

async fn run(exposure: &str) -> RunResult {
    let replay = spawn_replay_llm(vec![openai_tool_call(), openai_text()]).await;
    let mut harness = Harness::spawn(&replay.url, exposure).await;

    let initialize = harness
        .request(
            "initialize",
            json!({ "protocolVersion": 1, "clientCapabilities": {} }),
        )
        .await;
    let initialize_response = harness.receive_id(initialize).await;
    assert_eq!(
        initialize_response["result"]["agentInfo"]["name"],
        "buzz-agent"
    );
    let startup_to_initialize_us = harness.spawned_at.elapsed().as_micros();

    let session_started = Instant::now();
    let fake_mcp = env!("CARGO_BIN_EXE_fake-mcp");
    let session = harness
        .request(
            "session/new",
            json!({
                "cwd": std::env::temp_dir(),
                "mcpServers": [{
                    "name": "fake",
                    "command": fake_mcp,
                    "args": [],
                    "env": [
                        { "name": "FAKE_MCP_TOOL_COUNT", "value": TOOL_COUNT.to_string() },
                        { "name": "FAKE_MCP_SHELL_TOOL", "value": "1" },
                    ],
                }],
            }),
        )
        .await;
    let session_response = harness.receive_id(session).await;
    let session_id = session_response["result"]["sessionId"]
        .as_str()
        .expect("session id")
        .to_owned();
    let session_setup_us = session_started.elapsed().as_micros();

    let prompt_started = Instant::now();
    let prompt = harness
        .request(
            "session/prompt",
            json!({
                "sessionId": session_id,
                "prompt": [{ "type": "text", "text": "matched replay task" }],
            }),
        )
        .await;
    let completion = harness.receive_id(prompt).await;
    let turn_wall_us = prompt_started.elapsed().as_micros();

    let captures = replay.captured.lock().await;
    assert_eq!(
        captures.len(),
        2,
        "replay must make exactly two provider requests"
    );
    let prompt_to_first_provider_request_us = captures[0]
        .received_at
        .saturating_duration_since(prompt_started)
        .as_micros();

    let mut previous_digest: Option<String> = None;
    let mut schema_transitions = Vec::new();
    for (request_index, capture) in captures.iter().enumerate() {
        let tools = &capture.body["tools"];
        let serialized_tools_bytes = serde_json::to_vec(tools).unwrap().len();
        let exact_schema_digest = exact_schema_digest(tools);
        let same_as_previous = previous_digest.as_ref() == Some(&exact_schema_digest);
        schema_transitions.push(SchemaObservation {
            request_index,
            visible_tool_count: tools.as_array().map_or(0, Vec::len),
            exact_schema_digest: exact_schema_digest.clone(),
            serialized_tools_bytes,
            same_as_previous,
        });
        previous_digest = Some(exact_schema_digest);
    }
    let executed_tool_calls = tool_call_results(&captures[1].body);
    let full_catalog = schema_transitions
        .iter()
        .max_by_key(|observation| observation.visible_tool_count)
        .unwrap();
    let result = RunResult {
        exposure: exposure.to_owned(),
        success: completion["result"]["stopReason"] == "end_turn",
        startup_to_initialize_us,
        session_setup_us,
        prompt_to_first_provider_request_us,
        turn_wall_us,
        provider_requests: captures.len(),
        executed_tool_calls,
        full_catalog_count: full_catalog.visible_tool_count,
        full_catalog_digest: full_catalog.exact_schema_digest.clone(),
        schema_transitions,
    };
    drop(captures);
    harness.shutdown().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matched_full_and_anchored_replays_emit_comparable_metrics() {
    let full = run("full").await;
    let anchored = run("anchored").await;

    assert!(full.success && anchored.success);
    assert_eq!(full.provider_requests, 2);
    assert_eq!(anchored.provider_requests, 2);
    assert_eq!(full.executed_tool_calls, 1);
    assert_eq!(anchored.executed_tool_calls, 1);
    assert_eq!(full.full_catalog_count, TOOL_COUNT + 1);
    assert_eq!(anchored.full_catalog_count, TOOL_COUNT + 1);
    assert_eq!(full.full_catalog_digest, anchored.full_catalog_digest);

    assert_eq!(
        full.schema_transitions[0].visible_tool_count,
        TOOL_COUNT + 1
    );
    assert!(full.schema_transitions[1].same_as_previous);
    assert_eq!(anchored.schema_transitions[0].visible_tool_count, 1);
    assert!(!anchored.schema_transitions[1].same_as_previous);
    assert_eq!(
        anchored.schema_transitions[1].exact_schema_digest,
        full.schema_transitions[0].exact_schema_digest
    );
    assert!(
        anchored.schema_transitions[0].serialized_tools_bytes
            < full.schema_transitions[0].serialized_tools_bytes
    );

    let report = json!({
        "protocolVersion": 1,
        "kind": "buzz-agent-keyless-tool-exposure-eval",
        "timingsAreDescriptiveOnly": true,
        "runs": [full, anchored],
    });
    eprintln!(
        "KEYLESS_TOOL_EXPOSURE_EVAL={}",
        serde_json::to_string(&report).unwrap()
    );
}
