//! End-to-end test of the MCP stdio server: spawns the real
//! `apohara-agentguard mcp` binary and drives newline-delimited JSON-RPC over
//! its stdin/stdout pipes.
//!
//! Framing (pinned from `src/mcp/mod.rs`): one JSON-RPC object per line in,
//! one response line out, responses strictly in request order; the process
//! exits when stdin closes.
//!
//! Observed response shapes this file asserts against:
//!
//! initialize ->
//!   {"jsonrpc":"2.0","id":1,"result":{
//!     "protocolVersion":"2024-11-05",
//!     "capabilities":{"tools":{}},
//!     "serverInfo":{"name":"apohara-agentguard","version":"<pkg version>"}}}
//!
//! tools/list ->
//!   {"jsonrpc":"2.0","id":2,"result":{"tools":[
//!     {"name":"check_command","description":"...","inputSchema":{"type":"object",...}},
//!     {"name":"scan_prompt","description":"...","inputSchema":{"type":"object",...}}]}}
//!
//! tools/call check_command {"command":"rm -rf ~"} ->
//!   {"jsonrpc":"2.0","id":3,"result":{
//!     "content":[{"type":"text","text":"<verdict JSON, same bytes as structuredContent>"}],
//!     "structuredContent":{"tier":"block",
//!                          "reason":"blocked dangerous leg `rm -rf ~` (destructive [rm-rf])",
//!                          "feedback":"This command was blocked because ..."},
//!     "isError":false}}
//!
//! malformed line ("not json") ->
//!   {"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error: invalid JSON"}}
//!   Pinned current behavior: a per-line JSON-RPC parse error with null id;
//!   the server neither panics nor exits — it keeps serving later lines.

use std::io::Write as _;
use std::process::{Command, Stdio};

use serde_json::Value;

/// Fresh empty cwd so neither a stray `./agentguard.toml` in the repo nor a
/// policy env var can perturb the gate's default verdicts (same pattern as
/// `tests/check_cli.rs`).
fn temp_cwd() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-mcp-stdio-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp cwd");
    dir
}

fn spawn_mcp(cwd: &std::path::Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"))
        .arg("mcp")
        .current_dir(cwd)
        // Make sure the env kill-switch / policy override aren't inherited
        // from the test runner.
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn apohara-agentguard mcp")
}

/// Write every request line, then drop stdin (closing the pipe) so the server
/// drains its loop, answers everything, and exits on EOF. Responses are tiny
/// and strictly ordered, well under the pipe buffer, so write-all-then-read
/// cannot deadlock.
fn run_session(requests: &str) -> std::process::Output {
    let cwd = temp_cwd();
    let mut child = spawn_mcp(&cwd);
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(requests.as_bytes())
        .expect("write all requests then close stdin");
    let out = child.wait_with_output().expect("collect mcp output");
    let _ = std::fs::remove_dir_all(&cwd);
    out
}

fn parse_lines(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("stdout line is not JSON: {l:?}: {e}"))
        })
        .collect()
}

#[test]
fn mcp_stdio_full_session_initialize_list_and_call() {
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_command","arguments":{"command":"rm -rf ~"}}}"#,
        "\n",
        // Malformed-line robustness probe, answered last (order preserved).
        "not json\n",
    );
    let out = run_session(requests);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "clean EOF must exit 0; stderr={stderr}"
    );

    let lines = parse_lines(&out.stdout);
    assert_eq!(lines.len(), 4, "one response line per request line");

    // -- (1) initialize -----------------------------------------------------
    let init = &lines[0];
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    assert!(init.get("error").is_none(), "unexpected error: {init}");
    assert!(
        init["result"]["protocolVersion"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "protocolVersion must be a non-empty string: {init}"
    );
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "capabilities must advertise tools: {init}"
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "apohara-agentguard");

    // -- (2) tools/list ------------------------------------------------------
    let list = &lines[1];
    assert_eq!(list["jsonrpc"], "2.0");
    assert_eq!(list["id"], 2);
    assert!(list.get("error").is_none(), "unexpected error: {list}");
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    assert!(
        names.contains(&"check_command") && names.contains(&"scan_prompt"),
        "both tools must be listed; got {names:?}"
    );

    // -- (3) tools/call check_command "rm -rf ~" -----------------------------
    let call = &lines[2];
    assert_eq!(call["jsonrpc"], "2.0");
    assert_eq!(call["id"], 3);
    assert!(call.get("error").is_none(), "unexpected error: {call}");
    assert_eq!(call["result"]["isError"], false);
    // The structured verdict is the real payload field set:
    // tier is the snake_case Tier ("block"), reason names the matched leg.
    assert_eq!(call["result"]["structuredContent"]["tier"], "block");
    let reason = call["result"]["structuredContent"]["reason"]
        .as_str()
        .expect("reason string");
    assert!(
        reason.contains("blocked dangerous leg"),
        "reason must state the block; got {reason:?}"
    );
    assert!(
        reason.contains("rm -rf ~") && reason.contains("destructive"),
        "reason must name the command and its category; got {reason:?}"
    );
    // The canonical MCP text content block mirrors the structured verdict
    // byte-for-byte (it IS the serialized Verdict).
    assert_eq!(call["result"]["content"][0]["type"], "text");
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("text block");
    let from_text: Value = serde_json::from_str(text).expect("text block must be the verdict JSON");
    assert_eq!(from_text, call["result"]["structuredContent"]);

    // -- (4) malformed line --------------------------------------------------
    // Current behavior (pinned): per-line parse error, null id, code -32700;
    // the session above kept serving lines after it.
    let malformed = &lines[3];
    assert_eq!(malformed["jsonrpc"], "2.0");
    assert!(malformed["id"].is_null());
    assert_eq!(malformed["error"]["code"], -32700);
}

#[test]
fn mcp_stdio_malformed_only_session_still_exits_cleanly() {
    // Pins robustness in isolation: garbage input yields exactly one parse
    // error response and a clean exit — no panic, no hang, no crash-loop.
    let out = run_session("not json\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "garbage input must still exit cleanly on EOF; stderr={stderr}"
    );
    let lines = parse_lines(&out.stdout);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert!(lines[0]["id"].is_null());
}
