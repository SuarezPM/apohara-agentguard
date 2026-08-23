//! Contract tests for `packaging/opencode/agentguard-shim.mjs` (Wave U2′.6).
//!
//! The shim is the OpenCode/Kilo plugin transport: a `tool.execute.before`
//! handler that spawns `apohara-agentguard hook` per tool call with the
//! Claude PreToolUse envelope on stdin and translates the verdict:
//! - deny (exit 2 or nested permissionDecision) ⇒ THROW (blocks
//!   pre-permission, YOLO-immune),
//! - warn ⇒ stderr mirror + proceed,
//! - allow ⇒ return undefined,
//! - timeout / spawn error / unexpected exit ⇒ FAIL-CLOSED throw.
//!
//! Hermetic: each case runs `node` in an isolated tempdir HOME with
//! `AGENTGUARD_BIN` pointed at the freshly built binary (block/allow) or at a
//! nonexistent path (fail-closed). A tiny runner snippet imports the shim by
//! file URL and prints the outcome as one JSON line on stdout.
//!
//! If `node` is not installed the behavioral cases SKIP with a clear message
//! (the source-documentation case still runs — it is pure Rust).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The shim under test, compiled into this test binary.
const SHIM_SOURCE: &str = include_str!("../packaging/opencode/agentguard-shim.mjs");

/// The canonical mutation-propagation caveat marker every reader (and the
/// doc-regression guard below) must be able to find in the shim source.
const MUTATION_MARKER: &str = "MUTATION-PROPAGATION CAVEAT";

fn repo_shim_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/opencode/agentguard-shim.mjs")
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fresh unique temp dir (isolated HOME + cwd for one node invocation).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-shim-contract-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The JS runner snippet: import the shim, call `toolExecuteBefore`, print
/// the outcome as ONE JSON line (`{"outcome":"allow",...}` or
/// `{"outcome":"throw","message":...}`).
const RUNNER_SNIPPET: &str = r#"
import { pathToFileURL } from "node:url";
const mod = await import(pathToFileURL(process.env.AGENTGUARD_SHIM_PATH).href);
const input = JSON.parse(process.env.AGENTGUARD_INPUT_JSON);
try {
  const result = await mod.toolExecuteBefore(input, { sessionID: "shim-contract-test" });
  console.log(JSON.stringify({ outcome: "allow", result: result ?? null }));
} catch (e) {
  console.log(JSON.stringify({ outcome: "throw", message: String(e && e.message ? e.message : e) }));
}
"#;

/// Run one shim case under plain node. Returns the parsed outcome JSON line.
fn run_shim_case(home: &Path, agentguard_bin: Option<&str>, input_json: &str) -> serde_json::Value {
    let runner = home.join("runner.mjs");
    std::fs::write(&runner, RUNNER_SNIPPET).expect("write runner snippet");

    let mut cmd = Command::new("node");
    cmd.arg(&runner)
        .current_dir(home)
        .env("HOME", home)
        .env("AGENTGUARD_SHIM_PATH", repo_shim_path())
        .env("AGENTGUARD_INPUT_JSON", input_json)
        // Engine hygiene: no kill-switch, no policy override, no XDG leak.
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match agentguard_bin {
        Some(bin) => {
            cmd.env("AGENTGUARD_BIN", bin);
        }
        None => {
            cmd.env_remove("AGENTGUARD_BIN");
        }
    }
    let out = cmd.output().expect("spawn node");
    assert!(
        out.status.success(),
        "runner itself failed (status {:?}): stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .last()
        .unwrap_or_else(|| panic!("runner printed no JSON line: {stdout:?}"));
    serde_json::from_str(line).unwrap_or_else(|e| panic!("runner output not JSON ({e}): {line}"))
}

// ---------------------------------------------------------------------------
// Block path: dangerous command ⇒ throw carrying the engine reason
// ---------------------------------------------------------------------------

#[test]
fn shim_blocks_dangerous_command_with_engine_reason() {
    if !node_available() {
        println!("skipping: node is not available on PATH");
        return;
    }
    let home = temp_dir("block");
    let out = run_shim_case(
        &home,
        Some(env!("CARGO_BIN_EXE_apohara-agentguard")),
        r#"{"tool":"Bash","args":{"command":"rm -rf /"}}"#,
    );
    assert_eq!(out["outcome"], "throw", "{out}");
    let msg = out["message"].as_str().expect("string message");
    assert!(
        msg.starts_with("blocked by agentguard: "),
        "block wording missing: {msg}"
    );
    assert!(
        msg.len() > "blocked by agentguard: ".len(),
        "block must carry the engine reason: {msg}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Allow path: benign command ⇒ no throw, no mutation (undefined result)
// ---------------------------------------------------------------------------

#[test]
fn shim_allows_benign_command_without_touching_args() {
    if !node_available() {
        println!("skipping: node is not available on PATH");
        return;
    }
    let home = temp_dir("allow");
    let out = run_shim_case(
        &home,
        Some(env!("CARGO_BIN_EXE_apohara-agentguard")),
        r#"{"tool":"Bash","args":{"command":"ls -la"}}"#,
    );
    assert_eq!(out["outcome"], "allow", "{out}");
    assert_eq!(
        out["result"],
        serde_json::Value::Null,
        "the handler must return undefined (no arg mutation): {out}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Fail-closed path: unresolvable binary ⇒ throw with fail-closed wording
// ---------------------------------------------------------------------------

#[test]
fn shim_fails_closed_when_binary_is_missing() {
    if !node_available() {
        println!("skipping: node is not available on PATH");
        return;
    }
    let home = temp_dir("failclosed");
    let out = run_shim_case(
        &home,
        Some("/nonexistent/apohara-agentguard-under-test"),
        r#"{"tool":"Bash","args":{"command":"ls"}}"#,
    );
    assert_eq!(out["outcome"], "throw", "{out}");
    let msg = out["message"].as_str().expect("string message");
    assert!(
        msg.contains("failing closed"),
        "fail-closed wording missing: {msg}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Documentation regression guard (pure Rust — no node needed)
// ---------------------------------------------------------------------------

#[test]
fn shim_source_documents_mutation_propagation_caveat_and_v1_limits() {
    assert!(
        SHIM_SOURCE.contains(MUTATION_MARKER),
        "the shim header must keep the {MUTATION_MARKER} marker: it is the \
         load-bearing documentation that in-place property mutation propagates \
         while replacing the args object does NOT"
    );
    assert!(
        SHIM_SOURCE.contains("NEVER replaces args"),
        "the never-replace rule must stay documented"
    );
    assert!(
        SHIM_SOURCE.contains("REWRITE") && SHIM_SOURCE.contains("U2′"),
        "the REWRITE-not-supported-in-v1 rationale must stay documented"
    );
}
