//! FASE 4 (v0.5.0-SHIP): multi-harness `hook --harness <name>` end-to-end
//! CLI tests.
//!
//! Contract under test (real subprocess, real stdin pipe):
//! 1. **windsurf** — `pre_run_command` / `pre_mcp_tool_use`: a dangerous
//!    command BLOCKS with exit 2 and the reason on STDERR (its only read
//!    channel); benign commands exit 0 silently.
//! 2. **cursor** — `beforeShellExecution` / `beforeMCPExecution`: the verdict
//!    lives in the stdout JSON (`permission: deny`) and the process ALWAYS
//!    exits 0; allow is silent.
//! 3. **antigravity** — claude-like PreToolUse payload: deny =
//!    `{"allow_tool": false, "deny_reason": …}` with exit 0 (a non-zero exit
//!    would read as a hook failure); allow silent.
//! 4. Malformed/unknown stdin fails OPEN on every harness (exit 0, no output).
//! 5. The default (`--harness claude`, and the flag omitted entirely) stays
//!    BYTE-IDENTICAL to the pre-0.5 behavior: nested deny JSON + stderr
//!    mirror + exit 2.
//!
//! Every invocation runs with HOME pointed at a fresh tempdir (and that dir
//! as cwd) so neither the developer's configs nor repo-level files can leak
//! into the config loader.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// Fresh unique temp dir (isolated HOME/cwd for one CLI invocation).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-harness-cli-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run `apohara-agentguard hook [--harness h]` with `stdin_json` piped in,
/// HOME isolated to `home`.
fn run_hook(home: &Path, harness: Option<&str>, stdin_json: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"));
    cmd.arg("hook");
    if let Some(h) = harness {
        cmd.args(["--harness", h]);
    }
    let mut child = cmd
        .current_dir(home)
        .env("HOME", home)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn apohara-agentguard hook");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_json.as_bytes());
    }
    child.wait_with_output().expect("wait for hook")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// (1) windsurf
// ---------------------------------------------------------------------------

#[test]
fn windsurf_pre_run_command_blocks_via_stderr_exit_2() {
    let home = temp_dir("ws-block");
    let out = run_hook(
        &home,
        Some("windsurf"),
        r#"{"hook_event_name":"pre_run_command","command":"rm -rf ~"}"#,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "windsurf blocks through exit 2; stdout={} stderr={}",
        stdout_of(&out),
        stderr_of(&out)
    );
    // The reason travels on STDERR (the channel windsurf reads); stdout is
    // not part of its contract.
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
    let err = stderr_of(&out);
    assert!(!err.trim().is_empty(), "stderr must carry the block reason");
    assert!(
        err.contains("rm -rf"),
        "reason should name the offense: {err}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn windsurf_benign_command_is_silent_exit_0() {
    let home = temp_dir("ws-allow");
    let out = run_hook(
        &home,
        Some("windsurf"),
        r#"{"hook_event_name":"pre_run_command","command":"ls -la"}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_of(&out).is_empty());
    assert!(stderr_of(&out).is_empty());

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn windsurf_mcp_command_shaped_args_hit_the_gate() {
    let home = temp_dir("ws-mcp-gate");
    let out = run_hook(
        &home,
        Some("windsurf"),
        r#"{"hook_event_name":"pre_mcp_tool_use","tool_name":"shell","args":{"command":"rm -rf ~"}}"#,
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("rm -rf"));

    // A command-free MCP call fails open (allow, silent).
    let out = run_hook(
        &home,
        Some("windsurf"),
        r#"{"hook_event_name":"pre_mcp_tool_use","tool_name":"notes","args":{"query":"todo"}}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_of(&out).is_empty() && stderr_of(&out).is_empty());

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (2) cursor
// ---------------------------------------------------------------------------

#[test]
fn cursor_shell_block_is_deny_json_with_exit_0() {
    let home = temp_dir("cur-block");
    let out = run_hook(&home, Some("cursor"), r#"{"command":"rm -rf ~"}"#);
    // Exit codes are NOT the cursor signal: the verdict lives in the body.
    assert_eq!(
        out.status.code(),
        Some(0),
        "non-zero exits read as hook crashes there; stderr={}",
        stderr_of(&out)
    );
    assert!(stderr_of(&out).is_empty());
    let v: Value = serde_json::from_str(stdout_of(&out).trim()).expect("deny JSON on stdout");
    assert_eq!(v["permission"], "deny", "{v}");
    let msg = v["user_message"].as_str().expect("user_message string");
    assert!(msg.contains("rm -rf"), "{msg}");
    assert_eq!(
        v.as_object().unwrap().len(),
        2,
        "exactly the documented fields"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cursor_allow_is_silent_exit_0_and_mcp_gates_by_args() {
    let home = temp_dir("cur-allow-mcp");
    let out = run_hook(&home, Some("cursor"), r#"{"command":"ls -la"}"#);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_of(&out).is_empty());
    assert!(stderr_of(&out).is_empty());

    // beforeMCPExecution with a command-shaped args object → gated.
    let out = run_hook(
        &home,
        Some("cursor"),
        r#"{"tool_name":"shell","args":{"command":"rm -rf ~"}}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_str(stdout_of(&out).trim()).expect("deny JSON");
    assert_eq!(v["permission"], "deny");

    // Command-free MCP call → fail open.
    let out = run_hook(
        &home,
        Some("cursor"),
        r#"{"tool_name":"search","args":{"query":"docs"}}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_of(&out).is_empty());

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (3) antigravity
// ---------------------------------------------------------------------------

#[test]
fn antigravity_deny_is_allow_tool_false_exit_0_without_stderr() {
    let home = temp_dir("ag-block");
    let out = run_hook(
        &home,
        Some("antigravity"),
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}"#,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "a non-zero exit reads as a HOOK failure for its plugin loader; stderr={}",
        stderr_of(&out)
    );
    assert!(stderr_of(&out).is_empty(), "no stderr noise on its channel");
    let v: Value = serde_json::from_str(stdout_of(&out).trim()).expect("deny JSON on stdout");
    assert_eq!(v["allow_tool"], false);
    assert!(
        v["deny_reason"]
            .as_str()
            .is_some_and(|r| r.contains("rm -rf")),
        "{v}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn antigravity_allow_is_silent_exit_0() {
    let home = temp_dir("ag-allow");
    let out = run_hook(
        &home,
        Some("antigravity"),
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_of(&out).is_empty());
    assert!(stderr_of(&out).is_empty());

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (4) Fail-open discipline across harnesses
// ---------------------------------------------------------------------------

#[test]
fn malformed_and_unknown_stdin_fails_open_on_every_new_harness() {
    let payloads = [
        "not json at all",
        "{}",
        r#"{"hook_event_name":"some_future_event","command":"rm -rf ~"}"#,
        "", // empty stdin
    ];
    for harness in ["windsurf", "cursor", "antigravity"] {
        for p in payloads {
            let home = temp_dir("failopen");
            let out = run_hook(&home, Some(harness), p);
            assert_eq!(
                out.status.code(),
                Some(0),
                "harness={harness} payload={p:?}: must fail OPEN"
            );
            assert!(
                stdout_of(&out).is_empty() && stderr_of(&out).is_empty(),
                "harness={harness} payload={p:?}: fail-open must be silent"
            );
            let _ = std::fs::remove_dir_all(&home);
        }
    }
}

// ---------------------------------------------------------------------------
// (5) Default byte-identity (claude default == flag-less historical path)
// ---------------------------------------------------------------------------

#[test]
fn default_harness_is_claude_and_stays_byte_identical() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}"#;

    let home = temp_dir("default-flagless");
    let plain = run_hook(&home, None, payload);
    let _ = std::fs::remove_dir_all(&home);

    let home = temp_dir("explicit-claude");
    let explicit = run_hook(&home, Some("claude"), payload);
    let _ = std::fs::remove_dir_all(&home);

    assert_eq!(plain.status.code(), Some(2));
    assert_eq!(plain.status.code(), explicit.status.code());
    assert_eq!(stdout_of(&plain), stdout_of(&explicit));
    assert_eq!(stderr_of(&plain), stderr_of(&explicit));

    // And the shape is the canonical nested deny (unchanged since 0.1).
    let v: Value = serde_json::from_str(stdout_of(&plain).trim()).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");

    // codex rides the same wire family explicitly.
    let home = temp_dir("codex-explicit");
    let codex = run_hook(&home, Some("codex"), payload);
    assert_eq!(codex.status.code(), Some(2));
    assert_eq!(stdout_of(&codex), stdout_of(&plain));
    assert_eq!(stderr_of(&codex), stderr_of(&plain));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn unknown_harness_name_is_rejected_by_the_cli() {
    let home = temp_dir("bad-harness");
    let out = run_hook(&home, Some("vscode"), r#"{}"#);
    assert_ne!(
        out.status.code(),
        Some(0),
        "clap must reject an unsupported harness name"
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("--harness") || err.contains("invalid"),
        "the error should name the offending flag: {err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
