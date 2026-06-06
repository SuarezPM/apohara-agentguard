//! US-H: OpenAI Codex PreToolUse hook wiring.
//!
//! Codex (developers.openai.com/codex/hooks) ships a PreToolUse hook whose
//! documented release wire format intentionally mirrors Claude Code's: the same
//! snake_case keys (`hook_event_name`, `tool_name`, `tool_input.command`) and
//! the same block contract (`hookSpecificOutput.permissionDecision="deny"` /
//! exit 2). These tests drive a representative Codex-shaped stdin JSON through
//! the SAME engine seam the Claude Code hook uses (`hook::run`) and assert it
//! parses and dispatches to a sensible verdict — a dangerous Bash command still
//! Blocks (exit 2, nested deny).
//!
//! HONESTY / ASSUMPTION TO RE-VERIFY: the payloads below reflect the Codex hooks
//! docs as of 2026-06. Codex's documented release is snake_case; the camelCase
//! variant exercised in `codex_camelcase_alias_*` reflects Codex's *prototype*
//! schema and is handled defensively via additive serde aliases (see
//! `src/hook/contract.rs`). Re-verify field spellings against the current Codex
//! hooks documentation before claiming a hard compatibility guarantee.
//!
//! KNOWN LIMITATION (documented, not a bug): Codex's canonical tool name for
//! file edits is `apply_patch` (with `Edit`/`Write` matcher aliases), whereas
//! the dispatch table only routes `Read`/`Write`/`Edit`. So the pathguard surface
//! does not fire on Codex `apply_patch` inputs; the Bash gate — the core,
//! highest-value surface — works identically across both harnesses.

use apohara_agentguard::config::Config;
use apohara_agentguard::hook::run;
use serde_json::Value;

/// A representative Codex PreToolUse + Bash stdin JSON for `cmd`, including the
/// Codex-specific extras that agentguard must IGNORE (model, permission_mode,
/// turn_id, tool_use_id, transcript_path).
fn codex_pretooluse_bash(cmd: &str) -> String {
    serde_json::json!({
        "session_id": "sess-codex-1",
        "turn_id": "turn-1",
        "transcript_path": null,
        "cwd": "/work",
        "hook_event_name": "PreToolUse",
        "model": "gpt-test",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_use_id": "call-abc",
        "tool_input": { "command": cmd },
    })
    .to_string()
}

#[test]
fn codex_pretooluse_dangerous_bash_blocks_exit_2_nested_deny() {
    let (out, code) = run(&codex_pretooluse_bash("rm -rf ~"), &Config::default());
    assert_eq!(code, 2, "dangerous Codex command must exit 2 (block)");

    let json = out.expect("block must emit stdout JSON");
    let v: Value = serde_json::from_str(&json).expect("valid JSON");

    // Codex honors the same nested deny shape Claude Code does.
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        v["hookSpecificOutput"]["permissionDecisionReason"].is_string(),
        "deny must carry a reason"
    );
    // No bare top-level decision/context.
    assert!(v.get("permissionDecision").is_none());
    assert!(v.get("additionalContext").is_none());
}

#[test]
fn codex_pretooluse_safe_bash_allows_no_output() {
    let (out, code) = run(&codex_pretooluse_bash("ls -la"), &Config::default());
    assert!(
        out.is_none(),
        "safe Codex command must not emit block output"
    );
    assert_eq!(code, 0);
}

#[test]
fn codex_extra_fields_do_not_break_parsing() {
    // model / permission_mode / turn_id / tool_use_id / transcript_path are Codex
    // extras absent from Claude Code; they must be ignored, never rejected. A safe
    // command parsing + allowing is sufficient proof the extras parsed cleanly.
    let (_, code) = run(&codex_pretooluse_bash("echo hello"), &Config::default());
    assert_eq!(code, 0, "Codex extras must parse without error");
}

#[test]
fn codex_camelcase_alias_dangerous_bash_blocks() {
    // ADDITIVE hedge: a camelCase-shaped payload (Codex prototype schema) must
    // still parse and block via the serde aliases in `HookInput`.
    let stdin = serde_json::json!({
        "sessionId": "sess-codex-2",
        "hookEventName": "PreToolUse",
        "toolName": "Bash",
        "toolInput": { "command": "rm -rf ~" },
    })
    .to_string();

    let (out, code) = run(&stdin, &Config::default());
    assert_eq!(code, 2, "camelCase Codex payload must still block (exit 2)");

    let v: Value = serde_json::from_str(&out.expect("block JSON")).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}
