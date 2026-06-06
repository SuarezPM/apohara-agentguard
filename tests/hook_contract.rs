//! Hook contract integration tests: the nested `hookSpecificOutput` shape per
//! tier, the kill-switch, and the length-cap — driven through `hook::run`.

use apohara_agentguard::config::Config;
use apohara_agentguard::hook::contract::MAX_CONTEXT_BYTES;
use apohara_agentguard::hook::run;
use serde_json::Value;

/// Build a PreToolUse + Bash stdin JSON for `cmd`.
fn pretooluse_bash(cmd: &str) -> String {
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd },
    });
    input.to_string()
}

#[test]
fn pretooluse_bash_block_is_nested_deny_exit_2() {
    let (out, code) = run(&pretooluse_bash("rm -rf ~"), &Config::default());
    assert_eq!(code, 2, "dangerous command must exit 2");

    let json = out.expect("block must emit stdout JSON");
    let v: Value = serde_json::from_str(&json).expect("valid JSON");

    // Nested deny — the only shape the harness honors.
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
fn warn_level_is_nested_additional_context_exit_0() {
    // `chmod -R 777 .` is destructive-but-ambiguous -> WARN tier (sev 5..=7).
    let (out, code) = run(&pretooluse_bash("chmod -R 777 ."), &Config::default());
    assert_eq!(code, 0, "warn must exit 0");

    let json = out.expect("warn must emit stdout JSON");
    let v: Value = serde_json::from_str(&json).expect("valid JSON");

    // additionalContext nested under hookSpecificOutput.
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert!(
        v["hookSpecificOutput"]["additionalContext"].is_string(),
        "warn must carry additionalContext"
    );
    // NO bare top-level additionalContext.
    assert!(
        v.get("additionalContext").is_none(),
        "bare top-level additionalContext is ignored by the harness; must not emit it"
    );
    // NO permissionDecision on a warn.
    assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
}

#[test]
fn allow_command_has_no_output_exit_0() {
    let (out, code) = run(&pretooluse_bash("ls -la"), &Config::default());
    assert!(out.is_none(), "allow must not emit blocking output");
    assert_eq!(code, 0);
}

#[test]
fn kill_switch_config_disables_for_dangerous_command() {
    let cfg = Config {
        disable: true,
        ..Config::default()
    };
    let (out, code) = run(&pretooluse_bash("rm -rf ~"), &cfg);
    assert!(out.is_none(), "kill-switch must produce no blocking output");
    assert_eq!(code, 0, "kill-switch must allow (exit 0)");
}

// NOTE: the kill-switch ENV tests live in their own integration-test binary
// (`tests/kill_switch_env.rs`). They mutate the process-global
// `AGENTGUARD_DISABLE`, so they must NOT share a process with the many
// `run()`-calling tests below, which read that env var.

#[test]
fn block_reason_is_length_capped() {
    // A huge allow-list-free custom block produces a long reason; the contract
    // caps additionalContext / permissionDecisionReason to MAX_CONTEXT_BYTES.
    let long_cmd = format!("rm -rf {}", "a/".repeat(5000));
    let (out, code) = run(&pretooluse_bash(&long_cmd), &Config::default());
    assert_eq!(code, 2);

    let json = out.expect("block emits JSON");
    let v: Value = serde_json::from_str(&json).expect("valid JSON");
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("reason string");
    assert!(
        reason.len() <= MAX_CONTEXT_BYTES,
        "reason length {} exceeds cap {}",
        reason.len(),
        MAX_CONTEXT_BYTES
    );
}
