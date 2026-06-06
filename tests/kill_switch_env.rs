//! Kill-switch env tests, isolated in their own integration-test binary.
//!
//! These tests mutate the PROCESS-GLOBAL env var `AGENTGUARD_DISABLE`, which
//! `hook::run` reads. Cargo runs each integration-test file as a SEPARATE
//! PROCESS, so housing them here isolates the mutation from the many
//! `run()`-calling tests in `hook_contract.rs` (no shared process).
//!
//! Within THIS file the env-mutating tests are serialized against each other
//! with `ENV_LOCK`, held for each test's entire body, so a "nothing disabled"
//! sanity assertion can never observe another test's mutation.

use apohara_agentguard::config::Config;
use apohara_agentguard::hook::run;
use serde_json::Value;
use std::sync::Mutex;

/// Serializes the env-mutating tests in this file against each other. Held for
/// each test's whole body so the pre-mutation sanity checks are race-free.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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
fn kill_switch_env_disables_and_is_read_from_hook_process_env() {
    // The switch is read from std::env of the HOOK process (this test process),
    // NOT from the inspected command's env. Hold ENV_LOCK for the whole body so
    // a parallel env-mutating test cannot perturb the sanity check below.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let dangerous = pretooluse_bash("rm -rf ~");

    // Sanity: without the switch the command blocks.
    let (_, code_on) = run(&dangerous, &Config::default());
    assert_eq!(code_on, 2);

    std::env::set_var("AGENTGUARD_DISABLE", "1");
    let (out, code) = run(&dangerous, &Config::default());
    std::env::remove_var("AGENTGUARD_DISABLE");

    assert!(out.is_none(), "env kill-switch must produce no output");
    assert_eq!(code, 0, "env kill-switch must allow (exit 0)");
}

#[test]
fn kill_switch_env_component_list_is_granular_and_read_from_hook_process_env() {
    // US-F1: `AGENTGUARD_DISABLE=gate` disables ONLY the gate (read from this
    // hook process's env), leaving pathguard live. Hold ENV_LOCK for the whole
    // body so a parallel env-mutating test cannot perturb the sanity checks.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let dangerous = pretooluse_bash("rm -rf ~");
    let read_dotenv = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": ".env" },
    })
    .to_string();

    // Sanity: with nothing disabled, both block.
    assert_eq!(run(&dangerous, &Config::default()).1, 2);
    assert_eq!(run(&read_dotenv, &Config::default()).1, 2);

    std::env::set_var("AGENTGUARD_DISABLE", "gate,unknown");
    let (gate_out, gate_code) = run(&dangerous, &Config::default());
    let (guard_out, guard_code) = run(&read_dotenv, &Config::default());
    std::env::remove_var("AGENTGUARD_DISABLE");

    // gate disabled => rm -rf ~ allowed.
    assert!(
        gate_out.is_none(),
        "env gate disable must produce no output"
    );
    assert_eq!(gate_code, 0, "env gate disable must allow (exit 0)");

    // pathguard STILL ON => .env read blocks (unknown token ignored, not all-off).
    assert_eq!(guard_code, 2, "pathguard must still fire");
    let v: Value = serde_json::from_str(&guard_out.expect("block JSON")).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}
