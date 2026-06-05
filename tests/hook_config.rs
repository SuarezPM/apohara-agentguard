//! The user's TOML config is honored at the hook layer (not just by the gate
//! in isolation). These tests thread an explicit `Config` through `hook::run`
//! to prove allow_list, custom_blocks, and the `disable` kill-switch all take
//! effect on the Bash gate path. Passing the config directly keeps the tests
//! hermetic (no stray `./agentguard.toml` from default-location lookup).

use agentguard::config::{Config, CustomBlock};
use agentguard::hook::run;
use serde_json::Value;

/// Build a PreToolUse + Bash stdin JSON for `cmd`.
fn pretooluse_bash(cmd: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd },
    })
    .to_string()
}

#[test]
fn allow_list_is_honored_at_hook_layer() {
    let cmd = "rm -rf /tmp/build";

    // Sanity: with default config this command WOULD be flagged (blocked).
    let (_, code_default) = run(&pretooluse_bash(cmd), &Config::default());
    assert_eq!(
        code_default, 2,
        "baseline: a destructive command must block under default config"
    );

    // With the same command on the user allow_list, the hook returns Allow.
    let cfg = Config {
        allow_list: vec![cmd.to_string()],
        ..Config::default()
    };
    let (out, code) = run(&pretooluse_bash(cmd), &cfg);
    assert!(
        out.is_none(),
        "an allow-listed command must produce no blocking output"
    );
    assert_eq!(
        code, 0,
        "the user allow_list must be honored at the hook layer (exit 0)"
    );
}

#[test]
fn custom_block_is_honored_at_hook_layer() {
    // A command that is benign by default becomes a Block via a user custom rule.
    let cmd = "deploy --prod";
    let (_, code_default) = run(&pretooluse_bash(cmd), &Config::default());
    assert_eq!(code_default, 0, "baseline: command is benign by default");

    let cfg = Config {
        custom_blocks: vec![CustomBlock {
            pattern: "deploy --prod".to_string(),
            severity: 9,
            category: "policy".to_string(),
        }],
        ..Config::default()
    };
    let (out, code) = run(&pretooluse_bash(cmd), &cfg);
    assert_eq!(
        code, 2,
        "the user custom_blocks must be honored at the hook layer (exit 2)"
    );
    let v: Value = serde_json::from_str(&out.expect("block emits JSON")).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn config_disable_allows_dangerous_bash() {
    // The kill-switch via config (not the env var) must allow everything.
    let cfg = Config {
        disable: true,
        ..Config::default()
    };
    let (out, code) = run(&pretooluse_bash("rm -rf ~"), &cfg);
    assert!(
        out.is_none(),
        "config.disable must produce no blocking output"
    );
    assert_eq!(code, 0, "config.disable must allow a dangerous command");
}
