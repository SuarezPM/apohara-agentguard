//! Smoke test for the `apohara-agentguard check "<command>"` subcommand.
//!
//! Invokes the compiled binary (Cargo injects its path as
//! `CARGO_BIN_EXE_apohara-agentguard` for integration tests) and asserts the exit code
//! contract: 2 on a Block, 0 otherwise. Run from a fresh temp cwd so a stray
//! `./agentguard.toml` in the repo cannot perturb the verdict.

use std::path::PathBuf;
use std::process::Command;

fn temp_cwd() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-check-cli-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp cwd");
    dir
}

fn run_check(command: &str) -> std::process::Output {
    let cwd = temp_cwd();
    let out = Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"))
        .args(["check", command])
        .current_dir(&cwd)
        // Make sure the env kill-switch isn't inherited from the test runner.
        .env_remove("AGENTGUARD_DISABLE")
        .output()
        .expect("run apohara-agentguard check");
    let _ = std::fs::remove_dir_all(&cwd);
    out
}

#[test]
fn check_dangerous_command_exits_2() {
    let out = run_check("find . -delete");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a destructive command must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).starts_with("block:"),
        "Block must print a `block:` reason to stderr"
    );
}

#[test]
fn check_safe_command_exits_0() {
    let out = run_check("ls -la");
    assert_eq!(out.status.code(), Some(0), "a safe command must exit 0");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "allow");
}

// ============================================================================
// `apohara-agentguard ask '<cmd>'` integration tests (Story 4 — v0.3)
// ============================================================================

/// Run `ask '<cmd>'` with an optional `--policy <path>` (the global
/// flag from Story 2). The temp cwd is the only place a stray config
/// could come from; the test does NOT write any.
fn run_ask(command: &str, policy_path: Option<&std::path::Path>) -> std::process::Output {
    let cwd = temp_cwd();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"));
    cmd.args(["ask", command]);
    if let Some(p) = policy_path {
        cmd.args(["--policy", p.to_str().unwrap()]);
    }
    let out = cmd
        .current_dir(&cwd)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .output()
        .expect("run apohara-agentguard ask");
    let _ = std::fs::remove_dir_all(&cwd);
    out
}

#[test]
fn ask_cli_subcommand_allow() {
    // Benign command, no policy loaded => Allow (the empty-TOML
    // invariant: the engine is a no-op combine, the result is
    // byte-identical to `check`).
    let out = run_ask("ls -la", None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "ask 'ls -la' must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "allow",
        "ask 'ls -la' must print 'allow'"
    );
}

#[test]
fn ask_cli_subcommand_block() {
    // Dangerous command, no policy loaded => Block (the gate catches
    // it; exit 2; stderr carries the reason).
    let out = run_ask("rm -rf ~", None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "ask 'rm -rf ~' must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).starts_with("block: "),
        "Block must print a `block: ` reason to stderr"
    );
}

#[test]
fn ask_cli_subcommand_ask_with_budget_policy() {
    // A policy with `budgets.per_tool.Bash.max_invocations = 1`:
    // the FIRST Bash call is Allow, the SECOND is Ask (engine
    // escalates to the human). The CLI `ask` subcommand prints
    // `ask: <reason>` to stdout and exits 0 (Ask is a UI prompt,
    // not an error).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-ask-cli-{pid}-{nanos}",
        pid = std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let policy_path = dir.join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
schema_version = 1
[defaults]
default_action = "allow"
[budgets.per_tool.Bash]
max_invocations = 1
"#,
    )
    .unwrap();

    // The CLI does not share a process across invocations (each
    // `Command::new(...).output()` is a fresh process), so the
    // per-session budget counter resets per run. We exercise the
    // Ask path by having ONE call exceed the cap in a single run
    // — i.e., we need the per-invocation budget to be 0, so
    // the first call is also Ask. Adjust: set
    // `max_invocations = 0` so any Bash call is over budget.
    std::fs::write(
        &policy_path,
        r#"
schema_version = 1
[defaults]
default_action = "allow"
[budgets.per_tool.Bash]
max_invocations = 0
"#,
    )
    .unwrap();

    let out = run_ask("ls", Some(&policy_path));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The first Bash call exceeds max_invocations=0 (0 invocations
    // are allowed; 1 > 0), so the engine returns Ask. The CLI
    // prints `ask: <reason>` to stdout and exits 0.
    assert_eq!(
        out.status.code(),
        Some(0),
        "Ask must exit 0 (UI prompt, not error); stderr={stderr}"
    );
    assert!(
        stdout.trim().starts_with("ask: "),
        "Ask must print `ask: <reason>` to stdout; got stdout={stdout:?}"
    );
    assert!(
        stdout.contains("budget"),
        "reason should mention budget; got {stdout:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// Reason neutralization on the CLI surface (Wave U1 — CLI-reasons)
// ============================================================================

/// Run `check '<cmd>'` with an `agentguard.toml` written into the fresh
/// temp cwd (the highest-priority default config location), so the gate
/// sees deterministic custom_blocks. The config dies with the cwd.
fn run_check_with_config(command: &str, config_toml: &str) -> std::process::Output {
    let cwd = temp_cwd();
    std::fs::write(cwd.join("agentguard.toml"), config_toml).expect("write agentguard.toml");
    let out = Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"))
        .args(["check", command])
        .current_dir(&cwd)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .output()
        .expect("run apohara-agentguard check");
    let _ = std::fs::remove_dir_all(&cwd);
    out
}

#[test]
fn check_cli_neutralizes_hostile_shaped_content_in_reason() {
    // A custom_blocks category carrying a chat-role pseudo-tag flows
    // verbatim into the printed reason (`custom-block [<category>]`).
    // The CLI must render the NEUTRALIZED form (single guillemets) — the
    // same display-layer transform the MCP surface applies to
    // verdict.reason — never the raw tag.
    let config = r#"
[[custom_blocks]]
pattern = "deploy-prod"
severity = 9
category = "exfil <system>"
"#;
    let out = run_check_with_config("echo deploy-prod", config);
    assert_eq!(
        out.status.code(),
        Some(2),
        "severity 9 >= default block_at 8 must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("block: "),
        "Block must keep the `block: ` prefix; got {stderr:?}"
    );
    assert!(
        stderr.contains('\u{2039}') && stderr.contains("system\u{203a}"),
        "reason must carry the masked pseudo-tag form; got {stderr:?}"
    );
    assert!(
        !stderr.contains("<system>"),
        "raw pseudo-tag must never reach the terminal; got {stderr:?}"
    );
}

#[test]
fn check_cli_identity_ordinary_reason_passes_through_unchanged() {
    // Identity guarantee: an ordinary destructive-command reason contains
    // nothing the neutralizer acts on, so it reaches the terminal with its
    // content unchanged (same prose the pre-neutralization CLI printed).
    let out = run_check("rm -rf ~");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr.starts_with("block: blocked dangerous leg"),
        "prefix + reason prose must be unchanged; got {stderr:?}"
    );
    assert!(
        stderr.contains("`rm -rf ~`") && stderr.contains("(destructive [rm-rf])"),
        "ordinary reason must pass through semantically unchanged; got {stderr:?}"
    );
}
