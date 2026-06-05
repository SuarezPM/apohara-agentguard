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
