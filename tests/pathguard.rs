//! Path-guard integration tests: secret reads block, ordinary reads allow,
//! sensitive writes block, with case-insensitive + `~` normalization.
//!
//! Tests pass literal paths to `check_path` (hermetic — no filesystem / no
//! `$HOME` dependency) and additionally exercise the full `hook::run` PreToolUse
//! path for the `.env` read case to prove the tool-level deny.

use agentguard::config::Config;
use agentguard::hook::pathguard::check_path;
use agentguard::hook::run;
use agentguard::verdict::Tier;
use serde_json::Value;

#[test]
fn read_env_blocks_at_tool_level() {
    // Drive the full hook: PreToolUse + Read of `.env` must DENY (exit 2).
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": ".env" },
    })
    .to_string();

    let (out, code) = run(&input, &Config::default());
    assert_eq!(code, 2, ".env read must block (exit 2)");
    let v: Value = serde_json::from_str(&out.expect("deny JSON")).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn read_secret_blocks() {
    assert_eq!(check_path("Read", ".env", false).tier, Tier::Block);
    assert_eq!(
        check_path("Read", "config/.env.local", false).tier,
        Tier::Block
    );
    assert_eq!(check_path("Read", "server.pem", false).tier, Tier::Block);
    assert_eq!(check_path("Read", "id_rsa", false).tier, Tier::Block);
    assert_eq!(
        check_path("Read", "aws_credentials", false).tier,
        Tier::Block
    );
}

#[test]
fn read_ordinary_source_allows() {
    assert_eq!(check_path("Read", "src/main.rs", false).tier, Tier::Allow);
    assert_eq!(check_path("Read", "Cargo.toml", false).tier, Tier::Allow);
    assert_eq!(
        check_path("Read", "/home/u/project/notes.md", false).tier,
        Tier::Allow
    );
}

#[test]
fn write_to_ssh_authorized_keys_blocks() {
    assert_eq!(
        check_path("Write", "~/.ssh/authorized_keys", true).tier,
        Tier::Block
    );
}

#[test]
fn write_ordinary_file_allows() {
    assert_eq!(
        check_path("Write", "src/new_module.rs", true).tier,
        Tier::Allow
    );
    assert_eq!(check_path("Edit", "tests/foo.rs", true).tier, Tier::Allow);
}

#[test]
fn case_insensitive_match_on_secrets() {
    // NTFS/APFS case-insensitivity: `.ENV` must be caught like `.env`.
    assert_eq!(check_path("Read", ".ENV", false).tier, Tier::Block);
    assert_eq!(check_path("Read", "Server.PEM", false).tier, Tier::Block);
    assert_eq!(check_path("Read", "ID_RSA", false).tier, Tier::Block);
}

#[test]
fn tilde_expansion_guards_ssh() {
    // The `~/.ssh/...` shape is guarded regardless of $HOME resolution.
    assert_eq!(check_path("Read", "~/.ssh/id_rsa", false).tier, Tier::Block);
    assert_eq!(
        check_path("Read", "~\\.ssh\\known_hosts", false).tier,
        Tier::Block
    );
    // Windows %USERPROFILE% form.
    assert_eq!(
        check_path("Read", "%USERPROFILE%\\.ssh\\id_rsa", false).tier,
        Tier::Block
    );
}
