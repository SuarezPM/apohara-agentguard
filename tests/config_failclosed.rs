//! Fail-closed config semantics (Story D1): a PRESENT-but-malformed
//! `agentguard.toml` must never be silently discarded.
//!
//! Contract under test:
//! 1. Malformed TOML in a default location ⇒ the CLI prints a loud stderr
//!    diagnostic (naming the file / offending key) and exits 2. For `hook`,
//!    exit 2 IS the deny signal, so a broken config fails closed.
//! 2. Unknown keys are rejected (`deny_unknown_fields`) — both in the user
//!    config schema and in the policy-file schema.
//! 3. NO config anywhere ⇒ silent defaults, byte-identical behavior
//!    (`check` on a benign command exits 0 with empty stderr).
//!
//! Every CLI invocation runs in a fresh temp cwd with `HOME` pointed at it
//! and `XDG_CONFIG_HOME` removed, so the developer's real config can never
//! perturb the verdicts.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use apohara_agentguard::config::Config;
use apohara_agentguard::policy::schema::PolicyFile;

/// Fresh unique temp dir (cwd + isolated HOME for one CLI invocation).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-config-failclosed-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run the compiled binary in `cwd` with an isolated HOME (no XDG override,
/// no inherited kill-switch/policy env). `stdin_text` is fed to the process
/// when given (used by the `hook` subcommand).
fn run_cli(cwd: &Path, args: &[&str], stdin_text: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"));
    cmd.args(args)
        .current_dir(cwd)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .env("HOME", cwd)
        .env_remove("XDG_CONFIG_HOME");
    match stdin_text {
        Some(text) => {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().expect("spawn apohara-agentguard");
            child
                .stdin
                .take()
                .expect("stdin piped")
                .write_all(text.as_bytes())
                .expect("write stdin");
            child.wait_with_output().expect("wait for output")
        }
        None => cmd.output().expect("run apohara-agentguard"),
    }
}

// ---------------------------------------------------------------------------
// (a) Malformed TOML ⇒ exit 2 + loud stderr diagnostic
// ---------------------------------------------------------------------------

#[test]
fn malformed_config_check_exits_2_with_diagnostic() {
    let dir = temp_dir("malformed-check");
    std::fs::write(dir.join("agentguard.toml"), "allow_list = [").expect("write malformed config");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a present-but-malformed config must fail closed (exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agentguard.toml"),
        "diagnostic must name the config file: {stderr}"
    );
    assert!(
        stderr.contains("failing closed"),
        "diagnostic must state the fail-closed posture: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_config_hook_denies_fail_closed() {
    // The security-critical surface: even a benign command must be DENIED
    // (exit 2) while the config is unreadable — never silently allowed.
    let dir = temp_dir("malformed-hook");
    std::fs::write(dir.join("agentguard.toml"), "this is not = valid toml [")
        .expect("write malformed config");
    let stdin_json = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls -la" },
    })
    .to_string();

    let out = run_cli(&dir, &["hook"], Some(&stdin_json));
    assert_eq!(
        out.status.code(),
        Some(2),
        "hook must deny (exit 2) on a malformed config; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr_text = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr_text.contains("agentguard.toml"),
        "hook diagnostic must name the config file; stderr={stderr_text:?} stdout={:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (b) Unknown keys are rejected (deny_unknown_fields)
// ---------------------------------------------------------------------------

#[test]
fn unknown_key_in_config_exits_2_and_names_the_key() {
    let dir = temp_dir("unknown-key-cli");
    std::fs::write(dir.join("agentguard.toml"), "typo_key = true").expect("write config");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown key must be rejected, not ignored; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("typo_key"),
        "diagnostic must carry the offending key name: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_keys_rejected_by_config_schema() {
    // Top level.
    assert!(toml::from_str::<Config>("bogus = 1").is_err());
    // Inside a sub-table.
    assert!(toml::from_str::<Config>("[canary]\nnope = true").is_err());
    // Inside a table-array entry.
    assert!(toml::from_str::<Config>(
        "[[custom_blocks]]\npattern = \"x\"\nseverity = 9\ncategory = \"c\"\nextra = 1"
    )
    .is_err());
}

#[test]
fn unknown_keys_rejected_by_policy_schema() {
    // Top-level policy key.
    assert!(toml::from_str::<PolicyFile>("schema_version = 1\nunknown_section = 1").is_err());
    // Inside [[tools]].
    assert!(toml::from_str::<PolicyFile>(
        "schema_version = 1\n[[tools]]\nname = \"Bash\"\nnickname = \"b\""
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// (c) No config anywhere ⇒ silent defaults (byte-identical behavior)
// ---------------------------------------------------------------------------

#[test]
fn missing_config_is_silent_default_behavior() {
    let dir = temp_dir("missing-defaults");
    // No agentguard.toml written; HOME is the empty temp dir.

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "no config must behave exactly like Config::default(); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "allow",
        "benign command must allow under defaults"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "the missing-file path must stay SILENT (no diagnostic)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn valid_partial_config_still_takes_effect_end_to_end() {
    // Guards against over-tightening: a well-formed partial config keeps
    // working through the new fail-closed loader.
    let dir = temp_dir("valid-partial");
    std::fs::write(dir.join("agentguard.toml"), "allow_list = [\"ls *\"]").expect("write config");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "allow_list must still be honored"
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "allow");

    let _ = std::fs::remove_dir_all(&dir);
}
