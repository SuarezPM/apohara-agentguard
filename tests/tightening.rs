//! Monotonic tightening of layered configs (Story D3).
//!
//! Contract under test — when BOTH a user config
//! (`$HOME/.config/agentguard/config.toml`) and a project config
//! (`./agentguard.toml`) exist, the project file is an OVERLAY validated
//! tightening-only on top of the user BASE. A project file that LOOSENS any
//! protection field ⇒ loud error naming the offending field ⇒ fail-closed
//! exit 2 through the existing `load_config_fail_closed` path.
//!
//! Single-layer presence keeps the pre-D3 first-match-wins behavior byte-
//! identical; no config anywhere ⇒ silent defaults.
//!
//! Every CLI invocation runs in a fresh temp cwd with `HOME` pointed at it
//! and `XDG_CONFIG_HOME` removed, so the developer's real config can never
//! perturb the verdicts (hermetic pattern from `tests/config_failclosed.rs`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Fresh unique temp dir (cwd + isolated HOME for one CLI invocation).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-tightening-{tag}-{}-{nanos}",
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

/// Write the USER-layer config (`$HOME/.config/agentguard/config.toml`)
/// inside the hermetic cwd.
fn write_user_config(dir: &Path, text: &str) {
    let user_dir = dir.join(".config").join("agentguard");
    std::fs::create_dir_all(&user_dir).expect("create user config dir");
    std::fs::write(user_dir.join("config.toml"), text).expect("write user config");
}

/// Write the PROJECT-layer config (`./agentguard.toml`) inside the hermetic
/// cwd.
fn write_project_config(dir: &Path, text: &str) {
    std::fs::write(dir.join("agentguard.toml"), text).expect("write project config");
}

// ---------------------------------------------------------------------------
// (a) project ADDS an allow_list entry ⇒ exit 2, field named
// ---------------------------------------------------------------------------

#[test]
fn project_adding_allow_list_entry_is_rejected_with_exit_2() {
    let dir = temp_dir("allow-add");
    write_user_config(&dir, "allow_list = [\"ls *\"]");
    write_project_config(&dir, "allow_list = [\"ls *\", \"docker *\"]");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a loosening overlay must fail closed (exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("allow_list") && stderr.contains("docker *"),
        "diagnostic must name the field AND the offending entry: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (b) project RAISES the block threshold cutoff ⇒ exit 2, field named
// ---------------------------------------------------------------------------

#[test]
fn project_raising_block_threshold_is_rejected_with_exit_2() {
    let dir = temp_dir("threshold-raise");
    write_user_config(&dir, "[thresholds]\nblock_at = 7\nwarn_at = 4\n");
    // block_at 9 > user 7: severities 7..=8 stop blocking — a loosening.
    write_project_config(&dir, "[thresholds]\nblock_at = 9\nwarn_at = 4\n");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "raising a cutoff must fail closed (exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("block_at"),
        "diagnostic must name the offending cutoff: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (c) project sets disable=true over a user disable=false ⇒ exit 2
// ---------------------------------------------------------------------------

#[test]
fn project_disabling_the_gate_is_rejected_with_exit_2() {
    let dir = temp_dir("disable-true");
    write_user_config(&dir, "allow_list = []");
    write_project_config(&dir, "disable = true");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the project may not turn the gate off; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disable"),
        "diagnostic must name the disable field: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (d) project TIGHTENS (adds custom_block, narrows allow_list) ⇒ loads,
//     effective config verified end-to-end
// ---------------------------------------------------------------------------

#[test]
fn project_tightening_loads_and_takes_effect() {
    let dir = temp_dir("tighten-ok");
    // User layer: deliberately ALLOWS one dangerous command (allow-list
    // short-circuit) and blocks `shutdown`.
    write_user_config(
        &dir,
        "allow_list = [\"rm -rf /tmp/agentguard-tighten-play\"]\n\
         [[custom_blocks]]\npattern = \"shutdown\"\nseverity = 9\ncategory = \"system\"\n",
    );
    // Project layer: narrows the allowance away AND adds its own block.
    write_project_config(
        &dir,
        "allow_list = []\n\
         [[custom_blocks]]\npattern = \"shutdown\"\nseverity = 9\ncategory = \"system\"\n\
         [[custom_blocks]]\npattern = \"frobnicate\"\nseverity = 9\ncategory = \"test\"\n",
    );

    // Positive control: with ONLY the user layer, the dangerous command is
    // ALLOWED (allow-list short-circuit precedes the gate taxonomy).
    let user_only = temp_dir("tighten-control");
    write_user_config(
        &user_only,
        "allow_list = [\"rm -rf /tmp/agentguard-tighten-play\"]\n",
    );
    let out = run_cli(
        &user_only,
        &["check", "rm -rf /tmp/agentguard-tighten-play"],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "control: user layer alone must still allow its entry; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&user_only);

    // Layered: the narrowed allow_list removed that allowance ⇒ the gate
    // taxonomy now sees the command ⇒ block (exit 2).
    let out = run_cli(
        &dir,
        &["check", "rm -rf /tmp/agentguard-tighten-play"],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "the narrowed allow_list must take effect; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Layered: the project's ADDED custom_block fires.
    let out = run_cli(&dir, &["check", "echo frobnicate"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the added project custom_block must fire; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("frobnicate"),
        "block reason must surface the added pattern"
    );

    // Layered: the user's inherited custom_block STILL fires.
    let out = run_cli(&dir, &["check", "shutdown -h now"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the inherited user custom_block must keep firing; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (e) only the project config present ⇒ identical to today
// ---------------------------------------------------------------------------

#[test]
fn only_project_config_behaves_like_the_old_first_match_loader() {
    let dir = temp_dir("project-only");
    write_project_config(&dir, "allow_list = [\"ls *\"]");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "single project layer must load exactly as before; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "allow");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (f) neither config present ⇒ silent defaults
// ---------------------------------------------------------------------------

#[test]
fn neither_config_present_yields_silent_defaults() {
    let dir = temp_dir("no-configs");

    let out = run_cli(&dir, &["check", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "no configs must behave exactly like Config::default(); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "allow");
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "the missing-file path must stay SILENT (no diagnostic)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// (g) --policy flag precedence unaffected by layering
// ---------------------------------------------------------------------------

#[test]
fn policy_flag_precedence_unaffected_by_layering() {
    let dir = temp_dir("policy-flag");
    // Both layers present and mutually valid (project allow_list is a
    // strict subset of the user's — a legitimate tightening).
    write_user_config(&dir, "allow_list = [\"ls *\", \"git *\"]");
    write_project_config(&dir, "allow_list = [\"ls *\"]");
    // A default-deny policy: Bash has no explicit allow ⇒ every Bash command
    // Blocks at the POLICY layer regardless of the config allow_list.
    let policy_path = dir.join("deny-all.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\n[defaults]\ndefault_action = \"deny\"\n",
    )
    .expect("write policy");

    // Without --policy: layered config loads fine, benign command allows.
    let out = run_cli(&dir, &["ask", "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "layered config alone must allow; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // With --policy: the policy verdict (Block) wins over the gate Allow —
    // the CLI>config policy precedence survives the layered loader.
    let policy_arg = format!("--policy={}", policy_path.display());
    let out = run_cli(&dir, &["ask", &policy_arg, "ls -la"], None);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--policy default-deny must block through the layered config; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("default-deny"),
        "block reason must come from the policy engine: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
