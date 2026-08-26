//! `agentguard init` end-to-end CLI tests (Wave U0).
//!
//! Contract under test:
//! 1. A fresh Claude Code install gets `~/.claude/settings.json` with the
//!    three event groups (PreToolUse / PostToolUse / UserPromptSubmit) wired
//!    to the ABSOLUTE path of the running binary; a re-run reports
//!    "already wired" and does NOT duplicate entries.
//! 2. A fresh Codex install gets `~/.codex/hooks.json` with a `description`
//!    and PreToolUse ONLY; idempotent re-run.
//! 3. Pre-existing unrelated user hooks are PRESERVED (append semantics).
//! 4. A corrupt (unparseable) host config is REFUSED: loud stderr naming the
//!    file, exit 2, file bytes unchanged, and the OTHER host is not touched.
//! 5. `--undo` removes our entries, preserves unrelated ones, prunes emptied
//!    arrays, and drops OUR exact stamped Codex `description` (a
//!    user-customized description survives); undo on a clean install is a
//!    no-op success.
//! 6. Without `--yes` everything is a DRY-RUN: nothing is created or
//!    modified.
//! 7. Stale-path self-heal: marker wiring pointing at a dead binary path is
//!    refreshed IN PLACE (no duplicates); exact wiring stays AlreadyWired.
//! 8. Writes are atomic sibling-tempfile + rename: no `*.agentguard-tmp-*`
//!    leftovers after a successful run.
//!
//! Every invocation runs with `HOME` pointed at a fresh tempdir, so the
//! developer's real Claude/Codex configs can never be touched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

/// Fresh unique temp dir (isolated HOME for one CLI invocation).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-init-cli-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run the compiled `init` subcommand with HOME isolated to `home`.
fn run_init(home: &Path, args: &[&str]) -> Output {
    run_init_with_xdg(home, None, args)
}

/// Like [`run_init`], but optionally points `$XDG_CONFIG_HOME` at `xdg`
/// (None removes the variable — the default-branch behavior).
fn run_init_with_xdg(home: &Path, xdg: Option<&Path>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"));
    cmd.args(args)
        .current_dir(home)
        .env("HOME", home)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match xdg {
        Some(x) => {
            cmd.env("XDG_CONFIG_HOME", x);
        }
        None => {
            cmd.env_remove("XDG_CONFIG_HOME");
        }
    }
    cmd.output().expect("run apohara-agentguard init")
}

/// The absolute exe path `init` must have written (the CLI canonicalizes its
/// own current_exe; canonicalize the manifest-side path the same way).
fn expected_exe() -> String {
    std::fs::canonicalize(env!("CARGO_BIN_EXE_apohara-agentguard"))
        .expect("canonicalize cli exe")
        .to_string_lossy()
        .into_owned()
}

fn read_json(path: &Path) -> Value {
    let raw =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Count every inner hook in a parsed config whose command carries our marker.
fn count_marker_hooks(cfg: &Value) -> usize {
    cfg["hooks"]
        .as_object()
        .map(|hooks| {
            hooks
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(|g| g["hooks"].as_array())
                .flatten()
                .filter(|h| {
                    h["command"]
                        .as_str()
                        .is_some_and(|c| c.contains("apohara-agentguard"))
                })
                .count()
        })
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// (a) Fresh Claude Code install + idempotence
// ---------------------------------------------------------------------------

#[test]
fn fresh_claude_install_wires_three_events_and_rerun_is_idempotent() {
    let home = temp_dir("claude-fresh");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("claude-code: wired"), "{stdout}");
    assert!(
        stdout.contains("(created"),
        "a fresh install must state that the host dir was created: {stdout}"
    );

    let cfg_path = home.join(".claude").join("settings.json");
    let cfg = read_json(&cfg_path);
    let hooks = cfg["hooks"].as_object().expect("hooks table");
    assert_eq!(hooks.len(), 3, "exactly the three event groups: {hooks:?}");

    let pre = hooks["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 1);
    assert_eq!(pre[0]["matcher"], "Bash|Read|Write|Edit|WebFetch|WebSearch");
    let inner = pre[0]["hooks"].as_array().unwrap();
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0]["type"], "command");
    assert_eq!(
        inner[0]["command"],
        json!(expected_exe()),
        "ABSOLUTE exe path"
    );
    assert_eq!(inner[0]["args"], json!(["hook"]));
    assert_eq!(inner[0]["timeout"], 20);

    assert_eq!(hooks["PostToolUse"][0]["matcher"], "Bash");
    assert!(hooks["UserPromptSubmit"][0].get("matcher").is_none());

    // Idempotent re-run: already wired, no duplication.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert_eq!(out2.status.code(), Some(0));
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout2.contains("claude-code: already wired"), "{stdout2}");
    let cfg2 = read_json(&cfg_path);
    assert_eq!(
        cfg2["hooks"]["PreToolUse"].as_array().unwrap().len(),
        1,
        "re-run must NOT duplicate entries"
    );
    assert_eq!(count_marker_hooks(&cfg2), 3);

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (b) Fresh Codex install + idempotence
// ---------------------------------------------------------------------------

#[test]
fn fresh_codex_install_writes_description_and_pretooluse_only() {
    let home = temp_dir("codex-fresh");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("codex-code: wired"), "{stdout}");
    assert!(
        stdout.contains("/hooks"),
        "the Codex trust-review note must be printed after wiring: {stdout}"
    );

    let cfg_path = home.join(".codex").join("hooks.json");
    let cfg = read_json(&cfg_path);
    assert_eq!(cfg["description"], "Installed by apohara-agentguard init");
    let hooks = cfg["hooks"].as_object().expect("hooks table");
    assert_eq!(hooks.len(), 1, "Codex stays PreToolUse-only: {hooks:?}");
    assert!(hooks.contains_key("PreToolUse"));
    assert_eq!(
        hooks["PreToolUse"][0]["matcher"],
        "Bash|apply_patch|Edit|Write"
    );
    assert_eq!(
        hooks["PreToolUse"][0]["hooks"][0]["command"],
        json!(expected_exe())
    );

    // Idempotent re-run.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert_eq!(out2.status.code(), Some(0));
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout2.contains("codex-code: already wired"), "{stdout2}");
    let cfg2 = read_json(&cfg_path);
    assert_eq!(count_marker_hooks(&cfg2), 1, "no duplication");

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (c) Append semantics: user hooks preserved
// ---------------------------------------------------------------------------

#[test]
fn pre_existing_user_hooks_are_preserved_on_install() {
    let home = temp_dir("claude-preserve");
    let dir = home.join(".claude");
    std::fs::create_dir_all(&dir).expect("create .claude");
    std::fs::write(
        dir.join("settings.json"),
        serde_json::json!({
            "model": "opus",
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/my-linter", "args": ["scan"] }
                        ]
                    }
                ]
            }
        })
        .to_string(),
    )
    .expect("write user settings");

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let cfg = read_json(&dir.join("settings.json"));
    assert_eq!(cfg["model"], "opus", "unrelated top-level keys survive");
    let pre = cfg["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 2, "our group is APPENDED, not clobbered");
    // The user's entry is intact AND first (never reordered).
    assert_eq!(pre[0]["matcher"], "Bash");
    assert_eq!(pre[0]["hooks"][0]["command"], "/usr/bin/my-linter");
    // Ours is second.
    assert_eq!(pre[1]["hooks"][0]["command"], json!(expected_exe()));

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (d) Corrupt-config refusal (fail-closed integrity)
// ---------------------------------------------------------------------------

#[test]
fn corrupt_claude_settings_refuses_and_changes_nothing() {
    let home = temp_dir("claude-corrupt");
    let dir = home.join(".claude");
    std::fs::create_dir_all(&dir).expect("create .claude");
    let corrupt = b"{ this is definitely not json";
    std::fs::write(dir.join("settings.json"), corrupt).expect("write corrupt config");

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "corrupt config must refuse with exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("settings.json"),
        "diagnostic must name the offending file: {stderr}"
    );
    assert_eq!(
        std::fs::read(dir.join("settings.json")).unwrap(),
        corrupt,
        "the corrupt file's bytes must be untouched"
    );
    // Two-phase safety: the OTHER host must not be half-wired either.
    assert!(
        !home.join(".codex").exists(),
        "a corrupt config on one host must abort before wiring the other"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (e) Undo: removes ours, preserves theirs, prunes empties, clean no-op
// ---------------------------------------------------------------------------

#[test]
fn undo_removes_ours_preserves_user_entries_and_prunes_empties() {
    let home = temp_dir("undo-mixed");
    let dir = home.join(".claude");
    std::fs::create_dir_all(&dir).expect("create .claude");
    let settings = dir.join("settings.json");

    // Install over a user config that has its OWN PostToolUse hook.
    std::fs::write(
        &settings,
        serde_json::json!({
            "hooks": {
                "PostToolUse": [
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": "/usr/bin/audit-logger" }
                    ]}
                ]
            }
        })
        .to_string(),
    )
    .expect("write user settings");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0));

    let out = run_init(&home, &["init", "--undo"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("claude-code: unwired"), "{stdout}");

    let raw = std::fs::read_to_string(&settings).unwrap();
    assert!(
        !raw.contains("apohara-agentguard"),
        "no marker entries may survive undo: {raw}"
    );
    let cfg = read_json(&settings);
    let hooks = cfg["hooks"].as_object().unwrap();
    assert_eq!(
        hooks.len(),
        1,
        "emptied event groups (PreToolUse/UserPromptSubmit) must be pruned: {hooks:?}"
    );
    assert!(hooks.contains_key("PostToolUse"));
    let post = hooks["PostToolUse"].as_array().unwrap();
    assert_eq!(post.len(), 1, "the user's own PostToolUse hook survives");
    assert_eq!(post[0]["hooks"][0]["command"], "/usr/bin/audit-logger");

    // Undo again: clean no-op success.
    let out = run_init(&home, &["init", "--undo"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("nothing to undo"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn undo_on_clean_home_is_noop_success() {
    let home = temp_dir("undo-clean");
    let out = run_init(&home, &["init", "--undo"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing to undo"), "{stdout}");
    assert!(
        !home.join(".claude").exists(),
        "undo must not create anything"
    );
    assert!(!home.join(".codex").exists());

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (e') Stale-path refresh + atomicity
// ---------------------------------------------------------------------------

#[test]
fn stale_path_is_refreshed_in_place_without_duplicates() {
    let home = temp_dir("claude-stale");
    let dir = home.join(".claude");
    std::fs::create_dir_all(&dir).expect("create .claude");
    let settings = dir.join("settings.json");
    // Our wiring, but pointing at a binary that no longer exists (relocated
    // install): marker matches, command does NOT equal the current exe.
    let stale = "/nonexistent/bin/apohara-agentguard-0.2.0";
    std::fs::write(
        &settings,
        serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash|Read|Write|Edit|WebFetch|WebSearch", "hooks": [
                        { "type": "command", "command": stale, "args": ["hook"], "timeout": 20 }
                    ]}
                ],
                "PostToolUse": [
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": stale, "args": ["hook"], "timeout": 20 }
                    ]}
                ],
                "UserPromptSubmit": [
                    { "hooks": [
                        { "type": "command", "command": stale, "args": ["hook"], "timeout": 20 }
                    ]}
                ]
            }
        })
        .to_string(),
    )
    .expect("write stale wiring");

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("claude-code: refreshed"),
        "stale wiring must be reported as refreshed: {stdout}"
    );

    let cfg = read_json(&settings);
    assert_eq!(
        count_marker_hooks(&cfg),
        3,
        "refresh must rewrite IN PLACE — entry count unchanged"
    );
    let pre = cfg["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 1, "no duplicate group may be appended");
    assert_eq!(pre[0]["hooks"][0]["command"], json!(expected_exe()));
    // args / timeout untouched by the refresh.
    assert_eq!(pre[0]["hooks"][0]["args"], json!(["hook"]));
    assert_eq!(pre[0]["hooks"][0]["timeout"], 20);
    assert_eq!(
        cfg["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
        json!(expected_exe())
    );

    // After the refresh, a re-run is a clean AlreadyWired.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert!(String::from_utf8_lossy(&out2.stdout).contains("already wired"));

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn already_wired_with_current_exe_leaves_file_byte_identical() {
    let home = temp_dir("claude-exact");
    let settings = home.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).expect("create .claude");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0));
    let before = std::fs::read_to_string(&settings).unwrap();

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("claude-code: already wired"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        before,
        "AlreadyWired must not rewrite the file"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn undo_removes_stamped_codex_description_but_keeps_user_customized() {
    // (a) Fresh install: our stamped description is removed on undo.
    let home = temp_dir("codex-desc-stamped");
    let hooks_json = home.join(".codex").join("hooks.json");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        read_json(&hooks_json)["description"],
        "Installed by apohara-agentguard init"
    );
    let out = run_init(&home, &["init", "--undo"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = read_json(&hooks_json);
    assert!(
        cfg.get("description").is_none(),
        "our stamped description must not survive undo (false provenance): {cfg}"
    );

    // (b) User-customized description survives undo.
    let home = temp_dir("codex-desc-custom");
    let dir = home.join(".codex");
    std::fs::create_dir_all(&dir).expect("create .codex");
    let hooks_json = dir.join("hooks.json");
    std::fs::write(
        &hooks_json,
        serde_json::json!({
            "description": "my own codex hooks",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash|apply_patch|Edit|Write", "hooks": [
                        { "type": "command", "command": expected_exe(), "args": ["hook"], "timeout": 20 }
                    ]}
                ]
            }
        })
        .to_string(),
    )
    .expect("write custom description config");
    let out = run_init(&home, &["init", "--undo"]);
    assert_eq!(out.status.code(), Some(0));
    let cfg = read_json(&hooks_json);
    assert_eq!(
        cfg["description"], "my own codex hooks",
        "a user-customized description is never touched"
    );
    assert!(cfg["hooks"].as_object().is_some_and(|h| h.is_empty()));

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn install_leaves_no_temp_files_behind() {
    let home = temp_dir("atomicity-smoke");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    for subdir in [
        ".claude",
        ".codex",
        ".config/opencode/plugins",
        ".config/kilo/plugins",
        ".kitty-code",
        // FASE 4 hosts.
        ".codeium/windsurf",
        ".cursor",
        ".gemini/antigravity-cli/plugins/agentguard",
    ] {
        let entries = std::fs::read_dir(home.join(subdir))
            .unwrap_or_else(|e| panic!("read {subdir}: {e}"))
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            entries.iter().all(|n| !n.contains(".agentguard-tmp-")),
            "no sibling temp file may survive a successful write: {subdir}: {entries:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (f) Dry-run: nothing is created or modified without --yes
// ---------------------------------------------------------------------------

#[test]
fn dry_run_without_yes_modifies_nothing() {
    // Fresh home: dry-run plans but creates NOTHING.
    let home = temp_dir("dryrun-fresh");
    let out = run_init(&home, &["init"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "dry-run must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("would wire"), "{stdout}");
    assert!(
        !home.join(".claude").exists(),
        "dry-run must not create .claude"
    );
    assert!(
        !home.join(".codex").exists(),
        "dry-run must not create .codex"
    );
    let _ = std::fs::remove_dir_all(&home);

    // Existing config: dry-run install leaves it byte-identical, and an
    // undo with none of our entries present is a no-op that also leaves it
    // byte-identical (never rewrites a file it doesn't need to).
    let home = temp_dir("dryrun-existing");
    let dir = home.join(".claude");
    std::fs::create_dir_all(&dir).expect("create .claude");
    let settings = dir.join("settings.json");
    let original = r#"{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/bin/my-linter"}]}]}}"#;
    std::fs::write(&settings, original).expect("write settings");

    for args in [&["init"][..], &["init", "--undo"][..]] {
        let out = run_init(&home, args);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            std::fs::read_to_string(&settings).unwrap(),
            original,
            "({args:?}) must leave the file byte-identical"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (g) Flag hygiene
// ---------------------------------------------------------------------------

#[test]
fn yes_and_undo_are_mutually_exclusive() {
    let home = temp_dir("conflict");
    let out = run_init(&home, &["init", "--yes", "--undo"]);
    assert_ne!(out.status.code(), Some(0), "--yes and --undo must conflict");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--undo") && stderr.contains("--yes"),
        "clap must name both conflicting flags: {stderr}"
    );
    assert!(!home.join(".claude").exists());
    assert!(!home.join(".codex").exists());

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (h) Wave U2′.5+6+7: opencode / kilo / kitty-code drop-in hosts
// ---------------------------------------------------------------------------

/// The shim source `init` must copy verbatim (same file the lib embeds).
const SHIM_SOURCE: &str = include_str!("../packaging/opencode/agentguard-shim.mjs");

#[test]
fn fresh_opencode_install_drops_plugin_shim_idempotent_and_undo_removes() {
    let home = temp_dir("opencode-fresh");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("opencode: wired"), "{stdout}");
    assert!(
        stdout.contains("opencode.json was not modified"),
        "the no-config-edit note must be printed: {stdout}"
    );

    let shim = home.join(".config/opencode/plugins/agentguard-shim.mjs");
    assert_eq!(
        std::fs::read_to_string(&shim).expect("shim written"),
        SHIM_SOURCE,
        "init must copy the embedded shim VERBATIM"
    );

    // Idempotent re-run: already wired, byte-identical.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert_eq!(out2.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("opencode: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );
    assert_eq!(std::fs::read_to_string(&shim).unwrap(), SHIM_SOURCE);

    // Undo removes OUR file (exact content), then is a clean no-op.
    let out3 = run_init(&home, &["init", "--undo"]);
    assert_eq!(out3.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out3.stdout).contains("opencode: unwired"),
        "{}",
        String::from_utf8_lossy(&out3.stdout)
    );
    assert!(!shim.exists(), "undo must remove our exact shim");
    let out4 = run_init(&home, &["init", "--undo"]);
    assert_eq!(out4.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out4.stdout).contains("opencode: nothing to undo"),
        "{}",
        String::from_utf8_lossy(&out4.stdout)
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn opencode_respects_xdg_config_home() {
    let home = temp_dir("opencode-xdg");
    let xdg = home.join("xdg-config");
    std::fs::create_dir_all(&xdg).expect("create xdg root");

    let out = run_init_with_xdg(&home, Some(&xdg), &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shim = xdg.join("opencode/plugins/agentguard-shim.mjs");
    assert_eq!(
        std::fs::read_to_string(&shim).expect("shim under $XDG_CONFIG_HOME"),
        SHIM_SOURCE
    );
    assert!(
        !home.join(".config/opencode").exists(),
        "with XDG set, nothing may land under ~/.config"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn fresh_kilo_install_writes_plugin_and_veto_guide_undo_removes_both() {
    let home = temp_dir("kilo-fresh");
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("kilo: wired"), "{stdout}");

    let shim = home.join(".config/kilo/plugins/agentguard-shim.mjs");
    let guide = home.join(".config/kilo/agentguard-veto-guide.md");
    assert_eq!(
        std::fs::read_to_string(&shim).expect("kilo shim written"),
        SHIM_SOURCE
    );
    let guide_text = std::fs::read_to_string(&guide).expect("veto guide written");
    assert!(
        guide_text.contains("hardRuleset") && guide_text.contains("YOLO"),
        "the veto guide must document the YOLO-immune hardRuleset channel"
    );

    // Idempotent re-run.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert_eq!(out2.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("kilo: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );

    // Undo removes BOTH artifacts.
    let out3 = run_init(&home, &["init", "--undo"]);
    assert_eq!(out3.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out3.stdout).contains("kilo: unwired"),
        "{}",
        String::from_utf8_lossy(&out3.stdout)
    );
    assert!(!shim.exists(), "undo must remove the kilo shim");
    assert!(!guide.exists(), "undo must remove the veto guide");

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn kitty_scaffold_lifecycle_create_idempotent_and_exact_undo() {
    let home = temp_dir("kitty-fresh");
    let policy = home.join(".kitty-code/policy.toml");

    // Fresh install: scaffold written with the reported message.
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("kitty-code: scaffolded"), "{stdout}");
    assert!(
        stdout.contains("embedded via library — policy scaffold written"),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(&policy).expect("scaffold written"),
        apohara_agentguard::init::KITTY_SCAFFOLD,
        "scaffold must match the library constant exactly"
    );

    // Re-run: already wired (content equality), untouched.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert_eq!(out2.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("kitty-code: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );

    // Undo removes ONLY the exact scaffold.
    let out3 = run_init(&home, &["init", "--undo"]);
    assert_eq!(out3.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out3.stdout).contains("kitty-code: unwired"),
        "{}",
        String::from_utf8_lossy(&out3.stdout)
    );
    assert!(!policy.exists());

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn kitty_pre_existing_user_policy_is_never_touched() {
    let home = temp_dir("kitty-user-policy");
    let dir = home.join(".kitty-code");
    std::fs::create_dir_all(&dir).expect("create .kitty-code");
    let policy = dir.join("policy.toml");
    let user_policy = "# my own kitty-code policy\n[other]\nflag = true\n";
    std::fs::write(&policy, user_policy).expect("write user policy");

    // Install: detection only — user policy reported untouched.
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("kitty-code: existing policy detected, untouched"),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(&policy).unwrap(),
        user_policy,
        "a pre-existing non-scaffold policy.toml must be byte-identical after install"
    );

    // Undo: not ours ⇒ clean no-op, still untouched.
    let out2 = run_init(&home, &["init", "--undo"]);
    assert_eq!(out2.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("kitty-code: nothing to undo"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), user_policy);

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn dry_run_lists_all_eight_hosts_without_writing_anything() {
    let home = temp_dir("dryrun-eight-hosts");
    let out = run_init(&home, &["init"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for host in [
        "claude-code",
        "codex-code",
        "opencode",
        "kilo",
        "kitty-code",
        "windsurf",
        "cursor",
        "antigravity",
    ] {
        assert!(stdout.contains(host), "dry-run must list {host}: {stdout}");
    }
    for artifact in [
        ".claude",
        ".codex",
        ".config/opencode",
        ".config/kilo",
        ".kitty-code",
        ".codeium",
        ".cursor",
        ".gemini",
    ] {
        assert!(
            !home.join(artifact).exists(),
            "dry-run must not create {artifact}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// (i) FASE 4: windsurf / cursor / antigravity hosts
// ---------------------------------------------------------------------------

/// The full flat spawn line `init` must write for a flat-entry host.
fn expected_flat_command(harness: &str) -> String {
    format!("{} hook --harness {harness}", expected_exe())
}

#[test]
fn fresh_windsurf_install_writes_flat_event_arrays_idempotent_undo() {
    let home = temp_dir("windsurf-fresh");
    let cfg_path = home.join(".codeium/windsurf/hooks.json");

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("windsurf: wired"), "{stdout}");

    let cfg = read_json(&cfg_path);
    let hooks = cfg["hooks"].as_object().expect("hooks table");
    assert_eq!(hooks.len(), 2, "{hooks:?}");
    // Flat entries: the command IS the full spawn line (no matcher groups).
    for event in ["pre_run_command", "pre_mcp_tool_use"] {
        let arr = hooks[event].as_array().unwrap();
        assert_eq!(arr.len(), 1, "{event}");
        let entry = &arr[0];
        assert!(
            entry.get("hooks").is_none(),
            "{event}: windsurf entries are FLAT, not nested groups"
        );
        assert_eq!(entry["command"], expected_flat_command("windsurf"));
    }

    // Idempotent re-run.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert_eq!(out2.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("windsurf: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );

    // Undo removes our flat entries and prunes the emptied events.
    let out3 = run_init(&home, &["init", "--undo"]);
    assert_eq!(out3.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out3.stdout).contains("windsurf: unwired"),
        "{}",
        String::from_utf8_lossy(&out3.stdout)
    );
    let raw = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(!raw.contains("apohara-agentguard"), "{raw}");

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn windsurf_user_hooks_survive_and_stale_paths_self_heal() {
    let home = temp_dir("windsurf-mixed");
    let dir = home.join(".codeium/windsurf");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("hooks.json");

    // User content + our wiring pointing at a relocated binary.
    let stale_exe = "/nonexistent/bin/apohara-agentguard-0.4.1";
    std::fs::write(
        &cfg_path,
        serde_json::json!({
            "hooks": {
                "pre_run_command": [
                    { "command": format!("{stale_exe} hook --harness windsurf") },
                ],
                "pre_mcp_tool_use": [
                    { "command": "/usr/bin/user-tool", "timeout": 5 },
                ],
            }
        })
        .to_string(),
    )
    .unwrap();

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("windsurf: refreshed"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let cfg = read_json(&cfg_path);
    let arr = cfg["hooks"]["pre_run_command"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "refresh rewrites IN PLACE, no duplicates");
    assert_eq!(arr[0]["command"], expected_flat_command("windsurf"));
    // Marker-present wiring takes the REFRESH path (never duplicate groups),
    // so the user's own MCP entry is left exactly as it was.
    let mcp = cfg["hooks"]["pre_mcp_tool_use"].as_array().unwrap();
    assert_eq!(mcp.len(), 1, "user entries are never duplicated onto");
    assert_eq!(mcp[0]["command"], "/usr/bin/user-tool");

    // After the refresh a re-run is a clean AlreadyWired.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("windsurf: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn fresh_cursor_install_wires_both_events_lifecycle_complete() {
    let home = temp_dir("cursor-fresh");
    let cfg_path = home.join(".cursor/hooks.json");

    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cursor: wired"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let cfg = read_json(&cfg_path);
    for event in ["beforeShellExecution", "beforeMCPExecution"] {
        let arr = cfg["hooks"][event].as_array().expect("event array");
        assert_eq!(arr.len(), 1, "{event}");
        assert_eq!(arr[0]["command"], expected_flat_command("cursor"));
    }

    // Idempotent re-run; then undo removes ours and prunes empties.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("cursor: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );
    let out3 = run_init(&home, &["init", "--undo"]);
    assert!(
        String::from_utf8_lossy(&out3.stdout).contains("cursor: unwired"),
        "{}",
        String::from_utf8_lossy(&out3.stdout)
    );
    let raw = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(!raw.contains("apohara-agentguard"), "{raw}");
    let cfg2 = read_json(&cfg_path);
    let hooks = cfg2["hooks"].as_object().unwrap();
    assert!(hooks.is_empty() || cfg2.get("hooks").is_none());

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn antigravity_plugin_drop_in_is_exact_content_managed_and_self_heals() {
    let home = temp_dir("antigravity-fresh");
    let plugin_dir = home.join(".gemini/antigravity-cli/plugins/agentguard");
    let cfg_path = plugin_dir.join("hooks.json");

    // Fresh install: the generated document is written verbatim.
    let out = run_init(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("antigravity: wired"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let expected = apohara_agentguard::init::antigravity_plugin_document(std::path::Path::new(
        &expected_exe(),
    ));
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), expected);
    let doc: Value = serde_json::from_str(&expected).unwrap();
    assert_eq!(
        doc["hooks"]["PreToolUse"][0]["matcher"],
        "Bash|Read|Write|Edit|WebFetch|WebSearch"
    );
    assert_eq!(
        doc["hooks"]["PreToolUse"][0]["hooks"][0]["args"],
        json!(["hook", "--harness", "antigravity"])
    );

    // Idempotent re-run: exact content ⇒ already wired, byte-identical.
    let out2 = run_init(&home, &["init", "--yes"]);
    assert!(
        String::from_utf8_lossy(&out2.stdout).contains("antigravity: already wired"),
        "{}",
        String::from_utf8_lossy(&out2.stdout)
    );

    // Divergent content (relocated exe) self-heals in place on install.
    std::fs::write(&cfg_path, "{\"hooks\":{}}").unwrap();
    let out3 = run_init(&home, &["init", "--yes"]);
    assert!(
        String::from_utf8_lossy(&out3.stdout).contains("antigravity: refreshed"),
        "{}",
        String::from_utf8_lossy(&out3.stdout)
    );
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), expected);

    // Undo removes OUR file only when its content matches exactly.
    let out4 = run_init(&home, &["init", "--undo"]);
    assert!(
        String::from_utf8_lossy(&out4.stdout).contains("antigravity: unwired"),
        "{}",
        String::from_utf8_lossy(&out4.stdout)
    );
    assert!(!cfg_path.exists());
    let out5 = run_init(&home, &["init", "--undo"]);
    assert!(
        String::from_utf8_lossy(&out5.stdout).contains("antigravity: nothing to undo"),
        "{}",
        String::from_utf8_lossy(&out5.stdout)
    );

    let _ = std::fs::remove_dir_all(&home);
}
