//! `agentguard doctor` end-to-end CLI tests (Story X3).
//!
//! Contract under test:
//! 1. After `init --yes` on a fresh temp HOME, `doctor` exits 0 and reports
//!    every host wiring as healthy (the zero-touch install promise holds).
//! 2. `--json` emits a parseable document whose shape is
//!    `{ "ok": bool, "checks": [{ id, status, detail }] }`, statuses are
//!    lowercase, and `ok == true` on a wired install.
//! 3. STALE wiring (marker present but pointing at a different binary) is a
//!    FAIL ⇒ doctor exits 1 — silent protection loss must be loud.
//! 4. A clean HOME (no hosts at all) yields only WARNs ⇒ still exit 0
//!    (doctor diagnoses; it does not mandate adoption).
//!
//! Every invocation runs with `HOME` pointed at a fresh tempdir, so the
//! developer's real configs can never be touched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Fresh unique temp dir (isolated HOME for one CLI invocation).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "agentguard-doctor-cli-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run the compiled binary with HOME isolated to `home`.
fn run_cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run apohara-agentguard")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn doctor_after_init_reports_wired_hosts_and_exits_zero() {
    let home = temp_dir("wired");
    let out = run_cli(&home, &["init", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_cli(&home, &["doctor"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "doctor must be healthy right after init; stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        stdout_of(&out)
    );
    let text = stdout_of(&out);
    assert!(text.starts_with("apohara-agentguard doctor"), "{text}");
    // Every host row present AND passing.
    for host in [
        "claude-code",
        "codex-code",
        "opencode",
        "kilo",
        "kitty-code",
    ] {
        let needle = format!("PASS wiring/{host}");
        assert!(text.contains(&needle), "missing `{needle}` in:\n{text}");
    }
    // Core checks present.
    for id in [
        "version",
        "config",
        "policy",
        "pins-dir",
        "audit-dir",
        "sandbox",
    ] {
        assert!(text.contains(id), "missing check id {id} in:\n{text}");
    }
    assert!(text.contains("— healthy"), "{text}");

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn doctor_json_shape_is_stable_and_ok_on_a_wired_install() {
    let home = temp_dir("json");
    let out = run_cli(&home, &["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0));

    let out = run_cli(&home, &["doctor", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(stdout_of(&out).trim()).expect("doctor --json must emit valid JSON");

    assert_eq!(doc["ok"], serde_json::json!(true), "{doc}");
    let checks = doc["checks"].as_array().expect("checks array");
    assert!(checks.len() >= 9, "expected >= 9 checks, got {checks:?}");
    for c in checks {
        assert!(c["id"].is_string(), "check missing string id: {c}");
        let status = c["status"].as_str().expect("status string");
        assert!(
            ["pass", "warn", "fail"].contains(&status),
            "unexpected status {status}"
        );
        assert!(c["detail"].is_string(), "check missing detail: {c}");
    }
    // Stable schema: fixed ids in fixed order.
    let ids: Vec<&str> = checks.iter().filter_map(|c| c["id"].as_str()).collect();
    assert_eq!(ids.first(), Some(&"version"));
    assert!(ids.contains(&"config") && ids.contains(&"policy"));
    for host in [
        "claude-code",
        "codex-code",
        "opencode",
        "kilo",
        "kitty-code",
    ] {
        let want = format!("wiring/{host}");
        assert!(ids.contains(&want.as_str()), "missing {want} in {ids:?}");
    }
    // Right after init nothing may even warn about wiring.
    for c in checks
        .iter()
        .filter(|c| c["id"].as_str().unwrap().starts_with("wiring/"))
    {
        assert_eq!(
            c["status"], "pass",
            "wiring check should pass after init: {c}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn stale_wiring_is_a_failure_and_exits_one() {
    let home = temp_dir("stale");
    let out = run_cli(&home, &["init", "--yes"]);
    assert_eq!(out.status.code(), Some(0));

    // Relocate the binary: rewrite our marker-matched commands to a dead path.
    let settings = home.join(".claude").join("settings.json");
    let mut cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    for groups in cfg["hooks"].as_object_mut().unwrap().values_mut() {
        for group in groups.as_array_mut().unwrap() {
            for inner in group["hooks"].as_array_mut().unwrap() {
                if inner["command"]
                    .as_str()
                    .is_some_and(|c| c.contains("apohara-agentguard"))
                {
                    inner["command"] = serde_json::json!("/nonexistent/apohara-agentguard-0.0.0");
                }
            }
        }
    }
    std::fs::write(
        &settings,
        serde_json::to_string_pretty(&cfg).expect("serialize stale config"),
    )
    .unwrap();

    // Human mode.
    let out = run_cli(&home, &["doctor"]);
    assert_eq!(out.status.code(), Some(1), "stale wiring must FAIL");
    let text = stdout_of(&out);
    assert!(text.contains("FAIL wiring/claude-code"), "{text}");
    assert!(text.contains("stale"), "{text}");
    assert!(text.contains("NOT HEALTHY"), "{text}");

    // JSON mode agrees.
    let out = run_cli(&home, &["doctor", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_str(stdout_of(&out).trim()).expect("valid json");
    assert_eq!(doc["ok"], serde_json::json!(false), "{doc}");

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn clean_home_yields_only_warnings_and_exits_zero() {
    let home = temp_dir("clean");

    let out = run_cli(&home, &["doctor"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a hostless machine is not a failure; stdout={}",
        stdout_of(&out)
    );
    let text = stdout_of(&out);
    for host in [
        "claude-code",
        "codex-code",
        "opencode",
        "kilo",
        "kitty-code",
    ] {
        let needle = format!("WARN wiring/{host}");
        assert!(text.contains(&needle), "missing `{needle}` in:\n{text}");
    }
    assert!(text.contains("— healthy"), "{text}");

    let _ = std::fs::remove_dir_all(&home);
}
