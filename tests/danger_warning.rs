//! A2: the loud `danger_full_access` warning + audit-on-invocation, exercised
//! through the compiled binary.

mod common;
use common::TempDir;

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_apohara-agentguard")
}

#[test]
fn danger_full_access_prints_loud_warning() {
    let dir = TempDir::new("danger-warn");
    let out = Command::new(bin())
        .current_dir(dir.path())
        .env_remove("AGENTGUARD_DISABLE")
        .args([
            "sandbox",
            "--tier",
            "danger_full_access",
            "--i-know-what-im-doing",
            "--workspace-root",
            dir.path().to_str().unwrap(),
            "--",
            "echo",
            "hi",
        ])
        .output()
        .expect("run apohara-agentguard sandbox");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NO seccomp"),
        "warning must name NO seccomp; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("NO Landlock"),
        "warning must name NO Landlock; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("FULL host access"),
        "warning must state full host access; stderr=\n{stderr}"
    );
}

#[test]
fn danger_without_flag_still_refuses() {
    let dir = TempDir::new("danger-refuse");
    let out = Command::new(bin())
        .current_dir(dir.path())
        .env_remove("AGENTGUARD_DISABLE")
        .args([
            "sandbox",
            "--tier",
            "danger_full_access",
            "--",
            "echo",
            "hi",
        ])
        .output()
        .expect("run apohara-agentguard sandbox");

    assert_eq!(
        out.status.code(),
        Some(2),
        "danger_full_access without --i-know-what-im-doing must refuse (exit 2)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing danger_full_access"),
        "the existing refusal must still fire; stderr=\n{stderr}"
    );
}

#[test]
fn danger_invocation_is_audited_when_enabled() {
    let dir = TempDir::new("danger-audit");
    let log = dir.path().join("audit.jsonl");

    // A project-local agentguard.toml in the cwd enables auditing; the binary
    // loads it via Config::load_default_locations().
    let config = format!(
        "[audit]\nenabled = true\npath = {:?}\ninclude_command = false\n",
        log.to_str().unwrap()
    );
    std::fs::write(dir.path().join("agentguard.toml"), config).expect("write config");

    let out = Command::new(bin())
        .current_dir(dir.path())
        .env_remove("AGENTGUARD_DISABLE")
        .args([
            "sandbox",
            "--tier",
            "danger_full_access",
            "--i-know-what-im-doing",
            "--workspace-root",
            dir.path().to_str().unwrap(),
            "--",
            "echo",
            "hi",
        ])
        .output()
        .expect("run apohara-agentguard sandbox");
    assert!(
        out.status.success() || out.status.code() == Some(0),
        "the echo command should succeed; stderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let body = std::fs::read_to_string(&log).expect("audit file written for danger invocation");
    let rec: serde_json::Value =
        serde_json::from_str(body.lines().next().expect("a JSONL line")).unwrap();
    assert_eq!(rec["event"], "danger_full_access");
    // Metadata-only by default: no command text.
    assert!(
        rec.get("command").is_none(),
        "danger audit must be metadata-only by default; got: {rec}"
    );
}
