//! Integration tests for the V4-D audit hash chain (`audit verify`).
//!
//! Reduced-honest design (frozen plan §3): a plain SHA-256 hash chain over
//! redacted record content plus an atomically-rewritten sidecar state file —
//! tampering/truncation detection without key management. Ed25519 signatures
//! and rotation are DEFERRED by design; nothing here tests them.
//!
//! Contracts covered:
//!   1. a clean multi-record chain verifies ok (genesis linkage pinned);
//!   2. a tampered middle record is detected (hash mismatch, localized);
//!   3. a deleted middle line is detected (seq gap + link break);
//!   4. a TRUNCATED tail is detected via the sidecar;
//!   5. an extended-after-the-fact line is detected via the sidecar;
//!   6. legacy v1 records are tolerated and counted, never fatal;
//!   7. the raw secret never hits disk and the chain covers the REDACTED form;
//!   8. a missing sidecar still verifies the chain but warns tail truncation
//!      is undetectable;
//!   9. append self-heals (rebuilds state from the log tail) after sidecar loss;
//!  10. the `agentguard audit verify` CLI exit contract: 0 clean / 2 defect /
//!      74 internal I-O.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use apohara_agentguard::audit::{AuditConfig, ChainVerifyReport};
use apohara_agentguard::config::Config;
use apohara_agentguard::hook;
use common::TempDir;

/// A PreToolUse + Bash hook input wrapping `cmd`.
fn pretooluse_bash(cmd: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":{}}}}}"#,
        serde_json::to_string(cmd).unwrap()
    )
}

/// A config with audit pointed at `path`, optionally including command text.
fn audit_config(path: PathBuf, include_command: bool) -> Config {
    Config {
        audit: AuditConfig {
            enabled: true,
            path: Some(path),
            include_command,
        },
        ..Config::default()
    }
}

/// Append `n` distinct Block-verdict records to `log` through the real hook
/// dispatch (the same wiring production uses).
fn write_block_records(log: &Path, n: usize) {
    let cfg = audit_config(log.to_path_buf(), false);
    for i in 0..n {
        let (_out, code) = hook::run(&pretooluse_bash(&format!("rm -rf ~/x{i}")), &cfg);
        assert_eq!(code, 2, "record {i} must produce a Block verdict");
    }
}

/// The log's non-empty lines.
fn lines_of(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .expect("log readable")
        .lines()
        .map(str::to_string)
        .collect()
}

/// Rewrite the log keeping only `keep` (0-indexed) lines.
fn keep_lines(log: &Path, keep: &[usize]) {
    let all = lines_of(log);
    let body: Vec<&str> = keep.iter().map(|&i| all[i].as_str()).collect();
    std::fs::write(log, format!("{}\n", body.join("\n"))).unwrap();
}

#[test]
fn clean_multi_record_chain_verifies_ok() {
    let dir = TempDir::new("chain-clean");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 3);

    // Genesis linkage pinned explicitly: seq starts at 1, first prev is the
    // all-zeros genesis, each later prev links to the previous recorded hash.
    let lines = lines_of(&log);
    assert_eq!(lines.len(), 3);
    let genesis = "0".repeat(64);
    let mut prev_hash = genesis.clone();
    for (i, line) in lines.iter().enumerate() {
        let rec: serde_json::Value = serde_json::from_str(line).expect("valid JSONL");
        assert_eq!(rec["seq"].as_u64().unwrap(), (i + 1) as u64, "line {i}");
        assert_eq!(rec["prev"].as_str().unwrap(), prev_hash, "line {i}");
        prev_hash = rec["hash"].as_str().unwrap().to_string();
    }

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(report.is_clean(), "defects: {:?}", report.defects);
    assert_eq!(report.chained, 3);
    assert_eq!(report.legacy_unverified, 0);

    // The sidecar state tracks the head.
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("audit.jsonl.state")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["version"], 1);
    assert_eq!(state["last_seq"], 3);
    assert_eq!(state["head_hash"], prev_hash.as_str());
}

#[test]
fn tampered_middle_record_detected_and_localized() {
    let dir = TempDir::new("chain-tamper");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 3);

    // Flip a content field in the MIDDLE record (JSON stays valid).
    let mut lines = lines_of(&log);
    let mut rec: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    rec["decision"] = "warn".into();
    lines[1] = serde_json::to_string(&rec).unwrap();
    std::fs::write(&log, format!("{}\n", lines.join("\n"))).unwrap();

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(!report.is_clean());
    // Localized damage: exactly one defect, the hash mismatch on line 2 —
    // no cascade through record 3.
    assert_eq!(report.defects.len(), 1, "defects: {:?}", report.defects);
    assert!(
        report.defects[0].contains("hash mismatch") && report.defects[0].contains("line 2"),
        "got: {:?}",
        report.defects
    );
}

#[test]
fn deleted_middle_line_detected() {
    let dir = TempDir::new("chain-delete-middle");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 3);

    // Delete the middle line: the follower's seq gaps AND its prev-link
    // breaks against the surviving predecessor.
    keep_lines(&log, &[0, 2]);

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(!report.is_clean());
    let joined = report.defects.join("\n");
    assert!(
        joined.contains("seq gap/duplicate"),
        "deletion must surface as a seq gap; got: {joined}"
    );
}

#[test]
fn truncated_tail_detected_via_sidecar() {
    let dir = TempDir::new("chain-truncate-tail");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 3);

    // Delete the LAST line: pure chaining cannot see this — the sidecar can.
    keep_lines(&log, &[0, 1]);

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(!report.is_clean());
    let joined = report.defects.join("\n");
    assert!(
        joined.contains("tail truncation"),
        "tail deletion must be caught by the sidecar; got: {joined}"
    );
}

#[test]
fn extended_after_the_fact_detected_via_sidecar() {
    let dir = TempDir::new("chain-extend");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 3);

    // Forge an extra record AFTER the fact (plausible shape, wrong links).
    let forged = format!(
        r#"{{"seq":4,"prev":"{}","timestamp":123,"event":"gate","decision":"block","hash":"{}"}}"#,
        "0".repeat(64),
        "a".repeat(64)
    );
    let mut body = std::fs::read_to_string(&log).unwrap();
    body.push_str(&forged);
    body.push('\n');
    std::fs::write(&log, body).unwrap();

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(!report.is_clean());
    let joined = report.defects.join("\n");
    assert!(
        joined.contains("post-hoc extension"),
        "an appended-after-the-fact record must be caught by the sidecar; got: {joined}"
    );
}

#[test]
fn legacy_v1_records_tolerated_and_counted() {
    let dir = TempDir::new("chain-legacy");
    let log = dir.path().join("audit.jsonl");

    // Two pre-chain (v1) records in the exact old schema.
    let v1 = r#"{"timestamp":1700000000000,"event":"gate","decision":"block","rule_id":"rm-rf","category":"destructive"}"#;
    std::fs::write(&log, format!("{v1}\n{v1}\n")).unwrap();

    // One new chained record appended after them.
    write_block_records(&log, 1);

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(
        report.is_clean(),
        "legacy presence must NOT fail the run; defects: {:?}",
        report.defects
    );
    assert_eq!(report.chained, 1);
    assert_eq!(report.legacy_unverified, 2);
    // The new chain starts at seq 1 over the legacy prefix.
    let lines = lines_of(&log);
    let rec: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(rec["seq"], 1);
    assert_eq!(rec["prev"], "0".repeat(64));
}

#[test]
fn raw_secret_absent_and_verify_recomputes_over_redacted_form() {
    let dir = TempDir::new("chain-redaction");
    let log = dir.path().join("audit.jsonl");
    let cfg = audit_config(log.clone(), true);

    let secret = "sk-secret123";
    let (_out, code) = hook::run(
        &pretooluse_bash(&format!("export API_KEY={secret} && rm -rf ~")),
        &cfg,
    );
    assert_eq!(code, 2);

    let body = std::fs::read_to_string(&log).expect("audit file written");
    assert!(
        !body.contains(secret),
        "the raw secret must NOT hit disk; got: {body}"
    );

    // A clean verify IS the property proof: verification recomputes every
    // hash over the parsed (redacted) content, so passing here means the
    // stored digest was computed over exactly the redacted form.
    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(report.is_clean(), "defects: {:?}", report.defects);
    assert_eq!(report.chained, 1);
}

#[test]
fn missing_sidecar_verifies_chain_but_warns_tail_undetectable() {
    let dir = TempDir::new("chain-no-sidecar");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 3);
    std::fs::remove_file(dir.path().join("audit.jsonl.state")).unwrap();

    // Phase A: chain integrity is still fully checked; only a WARNING notes
    // that tail truncation became undetectable.
    let report: ChainVerifyReport = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(report.is_clean(), "defects: {:?}", report.defects);
    assert_eq!(report.chained, 3);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("TAIL TRUNCATION")),
        "warnings: {:?}",
        report.warnings
    );

    // Phase B (honesty demo): with the sidecar gone, deleting the LAST line
    // is NOT detectable — the run stays clean (with the same warning).
    keep_lines(&log, &[0, 1]);
    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(
        report.is_clean(),
        "without the sidecar a tail cut is invisible by design; defects: {:?}",
        report.defects
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("TAIL TRUNCATION")),
        "warnings: {:?}",
        report.warnings
    );
}

#[test]
fn self_heal_rebuild_on_append_after_sidecar_loss() {
    let dir = TempDir::new("chain-self-heal");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 2);
    std::fs::remove_file(dir.path().join("audit.jsonl.state")).unwrap();

    // The next append rebuilds state from the log tail and CONTINUES the
    // chain (seq 3 linking to record 2's hash) instead of restarting.
    write_block_records(&log, 1);

    let state_path = dir.path().join("audit.jsonl.state");
    assert!(state_path.exists(), "sidecar must be recreated on append");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state["last_seq"], 3);

    let lines = lines_of(&log);
    assert_eq!(lines.len(), 3);
    let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    let third: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
    assert_eq!(third["seq"], 3);
    assert_eq!(third["prev"], second["hash"]);

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(report.is_clean(), "defects: {:?}", report.defects);
    assert_eq!(report.chained, 3);
}

#[test]
fn legacy_only_log_without_usable_sidecar_warns_full_strip() {
    let dir = TempDir::new("chain-full-strip");
    let log = dir.path().join("audit.jsonl");

    // A pure-legacy log with NO sidecar is exactly what a full strip of the
    // v2 region would look like — verify must say so explicitly.
    let v1 = r#"{"timestamp":1700000000000,"event":"gate","decision":"block","rule_id":"rm-rf","category":"destructive"}"#;
    std::fs::write(&log, format!("{v1}\n{v1}\n")).unwrap();

    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(report.is_clean(), "defects: {:?}", report.defects);
    assert_eq!(report.chained, 0);
    assert_eq!(report.legacy_unverified, 2);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("full-strip cannot be ruled out")),
        "warnings: {:?}",
        report.warnings
    );

    // Same for an UNREADABLE sidecar (crash-torn / unknown version).
    std::fs::write(dir.path().join("audit.jsonl.state"), "not-json").unwrap();
    let report = apohara_agentguard::audit::verify_chain(&log).expect("verify");
    assert!(report.is_clean(), "defects: {:?}", report.defects);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("full-strip cannot be ruled out")),
        "warnings: {:?}",
        report.warnings
    );
}

// ---- CLI surface (`agentguard audit verify`) --------------------------------

/// Run `agentguard audit verify --file <log>` from a fresh temp cwd so no
/// stray config perturbs the run.
fn run_cli(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_apohara-agentguard"))
        .args(args)
        .current_dir(cwd)
        .env_remove("AGENTGUARD_DISABLE")
        .env_remove("AGENTGUARD_POLICY")
        .output()
        .expect("run apohara-agentguard audit verify")
}

#[test]
fn cli_audit_verify_exit_contract() {
    let dir = TempDir::new("chain-cli");
    let log = dir.path().join("audit.jsonl");
    write_block_records(&log, 2);

    // Clean: exit 0 + `ok:` summary.
    let out = run_cli(
        &["audit", "verify", "--file", log.to_str().unwrap()],
        dir.path(),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok: 2 chained, 0 legacy-unverified"),
        "stdout: {stdout}"
    );

    // Truncated tail: exit 2 + one `defect:` line per problem.
    keep_lines(&log, &[0]);
    let out = run_cli(
        &["audit", "verify", "--file", log.to_str().unwrap()],
        dir.path(),
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "a detected defect must exit 2; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("defect:"), "stdout: {stdout}");
    assert!(stdout.contains("FAILED:"), "stdout: {stdout}");

    // Unreadable log: internal I/O error, exit 74.
    let out = run_cli(
        &[
            "audit",
            "verify",
            "--file",
            dir.path().join("nope.jsonl").to_str().unwrap(),
        ],
        dir.path(),
    );
    assert_eq!(
        out.status.code(),
        Some(74),
        "stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}
