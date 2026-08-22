//! FP/FN benchmark for the v0.3 policy engine (Story 2 — star item).
//!
//! Runs `policy::engine::PolicySet::evaluate` over the same TWO corpora
//! under a default-deny policy with explicit Block rules:
//!
//!   (a) BENIGN commands (from `tests/corpus/policy_benign.txt`) —
//!       none MUST produce a Block (the pre-committed 0-FP gate).
//!   (b) DANGEROUS commands (from `tests/corpus/policy_dangerous.txt`)
//!       — all MUST produce a Block (the pre-committed 0-FN gate).
//!
//! ## Why this exists
//!
//! The `tests/benchmark.rs` benchmark exercises the **gate** (the
//! pre-existing taxonomy + custom_blocks). The policy engine is a NEW
//! pass that COMPOSES with the gate via `max_verdict`; this benchmark
//! measures the engine in isolation so a misclassified verdict is
//! surfaced as a test failure, not a prose claim.
//!
//! ## Pre-committed gates (asserted, NOT tuned to the measured values)
//!
//!   1. `ag_block == 0` on the benign corpus (0-FP).
//!   2. `ag_fn   == 0` on the dangerous corpus (0-FN).
//!
//! If either gate fails, this test fails. The corpus is NOT to be
//! tuned to make it pass: a benign command that Blocks is a real bug
//! (or a mis-curated entry), and a dangerous command that slips is a
//! real false negative. A summary table is printed to stdout (run with
//! `--nocapture`) for transcription into `BENCHMARK.md`.

use std::path::PathBuf;

use apohara_agentguard::config::Config;
use apohara_agentguard::contract::HookInput;
use apohara_agentguard::policy::engine::PolicySet;
use apohara_agentguard::verdict::Tier;
use serde_json::json;

/// The default-deny policy used by the benchmark. Stored as a `&'static
/// str` (the loader will be fed a temp file with this content).
const BENCHMARK_POLICY: &str = r#"
schema_version = 1

[defaults]
default_action = "deny"

[[tools]]
name = "Bash"
allow = ["list_dir", "read_file", "search", "git", "cargo", "echo"]
rules = [
  # `rm -rf` and its case variations on the short flags. The matcher
  # is case-sensitive, so each permutation needs its own rule.
  { arg = "command", pattern = "*rm -rf*",   severity = 8, reason = "policy: destructive rm" },
  { arg = "command", pattern = "*rm -Rf*",   severity = 8, reason = "policy: destructive rm" },
  { arg = "command", pattern = "*rm -rF*",   severity = 8, reason = "policy: destructive rm" },
  { arg = "command", pattern = "*rm -RF*",   severity = 8, reason = "policy: destructive rm" },
  { arg = "command", pattern = "*rm -fr*",   severity = 8, reason = "policy: destructive rm" },
  # Long-flag variant (`rm --recursive --force …`).
  { arg = "command", pattern = "*rm *--recursive*", severity = 8, reason = "policy: destructive rm (long flag)" },
  { arg = "command", pattern = "*rm *--force*",     severity = 8, reason = "policy: destructive rm (long flag)" },
  # Other destructive primitives.
  { arg = "command", pattern = "*mkfs*",     severity = 9, reason = "policy: filesystem format" },
  { arg = "command", pattern = "*dd if=*",   severity = 8, reason = "policy: dd device write" },
  { arg = "command", pattern = "*shutdown*", severity = 9, reason = "policy: shutdown" },
  { arg = "command", pattern = "*reboot*",   severity = 9, reason = "policy: reboot" },
  { arg = "command", pattern = "*wipefs*",   severity = 9, reason = "policy: wipefs" },
  { arg = "command", pattern = "*blkdiscard*", severity = 9, reason = "policy: blkdiscard" },
  { arg = "command", pattern = "*poweroff*", severity = 9, reason = "policy: poweroff" },
  { arg = "command", pattern = "*halt*",     severity = 9, reason = "policy: halt" },
  # Sudo is a privilege escalation — Block (severity 8) rather than
  # Warn (severity 7) so the 0-FN gate holds: a sudo that
  # downgrades to Warn is a misclassification in the agent context.
  { arg = "command", pattern = "sudo *",     severity = 8, reason = "policy: sudo command" },
]

[[tools]]
name = "Read"
allow = ["read_file"]

[[tools]]
name = "Write"
allow = ["write_file"]
"#;

/// Write the benchmark policy to a unique temp file and return the
/// `PolicySet`. Uses a per-test counter so parallel tests don't
/// clobber each other's `policy.toml`.
fn load_benchmark_policy() -> (PolicySet, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "agentguard-policy-bench-{pid}-{n}",
        pid = std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.toml");
    std::fs::write(&path, BENCHMARK_POLICY).unwrap();
    let set = PolicySet::load(Some(&path)).expect("load benchmark policy");
    (set, dir) // caller cleans up the dir
}

/// Parse a corpus file into logical commands (mirrors `tests/benchmark.rs`).
fn parse_corpus(raw: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut pending: Option<String> = None;

    for line in raw.lines() {
        if let Some(mut acc) = pending.take() {
            acc.push('\n');
            acc.push_str(line);
            if ends_with_odd_backslash(line) {
                pending = Some(acc);
            } else {
                commands.push(acc);
            }
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if ends_with_odd_backslash(line) {
            pending = Some(line.to_string());
        } else {
            commands.push(line.to_string());
        }
    }

    if let Some(acc) = pending {
        commands.push(acc);
    }
    commands
}

fn ends_with_odd_backslash(line: &str) -> bool {
    line.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
}

/// Wrap a `command` string as a PreToolUse Bash `HookInput`.
fn pretooluse_bash(cmd: &str) -> HookInput {
    HookInput {
        hook_event_name: "PreToolUse".to_string(),
        session_id: Some("bench".to_string()),
        tool_name: Some("Bash".to_string()),
        tool_input: json!({ "command": cmd }),
        prompt: None,
        tool_response: serde_json::Value::Null,
    }
}

fn rate(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        100.0 * num as f64 / den as f64
    }
}

#[test]
fn fp_fn_benchmark_for_policy_engine() {
    let (set, dir) = load_benchmark_policy();
    // Best-effort cleanup; not fatal if it fails.
    let _ = std::fs::remove_dir_all(&dir);

    let benign = parse_corpus(include_str!("corpus/policy_benign.txt"));
    let dangerous = parse_corpus(include_str!("corpus/policy_dangerous.txt"));

    assert!(
        benign.len() >= 60,
        "policy_benign corpus must have >= 60 commands, got {}",
        benign.len()
    );
    assert!(
        dangerous.len() >= 30,
        "policy_dangerous corpus must have >= 30 commands, got {}",
        dangerous.len()
    );

    let cfg = Config::default();
    let mut false_positives: Vec<&String> = Vec::new();
    let mut false_negatives: Vec<&String> = Vec::new();
    let mut asked_benign: usize = 0;
    let mut asked_dangerous: usize = 0;

    for cmd in &benign {
        let v = set.evaluate(&pretooluse_bash(cmd), &cfg);
        match v.tier {
            Tier::Block => false_positives.push(cmd),
            Tier::Ask => asked_benign += 1,
            Tier::Allow | Tier::Warn => {}
        }
    }
    for cmd in &dangerous {
        let v = set.evaluate(&pretooluse_bash(cmd), &cfg);
        match v.tier {
            Tier::Block => {}
            Tier::Ask => asked_dangerous += 1,
            Tier::Allow | Tier::Warn => false_negatives.push(cmd),
        }
    }

    let ag_fp = false_positives.len();
    let ag_fn = false_negatives.len();

    // --- Summary table (for BENCHMARK.md transcription) ---------------------
    println!();
    println!("== Policy engine FP/FN benchmark ==");
    println!(
        "Policy: default-deny, Bash allow=[list_dir, read_file, search, git, cargo, echo], \
         Block rules for rm-rf/mkfs/dd/shutdown/reboot/sudo/wipefs/blkdiscard/poweroff/halt."
    );
    println!(
        "Corpora: {} benign, {} dangerous (author-curated; the policy_benign corpus \
         does NOT contain any pattern the Block rules target).",
        benign.len(),
        dangerous.len()
    );
    println!();
    println!("| Metric                 | Count / N       | Rate   |");
    println!("|------------------------|----------------:|-------:|");
    println!(
        "| False positives        | {:>3} / {:>8} | {:>5.1}% |",
        ag_fp,
        benign.len(),
        rate(ag_fp, benign.len())
    );
    println!(
        "| False negatives        | {:>3} / {:>8} | {:>5.1}% |",
        ag_fn,
        dangerous.len(),
        rate(ag_fn, dangerous.len())
    );
    println!(
        "| Benign escalated (Ask) | {:>3} / {:>8} | {:>5.1}% |",
        asked_benign,
        benign.len(),
        rate(asked_benign, benign.len())
    );
    println!(
        "| Dangerous escalated (Ask) | {:>3} / {:>8} | {:>5.1}% |",
        asked_dangerous,
        dangerous.len(),
        rate(asked_dangerous, dangerous.len())
    );
    println!();

    if !false_positives.is_empty() {
        println!("FALSE POSITIVES (benign that BLOCK) — investigate, do not tune away:");
        for o in &false_positives {
            println!("  - {o:?}");
        }
    }
    if !false_negatives.is_empty() {
        println!("FALSE NEGATIVES (dangerous NOT Blocked) — investigate, do not tune away:");
        for o in &false_negatives {
            println!("  - {o:?}");
        }
    }

    // --- Pre-committed, absolute gates --------------------------------------
    assert_eq!(
        ag_fp, 0,
        "GATE 1 FAILED: policy engine has {ag_fp} false positive(s) (benign that BLOCK). \
         A benign command blocking is a real bug or a mis-curated corpus entry — fix it \
         honestly, do not relax the gate."
    );
    assert_eq!(
        ag_fn, 0,
        "GATE 2 FAILED: policy engine has {ag_fn} false negative(s) (dangerous NOT Blocked). \
         A dangerous command slipping is a real FN — fix the engine or policy, do not \
         relax the corpus."
    );
}

#[test]
fn engine_byte_identical_when_no_policy_loaded() {
    // Empty-TOML invariant at the engine level: with no policy file
    // loaded, `PolicySet::default()` is a no-op combine and the engine
    // returns Allow for every input. This anchors the
    // pre-Story-2-baseline invariant at the engine level (the
    // hook-level byte-identity test lives in `hook_contract.rs`).
    let set = PolicySet::default();
    let cfg = Config::default();
    for cmd in [
        "ls -la",
        "rm -rf ~",
        "echo hello",
        "cat /etc/passwd",
        "kubectl delete namespace prod",
    ] {
        let v = set.evaluate(&pretooluse_bash(cmd), &cfg);
        assert_eq!(
            v.tier,
            Tier::Allow,
            "no policy loaded => Allow (got {v:?} for {cmd:?})"
        );
    }
}

#[test]
fn engine_load_missing_path_is_error_not_panic() {
    // Fail-closed posture: `PolicySet::load` on a missing path returns
    // an `Err`, NOT a panic. The dispatcher maps the error to
    // `Verdict::block` (covered by the hook-level
    // `engine_byte_identical_*` test).
    let bogus = std::env::temp_dir().join("agentguard-policy-bench-missing-12345.toml");
    let _ = std::fs::remove_file(&bogus);
    let res = PolicySet::load(Some(&bogus));
    assert!(res.is_err(), "missing path must be an error, not a panic");
}
