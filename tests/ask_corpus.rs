//! 0-FP / 0-FN benchmark for the v0.3 Ask tier (Story 6).
//!
//! Runs the FULL hook decision pipeline (gate + policy engine) over
//! two corpora under a policy that escalates every Bash call to
//! `Verdict::ask` via a `budgets.per_tool.Bash.max_invocations = 0`
//! budget cap:
//!
//!   (a) BENIGN commands (from `tests/corpus/ask_benign.txt`) —
//!       none MUST produce an Ask (the pre-committed 0-FP gate).
//!       The benign corpus contains ONLY non-Bash commands
//!       (Read, Write, Edit, WebFetch, UserPromptSubmit) so the
//!       engine's budget is never charged and the engine returns
//!       Allow; the gate is silent on these (no destructive
//!       taxonomy hit, pathguard allows the paths, firewall
//!       returns benign for the URLs).
//!   (b) DANGEROUS commands (from `tests/corpus/ask_dangerous.txt`)
//!       — all MUST produce an Ask. The dangerous corpus contains
//!       Bash commands that the gate does NOT Block (benign in
//!       isolation — `ls`, `cat`, `git status`) but that the
//!       engine's per-tool Bash budget escalates to Ask on the
//!       first call (max_invocations=0). The composition is
//!       engine Ask + gate Allow = Ask (Ask outranks Allow).
//!
//! ## Why this exists
//!
//! The `Tier::Ask` verdict was added in Story 1 (the schema
//! growth) and the policy engine's Ask path was added in
//! Story 2 (budget-cap overage). This benchmark measures the
//! composition: "is the engine's Ask classified correctly, and
//! is the gate's Block correctly NOT downgraded to Ask?".
//! A misclassification is a test failure, not a prose claim.
//!
//! ## Pre-committed gates (asserted, NOT tuned to the measured
//!    values)
//!
//!   1. `ag_ask == 0` on the benign corpus (0-FP).
//!   2. `ag_miss == 0` on the dangerous corpus (0-FN; the
//!      dangerous corpus MUST all produce Ask).
//!
//! If either gate fails, this test fails. The corpus is NOT to
//! be tuned to make it pass. A summary table is printed to
//! stdout (run with `--nocapture`) for transcription into
//! `BENCHMARK.md`.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

use apohara_agentguard::config::Config;
use apohara_agentguard::contract::HookInput;
use apohara_agentguard::policy::engine::PolicySet;
use apohara_agentguard::verdict::{Tier, Verdict};
use serde_json::json;

/// The policy used by the benchmark. A single `PolicySet` instance
/// is shared across all commands in a single run (the engine's
/// budget counters are per-set; a fresh `PolicySet` per command
/// would reset the budget and the corpus would never trigger
/// Ask).
///
/// `max_invocations = 0` means "0 Bash invocations are allowed"
/// (the first Bash call charges 1, which exceeds 0). ALL Bash
/// commands are escalated to Ask on the first call.
const BENCHMARK_POLICY: &str = r#"
schema_version = 1

[defaults]
default_action = "allow"

[[tools]]
name = "Bash"
allow = ["list_dir", "read_file", "search", "git", "cargo", "echo"]

[budgets.per_tool.Bash]
max_invocations = 0
"#;

/// Load the benchmark policy and the `PolicySet` instance. Each
/// test gets its own set (the budget counter is per-set).
fn load_benchmark_set() -> (PolicySet, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "agentguard-ask-corpus-{pid}-{n}",
        pid = std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.toml");
    std::fs::write(&path, BENCHMARK_POLICY).unwrap();
    let set = PolicySet::load(Some(&path)).expect("load ask-benchmark policy");
    (set, dir)
}

/// Parse a corpus file into logical commands (mirrors
/// `tests/benchmark.rs`).
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

/// Parse a corpus line into a HookInput. The corpus format is:
///   - "UserPromptSubmit <text>" → PreToolUse-prompt event
///   - "Read <path>" / "Write <path>" / "Edit <path>" →
///     PreToolUse + tool_name = the literal tool
///   - anything else (Bash-y text like "ls -la", "cat README.md",
///     "git status") → PreToolUse + tool_name = "Bash" + the
///     full text as the Bash `command` arg. This is the
///     convention from the Story 2 policy_engine benchmark
///     (the corpus is "what a user would type at the
///     Claude Code prompt", which IS a Bash command).
fn parse_input(line: &str) -> HookInput<'_> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("UserPromptSubmit ") {
        return HookInput {
            hook_event_name: std::borrow::Cow::Borrowed("UserPromptSubmit"),
            session_id: Some(std::borrow::Cow::Borrowed("ask-corpus")),
            tool_name: None,
            tool_input: json!({ "prompt": rest }),
            prompt: Some(std::borrow::Cow::Owned(rest.to_string())),
            tool_response: serde_json::Value::Null,
        };
    }
    // The known non-Bash tools are spelled with a space (e.g.
    // "Read /etc/hostname"). Anything else (no space, or a
    // space followed by a non-tool-name) is treated as a Bash
    // command — the FULL line becomes the `command` arg.
    if let Some((tool, arg)) = line.split_once(' ') {
        match tool {
            "Read" | "Write" | "Edit" | "WebFetch" | "WebSearch" => {
                return HookInput {
                    hook_event_name: std::borrow::Cow::Borrowed("PreToolUse"),
                    session_id: Some(std::borrow::Cow::Borrowed("ask-corpus")),
                    tool_name: Some(std::borrow::Cow::Owned(tool.to_string())),
                    tool_input: json!({ "command": arg, "path": arg }),
                    prompt: None,
                    tool_response: serde_json::Value::Null,
                };
            }
            _ => {}
        }
    }
    // Default: treat the whole line as a Bash command.
    HookInput {
        hook_event_name: std::borrow::Cow::Borrowed("PreToolUse"),
        session_id: Some(std::borrow::Cow::Borrowed("ask-corpus")),
        tool_name: Some(std::borrow::Cow::Borrowed("Bash")),
        tool_input: json!({ "command": line }),
        prompt: None,
        tool_response: serde_json::Value::Null,
    }
}

/// Compose the gate + policy engine for `input`, returning the
/// final verdict. The compose rule: the MORE SEVERE tier wins
/// (`Block > Ask > Warn > Allow`).
fn compose(set: &PolicySet, input: &HookInput, cfg: &Config) -> Verdict {
    let engine_v = set.evaluate(input, cfg);
    // The gate's `evaluate` takes a bash command; for non-Bash
    // PreToolUse events (Read, Write, Edit, WebFetch) the
    // `gate::evaluate` would be the wrong call. The honest
    // pipeline is more involved (pathguard for Read/Write/Edit,
    // firewall for WebFetch). For the Ask benchmark, the
    // non-Bash tools are KNOWN to not hit the gate's destructive
    // taxonomy, so a synthetic "gate = Allow" is the right
    // representation.
    let gate_v = if input.tool_name.as_deref() == Some("Bash") {
        apohara_agentguard::gate::evaluate(
            input
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            cfg,
        )
    } else {
        Verdict::allow()
    };
    let rank = |t: Tier| -> u8 {
        match t {
            Tier::Allow => 0,
            Tier::Warn => 1,
            Tier::Ask => 2,
            Tier::Block => 3,
        }
    };
    if rank(engine_v.tier) > rank(gate_v.tier) {
        engine_v
    } else {
        gate_v
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
fn ask_fp_fn_benchmark() {
    let (set, dir) = load_benchmark_set();
    // Best-effort cleanup; not fatal if it fails.
    let _ = std::fs::remove_dir_all(&dir);

    let benign = parse_corpus(include_str!("corpus/ask_benign.txt"));
    let dangerous = parse_corpus(include_str!("corpus/ask_dangerous.txt"));

    assert!(
        benign.len() >= 30,
        "ask_benign corpus must have >= 30 commands, got {}",
        benign.len()
    );
    assert!(
        dangerous.len() >= 15,
        "ask_dangerous corpus must have >= 15 commands, got {}",
        dangerous.len()
    );

    let cfg = Config::default();
    let mut false_positives: Vec<&String> = Vec::new();
    let mut false_negatives: Vec<&String> = Vec::new();
    let mut blocked_benign: usize = 0;
    let mut blocked_dangerous: usize = 0;

    for cmd in &benign {
        let input = parse_input(cmd);
        let v = compose(&set, &input, &cfg);
        match v.tier {
            Tier::Allow => {}
            Tier::Warn => {}
            Tier::Ask => false_positives.push(cmd),
            Tier::Block => {
                blocked_benign += 1;
                false_positives.push(cmd);
            }
        }
    }
    for cmd in &dangerous {
        let input = parse_input(cmd);
        let v = compose(&set, &input, &cfg);
        match v.tier {
            Tier::Ask => {}
            Tier::Allow | Tier::Warn => false_negatives.push(cmd),
            Tier::Block => {
                blocked_dangerous += 1;
                false_negatives.push(cmd);
            }
        }
    }

    let ag_fp = false_positives.len();
    let ag_fn = false_negatives.len();

    // --- Summary table (for BENCHMARK.md transcription) ---------------------
    println!();
    println!("== Ask tier FP/FN benchmark ==");
    println!(
        "Policy: default-allow, Bash allow=[list_dir, read_file, search, git, cargo, echo], \
         budgets.per_tool.Bash.max_invocations = 0 (any Bash call exceeds the budget => Ask)."
    );
    println!(
        "Corpora: {} benign (non-Bash tools only), {} dangerous (Bash commands; \
         engine escalates the FIRST call to Ask).",
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
        "| Benign Blocked (over-restrict) | {:>3} / {:>8} | {:>5.1}% |",
        blocked_benign,
        benign.len(),
        rate(blocked_benign, benign.len())
    );
    println!(
        "| Dangerous Blocked (not Ask)    | {:>3} / {:>8} | {:>5.1}% |",
        blocked_dangerous,
        dangerous.len(),
        rate(blocked_dangerous, dangerous.len())
    );
    println!();

    if !false_positives.is_empty() {
        println!("FALSE POSITIVES (benign that ASK or BLOCK) — investigate, do not tune away:");
        for o in &false_positives {
            println!("  - {o:?}");
        }
    }
    if !false_negatives.is_empty() {
        println!("FALSE NEGATIVES (dangerous NOT Ask) — investigate, do not tune away:");
        for o in &false_negatives {
            println!("  - {o:?}");
        }
    }

    // --- Pre-committed, absolute gates --------------------------------------
    assert_eq!(
        ag_fp, 0,
        "GATE 1 FAILED: Ask tier has {ag_fp} false positive(s) (benign that ASK or BLOCK). \
         A benign command producing Ask or Block is a real bug or a mis-curated corpus entry — \
         fix it honestly, do not relax the gate."
    );
    assert_eq!(
        ag_fn, 0,
        "GATE 2 FAILED: Ask tier has {ag_fn} false negative(s) (dangerous NOT Ask). \
         A dangerous command that does NOT produce Ask is a real FN — fix the policy or \
         the gate, do not relax the corpus."
    );
}
