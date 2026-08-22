//! Story T3 — structured evaluation harness with per-case expectations.
//!
//! Walks `evals/{gate,firewall,policy}/cases/*/` deterministically (sorted),
//! evaluates every case through the component's public API, and compares the
//! resulting [`Tier`] against the case's `_expected.json`. A summary table
//! (per-component totals, mismatches, and precision/recall over the
//! block/warn = "flagged" binary view) is printed to stdout; the test then
//! asserts zero mismatches so any drift fails loudly with the case id.
//!
//! This is the characterization net: a refactor that changes any pinned
//! security-relevant behavior turns an eval case red instead of passing
//! silently. To add a case, see `evals/README.md`.
//!
//! No new dependencies: serde/serde_json/regex are already in the tree.

use std::fs;
use std::path::{Path, PathBuf};

use apohara_agentguard::config::Config;
use apohara_agentguard::contract::HookInput;
use apohara_agentguard::firewall::refetch::{ContentSource, FetchError, FetchTarget, Surface};
use apohara_agentguard::firewall::{scan_surface, FirewallInput};
use apohara_agentguard::policy::engine::PolicySet;
use apohara_agentguard::verdict::{Thresholds, Tier, Verdict};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Case model
// ---------------------------------------------------------------------------

/// Parsed `_expected.json`.
struct Expected {
    tier: Tier,
    /// Optional substring that must appear in the verdict reason.
    reason_contains: Option<String>,
    /// Firewall only: which surface posture to apply (default `user_prompt`).
    surface: String,
    /// Policy only: how many times to evaluate the input against the same
    /// `PolicySet` (budget cases need repeat > 1 to exhaust a cap).
    repeat: usize,
    notes: Option<String>,
}

/// One evaluated case.
struct Outcome {
    component: &'static str,
    id: String,
    expected: Tier,
    actual: Tier,
    ok: bool,
    /// Empty when ok; otherwise a human-readable explanation of the mismatch.
    detail: String,
}

fn parse_tier(s: &str) -> Result<Tier, String> {
    match s {
        "allow" => Ok(Tier::Allow),
        "warn" => Ok(Tier::Warn),
        "ask" => Ok(Tier::Ask),
        "block" => Ok(Tier::Block),
        other => Err(format!("unknown tier `{other}` (allow|warn|ask|block)")),
    }
}

fn parse_expected(v: &Value, path: &Path) -> Result<Expected, String> {
    let tier_str = v
        .get("expected_tier")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}: missing string field `expected_tier`", path.display()))?;
    Ok(Expected {
        tier: parse_tier(tier_str)?,
        reason_contains: v
            .get("reason_contains")
            .and_then(Value::as_str)
            .map(str::to_string),
        surface: v
            .get("surface")
            .and_then(Value::as_str)
            .unwrap_or("user_prompt")
            .to_string(),
        repeat: v
            .get("repeat")
            .and_then(Value::as_u64)
            .map(|n| n.max(1) as usize)
            .unwrap_or(1),
        notes: v.get("notes").and_then(Value::as_str).map(str::to_string),
    })
}

/// Deterministic (sorted) walk of `evals/<component>/cases/*/`.
fn case_dirs(component: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evals")
        .join(component)
        .join("cases");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("evals/{component}/cases must exist: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

// ---------------------------------------------------------------------------
// Per-component evaluation (public APIs only)
// ---------------------------------------------------------------------------

fn run_gate_case(dir: &Path) -> Result<Verdict, String> {
    let raw = fs::read_to_string(dir.join("input.txt")).map_err(|e| format!("input.txt: {e}"))?;
    // Single-line command: strip only the trailing newline the file carries.
    let command = raw.trim_end_matches(['\n', '\r']);
    Ok(apohara_agentguard::gate::evaluate(
        command,
        &Config::default(),
    ))
}

/// Content source that is never consulted: firewall cases carry inline text,
/// so even BLOCK-capable surfaces scan what they already have (hermetic — no
/// network). If a future change starts fetching for inline payloads, the empty
/// body makes the case fail visibly instead of silently passing.
struct UnusedSource;

impl ContentSource for UnusedSource {
    fn fetch(&self, _target: &FetchTarget) -> Result<String, FetchError> {
        Ok(String::new())
    }
}

fn parse_surface(s: &str) -> Result<Surface, String> {
    match s {
        "user_prompt" => Ok(Surface::UserPrompt),
        "bash_stdout" => Ok(Surface::BashStdout),
        "read_file" => Ok(Surface::ReadFile),
        "web_fetch" => Ok(Surface::WebFetch),
        "web_search" => Ok(Surface::WebSearch),
        other => Err(format!("unknown surface `{other}`")),
    }
}

fn run_firewall_case(dir: &Path, exp: &Expected) -> Result<Verdict, String> {
    // Prompt/content text; may be multiline.
    let text = fs::read_to_string(dir.join("input.txt")).map_err(|e| format!("input.txt: {e}"))?;
    let surface = parse_surface(&exp.surface)?;
    Ok(scan_surface(
        surface,
        &FirewallInput::inline(text),
        &UnusedSource,
        &Thresholds::default(),
    ))
}

fn run_policy_case(dir: &Path, exp: &Expected) -> Result<Verdict, String> {
    let input_raw =
        fs::read_to_string(dir.join("input.json")).map_err(|e| format!("input.json: {e}"))?;
    let input: HookInput =
        serde_json::from_str(&input_raw).map_err(|e| format!("input.json parse: {e}"))?;
    let policy_path = dir.join("policy.toml");
    // Fail-closed parity with the hook dispatcher: a load error maps to Block.
    let set = match PolicySet::load(Some(&policy_path)) {
        Ok(set) => set,
        Err(e) => {
            return Ok(Verdict::block(format!(
                "policy failed to load (fail-closed): {e}"
            )));
        }
    };
    // Budget counters live on the PolicySet, so repeated evaluations against
    // the same set accumulate charges — that is how exhaustion cases reach Ask.
    let mut verdict = Verdict::allow();
    for _ in 0..exp.repeat {
        verdict = set.evaluate(&input, &Config::default());
    }
    Ok(verdict)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn run_case(component: &'static str, dir: &Path, id: &str) -> Outcome {
    let expected_path = dir.join("_expected.json");
    let outcome = (|| -> Result<Outcome, String> {
        let raw = fs::read_to_string(&expected_path).map_err(|e| format!("_expected.json: {e}"))?;
        let v: Value =
            serde_json::from_str(&raw).map_err(|e| format!("_expected.json parse: {e}"))?;
        let exp = parse_expected(&v, &expected_path)?;

        let verdict = match component {
            "gate" => run_gate_case(dir)?,
            "firewall" => run_firewall_case(dir, &exp)?,
            "policy" => run_policy_case(dir, &exp)?,
            other => return Err(format!("unknown component `{other}`")),
        };

        let mut detail = String::new();
        if verdict.tier != exp.tier {
            detail.push_str(&format!(
                "tier mismatch (expected {}, got {})",
                tier_name(exp.tier),
                tier_name(verdict.tier)
            ));
        }
        if let Some(needle) = &exp.reason_contains {
            if !verdict.reason.contains(needle.as_str()) {
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                detail.push_str(&format!(
                    "reason {:?} does not contain {needle:?}",
                    verdict.reason
                ));
            }
        }
        if !detail.is_empty() {
            if let Some(notes) = &exp.notes {
                detail.push_str(&format!(" [notes: {notes}]"));
            }
        }

        Ok(Outcome {
            component,
            id: id.to_string(),
            expected: exp.tier,
            actual: verdict.tier,
            ok: detail.is_empty(),
            detail,
        })
    })();

    match outcome {
        Ok(o) => o,
        Err(e) => Outcome {
            component,
            id: id.to_string(),
            expected: Tier::Allow,
            actual: Tier::Allow,
            ok: false,
            detail: format!("case error: {e}"),
        },
    }
}

fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Allow => "allow",
        Tier::Warn => "warn",
        Tier::Ask => "ask",
        Tier::Block => "block",
    }
}

/// Binary "flagged" view for precision/recall: Block and Warn count as flagged.
fn flagged(t: Tier) -> bool {
    matches!(t, Tier::Block | Tier::Warn)
}

fn print_summary(outcomes: &[&Outcome]) {
    println!();
    println!("== eval harness summary ==");
    println!(
        "{:<10} {:>5} {:>7} {:>10} {:>9} {:>9}",
        "component", "total", "matched", "mismatches", "precision", "recall"
    );
    for component in ["gate", "firewall", "policy"] {
        let cases: Vec<&Outcome> = outcomes
            .iter()
            .copied()
            .filter(|o| o.component == component)
            .collect();
        let total = cases.len();
        let matched = cases.iter().filter(|o| o.ok).count();
        let mut tp = 0usize;
        let mut fp = 0usize;
        let mut misses = 0usize;
        for o in &cases {
            match (flagged(o.expected), flagged(o.actual)) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => misses += 1,
                (false, false) => {}
            }
        }
        let precision = match tp + fp {
            0 => "n/a".to_string(),
            d => format!("{:.1}%", 100.0 * tp as f64 / d as f64),
        };
        let recall = match tp + misses {
            0 => "n/a".to_string(),
            d => format!("{:.1}%", 100.0 * tp as f64 / d as f64),
        };
        println!(
            "{:<10} {:>5} {:>7} {:>10} {:>9} {:>9}",
            component,
            total,
            matched,
            total - matched,
            precision,
            recall
        );
    }
    println!();
    println!(
        "precision/recall over the binary \"flagged\" view \
         (block/warn = flagged; ask/allow = not flagged)."
    );

    let failures: Vec<&&Outcome> = outcomes.iter().filter(|o| !o.ok).collect();
    if !failures.is_empty() {
        println!("MISMATCHES:");
        for o in failures {
            println!(
                "  - [{}/{}] expected {} vs actual {} — {}",
                o.component,
                o.id,
                tier_name(o.expected),
                tier_name(o.actual),
                o.detail
            );
        }
    } else {
        println!("all cases match their expectations.");
    }
    println!();
}

#[test]
fn eval_cases_match_expectations() {
    let mut all: Vec<Outcome> = Vec::new();
    for component in ["gate", "firewall", "policy"] {
        for dir in case_dirs(component) {
            let id = dir
                .file_name()
                .expect("case dir has a name")
                .to_string_lossy()
                .into_owned();
            all.push(run_case(component, &dir, &id));
        }
    }

    let refs: Vec<&Outcome> = all.iter().collect();
    print_summary(&refs);

    let failed: Vec<String> = all
        .iter()
        .filter(|o| !o.ok)
        .map(|o| format!("{}/{}: {}", o.component, o.id, o.detail))
        .collect();
    assert!(
        failed.is_empty(),
        "eval harness found {} mismatch(es):\n  {}",
        failed.len(),
        failed.join("\n  ")
    );
}
