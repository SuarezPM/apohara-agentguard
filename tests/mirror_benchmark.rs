//! External-style benchmark #2: the Mirror paraphrase corpus
//! (`evals/mirror/`) vs. the input firewall.
//!
//! Why this exists: external #1 (TensorTrust, `tests/benchmark_tensortrust.rs`)
//! measures the firewall against human-written social engineering. This
//! benchmark measures the OTHER documented weakness of a signature-based
//! detector: **paraphrasing**. Every attack here keeps the semantic intent of a
//! canonical injection pattern (the families the DJL/OWASP tables and
//! `evals/firewall/cases/` already cover) but rewrites its surface — synonyms,
//! restructuring, indirect framing, translation-flavored phrasing, encoding-lite
//! tricks. A signature firewall's ceiling on paraphrases is EXPECTED to be low;
//! measuring that ceiling honestly is the entire point (see BENCHMARK.md).
//!
//! What it MEASURES (published with --nocapture, NOT a pass/fail gate):
//! - per-class false-negative rate over attacks: an attack counts as missed iff
//!   `scan_content` returns anything other than `Block` (a Warn passes content
//!   through, so it is a miss — same accounting as external #1);
//! - false-positive rate over the matched benign controls: a control counts as
//!   flagged iff the verdict is `Warn` or `Block`.
//!
//! Assertions are STRUCTURAL ONLY (corpus parses, expected counts present, ids
//! unique, every case reaches exactly one verdict bucket). No numeric gate on
//! FN or FP: the measured numbers are transcribed into BENCHMARK.md as the
//! publishable result.

use std::collections::BTreeMap;

use apohara_agentguard::firewall::scan_content;
use apohara_agentguard::verdict::{Thresholds, Tier};
use serde::Deserialize;

/// One Mirror corpus record (`evals/mirror/{attacks,benign}.jsonl`).
#[derive(Deserialize)]
struct Case {
    id: String,
    class: String,
    text: String,
}

/// Minimum corpus sizes this benchmark was authored with. Guards against a
/// truncated or half-deleted corpus silently shrinking the measurement; the
/// exact counts live in `evals/mirror/README.md`.
const MIN_ATTACKS: usize = 30;
const MIN_BENIGN: usize = 15;

fn parse_cases(raw: &str, label: &str) -> Vec<Case> {
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("{label}.jsonl line {} is not valid JSON: {e}", i + 1))
        })
        .collect()
}

#[derive(Default)]
struct ClassStats {
    total: usize,
    blocked: usize,
    warned: usize,
    missed: usize,
}

impl ClassStats {
    fn record(&mut self, tier: Tier) {
        self.total += 1;
        match tier {
            Tier::Block => self.blocked += 1,
            Tier::Warn => {
                self.warned += 1;
                self.missed += 1; // Warn passes content through => a miss.
            }
            Tier::Allow => self.missed += 1,
            // scan_content maps severity via severity_to_tier, which never
            // yields Ask; the arm exists only for match exhaustiveness.
            Tier::Ask => unreachable!("scan_content never returns Tier::Ask"),
        }
    }
}

#[test]
fn mirror_paraphrase_benchmark() {
    let attacks = parse_cases(include_str!("../evals/mirror/attacks.jsonl"), "attacks");
    let benign = parse_cases(include_str!("../evals/mirror/benign.jsonl"), "benign");

    // ---- structural sanity (the ONLY assertions) ---------------------------
    assert!(
        attacks.len() >= MIN_ATTACKS,
        "expected >= {MIN_ATTACKS} mirror attacks, got {} (corpus truncated? see evals/mirror/README.md)",
        attacks.len()
    );
    assert!(
        benign.len() >= MIN_BENIGN,
        "expected >= {MIN_BENIGN} benign controls, got {} (corpus truncated?)",
        benign.len()
    );
    let mut ids: Vec<&str> = attacks
        .iter()
        .chain(benign.iter())
        .map(|c| c.id.as_str())
        .collect();
    let unique = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        unique,
        ids.len(),
        "duplicate case id across evals/mirror corpora"
    );
    for c in attacks.iter().chain(benign.iter()) {
        assert!(!c.class.is_empty(), "case {} has empty class", c.id);
        assert!(!c.text.is_empty(), "case {} has empty text", c.id);
    }

    // ---- measurement --------------------------------------------------------
    let thresholds = Thresholds::default();

    let mut per_class: BTreeMap<&str, ClassStats> = BTreeMap::new();
    let mut atk_blocked = 0usize;
    let mut atk_warned = 0usize;
    let mut atk_allowed = 0usize;
    for a in &attacks {
        let stats = per_class.entry(a.class.as_str()).or_default();
        let tier = scan_content(&a.text, &thresholds).tier;
        stats.record(tier);
        match tier {
            Tier::Block => atk_blocked += 1,
            Tier::Warn => atk_warned += 1,
            Tier::Allow => atk_allowed += 1,
            Tier::Ask => unreachable!("scan_content never returns Tier::Ask"),
        }
    }
    let atk_missed = atk_warned + atk_allowed;

    let mut fp_per_class: BTreeMap<&str, usize> = BTreeMap::new();
    let mut ben_allow = 0usize;
    let mut ben_warned = 0usize;
    let mut ben_blocked = 0usize;
    for b in &benign {
        let tier = scan_content(&b.text, &thresholds).tier;
        match tier {
            Tier::Allow => ben_allow += 1,
            Tier::Warn => {
                ben_warned += 1;
                *fp_per_class.entry(b.class.as_str()).or_default() += 1;
            }
            Tier::Block => {
                ben_blocked += 1;
                *fp_per_class.entry(b.class.as_str()).or_default() += 1;
            }
            Tier::Ask => unreachable!("scan_content never returns Tier::Ask"),
        }
    }
    let ben_flagged = ben_warned + ben_blocked;

    // ---- published report (run with --nocapture) ----------------------------
    let pct = |n: usize, d: usize| format!("{:>5.1}%", 100.0 * n as f64 / d as f64);

    println!();
    println!(
        "== Mirror paraphrase benchmark (external-style #2): firewall vs. rewritten attacks =="
    );
    println!(
        "Corpus: {atk} paraphrase attacks + {ben} matched benign controls \
         (author-written; method in evals/mirror/README.md).",
        atk = attacks.len(),
        ben = benign.len()
    );
    println!();
    println!("Per-class ATTACK results (missed = verdict is not Block):");
    println!(
        "{:<22} {:>6} {:>8} {:>6} {:>8} {:>9}",
        "class", "total", "blocked", "warned", "missed", "FN rate"
    );
    for (class, s) in &per_class {
        println!(
            "{:<22} {:>6} {:>8} {:>6} {:>8} {:>9}",
            class,
            s.total,
            s.blocked,
            s.warned,
            s.missed,
            pct(s.missed, s.total)
        );
    }
    println!();
    println!("Overall ATTACKS:");
    println!(
        "  Blocked:              {:>4} / {} ({})",
        atk_blocked,
        attacks.len(),
        pct(atk_blocked, attacks.len())
    );
    println!(
        "  Warn-only (slips):    {:>4} / {} ({})",
        atk_warned,
        attacks.len(),
        pct(atk_warned, attacks.len())
    );
    println!(
        "  Allowed (slips):      {:>4} / {} ({})",
        atk_allowed,
        attacks.len(),
        pct(atk_allowed, attacks.len())
    );
    println!(
        "  FALSE NEGATIVES:      {:>4} / {} ({})",
        atk_missed,
        attacks.len(),
        pct(atk_missed, attacks.len())
    );
    println!();
    println!("Overall BENIGN controls (flagged = Warn or Block):");
    println!(
        "  Allowed:              {:>4} / {} ({})",
        ben_allow,
        benign.len(),
        pct(ben_allow, benign.len())
    );
    println!(
        "  Warned:               {:>4} / {} ({})",
        ben_warned,
        benign.len(),
        pct(ben_warned, benign.len())
    );
    println!(
        "  Blocked:              {:>4} / {} ({})",
        ben_blocked,
        benign.len(),
        pct(ben_blocked, benign.len())
    );
    println!(
        "  FALSE POSITIVES:      {:>4} / {} ({})",
        ben_flagged,
        benign.len(),
        pct(ben_flagged, benign.len())
    );
    if !fp_per_class.is_empty() {
        println!("  FP by class:");
        for (class, n) in &fp_per_class {
            let total = benign.iter().filter(|b| b.class == *class).count();
            println!("    {:<20} {:>3} / {}", class, n, total);
        }
    }
    println!();
    println!(
        "(Informational only — no numeric gate. Transcribe these numbers into \
         BENCHMARK.md §\"Mirror paraphrase benchmark (external #2)\".)"
    );

    // Bucket coverage: every case must land in exactly one verdict bucket, so
    // the published denominators are real (same discipline as external #1).
    assert_eq!(
        atk_blocked + atk_warned + atk_allowed,
        attacks.len(),
        "verdict buckets do not cover all attack cases — some were silently \
         skipped and the benchmark harness is broken"
    );
}
