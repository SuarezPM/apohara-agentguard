//! FP/FN benchmark with PRE-COMMITTED, ABSOLUTE pass/fail gates.
//!
//! Runs BOTH engines over the SAME two corpora:
//!   (a) apohara-agentguard — `gate::evaluate(cmd, &Config::default())`, where a `Block`
//!       counts as "flagged" (and `Warn` on benign is reported separately);
//!   (b) the naive fixed-list baseline (`common::naive_fixed_list`, the exact
//!       hookify-class substring gate lifted from `inv_bash_scope.rs`).
//!
//! Metrics (raw counts + rates):
//!   - apohara-agentguard FP  = benign commands that BLOCK (per spec, FP = benign Block)
//!   - apohara-agentguard FN  = dangerous commands NOT Blocked
//!   - naive FP       = benign commands the baseline flags
//!   - naive FN       = dangerous commands the baseline misses
//!   - Warn-on-benign = informational only (kept low, NOT a hard fail)
//!
//! PRE-COMMITTED HARD GATES (asserted, NOT tuned to the measured values):
//!   1. apohara-agentguard FP_block == 0 on the benign corpus
//!   2. apohara-agentguard FN       == 0 on the dangerous corpus
//!   3. apohara-agentguard FN       <  naive FN  (the quantified differentiator)
//!
//! If any gate fails, this test fails. The corpus is NOT to be tuned to make it
//! pass: a benign command that Blocks is a real bug (or a mis-curated entry), and
//! a dangerous command that slips is a real false negative. A summary table is
//! printed to stdout (run with `--nocapture`) for transcription into the README.

use apohara_agentguard::config::Config;
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::verdict::Tier;

mod common;
use common::naive_fixed_list;

/// Parse a corpus file into logical commands.
///
/// - `#`-prefixed lines and blank lines are ignored.
/// - A physical line ending in a single odd-count trailing backslash is a
///   shell line-continuation: it is rejoined with the next physical line,
///   preserving the `\<newline>` so the gate's normalize pre-pass sees the real
///   construct (e.g. the `r\<nl>m -rf ~` evasion in `dangerous.txt`).
fn parse_corpus(raw: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut pending: Option<String> = None;

    for line in raw.lines() {
        // If we are mid-continuation, this physical line is part of the previous
        // logical command, regardless of comment/blank rules.
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

    // A trailing dangling continuation (no following line) is still a command.
    if let Some(acc) = pending {
        commands.push(acc);
    }

    commands
}

/// True if the line ends with an odd number of backslashes (a real shell
/// line-continuation; an even count is an escaped literal backslash).
fn ends_with_odd_backslash(line: &str) -> bool {
    let trailing = line.chars().rev().take_while(|&c| c == '\\').count();
    trailing % 2 == 1
}

struct Counts {
    n: usize,
    ag_block: usize,
    ag_warn: usize,
    naive_flag: usize,
}

fn measure(commands: &[String]) -> Counts {
    let cfg = Config::default();
    let mut c = Counts {
        n: commands.len(),
        ag_block: 0,
        ag_warn: 0,
        naive_flag: 0,
    };
    for cmd in commands {
        match evaluate(cmd, &cfg).tier {
            Tier::Block => c.ag_block += 1,
            Tier::Warn => c.ag_warn += 1,
            Tier::Allow => {}
        }
        if naive_fixed_list(cmd) {
            c.naive_flag += 1;
        }
    }
    c
}

fn rate(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        100.0 * num as f64 / den as f64
    }
}

#[test]
fn fp_fn_benchmark_vs_naive_baseline() {
    let benign = parse_corpus(include_str!("corpus/benign.txt"));
    let dangerous = parse_corpus(include_str!("corpus/dangerous.txt"));

    assert!(
        benign.len() >= 60,
        "benign corpus must have >= 60 commands, got {}",
        benign.len()
    );
    assert!(
        dangerous.len() >= 30,
        "dangerous corpus must have >= 30 commands, got {}",
        dangerous.len()
    );

    let b = measure(&benign);
    let d = measure(&dangerous);

    // apohara-agentguard: FP = benign that BLOCK; FN = dangerous NOT blocked.
    let ag_fp = b.ag_block;
    let ag_warn_benign = b.ag_warn;
    let ag_fn = d.n - d.ag_block;
    // naive baseline: FP = benign flagged; FN = dangerous NOT flagged.
    let naive_fp = b.naive_flag;
    let naive_fn = d.n - d.naive_flag;

    // --- Summary table (raw counts + rates) for README transcription ---------
    println!();
    println!("== FP/FN benchmark: apohara-agentguard vs naive fixed-list baseline ==");
    println!("Corpus: {} benign, {} dangerous (same corpus, both engines; author-curated; dangerous.txt deliberately includes apohara-agentguard-targeted constructs).", b.n, d.n);
    println!();
    println!(
        "| Engine     | Benign N | FP (block) | FP rate | Dangerous N | FN (miss) | FN rate |"
    );
    println!(
        "|------------|---------:|-----------:|--------:|------------:|----------:|--------:|"
    );
    println!(
        "| apohara-agentguard | {:>8} | {:>10} | {:>6.1}% | {:>11} | {:>9} | {:>6.1}% |",
        b.n,
        ag_fp,
        rate(ag_fp, b.n),
        d.n,
        ag_fn,
        rate(ag_fn, d.n)
    );
    println!(
        "| naive      | {:>8} | {:>10} | {:>6.1}% | {:>11} | {:>9} | {:>6.1}% |",
        b.n,
        naive_fp,
        rate(naive_fp, b.n),
        d.n,
        naive_fn,
        rate(naive_fn, d.n)
    );
    println!();
    println!(
        "Informational (NOT a hard gate): apohara-agentguard Warn-on-benign = {} of {} ({:.1}%).",
        ag_warn_benign,
        b.n,
        rate(ag_warn_benign, b.n)
    );
    println!();

    // If a gate is about to fail, name the offending commands so the failure is
    // actionable (a real bug surfaced, not a number to silently relax).
    if ag_fp > 0 {
        let offenders: Vec<&String> = benign
            .iter()
            .filter(|c| evaluate(c, &Config::default()).tier == Tier::Block)
            .collect();
        println!("FALSE POSITIVES (benign that BLOCK) — investigate, do not tune away:");
        for o in &offenders {
            println!("  - {o:?}");
        }
    }
    if ag_fn > 0 {
        let offenders: Vec<&String> = dangerous
            .iter()
            .filter(|c| evaluate(c, &Config::default()).tier != Tier::Block)
            .collect();
        println!("FALSE NEGATIVES (dangerous NOT blocked) — investigate, do not tune away:");
        for o in &offenders {
            println!("  - {o:?}");
        }
    }

    // --- PRE-COMMITTED, ABSOLUTE GATES ---------------------------------------
    assert_eq!(
        ag_fp, 0,
        "GATE 1 FAILED: apohara-agentguard has {ag_fp} false positive(s) (benign that BLOCK). \
         A benign command blocking is a real bug or a mis-curated corpus entry — fix it honestly, do not relax the gate."
    );
    assert_eq!(
        ag_fn, 0,
        "GATE 2 FAILED: apohara-agentguard has {ag_fn} false negative(s) (dangerous NOT blocked). \
         A dangerous command slipping is a real FN — fix the gate, do not relax the corpus."
    );
    assert!(
        ag_fn < naive_fn,
        "GATE 3 FAILED: apohara-agentguard FN ({ag_fn}) must be strictly < naive baseline FN ({naive_fn}); \
         the quantified differentiator does not hold."
    );
}
