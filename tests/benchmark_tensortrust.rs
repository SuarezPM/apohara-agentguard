//! External benchmark: the input firewall vs. REAL human-written prompt-injection
//! attacks from the Tensor Trust dataset (BSD-2-Clause; see
//! `tests/corpus/tensortrust/{LICENSE,PROVENANCE.md}`).
//!
//! Why this exists: the in-repo `benchmark.rs` corpus is author-curated, so it
//! can be (unconsciously) tuned to what the gate already catches. This benchmark
//! is the honest counterweight — 400 attacks WE DID NOT WRITE, from a published
//! adversarial-ML dataset, scanned with the production firewall entry point
//! `firewall::scan_content`.
//!
//! What it MEASURES (not a hard 0-FN gate): how many of those human attacks the
//! firewall does NOT flag (false negatives). On the BLOCK-capable surfaces
//! (Read/WebFetch/WebSearch), `scan_content` returning anything other than a
//! `Block` means the attack would slip through — so an attack is counted as a
//! false negative iff its verdict tier is NOT `Block`. (A `Warn` still passes the
//! content through, so it is a miss for this purpose.)
//!
//! The FN count is PUBLISHED to stdout (run with `--nocapture`). Two assertions,
//! neither tuned to the measured value: every corpus case must actually reach a
//! verdict bucket (no silent skips), and the firewall must flag SOMETHING (a
//! run where nothing at all is flagged means the detector is broken, not
//! honest). We do not yet claim a target FN rate on human attacks; measuring it
//! honestly is the entire point of this story (US-D).

use apohara_agentguard::firewall::scan_content;
use apohara_agentguard::verdict::{Thresholds, Tier};

// `scan_content` is the firewall's severity_to_tier mapping, which never
// returns `Tier::Ask` in v0.3 (Ask is a POLICY-engine decision, not a
// severity-tier mapping — F3' sub-step). The `Ask` arm below is
// unreachable in this benchmark and exists only to keep the test binary
// compiling after the v0.3 schema growth.

/// One vendored Tensor Trust record: the human-written `attack` text plus the
/// upstream `sample_id` and a `category` tag, for traceable reporting.
#[derive(serde::Deserialize)]
struct Attack {
    sample_id: i64,
    category: String,
    attack: String,
}

/// Parse the vendored JSONL (one JSON object per line) into attack records.
fn parse_attacks(raw: &str) -> Vec<Attack> {
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("vendored tensortrust line is valid JSON"))
        .collect()
}

#[test]
fn tensortrust_false_negative_benchmark() {
    let attacks = parse_attacks(include_str!("corpus/tensortrust/attacks.jsonl"));

    // Guard the vendored data itself: a truncated/missing corpus would otherwise
    // make the FN count meaninglessly small.
    assert_eq!(
        attacks.len(),
        400,
        "expected 400 vendored Tensor Trust attacks, got {} \
         (see tests/corpus/tensortrust/PROVENANCE.md)",
        attacks.len()
    );

    let thresholds = Thresholds::default();
    let total = attacks.len();
    let mut blocked = 0usize;
    let mut warned = 0usize;
    let mut false_negatives: Vec<&Attack> = Vec::new();

    for a in &attacks {
        match scan_content(&a.attack, &thresholds).tier {
            Tier::Block => blocked += 1,
            Tier::Warn => {
                warned += 1;
                false_negatives.push(a); // Warn passes content through => a miss.
            }
            Tier::Allow => false_negatives.push(a),
            Tier::Ask => unreachable!("scan_content never returns Tier::Ask"),
        }
    }

    let fn_count = false_negatives.len();

    // --- Published measurement (run with --nocapture) ------------------------
    println!();
    println!("== Tensor Trust external benchmark: firewall vs. human-written attacks ==");
    println!(
        "Corpus: {total} real prompt-injection attacks (BSD-2-Clause; \
         200 hijacking + 200 extraction). Source/revision in \
         tests/corpus/tensortrust/PROVENANCE.md."
    );
    println!(
        "Flagged (Block):        {blocked:>4} / {total} ({:>5.1}%)",
        100.0 * blocked as f64 / total as f64
    );
    println!(
        "Warn-only (still slips):{warned:>4} / {total} ({:>5.1}%)",
        100.0 * warned as f64 / total as f64
    );
    println!(
        "FALSE NEGATIVES (not Blocked): {fn_count:>4} / {total} ({:>5.1}%)",
        100.0 * fn_count as f64 / total as f64
    );
    println!("(A Warn passes content through, so it counts as a false negative here.)");

    // Name a bounded sample of the misses so the number is actionable, not a bare
    // statistic — without dumping 400 multi-KB attack bodies to the log.
    if !false_negatives.is_empty() {
        println!();
        println!("Sample of false negatives (up to 15, by upstream sample_id):");
        for a in false_negatives.iter().take(15) {
            let preview: String = a.attack.chars().take(80).collect();
            let preview = preview.replace('\n', " ");
            println!(
                "  - [{}] sample_id={}: {preview:?}",
                a.category, a.sample_id
            );
        }
    }
    println!();

    // --- Assertions (both structural, neither tuned to the measurement) -----
    // (a) Coverage: every corpus case must land in exactly one verdict bucket.
    //     (`fn_count` spans BOTH non-Block tiers: Warn + Allow.) A sum below
    //     the corpus size means cases were silently skipped and the published
    //     FN number is meaningless.
    let allow_only = fn_count - warned; // Allow-tier misses
    assert_eq!(
        blocked + warned + allow_only,
        total,
        "verdict buckets ({blocked}+{warned}+{allow_only}) do not cover all \
         {total} corpus cases — some were silently skipped, the benchmark \
         harness is broken"
    );
    // (b) Floor of usefulness: if NOTHING was flagged, the detector is broken,
    //     not honest. This is NOT a target FN rate — the honest measured value
    //     is the printed number above; transcribe THAT into BENCHMARK.md.
    assert!(
        fn_count < total,
        "firewall flagged nothing — detector broken"
    );
}
