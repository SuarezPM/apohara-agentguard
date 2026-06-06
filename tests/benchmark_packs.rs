//! Per-pack FP/FN benchmark for the OPT-IN domain packs (cloud / db / container).
//!
//! For EACH pack, the gate runs with ONLY that pack enabled
//! (`config.packs = [pack]`) over its own `{benign,dangerous}_<pack>.txt`
//! corpora, asserting the same ABSOLUTE gates as the default benchmark:
//!   1. FP_block == 0 on the pack's benign corpus (a benign look-alike Blocking
//!      is a real over-match bug — fix the rule, do not relax the corpus).
//!   2. FN       == 0 on the pack's dangerous corpus (a destructive command
//!      slipping is a real false negative — fix the rule).
//!
//! Packs are OFF by default, so these corpora never touch `tests/benchmark.rs`
//! (which runs `Config::default()`); a separate test asserts that invariant.

use apohara_agentguard::config::Config;
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::verdict::Tier;

/// Parse a corpus file into logical commands: `#`-prefixed and blank lines are
/// ignored (the pack corpora use no line-continuations, so a single-line parse
/// is sufficient — see `tests/benchmark.rs` for the continuation-aware variant).
fn parse_corpus(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// A config with exactly one pack enabled.
fn config_with_pack(pack: &str) -> Config {
    Config {
        packs: vec![pack.to_string()],
        ..Config::default()
    }
}

/// Run one pack's corpora and assert 0-FP / 0-FN.
fn assert_pack(pack: &str, benign_raw: &str, dangerous_raw: &str) {
    let cfg = config_with_pack(pack);
    let benign = parse_corpus(benign_raw);
    let dangerous = parse_corpus(dangerous_raw);

    assert!(
        benign.len() >= 5,
        "[{pack}] benign corpus must have >= 5 commands, got {}",
        benign.len()
    );
    assert!(
        dangerous.len() >= 5,
        "[{pack}] dangerous corpus must have >= 5 commands, got {}",
        dangerous.len()
    );

    let fp: Vec<&String> = benign
        .iter()
        .filter(|c| evaluate(c, &cfg).tier == Tier::Block)
        .collect();
    let fn_: Vec<&String> = dangerous
        .iter()
        .filter(|c| evaluate(c, &cfg).tier != Tier::Block)
        .collect();

    if !fp.is_empty() {
        println!("[{pack}] FALSE POSITIVES (benign that BLOCK) — fix the rule, do not tune away:");
        for o in &fp {
            println!("  - {o:?}");
        }
    }
    if !fn_.is_empty() {
        println!("[{pack}] FALSE NEGATIVES (dangerous NOT blocked) — fix the rule:");
        for o in &fn_ {
            println!("  - {o:?}");
        }
    }

    assert_eq!(
        fp.len(),
        0,
        "[{pack}] GATE 1 FAILED: {} false positive(s) (benign that BLOCK).",
        fp.len()
    );
    assert_eq!(
        fn_.len(),
        0,
        "[{pack}] GATE 2 FAILED: {} false negative(s) (dangerous NOT blocked).",
        fn_.len()
    );
}

#[test]
fn cloud_pack_zero_fp_zero_fn() {
    assert_pack(
        "cloud",
        include_str!("corpus/benign_cloud.txt"),
        include_str!("corpus/dangerous_cloud.txt"),
    );
}

#[test]
fn db_pack_zero_fp_zero_fn() {
    assert_pack(
        "db",
        include_str!("corpus/benign_db.txt"),
        include_str!("corpus/dangerous_db.txt"),
    );
}

#[test]
fn container_pack_zero_fp_zero_fn() {
    assert_pack(
        "container",
        include_str!("corpus/benign_container.txt"),
        include_str!("corpus/dangerous_container.txt"),
    );
}

#[test]
fn packs_off_by_default_do_not_block_pack_targets() {
    // With NO packs enabled (Config::default), a pack-only destructive command
    // is NOT blocked — proving packs are opt-in and never touch the default
    // benchmark. (These commands match no built-in taxonomy rule.)
    let cfg = Config::default();
    assert!(cfg.packs.is_empty());
    for cmd in [
        "aws s3 rb s3://my-bucket --force",
        "DROP TABLE users;",
        "docker system prune -af",
        "kubectl delete pods --all",
    ] {
        assert_eq!(
            evaluate(cmd, &cfg).tier,
            Tier::Allow,
            "with packs OFF, `{cmd}` must Allow (opt-in invariant)"
        );
    }
}
