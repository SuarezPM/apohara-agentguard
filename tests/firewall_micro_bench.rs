//! Ad-hoc micro-benchmark for the FASE 5-A firewall normalization (NOT a
//! gate).
//!
//! Measures the wall-clock cost of scanning a deterministic ~100 KB benign
//! document through [`scan_content`]. Run in release mode:
//!
//! ```text
//! cargo test --release --test firewall_micro_bench -- --ignored --nocapture
//! ```
//!
//! Acceptance (from the phase brief): the delta must stay under 2x versus
//! HEAD, and clean-file scans must be dominated by fast-path byte probes —
//! i.e., no allocation on a clean haystack (the borrowed-Cow contract of the
//! pipeline keeps the corpus to a single pass). Informational output only; no
//! numeric assertions on absolute times so the harness stays robust to
//! machine jitter.

use std::time::Instant;

use apohara_agentguard::firewall::scan_content;
use apohara_agentguard::verdict::{Thresholds, Tier};

/// Build a deterministic ~`target_bytes` benign document mixing prose, code,
/// accented text, emoji and query-less URLs — realistic whole-file scan input
/// that must remain Allow AND exercise every normalization fast path.
fn corpus(target_bytes: usize) -> String {
    let mut out = String::with_capacity(target_bytes + 512);
    let mut i = 0usize;
    while out.len() < target_bytes {
        match i % 6 {
            0 => out.push_str(&format!(
                "fn process_item_{i}(input: &str) -> Result<Item, Error> {{ let cached = cache.get_or_insert(input); Ok(Item::new(cached)) }}\n"
            )),
            1 => out.push_str(&format!(
                "NOTE [{i}]: el café del niño José está sobre la mesa {i} veces — revisar después.\n"
            )),
            2 => out.push_str(&format!(
                "# Release notes v0.{i}\n- fixed parser edge case\n- improved docs\nSee https://example.test/docs/release-{i} for details.\n"
            )),
            3 => out.push_str("这是一段正常的中文说明文本，用于测试多字节内容的扫描性能。\n"),
            4 => out.push_str(&format!(
                "team sync \u{1F44D} shipped \u{1F680} item {i}: [31m literal brackets and {{json: true}} stay intact\n"
            )),
            _ => out.push_str(&format!(
                "log line {}: GET /api/v1/items/{} -> 200 OK ({} ms) user=dev-{}\n",
                i,
                i * 7,
                i % 50 + 1,
                i % 13
            )),
        }
        i += 1;
    }
    out
}

fn bench(label: &str, f: impl Fn(&str)) {
    // Warmup: LazyLock rule tables + DFA caches + allocator arenas.
    let warm = corpus(4_096);
    for _ in 0..32 {
        f(&warm);
    }
    let text = corpus(100_000);
    const ITERATIONS: u32 = 1000;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        f(&text);
    }
    let total = start.elapsed();
    println!(
        "{label:<22} {ITERATIONS} iterations over {} bytes: total {:?}, per-scan {:?}",
        text.len(),
        total,
        total / ITERATIONS
    );
}

#[test]
#[ignore = "ad-hoc timing harness; run explicitly with --ignored --nocapture"]
fn micro_bench_scan_100kb_clean_file() {
    let t = Thresholds::default();
    let text = corpus(100_000);

    // Structural sanity: the corpus is BENIGN and must stay Allow (a Block
    // here would invalidate the measurement entirely).
    assert_eq!(scan_content(&text, &t).tier, Tier::Allow);

    bench("scan_content (clean)", |s| {
        let _ = scan_content(s, &t);
    });
}
