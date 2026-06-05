//! ReDoS guard: feed pathological inputs to the firewall and assert the scan
//! stays bounded AND scales linearly.
//!
//! The Rust `regex` crate is linear-time by construction (no backtracking), so
//! catastrophic backtracking is impossible — this is a regression guard that
//! confirms no two-stage post-validator (or future change) reintroduces
//! super-linear behavior on adversarial inputs.
//!
//! Two checks per input class:
//! 1. Absolute bound: a single scan of a ~2 KB adversarial input stays under a
//!    generous wall-clock cap (the engine's compiled regexes are warmed up
//!    first so one-time `LazyLock` compilation is excluded from the timing).
//! 2. Linearity: a 4x larger input must take well under 16x the time. A
//!    quadratic blowup would fail this even if the absolute timing flaked; this
//!    is the real ReDoS signal and is robust to scheduling jitter.
//!
//! Registered as a `harness = false` bench so it runs as a plain binary under
//! both `cargo test` and `cargo bench`. Sizes are realistic-but-stressful: 2 KB
//! is already far larger than a typical prompt; the firewall is linear so even
//! tens of KB stay in the low-millisecond range in release.

use std::time::{Duration, Instant};

use agentguard::firewall::scan_content;
use agentguard::verdict::Thresholds;

/// Generous absolute cap for a single ~2 KB scan. Release-mode cost is ~tens of
/// microseconds; the unoptimized debug build (what `cargo test` runs) is ~50-100x
/// slower over ~100 patterns (observed worst case ~150 ms on a loaded box). The
/// 400 ms cap catches a true super-linear regression (which would be seconds)
/// while leaving headroom for scheduling jitter. The linearity check below is
/// the primary ReDoS signal; this absolute bound is a coarse backstop.
const MAX: Duration = Duration::from_millis(400);

/// Build the adversarial input families at a given repeat count.
fn inputs(n: usize) -> Vec<(&'static str, String)> {
    vec![
        // Long single-char repeats stress the quantifier-heavy PII / base64 rules.
        ("long_digits", "1".repeat(n)),
        ("long_base64", "A".repeat(n)),
        ("long_dashes", "-".repeat(n)),
        ("long_at", "@".repeat(n)),
        // Many near-miss SSN candidates exercise the two-stage validators.
        ("many_ssn", "123-45-6789 ".repeat(n / 12)),
        ("many_dashed_nums", "1-1-1-1-1-1-1-1 ".repeat(n / 16)),
        // Injection-prefix spam pressures the prompt-injection alternations.
        ("nested_ignore", "ignore ".repeat(n / 7)),
    ]
}

/// Time one scan (engine already warmed).
fn time_scan(text: &str) -> Duration {
    let t = Thresholds::default();
    let start = Instant::now();
    let _ = scan_content(text, &t);
    start.elapsed()
}

fn main() {
    println!("ReDoS guard: pathological-input timing");
    let thresholds = Thresholds::default();

    // Warm up: force LazyLock regex/RegexSet compilation so it is not charged
    // to the first measured scan.
    let _ = scan_content(
        "warmup ignore all previous instructions 123-45-6789",
        &thresholds,
    );

    // --- Absolute bound at ~2 KB ------------------------------------------
    let small = 2_000usize;
    for (label, text) in inputs(small) {
        let elapsed = time_scan(&text);
        println!("  [{small:>6}] {label:<16}: {elapsed:?}");
        assert!(
            elapsed < MAX,
            "ReDoS guard: scan of {label} ({small} units) took {elapsed:?} (>= {MAX:?})"
        );
    }

    // --- Linearity: 4x input must cost well under 16x time ----------------
    // A quadratic regression would push the ratio toward 16+; linear stays ~4.
    let big = small * 4;
    for ((label, small_text), (_, big_text)) in inputs(small).into_iter().zip(inputs(big)) {
        // Median of 3 to damp jitter on the small (fast) measurement.
        let mut small_runs = [
            time_scan(&small_text),
            time_scan(&small_text),
            time_scan(&small_text),
        ];
        small_runs.sort_unstable();
        let small_t = small_runs[1].max(Duration::from_micros(1));
        let big_t = time_scan(&big_text);
        let ratio = big_t.as_secs_f64() / small_t.as_secs_f64();
        println!("  linearity {label:<16}: 4x input => {ratio:.1}x time (small {small_t:?}, big {big_t:?})");
        assert!(
            ratio < 12.0,
            "ReDoS guard: {label} scaled {ratio:.1}x for a 4x input (super-linear); expected ~4x"
        );
    }

    println!("ReDoS guard: PASS");
}
