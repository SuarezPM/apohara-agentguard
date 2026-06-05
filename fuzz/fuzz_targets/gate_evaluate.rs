//! Fuzz target hardening the gate's core soundness claim ("parser-bounded").
//!
//! It drives arbitrary bytes through the exact pipeline the live hook uses —
//! `normalize_command` -> `split_compound` -> `gate::evaluate` — and enforces
//! two invariants:
//!
//! * **INVARIANT 1 (implicit, primary): the gate never panics / never hangs.**
//!   libfuzzer reports any panic as a crash and has its own timeout, so simply
//!   exercising the functions on adversarial UTF-8 proves the never-abort
//!   contract that "parser-bounded" rests on. This is the load-bearing check.
//!
//! * **INVARIANT 2 (explicit, conservative): a real `rm -rf <path>` leg is
//!   never Allowed.** Asserting this on *arbitrary* input would produce
//!   spurious crashes (most random bytes are benign and correctly Allowed), so
//!   the check is deliberately constructed: we splice a known-dangerous
//!   `rm -rf <suffix>` leg onto the fuzzer-derived bytes as its own top-level
//!   leg. The gate is contracted to surface a destructive `rm -rf` against a
//!   path, so for this constructed input it MUST NOT return `Allow`. This
//!   hardens the destructive-leg-surfacing claim without false positives.

#![no_main]

use agentguard::config::Config;
use agentguard::gate::{self, compound, normalize};
use agentguard::verdict::Tier;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lossy so EVERY byte slice becomes a &str — we want to fuzz the gate, not
    // UTF-8 validation, and the live hook also receives already-decoded strings.
    let s = String::from_utf8_lossy(data);

    let config = Config::default();

    // INVARIANT 1: none of these may panic on any input.
    let _ = normalize::normalize_command(&s);
    let _ = compound::split_compound(&s);
    let _ = gate::evaluate(&s, &config);

    // INVARIANT 2 (conservative): a deliberately-constructed dangerous leg must
    // never be Allowed. We append `rm -rf <fuzz-derived path>` as its own leg
    // (separated by `;`). The fuzzer can mutate the path/prefix freely, but the
    // destructive verb+flags+target shape is fixed by us, so the gate's
    // contract ("surface destructive `rm -rf` legs") must hold: Warn or Block,
    // never Allow.
    //
    // Both the prefix and the path are sanitized to plain shell words: we drop
    // every shell-significant char (quotes, separators, expansions, escapes) so
    // the constructed input is exactly `<prefix> ; rm -rf <path>` with the
    // destructive `rm -rf` unambiguously in command position and UNQUOTED. This
    // keeps the assertion narrow — it never accuses the gate of a false negative
    // when a fuzzer-injected quote/separator would legitimately change parsing
    // (e.g. `rm -rf` landing inside a quoted argument, which the verb-aware
    // taxonomy correctly treats as data).
    fn plain_word(input: &str, max: usize) -> String {
        input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~'))
            .take(max)
            .collect()
    }

    let prefix = plain_word(&s, 64);
    let path = {
        let p = plain_word(&s, 64);
        if p.is_empty() {
            "~/target".to_string()
        } else {
            p
        }
    };

    let constructed = format!("{prefix} ; rm -rf {path}");
    let verdict = gate::evaluate(&constructed, &config);
    assert_ne!(
        verdict.tier,
        Tier::Allow,
        "INVARIANT 2 violated: a constructed `rm -rf {path}` leg was Allowed for input {constructed:?}"
    );

    // INVARIANT 2b (constructed): a `$(rm -rf <path>)` LIVE command substitution
    // placed inside a DOUBLE-quoted argument to a non-executing verb (`echo`) is
    // run by bash regardless of the outer verb. This closes the structural blind
    // spot of the A5 verb-aware taxonomy (which used to strip the whole quoted
    // span, deleting the live substitution). The body is fixed by us to the
    // unambiguous destructive `rm -rf <path>` shape, so the gate MUST NOT Allow.
    // The path is the same sanitized plain shell word (no quotes/separators that
    // would legitimately change parsing), keeping the assertion narrow.
    let smuggled = format!("echo \"$(rm -rf {path})\"");
    let smuggled_verdict = gate::evaluate(&smuggled, &config);
    assert_ne!(
        smuggled_verdict.tier,
        Tier::Allow,
        "INVARIANT 2b violated: a live `$(rm -rf {path})` inside a double-quoted \
         non-exec verb arg was Allowed for input {smuggled:?}"
    );
});
