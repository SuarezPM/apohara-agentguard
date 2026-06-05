//! Two-stage matchers for DJL rules whose Python `re` patterns use lookaround
//! features that the Rust `regex` crate cannot compile (it forbids lookahead /
//! lookbehind to guarantee linear-time matching).
//!
//! Each matcher is broad-regex (a pattern `regex` *can* compile) followed by a
//! Rust post-validator that reproduces the exact lookaround semantics of the
//! original Python rule. The three affected rules:
//!
//! - `DJL-PII-001` US SSN — `\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`
//! - `DJL-PII-008` German Steuer-ID — `(?<!\d)\d{11}(?!\d)`
//! - `DJL-HARM-003` weapons/explosives — phrase + trailing `(?![\w\-])`
//!
//! These are the *only* rules requiring this treatment: every other DJL and
//! OWASP pattern uses solely `(?:...)`, `(?i)`, `\b`, and character classes,
//! all of which port directly.

use std::sync::LazyLock;

use regex::Regex;

/// Stable id => two-stage matcher fn, so the registry in [`super::djl`] can
/// route the three lookaround rules without inlining their logic.
pub fn matches(id: &str, text: &str) -> bool {
    match id {
        "DJL-PII-001" => ssn_matches(text),
        "DJL-PII-008" => steuer_id_matches(text),
        "DJL-HARM-003" => weapons_matches(text),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// DJL-PII-001 — US SSN
// ---------------------------------------------------------------------------
//
// Python: \b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b
// Stage 1: broad `\b\d{3}-\d{2}-\d{4}\b`.
// Stage 2: reject area in {000, 666, 900..=999}, group == 00, serial == 0000.

static SSN_BROAD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").expect("valid SSN regex"));

/// True iff `text` contains a structurally valid US SSN (matching the Python
/// lookahead-guarded rule's semantics).
pub fn ssn_matches(text: &str) -> bool {
    SSN_BROAD.captures_iter(text).any(|c| {
        let area = &c[1];
        let group = &c[2];
        let serial = &c[3];
        // (?!000|666|9\d{2}) on the area number.
        let area_ok = area != "000" && area != "666" && !area.starts_with('9');
        // (?!00) on the group number.
        let group_ok = group != "00";
        // (?!0000) on the serial number.
        let serial_ok = serial != "0000";
        area_ok && group_ok && serial_ok
    })
}

// ---------------------------------------------------------------------------
// DJL-PII-008 — German Steuer-ID (11-digit run, digit-boundary on both sides)
// ---------------------------------------------------------------------------
//
// Python: \b(?<!\d)\d{11}(?!\d)\b
// The lookbehind `(?<!\d)` and lookahead `(?!\d)` require that the 11-digit run
// is NOT adjacent to another digit (so a 12+ digit run does not match). The `\b`
// anchors are redundant with the digit-boundary lookarounds for digit runs.
// Stage 1: find every maximal digit run; Stage 2: accept iff its length is 11.

static DIGIT_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d+").expect("valid digit-run regex"));

/// True iff `text` contains a maximal run of exactly 11 digits (no adjacent
/// digit on either side), matching the Python digit-boundary semantics.
pub fn steuer_id_matches(text: &str) -> bool {
    // A *maximal* digit run has no adjacent digit by construction, so its length
    // being exactly 11 is equivalent to `(?<!\d)\d{11}(?!\d)`.
    DIGIT_RUN.find_iter(text).any(|m| m.as_str().len() == 11)
}

// ---------------------------------------------------------------------------
// DJL-HARM-003 — Weapons / explosives assembly instructions (EN)
// ---------------------------------------------------------------------------
//
// Python trailing guard: (?![\w\-]) after the target word, so "IED-themed",
// "bomb-themed", "silencer-shaped" do NOT trip the rule — the target must be
// standalone (no word-char or hyphen continuation).
// Stage 1: the full phrase WITHOUT the trailing lookahead, but capture the byte
// offset right after the target word. Stage 2: reject if the next char is a
// word-char or hyphen.

static WEAPONS_BROAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:how\s+to\s+(?:make|build|assemble|construct)|step[s]?\s+to\s+(?:make|build|assemble)|recipe\s+for|instructions?\s+for)\s+(?:a\s+|an\s+)?(?:bomb|explosive|ied|pipe[\s\-]?bomb|nail[\s\-]?bomb|nerve\s+agent|chemical\s+weapon|biological\s+weapon|firearm|untraceable\s+(?:gun|weapon)|ghost\s+gun|silencer|suppressor)",
    )
    .expect("valid weapons regex")
});

/// True iff `text` requests weapons/explosives assembly with the target word
/// standalone, reproducing the Python `(?![\w\-])` trailing guard.
pub fn weapons_matches(text: &str) -> bool {
    WEAPONS_BROAD.find_iter(text).any(|m| {
        // (?![\w\-]): the char immediately after the match must not be a
        // word-char or hyphen.
        match text[m.end()..].chars().next() {
            Some(c) => !(c.is_alphanumeric() || c == '_' || c == '-'),
            None => true, // end of string => guard satisfied
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DJL-PII-001 US SSN ------------------------------------------------

    #[test]
    fn ssn_positive() {
        assert!(ssn_matches("my ssn is 123-45-6789 thanks"));
    }

    #[test]
    fn ssn_negative_benign() {
        // Product code, not an SSN structure.
        assert!(!ssn_matches("order ref AB-12-CDEF for the widget"));
    }

    // Semantic-delta cases: assert the Rust impl agrees with the Python
    // lookahead semantics on the boundary cases the lookaheads were guarding.
    #[test]
    fn ssn_semantic_delta_invalid_area_000() {
        assert!(!ssn_matches("000-12-3456"));
    }

    #[test]
    fn ssn_semantic_delta_invalid_area_666() {
        assert!(!ssn_matches("666-12-3456"));
    }

    #[test]
    fn ssn_semantic_delta_invalid_area_9xx() {
        assert!(!ssn_matches("900-12-3456"));
        assert!(!ssn_matches("999-12-3456"));
    }

    #[test]
    fn ssn_semantic_delta_invalid_group_00() {
        assert!(!ssn_matches("123-00-4567"));
    }

    #[test]
    fn ssn_semantic_delta_invalid_serial_0000() {
        assert!(!ssn_matches("123-45-0000"));
    }

    #[test]
    fn ssn_semantic_delta_valid_canonical() {
        assert!(ssn_matches("123-45-6789"));
    }

    // ---- DJL-PII-008 German Steuer-ID -------------------------------------

    #[test]
    fn steuer_id_positive() {
        assert!(steuer_id_matches("Steuer-ID 12345678901 on file"));
    }

    #[test]
    fn steuer_id_negative_benign() {
        // A 10-digit phone-ish run, not 11.
        assert!(!steuer_id_matches("call 1234567890 today"));
    }

    #[test]
    fn steuer_id_semantic_delta_twelve_digits() {
        // (?<!\d)\d{11}(?!\d): a 12-digit run must NOT match (digit boundary).
        assert!(!steuer_id_matches("123456789012"));
    }

    #[test]
    fn steuer_id_semantic_delta_exactly_eleven() {
        assert!(steuer_id_matches("12345678901"));
    }

    #[test]
    fn steuer_id_semantic_delta_eleven_bounded_by_nondigits() {
        assert!(steuer_id_matches("id=12345678901;"));
    }

    // ---- DJL-HARM-003 weapons ---------------------------------------------

    #[test]
    fn weapons_positive() {
        assert!(weapons_matches("how to build a bomb at home"));
    }

    #[test]
    fn weapons_negative_benign() {
        assert!(!weapons_matches("how to build a website with React"));
    }

    #[test]
    fn weapons_semantic_delta_bare_phrase_matches() {
        // The bare target word (no hyphen suffix) must match.
        assert!(weapons_matches("instructions for an ied"));
    }

    #[test]
    fn weapons_semantic_delta_themed_suffix_excluded() {
        // (?![\w\-]): "IED-themed" must NOT match.
        assert!(!weapons_matches("instructions for an ied-themed costume"));
        assert!(!weapons_matches("recipe for a bomb-shaped cake"));
    }

    #[test]
    fn weapons_semantic_delta_word_continuation_excluded() {
        // A word-char continuation also fails the guard ("bombard").
        assert!(!weapons_matches("how to build a bombardment simulation"));
    }

    // ---- registry dispatch -------------------------------------------------

    #[test]
    fn dispatch_routes_by_id() {
        assert!(matches("DJL-PII-001", "123-45-6789"));
        assert!(matches("DJL-PII-008", "12345678901"));
        assert!(matches("DJL-HARM-003", "how to build a bomb"));
        assert!(!matches("DJL-PII-001", "benign text"));
        assert!(!matches("UNKNOWN-ID", "123-45-6789"));
    }
}
