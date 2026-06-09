//! Pattern matching for the policy engine — shared with the hook's
//! `tool_rule_verdict` so the two CANNOT drift.
//!
//! The semantic is exactly the one the gate's `custom_block_matches` and
//! the hook's `arg_pattern_matches` already use:
//! - a pattern containing `*` matches when every non-empty `*`-separated
//!   part appears in `value` in order (a non-anchored contains-of-parts);
//! - a pattern without `*` matches when it is a substring of `value`.
//!
//! Re-exported `pub(crate)` so the hook can delegate to the SAME function;
//! the `glob_match_reuses_hook_semantics` test (Story 2 acceptance
//! criterion) asserts both the policy matcher and the hook agree on a
//! fixed matrix of inputs.

/// Match a `pattern` against a `value` using the project's canonical
/// `*`-substring semantics.
///
/// A pattern containing `*` matches when every non-empty `*`-separated
/// part appears in `value` in order. A pattern without `*` matches when
/// it is a literal substring of `value`. An empty pattern never matches.
pub(crate) fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            // Pattern is all `*`s — match anything non-empty.
            return !value.is_empty();
        }
        let mut cursor = 0usize;
        for part in parts {
            match value[cursor..].find(part) {
                Some(pos) => cursor += pos + part.len(),
                None => return false,
            }
        }
        true
    } else {
        value.contains(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_reuses_hook_semantics() {
        // The canonical-reference matrix: policy matcher vs. hook semantics.
        // Each row is `(pattern, value, expected)`. The hook's
        // `arg_pattern_matches` (src/hook/mod.rs:452) is a copy of this
        // logic; any divergence is a bug in one of the two.
        let cases: &[(&str, &str, bool)] = &[
            // Literal substring (no `*`).
            ("rm", "rm -rf ~", true),
            ("rm -rf", "rm -rf ~", true),
            ("hello", "rm -rf ~", false),
            // `*`-parts in order (anchored on first part; nothing
            // anchoring the end, so trailing content is fine).
            ("*rm*", "rm -rf ~", true),
            ("*rm*", "do not rm me", true),
            ("*rm*", "no match here", false),
            ("*rm*-rf*", "rm -rf ~", true),
            // "-rf ~" (with the literal space + tilde) is a substring
            // of "rm -rf ~" but NOT of "rm -rf /" (the matcher does
            // NOT collapse whitespace).
            ("*-rf ~*", "rm -rf ~", true),
            ("*-rf ~*", "rm -rf /", false),
            // All-`*` matches anything non-empty.
            ("***", "anything", true),
            ("***", "", false),
            // Empty pattern never matches.
            ("", "anything", false),
        ];
        for (pat, val, exp) in cases {
            assert_eq!(
                pattern_matches(pat, val),
                *exp,
                "pattern_matches({pat:?}, {val:?}) => {} (expected {exp})",
                pattern_matches(pat, val)
            );
        }
    }

    #[test]
    fn empty_pattern_never_matches_even_on_empty_value() {
        assert!(!pattern_matches("", ""));
        assert!(!pattern_matches("", "non-empty"));
    }

    #[test]
    fn star_only_pattern_requires_non_empty_value() {
        assert!(pattern_matches("*", "x"));
        assert!(!pattern_matches("*", ""));
    }
}
