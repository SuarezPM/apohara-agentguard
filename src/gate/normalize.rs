//! Bounded, in-place normalization pre-pass that closes four Bash obfuscation
//! evasions BEFORE the command is split into legs.
//!
//! Unlike a tokenizer, every pass here performs an **in-place textual splice**:
//! the decoded/extracted text is written contiguously into the command string
//! where the construct stood, so the result is a normal command line that
//! [`crate::gate::compound::split_compound`] then tokenizes exactly as it would
//! a hand-typed command. Example: `$(echo rm) -rf ~` becomes the contiguous
//! string `rm -rf ~`, so taxonomy `m_rm_rf` fires on the single surfaced leg.
//!
//! Passes run in ONE shared, ordered rewrite buffer so they compose
//! (e.g. ANSI-C inside an echo-subst: `$(echo $'\x72\x6d')` → `rm`):
//!   1. backslash line-continuation join (`\<newline>` → ``)
//!   2. ANSI-C `$'...'` decoding (spliced in place of the span)
//!   3. hex-encoded `printf '<\xHH…>' | <shell>` decode — the invocation is
//!      replaced by its decoded literal so the piped interpreter's input is
//!      what gets scanned (**leg-head/verb position only**)
//!   4. echo/printf command-substitution splice — **leg-head/verb position only**
//!   5. IFS reassignment — records an extra top-level separator (NOT a splice)
//!
//! This is a *string rewriter with a hard budget*, never a shell evaluator.
//! Three caps bound fan-out: [`MAX_NORMALIZE_BYTES`] (total size),
//! [`MAX_REWRITES`] (number of splices across all passes), and a per-span
//! expansion-ratio cap (a decoded span may not exceed `4×` its source length).

use std::borrow::Cow;

/// Maximum size (in bytes) of the rewrite buffer. Inputs/rewrites past this are
/// left intact (mirrors `decode::MAX_DECODE_BYTES`).
pub(crate) const MAX_NORMALIZE_BYTES: usize = 64 * 1024;

/// Maximum number of in-place splices across the whole pre-pass. A pathological
/// input with hundreds of spans cannot fan out past this.
pub(crate) const MAX_REWRITES: usize = 64;

/// A decoded/extracted span may not exceed this multiple of its source length.
const MAX_EXPANSION_RATIO: usize = 4;

/// The result of [`normalize_command`]: the rewritten command plus any
/// top-level separators derived from an `IFS=<char>` reassignment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)] // Internal type — lifetime param change is not a public API break
pub struct Normalized<'a> {
    /// The command after the in-place splices.
    pub command: Cow<'a, str>,
    /// Extra characters to treat as top-level separators when splitting the
    /// SUBSEQUENT legs (from an `IFS=<char>` reassignment). Empty by default.
    pub extra_separators: Vec<char>,
}

/// Apply the four bounded normalization passes in order, in one shared buffer.
///
/// The gate calls this internally; this is `pub` (hidden from docs) so the fuzz
/// target + `tests/gate_normalize.rs` can pin the pre-pass directly.
#[doc(hidden)]
pub fn normalize_command<'a>(cmd: &'a str) -> Normalized<'a> {
    if cmd.len() > MAX_NORMALIZE_BYTES {
        return Normalized {
            command: Cow::Borrowed(cmd),
            extra_separators: Vec::new(),
        };
    }

    let mut budget = Budget {
        rewrites: 0,
        max_bytes: MAX_NORMALIZE_BYTES,
    };

    // Pass 1: join backslash line-continuations.
    let s = join_line_continuations(Cow::Borrowed(cmd), &mut budget);
    // Pass 2: decode ANSI-C `$'...'` spans in place.
    let s = decode_ansi_c(s, &mut budget);
    // Pass 3: decode a leg-head `printf '<\xHH…>' | <shell>` into its literal.
    let s = decode_printf_pipe_shell(s, &mut budget);
    // Pass 4: splice leg-head echo/printf command substitutions.
    let s = splice_echo_substitution(s, &mut budget);
    // Pass 5: collect IFS-derived extra separators (no splice).
    let extra_separators = collect_ifs_separators(&s);

    Normalized {
        command: s,
        extra_separators,
    }
}

/// Shared splice budget across all passes.
struct Budget {
    rewrites: usize,
    max_bytes: usize,
}

impl Budget {
    /// Try to consume one rewrite producing a result of `new_len` bytes. Returns
    /// false (refuse) when the count cap or the byte cap would be exceeded.
    fn allow(&mut self, new_len: usize) -> bool {
        if self.rewrites >= MAX_REWRITES || new_len > self.max_bytes {
            return false;
        }
        self.rewrites += 1;
        true
    }
}

// --- Pass 1: backslash line-continuation -----------------------------------

/// Join `\<newline>` and `\<carriage-return><newline>` into nothing (continue
/// the line). A lone trailing `\` not before a newline is left untouched, and a
/// `\x`-style escape (not before a newline) is left for the ANSI-C pass.
fn join_line_continuations<'a>(s: Cow<'a, str>, budget: &mut Budget) -> Cow<'a, str> {
    if !s.contains('\\') {
        return s;
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            // `\` + `\n`
            if bytes.get(i + 1) == Some(&b'\n') && budget.allow(out.len()) {
                i += 2;
                continue;
            }
            // `\` + `\r\n`
            if bytes.get(i + 1) == Some(&b'\r')
                && bytes.get(i + 2) == Some(&b'\n')
                && budget.allow(out.len())
            {
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Cow::Owned(out)
}

// --- Pass 2: ANSI-C `$'...'` quoting ----------------------------------------

/// Find `$'...'` spans (outside `'...'` / `"..."`) and splice their decoded
/// literal in place. Respects the byte/count budget and a per-span 4× expansion
/// cap; a span that violates a cap (or contains a malformed escape we choose not
/// to expand) is left intact.
fn decode_ansi_c<'a>(s: Cow<'a, str>, budget: &mut Budget) -> Cow<'a, str> {
    if !s.contains("$'") {
        return s;
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while i < bytes.len() {
        let c = bytes[i];

        // `$'` only starts an ANSI-C span outside ordinary quotes.
        if c == b'$' && bytes.get(i + 1) == Some(&b'\'') && !in_single && !in_double {
            if let Some((decoded, end)) = read_ansi_c_span(bytes, i) {
                let src_len = end - i;
                let within_ratio = decoded.len() <= src_len.saturating_mul(MAX_EXPANSION_RATIO);
                if within_ratio && budget.allow(out.len() + decoded.len()) {
                    out.push_str(&decoded);
                    i = end;
                    continue;
                }
                // Cap exceeded: leave the span verbatim.
                out.push_str(&s[i..end]);
                i = end;
                continue;
            }
        }

        // Track ordinary quote state so we never touch `$'` inside `'...'`/`"..."`.
        if c == b'\'' && !in_double {
            in_single = !in_single;
        } else if c == b'"' && !in_single {
            in_double = !in_double;
        }

        out.push(c as char);
        i += 1;
    }
    Cow::Owned(out)
}

/// Read a `$'...'` span starting at `start` (pointing at `$`). Returns the
/// decoded literal and the index just past the closing `'`, or `None` if the
/// span is unterminated.
fn read_ansi_c_span(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    // bytes[start] == '$', bytes[start+1] == '\''
    let mut i = start + 2;
    let mut decoded = String::new();
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' {
            return Some((decoded, i + 1));
        }
        if c == b'\\' && i + 1 < bytes.len() {
            let (ch, advance) = decode_escape(bytes, i + 1);
            if let Some(ch) = ch {
                decoded.push(ch);
                i = advance;
                continue;
            }
            // Unknown escape: keep the backslash + char literally.
            decoded.push('\\');
            decoded.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        decoded.push(c as char);
        i += 1;
    }
    None // unterminated span
}

/// Decode a single ANSI-C escape whose backslash was at `pos-1`; `pos` points at
/// the first char after the backslash. Returns `(Some(char), next_index)` for a
/// recognised escape, or `(None, _)` to signal "unknown, keep literally".
fn decode_escape(bytes: &[u8], pos: usize) -> (Option<char>, usize) {
    let c = bytes[pos];
    match c {
        b'n' => (Some('\n'), pos + 1),
        b't' => (Some('\t'), pos + 1),
        b'r' => (Some('\r'), pos + 1),
        b'\\' => (Some('\\'), pos + 1),
        b'\'' => (Some('\''), pos + 1),
        b'"' => (Some('"'), pos + 1),
        b'x' => {
            // \xHH (1-2 hex digits)
            let mut j = pos + 1;
            let mut val: u32 = 0;
            let mut count = 0;
            while j < bytes.len() && count < 2 && bytes[j].is_ascii_hexdigit() {
                val = val * 16 + hex_val(bytes[j]);
                j += 1;
                count += 1;
            }
            if count == 0 {
                return (None, pos);
            }
            (char::from_u32(val), j)
        }
        b'u' => {
            // \uHHHH (up to 4 hex digits)
            let mut j = pos + 1;
            let mut val: u32 = 0;
            let mut count = 0;
            while j < bytes.len() && count < 4 && bytes[j].is_ascii_hexdigit() {
                val = val * 16 + hex_val(bytes[j]);
                j += 1;
                count += 1;
            }
            if count == 0 {
                return (None, pos);
            }
            (char::from_u32(val), j)
        }
        b'0'..=b'7' => {
            // \NNN or \0NNN octal (up to 3 octal digits after an optional 0).
            let mut j = pos;
            let mut val: u32 = 0;
            let mut count = 0;
            while j < bytes.len() && count < 3 && (b'0'..=b'7').contains(&bytes[j]) {
                val = val * 8 + (bytes[j] - b'0') as u32;
                j += 1;
                count += 1;
            }
            (char::from_u32(val), j)
        }
        _ => (None, pos),
    }
}

fn hex_val(b: u8) -> u32 {
    match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'f' => (b - b'a' + 10) as u32,
        b'A'..=b'F' => (b - b'A' + 10) as u32,
        _ => 0,
    }
}

/// Decode backslash escapes in a printf/echo FORMAT literal (the inner text of
/// a quoted argument), using the same escape table as ANSI-C spans — this is
/// what `printf` itself does to its format string. Returns `None` when any
/// escape is truncated or unrecognized; callers treat that as "leave the
/// construct intact" (fail-closed).
fn decode_printf_escapes(lit: &str) -> Option<String> {
    if !lit.contains('\\') {
        return Some(lit.to_string());
    }
    let bytes = lit.as_bytes();
    let mut out = String::with_capacity(lit.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            if i + 1 >= bytes.len() {
                return None; // lone trailing backslash
            }
            let (ch, next) = decode_escape(bytes, i + 1);
            out.push(ch?);
            i = next;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    Some(out)
}

// --- Pass 3: hex-encoded printf piped to a shell -----------------------------

/// Shell interpreters a piped `printf '<lit>'` leg may feed for its payload to
/// be surfaced. Matched on the target's basename, so `/bin/sh` counts while
/// `| xargs sh` or `| env sh` do not (conservative).
const SHELL_INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "ksh", "dash", "ash", "busybox"];

/// Decode a leg-head `printf '\xHH…'` invocation whose leg pipes into a shell
/// interpreter (`| sh`, `| /bin/bash`, …): the whole invocation up to its
/// closing quote is replaced by the DECODED literal, leaving the pipe tail in
/// place so the split surfaces exactly what the interpreter would read from
/// stdin. This closes the benchmark "hexesc" manipulation
/// (`cat /etc/shadow` → `printf '\x63\x61\x74\x20…' | sh`).
///
/// Deliberately narrow (fail-closed): only a single single-quoted argument
/// containing at least one `\xHH` escape is decoded. `%` or `$` inside the
/// literal, double-quoted/backtick arguments, anything but whitespace between
/// the closing quote and the `|`, a non-shell pipe target, or any malformed
/// escape leave the command intact.
fn decode_printf_pipe_shell<'a>(s: Cow<'a, str>, budget: &mut Budget) -> Cow<'a, str> {
    // Cheap guards before walking bytes (hot path): both are necessary
    // conditions of the shape, so missing either skips the pass entirely.
    if !s.contains("printf") || !s.contains(r"\x") {
        return s;
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while i < bytes.len() {
        let c = bytes[i];

        if c == b'p'
            && !in_single
            && !in_double
            && at_leg_head(&out)
            && bytes[i..].starts_with(b"printf")
        {
            if let Some((decoded, end)) = try_decode_printf_head(bytes, i) {
                let src_len = end - i;
                // Decoding shrinks (\xHH → one byte); enforce the shared cap anyway.
                let within_ratio = decoded.len() <= src_len.saturating_mul(MAX_EXPANSION_RATIO);
                if within_ratio && budget.allow(out.len() + decoded.len()) {
                    out.push_str(&decoded);
                    i = end;
                    continue;
                }
            }
        }

        // Track ordinary quote state so we never touch a printf inside quotes.
        if c == b'\'' && !in_double {
            in_single = !in_single;
        } else if c == b'"' && !in_single {
            in_double = !in_double;
        }

        out.push(c as char);
        i += 1;
    }
    Cow::Owned(out)
}

/// Read a leg-head `printf '<lit>' … | <shell>` span starting at `start`
/// (pointing at `printf`). On success returns the decoded literal and the index
/// just past the closing quote — the `| <shell>` tail is verified but NOT part
/// of the replacement. `None` for any shape outside the accepted form (see
/// [`decode_printf_pipe_shell`]).
fn try_decode_printf_head(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    const VERB: &[u8] = b"printf";
    let mut j = start + VERB.len();
    while matches!(bytes.get(j), Some(b' ') | Some(b'\t')) {
        j += 1;
    }

    // Exactly one argument, single-quoted.
    if bytes.get(j) != Some(&b'\'') {
        return None;
    }
    j += 1;

    let mut decoded = String::new();
    let mut saw_hex = false;
    let close;
    loop {
        let Some(&c) = bytes.get(j) else {
            return None; // unterminated literal
        };
        if c == b'\'' {
            close = j + 1; // just past the closing quote
            j += 1;
            break;
        }
        if c == b'%' || c == b'$' {
            // Format directives consume arguments; `$` is expansion-shaped even
            // though single quotes make it literal. Don't model either.
            return None;
        }
        if c == b'\\' {
            if j + 1 >= bytes.len() {
                return None; // lone trailing backslash
            }
            saw_hex |= bytes[j + 1] == b'x';
            let (ch, next) = decode_escape(bytes, j + 1);
            decoded.push(ch?); // unknown/truncated escape -> fail closed
            j = next;
            continue;
        }
        decoded.push(c as char);
        j += 1;
    }
    // No `\xHH` anywhere -> not the hexesc shape this pass targets.
    if !saw_hex {
        return None;
    }

    // Only whitespace may sit between the closing quote and the pipe.
    while matches!(bytes.get(j), Some(b' ') | Some(b'\t')) {
        j += 1;
    }
    if bytes.get(j) != Some(&b'|') {
        return None;
    }
    j += 1;
    while matches!(bytes.get(j), Some(b' ') | Some(b'\t')) {
        j += 1;
    }

    // The pipe target token must resolve (basename) to a shell interpreter.
    let tok_end = bytes[j..]
        .iter()
        .position(|b| {
            matches!(
                b,
                b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>'
            )
        })
        .map_or(bytes.len(), |p| j + p);
    if tok_end == j {
        return None; // empty target (`| |sh` etc.)
    }
    let Ok(target) = std::str::from_utf8(&bytes[j..tok_end]) else {
        return None;
    };
    let base = target.rsplit('/').next().unwrap_or(target);
    if !SHELL_INTERPRETERS.contains(&base) {
        return None;
    }

    Some((decoded, close))
}

// --- Pass 4: echo/printf command-substitution splice (leg-head only) --------

/// Splice a leg-head `$(echo ...)` / `` `echo ...` `` / `$(printf ...)` whose
/// body is exactly an `echo`/`printf` of literal args into the literal it would
/// emit. ONLY fires in VERB/command position (the leg head), never as an
/// argument — so `git commit -m "$(echo rm -rf)"` is untouched.
fn splice_echo_substitution<'a>(s: Cow<'a, str>, budget: &mut Budget) -> Cow<'a, str> {
    if !s.contains("$(") && !s.contains('`') {
        return s;
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while i < bytes.len() {
        let c = bytes[i];

        if !in_single && !in_double && at_leg_head(&out) {
            // `$(...)`
            if c == b'$' && bytes.get(i + 1) == Some(&b'(') {
                if let Some((body, end)) = read_paren_body(bytes, i + 2) {
                    if let Some(literal) = echo_printf_literal(&body) {
                        let src_len = end - i;
                        let within_ratio =
                            literal.len() <= src_len.saturating_mul(MAX_EXPANSION_RATIO);
                        if within_ratio && budget.allow(out.len() + literal.len()) {
                            out.push_str(&literal);
                            i = end;
                            continue;
                        }
                    }
                }
            }
            // backtick `...`
            if c == b'`' {
                if let Some((body, end)) = read_backtick_body(bytes, i + 1) {
                    if let Some(literal) = echo_printf_literal(&body) {
                        let src_len = end - i;
                        let within_ratio =
                            literal.len() <= src_len.saturating_mul(MAX_EXPANSION_RATIO);
                        if within_ratio && budget.allow(out.len() + literal.len()) {
                            out.push_str(&literal);
                            i = end;
                            continue;
                        }
                    }
                }
            }
        }

        if c == b'\'' && !in_double {
            in_single = !in_single;
        } else if c == b'"' && !in_single {
            in_double = !in_double;
        }

        out.push(c as char);
        i += 1;
    }
    Cow::Owned(out)
}

/// True iff the text emitted so far ends at a leg head — i.e. the current
/// position is the first token of a leg (only separators/whitespace since the
/// last leg boundary). This is what makes pass 3 fire only in verb position.
fn at_leg_head(out: &str) -> bool {
    for ch in out.chars().rev() {
        match ch {
            ' ' | '\t' => {}                             // leading whitespace, keep scanning
            ';' | '|' | '&' | '\n' | '(' => return true, // leg/group boundary
            _ => return false,                           // a real token precedes us → argument
        }
    }
    true // nothing before us → very first token
}

/// Read a `$(...)`-style paren body starting at `start` (just past `(`),
/// tracking nesting. Returns the inner text and the index just past the
/// matching `)`, or `None` if unterminated.
fn read_paren_body(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    let mut depth = 1usize;
    let mut inner = String::new();
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                return Some((inner, i + 1));
            }
        }
        inner.push(c as char);
        i += 1;
    }
    None
}

/// Read a backtick body starting at `start` (just past the opening backtick).
fn read_backtick_body(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    let mut inner = String::new();
    while i < bytes.len() {
        if bytes[i] == b'`' {
            return Some((inner, i + 1));
        }
        inner.push(bytes[i] as char);
        i += 1;
    }
    None
}

/// If `body` is exactly `echo [-n|-e] <literal...>` or `printf <literal>` with
/// NO `$`, `|`, `;`, `&`, no nested `$(`/backtick, and no flags beyond `-n`/`-e`,
/// return the literal text it would emit. Otherwise `None` (leave intact).
fn echo_printf_literal(body: &str) -> Option<String> {
    let body = body.trim();
    // Reject anything that smells like expansion, chaining, or nesting.
    if body.contains('$')
        || body.contains('|')
        || body.contains(';')
        || body.contains('&')
        || body.contains('`')
    {
        return None;
    }
    let mut tokens = body.split_whitespace();
    let verb = tokens.next()?;
    if verb != "echo" && verb != "printf" {
        return None;
    }
    let mut rest: Vec<&str> = tokens.collect();
    // Allow only `-n`/`-e` flags for echo (printf takes no such flags here).
    if verb == "echo" {
        while let Some(&first) = rest.first() {
            if first == "-n" || first == "-e" {
                rest.remove(0);
            } else {
                break;
            }
        }
    }
    // Any remaining token starting with `-` (other than the literal) is a flag
    // we don't model → bail out conservatively.
    if rest.iter().any(|t| t.starts_with('-')) {
        return None;
    }
    let joined = rest.join(" ");
    // printf interprets backslash escapes in its format; decode them so the
    // spliced literal is what the shell would emit (e.g. `$(printf '\x72\x6d')`
    // surfaces as `rm`). Any malformed escape leaves the substitution intact.
    decode_printf_escapes(&strip_quotes(joined.trim()))
}

/// Remove one layer of matching single/double quotes around `s`.
fn strip_quotes(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

// --- Pass 5: IFS reassignment -----------------------------------------------

/// Scan the top-level legs for an `IFS=<value>` reassignment with a NON-EMPTY,
/// single-character value, and return those characters as extra separators.
/// Empty `IFS=` is a no-op. `IFS=` inside a quoted string is ignored. The
/// returned separators are applied (gated on surfacing a hit) by the caller.
fn collect_ifs_separators(s: &str) -> Vec<char> {
    if !s.contains("IFS=") {
        return Vec::new();
    }
    let mut extra: Vec<char> = Vec::new();
    for leg in top_level_legs(s) {
        let leg = leg.trim();
        if let Some(rest) = leg.strip_prefix("IFS=") {
            // `IFS=` (empty) → no-op. `IFS=X read ...` → take only the value
            // token (up to the first space), single-char only.
            let value = rest.split_whitespace().next().unwrap_or("");
            let unquoted = strip_quotes(value);
            let chars: Vec<char> = unquoted.chars().collect();
            if chars.len() == 1 && !extra.contains(&chars[0]) {
                extra.push(chars[0]);
            }
        }
    }
    extra
}

/// Split `s` into top-level legs on `;`, `\n`, and `&` (quote-aware), WITHOUT
/// recursing into substitutions. Used only to spot a leading `IFS=` leg.
fn top_level_legs(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut legs = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' && !in_double {
            in_single = !in_single;
        } else if c == b'"' && !in_single {
            in_double = !in_double;
        }
        if !in_single && !in_double && (c == b';' || c == b'\n' || c == b'&') {
            let t = current.trim();
            if !t.is_empty() {
                legs.push(t.to_string());
            }
            current.clear();
            i += 1;
            continue;
        }
        current.push(c as char);
        i += 1;
    }
    let t = current.trim();
    if !t.is_empty() {
        legs.push(t.to_string());
    }
    legs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(cmd: &str) -> String {
        normalize_command(cmd).command.into_owned()
    }

    // --- Pass 1: line-continuation ---

    #[test]
    fn joins_backslash_newline() {
        assert_eq!(norm("r\\\nm -rf ~"), "rm -rf ~");
    }

    #[test]
    fn joins_backslash_crlf() {
        assert_eq!(norm("r\\\r\nm -rf ~"), "rm -rf ~");
    }

    #[test]
    fn lone_trailing_backslash_untouched() {
        // `\b` is not a continuation and not a recognised ANSI-C span here.
        assert_eq!(norm("echo a\\b"), "echo a\\b");
    }

    #[test]
    fn lone_backslash_at_end_untouched() {
        assert_eq!(norm("echo foo\\"), "echo foo\\");
    }

    // --- Pass 2: ANSI-C ---

    #[test]
    fn decodes_ansi_c_hex() {
        assert_eq!(norm(r"$'\x72\x6d' -rf ~"), "rm -rf ~");
    }

    #[test]
    fn decodes_ansi_c_octal() {
        // \162 = 'r', \155 = 'm'
        assert_eq!(norm(r"$'\162\155' -rf ~"), "rm -rf ~");
    }

    #[test]
    fn decodes_ansi_c_unicode() {
        // r = 'r', m = 'm'
        let src = format!("$'{}{}' -rf ~", "\\u0072", "\\u006d");
        assert_eq!(norm(&src), "rm -rf ~");
    }

    #[test]
    fn decodes_ansi_c_named_escapes() {
        assert_eq!(norm(r"$'a\tb'"), "a\tb");
    }

    #[test]
    fn does_not_touch_plain_single_quotes() {
        assert_eq!(norm(r"echo 'a\x72b'"), r"echo 'a\x72b'");
    }

    #[test]
    fn does_not_touch_ansi_c_inside_double_quotes() {
        assert_eq!(norm(r#"echo "$'\x72'""#), r#"echo "$'\x72'""#);
    }

    // --- Pass 3: printf hexesc pipe-to-shell ---

    #[test]
    fn decodes_hexesc_printf_pipe_shell() {
        // Exact m_hexesc shape for `cat /etc/shadow`.
        let src = r"printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77' | sh";
        assert_eq!(norm(src), "cat /etc/shadow | sh");
    }

    #[test]
    fn decodes_hexesc_mixed_literal_chars() {
        assert_eq!(norm(r"printf '\x72m -rf /' | sh"), "rm -rf / | sh");
    }

    #[test]
    fn decodes_hexesc_uppercase_hex_digits() {
        assert_eq!(norm(r"printf '\x72\x6D' | sh"), "rm | sh");
    }

    #[test]
    fn decodes_hexesc_pathed_shell_target() {
        assert_eq!(
            norm(r"printf '\x72\x6d -rf /' | /bin/bash"),
            "rm -rf / | /bin/bash"
        );
    }

    #[test]
    fn hexesc_double_quoted_untouched() {
        let src = r#"printf "\x72\x6d" | sh"#;
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_without_pipe_to_shell_untouched() {
        // printf writes to stdout; nothing executes the payload.
        let src = r"printf '\x72\x6d -rf /'";
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_pipe_to_non_shell_untouched() {
        let src = r"printf '\x72\x6d -rf /' | sort";
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_arg_with_dollar_untouched() {
        let src = r"printf '\x72\x6d $HOME' | sh";
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_arg_with_percent_untouched() {
        let src = r"printf '%s\x72\x6d' | sh";
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_truncated_escape_untouched() {
        // `\x` with zero hex digits: malformed byte -> leave intact.
        let src = r"printf '\x72\x' | sh";
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_unknown_escape_untouched() {
        let src = r"printf '\x72\q' | sh";
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_not_in_verb_position_untouched() {
        let src = r#"git commit -m "printf '\x72\x6d' | sh""#;
        assert_eq!(norm(src), src);
    }

    #[test]
    fn hexesc_rewrite_count_cap_enforced() {
        // Many independent hexesc invocations; only MAX_REWRITES decode, the
        // tail stays verbatim.
        let unit = r"printf '\x61\x62\x63\x64' | sh"; // -> `abcd | sh`
        let input = vec![unit; MAX_REWRITES + 5].join("; ");
        let out = norm(&input);
        assert_eq!(out.matches("abcd").count(), MAX_REWRITES);
        assert_eq!(out.matches(unit).count(), 5);
    }

    // --- Pass 4: echo/printf cmdsubst splice (leg-head only) ---

    #[test]
    fn splices_echo_subst_in_verb_position() {
        assert_eq!(norm("$(echo rm) -rf ~"), "rm -rf ~");
    }

    #[test]
    fn splices_backtick_echo_in_verb_position() {
        assert_eq!(norm("`echo rm` -rf ~"), "rm -rf ~");
    }

    #[test]
    fn splices_printf_subst_in_verb_position() {
        assert_eq!(norm("$(printf rm) -rf ~"), "rm -rf ~");
    }

    #[test]
    fn does_not_splice_echo_subst_in_argument_position() {
        // The substitution is an ARGUMENT to git commit -m → must be untouched.
        let s = norm(r#"git commit -m "$(echo rm -rf)""#);
        assert_eq!(s, r#"git commit -m "$(echo rm -rf)""#);
    }

    #[test]
    fn does_not_splice_nested_echo_argument() {
        assert_eq!(norm(r#"echo "$(echo rm)""#), r#"echo "$(echo rm)""#);
    }

    #[test]
    fn does_not_splice_subst_with_expansion() {
        assert_eq!(norm(r#"$(echo "$VAR") -rf ~"#), r#"$(echo "$VAR") -rf ~"#);
    }

    #[test]
    fn does_not_splice_non_echo_subst() {
        assert_eq!(norm("$(git rev-parse HEAD)"), "$(git rev-parse HEAD)");
    }

    #[test]
    fn splices_printf_subst_with_hex_decoded() {
        assert_eq!(norm(r"$(printf '\x72\x6d') -rf ~"), "rm -rf ~");
    }

    #[test]
    fn splices_backtick_printf_subst_with_hex_decoded() {
        assert_eq!(norm(r"`printf '\x72\x6d'` -rf ~"), "rm -rf ~");
    }

    #[test]
    fn does_not_splice_printf_subst_with_malformed_escape() {
        // Fail-closed: a truncated escape leaves the substitution intact.
        let src = r"$(printf '\x72\x') -rf ~";
        assert_eq!(norm(src), src);
    }

    // --- Composition (shared buffer) ---

    #[test]
    fn composes_ansi_c_inside_echo_subst() {
        assert_eq!(norm(r"$(echo $'\x72\x6d') -rf ~"), "rm -rf ~");
    }

    // --- Pass 5: IFS ---

    #[test]
    fn collects_single_char_ifs_separator() {
        let n = normalize_command("IFS=X; cmdXrmX-rfX~");
        assert_eq!(n.extra_separators, vec!['X']);
    }

    #[test]
    fn empty_ifs_is_noop() {
        let n = normalize_command("IFS= read -r line");
        assert!(n.extra_separators.is_empty());
    }

    #[test]
    fn ifs_inline_read_takes_only_value() {
        // `IFS=, read -ra a` → value is `,`; we record it but the caller only
        // applies it if a re-split surfaces a hit (benign here).
        let n = normalize_command("IFS=, read -ra a");
        assert_eq!(n.extra_separators, vec![',']);
    }

    #[test]
    fn ifs_multichar_value_ignored() {
        let n = normalize_command("IFS=abc; foo");
        assert!(n.extra_separators.is_empty());
    }

    // --- Bounds ---

    #[test]
    fn rewrite_count_cap_enforced() {
        // Many `$'a'` spans; only MAX_REWRITES splices happen, the rest stay.
        let input = "$'a'".repeat(MAX_REWRITES + 10);
        let out = norm(&input);
        // The tail spans past the cap are left verbatim.
        assert!(out.contains("$'a'"));
    }

    #[test]
    fn oversized_input_left_intact() {
        let big = format!("{} -rf ~", "a".repeat(MAX_NORMALIZE_BYTES + 1));
        assert_eq!(norm(&big), big);
    }

    #[test]
    fn no_construct_is_identity() {
        for cmd in ["ls -la", "git status && cargo build", "rm -rf ~", "echo hi"] {
            assert_eq!(norm(cmd), cmd, "normalize must be identity on `{cmd}`");
        }
    }
}
