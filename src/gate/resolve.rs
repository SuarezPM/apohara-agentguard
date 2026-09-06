//! Variable-assignment resolution across compound legs.
//!
//! Closes the `x=rm; $x -rf ~` bypass the fixed-list engine missed: a leg that
//! is a pure assignment (`VAR=value`) records the binding, and `$VAR` / `${VAR}`
//! occurrences in SUBSEQUENT legs are substituted before matching. Last write
//! wins (reassignment), and multiple variables are tracked independently.
//!
//! This is deliberately a narrow, conservative subset of bash expansion: only
//! leading `VAR=value` assignment legs feed the map, and only `$VAR`/`${VAR}`
//! references are expanded. It exists to defeat the obvious aliasing bypass, not
//! to be a full shell. Assignment legs are kept in the output (so an assignment
//! whose value is itself dangerous can still be matched).

use std::borrow::Cow;
use std::collections::HashMap;

/// Resolve `$VAR` / `${VAR}` references using `VAR=value` assignments seen in
/// earlier legs. Returns the legs with references expanded.
pub(crate) fn resolve_assignments<'a>(legs: &'a [Cow<'a, str>]) -> Cow<'a, [Cow<'a, str>]> {
    if !legs.iter().any(|l| l.contains('=') || l.contains('$')) {
        return Cow::Borrowed(legs);
    }

    let mut vars: HashMap<&str, String> = HashMap::new();
    let mut out: Vec<Cow<'a, str>> = Vec::with_capacity(legs.len());

    for leg in legs {
        // Expand using bindings known BEFORE this leg, so a self-referential
        // assignment does not expand itself.
        let expanded = expand_vars(leg, &vars);

        // If the leg is a pure assignment, record/overwrite the binding. We
        // parse the binding from the ORIGINAL leg text (an assignment value is
        // usually a literal, not a reference).
        if let Some((name, value)) = parse_assignment(leg) {
            vars.insert(name, value.into_owned());
        }

        out.push(expanded);
    }

    Cow::Owned(out)
}

/// Parse a leading `VAR=value` assignment, handling optional declaration keywords
/// (`export`, `local`, `declare`, `readonly`), stripping surrounding quotes and quote
/// concatenations, and unwrapping command/process substitution bodies (`$(echo rm)` -> `echo rm`).
///
/// Returns `None` if `leg` is not a single assignment token or valid assignment expression.
fn parse_assignment(leg: &str) -> Option<(&str, Cow<'_, str>)> {
    let trimmed = leg.trim();
    let mut rest = trimmed;

    // Strip declaration keyword prefixes if present.
    for kw in &["export", "local", "declare", "readonly"] {
        if let Some(after) = rest.strip_prefix(kw) {
            if after.starts_with(char::is_whitespace) {
                rest = after.trim_start();
                break;
            }
        }
    }

    let eq = rest.find('=')?;
    let name = &rest[..eq];
    if name.is_empty() || !is_valid_var_name(name) {
        return None;
    }

    let val_raw = rest[eq + 1..].trim();
    let val_unwrapped = unwrap_substitution(val_raw);
    let val_clean = strip_quotes_and_concat(val_unwrapped);

    Some((name, val_clean))
}

/// Unwrap substitution envelopes (`$(cmd)`, `` `cmd` ``, `<(cmd)`, `>(cmd)`) to expose inner command text.
/// If the inner command is a simple output emitter like `echo text` or `printf text`, extract `text` as the evaluated value.
fn unwrap_substitution(val: &str) -> &str {
    let mut s = val.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s = s[1..s.len() - 1].trim();
    }

    if s.starts_with("$(") && s.ends_with(')') && s.len() >= 3 {
        s = s[2..s.len() - 1].trim();
    } else if s.starts_with('`') && s.ends_with('`') && s.len() >= 2 {
        s = s[1..s.len() - 1].trim();
    } else if (s.starts_with("<(") || s.starts_with(">(")) && s.ends_with(')') && s.len() >= 3 {
        s = s[2..s.len() - 1].trim();
    }

    if let Some(rest) = s.strip_prefix("echo ") {
        return rest.trim();
    }
    if let Some(rest) = s.strip_prefix("printf ") {
        return rest.trim();
    }

    s
}

/// Remove quotes and normalize quote-concatenated tokens (e.g. `"r""m"` -> `"rm"`, `'r''m'` -> `'rm'`).
fn strip_quotes_and_concat(s: &str) -> Cow<'_, str> {
    if !s.contains('"') && !s.contains('\'') {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        if c == '\\' && !in_single {
            if let Some(next) = chars.next() {
                out.push(next);
                continue;
            }
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        out.push(c);
    }

    Cow::Owned(out)
}

/// A valid shell variable name: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Substitute `$VAR` and `${VAR}` references in `text` using `vars`. Unknown
/// references are left intact. A `$$` is treated literally (no expansion).
fn expand_vars<'a>(text: &'a Cow<'a, str>, vars: &HashMap<&str, String>) -> Cow<'a, str> {
    if !text.contains('$') {
        return text.clone();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'{' {
                // ${VAR}
                if let Some(close) = find_byte(bytes, i + 2, b'}') {
                    let name = &text[i + 2..close];
                    if is_valid_var_name(name) {
                        if let Some(v) = vars.get(name) {
                            out.push_str(v);
                            i = close + 1;
                            changed = true;
                            continue;
                        }
                    }
                }
            } else {
                // $VAR
                let name_start = i + 1;
                let mut j = name_start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > name_start {
                    let name = &text[name_start..j];
                    if let Some(v) = vars.get(name) {
                        out.push_str(v);
                        i = j;
                        changed = true;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    if changed {
        Cow::Owned(out)
    } else {
        text.clone()
    }
}

fn find_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    (from..bytes.len()).find(|&k| bytes[k] == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legs<'a>(parts: &[&'a str]) -> Vec<Cow<'a, str>> {
        parts.iter().map(|&s| Cow::Borrowed(s)).collect()
    }

    #[test]
    fn resolves_simple_alias() {
        let input = legs(&["x=rm", "$x -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out, vec!["x=rm", "rm -rf ~"]);
    }

    #[test]
    fn resolves_braced_reference() {
        let input = legs(&["bin=rm", "${bin} -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[1], "rm -rf ~");
    }

    #[test]
    fn last_write_wins() {
        let input = legs(&["x=ls", "x=rm", "$x -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[2], "rm -rf ~");
    }

    #[test]
    fn multiple_vars() {
        let input = legs(&["a=rm", "b=-rf", "$a $b /tmp/x"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[2], "rm -rf /tmp/x");
    }

    #[test]
    fn unknown_var_left_intact() {
        let input = legs(&["echo $undefined"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[0], "echo $undefined");
    }

    #[test]
    fn quoted_assignment_value() {
        let input = legs(&["x=\"rm\"", "$x -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[1], "rm -rf ~");
    }

    #[test]
    fn command_with_equals_arg_is_not_assignment() {
        // `dd if=/dev/zero` has a space before nothing relevant, but the leg
        // `find . -name x=y` should not be treated as an assignment of `find`.
        let input = legs(&["find . -name x=y", "$find"]);
        let out = resolve_assignments(&input);
        // `find ...` is not a valid var name (has spaces) so no binding; the
        // later `$find` stays literal.
        assert_eq!(out[1], "$find");
    }

    #[test]
    fn assignment_leg_preserved() {
        let input = legs(&["x=rm"]);
        let out = resolve_assignments(&input);
        assert_eq!(out, vec!["x=rm"]);
    }

    #[test]
    fn resolves_export_and_declaration_keywords() {
        let input = legs(&["export x=rm", "$x -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[1], "rm -rf ~");

        let input2 = legs(&["local y=rm", "$y -rf ~"]);
        let out2 = resolve_assignments(&input2);
        assert_eq!(out2[1], "rm -rf ~");

        let input3 = legs(&["declare z=rm", "$z -rf ~"]);
        let out3 = resolve_assignments(&input3);
        assert_eq!(out3[1], "rm -rf ~");

        let input4 = legs(&["readonly w=rm", "$w -rf ~"]);
        let out4 = resolve_assignments(&input4);
        assert_eq!(out4[1], "rm -rf ~");
    }

    #[test]
    fn resolves_command_and_process_substitutions() {
        let input = legs(&["cmd=$(echo rm)", "$cmd -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[1], "rm -rf ~");

        let input2 = legs(&["cmd=`echo rm`", "$cmd -rf ~"]);
        let out2 = resolve_assignments(&input2);
        assert_eq!(out2[1], "rm -rf ~");

        let input3 = legs(&["cmd=<(echo rm)", "$cmd -rf ~"]);
        let out3 = resolve_assignments(&input3);
        assert_eq!(out3[1], "rm -rf ~");
    }

    #[test]
    fn resolves_quoted_and_concatenated_assignments() {
        let input = legs(&["cmd=\"r\"\"m\"", "$cmd -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[1], "rm -rf ~");

        let input2 = legs(&["cmd='r''m'", "$cmd -rf ~"]);
        let out2 = resolve_assignments(&input2);
        assert_eq!(out2[1], "rm -rf ~");
    }

    #[test]
    fn resolves_utf8_multibyte_assignments() {
        let input = legs(&["path=\"/tmp/Âñçöðê\"", "cat $path"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[1], "cat /tmp/Âñçöðê");
    }
}
