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

    let mut vars: HashMap<String, String> = HashMap::new();
    let mut out: Vec<Cow<'a, str>> = Vec::with_capacity(legs.len());

    for leg in legs {
        let (expanded_str, changed) = expand_vars(leg.as_ref(), &mut vars);

        if let Some((name, value)) =
            parse_assignment(&expanded_str).or_else(|| parse_assignment(leg.as_ref()))
        {
            vars.insert(name.to_string(), value.to_string());
        }

        if changed {
            out.push(Cow::Owned(expanded_str));
        } else {
            out.push(leg.clone());
        }
    }

    Cow::Owned(out)
}

/// Parse a leading `VAR=value` assignment. Returns `None` if `leg` is not a
/// single assignment token (i.e. there is a space before any `=`, meaning it is
/// a command with arguments rather than an assignment).
fn parse_assignment(leg: &str) -> Option<(&str, &str)> {
    let eq = leg.find('=')?;
    let name = &leg[..eq];
    if name.is_empty() || !is_valid_var_name(name) {
        return None;
    }
    // A real assignment leg has no whitespace before `=` (we already checked the
    // name is a valid identifier, which forbids spaces). Strip surrounding
    // quotes from the value so `x="rm"` binds `rm`.
    let value = strip_quotes_borrowed(&leg[eq + 1..]);
    Some((name, value))
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

/// Remove one layer of matching single or double quotes around `s`.
fn strip_quotes_borrowed(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return &s[1..s.len() - 1];
    }
    s
}

enum ParamExpansion<'a> {
    Plain(&'a str),
    WithDefault {
        name: &'a str,
        op: &'a str,
        default: &'a str,
    },
}

fn parse_param_expansion(inner: &str) -> Option<ParamExpansion<'_>> {
    let inner_trimmed = inner.trim();
    if is_valid_var_name(inner_trimmed) {
        return Some(ParamExpansion::Plain(inner_trimmed));
    }

    for op in [":-", ":=", "-", "="] {
        if let Some((name, default_raw)) = inner_trimmed.split_once(op) {
            let name = name.trim();
            if is_valid_var_name(name) {
                let default = strip_quotes_borrowed(default_raw.trim());
                return Some(ParamExpansion::WithDefault { name, op, default });
            }
        }
    }

    None
}

fn evaluate_param_expansion(
    pe: ParamExpansion<'_>,
    vars: &mut HashMap<String, String>,
) -> Option<String> {
    match pe {
        ParamExpansion::Plain(name) => vars.get(name).cloned(),
        ParamExpansion::WithDefault { name, op, default } => {
            let val = vars.get(name).map(|s| s.as_str());
            match op {
                ":-" | ":=" => {
                    if let Some(v) = val {
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                    if op == ":=" {
                        vars.insert(name.to_string(), default.to_string());
                    }
                    Some(default.to_string())
                }
                "-" | "=" => {
                    if let Some(v) = val {
                        return Some(v.to_string());
                    }
                    if op == "=" {
                        vars.insert(name.to_string(), default.to_string());
                    }
                    Some(default.to_string())
                }
                _ => None,
            }
        }
    }
}

fn expand_vars_pass(text: &str, vars: &mut HashMap<String, String>) -> (String, bool) {
    if !text.contains('$') {
        return (text.to_string(), false);
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'{' {
                // ${VAR...}
                if let Some(close) = find_byte(bytes, i + 2, b'}') {
                    let inner = &text[i + 2..close];
                    if let Some(pe) = parse_param_expansion(inner) {
                        if let Some(replacement) = evaluate_param_expansion(pe, vars) {
                            out.push_str(&replacement);
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

        if let Some(ch) = text[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    (out, changed)
}

/// Substitute `$VAR` and `${VAR}` (including `${VAR:-default}` parameter expansions)
/// references in `text` using `vars`. Unknown references are left intact. A `$$` is
/// treated literally (no expansion). Bounded depth cap prevents infinite loops.
fn expand_vars(text: &str, vars: &mut HashMap<String, String>) -> (String, bool) {
    const MAX_EXPAND_DEPTH: usize = 8;
    let mut current = text.to_string();
    let mut any_changed = false;

    for _ in 0..MAX_EXPAND_DEPTH {
        let (next, changed) = expand_vars_pass(&current, vars);
        if !changed {
            break;
        }
        any_changed = true;
        current = next;
    }

    (current, any_changed)
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
    fn resolves_param_expansion_default_dash() {
        let input = legs(&["${x:-rm} -rf ~"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[0], "rm -rf ~");

        let input_set = legs(&["x=ls", "${x:-rm} -rf ~"]);
        let out_set = resolve_assignments(&input_set);
        assert_eq!(out_set[1], "ls -rf ~");
    }

    #[test]
    fn resolves_param_expansion_default_eq() {
        let input = legs(&["${x:=rm} -rf ~", "$x /tmp/x"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[0], "rm -rf ~");
        assert_eq!(out[1], "rm /tmp/x");
    }

    #[test]
    fn resolves_multi_variable_and_chained_expansions() {
        let input = legs(&["a=rm", "b=-rf", "c=~", "$a $b $c"]);
        let out = resolve_assignments(&input);
        assert_eq!(out[3], "rm -rf ~");

        let input_indirect = legs(&["x=y", "y=rm", "${$x} -rf ~"]);
        let out_indirect = resolve_assignments(&input_indirect);
        assert_eq!(out_indirect[2], "rm -rf ~");
    }
}
