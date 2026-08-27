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

use std::collections::HashMap;

/// Resolve `$VAR` / `${VAR}` references using `VAR=value` assignments seen in
/// earlier legs. Returns the legs with references expanded.
pub(crate) fn resolve_assignments(legs: &[String]) -> Vec<String> {
    if !legs.iter().any(|l| l.contains('=') || l.contains('$')) {
        return legs.to_vec();
    }

    let mut vars: HashMap<String, String> = HashMap::new();
    let mut out: Vec<String> = Vec::with_capacity(legs.len());

    for leg in legs {
        // Expand using bindings known BEFORE this leg, so a self-referential
        // assignment does not expand itself.
        let expanded = expand_vars(leg, &vars);

        // If the leg is a pure assignment, record/overwrite the binding. We
        // parse the binding from the ORIGINAL leg text (an assignment value is
        // usually a literal, not a reference).
        if let Some((name, value)) = parse_assignment(leg) {
            vars.insert(name, value);
        }

        out.push(expanded);
    }

    out
}

/// Parse a leading `VAR=value` assignment. Returns `None` if `leg` is not a
/// single assignment token (i.e. there is a space before any `=`, meaning it is
/// a command with arguments rather than an assignment).
fn parse_assignment(leg: &str) -> Option<(String, String)> {
    let eq = leg.find('=')?;
    let name = &leg[..eq];
    if name.is_empty() || !is_valid_var_name(name) {
        return None;
    }
    // A real assignment leg has no whitespace before `=` (we already checked the
    // name is a valid identifier, which forbids spaces). Strip surrounding
    // quotes from the value so `x="rm"` binds `rm`.
    let value = strip_quotes(&leg[eq + 1..]);
    Some((name.to_string(), value))
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
fn strip_quotes(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// Substitute `$VAR` and `${VAR}` references in `text` using `vars`. Unknown
/// references are left intact. A `$$` is treated literally (no expansion).
fn expand_vars(text: &str, vars: &HashMap<String, String>) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
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
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn find_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    (from..bytes.len()).find(|&k| bytes[k] == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
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
}
