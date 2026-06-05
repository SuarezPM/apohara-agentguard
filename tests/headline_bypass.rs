//! Headline differentiator: agentguard BLOCKS the three bypasses that the
//! legacy fixed-list engine (`inv_bash_scope.rs:64-110`) silently let through.
//!
//! Each test asserts agentguard returns `Block`, and the side-by-side test
//! proves the contrast: a faithful reimplementation of the legacy fixed-list
//! gate returns Safe (no block) for all three, while agentguard blocks.

use agentguard::config::Config;
use agentguard::gate::evaluate;
use agentguard::verdict::Tier;

#[test]
fn blocks_variable_alias_bypass() {
    // `x=rm; $x -rf ~` — the alias hides `rm` behind `$x` until resolved.
    let v = evaluate("x=rm; $x -rf ~", &Config::default());
    assert_eq!(v.tier, Tier::Block, "var-alias bypass must block: {v:?}");
}

#[test]
fn blocks_base64_smuggled_bypass() {
    // `cm0gLXJmIH4K` is base64 for "rm -rf ~\n" (verified: echo cm0gLXJmIH4K |
    // base64 -d -> rm -rf ~). The payload is invisible to a literal match.
    let v = evaluate("echo cm0gLXJmIH4K | base64 -d | sh", &Config::default());
    assert_eq!(v.tier, Tier::Block, "base64 bypass must block: {v:?}");
}

#[test]
fn blocks_find_delete_bypass() {
    // `find . -delete` deletes recursively but never contains the `rm` token
    // the fixed list keys on.
    let v = evaluate("find . -delete", &Config::default());
    assert_eq!(v.tier, Tier::Block, "find -delete must block: {v:?}");
}

/// Faithful reimplementation of the FLAWED legacy gate
/// (`inv_bash_scope.rs:64-110`): split on separators, then substring-match each
/// leg against a fixed 12-item list. No variable expansion, no base64 decode,
/// and the `| sh` entries are dead after splitting (the pipe is gone).
///
/// Returns `true` if the legacy gate would flag the command (Unsafe), `false`
/// for Safe. The headline commands must all be Safe (false) here — that is the
/// gap agentguard closes.
fn naive_fixed_list(cmd: &str) -> bool {
    // The exact fixed list from inv_bash_scope.rs:64-77.
    const DANGEROUS: &[&str] = &[
        "rm -rf",
        "rm -fr",
        "| bash",
        "| sh",
        "|bash",
        "|sh",
        "curl ",
        "wget ",
        "eval ",
        "dd if=",
        "chmod 777",
        "mkfs",
    ];

    // Naive separator split (the legacy gate's quote-aware splitter, simplified
    // to the separators that matter for these inputs: ; && || | & newline).
    let legs = naive_split(cmd);
    for leg in &legs {
        let lower = leg.to_ascii_lowercase();
        for pat in DANGEROUS {
            if lower.contains(pat) {
                return true; // Unsafe
            }
        }
    }
    false // Safe
}

/// Separator-aware split matching the legacy parser's leg boundaries: `;`,
/// `&&`, `||`, `|`, `&`, newline. Crucially, splitting on `|` destroys the
/// `| sh` / `|sh` substrings the fixed list relies on — the dead-check the
/// plan calls out.
fn naive_split(cmd: &str) -> Vec<String> {
    let mut legs = Vec::new();
    let mut current = String::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let two = bytes.get(i + 1).copied();
        if (c == b'&' && two == Some(b'&')) || (c == b'|' && two == Some(b'|')) {
            push(&mut current, &mut legs);
            i += 2;
            continue;
        }
        if c == b';' || c == b'|' || c == b'&' || c == b'\n' {
            push(&mut current, &mut legs);
            i += 1;
            continue;
        }
        current.push(c as char);
        i += 1;
    }
    push(&mut current, &mut legs);
    legs
}

fn push(current: &mut String, legs: &mut Vec<String>) {
    let t = current.trim();
    if !t.is_empty() {
        legs.push(t.to_string());
    }
    current.clear();
}

#[test]
fn side_by_side_legacy_misses_what_agentguard_blocks() {
    let cases = [
        "x=rm; $x -rf ~",
        "echo cm0gLXJmIH4K | base64 -d | sh",
        "find . -delete",
    ];

    for cmd in cases {
        // Legacy fixed-list gate: Safe (false) — it MISSES the bypass.
        assert!(
            !naive_fixed_list(cmd),
            "legacy fixed-list gate unexpectedly flagged `{cmd}`; \
             the side-by-side contrast requires it to MISS this"
        );
        // agentguard: Block — it CLOSES the gap.
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Block,
            "agentguard must block `{cmd}` the legacy gate missed"
        );
    }
}
