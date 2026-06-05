//! Headline differentiator: apohara-agentguard BLOCKS the three bypasses that the
//! legacy fixed-list engine (`inv_bash_scope.rs:64-110`) silently let through.
//!
//! Each test asserts apohara-agentguard returns `Block`, and the side-by-side test
//! proves the contrast: a faithful reimplementation of the legacy fixed-list
//! gate returns Safe (no block) for all three, while apohara-agentguard blocks.

use apohara_agentguard::config::Config;
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::verdict::Tier;

mod common;
use common::naive_fixed_list;

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
        // apohara-agentguard: Block — it CLOSES the gap.
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Block,
            "apohara-agentguard must block `{cmd}` the legacy gate missed"
        );
    }
}
