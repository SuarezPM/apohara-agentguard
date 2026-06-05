//! A3 normalization pre-pass: mechanism tests (the in-place splice surfaces a
//! destructive leg) plus the FP negatives that keep the false-positive rate at 0.
//!
//! The mechanism tests assert the load-bearing P0 detail: each construct is
//! spliced CONTIGUOUSLY into the command so `split_compound` then surfaces the
//! single destructive leg `rm -rf ~`. The end-to-end Block/Allow checks pin the
//! full `gate::evaluate` verdict.

use apohara_agentguard::config::Config;
use apohara_agentguard::gate::compound::split_compound;
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::gate::normalize::normalize_command;
use apohara_agentguard::verdict::Tier;

fn block(cmd: &str) {
    assert_eq!(
        evaluate(cmd, &Config::default()).tier,
        Tier::Block,
        "expected Block for `{cmd}`"
    );
}

fn allow(cmd: &str) {
    assert_eq!(
        evaluate(cmd, &Config::default()).tier,
        Tier::Allow,
        "expected Allow for `{cmd}`"
    );
}

// --- Mechanism: the splice surfaces the destructive leg --------------------

#[test]
fn echo_subst_splice_surfaces_rm_leg() {
    let n = normalize_command("$(echo rm) -rf ~");
    assert_eq!(n.command, "rm -rf ~");
    let legs = split_compound(&n.command);
    assert!(
        legs.iter().any(|l| l == "rm -rf ~"),
        "splice must surface a single `rm -rf ~` leg: {legs:?}"
    );
}

#[test]
fn ansi_c_splice_yields_contiguous_rm() {
    assert_eq!(normalize_command(r"$'\x72\x6d' -rf ~").command, "rm -rf ~");
}

#[test]
fn ansi_c_inside_echo_subst_composes() {
    // Shared-buffer composition: ANSI-C decoded INSIDE the echo-subst body.
    assert_eq!(
        normalize_command(r"$(echo $'\x72\x6d') -rf ~").command,
        "rm -rf ~"
    );
}

// --- End-to-end: the four closed evasions Block ----------------------------

#[test]
fn ansi_c_quoting_blocks() {
    block(r"$'\x72\x6d' -rf ~");
}

#[test]
fn ansi_c_inside_cmdsubst_blocks() {
    block(r"$(echo $'\x72\x6d') -rf ~");
}

#[test]
fn line_continuation_blocks() {
    block("rm -r\\\nf ~");
    block("r\\\nm -rf ~");
}

#[test]
fn ifs_reassignment_blocks() {
    block("IFS=X; cmdXrmX-rfX~");
}

#[test]
fn echo_subst_verb_blocks() {
    block("$(echo rm) -rf ~");
    block("`echo rm` -rf ~");
}

// --- Negatives: must Allow (keep FP at 0) ----------------------------------

#[test]
fn ifs_negatives_allow() {
    allow("while IFS= read -r line");
    allow("IFS=, read -ra a");
    allow("IFS=: ; for p in $PATH; do echo $p; done");
    allow(r"IFS=$'\n'");
}

#[test]
fn cmdsubst_argument_position_allows() {
    allow(r#"git commit -m "$(echo rm -rf helper)""#);
    allow(r#"echo "$(echo rm)""#);
}

#[test]
fn lone_backslash_allows() {
    // `echo a\b` is a lone backslash, NOT a line-continuation.
    allow(r"echo a\b");
}

// --- Kill-switch: normalize = false reverts to pre-A3 behavior --------------

#[test]
fn kill_switch_disables_prepass() {
    let cfg = Config {
        normalize: false,
        ..Config::default()
    };
    // With the pre-pass off, the four constructs revert to their pre-A3 verdict
    // (Allow) — but the rest of the gate still works.
    assert_eq!(evaluate(r"$'\x72\x6d' -rf ~", &cfg).tier, Tier::Allow);
    assert_eq!(evaluate("$(echo rm) -rf ~", &cfg).tier, Tier::Allow);
    assert_eq!(evaluate("IFS=X; cmdXrmX-rfX~", &cfg).tier, Tier::Allow);
    // A raw `rm -rf ~` still Blocks (the gate is not disabled, only the pre-pass).
    assert_eq!(evaluate("rm -rf ~", &cfg).tier, Tier::Block);
}
