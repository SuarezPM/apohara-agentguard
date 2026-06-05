//! M3 regression net: pin the gate's verdict for the KNOWN Bash-obfuscation
//! evasions documented in the README "Known evasions" section.
//!
//! These assertions pin REALITY, not a desired outcome. As of v0.1.x the
//! normalization pre-pass (`gate::normalize`) DELIBERATELY closes four forms —
//! ANSI-C `$'...'`, echo/printf command-substitution verbs, IFS reassignment,
//! and backslash line-continuation — so they now Block. The remaining forms are
//! still parser-bounded out of scope; we pin the present verdict so that if a
//! future change starts catching (or stops catching) one of them, this test
//! surfaces the shift instead of letting it pass silently.
//!
//! NOT `#[ignore]`d on purpose: a regression net only works if it runs.
//!
//! IMPORTANT: a `Block` on a "now caught" case is a DELIBERATE handler, while a
//! couple of forms (`${x:-rm}`, here-doc) Block as an INCIDENTAL side effect of
//! substring/leg matching, not by deliberate construct handling; we pin that
//! real behavior too and label it as incidental.

use agentguard::config::Config;
use agentguard::gate::evaluate;
use agentguard::verdict::Tier;

/// ANSI-C quoting: `$'\x72\x6d'` decodes to `rm`. The normalize pre-pass decodes
/// ANSI-C `$'...'` spans in place -> now DELIBERATELY Blocks (v0.1.x).
#[test]
fn ansi_c_quoting_blocks() {
    let v = evaluate(r"$'\x72\x6d' -rf ~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "NOW CAUGHT (v0.1.x): ANSI-C hex/octal quoting is decoded by normalize"
    );
}

/// Parameter expansion with `:-` default. The gate does not perform parameter
/// expansion, but the literal `rm` followed by `-rf ~` in the leg is matched by
/// the destructive taxonomy -> currently BLOCKS, incidentally (not by design).
#[test]
fn param_default_dash_currently_blocks_incidentally() {
    let v = evaluate(r"${x:-rm} -rf ~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "INCIDENTAL: `${{x:-rm}} -rf ~` blocks via leg substring match, not \
         deliberate parameter-default handling"
    );
}

/// Parameter expansion with `:=` default. Same incidental block as `:-`.
#[test]
fn param_default_eq_currently_blocks_incidentally() {
    let v = evaluate(r"${x:=rm} -rf ~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "INCIDENTAL: `${{x:=rm}} -rf ~` blocks via leg substring match, not \
         deliberate parameter-default handling"
    );
}

/// Command-substitution-produced verb: `$(echo rm) -rf ~`. The normalize
/// pre-pass splices a leg-head `echo`/`printf` literal substitution in place ->
/// now DELIBERATELY Blocks (v0.1.x). Both `$(...)` and backtick forms.
#[test]
fn cmdsubst_echo_verb_blocks() {
    let v = evaluate(r"$(echo rm) -rf ~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "NOW CAUGHT (v0.1.x): leg-head echo/printf cmd-subst verb is spliced"
    );
    let v = evaluate("`echo rm` -rf ~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "NOW CAUGHT (v0.1.x): backtick echo cmd-subst verb is spliced"
    );
}

/// FP guard for the cmdsubst splice: an echo/printf substitution in ARGUMENT
/// position (not the leg head) is DATA, not a verb, and must NOT be spliced.
#[test]
fn cmdsubst_echo_in_argument_position_allows() {
    let v = evaluate(
        r#"git commit -m "$(echo rm -rf helper)""#,
        &Config::default(),
    );
    assert_eq!(
        v.tier,
        Tier::Allow,
        "argument-position echo cmd-subst must NOT be spliced (no FP)"
    );
    let v = evaluate(r#"echo "$(echo rm)""#, &Config::default());
    assert_eq!(v.tier, Tier::Allow, "nested echo arg must NOT be spliced");
}

/// Here-document: the payload is fed via `<<EOF ... EOF`. The compound splitter
/// treats the `rm -rf ~` body line as its own leg -> currently BLOCKS,
/// incidentally (the gate has no real here-doc parsing).
#[test]
fn heredoc_currently_blocks_incidentally() {
    let v = evaluate("cat <<EOF\nrm -rf ~\nEOF", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "INCIDENTAL: the here-doc body line is matched as a bare leg, not via \
         real here-doc parsing"
    );
}

/// IFS reassignment: rebuilding a command by manipulating the field separator.
/// The normalize pre-pass records the `IFS=<char>` and re-scans subsequent legs
/// with that char word-joined to a space, gated on surfacing a Block hit ->
/// now DELIBERATELY Blocks (v0.1.x).
#[test]
fn ifs_reassignment_blocks() {
    let v = evaluate("IFS=X; cmdXrmX-rfX~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "NOW CAUGHT (v0.1.x): IFS reassignment re-split surfaces `rm -rf ~`"
    );
}

/// FP guard for the IFS handler: a benign `IFS`-driven loop / `read` must NOT be
/// mangled into a false positive (the re-split is gated on a destructive hit).
#[test]
fn ifs_benign_loop_allows() {
    for cmd in [
        "while IFS= read -r line; do echo \"$line\"; done",
        "IFS=, read -ra arr",
        "IFS=:",
    ] {
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Allow,
            "benign IFS usage must Allow: `{cmd}`"
        );
    }
}

/// Backslash line-continuation: a verb split across `\`-continued lines
/// (`r\<newline>m` -> `rm`). The normalize pre-pass joins the continuation ->
/// now DELIBERATELY Blocks (v0.1.x).
#[test]
fn backslash_line_continuation_blocks() {
    let v = evaluate("r\\\nm -rf ~", &Config::default());
    assert_eq!(
        v.tier,
        Tier::Block,
        "NOW CAUGHT (v0.1.x): backslash line-continuation is joined by normalize"
    );
}
