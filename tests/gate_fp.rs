//! False-positive guard: common benign commands must NOT block.
//!
//! These are the everyday commands an agent runs constantly. A gate that
//! blocks them is unusable, so they are pinned as Allow. The borderline
//! `rm file.txt` (non-recursive, explicit single file) is documented below.

use apohara_agentguard::config::Config;
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::verdict::Tier;

#[test]
fn benign_commands_allow() {
    let allow = [
        "ls -la",
        "git status && cargo build",
        "echo hello",
        "cat README.md",
    ];
    for cmd in allow {
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Allow,
            "expected Allow for benign `{cmd}`"
        );
    }
}

/// Borderline: `rm file.txt` is a non-recursive removal of one explicit file.
///
/// DECISION: this is **Allow**, not Block and not Warn. Rationale: deleting a
/// single named file is an ordinary, reversible-from-VCS editing operation that
/// agents perform routinely; only the recursive/force `rm -rf` form (which can
/// wipe trees and is the actual destructive pattern) is dangerous. The
/// `rm-rf` taxonomy rule deliberately requires the recursive+force flag combo,
/// so a bare `rm file.txt` does not match. Warning on every `rm` would train
/// users to ignore the gate (alert fatigue). The MUST-NOT-Block requirement
/// from the acceptance criteria is satisfied either way.
#[test]
fn non_recursive_rm_of_single_file_is_not_blocked() {
    let v = evaluate("rm file.txt", &Config::default());
    assert_ne!(v.tier, Tier::Block, "single-file rm must not block: {v:?}");
    // Our chosen behaviour is Allow.
    assert_eq!(v.tier, Tier::Allow, "single-file rm chosen to Allow: {v:?}");
}

/// A5 verb-aware taxonomy: a destructive substring inside a quoted ARGUMENT to a
/// NON-EXECUTING verb (a git commit message, an `echo`/`printf` literal, a `#`
/// comment) is DATA, not a command, and must Allow. This is the pre-existing
/// commit-message false positive the verb-aware fix closes.
#[test]
fn destructive_text_in_non_executing_quoted_arg_allows() {
    let allow = [
        r#"git commit -m "remove the rm -rf helper""#,
        r#"git commit -m "drop dd if= usage""#,
        r#"echo "rm -rf is dangerous""#,
        "printf 'mkfs note\\n'",
        "# rm -rf ~ would be destructive",
    ];
    for cmd in allow {
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Allow,
            "non-executing verb quoted arg must Allow: `{cmd}`"
        );
    }
}

/// FP guard for the live-substitution fix (closing the A5 verb-aware FN must NOT
/// over-block): a single-quoted `$()` is LITERAL, and a `$()` whose body is a
/// harmless literal-emitter (`echo …`) is captured as an inert string — both
/// Allow. This is the no-regress contract paired with the new Block group.
#[test]
fn inert_or_literal_substitution_in_quoted_arg_allows() {
    let allow = [
        // Harmless literal-emitter body: `echo rm -rf` just prints a string.
        r#"git commit -m "$(echo rm -rf helper)""#,
        r#"echo "$(echo rm -rf)""#,
        r#"echo "$(echo rm)""#,
        // Single quotes: bash does NOT expand `$()` inside them.
        r#"git commit -m 'literal $(rm -rf ~)'"#,
        r#"echo 'no $(rm -rf ~) here'"#,
    ];
    for cmd in allow {
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Allow,
            "inert/literal substitution must Allow: `{cmd}`"
        );
    }
}

/// A5 FN guard: an EXECUTING verb runs its quoted content, so a destructive
/// substring there MUST still Block — the verb-aware suppression must not weaken
/// these.
#[test]
fn destructive_text_in_executing_verb_still_blocks() {
    let block = [
        r#"sh -c "rm -rf ~""#,
        r#"bash -c "rm -rf ~""#,
        r#"eval "rm -rf ~""#,
        "find . -name x | xargs rm -rf",
        "echo rm -rf ~ | sh",
    ];
    for cmd in block {
        assert_eq!(
            evaluate(cmd, &Config::default()).tier,
            Tier::Block,
            "executing verb must still Block: `{cmd}`"
        );
    }
}
