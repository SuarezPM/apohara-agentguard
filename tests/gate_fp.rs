//! False-positive guard: common benign commands must NOT block.
//!
//! These are the everyday commands an agent runs constantly. A gate that
//! blocks them is unusable, so they are pinned as Allow. The borderline
//! `rm file.txt` (non-recursive, explicit single file) is documented below.

use agentguard::config::Config;
use agentguard::gate::evaluate;
use agentguard::verdict::Tier;

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
