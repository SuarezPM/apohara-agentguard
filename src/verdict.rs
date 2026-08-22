//! Core verdict types: the shared spine for gate, hook, and firewall.
//!
//! A [`Verdict`] is the single decision shape every component returns. Its
//! [`Tier`] is derived from a numeric severity via [`severity_to_tier`], with
//! the cutoffs supplied by [`Thresholds`]. Defaults:
//! `sev >= 8` BLOCK, `5..=7` REVIEW/Warn, else Allow.

use serde::{Deserialize, Serialize};

/// Decision tier for a single evaluation.
///
/// Precedence (most-severe wins, used by [`crate::hook::max_verdict`]):
/// `Block > Ask > Warn > Allow`. A default-deny request for human
/// confirmation (`Ask`) outranks `Warn` (so it is never silently
/// downgraded to a caution) and is outranked by `Block` (a hard refusal
/// still wins). `Allow` is the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Permit the action.
    Allow,
    /// Permit but surface a caution to the user/agent.
    Warn,
    /// Escalate to the human: a one-way ask surfaced as a UI prompt by
    /// the harness (`permissionDecision: "ask"`, exit 0). The human's
    /// response is the harness's concern, not agentguard's hook path —
    /// the verdict is "ask", nothing more.
    Ask,
    /// Refuse the action.
    Block,
}

/// A safety decision plus its rationale and optional agent-facing feedback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// The decision tier.
    pub tier: Tier,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Optional extra guidance surfaced back to the agent.
    pub feedback: Option<String>,
}

impl Verdict {
    /// An allow verdict with an empty reason and no feedback.
    pub fn allow() -> Self {
        Self {
            tier: Tier::Allow,
            reason: String::new(),
            feedback: None,
        }
    }

    /// A warn verdict carrying the given reason.
    pub fn warn(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Warn,
            reason: reason.into(),
            feedback: None,
        }
    }

    /// A block verdict carrying the given reason.
    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Block,
            reason: reason.into(),
            feedback: None,
        }
    }

    /// An ask verdict carrying the given reason. The hook output
    /// `permissionDecision: "ask"` (exit 0) is produced downstream by
    /// [`crate::contract::HookOutput::ask`] + [`crate::contract::emit`].
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Ask,
            reason: reason.into(),
            feedback: None,
        }
    }

    /// Attach (or replace) the optional agent-facing feedback. Builder style.
    pub fn with_feedback(mut self, feedback: impl Into<String>) -> Self {
        self.feedback = Some(feedback.into());
        self
    }
}

/// Severity cutoffs that map a numeric severity to a [`Tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Severities `>= block_at` map to [`Tier::Block`].
    pub block_at: u8,
    /// Severities `>= warn_at` (but below `block_at`) map to [`Tier::Warn`].
    pub warn_at: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        // Severity cutoffs: sev >= 8 BLOCK, 5..=7 Warn, else Allow.
        Self {
            block_at: 8,
            warn_at: 5,
        }
    }
}

/// Map a numeric severity to a [`Tier`] using the given [`Thresholds`].
pub fn severity_to_tier(sev: u8, t: &Thresholds) -> Tier {
    if sev >= t.block_at {
        Tier::Block
    } else if sev >= t.warn_at {
        Tier::Warn
    } else {
        Tier::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_to_tier_default_thresholds() {
        let t = Thresholds::default();
        assert_eq!(severity_to_tier(9, &t), Tier::Block);
        assert_eq!(severity_to_tier(8, &t), Tier::Block);
        assert_eq!(severity_to_tier(7, &t), Tier::Warn);
        assert_eq!(severity_to_tier(5, &t), Tier::Warn);
        assert_eq!(severity_to_tier(4, &t), Tier::Allow);
        assert_eq!(severity_to_tier(0, &t), Tier::Allow);
    }

    #[test]
    fn severity_to_tier_custom_thresholds() {
        let t = Thresholds {
            block_at: 10,
            warn_at: 3,
        };
        assert_eq!(severity_to_tier(9, &t), Tier::Warn);
        assert_eq!(severity_to_tier(3, &t), Tier::Warn);
        assert_eq!(severity_to_tier(2, &t), Tier::Allow);
    }

    #[test]
    fn verdict_constructors() {
        assert_eq!(Verdict::allow().tier, Tier::Allow);
        assert_eq!(Verdict::warn("careful").tier, Tier::Warn);
        assert_eq!(Verdict::block("nope").tier, Tier::Block);
        assert_eq!(Verdict::ask("human?").tier, Tier::Ask);

        let v = Verdict::block("nope").with_feedback("try X instead");
        assert_eq!(v.feedback.as_deref(), Some("try X instead"));
    }

    #[test]
    fn ask_tier_rank_above_warn_below_block() {
        // v0.3 precedence: Block > Ask > Warn > Allow. This test is the
        // canonical reference for the new rank order; a refactor of
        // `crate::hook::tier_rank` that disagrees with this matrix is a
        // bug, not a stylistic change. (F8 from the ralplan Critic
        // findings — the matrix is the single source of truth.)
        use crate::hook::tier_rank;
        assert!(tier_rank(Tier::Block) > tier_rank(Tier::Ask));
        assert!(tier_rank(Tier::Ask) > tier_rank(Tier::Warn));
        assert!(tier_rank(Tier::Warn) > tier_rank(Tier::Allow));
        // The 4 ranks are distinct (no two tiers share a rank).
        let ranks = [
            tier_rank(Tier::Allow),
            tier_rank(Tier::Warn),
            tier_rank(Tier::Ask),
            tier_rank(Tier::Block),
        ];
        for i in 0..ranks.len() {
            for j in (i + 1)..ranks.len() {
                assert_ne!(ranks[i], ranks[j], "ranks must be unique");
            }
        }
    }
}
