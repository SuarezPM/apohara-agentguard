//! Core verdict types: the shared spine for gate, hook, and firewall.
//!
//! A [`Verdict`] is the single decision shape every component returns. Its
//! [`Tier`] is derived from a numeric severity via [`severity_to_tier`], with
//! the cutoffs supplied by [`Thresholds`]. Defaults mirror aegis `djl.py`:
//! `sev >= 8` BLOCK, `5..=7` REVIEW/Warn, else Allow.

use serde::{Deserialize, Serialize};

/// Decision tier for a single evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Permit the action.
    Allow,
    /// Permit but surface a caution to the user/agent.
    Warn,
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
        // Matches aegis djl.py: sev >= 8 BLOCK, 5..=7 REVIEW/Warn, else Allow.
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

        let v = Verdict::block("nope").with_feedback("try X instead");
        assert_eq!(v.feedback.as_deref(), Some("try X instead"));
    }
}
