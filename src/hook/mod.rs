//! Hook entry point: stdin JSON in, decision out.
//!
//! The CLI (`apohara-agentguard hook`) reads stdin, calls [`run`], prints the
//! returned JSON, and exits with the returned code. This module is the thin
//! root of the hook subtree; the semantics live next to the code they govern:
//!
//! - [`dispatch`] — event routing: kill-switch checks, `PreToolUse` /
//!   `PostToolUse` / `UserPromptSubmit` / `SessionStart` routing, and policy
//!   composition (max-severity-wins).
//! - [`harness`] — the multi-harness contract (FASE 4): per-harness stdin
//!   parsers + emitters over the SAME dispatch core (`--harness windsurf /
//!   cursor / antigravity`; `claude`/`codex` stay on [`dispatch::run`] for
//!   byte-identical default behavior).
//! - [`canary_hook`] — SessionStart sentinel seeding + PostToolUse canary scan.
//! - [`pathguard_hook`] — Read/Write/Edit path-guard integration points.
//! - [`canary`] — the canary token primitive (generate/persist/read).
//! - [`pathguard`] — the pure secret-path deny-glob evaluator.
//!
//! Guards invoked per event (see `dispatch` for the full matrix):
//! - `PreToolUse` + `Bash` -> [`crate::gate::evaluate`] on the command.
//! - `PreToolUse` + `Read`/`Write`/`Edit` -> path-guard FIRST, then a firewall
//!   content scan of the file bytes for `Read`.
//! - `PreToolUse` + `WebFetch`/`WebSearch` -> firewall out-of-band re-fetch +
//!   content scan (BLOCK-capable).
//! - `UserPromptSubmit` / `PostToolUse` + `Bash` -> firewall scans, WARN-only.

pub mod harness;
pub mod pathguard;

mod canary;
mod canary_hook;
mod dispatch;
mod pathguard_hook;

// Facade re-export: the hook-contract types live canonically in the crate-level
// leaf module (`crate::contract`) so `policy` can depend on them without a
// dependency on `hook` (which depends on `policy`). Every historical path
// (`crate::hook::contract::…`) keeps resolving through this re-export.
pub use crate::contract;

// Public API surface of the hook subsystem.
pub use dispatch::{run, run_with_source};
pub use harness::{Emission, Harness};
// The tier-rank ordering is pinned by verdict.rs's precedence-matrix test via
// this crate-internal path.
#[cfg(test)]
pub(crate) use dispatch::tier_rank;

use crate::audit::{self, AuditRecord};
use crate::config::Config;
use crate::contract::HookInput;
use crate::verdict::{Tier, Verdict};

/// Component names recognized by the granular kill-switch (US-F1).
const COMPONENT_GATE: &str = "gate";
const COMPONENT_FIREWALL: &str = "firewall";
const COMPONENT_PATHGUARD: &str = "pathguard";
const COMPONENT_CANARY: &str = "canary";

/// Record a Block/Warn/Ask decision to the audit log (no-op when audit is
/// disabled, or the verdict is Allow). Best-effort and verdict-isolated.
/// `policy_fingerprint` is stamped onto the record only when a policy file
/// was actually loaded for this decision (`None` keeps the JSONL line
/// byte-identical to the no-policy schema).
fn audit_decision(
    input: &HookInput,
    verdict: &Verdict,
    config: &Config,
    policy_fingerprint: Option<&str>,
) {
    if !config.audit.enabled {
        return;
    }
    let decision = match audit_decision_str(verdict.tier) {
        Some(d) => d,
        None => return,
    };

    // Determine the audited event + surface + command text from the input.
    let (event, surface, command) = match (
        input.hook_event_name.as_str(),
        input.tool_name.as_deref().unwrap_or(""),
    ) {
        ("PreToolUse", "Bash") => ("gate", None, input.bash_command().map(str::to_string)),
        ("PreToolUse", "Read") => (
            "firewall",
            Some("read_file"),
            input.file_path().map(str::to_string),
        ),
        ("PreToolUse", "Write") | ("PreToolUse", "Edit") => (
            "firewall",
            Some("path_guard"),
            input.file_path().map(str::to_string),
        ),
        ("PreToolUse", "WebFetch") => (
            "firewall",
            Some("web_fetch"),
            input.web_url().map(str::to_string),
        ),
        ("PreToolUse", "WebSearch") => (
            "firewall",
            Some("web_search"),
            input.web_query().map(str::to_string),
        ),
        ("PostToolUse", "Bash") => ("firewall", Some("bash_stdout"), None),
        ("UserPromptSubmit", _) => ("firewall", Some("user_prompt"), None),
        _ => return,
    };

    let (rule_id, category) = parse_rule_label(&verdict.reason);
    let rec = AuditRecord {
        policy_fingerprint: policy_fingerprint.map(str::to_string),
        ..AuditRecord::new(
            event,
            decision,
            rule_id,
            category,
            surface.map(str::to_string),
            command,
        )
    };
    audit::record(&config.audit, &rec);
}

/// Extract a `(rule_id, category)` hint from a verdict reason. The gate emits
/// `"... (category [rule_id])"`; the firewall emits `"firewall rule {id} ..."`.
/// Returns `(None, None)` when neither shape is present.
fn parse_rule_label(reason: &str) -> (Option<String>, Option<String>) {
    // Gate shape: trailing `(category [rule_id])`.
    if let Some(open) = reason.rfind('[') {
        if let Some(close) = reason[open..].find(']') {
            let rule_id = reason[open + 1..open + close].to_string();
            // Category is the word(s) between the last '(' and the '['.
            let category = reason[..open]
                .rfind('(')
                .map(|p| reason[p + 1..open].trim().to_string())
                .filter(|c| !c.is_empty());
            return (Some(rule_id), category);
        }
    }
    // Firewall shape: `firewall rule {id} matched ...`.
    if let Some(rest) = reason.strip_prefix("firewall rule ") {
        let id = rest.split_whitespace().next().map(str::to_string);
        return (id, Some("firewall".to_string()));
    }
    (None, None)
}

/// Map a verdict tier to its audit-log decision string. Returns `None` for
/// `Allow` (which is not logged). A pure helper so the mapping can be tested
/// without setting up an audit file — the v0.3 F3' sub-step requires the
/// `Tier::Ask => "ask"` arm to be in place, and the
/// `audit_decision_records_ask` test asserts it.
fn audit_decision_str(tier: Tier) -> Option<&'static str> {
    match tier {
        Tier::Block => Some("block"),
        Tier::Warn => Some("warn"),
        Tier::Ask => Some("ask"),
        Tier::Allow => None,
    }
}

/// Test-only canned [`crate::firewall::refetch::ContentSource`]: every fetch
/// returns the same text. Shared by the dispatch and canary-hook test modules
/// to keep their tests hermetic (no real network / filesystem).
#[cfg(test)]
pub(crate) struct CannedSource(pub &'static str);

#[cfg(test)]
impl crate::firewall::refetch::ContentSource for CannedSource {
    fn fetch(
        &self,
        _t: &crate::firewall::refetch::FetchTarget,
    ) -> Result<String, crate::firewall::refetch::FetchError> {
        Ok(self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_decision_records_ask() {
        // The v0.3 F3' sub-step: audit_decision MUST record the Ask tier
        // with decision = "ask" (not silently fall through to a different
        // string or skip the log entry). Without this arm, the ralph loop's
        // first cargo build after the Tier::Ask addition goes RED at
        // audit_decision (Rust's non-exhaustive match). The pure helper
        // `audit_decision_str` is the testable seam.
        assert_eq!(audit_decision_str(Tier::Block), Some("block"));
        assert_eq!(audit_decision_str(Tier::Warn), Some("warn"));
        // The new arm:
        assert_eq!(audit_decision_str(Tier::Ask), Some("ask"));
        // Allow is not logged:
        assert_eq!(audit_decision_str(Tier::Allow), None);
    }
}
