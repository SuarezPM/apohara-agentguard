//! On-disk schema for the policy file (TOML, `schema_version = 1`).
//!
//! Kept as a flat serde-only module so the parser surface is one file. The
//! runtime evaluator lives in [`super::engine`]; the pattern matcher lives
//! in [`super::matcher`]. This module is `pub` so the test suite can build
//! policies by hand.
//!
//! ## Schema (v1)
//!
//! ```toml
//! schema_version = 1
//!
//! [defaults]
//! # "allow" (default if [defaults] is omitted) or "deny".
//! # "deny" => any tool without an explicit [[tools]] entry is Blocked.
//! default_action = "allow"
//!
//! # Per-tool configuration. Each [[tools]] entry is matched on the
//! # HookInput's `tool_name` field; the FIRST matching entry wins for
//! # `allow`/`deny`; rules from all matching entries are evaluated and
//! # the most-severe verdict wins (composed via `max_verdict`).
//! [[tools]]
//! name = "Bash"
//! # Capability labels (informational; reserved for v0.4+ capability-aware
//! # decisions). An empty list means "no capability constraints".
//! allow = ["list_dir", "read_file", "edit_file"]
//! deny  = ["rm_rf", "drop_table", "shell_exec"]
//! # Pattern rules: the first match contributes a verdict at
//! # `severity_to_tier(rule.severity, &thresholds)`, with the given
//! # `reason` (rendered to the hook output).
//! rules = [
//!   { arg = "command", pattern = "*rm -rf*", severity = 8, reason = "destructive rm" },
//!   { arg = "command", pattern = "*mkfs*",   severity = 9, reason = "filesystem format" },
//!   { arg = "command", pattern = "sudo *",   severity = 7, reason = "sudo command" },
//! ]
//!
//! [[tools]]
//! name = "Read"
//! allow = ["read_file"]
//!
//! # Per-session + per-tool budget caps (token heuristic).
//! [budgets.session]
//! max_tokens           = 100000
//! max_tool_invocations = 200
//!
//! [budgets.per_tool.Bash]
//! max_tokens     = 50000
//! max_invocations = 100
//! ```

use serde::{Deserialize, Serialize};

/// Current on-disk schema version. A load with any other value is an error
/// (forces migration paths to be explicit; v0.3 rejects future-schema files
/// loudly rather than silently misinterpreting them).
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The fallback action when no rule matches AND the tool has no explicit
/// `[[tools]]` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Permit (today's no-policy behavior; the default).
    #[default]
    Allow,
    /// Refuse: the tool is not on the allow list, so Block.
    Deny,
}

/// The `[defaults]` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Defaults {
    /// Fallback action when no rule matches AND the tool has no explicit
    /// `[[tools]]` entry. Defaults to [`DefaultAction::Allow`] (preserves
    /// today's no-policy behavior).
    #[serde(default)]
    pub default_action: DefaultAction,
}

/// A single per-tool rule: pattern-match an `arg` of `tool_input` and
/// contribute a verdict at the given severity (mapped to a [`crate::verdict::Tier`]
/// via the config thresholds). The worst match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRule {
    /// Which key (or dotted nested path) of `tool_input` to read.
    pub arg: String,
    /// Glob pattern (see [`super::matcher`]). A non-`*` pattern is a literal
    /// substring; a `*`-containing pattern is split on `*` and the parts
    /// must appear in order.
    pub pattern: String,
    /// Numeric severity; mapped to a tier via the config's thresholds.
    pub severity: u8,
    /// Human-readable reason surfaced in the verdict.
    pub reason: String,
}

/// A `[[tools]]` entry. Matches on the HookInput's `tool_name`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolSpec {
    /// The tool name (matches `HookInput::tool_name`).
    pub name: String,
    /// Capability labels (informational; reserved for v0.4+).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Capability labels (informational; reserved for v0.4+).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Pattern rules. The most-severe matching rule wins; rules are
    /// evaluated AFTER the default-deny check (so a default-deny Block
    /// is never softened to a rule's Warn).
    #[serde(default)]
    pub rules: Vec<ToolRule>,
}

/// Per-tool budget caps. Counted in `tokens` (see `tokens_for` in
/// [`super::engine`]) and `invocations` (call count for the same tool in
/// the same session).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolBudget {
    /// Max tokens across all invocations of THIS tool in the same session.
    #[serde(default)]
    pub max_tokens: Option<u64>,
    /// Max number of invocations of THIS tool in the same session.
    #[serde(default)]
    pub max_invocations: Option<u64>,
}

/// The `[budgets.session]` table. Caps apply across the whole session
/// (any tool / event), in addition to any per-tool caps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionBudget {
    /// Max tokens across the whole session.
    #[serde(default)]
    pub max_tokens: Option<u64>,
    /// Max number of tool invocations across the whole session.
    #[serde(default)]
    pub max_tool_invocations: Option<u64>,
}

/// The `[budgets.*]` table. The session budget applies globally; the
/// `per_tool` map applies per-tool (keyed by tool name).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Budgets {
    /// Whole-session caps.
    #[serde(default)]
    pub session: SessionBudget,
    /// Per-tool caps. Keyed by tool name (e.g. `"Bash"`, `"Read"`).
    #[serde(default)]
    pub per_tool: std::collections::BTreeMap<String, ToolBudget>,
}

/// The top-level policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    /// Must equal [`CURRENT_SCHEMA_VERSION`]; otherwise the load is
    /// rejected.
    pub schema_version: u32,
    /// The `[defaults]` table.
    #[serde(default)]
    pub defaults: Defaults,
    /// The per-tool specs.
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    /// The budget table.
    #[serde(default)]
    pub budgets: Budgets,
}
