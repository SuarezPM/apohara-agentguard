//! OpenAI Codex host adapter (PLAN-V05-UNIVERSAL §1.2, Wave U2′.4).
//!
//! Codex's documented hook contract deliberately mirrors Claude Code's
//! snake_case subprocess envelope (verified research; see the cross-harness
//! notes on [`crate::contract::HookInput`]), so parsing shares the canonical
//! parser. Codex-specific extras (`turn_id`, `model`, `permission_mode`) are
//! ignored — `permission_mode` in particular is NOT carried into the IR:
//! Codex's approval-policy echo is semantically unrelated to Claude's mode
//! field, and carrying it would invite Claude-shaped logic on Codex data.
//!
//! Known limitation (v1): Codex file edits report `apply_patch`, which has
//! no canonical variant yet — it stays [`CanonicalTool::Unknown`] verbatim
//! (raw name preserved, engine routes it as unrecognized).
//!
//! Formatting routes through the shared choke point with the Codex row of
//! the capabilities matrix (`can_ask=false`, `can_rewrite=false`,
//! `can_add_context=false`): an Ask arrives as a Deny via
//! [`super::capabilities::degrade`], and the `updatedInput` /
//! `additionalContext` emission arms are unreachable BY CONSTRUCTION — this
//! adapter can never emit them regardless of the decision handed in.

use std::path::Path;

use super::{
    format_decision_core, parse_subprocess_invocation, AdapterError, Capabilities, Decision,
    HostId, HostOutput, Invocation,
};

/// Parse a Codex hook stdin payload into the canonical IR.
///
/// Same shape family as Claude's envelope (snake_case canonical + camelCase
/// prototype aliases). Codex extras (`turn_id`, `model`,
/// `permission_mode`) are ignored; `tool_use_id` maps to
/// [`Invocation::call_id`]. See [`super::claude::parse_invocation`] for the
/// full field mapping and fail-closed error behavior.
pub fn parse_invocation(payload: &str) -> Result<Invocation, AdapterError> {
    let mut inv = parse_subprocess_invocation(HostId::Codex, payload)?;
    // Codex extra, deliberately dropped (module docs): not Claude's mode
    // field, and no Codex adapter logic may key off it.
    inv.permission_mode = None;
    Ok(inv)
}

/// Format an engine [`Decision`] for the Codex hooks.json transport.
///
/// Codex honors the identical nested-deny subprocess contract as Claude
/// (exit 2 + `hookSpecificOutput.permissionDecision: "deny"`), so Deny and
/// Allow look familiar — but Codex has NO ask flow, NO input rewrite and NO
/// context channel (`caps.can_ask/can_rewrite/can_add_context` all false):
///
/// - Ask ⇒ DEGRADED to Deny by [`super::capabilities::degrade`] before any
///   shape is chosen: exit 2 + deny JSON.
/// - Rewrite ⇒ fails closed as Deny (the `updatedInput` arm is guarded by
///   `caps.can_rewrite` and structurally unreachable here).
/// - Warn ⇒ silent exit 0 (no `additionalContext` channel).
///
/// Behavior follows `caps`, not this module. `config_patch` is `None`.
pub fn format_decision(inv: &Invocation, decision: Decision, caps: &Capabilities) -> HostOutput {
    format_decision_core(inv, decision, caps)
}

/// The `description` stamped into a Codex `hooks.json` we create (Codex has
/// no equivalent top-level description on Claude settings.json).
///
/// SINGLE SOURCE OF TRUTH: the init module consumes this constant — the
/// dependency edge points init → adapters, never the reverse.
pub const CODEX_DESCRIPTION: &str = "Installed by apohara-agentguard init";

/// Codex PreToolUse matcher group. Codex stays minimal PreToolUse-only (no
/// PostToolUse/UserPromptSubmit semantics).
pub const CODEX_PRE_TOOL_USE_MATCHER: &str = "Bash|apply_patch|Edit|Write";

/// Canonical subprocess-envelope spawn arguments (`<exe> hook`). Shared by
/// every JSON-hook host wiring (Claude Code / Codex), matching
/// `packaging/hooks.json`.
pub const SPAWN_ARGS: &[&str] = &["hook"];

/// Per-hook timeout (seconds), matching `packaging/hooks.json`. Shared by
/// every JSON-hook host wiring.
pub const HOOK_TIMEOUT: i64 = 20;

/// The exact `~/.codex/hooks.json` document `agentguard init` writes for a
/// fresh install — assembled ENTIRELY from this module's constants above, so
/// the manifest and the init-written document cannot drift.
///
/// Structural equality with what init actually writes is pinned by
/// `tests/adapters_contract.rs::codex_install_manifest_matches_init_written_document`,
/// so drift between this document and init fails CI loudly.
pub fn install_manifest(exe: &Path) -> serde_json::Value {
    serde_json::json!({
        "description": CODEX_DESCRIPTION,
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": CODEX_PRE_TOOL_USE_MATCHER,
                    "hooks": [
                        {
                            "type": "command",
                            "command": exe.to_string_lossy(),
                            "args": SPAWN_ARGS,
                            "timeout": HOOK_TIMEOUT
                        }
                    ]
                }
            ]
        }
    })
}
