//! Claude Code host adapter (PLAN-V05-UNIVERSAL §1.2, Wave U2′.3).
//!
//! Claude Code's native PreToolUse hook IS the canonical subprocess envelope
//! (plan §1.1 decision #2): snake_case stdin JSON in, nested
//! `hookSpecificOutput` JSON + exit codes out. Parsing reuses the validated
//! [`crate::contract::HookInput`] shapes (camelCase prototype aliases
//! accepted; unknown extras such as `model` / `transcript_path` ignored by
//! construction). Formatting routes through the shared emission choke point
//! ([`format_decision_core`]) with the Claude row of the capabilities matrix
//! as the sole enforcement authority — this adapter adds no host quirks of
//! its own.

use super::{
    format_decision_core, parse_subprocess_invocation, AdapterError, Capabilities, Decision,
    HostId, HostOutput, Invocation,
};

/// Parse a Claude Code hook stdin payload into the canonical IR.
///
/// Accepts the snake_case PreToolUse/PostToolUse/UserPromptSubmit envelope
/// (plus the camelCase prototype aliases [`crate::contract::HookInput`]
/// already handles) and normalizes:
///
/// - `tool_name` → [`CanonicalTool`] (`Bash`/`Read`/`Edit`/`Write`/
///   `WebFetch`/`WebSearch` known; `mcp__<server>__<tool>` →
///   [`CanonicalTool::Mcp`]; anything else stays [`CanonicalTool::Unknown`]
///   with the raw name).
/// - `cwd`, `session_id`, `tool_use_id` → `call_id`, `permission_mode` are
///   carried when present.
/// - The untouched payload becomes [`Invocation::source_payload`].
///
/// Fails closed ([`AdapterError`]) on malformed JSON, an unknown
/// `hook_event_name`, or a missing `tool_name`.
pub fn parse_invocation(payload: &str) -> Result<Invocation, AdapterError> {
    parse_subprocess_invocation(HostId::ClaudeCode, payload)
}

/// Format an engine [`Decision`] for the Claude Code PreToolUse transport.
///
/// `decision` is routed through [`super::capabilities::degrade`] FIRST
/// (load-bearing), then translated:
///
/// - Deny ⇒ exit `caps.fail_closed_exit` (2) + nested deny JSON on stdout +
///   stderr mirror.
/// - Ask ⇒ exit 0 + `permissionDecision: "ask"` JSON (Claude can ask).
/// - Rewrite ⇒ exit 0 + `updatedInput` JSON — only when `caps.can_rewrite`;
///   otherwise fails closed as a Deny.
/// - Warn ⇒ exit 0 + nested `additionalContext` when `caps.can_add_context`.
/// - Allow ⇒ silent exit 0.
///
/// Behavior follows `caps`, not this module: hand this function a degraded
/// row and you get degraded emission. `config_patch` is `None` this wave.
pub fn format_decision(inv: &Invocation, decision: Decision, caps: &Capabilities) -> HostOutput {
    format_decision_core(inv, decision, caps)
}
