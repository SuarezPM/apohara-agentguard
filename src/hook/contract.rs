//! Claude Code hook contract: stdin input + stdout output serde structs.
//!
//! Validated against the current Claude Code hooks docs
//! (code.claude.com/docs/en/hooks, confirmed 2026-06): for **PreToolUse** and
//! **PostToolUse** the `additionalContext` and decision fields MUST be nested in
//! a `hookSpecificOutput` object carrying `hookEventName`; a *bare top-level*
//! `additionalContext` is IGNORED. PreToolUse uses
//! `permissionDecision` (allow/deny/ask) + `permissionDecisionReason`; PostToolUse
//! cannot block. UserPromptSubmit can block, but exit 2 ERASES the prompt, so
//! apohara-agentguard only ever WARNs there (additionalContext + exit 0).
//!
//! Output is ALWAYS serde-serialized — never string-concatenated JSON — and every
//! free-text field is length-capped at [`MAX_CONTEXT_BYTES`] so a runaway reason
//! can't produce an oversized/malformed payload.

use serde::{Deserialize, Serialize};

use crate::verdict::{Tier, Verdict};

/// Hard cap on the byte length of `additionalContext` / `permissionDecisionReason`.
///
/// Oversized payloads risk being rejected or truncated unpredictably by the
/// harness; we truncate ourselves (with an ellipsis marker) to stay well-formed.
pub const MAX_CONTEXT_BYTES: usize = 4096;

/// Marker appended when a reason is truncated to [`MAX_CONTEXT_BYTES`].
const ELLIPSIS: &str = "…";

// ---------------------------------------------------------------------------
// Input (stdin JSON)
// ---------------------------------------------------------------------------

/// Permissive view of the hook stdin JSON.
///
/// Only the fields apohara-agentguard dispatches on are modeled; everything else
/// (`cwd`, `permission_mode`, …) is ignored via `#[serde(default)]` + the
/// absence of `deny_unknown_fields`, so a schema addition upstream can never
/// break parsing.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HookInput {
    /// The event that fired: `"PreToolUse"`, `"PostToolUse"`, `"UserPromptSubmit"`, …
    #[serde(default)]
    pub hook_event_name: String,
    /// The Claude Code session identifier. Used to key the per-session canary
    /// token (US-Bemit / US-Bscan). Absent on some events / older schemas.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Tool name for tool-use events (e.g. `"Bash"`, `"Read"`). Absent for
    /// `UserPromptSubmit`.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// Raw tool input payload (e.g. `{ "command": "npm test" }` or
    /// `{ "file_path": "…" }`). Kept as an opaque value and read per-tool.
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// The submitted text for `UserPromptSubmit`.
    #[serde(default)]
    pub prompt: Option<String>,
    /// The tool's result for `PostToolUse` (Claude Code spells it `tool_response`;
    /// `tool_output` is accepted as an alias for forward/back compat).
    #[serde(default, alias = "tool_output")]
    pub tool_response: serde_json::Value,
}

impl HookInput {
    /// Extract the Bash command from `tool_input.command`, if present.
    pub fn bash_command(&self) -> Option<&str> {
        self.tool_input.get("command").and_then(|v| v.as_str())
    }

    /// Extract a file path from `tool_input`, trying the common key spellings
    /// used by Read/Write/Edit (`file_path`, then `path`).
    pub fn file_path(&self) -> Option<&str> {
        self.tool_input
            .get("file_path")
            .or_else(|| self.tool_input.get("path"))
            .and_then(|v| v.as_str())
    }

    /// Extract the URL from a `WebFetch` `tool_input.url`.
    pub fn web_url(&self) -> Option<&str> {
        self.tool_input.get("url").and_then(|v| v.as_str())
    }

    /// Extract the query string from a `WebSearch` `tool_input.query`.
    pub fn web_query(&self) -> Option<&str> {
        self.tool_input.get("query").and_then(|v| v.as_str())
    }

    /// Best-effort extraction of textual `PostToolUse` output for scanning.
    ///
    /// Claude Code's `tool_response` for Bash is typically an object with
    /// `stdout`/`stderr` fields, but older shapes are a bare string. Both are
    /// accepted; an object's `stdout` (then `stderr`, then the whole JSON) is used.
    pub fn tool_stdout(&self) -> Option<String> {
        match &self.tool_response {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => Some(s.clone()),
            v => {
                if let Some(s) = v.get("stdout").and_then(|x| x.as_str()) {
                    Some(s.to_string())
                } else if let Some(s) = v.get("stderr").and_then(|x| x.as_str()) {
                    Some(s.to_string())
                } else {
                    Some(v.to_string())
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output (stdout JSON)
// ---------------------------------------------------------------------------

/// The nested `hookSpecificOutput` object — the ONLY shape the harness honors
/// for tool-use decisions and added context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    /// Echoes the event name (required by the harness).
    pub hook_event_name: String,
    /// `"allow" | "deny" | "ask"` — PreToolUse decision control. Omitted for warns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    /// Reason shown to the user when `permission_decision` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    /// Extra context surfaced to the agent (WARN tier; never a bare top-level field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// The top-level stdout JSON object: just the nested `hookSpecificOutput`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    /// The nested decision/context block.
    pub hook_specific_output: HookSpecificOutput,
}

impl HookOutput {
    /// A WARN output: nested `additionalContext` only (exit 0). Reason is capped.
    pub fn warn(event: &str, reason: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: event.to_string(),
                permission_decision: None,
                permission_decision_reason: None,
                additional_context: Some(cap_reason(reason)),
            },
        }
    }

    /// A SessionStart context-injection output: `hookSpecificOutput` carrying
    /// `hookEventName="SessionStart"` + `additionalContext`. Per the Claude Code
    /// hooks docs, SessionStart `additionalContext` is injected into the session
    /// context — apohara-agentguard uses it to seed the canary sentinel as data.
    /// The context string is capped like every other free-text field.
    pub fn session_context(context: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "SessionStart".to_string(),
                permission_decision: None,
                permission_decision_reason: None,
                additional_context: Some(cap_reason(context)),
            },
        }
    }

    /// A PreToolUse DENY output: `permissionDecision="deny"` + capped reason.
    pub fn deny(event: &str, reason: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: event.to_string(),
                permission_decision: Some("deny".to_string()),
                permission_decision_reason: Some(cap_reason(reason)),
                additional_context: None,
            },
        }
    }

    /// Serialize to the stdout JSON string.
    pub fn to_json(&self) -> String {
        // Serialization of these plain structs cannot fail; fall back defensively.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Map a [`Verdict`] for a given `event` to `(optional stdout JSON, exit code)`.
///
/// - `Allow`  -> `(None, 0)` (no output).
/// - `Warn`   -> `(Some(nested additionalContext), 0)`.
/// - `Block` on a **blocking** event (`PreToolUse`) ->
///   `(Some(permissionDecision=deny + reason), 2)` — belt-and-suspenders: the
///   caller ALSO writes the reason to stderr (exit 2 is the effective signal;
///   the JSON is harmless and documents intent).
/// - `Block` on a **non-blocking** event (`PostToolUse`/`UserPromptSubmit`) ->
///   graceful downgrade to `(Some(nested additionalContext warn), 0)`, because
///   exit 2 there cannot block (PostToolUse) or would erase the prompt
///   (UserPromptSubmit).
pub fn emit(event: &str, verdict: &Verdict) -> (Option<String>, i32) {
    match verdict.tier {
        Tier::Allow => (None, 0),
        Tier::Warn => (Some(HookOutput::warn(event, &verdict.reason).to_json()), 0),
        Tier::Block => {
            if is_blocking_event(event) {
                (Some(HookOutput::deny(event, &verdict.reason).to_json()), 2)
            } else {
                // Graceful downgrade: surface as a warn rather than a no-op block.
                (Some(HookOutput::warn(event, &verdict.reason).to_json()), 0)
            }
        }
    }
}

/// Whether a Block on `event` can be enforced via the permission-deny path.
///
/// Only `PreToolUse` blocks a tool. `PostToolUse` runs after the tool (cannot
/// block) and `UserPromptSubmit` exit-2 erases the prompt, so neither is a
/// blocking surface for apohara-agentguard — both downgrade to WARN.
fn is_blocking_event(event: &str) -> bool {
    event == "PreToolUse"
}

/// Truncate `reason` to at most [`MAX_CONTEXT_BYTES`] bytes on a char boundary,
/// appending an ellipsis marker when truncation occurred.
fn cap_reason(reason: &str) -> String {
    if reason.len() <= MAX_CONTEXT_BYTES {
        return reason.to_string();
    }
    // Reserve room for the ellipsis and back off to a char boundary.
    let budget = MAX_CONTEXT_BYTES.saturating_sub(ELLIPSIS.len());
    let mut end = budget;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &reason[..end], ELLIPSIS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_extracts_bash_command() {
        let input: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
        )
        .expect("parse");
        assert_eq!(input.hook_event_name, "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.bash_command(), Some("ls -la"));
    }

    #[test]
    fn input_extracts_file_path_both_spellings() {
        let a: HookInput =
            serde_json::from_str(r#"{"tool_input":{"file_path":"/x/.env"}}"#).expect("parse");
        assert_eq!(a.file_path(), Some("/x/.env"));
        let b: HookInput =
            serde_json::from_str(r#"{"tool_input":{"path":"/x/.env"}}"#).expect("parse");
        assert_eq!(b.file_path(), Some("/x/.env"));
    }

    #[test]
    fn input_ignores_unknown_fields() {
        // Forward-compat: unknown/added fields must not break parsing.
        let input: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"PreToolUse","session_id":"x","cwd":"/y","brand_new_field":42}"#,
        )
        .expect("parse with unknown fields");
        assert_eq!(input.hook_event_name, "PreToolUse");
    }

    #[test]
    fn warn_output_is_nested_additional_context() {
        let json = HookOutput::warn("PreToolUse", "careful").to_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "careful");
        // No bare top-level additionalContext, no permissionDecision.
        assert!(v.get("additionalContext").is_none());
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
    }

    #[test]
    fn deny_output_has_permission_decision() {
        let json = HookOutput::deny("PreToolUse", "blocked rm -rf").to_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "blocked rm -rf"
        );
        assert!(v["hookSpecificOutput"].get("additionalContext").is_none());
    }

    #[test]
    fn emit_allow_is_no_output_exit_0() {
        let (out, code) = emit("PreToolUse", &Verdict::allow());
        assert!(out.is_none());
        assert_eq!(code, 0);
    }

    #[test]
    fn emit_warn_is_additional_context_exit_0() {
        let (out, code) = emit("PreToolUse", &Verdict::warn("hmm"));
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "hmm");
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
    }

    #[test]
    fn emit_block_pretooluse_is_deny_exit_2() {
        let (out, code) = emit("PreToolUse", &Verdict::block("nope"));
        assert_eq!(code, 2);
        let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn emit_block_posttooluse_downgrades_to_warn_exit_0() {
        // PostToolUse cannot block -> graceful downgrade to a warn (exit 0).
        let (out, code) = emit("PostToolUse", &Verdict::block("ran already"));
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "ran already");
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
    }

    #[test]
    fn emit_block_userpromptsubmit_downgrades_to_warn_exit_0() {
        // exit 2 there would ERASE the prompt -> warn-only.
        let (out, code) = emit("UserPromptSubmit", &Verdict::block("suspicious"));
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "suspicious");
    }

    #[test]
    fn reason_is_length_capped() {
        let huge = "x".repeat(MAX_CONTEXT_BYTES * 4);
        let out = HookOutput::warn("PreToolUse", &huge);
        let ctx = out
            .hook_specific_output
            .additional_context
            .expect("has context");
        assert!(ctx.len() <= MAX_CONTEXT_BYTES, "len was {}", ctx.len());
        assert!(ctx.ends_with(ELLIPSIS));
    }

    #[test]
    fn short_reason_is_not_capped() {
        let out = HookOutput::deny("PreToolUse", "short");
        assert_eq!(
            out.hook_specific_output
                .permission_decision_reason
                .as_deref(),
            Some("short")
        );
    }
}
