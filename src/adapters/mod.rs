//! Provider-agnostic adapter foundation (PLAN-V05-UNIVERSAL §1.2/§1.3).
//!
//! Wave U1 laid the canonical IR ([`ir`]) and the per-host/per-OS capability
//! matrix plus the fixed Ask-degradation rule ([`capabilities`]). Wave U2′.3+
//! U2′.4 add the first two formal host adapters on top of that foundation:
//! [`claude`] (canonical subprocess envelope) and [`codex`] (hooks.json
//! transport). U2′.5 adds [`kilo`] (plugin registration + hardRuleset veto
//! guide). OpenCode, Kitty embed and the MCP gateway follow in later U2′
//! stories.
//!
//! Design decisions honored here (plan §1.1):
//! - #2: `AGENTGUARD_HOOK_VERSION` pins the wire envelope version; the Claude
//!   PreToolUse snake_case shape is canonical for subprocess transports.
//! - #3: the wire IR carries RAW strings; typed spans live inside the engine,
//!   never in these types.
//! - #5: EVERY decision emission routes through [`capabilities::degrade`]
//!   FIRST ([`format_decision_core`], Oracle U1 nit #5) — the single choke
//!   point that keeps a non-ask host from downgrading an Ask into an
//!   Allow-shaped outcome.

pub mod capabilities;
pub mod claude;
pub mod codex;
pub mod ir;
pub mod kilo;

pub use capabilities::{capabilities_for, degrade, Capabilities, TargetOs};
pub use ir::{
    CanonicalTool, Decision, HookEvent, HostId, HostOutput, Invocation, AGENTGUARD_HOOK_VERSION,
};

/// Error surfaced by host-adapter payload parsing.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// The payload is not valid JSON at all.
    #[error("invalid host payload JSON: {source}")]
    Parse {
        #[from]
        source: serde_json::Error,
    },
    /// The payload parses as JSON but violates the subprocess-envelope
    /// contract (unknown `hook_event_name`, missing `tool_name`, …).
    #[error("invalid host payload: {reason}")]
    Invalid { reason: String },
}

/// Wire-spelling of a [`HookEvent`] in the canonical subprocess envelope.
pub(crate) fn event_wire_name(event: HookEvent) -> &'static str {
    match event {
        HookEvent::PreToolUse => "PreToolUse",
        HookEvent::PostToolUse => "PostToolUse",
        HookEvent::UserPromptSubmit => "UserPromptSubmit",
    }
}

/// Route-level tool classification shared by the subprocess adapters.
///
/// Deliberately coarse (decision #3): builtin names map to their canonical
/// variants, `mcp__<server>__<tool>` maps to [`CanonicalTool::Mcp`] (the
/// server may itself contain single underscores; the split is on the FIRST
/// double underscore after the prefix), and anything else — including a
/// malformed `mcp__` prefix — stays [`CanonicalTool::Unknown`] with the RAW
/// name verbatim.
pub(crate) fn classify_tool(raw: &str) -> CanonicalTool {
    match raw {
        "Bash" => CanonicalTool::Bash,
        "Read" => CanonicalTool::Read,
        "Edit" => CanonicalTool::Edit,
        "Write" => CanonicalTool::Write,
        "WebFetch" => CanonicalTool::WebFetch,
        "WebSearch" => CanonicalTool::WebSearch,
        _ => {
            if let Some(rest) = raw.strip_prefix("mcp__") {
                if let Some((server, tool)) = rest.split_once("__") {
                    if !server.is_empty() && !tool.is_empty() {
                        return CanonicalTool::Mcp {
                            server: server.to_string(),
                            tool: tool.to_string(),
                        };
                    }
                }
            }
            CanonicalTool::Unknown(raw.to_string())
        }
    }
}

/// Shared parser behind [`claude::parse_invocation`] and
/// [`codex::parse_invocation`]: one canonical subprocess envelope
/// (snake_case, with the camelCase prototype aliases already accepted by
/// [`crate::contract::HookInput`]) into the IR.
///
/// Host extras (`model`, `transcript_path`, `turn_id`, …) are ignored by
/// construction — only the fields modeled below are read — while the
/// untouched original payload travels along as
/// [`Invocation::source_payload`] for audit and host-dialect replies.
pub(crate) fn parse_subprocess_invocation(
    host: HostId,
    payload: &str,
) -> Result<Invocation, AdapterError> {
    let raw: serde_json::Value = serde_json::from_str(payload)?;
    // Reuse the battle-tested hook-contract parsing for the fields it models
    // (snake_case canonical + camelCase aliases + extras ignored).
    let parsed: crate::contract::HookInput<'_> = serde_json::from_str(payload)?;

    let event = match parsed.hook_event_name.as_ref() {
        "PreToolUse" => HookEvent::PreToolUse,
        "PostToolUse" => HookEvent::PostToolUse,
        "UserPromptSubmit" => HookEvent::UserPromptSubmit,
        other => {
            return Err(AdapterError::Invalid {
                reason: format!("unsupported hook_event_name `{other}`"),
            })
        }
    };
    let raw_tool_name =
        parsed
            .tool_name
            .map(|s| s.into_owned())
            .ok_or_else(|| AdapterError::Invalid {
                reason: "`tool_name` missing: tool-use adapters require a tool call".to_string(),
            })?;

    Ok(Invocation {
        host,
        event,
        tool: classify_tool(&raw_tool_name),
        input: parsed.tool_input,
        raw_tool_name,
        cwd: raw
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(std::path::PathBuf::from),
        session_id: parsed.session_id.map(|s| s.into_owned()),
        call_id: opt_str(&raw, "tool_use_id", "toolUseId").map(str::to_string),
        permission_mode: opt_str(&raw, "permission_mode", "permissionMode").map(str::to_string),
        source_payload: raw,
    })
}

/// Read an optional string field trying the snake_case spelling first, then
/// the camelCase prototype alias.
fn opt_str<'a>(v: &'a serde_json::Value, snake: &str, camel: &str) -> Option<&'a str> {
    v.get(snake)
        .or_else(|| v.get(camel))
        .and_then(serde_json::Value::as_str)
}

/// Single decision-emission choke point (Oracle U1 nit #5) behind
/// [`claude::format_decision`] and [`codex::format_decision`].
///
/// The enforcement level is determined ENTIRELY by `caps` — the load-bearing
/// capabilities matrix — never by which adapter function the caller entered:
///
/// 1. `decision` is routed through [`degrade`] FIRST: on a `can_ask=false`
///    host an Ask is structurally turned into a Deny before any output shape
///    is chosen, so the Ask arm below is reachable only on can-ask hosts.
/// 2. `updatedInput` is emitted only inside an arm guarded by
///    `caps.can_rewrite`; `additionalContext` only under
///    `caps.can_add_context`. On hosts where those flags are false the arms
///    are unreachable BY CONSTRUCTION.
/// 3. A Rewrite arriving at a host that cannot rewrite fails CLOSED as a
///    Deny: silently executing the ORIGINAL input would defeat the engine
///    verdict that produced the rewrite.
/// 4. Deny exits with [`Capabilities::fail_closed_exit`] and emits the nested
///    deny JSON on stdout with a stderr mirror (belt-and-suspenders: the exit
///    code is the effective block signal).
///
/// Scope note: this wave serves PreToolUse decisions — the only blocking
/// surface these adapters gate. Callers must not route non-blocking events
/// (`PostToolUse`/`UserPromptSubmit`) through here: the event name is echoed
/// verbatim and no graceful downgrade is applied.
///
/// `config_patch` stays `None` this wave (no host-config mutation channel).
pub(crate) fn format_decision_core(
    inv: &Invocation,
    decision: Decision,
    caps: &Capabilities,
) -> HostOutput {
    // LOAD-BEARING (plan §1.1 decision #5): every emission degrades first.
    let degraded = degrade(decision, caps);
    let event = event_wire_name(inv.event);
    match degraded {
        Decision::Allow => HostOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            config_patch: None,
        },
        Decision::Warn { reason } => {
            // Without a context channel a Warn degrades to a silent allow
            // shape (exit 0): a warn never blocked anything.
            let stdout = if caps.can_add_context {
                crate::contract::HookOutput::warn(event, &reason).to_json()
            } else {
                String::new()
            };
            HostOutput {
                stdout,
                stderr: String::new(),
                exit_code: 0,
                config_patch: None,
            }
        }
        Decision::Ask { reason } => {
            // Reachable only when caps.can_ask (degrade() above mapped every
            // other Ask to Deny). Exit 0: the ask verdict is a UI prompt in
            // the harness, not an error.
            HostOutput {
                stdout: crate::contract::HookOutput::ask(event, &reason).to_json(),
                stderr: String::new(),
                exit_code: 0,
                config_patch: None,
            }
        }
        Decision::Deny { reason, .. } => {
            let json = crate::contract::HookOutput::deny(event, &reason).to_json();
            HostOutput {
                stdout: json.clone(),
                stderr: json,
                exit_code: caps.fail_closed_exit,
                config_patch: None,
            }
        }
        Decision::Rewrite { new_input, .. } if caps.can_rewrite => {
            let json = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "permissionDecision": "allow",
                    "updatedInput": new_input,
                }
            })
            .to_string();
            HostOutput {
                stdout: json,
                stderr: String::new(),
                exit_code: 0,
                config_patch: None,
            }
        }
        Decision::Rewrite { reason, .. } => {
            // Fail-closed fallback: this host cannot rewrite, and running the
            // ORIGINAL input would silently defeat the engine verdict.
            let json = crate::contract::HookOutput::deny(event, &reason).to_json();
            HostOutput {
                stdout: json.clone(),
                stderr: json,
                exit_code: caps.fail_closed_exit,
                config_patch: None,
            }
        }
    }
}
