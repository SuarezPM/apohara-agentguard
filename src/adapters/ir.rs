//! Canonical provider-agnostic IR (PLAN-V05-UNIVERSAL §1.2).
//!
//! Plain data, no trait objects: the `PolicyEngine` trait arrives with the
//! Kitty in-process embed in Wave U2′. Wire IR carries RAW strings — typed
//! spans are an engine-internal concern (decision #3) and must never leak
//! into these types.

/// Version of the agentguard hook wire contract (plan §1.1 decision #2).
/// Bump on any breaking change to the canonical subprocess envelope.
pub const AGENTGUARD_HOOK_VERSION: u32 = 1;

/// The host harness an [`Invocation`] came from (or a [`Decision`]/[`HostOutput`]
/// is destined for). `Acp` is a reserved variant only — no story until the
/// ACP registry matures (V5-E, plan §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostId {
    /// Claude Code — native PreToolUse hooks; the CANONICAL subprocess
    /// envelope is this host's snake_case shape (decision #2).
    ClaudeCode,
    /// OpenAI Codex — hooks.json generation; wire format mirrors Claude's.
    Codex,
    /// OpenCode ≥1.18 — TS shim `tool.execute.before`, pre-permission,
    /// YOLO-immune block-via-throw.
    OpenCode,
    /// Kilo Code — config-generator + hardRuleset veto (YOLO-immune).
    KiloCode,
    /// Kitty-Code — library-embed path-dep (~ns), Landlock-unified sandbox.
    KittyCode,
    /// Universal MCP gateway proxy — the fallback for uncovered hosts.
    McpGateway,
    /// ACP (`session/request_permission`) — RESERVED, V5-E only.
    Acp,
}

/// The hook event the invocation was delivered on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookEvent {
    PreToolUse,
    PostToolUse,
    UserPromptSubmit,
}

/// Tool identity normalized across hosts. Deliberately coarse: routing-level
/// classification only. The RAW name travels separately in
/// [`Invocation::raw_tool_name`] because the wire contract is raw strings
/// (decision #3).
#[derive(Debug, Clone, PartialEq)]
pub enum CanonicalTool {
    Bash,
    Read,
    Edit,
    Write,
    WebFetch,
    /// Web search invocation (routed by the hook dispatch alongside the
    /// other builtin surfaces).
    WebSearch,
    /// An MCP tool call: `server` + `tool` as advertised over MCP.
    Mcp {
        server: String,
        tool: String,
    },
    /// Anything the normalizer does not recognize; kept verbatim.
    Unknown(String),
}

/// One normalized tool-call observation handed to the engine.
///
/// Wire IR carries RAW strings (decision #3): `raw_tool_name` and `input`
/// are exactly what the host sent; parsing into typed spans happens inside
/// the engine, not here.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub host: HostId,
    pub event: HookEvent,
    pub tool: CanonicalTool,
    /// Verbatim tool name from the host payload (e.g. `"Bash"`,
    /// `"apply_patch"`); never re-spelled by the adapter layer.
    pub raw_tool_name: String,
    /// Raw tool input as received (e.g. `{"command": "..."}`).
    pub input: serde_json::Value,
    pub cwd: Option<std::path::PathBuf>,
    pub session_id: Option<String>,
    /// Host call identifier (Claude/Codex `tool_use_id`, MCP request id).
    pub call_id: Option<String>,
    pub permission_mode: Option<String>,
    /// The untouched original payload, for audit and for adapters that must
    /// answer in the host's own dialect.
    pub source_payload: serde_json::Value,
}

/// Engine verdict, host-agnostic. Adapters translate this into each host's
/// native response shape; [`crate::adapters::capabilities::degrade`] applies
/// the fixed Ask→Deny degradation when the target host cannot ask (decision
/// #5).
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Warn {
        reason: String,
    },
    Ask {
        reason: String,
    },
    Deny {
        reason: String,
        rule_id: Option<String>,
    },
    Rewrite {
        new_input: serde_json::Value,
        reason: String,
    },
}

/// What an adapter emits back to its host after a verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct HostOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    /// Optional host-config mutation (e.g. Claude `hookSpecificOutput`
    /// patches); `None` when the transport has no config channel.
    pub config_patch: Option<serde_json::Value>,
}
