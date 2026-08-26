//! Per-host / per-OS capability matrix (PLAN-V05-UNIVERSAL §1.3) and the
//! fixed Ask-degradation rule (§1.1 decision #5).
//!
//! The matrix is the single source of truth for what each host transport can
//! actually enforce; adapters consult it instead of hard-coding host quirks.

use super::ir::{Decision, HostId};

/// Operating system the host harness runs on. Only [`TargetOs::Linux`] gets
/// kernel sandboxing today (Landlock/seccomp); mac/win fall back to
/// Guard-only enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    Linux,
    MacOS,
    Windows,
}

/// What one host on one OS can enforce. All capability flags default to
/// `false` — an unknown host degrades to the MCP gateway fallback, never to
/// silent pass-through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub host: HostId,
    pub os: TargetOs,
    /// Host can BLOCK before execution. `false` ⇒ degrade to the MCP
    /// gateway (plan §6 risk 1).
    pub can_block: bool,
    /// Host can surface an interactive ASK. `false` ⇒ [`degrade`] maps
    /// `Decision::Ask` to `Decision::Deny` (decision #5).
    pub can_ask: bool,
    /// Host honors a rewritten tool input.
    pub can_rewrite: bool,
    /// Host accepts additional context attached to the verdict.
    pub can_add_context: bool,
    /// Process exit code that means "blocked/fail-closed" for this
    /// transport. `0` where the mechanism is NOT an exit code (throw,
    /// declarative config, in-process error) — see per-host docs.
    pub fail_closed_exit: i32,
    /// Kernel/companion sandbox available for this host+OS combination.
    pub sandbox_available: bool,
}

/// Capabilities for `host` on `os`, encoding plan §1.3 EXACTLY.
pub fn capabilities_for(host: HostId, os: TargetOs) -> Capabilities {
    // All-false base row; every match arm overrides only what the host
    // genuinely supports, so new hosts fail closed by construction.
    let base = Capabilities {
        host,
        os,
        can_block: false,
        can_ask: false,
        can_rewrite: false,
        can_add_context: false,
        fail_closed_exit: 0,
        sandbox_available: false,
    };
    let linux_sandbox = os == TargetOs::Linux;
    match host {
        HostId::ClaudeCode => Capabilities {
            can_block: true,       // native PreToolUse, exit 2
            can_ask: true,         // permissionDecision "ask"
            can_rewrite: true,     // updatedInput
            can_add_context: true, // additionalContext
            fail_closed_exit: 2,
            sandbox_available: linux_sandbox, // ⚠️ mac-win: Guard-only
            ..base
        },
        HostId::Codex => Capabilities {
            can_block: true, // hooks.json generation, exit 2
            // Codex has no ask flow: Ask→Deny via degrade().
            can_ask: false,
            can_rewrite: false, // updatedInput is rejected upstream
            can_add_context: false,
            fail_closed_exit: 2,
            sandbox_available: linux_sandbox,
            ..base
        },
        HostId::OpenCode => Capabilities {
            can_block: true, // TS shim `tool.execute.before` throw, pre-permission (YOLO-immune)
            can_ask: false,  // no ask flow: Ask→Deny via degrade()
            // REWRITE is in-place mutation ONLY (by-reference args): a
            // replacement object is NOT propagated. Adapters must mutate the
            // args they were handed; pinned by a U2′ contract test.
            can_rewrite: true,
            // Context reaches the model via appended args only — weaker than
            // Claude's additionalContext but real.
            can_add_context: true,
            // throw=op failure, not a process exit code → encode 0.
            fail_closed_exit: 0,
            sandbox_available: linux_sandbox,
            ..base
        },
        HostId::KiloCode => Capabilities {
            can_block: true, // hardRuleset veto — YOLO-immune
            // Interactive ask flow exists but is not reliably hook-driven;
            // encoded FALSE conservatively so degrade() maps Ask→Deny.
            can_ask: false,
            can_rewrite: false, // config-generator cannot rewrite inputs
            can_add_context: false,
            // Declarative config generation: exit codes n/a → encode 0.
            fail_closed_exit: 0,
            // kilo-sandbox is a complement, not a wrap → conservative false.
            sandbox_available: false,
            ..base
        },
        HostId::KittyCode => Capabilities {
            can_block: true,       // in-process veto
            can_ask: true,         // native prompt
            can_rewrite: true,     // full control over input
            can_add_context: true, //
            // In-process embed surfaces failure as an internal ToolError, not
            // a process exit code → encode 0.
            fail_closed_exit: 0,
            // Landlock-unified sandbox on Linux; mac/win are Guard-only.
            sandbox_available: linux_sandbox,
            ..base
        },
        HostId::Windsurf => Capabilities {
            can_block: true, // pre_run_command / pre_mcp_tool_use, exit 2 + stderr reason
            // No ask flow is documented for the hook transport: Ask→Deny
            // via degrade() (consistent with the Codex treatment).
            can_ask: false,
            can_rewrite: false,
            can_add_context: false, // stderr carries deny reasons only
            fail_closed_exit: 2,    // exit 2 IS the block signal (stderr = reason)
            sandbox_available: linux_sandbox,
            ..base
        },
        HostId::Cursor => Capabilities {
            can_block: true, // beforeShellExecution / beforeMCPExecution deny JSON
            // Documented upstream quirk: an "ask" permission reply is IGNORED
            // by the host. Encoding can_ask=false routes every Ask through
            // degrade() into an explicit Deny with a "requires human
            // approval" message — never a silently-ignored ask.
            can_ask: false,
            can_rewrite: false,
            can_add_context: false,
            // The verdict lives in the stdout JSON body; exit 0 ALWAYS (a
            // non-zero exit would be read as a hook crash, not as a deny).
            fail_closed_exit: 0,
            sandbox_available: linux_sandbox,
            ..base
        },
        HostId::Antigravity => Capabilities {
            can_block: true, // PreToolUse plugin reply {"allow_tool": false}
            // No ask channel in the plugin hook contract: Ask→Deny via
            // degrade().
            can_ask: false,
            can_rewrite: false,
            can_add_context: false,
            // Deny is signaled IN the JSON body with exit 0; a non-zero exit
            // is treated by the host as a hook failure.
            fail_closed_exit: 0,
            sandbox_available: linux_sandbox,
            ..base
        },
        HostId::McpGateway => Capabilities {
            can_block: true,       // refuse `tools/call` at the proxy
            can_ask: false,        // proxy cannot prompt: Ask→Deny via degrade()
            can_rewrite: true,     // args rewritten before forwarding
            can_add_context: true, // output scanning injects context
            // Fail-closed is a JSON-RPC error response, not a process exit;
            // 2 keeps the deny-exit convention should the proxy ever be
            // subprocess-wrapped.
            fail_closed_exit: 2,
            // Network-policy enforcement wraps every forwarded call.
            sandbox_available: true,
            ..base
        },
        HostId::Acp => Capabilities {
            // V5-E RESERVED variant — matrix cells from plan §1.3 ACP row;
            // no adapter ships until the registry matures.
            can_block: true,        // session/request_permission
            can_ask: true,          // native protocol ask
            can_rewrite: false,     // ⚠️ in plan → conservatively false
            can_add_context: false, // ⚠️ in plan → conservatively false
            // Permission negotiation is protocol-level, not exit-code-level.
            fail_closed_exit: 0,
            sandbox_available: false, // "por definir" in plan
            ..base
        },
    }
}

/// Fixed degradation rule (plan §1.1 decision #5): when the target host
/// cannot ask, `Decision::Ask` becomes `Decision::Deny` preserving the
/// reason with `rule_id: None`. Every other decision passes through
/// unchanged.
///
/// This is REAL enforcement logic: it is the seam that keeps a non-ask host
/// from silently downgrading an Ask into an Allow-shaped outcome.
pub fn degrade(decision: Decision, caps: &Capabilities) -> Decision {
    match decision {
        Decision::Ask { reason } if !caps.can_ask => Decision::Deny {
            reason,
            rule_id: None,
        },
        other => other,
    }
}
