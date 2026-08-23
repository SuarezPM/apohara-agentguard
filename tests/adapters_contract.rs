//! Adapters foundation contract tests (PLAN-V05-UNIVERSAL §1.2/§1.3/§1.4).
//!
//! Denominator: the 6 contractual surfaces in scope — Claude Code, Codex,
//! OpenCode, Kilo Code, Kitty-Code, MCP Gateway (ACP is reserved V5-E and
//! excluded per plan §1.4).
//!
//! Wave U1 status:
//! - WORKING rows: ClaudeCode + Codex round-trip a synthetic `rm -rf /`
//!   Invocation through the canonical subprocess envelope into the existing
//!   engine seam `hook::run` (same seam as `tests/hook_contract.rs` /
//!   `tests/codex_hook.rs`; payloads here are built from the IR, not copied).
//! - SKELETON rows: OpenCode/Kilo/Kitty/Gateway are `#[ignore]`d until their
//!   adapters land in Wave U2′; each pre-writes the deny-shape assertions and
//!   pins its §1.3 capabilities cell so premature un-ignoring fails loudly.
//!
//! The envelope harness below makes decision #2 (envelope-canonical) and #3
//! (wire carries RAW strings) executable.

use apohara_agentguard::adapters::{
    capabilities_for, degrade, CanonicalTool, Decision, HookEvent, HostId, Invocation, TargetOs,
    AGENTGUARD_HOOK_VERSION,
};
use apohara_agentguard::config::Config;
use apohara_agentguard::hook::run;
use serde_json::Value;

// ---- Harness: canonical subprocess envelope (decision #2) ------------------
//
// The CANONICAL wire shape for subprocess transports is Claude Code's
// snake_case PreToolUse payload — exactly what `src/hook/` parses. Typed IR
// never serializes directly (decision #3): `raw_tool_name` becomes
// `tool_name`; the typed `tool` field is dropped on the wire.
fn wire_invocation_claude_envelope(inv: &Invocation) -> Value {
    let event = match inv.event {
        HookEvent::PreToolUse => "PreToolUse",
        HookEvent::PostToolUse => "PostToolUse",
        HookEvent::UserPromptSubmit => "UserPromptSubmit",
    };
    let mut env = serde_json::json!({
        "hook_event_name": event,
        "tool_name": inv.raw_tool_name,
        "tool_input": inv.input,
    });
    if let Some(cwd) = &inv.cwd {
        env["cwd"] = Value::String(cwd.display().to_string());
    }
    if let Some(sid) = &inv.session_id {
        env["session_id"] = Value::String(sid.clone());
    }
    if let Some(cid) = &inv.call_id {
        env["tool_use_id"] = Value::String(cid.clone());
    }
    if let Some(mode) = &inv.permission_mode {
        env["permission_mode"] = Value::String(mode.clone());
    }
    env
}

/// Minimal PreToolUse Bash invocation for `cmd` from `host`.
fn bash_invocation(host: HostId, cmd: &str) -> Invocation {
    Invocation {
        host,
        event: HookEvent::PreToolUse,
        tool: CanonicalTool::Bash,
        raw_tool_name: "Bash".to_string(),
        input: serde_json::json!({ "command": cmd }),
        cwd: Some("/tmp/proj".into()),
        session_id: Some(format!("sess-u1-{host:?}").to_lowercase()),
        call_id: None,
        permission_mode: None,
        source_payload: serde_json::json!({}),
    }
}

/// Shared deny-shape assertions: exit 2 + nested hookSpecificOutput deny.
fn assert_nested_deny_exit_2(out: Option<String>, code: i32) {
    assert_eq!(code, 2, "rm -rf / must block at exit 2");
    let v: Value =
        serde_json::from_str(&out.expect("block must emit stdout JSON")).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        v["hookSpecificOutput"]["permissionDecisionReason"].is_string(),
        "deny must carry a reason"
    );
    assert!(
        v.get("permissionDecision").is_none(),
        "no bare top-level decision"
    );
    assert!(
        v.get("additionalContext").is_none(),
        "no bare top-level context"
    );
}

// ---- Version pin (decision #2) ----------------------------------------------

#[test]
fn hook_version_const_is_pinned_to_1() {
    assert_eq!(AGENTGUARD_HOOK_VERSION, 1);
}

// ---- Envelope harness invariants (decisions #2/#3) ---------------------------

#[test]
fn envelope_carries_raw_tool_name_not_typed_tool() {
    // Wire IR carries RAW strings (decision #3): an unrecognized host tool
    // name must reach the wire verbatim, whatever the typed classification.
    let inv = Invocation {
        raw_tool_name: "apply_patch".to_string(),
        tool: CanonicalTool::Unknown("apply_patch".to_string()),
        ..bash_invocation(HostId::Codex, "echo hi")
    };
    let env = wire_invocation_claude_envelope(&inv);
    assert_eq!(env["tool_name"], "apply_patch");
    assert_eq!(env["hook_event_name"], "PreToolUse");
    assert_eq!(env["tool_input"]["command"], "echo hi");
    // Canonical snake_case keys only — no typed-IR leakage.
    let keys: Vec<&str> = env
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    for k in keys {
        assert!(
            matches!(
                k,
                "hook_event_name"
                    | "tool_name"
                    | "tool_input"
                    | "cwd"
                    | "session_id"
                    | "tool_use_id"
                    | "permission_mode"
            ),
            "unexpected envelope key {k}"
        );
    }
}

// ---- WORKING contract rows (2 of the 6-surface denominator) ------------------

#[test]
fn claude_code_round_trip_rm_rf_root_blocks_exit_2_nested_deny() {
    let inv = bash_invocation(HostId::ClaudeCode, "rm -rf /");
    let wire = wire_invocation_claude_envelope(&inv);
    let (out, code) = run(&wire.to_string(), &Config::default());
    assert_nested_deny_exit_2(out, code);
}

#[test]
fn codex_round_trip_rm_rf_root_blocks_exit_2_nested_deny() {
    // Codex mirrors Claude's snake_case wire format plus host extras
    // (permission_mode / tool_use_id); extras ride along and are ignored by
    // the engine — same seam as tests/codex_hook.rs, IR-built payload.
    let mut inv = bash_invocation(HostId::Codex, "rm -rf /");
    inv.call_id = Some("call-u1-codex".to_string());
    inv.permission_mode = Some("default".to_string());
    let wire = wire_invocation_claude_envelope(&inv);
    assert_eq!(wire["tool_use_id"], "call-u1-codex");
    assert_eq!(wire["permission_mode"], "default");
    let (out, code) = run(&wire.to_string(), &Config::default());
    assert_nested_deny_exit_2(out, code);
}

// ---- SKELETON contract rows (4 of the 6-surface denominator; U2′) ------------
//
// Each row pins its §1.3 capabilities cell (executable today) and pre-writes
// the deny-shape assertion body against the future adapter seam. They stay
// `#[ignore]`d until the real transport replaces the generic envelope
// round-trip.

#[test]
#[ignore = "adapter lands in Wave U2′"]
fn opencode_shim_round_trip_rm_rf_root_blocks() {
    let caps = capabilities_for(HostId::OpenCode, TargetOs::Linux);
    assert!(
        caps.can_block,
        "OpenCode blocks via tool.execute.before throw (pre-permission, YOLO-immune)"
    );
    assert!(
        !caps.can_ask,
        "OpenCode cannot ask; degrade() must map Ask→Deny"
    );
    assert!(
        caps.can_rewrite,
        "in-place mutation supported (by-reference args)"
    );
    let inv = bash_invocation(HostId::OpenCode, "rm -rf /");
    // TODO(U2′): replace the generic envelope round-trip below with the TS
    // shim transport (`tool.execute.before`, spawn-per-call ≤50ms p99): block
    // is a THROWN op failure, not exit 2 — swap the exit-code assert for a
    // thrown-op assertion at the shim seam.
    // TODO(U2′): add the two OpenCode-specific contract tests pinned by plan
    // §1.4: (1) mutation propagation in-place-vs-replacement (in-place
    // propagates, replacement does NOT); (2) Rewrite-never-escalates-
    // permissions (a Rewrite must never feed user allow-rules).
    let wire = wire_invocation_claude_envelope(&inv);
    let (out, code) = run(&wire.to_string(), &Config::default());
    assert_nested_deny_exit_2(out, code);
}

#[test]
#[ignore = "adapter lands in Wave U2′"]
fn kilo_generator_veto_round_trip_rm_rf_root_blocks() {
    let caps = capabilities_for(HostId::KiloCode, TargetOs::Linux);
    assert!(
        caps.can_block,
        "Kilo blocks via hardRuleset veto (YOLO-immune)"
    );
    assert!(
        !caps.can_ask,
        "encoded FALSE conservative; degrade() maps Ask→Deny"
    );
    assert!(
        !caps.can_rewrite && !caps.can_add_context,
        "config-gen cannot rewrite/context"
    );
    let inv = bash_invocation(HostId::KiloCode, "rm -rf /");
    // TODO(U2′): drive through the config-generator + hardRuleset veto seam;
    // declarative config has no process exit semantics — the exit-2 assert
    // below is envelope-model placeholder and must become a veto assertion.
    let wire = wire_invocation_claude_envelope(&inv);
    let (out, code) = run(&wire.to_string(), &Config::default());
    assert_nested_deny_exit_2(out, code);
}

#[test]
#[ignore = "adapter lands in Wave U2′"]
fn kitty_embed_round_trip_rm_rf_root_blocks() {
    let caps = capabilities_for(HostId::KittyCode, TargetOs::Linux);
    assert!(
        caps.can_block && caps.can_ask && caps.can_rewrite && caps.can_add_context,
        "Kitty embed is full-capability on Linux"
    );
    assert!(caps.sandbox_available, "Landlock-unified sandbox on Linux");
    let inv = bash_invocation(HostId::KittyCode, "rm -rf /");
    // TODO(U2′): call the in-process library embed directly (path-dep,
    // decision #7) — embeds skip serialization entirely (decision #2 clause),
    // so this envelope round-trip disappears in favor of a direct engine call
    // asserting the internal ToolError/block verdict.
    let wire = wire_invocation_claude_envelope(&inv);
    let (out, code) = run(&wire.to_string(), &Config::default());
    assert_nested_deny_exit_2(out, code);
}

#[test]
#[ignore = "adapter lands in Wave U2′"]
fn mcp_gateway_proxy_round_trip_rm_rf_root_blocks() {
    let caps = capabilities_for(HostId::McpGateway, TargetOs::Linux);
    assert!(caps.can_block, "gateway refuses tools/call at the proxy");
    assert!(
        !caps.can_ask,
        "proxy cannot prompt; degrade() maps Ask→Deny"
    );
    assert!(
        caps.can_rewrite && caps.can_add_context,
        "args rewrite + output scan"
    );
    let inv = Invocation {
        tool: CanonicalTool::Mcp {
            server: "fs".to_string(),
            tool: "run_command".to_string(),
        },
        raw_tool_name: "run_command".to_string(),
        ..bash_invocation(HostId::McpGateway, "rm -rf /")
    };
    // TODO(U2′): drive through the agentguard-proxy NDJSON transport (V4-B)
    // with tool pinning (V4-C); block is a JSON-RPC error response on
    // tools/call, not exit 2 — swap the exit-code assert accordingly.
    let wire = wire_invocation_claude_envelope(&inv);
    let (out, code) = run(&wire.to_string(), &Config::default());
    assert_nested_deny_exit_2(out, code);
}

// ---- Capabilities matrix unit tests (plan §1.3, table-driven) ----------------

#[test]
fn capabilities_matrix_matches_plan_1_3_per_host_and_os() {
    struct Row {
        host: HostId,
        os: TargetOs,
        block: bool,
        ask: bool,
        rewrite: bool,
        ctx: bool,
        exit: i32,
        sandbox: bool,
    }

    impl std::fmt::Debug for Row {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{:?}/{:?} block={} ask={} rewrite={} ctx={} exit={} sandbox={}",
                self.host,
                self.os,
                self.block,
                self.ask,
                self.rewrite,
                self.ctx,
                self.exit,
                self.sandbox
            )
        }
    }
    // One row per host × OS. Sandbox column encodes: Linux-only kernel wrap
    // for Claude/Codex/OpenCode/Kitty; Kilo complement → false everywhere;
    // Gateway network-policy → true everywhere; ACP undefined → false.
    let rows = vec![
        Row {
            host: HostId::ClaudeCode,
            os: TargetOs::Linux,
            block: true,
            ask: true,
            rewrite: true,
            ctx: true,
            exit: 2,
            sandbox: true,
        },
        Row {
            host: HostId::ClaudeCode,
            os: TargetOs::MacOS,
            block: true,
            ask: true,
            rewrite: true,
            ctx: true,
            exit: 2,
            sandbox: false,
        },
        Row {
            host: HostId::ClaudeCode,
            os: TargetOs::Windows,
            block: true,
            ask: true,
            rewrite: true,
            ctx: true,
            exit: 2,
            sandbox: false,
        },
        Row {
            host: HostId::Codex,
            os: TargetOs::Linux,
            block: true,
            ask: false,
            rewrite: false,
            ctx: false,
            exit: 2,
            sandbox: true,
        },
        Row {
            host: HostId::Codex,
            os: TargetOs::MacOS,
            block: true,
            ask: false,
            rewrite: false,
            ctx: false,
            exit: 2,
            sandbox: false,
        },
        Row {
            host: HostId::Codex,
            os: TargetOs::Windows,
            block: true,
            ask: false,
            rewrite: false,
            ctx: false,
            exit: 2,
            sandbox: false,
        },
        Row {
            host: HostId::OpenCode,
            os: TargetOs::Linux,
            block: true,
            ask: false,
            rewrite: true,
            ctx: true,
            exit: 0,
            sandbox: true,
        },
        Row {
            host: HostId::OpenCode,
            os: TargetOs::MacOS,
            block: true,
            ask: false,
            rewrite: true,
            ctx: true,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::OpenCode,
            os: TargetOs::Windows,
            block: true,
            ask: false,
            rewrite: true,
            ctx: true,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::KiloCode,
            os: TargetOs::Linux,
            block: true,
            ask: false,
            rewrite: false,
            ctx: false,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::KiloCode,
            os: TargetOs::MacOS,
            block: true,
            ask: false,
            rewrite: false,
            ctx: false,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::KiloCode,
            os: TargetOs::Windows,
            block: true,
            ask: false,
            rewrite: false,
            ctx: false,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::KittyCode,
            os: TargetOs::Linux,
            block: true,
            ask: true,
            rewrite: true,
            ctx: true,
            exit: 0,
            sandbox: true,
        },
        Row {
            host: HostId::KittyCode,
            os: TargetOs::MacOS,
            block: true,
            ask: true,
            rewrite: true,
            ctx: true,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::KittyCode,
            os: TargetOs::Windows,
            block: true,
            ask: true,
            rewrite: true,
            ctx: true,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::McpGateway,
            os: TargetOs::Linux,
            block: true,
            ask: false,
            rewrite: true,
            ctx: true,
            exit: 2,
            sandbox: true,
        },
        Row {
            host: HostId::McpGateway,
            os: TargetOs::MacOS,
            block: true,
            ask: false,
            rewrite: true,
            ctx: true,
            exit: 2,
            sandbox: true,
        },
        Row {
            host: HostId::McpGateway,
            os: TargetOs::Windows,
            block: true,
            ask: false,
            rewrite: true,
            ctx: true,
            exit: 2,
            sandbox: true,
        },
        Row {
            host: HostId::Acp,
            os: TargetOs::Linux,
            block: true,
            ask: true,
            rewrite: false,
            ctx: false,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::Acp,
            os: TargetOs::MacOS,
            block: true,
            ask: true,
            rewrite: false,
            ctx: false,
            exit: 0,
            sandbox: false,
        },
        Row {
            host: HostId::Acp,
            os: TargetOs::Windows,
            block: true,
            ask: true,
            rewrite: false,
            ctx: false,
            exit: 0,
            sandbox: false,
        },
    ];
    assert_eq!(rows.len(), 7 * 3, "matrix coverage: every host on every OS");
    for r in &rows {
        let c = capabilities_for(r.host, r.os);
        assert_eq!(c.host, r.host, "{r:?}: host echoed");
        assert_eq!(c.os, r.os, "{r:?}: os echoed");
        assert_eq!(c.can_block, r.block, "{r:?}: can_block");
        assert_eq!(c.can_ask, r.ask, "{r:?}: can_ask");
        assert_eq!(c.can_rewrite, r.rewrite, "{r:?}: can_rewrite");
        assert_eq!(c.can_add_context, r.ctx, "{r:?}: can_add_context");
        assert_eq!(c.fail_closed_exit, r.exit, "{r:?}: fail_closed_exit");
        assert_eq!(c.sandbox_available, r.sandbox, "{r:?}: sandbox_available");
    }
}

// ---- degrade() unit tests (decision #5 — REAL enforcement logic) -------------

#[test]
fn degrade_ask_becomes_deny_on_every_cannot_ask_host() {
    for host in [
        HostId::Codex,
        HostId::OpenCode,
        HostId::KiloCode,
        HostId::McpGateway,
    ] {
        for os in [TargetOs::Linux, TargetOs::MacOS, TargetOs::Windows] {
            let caps = capabilities_for(host, os);
            assert!(!caps.can_ask, "{host:?}/{os:?}: precondition");
            let degraded = degrade(
                Decision::Ask {
                    reason: "needs human review".to_string(),
                },
                &caps,
            );
            match degraded {
                Decision::Deny { reason, rule_id } => {
                    assert_eq!(
                        reason, "needs human review",
                        "{host:?}/{os:?}: reason preserved"
                    );
                    assert!(rule_id.is_none(), "{host:?}/{os:?}: rule_id None");
                }
                other => panic!("{host:?}/{os:?}: expected Deny, got {other:?}"),
            }
        }
    }
}

#[test]
fn degrade_preserves_ask_on_can_ask_hosts() {
    for host in [HostId::ClaudeCode, HostId::KittyCode, HostId::Acp] {
        let caps = capabilities_for(host, TargetOs::Linux);
        assert!(caps.can_ask, "{host:?}: precondition");
        let ask = Decision::Ask {
            reason: "confirm?".to_string(),
        };
        assert_eq!(
            degrade(ask.clone(), &caps),
            ask,
            "{host:?}: Ask must survive"
        );
    }
}

#[test]
fn degrade_passthrough_non_ask_decisions_even_without_ask_capability() {
    // Every non-Ask decision passes through unchanged on a can_ask=false
    // host — degrade() touches ONLY Ask.
    let caps = capabilities_for(HostId::Codex, TargetOs::Linux);
    let decisions = vec![
        Decision::Allow,
        Decision::Warn {
            reason: "watch this".to_string(),
        },
        Decision::Deny {
            reason: "no".to_string(),
            rule_id: Some("G-01".to_string()),
        },
        Decision::Rewrite {
            new_input: serde_json::json!({ "command": "echo safe" }),
            reason: "sanitized".to_string(),
        },
    ];
    for d in decisions {
        assert_eq!(
            degrade(d.clone(), &caps),
            d,
            "passthrough violated for {d:?}"
        );
    }
}
