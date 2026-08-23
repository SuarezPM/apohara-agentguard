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
//!
//! Wave U2′ status: the formal per-host adapters (`adapters::claude`,
//! `adapters::codex`, `adapters::kilo`) are under contract below — parse
//! round-trips over the canonical envelope, per-host format_decision tables
//! proving that the Capabilities matrix and `degrade()` are LOAD-BEARING
//! (Codex Ask degrades to Deny exit 2; updatedInput/additionalContext are
//! unreachable by construction), and `install_manifest` structural equality
//! with what `init` writes today. The former `#[ignore]`d SKELETON rows for
//! OpenCode/Kilo/Kitty/Gateway are superseded by live coverage elsewhere —
//! see the pointer comment in the body for where each surface's evidence
//! lives.
//!
//! The envelope harness below makes decision #2 (envelope-canonical) and #3
//! (wire carries RAW strings) executable.

mod common;

use std::path::Path;

use apohara_agentguard::adapters::{
    capabilities_for, claude, codex, degrade, AdapterError, CanonicalTool, Decision, HookEvent,
    HostId, Invocation, TargetOs, AGENTGUARD_HOOK_VERSION,
};
use apohara_agentguard::config::Config;
use apohara_agentguard::hook::run;
use apohara_agentguard::init::{self, Mode};
use common::TempDir;
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

// ---- Former SKELETON contract rows: superseded by live coverage -------------
//
// The 6-surface denominator (plan §1.4) stays auditable; each surface's live
// contract evidence now lives where its real transport is exercised:
// - OpenCode + Kilo Code transport → `tests/shim_contract.rs`
//   (`tool.execute.before` shim: block/allow/fail-closed through the built
//   binary) and `tests/init_cli.rs` (drop-in install/idempotence/undo).
// - MCP Gateway transport → `tests/proxy_e2e.rs` (NDJSON proxy, tools/call,
//   tool pinning).
// - Kitty embed → kitty-code repo suites (the engine embeds via library
//   path-dep there; no subprocess envelope round-trip applies — plan
//   decision #2 clause).

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

// ---- Wave U2′.3/U2′.4: formal per-host parse/format adapters -----------------
//
// The adapters make the Capabilities matrix and degrade() LOAD-BEARING:
// every decision emission routes through ONE shared choke point
// (adapters::format_decision_core → capabilities::degrade, Oracle U1 nit #5)
// and every capability-gated output shape is guarded by its flag.

/// Representative-invocation table for the adapter round-trip property.
fn round_trip_cases() -> Vec<(&'static str, Invocation)> {
    let full = |tool: CanonicalTool, raw: &str| Invocation {
        host: HostId::ClaudeCode,
        event: HookEvent::PreToolUse,
        tool,
        raw_tool_name: raw.to_string(),
        input: serde_json::json!({ "command": "cargo test" }),
        cwd: Some("/tmp/proj".into()),
        session_id: Some("sess-rt".to_string()),
        call_id: Some("call-rt".to_string()),
        permission_mode: Some("default".to_string()),
        source_payload: serde_json::json!({}),
    };
    vec![
        ("bash-full-fields", full(CanonicalTool::Bash, "Bash")),
        (
            "read-minimal-no-optionals",
            Invocation {
                cwd: None,
                session_id: None,
                call_id: None,
                permission_mode: None,
                ..full(CanonicalTool::Read, "Read")
            },
        ),
        (
            "mcp-tool",
            full(
                CanonicalTool::Mcp {
                    server: "github".to_string(),
                    tool: "create_issue".to_string(),
                },
                "mcp__github__create_issue",
            ),
        ),
        (
            "mcp-underscored-server",
            full(
                CanonicalTool::Mcp {
                    server: "fs_server".to_string(),
                    tool: "read_file".to_string(),
                },
                "mcp__fs_server__read_file",
            ),
        ),
        (
            "unknown-verbatim",
            full(
                CanonicalTool::Unknown("apply_patch".to_string()),
                "apply_patch",
            ),
        ),
        ("websearch", full(CanonicalTool::WebSearch, "WebSearch")),
    ]
}

#[test]
fn claude_parse_round_trip_recovers_every_ir_field() {
    for (label, inv) in round_trip_cases() {
        let wire = wire_invocation_claude_envelope(&inv);
        let parsed = claude::parse_invocation(&wire.to_string())
            .unwrap_or_else(|e| panic!("{label}: parse failed: {e}"));
        assert_eq!(parsed.host, inv.host, "{label}: host");
        assert_eq!(parsed.event, inv.event, "{label}: event");
        assert_eq!(parsed.tool, inv.tool, "{label}: classified tool");
        assert_eq!(
            parsed.raw_tool_name, inv.raw_tool_name,
            "{label}: raw tool name"
        );
        assert_eq!(parsed.input, inv.input, "{label}: input");
        assert_eq!(parsed.cwd, inv.cwd, "{label}: cwd");
        assert_eq!(parsed.session_id, inv.session_id, "{label}: session id");
        assert_eq!(parsed.call_id, inv.call_id, "{label}: call id");
        assert_eq!(
            parsed.permission_mode, inv.permission_mode,
            "{label}: permission mode"
        );
        assert_eq!(
            parsed.source_payload, wire,
            "{label}: source payload is the untouched envelope"
        );
    }
}

// ---- claude::parse_invocation unit contracts ---------------------------------

#[test]
fn claude_parse_accepts_camel_case_prototype_aliases() {
    let payload = r#"{"hookEventName":"PreToolUse","sessionId":"s1","toolName":"Bash",
        "toolInput":{"command":"ls"},"toolUseId":"c1","permissionMode":"default","cwd":"/w"}"#;
    let inv = claude::parse_invocation(payload).expect("parse camelCase aliases");
    assert_eq!(inv.event, HookEvent::PreToolUse);
    assert_eq!(inv.session_id.as_deref(), Some("s1"));
    assert_eq!(inv.call_id.as_deref(), Some("c1"));
    assert_eq!(inv.permission_mode.as_deref(), Some("default"));
    assert_eq!(inv.cwd.as_deref(), Some(Path::new("/w")));
    assert_eq!(inv.tool, CanonicalTool::Bash);
}

#[test]
fn claude_parse_ignores_unknown_extras_but_preserves_them_in_source_payload() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash",
        "tool_input":{"command":"ls"},"model":"opus","transcript_path":"/t.jsonl"}"#;
    let inv = claude::parse_invocation(payload).expect("extras ignored");
    assert_eq!(inv.tool, CanonicalTool::Bash);
    assert_eq!(inv.cwd, None);
    assert_eq!(inv.source_payload["model"], "opus");
    assert_eq!(inv.source_payload["transcript_path"], "/t.jsonl");
}

#[test]
fn claude_parse_maps_mcp_prefix_and_keeps_malformed_prefix_unknown() {
    let inv = claude::parse_invocation(
        r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__fs_server__read_file","tool_input":{}}"#,
    )
    .expect("parse mcp tool");
    assert_eq!(
        inv.tool,
        CanonicalTool::Mcp {
            server: "fs_server".to_string(),
            tool: "read_file".to_string()
        }
    );
    // Malformed mcp__ prefixes stay Unknown verbatim (fail-open naming,
    // fail-closed engine routing).
    let inv = claude::parse_invocation(
        r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__onlyserver","tool_input":{}}"#,
    )
    .expect("parse malformed mcp prefix");
    assert_eq!(
        inv.tool,
        CanonicalTool::Unknown("mcp__onlyserver".to_string())
    );
}

#[test]
fn claude_parse_fails_closed_on_malformed_json_and_bad_envelopes() {
    let err = claude::parse_invocation("{not json").unwrap_err();
    assert!(matches!(err, AdapterError::Parse { .. }), "got: {err:?}");
    let err = claude::parse_invocation(r#"{"hook_event_name":"SessionStart"}"#).unwrap_err();
    assert!(
        matches!(err, AdapterError::Invalid { .. }),
        "unknown event: {err:?}"
    );
    let err = claude::parse_invocation(r#"{"hook_event_name":"PreToolUse"}"#).unwrap_err();
    assert!(
        matches!(err, AdapterError::Invalid { .. }),
        "missing tool_name: {err:?}"
    );
}

// ---- codex::parse_invocation unit contracts -----------------------------------

#[test]
fn codex_parse_ignores_codex_extras_including_permission_mode() {
    let payload = r#"{"session_id":"s","turn_id":"t7","cwd":"/p","hook_event_name":"PreToolUse",
        "model":"gpt-test","permission_mode":"on-request","tool_name":"Bash",
        "tool_use_id":"call-9","tool_input":{"command":"make"}}"#;
    let inv = codex::parse_invocation(payload).expect("parse codex payload");
    assert_eq!(inv.host, HostId::Codex);
    assert_eq!(inv.call_id.as_deref(), Some("call-9"));
    assert_eq!(inv.cwd.as_deref(), Some(Path::new("/p")));
    assert_eq!(
        inv.permission_mode, None,
        "Codex approval-policy echo is NOT carried into the IR"
    );
    // Extras still ride along verbatim in the untouched source payload.
    assert_eq!(inv.source_payload["turn_id"], "t7");
    assert_eq!(inv.source_payload["model"], "gpt-test");
}

#[test]
fn codex_parse_apply_patch_stays_unknown_v1() {
    // Documented v1 limitation: apply_patch has no canonical variant yet.
    let inv = codex::parse_invocation(
        r#"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch"}}"#,
    )
    .expect("parse apply_patch");
    assert_eq!(inv.raw_tool_name, "apply_patch");
    assert_eq!(inv.tool, CanonicalTool::Unknown("apply_patch".to_string()));
}

// ---- claude::format_decision table (caps row: block/ask/rewrite/ctx all true) -

#[test]
fn claude_format_deny_is_exit2_nested_deny_with_stderr_mirror() {
    let inv = bash_invocation(HostId::ClaudeCode, "rm -rf /");
    let caps = capabilities_for(HostId::ClaudeCode, TargetOs::Linux);
    let out = claude::format_decision(
        &inv,
        Decision::Deny {
            reason: "destructive".to_string(),
            rule_id: Some("G-01".to_string()),
        },
        &caps,
    );
    assert_eq!(out.exit_code, 2);
    assert_eq!(out.config_patch, None, "config_patch stays None this wave");
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "destructive"
    );
    assert_eq!(out.stderr, out.stdout, "stderr mirrors the deny JSON");
}

#[test]
fn claude_format_ask_is_preserved_as_ask_json_exit0() {
    let inv = bash_invocation(HostId::ClaudeCode, "./deploy.sh");
    let caps = capabilities_for(HostId::ClaudeCode, TargetOs::Linux);
    let out = claude::format_decision(
        &inv,
        Decision::Ask {
            reason: "confirm deploy".to_string(),
        },
        &caps,
    );
    assert_eq!(out.exit_code, 0, "ask is a UI prompt, not an error");
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "confirm deploy"
    );
    assert!(out.stderr.is_empty());
}

#[test]
fn claude_format_rewrite_emits_updated_input_when_capable() {
    let inv = bash_invocation(HostId::ClaudeCode, "rm -rf /tmp/x");
    let caps = capabilities_for(HostId::ClaudeCode, TargetOs::Linux);
    let new_input = serde_json::json!({ "command": "rm -rfi /tmp/x" });
    let out = claude::format_decision(
        &inv,
        Decision::Rewrite {
            new_input: new_input.clone(),
            reason: "interactive confirm".to_string(),
        },
        &caps,
    );
    assert_eq!(out.exit_code, 0);
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(v["hookSpecificOutput"]["updatedInput"], new_input);
}

#[test]
fn claude_format_warn_carries_additional_context_only_when_capable() {
    let inv = bash_invocation(HostId::ClaudeCode, "curl example.com");
    let caps = capabilities_for(HostId::ClaudeCode, TargetOs::Linux);
    let out = claude::format_decision(
        &inv,
        Decision::Warn {
            reason: "network egress".to_string(),
        },
        &caps,
    );
    assert_eq!(out.exit_code, 0);
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(
        v["hookSpecificOutput"]["additionalContext"],
        "network egress"
    );
    assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
}

#[test]
fn claude_format_allow_is_silent_exit0() {
    let inv = bash_invocation(HostId::ClaudeCode, "ls -la");
    let caps = capabilities_for(HostId::ClaudeCode, TargetOs::Linux);
    let out = claude::format_decision(&inv, Decision::Allow, &caps);
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
    assert_eq!(out.config_patch, None);
}

// ---- codex::format_decision table (caps row: ask/rewrite/ctx all false) -------
//
// These four tests are the LOAD-BEARING proof: identical decisions behave
// differently per host ONLY because emission routes through degrade()/caps.

#[test]
fn codex_format_ask_degrades_to_deny_exit2_proving_degrade_is_load_bearing() {
    // The SAME Ask decision Claude surfaces as an interactive prompt becomes
    // a hard Deny on Codex — because format_decision routes through
    // degrade() (caps.can_ask=false) BEFORE any output shape is chosen.
    let inv = bash_invocation(HostId::Codex, "./deploy.sh");
    let caps = capabilities_for(HostId::Codex, TargetOs::Linux);
    assert!(!caps.can_ask, "precondition: Codex cannot ask");
    let out = codex::format_decision(
        &inv,
        Decision::Ask {
            reason: "confirm deploy".to_string(),
        },
        &caps,
    );
    assert_eq!(out.exit_code, 2, "degraded Ask must be a hard deny");
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"], "confirm deploy",
        "degrade preserves the reason"
    );
}

#[test]
fn codex_format_rewrite_never_emits_updated_input_even_if_constructed() {
    let inv = bash_invocation(HostId::Codex, "rm -rf /tmp/x");
    let caps = capabilities_for(HostId::Codex, TargetOs::Linux);
    assert!(!caps.can_rewrite, "precondition: Codex cannot rewrite");
    let out = codex::format_decision(
        &inv,
        Decision::Rewrite {
            new_input: serde_json::json!({ "command": "echo safe" }),
            reason: "sanitized".to_string(),
        },
        &caps,
    );
    assert!(
        !out.stdout.contains("updatedInput"),
        "updatedInput must never reach Codex: {}",
        out.stdout
    );
    // Fail-closed: a rewrite a non-rewriting host cannot apply becomes a
    // deny, never a silent pass-through of the ORIGINAL input.
    assert_eq!(out.exit_code, 2);
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn codex_format_warn_has_no_additional_context_channel() {
    let inv = bash_invocation(HostId::Codex, "curl example.com");
    let caps = capabilities_for(HostId::Codex, TargetOs::Linux);
    assert!(!caps.can_add_context, "precondition");
    let out = codex::format_decision(
        &inv,
        Decision::Warn {
            reason: "network egress".to_string(),
        },
        &caps,
    );
    assert_eq!(out.exit_code, 0);
    assert!(
        out.stdout.is_empty(),
        "no additionalContext channel on Codex: {}",
        out.stdout
    );
}

#[test]
fn codex_format_deny_is_exit2_nested_deny_and_allow_silent() {
    let inv = bash_invocation(HostId::Codex, "rm -rf /");
    let caps = capabilities_for(HostId::Codex, TargetOs::Linux);
    let out = codex::format_decision(
        &inv,
        Decision::Deny {
            reason: "destructive".to_string(),
            rule_id: None,
        },
        &caps,
    );
    assert_eq!(out.exit_code, 2);
    let v: Value = serde_json::from_str(&out.stdout).expect("valid JSON");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    let allow = codex::format_decision(&inv, Decision::Allow, &caps);
    assert_eq!(allow.exit_code, 0);
    assert!(allow.stdout.is_empty() && allow.stderr.is_empty());
}

// ---- install_manifest ↔ init structural equality ------------------------------

#[test]
fn codex_install_manifest_matches_init_written_document() {
    let exe = Path::new("/usr/local/bin/apohara-agentguard");
    let home = TempDir::new("adapters-manifest");
    let results = init::run(home.path(), exe, Mode::Install, true).expect("init run");
    let codex_result = results
        .iter()
        .find(|r| r.host == "codex-code")
        .expect("codex host result");
    let written = std::fs::read_to_string(&codex_result.path).expect("hooks.json written");
    let doc: Value = serde_json::from_str(&written).expect("valid JSON");
    assert_eq!(
        doc,
        codex::install_manifest(exe),
        "install_manifest must stay structurally identical to what init writes today"
    );
}
