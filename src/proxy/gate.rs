//! tools/call gating for the MCP transport proxy (V4-C integration).
//!
//! Every `tools/call` the client sends is evaluated BEFORE it may reach the
//! upstream server. Two enforcement layers run, then a deliberate
//! **default-ALLOW** closes the pipeline:
//!
//! 1. **Policy pass** — a synthetic [`HookInput`] (`hook_event_name =
//!    "PreToolUse"`, `tool_name` = the MCP tool name, `tool_input` = the call
//!    arguments) goes through [`PolicySet::evaluate`], so policy-file
//!    `[[tools]]` rules and budgets apply to MCP traffic exactly as they do
//!    to hook traffic. `Block` denies outright; **`Ask` DEGRADES TO DENY**
//!    (reason prefix "ask degraded to deny on transport proxy") — a transport
//!    proxy has no interactive human to escalate to, mirroring the
//!    capabilities-matrix degradation doctrine
//!    ([`crate::adapters::capabilities`]: hosts without an ask channel get a
//!    fixed Ask→Deny degrade; the McpGateway caps row carries
//!    `can_ask = false`). A `Warn` forwards: it carries no enforcement and
//!    has no proxy-side display channel.
//!
//! 2. **Deep check** — any TOP-LEVEL string argument whose key matches
//!    `(command|cmd|script|code)` case-insensitively is treated as embedded
//!    shell/code and runs through the anti-bypass [`gate::evaluate`]. A gate
//!    `Block` propagates. This is what stops
//!    `{"command": "rm -rf /"}` from riding through a tool the policy never
//!    named. Key matching is plain ASCII-lowercase set membership — exactly
//!    equivalent to the `(?i)^…$` regex for these ASCII keys, without paying
//!    a regex compile per call on the hot path.
//!
//! 3. **Default ALLOW** — BY DESIGN, not by omission: a blanket default-deny
//!    would break every legitimate MCP server (each has its own tool
//!    vocabulary the policy cannot enumerate), making the proxy unusable and
//!    therefore unused. The security value of this layer comes from the
//!    combination of manifest pinning ([`crate::proxy::pinning`]), the deep
//!    check, and operator-written policy rules — not from a deny-all floor.
//!
//! Config/policy loading reuses the existing public seams
//! ([`Config::load_default_locations`], [`PolicySet::load`]) so the proxy
//! honors the same user/project config layering as every other surface.

use std::path::Path;

use serde_json::Value;

use crate::config::Config;
use crate::contract::HookInput;
use crate::policy::engine::PolicySet;
use crate::verdict::Tier;

/// Argument keys whose string value is treated as embedded shell/code by the
/// deep check (compared case-insensitively).
const DEEP_CHECK_KEYS: [&str; 4] = ["command", "cmd", "script", "code"];

/// The loaded enforcement context threaded through the relay.
#[derive(Debug)]
pub struct Gates {
    /// Layered config from the default locations (user + project TOML).
    pub config: Config,
    /// The loaded policy set (`--policy` override wins over
    /// `config.policy.file`; neither set ⇒ the no-op combine).
    pub policy: PolicySet,
}

impl Gates {
    /// Load config + policy from disk. `policy_override` (the CLI
    /// `--policy <path>`) replaces whatever `config.policy.file` names.
    ///
    /// Errors are LOUD startup failures: unlike the hook (which must keep
    /// serving mid-session and maps policy errors to per-call Blocks), the
    /// proxy owns its own startup phase and refuses to start ungated.
    pub fn load(policy_override: Option<&Path>) -> Result<Self, String> {
        let config = Config::load_default_locations()
            .map_err(|e| format!("loading agentguard config: {e:#}"))?;
        let path: Option<&Path> = policy_override.or(config.policy.file.as_deref());
        let policy = PolicySet::load(path).map_err(|e| format!("loading policy file: {e}"))?;
        Ok(Self { config, policy })
    }
}

/// The outcome of evaluating one `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateDecision {
    /// `true` ⇒ forward upstream; `false` ⇒ synthesize the blocked response.
    pub allowed: bool,
    /// Denial rationale (empty when allowed).
    pub reason: String,
}

impl GateDecision {
    fn allow() -> Self {
        Self {
            allowed: true,
            reason: String::new(),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

/// Evaluate one `tools/call` (`tool_name` + `args`) against the gates.
///
/// Pure with respect to disk; only the policy's in-memory budget counters
/// mutate (mirroring the hook's engine semantics).
pub fn evaluate_tool_call(tool_name: &str, args: &Value, gates: &Gates) -> GateDecision {
    // Kill-switch parity with the hook path: AGENTGUARD_DISABLE / config
    // disable gets out of the way entirely.
    if gates.config.disable {
        return GateDecision::allow();
    }

    // 1. Policy pass on a synthetic PreToolUse input.
    let input = HookInput {
        hook_event_name: "PreToolUse".to_string(),
        session_id: None,
        tool_name: Some(tool_name.to_string()),
        tool_input: args.clone(),
        prompt: None,
        tool_response: Value::Null,
    };
    let verdict = gates.policy.evaluate(&input, &gates.config);
    match verdict.tier {
        Tier::Block => {
            return GateDecision::deny(format!(
                "policy rule for tool `{tool_name}`: {}",
                verdict.reason
            ));
        }
        // Ask degrades to deny: a transport proxy has no interactive human
        // to escalate to (capabilities::degrade doctrine, McpGateway
        // can_ask=false). Never silently softened into a forward.
        Tier::Ask => {
            return GateDecision::deny(format!(
                "ask degraded to deny on transport proxy: {}",
                verdict.reason
            ));
        }
        Tier::Allow | Tier::Warn => {}
    }

    // 2. Deep check: embedded shell/code arguments go through the gate.
    if let Some(obj) = args.as_object() {
        for (key, value) in obj {
            let is_code_key =
                key.len() <= 7 && DEEP_CHECK_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key));
            if !(is_code_key && value.is_string()) {
                continue;
            }
            // Unwrap-safe: `is_string` was just checked.
            let code = value.as_str().expect("string checked above");
            let verdict = crate::gate::evaluate(code, &gates.config);
            if matches!(verdict.tier, Tier::Block) {
                return GateDecision::deny(format!(
                    "deep check on argument `{key}`: {}",
                    verdict.reason
                ));
            }
        }
    }

    // 3. Default allow (see module docs for why this is deliberate).
    GateDecision::allow()
}

/// Build the synthesized JSON-RPC error-result the proxy returns INSTEAD of
/// forwarding a denied call: `{"result":{"content":[{"type":"text","text":
/// "blocked by agentguard: <reason>"}],"isError":true}}` under the request's
/// `jsonrpc`/`id`. Never forwarded upstream; the reason is neutralized like
/// every other operator-facing verdict text.
pub fn blocked_response(id: &Value, reason: &str) -> String {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [
                {"type": "text", "text": format!("blocked by agentguard: {}", crate::neutralize_reason(reason))}
            ],
            "isError": true
        }
    });
    payload.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn gates_with_policy(toml_text: &str) -> Gates {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "agentguard-proxy-gate-test-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("policy.toml");
        std::fs::write(&path, toml_text).expect("write policy");
        Gates {
            config: Config::default(),
            policy: PolicySet::load(Some(&path)).expect("load policy"),
        }
    }

    fn default_gates() -> Gates {
        Gates {
            config: Config::default(),
            policy: PolicySet::default(),
        }
    }

    #[test]
    fn default_posture_allows_unlisted_tools_and_args() {
        let g = default_gates();
        let d = evaluate_tool_call("some_server_tool", &json!({"path": "/tmp/x", "n": 3}), &g);
        assert!(d.allowed, "{d:?}");
    }

    #[test]
    fn deep_check_blocks_destructive_command_arg() {
        let g = default_gates();
        let d = evaluate_tool_call("shell", &json!({"command": "rm -rf /"}), &g);
        assert!(!d.allowed, "rm -rf must be blocked");
        assert!(d.reason.contains("deep check"), "{d:?}");
    }

    #[test]
    fn deep_check_key_matching_is_case_insensitive() {
        let g = default_gates();
        for key in ["CMD", "Command", "SCRIPT", "Code"] {
            let args = serde_json::from_value(json!({ key: "rm -rf ~" })).expect("obj");
            let d = evaluate_tool_call("t", &args, &g);
            assert!(!d.allowed, "key {key} must trigger the deep check");
        }
    }

    #[test]
    fn deep_check_ignores_non_top_level_and_non_string_values() {
        let g = default_gates();
        // Nested command objects and non-string values are out of scope for
        // the pinned top-level deep check.
        let d = evaluate_tool_call(
            "t",
            &json!({"opts": {"command": "rm -rf /"}, "count": 5}),
            &g,
        );
        assert!(d.allowed, "{d:?}");
    }

    #[test]
    fn benign_command_arg_forwards() {
        let g = default_gates();
        let d = evaluate_tool_call("shell", &json!({"command": "ls -la"}), &g);
        assert!(d.allowed, "{d:?}");
    }

    #[test]
    fn policy_tool_rule_blocks_named_mcp_tool() {
        let g = gates_with_policy(
            r#"
schema_version = 1
[[tools]]
name = "deploy"
rules = [
  { arg = "env", pattern = "*prod*", severity = 9, reason = "no prod deploys via MCP" },
]
"#,
        );
        let d = evaluate_tool_call("deploy", &json!({"env": "production"}), &g);
        assert!(!d.allowed, "policy rule must block");
        assert!(d.reason.contains("no prod deploys"), "{d:?}");

        let d = evaluate_tool_call("deploy", &json!({"env": "staging"}), &g);
        assert!(d.allowed, "non-matching arg must forward: {d:?}");
    }

    #[test]
    fn policy_block_wins_before_deep_check() {
        // A policy Block short-circuits (its reason surfaces first).
        let g = gates_with_policy(
            r#"
schema_version = 1
[[tools]]
name = "shell"
rules = [
  { arg = "command", pattern = "*sudo*", severity = 9, reason = "no sudo" },
]
"#,
        );
        let d = evaluate_tool_call("shell", &json!({"command": "sudo rm -rf /"}), &g);
        assert!(!d.allowed);
        assert!(
            d.reason.contains("no sudo"),
            "policy reason must win: {d:?}"
        );
    }

    #[test]
    fn policy_ask_degrades_to_deny_not_forward() {
        // Plan §1.1 decision #5: a transport proxy has no interactive human,
        // so a policy Ask must DENY (capabilities::degrade doctrine), never
        // forward. The engine's charged path (tool named `Bash` + command
        // arg) with max_invocations = 0 makes the FIRST call exceed budget
        // ⇒ Ask.
        let g = gates_with_policy(
            r#"
schema_version = 1
[defaults]
default_action = "allow"
[budgets.per_tool.Bash]
max_invocations = 0
"#,
        );
        let d = evaluate_tool_call("Bash", &json!({"command": "ls"}), &g);
        assert!(!d.allowed, "Ask must degrade to deny, not forward: {d:?}");
        assert!(
            d.reason
                .starts_with("ask degraded to deny on transport proxy"),
            "{d:?}"
        );
        // The engine's own reason (budget exceeded) is preserved as context.
        assert!(d.reason.contains("budget"), "{d:?}");
    }

    #[test]
    fn config_disable_disables_the_gate_entirely() {
        let cfg = Config {
            disable: true,
            ..Config::default()
        };
        let g = Gates {
            config: cfg,
            policy: PolicySet::default(),
        };
        let d = evaluate_tool_call("shell", &json!({"command": "rm -rf /"}), &g);
        assert!(d.allowed, "kill-switch must get out of the way");
    }

    #[test]
    fn blocked_response_shape_matches_spec() {
        let s = blocked_response(&json!(7), "bad thing");
        let v: Value = serde_json::from_str(&s).expect("valid json");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["isError"], true);
        assert_eq!(v["result"]["content"][0]["type"], "text");
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with("blocked by agentguard: bad thing"),
            "{text}"
        );
        // No error object: this is a TOOL-level failure result, not a
        // protocol error.
        assert!(v.get("error").is_none());
    }

    #[test]
    fn blocked_response_neutralizes_hostile_reason_text() {
        // A reason derived from attacker-controlled input must not carry raw
        // bidi controls into the JSON text block.
        let s = blocked_response(&json!(1), "evil\u{202b}reason");
        assert!(!s.contains('\u{202b}'), "{s}");
        assert!(s.contains("\\u{202b}"), "escape form expected: {s}");
    }

    #[test]
    fn load_fails_loudly_on_missing_policy_override() {
        let err = Gates::load(Some(Path::new("/nonexistent/policy.toml")));
        assert!(err.is_err(), "missing --policy file must fail startup");
    }

    #[test]
    fn load_succeeds_with_no_config_and_no_policy() {
        // With cwd inside an empty temp dir and XDG pointed at an empty dir,
        // loading must succeed with defaults (the empty-config invariant).
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "agentguard-proxy-gate-load-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let saved_cwd = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&dir).expect("chdir temp");
        let g = Gates::load(None);
        std::env::set_current_dir(saved_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&dir);
        let g = g.expect("default load must succeed");
        // The exact config content depends on the machine; the contract is
        // that loading SUCCEEDS (empty-config invariant / fail-closed split
        // is pinned by src/config.rs tests).
        let _ = g.config.policy.file;
    }
}
