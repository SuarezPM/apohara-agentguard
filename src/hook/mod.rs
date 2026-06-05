//! Hook entry point: stdin JSON parse, event dispatch, emission, kill-switch.
//!
//! [`run`] is the single testable seam: it takes the raw stdin JSON plus a
//! [`Config`] and returns `(optional stdout JSON, exit code)`. The CLI
//! (`agentguard hook`) is a thin wrapper that reads stdin, calls [`run`], prints
//! the JSON, and exits with the code.
//!
//! Dispatch:
//! - `PreToolUse` + `Bash` -> [`crate::gate::evaluate`] on the command.
//! - `PreToolUse` + `Read`/`Write`/`Edit` -> [`pathguard::check_path`] on the path.
//! - Firewall surfaces (`Read`/`WebFetch`/`WebSearch` content, `UserPromptSubmit`,
//!   `PostToolUse` Bash stdout) are wired in US-008 — see the clearly-marked
//!   extension point below, which currently returns Allow so the build is green.

pub mod contract;
pub mod pathguard;

use crate::config::Config;
use crate::gate;
use crate::verdict::Verdict;
use contract::HookInput;

/// Run the hook against raw stdin JSON and a config.
///
/// Returns `(Some(stdout_json), exit_code)` or `(None, 0)` for an allow/no-op.
/// Never panics on malformed input: unparseable JSON fails OPEN (allow) so a
/// schema surprise can't brick the user's tools.
pub fn run(stdin_json: &str, config: &Config) -> (Option<String>, i32) {
    // KILL-SWITCH FIRST — before any parsing or evaluation.
    //
    // Read from the HOOK PROCESS environment via `std::env`, NOT from the
    // inspected/agent command's env. The agent's `tool_input` (e.g. a Bash
    // command that sets `AGENTGUARD_DISABLE=1`) runs in a *different* process,
    // so a malicious command cannot self-disarm the gate this way. The switch is
    // all-or-nothing and emergency-only (disables gate + path-guard + firewall).
    if kill_switch_active(config) {
        return (None, 0);
    }

    // Fail OPEN on malformed input: a parse error must not block the tool.
    let input: HookInput = match serde_json::from_str(stdin_json) {
        Ok(i) => i,
        Err(_) => return (None, 0),
    };

    let verdict = dispatch(&input);
    contract::emit(&input.hook_event_name, &verdict)
}

/// Whether the emergency kill-switch is engaged (env OR config).
///
/// Env truthiness accepts `"1"` and `"true"` (case-insensitive) from the hook
/// process env only.
fn kill_switch_active(config: &Config) -> bool {
    if config.disable {
        return true;
    }
    match std::env::var("AGENTGUARD_DISABLE") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true"
        }
        Err(_) => false,
    }
}

/// Route a parsed input to the right evaluator and return its [`Verdict`].
fn dispatch(input: &HookInput) -> Verdict {
    match input.hook_event_name.as_str() {
        "PreToolUse" => dispatch_pretooluse(input),

        // TODO(US-008): firewall surfaces — wire these to crate::firewall:
        //   - PostToolUse + Bash  -> scan tool stdout, WARN-only (cannot block).
        //   - UserPromptSubmit     -> scan `input.prompt`, WARN-only (exit 2 erases).
        // Until US-008 they return Allow so the build stays green and the
        // contract mapper is exercised end-to-end for the implemented surfaces.
        "PostToolUse" | "UserPromptSubmit" => Verdict::allow(),

        // Unknown event: fail open.
        _ => Verdict::allow(),
    }
}

/// PreToolUse dispatch by tool name: Bash -> gate, Read/Write/Edit -> pathguard.
fn dispatch_pretooluse(input: &HookInput) -> Verdict {
    let tool = input.tool_name.as_deref().unwrap_or("");
    match tool {
        "Bash" => match input.bash_command() {
            // Note: the gate also short-circuits on config.disable, but the
            // kill-switch already returned earlier, so this is the live path.
            Some(cmd) => gate::evaluate(cmd, &gate_config()),
            None => Verdict::allow(),
        },
        "Read" => path_verdict(input, tool, false),
        "Write" | "Edit" => path_verdict(input, tool, true),

        // TODO(US-008): PreToolUse firewall surfaces (Read content scan via
        //   out-of-band inspection, WebFetch/WebSearch re-fetch) land here and
        //   may DENY on high severity. For now non-path tools fail open.
        _ => Verdict::allow(),
    }
}

/// Path-guard a Read/Write/Edit input; allow when no path is present.
fn path_verdict(input: &HookInput, tool: &str, write: bool) -> Verdict {
    match input.file_path() {
        Some(p) => pathguard::check_path(tool, p, write),
        None => Verdict::allow(),
    }
}

/// The config handed to the gate.
///
/// `run` already loads the user config and applies the kill-switch; the gate
/// re-reads `config.disable` defensively but we are past that point, so default
/// thresholds suffice here. Kept as a seam in case `run` later threads the live
/// config through (US-008).
fn gate_config() -> Config {
    Config::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pretooluse_bash(cmd: &str) -> String {
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":{}}}}}"#,
            serde_json::to_string(cmd).unwrap()
        )
    }

    #[test]
    fn dangerous_bash_denies_exit_2() {
        let (out, code) = run(&pretooluse_bash("rm -rf ~"), &Config::default());
        assert_eq!(code, 2);
        let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn safe_bash_allows() {
        let (out, code) = run(&pretooluse_bash("ls -la"), &Config::default());
        assert!(out.is_none());
        assert_eq!(code, 0);
    }

    #[test]
    fn kill_switch_config_allows_dangerous() {
        let cfg = Config {
            disable: true,
            ..Config::default()
        };
        let (out, code) = run(&pretooluse_bash("rm -rf ~"), &cfg);
        assert!(out.is_none());
        assert_eq!(code, 0);
    }

    #[test]
    fn read_dotenv_denies() {
        let json = r#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":".env"}}"#;
        let (out, code) = run(json, &Config::default());
        assert_eq!(code, 2);
        let v: serde_json::Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn malformed_input_fails_open() {
        let (out, code) = run("not json at all", &Config::default());
        assert!(out.is_none());
        assert_eq!(code, 0);
    }

    #[test]
    fn unknown_event_allows() {
        let (out, code) = run(r#"{"hook_event_name":"SessionStart"}"#, &Config::default());
        assert!(out.is_none());
        assert_eq!(code, 0);
    }

    #[test]
    fn posttooluse_is_allow_until_us008() {
        let json = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}"#;
        let (out, code) = run(json, &Config::default());
        assert!(out.is_none());
        assert_eq!(code, 0);
    }
}
