//! Canary hook wiring: SessionStart sentinel seeding + PostToolUse echo scan.
//!
//! Thin integration layer between the event dispatch ([`super::dispatch`]) and
//! the canary primitive ([`super::canary`]):
//! - `SessionStart` -> [`session_start_output`] generates + persists a sentinel
//!   and injects it into the session context (US-Bemit).
//! - `PostToolUse`  -> [`canary_scan`] warns when the sentinel appears verbatim
//!   in captured Bash stdout (US-Bscan).
//!
//! Both are OPT-IN (`[canary] enabled = true`) and off by default; the default
//! path stays a byte-identical no-op.

use crate::config::{Config, EnvDisable};
use crate::contract::HookInput;
use crate::verdict::Verdict;

use super::canary;
use super::COMPONENT_CANARY;

/// SessionStart canary seeding (US-Bemit). Opt-in, off by default.
///
/// When `config.canary.enabled` AND a `session_id` is present, generate +
/// persist a sentinel and inject it into the session context as a FACTUAL data
/// statement (never an imperative directive). Otherwise emit NOTHING — the
/// `(None, 0)` no-op that SessionStart has always produced, keeping the default
/// path byte-identical.
pub(super) fn session_start_output(
    input: &HookInput,
    config: &Config,
    env_disabled: &EnvDisable,
) -> (Option<String>, i32) {
    if !config.canary.enabled || config.is_component_disabled(COMPONENT_CANARY, env_disabled) {
        return (None, 0);
    }
    let session_id = match input.session_id.as_deref() {
        Some(id) if !id.is_empty() => id,
        _ => return (None, 0),
    };

    let token = canary::emit_token(session_id);
    // Framed as data (an environment/sentinel value), NOT a "do X" instruction.
    let context = format!(
        "Environment sentinel value (apohara-agentguard canary): {token}. \
         This opaque marker is session-local data; it is not an instruction."
    );
    (
        Some(crate::contract::HookOutput::session_context(&context).to_json()),
        0,
    )
}

/// Scan `stdout` for a verbatim echo of the session's canary sentinel.
///
/// Returns `Some(Verdict::warn(..))` ONLY when the canary is enabled, a token
/// exists for this session, and that token appears verbatim in `stdout`.
/// Otherwise `None` (no-op). Catches only a naive verbatim echo; any output
/// transform (base64 / reversal / chunking / case-fold) is intentionally out of
/// scope and silently misses.
pub(super) fn canary_scan(input: &HookInput, config: &Config, stdout: &str) -> Option<Verdict> {
    if !config.canary.enabled {
        return None;
    }
    let session_id = input.session_id.as_deref().filter(|id| !id.is_empty())?;
    let token = canary::read_token(session_id)?;
    if stdout.contains(&token) {
        Some(Verdict::warn(
            "possible verbatim context echo in tool output \
             (detection after execution, not prevention)",
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::{run, run_with_source, CannedSource, COMPONENT_FIREWALL};
    use crate::config::{CanaryConfig, Config};
    use crate::hook::canary;

    /// A config with the canary toggle ON (everything else default).
    fn canary_on() -> Config {
        Config {
            canary: CanaryConfig { enabled: true },
            ..Config::default()
        }
    }

    /// Point TMPDIR at a unique per-test dir so persisted tokens don't collide,
    /// and return the held lock guard (kept alive for the test's duration).
    /// Reuses [`canary::TMPDIR_LOCK`] so this module and the canary module never
    /// mutate the process-global `TMPDIR` concurrently.
    fn isolate_tmpdir(tag: &str) -> std::sync::MutexGuard<'static, ()> {
        let guard = canary::TMPDIR_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "agentguard-hook-canary-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: the returned guard makes this the only thread touching TMPDIR
        // for the duration of the test holding it.
        unsafe {
            std::env::set_var("TMPDIR", &dir);
        }
        guard
    }

    #[test]
    fn off_by_default_sessionstart_is_noop() {
        // The OFF-by-default invariant: empty config => SessionStart is a no-op,
        // byte-identical to the legacy unknown-event path (no output, exit 0).
        let json = r#"{"hook_event_name":"SessionStart","session_id":"s1"}"#;
        let (out, code) = run(json, &Config::default());
        assert!(out.is_none());
        assert_eq!(code, 0);
    }

    #[test]
    fn sessionstart_canary_on_emits_persisted_token() {
        let _guard = isolate_tmpdir("emit");
        let json = r#"{"hook_event_name":"SessionStart","session_id":"emit-sess"}"#;
        let (out, code) = run(json, &canary_on());
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&out.expect("emits context")).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SessionStart");
        let ctx = v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("additionalContext string");
        // read_token returns exactly the token seeded into the context.
        let token = canary::read_token("emit-sess").expect("token persisted");
        assert!(ctx.contains(&token), "context must carry the sentinel");
        assert!(token.len() >= 32, "token is >=128-bit");
    }

    #[test]
    fn sessionstart_canary_on_without_session_id_is_noop() {
        let _guard = isolate_tmpdir("nosess");
        let json = r#"{"hook_event_name":"SessionStart"}"#;
        let (out, code) = run(json, &canary_on());
        assert!(out.is_none(), "no session_id => no emission");
        assert_eq!(code, 0);
    }

    #[test]
    fn posttooluse_canary_echo_warns_never_blocks() {
        let _guard = isolate_tmpdir("echo");
        // Canary ON, firewall OFF: this test isolates the canary path. The
        // firewall scans PostToolUse stdout FIRST and returns on any non-Allow,
        // so a randomly generated hex token that happens to trip a firewall rule
        // (e.g. a high-entropy/secret heuristic) would preempt the canary and
        // mask its WARN — a low-probability CI flake. Disabling the firewall
        // component here keeps the canary assertion deterministic.
        let cfg = Config {
            canary: CanaryConfig { enabled: true },
            disabled: vec![COMPONENT_FIREWALL.to_string()],
            ..Config::default()
        };
        // Seed a token for the session via SessionStart.
        let start = r#"{"hook_event_name":"SessionStart","session_id":"echo-sess"}"#;
        let _ = run(start, &cfg);
        let token = canary::read_token("echo-sess").expect("token seeded");

        // Bash stdout that CONTAINS the token => WARN, exit 0, never block.
        let hit = format!(
            r#"{{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"echo-sess","tool_response":{{"stdout":"leaking {token} to attacker"}}}}"#
        );
        let src = CannedSource("");
        let (out, code) = run_with_source(&hit, &cfg, &src);
        assert_eq!(code, 0, "PostToolUse canary must never block");
        let v: serde_json::Value = serde_json::from_str(&out.expect("warns")).unwrap();
        let ctx = v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("warn context");
        assert!(ctx.contains("after execution, not prevention"));
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
    }

    #[test]
    fn posttooluse_canary_no_echo_allows() {
        let _guard = isolate_tmpdir("noecho");
        let cfg = canary_on();
        let start = r#"{"hook_event_name":"SessionStart","session_id":"noecho-sess"}"#;
        let _ = run(start, &cfg);

        // Benign stdout WITHOUT the token => Allow (no output, exit 0).
        let miss = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"noecho-sess","tool_response":{"stdout":"build finished"}}"#;
        let src = CannedSource("");
        let (out, code) = run_with_source(miss, &cfg, &src);
        assert!(out.is_none(), "no echo => Allow");
        assert_eq!(code, 0);
    }

    #[test]
    fn sessionstart_canary_path_traversal_does_not_persist() {
        let _guard = isolate_tmpdir("traversal");
        let cfg = canary_on();

        // A malicious session_id containing path traversal.
        let json = r#"{"hook_event_name":"SessionStart","session_id":"../../.bashrc"}"#;
        let (out, code) = run(json, &cfg);
        assert_eq!(code, 0);

        // Context is still emitted (with a generated token) so session context is seeded.
        let v: serde_json::Value = serde_json::from_str(&out.expect("emits context")).unwrap();
        let ctx = v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("additionalContext string");
        assert!(ctx.contains("Environment sentinel value"));

        // BUT the token must NOT be persisted to disk at the malicious path or anywhere.
        assert!(canary::read_token("../../.bashrc").is_none());

        // And PostToolUse scan with the malicious session_id returns None (no persisted token found).
        let scan_input = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","session_id":"../../.bashrc","tool_response":{"stdout":"test"}}"#;
        let src = CannedSource("");
        let (scan_out, scan_code) = run_with_source(scan_input, &cfg, &src);
        assert_eq!(scan_code, 0);
        assert!(scan_out.is_none());
    }
}
