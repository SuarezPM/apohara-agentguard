//! Kilo Code host adapter (PLAN-V05-UNIVERSAL §1.2, Wave U2′.5).
//!
//! Fork lineage: Kilo Code's CLI is an OpenCode fork, so its plugin system
//! speaks the SAME V1 plugin API — a `tool.execute.before` handler receives
//! `{tool, args}` with `args` passed BY REFERENCE (in-place property mutation
//! propagates; replacing the args object does not) and a thrown handler
//! blocks the tool PRE-permission, which makes the block YOLO-immune.
//!
//! Kilo additionally exposes a declarative `hardRuleset` veto channel that no
//! approval mode can override. That makes Kilo a TWO-LAYER host:
//!
//! 1. PRIMARY (YOLO-immune by construction): the `hardRuleset` veto — see
//!    [`veto_guide`], shipped to `~/.config/kilo/agentguard-veto-guide.md`
//!    by `agentguard init`.
//! 2. SECOND layer: the plugin hook shim (`plugins/agentguard-shim.mjs`,
//!    shared verbatim with OpenCode — see
//!    `packaging/opencode/agentguard-shim.mjs`).
//!
//! Residual risk (documented in the guide): commands executed directly in an
//! integrated terminal bypass both channels.
//!
//! Like Codex, this host has NO ask flow and NO rewrite/context channel
//! (capabilities matrix row `KiloCode`: `can_ask/can_rewrite/can_add_context`
//! all false), so an Ask must degrade to Deny before any emission.

use std::path::Path;

/// The Kilo plugin registration fragment: the same `tool.execute.before`
/// shape OpenCode plugins register (fork lineage above), described as data so
/// tests and docs can pin what the drop-in shim provides.
///
/// The shim file itself is the single source of truth for behavior; this
/// manifest only records the registration shape and which subprocess the
/// handler spawns (`exe hook` — the Claude-envelope PreToolUse gate).
pub fn install_manifest(exe: &Path) -> serde_json::Value {
    serde_json::json!({
        "tool": {
            "execute": {
                "before": {
                    "source": "plugins/agentguard-shim.mjs",
                    "handler": "toolExecuteBefore",
                    "transport": {
                        "command": exe.to_string_lossy(),
                        "args": ["hook"],
                    },
                }
            }
        },
        "veto_guide": "agentguard-veto-guide.md",
    })
}

/// The `hardRuleset` veto guide markdown written to
/// `~/.config/kilo/agentguard-veto-guide.md` on `agentguard init`.
///
/// Documents the YOLO-immune primary enforcement channel (hardRuleset veto),
/// the plugin hook as the second layer, and the terminal-integrated VS Code
/// residual risk.
pub fn veto_guide() -> &'static str {
    KILO_VETO_GUIDE
}

const KILO_VETO_GUIDE: &str = r#"# apohara-agentguard for Kilo Code — enforcement guide

Kilo Code's CLI is an OpenCode fork, so apohara-agentguard protects it through
the same plugin API **plus** a Kilo-specific declarative channel. Two layers,
one engine (`apohara-agentguard hook`, deterministic, offline, no model).

## Layer 1 (PRIMARY, YOLO-immune): hardRuleset veto

Kilo's `hardRuleset` vetoes are enforced even in YOLO / auto-approve modes —
no permission setting can wave them through. Wire destructive-command vetoes
to the engine:

- Route every Bash-shaped tool call through `apohara-agentguard check "<command>"`.
- A non-zero exit (2 = block) maps to a hardRuleset veto entry, denying the
  command before execution regardless of approval mode.

This is the PRIMARY enforcement channel on Kilo precisely because it survives
YOLO mode; treat it as load-bearing and keep it enabled.

## Layer 2 (second layer): plugin hook

`~/.config/kilo/plugins/agentguard-shim.mjs` registers a `tool.execute.before`
handler (same plugin API as OpenCode — fork lineage). It spawns
`apohara-agentguard hook` per tool call and THROWS on a deny, which blocks the
tool BEFORE permission evaluation — also YOLO-immune. Install/uninstall it
with `apohara-agentguard init --yes` / `--undo`.

## Residual risk

Terminal-integrated VS Code usage: commands typed or scripted directly in an
integrated terminal never pass through the plugin hook NOR the hardRuleset
veto — both channels only see harness-mediated tool calls. For terminal work
you want confined, run it under `apohara-agentguard sandbox -- <command>`.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_manifest_has_opencode_tool_execute_before_shape() {
        let exe = Path::new("/usr/local/bin/apohara-agentguard");
        let m = install_manifest(exe);
        let before = &m["tool"]["execute"]["before"];
        assert_eq!(
            before["source"], "plugins/agentguard-shim.mjs",
            "drop-in shim path"
        );
        assert_eq!(before["handler"], "toolExecuteBefore", "exported handler");
        assert_eq!(
            before["transport"]["command"], "/usr/local/bin/apohara-agentguard",
            "spawned binary is the wired exe"
        );
        assert_eq!(before["transport"]["args"], serde_json::json!(["hook"]));
        assert_eq!(
            m["veto_guide"], "agentguard-veto-guide.md",
            "guide artifact recorded alongside the plugin"
        );
    }

    #[test]
    fn veto_guide_documents_hardruleset_yolo_and_residual_risk() {
        let g = veto_guide();
        assert!(
            g.contains("hardRuleset"),
            "guide must name the primary veto channel"
        );
        assert!(
            g.contains("YOLO"),
            "guide must state the channel is YOLO-immune"
        );
        assert!(
            g.contains("Residual risk"),
            "guide must document the residual risk"
        );
        assert!(
            g.contains("terminal"),
            "residual risk section must cover terminal-integrated VS Code"
        );
        assert!(g.contains("OpenCode fork"), "fork lineage must be cited");
    }
}
