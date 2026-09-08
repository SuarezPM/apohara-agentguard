//! Host path constants, embedded artifacts, and per-host event-group tables.
//! Single source for every wire constant `init` and `doctor` share.

use std::path::Path;

use serde_json::json;

/// Substring identifying an apohara-agentguard-installed inner hook: any
/// inner hook whose `command` contains this marker is ours.
pub const MARKER: &str = "apohara-agentguard";

pub const CLAUDE_DIR: &str = ".claude";
pub const CLAUDE_FILE: &str = "settings.json";
pub const CODEX_DIR: &str = ".codex";
pub const CODEX_FILE: &str = "hooks.json";

// --- FASE 4 (v0.5.0) JSON-hook + drop-in hosts ------------------------------

/// `~/.codeium/windsurf/hooks.json` (user scope).
pub const WINDSURF_DIR: &str = ".codeium";
pub const WINDSURF_SUBDIR: &str = "windsurf";
/// `~/.cursor/hooks.json`.
pub const CURSOR_DIR: &str = ".cursor";
/// Antigravity plugin drop-in dir (we OWN this directory's hooks.json).
pub const ANTIGRAVITY_PLUGIN_DIR: &str = ".gemini/antigravity-cli/plugins/agentguard";
/// Config file name shared by the three FASE-4 hosts.
pub const HOOKS_JSON_FILE: &str = "hooks.json";

// --- Drop-in hosts (opencode / kilo / kitty-code) ---------------------------

pub const OPENCODE_APP: &str = "opencode";
pub const KILO_APP: &str = "kilo";
pub const PLUGINS_SUBDIR: &str = "plugins";
/// Reserved plugin filename in the OpenCode/Kilo `plugins/` drop-in dir.
pub const SHIM_FILE_NAME: &str = "agentguard-shim.mjs";
pub const KILO_GUIDE_FILE_NAME: &str = "agentguard-veto-guide.md";
pub const KITTY_DIR_NAME: &str = ".kitty-code";
pub const KITTY_POLICY_FILE_NAME: &str = "policy.toml";

/// Embedded OpenCode/Kilo plugin shim — single source of truth is
/// `packaging/opencode/agentguard-shim.mjs`; init copies it verbatim into
/// each host's `plugins/` directory.
pub const OPENCODE_SHIM: &str = include_str!("../../packaging/opencode/agentguard-shim.mjs");

/// kitty-code policy scaffold: a fully commented `[agentguard]` section. The
/// engine itself is EMBEDDED VIA LIBRARY inside kitty-code (path dependency,
/// plan decision #7), so this file is operator documentation + policy
/// placeholder only — nothing of ours executes from it. Exact content
/// equality against this constant is what makes install idempotent and undo
/// safe (a user-customized policy.toml is never touched).
pub const KITTY_SCAFFOLD: &str = concat!(
    "# apohara-agentguard — kitty-code policy scaffold\n",
    "#\n",
    "# The agentguard engine is EMBEDDED VIA LIBRARY inside kitty-code (path\n",
    "# dependency), not spawned as a subprocess. This file only holds your\n",
    "# policy overrides. Uncomment to activate:\n",
    "#\n",
    "# [agentguard]\n",
    "# enabled = true\n",
);

// Codex manifest constants are SINGLE-SOURCED in `adapters::codex` (the
// adapters → init edge is forbidden; init → adapters is the correct
// direction). The spawn args/timeout are the canonical subprocess-envelope
// parameters shared by every JSON-hook host.
use crate::adapters::codex::{CODEX_PRE_TOOL_USE_MATCHER, HOOK_TIMEOUT};

/// Generate the EXACT `hooks.json` document `init` writes into OUR
/// antigravity plugin directory (`~/.gemini/antigravity-cli/plugins/agentguard/`).
///
/// Antigravity is claude-like (`PreToolUse` + `{tool_name, tool_input}`), so
/// the document uses the nested matcher-group envelope with the canonical
/// spawn args plus `--harness antigravity`. Because the whole file is ours,
/// install/undo/doctor manage it by exact content equality — this generator
/// is the single source shared by all three (and by the contract tests).
pub fn antigravity_plugin_document(exe: &Path) -> String {
    let doc = json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ANTIGRAVITY_MATCHER,
                    "hooks": [
                        {
                            "type": "command",
                            "command": exe.to_string_lossy(),
                            "args": ["hook", "--harness", "antigravity"],
                            "timeout": HOOK_TIMEOUT,
                        }
                    ]
                }
            ]
        }
    });
    // serde_json serialization of a Value cannot fail.
    let mut out =
        serde_json::to_string_pretty(&doc).expect("antigravity doc serialization is infallible");
    out.push('\n');
    out
}

/// Event groups wired per host: `(event key, matcher)`. A `None` matcher is
/// omitted (Claude Code's UserPromptSubmit takes no matcher).
pub const CLAUDE_GROUPS: &[(&str, Option<&str>)] = &[
    (
        "PreToolUse",
        Some("Bash|Read|Write|Edit|WebFetch|WebSearch"),
    ),
    ("PostToolUse", Some("Bash")),
    ("UserPromptSubmit", None),
];
pub const CODEX_GROUPS: &[(&str, Option<&str>)] =
    &[("PreToolUse", Some(CODEX_PRE_TOOL_USE_MATCHER))];

/// Windsurf hook events (ASSUMPTION documented: the researched wire format
/// exposes these two pre-action events at user scope; entries are flat
/// `{command}` objects, so no matchers are written — a catch-all entry is the
/// tolerant shape and the gate itself decides what to evaluate).
pub const WINDSURF_GROUPS: &[(&str, Option<&str>)] =
    &[("pre_run_command", None), ("pre_mcp_tool_use", None)];

/// Cursor hook events (flat per-event command arrays; no matcher channel on
/// these two events in the researched format).
pub const CURSOR_GROUPS: &[(&str, Option<&str>)] =
    &[("beforeShellExecution", None), ("beforeMCPExecution", None)];

/// Antigravity is claude-like (`PreToolUse` + `{tool_name, tool_input}`), so
/// it gets the SAME matcher surface as the Claude wiring. ASSUMPTION: its
/// plugin `hooks.json` accepts the nested matcher-group document; if the
/// loader proves stricter, only [`antigravity_plugin_document`] needs to
/// change (the file is ours by exact content).
const ANTIGRAVITY_MATCHER: &str = "Bash|Read|Write|Edit|WebFetch|WebSearch";
