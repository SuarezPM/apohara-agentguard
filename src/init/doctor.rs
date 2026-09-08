//! Doctor surface: observed wiring state per host (read-only). Mirrors the
//! install / undo semantics WITHOUT writing anything.

use std::path::{Path, PathBuf};

use super::plan::parse_config;
use super::tables::antigravity_plugin_document;
use super::tables::{
    ANTIGRAVITY_PLUGIN_DIR, CLAUDE_DIR, CLAUDE_FILE, CODEX_DIR, CODEX_FILE, CURSOR_DIR,
    HOOKS_JSON_FILE, KILO_APP, KILO_GUIDE_FILE_NAME, KITTY_DIR_NAME, KITTY_POLICY_FILE_NAME,
    KITTY_SCAFFOLD, OPENCODE_APP, OPENCODE_SHIM, SHIM_FILE_NAME, WINDSURF_DIR, WINDSURF_SUBDIR,
};
use super::wire::{expected_command, is_wired, marker_sites};
use super::{plugins_dir, xdg_config_dir, InitError};

/// Observed wiring state of one host's artifacts on disk. Computed by
/// [`diagnose_hosts`] for `agentguard doctor`; mirrors the install / undo
/// semantics above WITHOUT writing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WiringState {
    /// Our marker / artifacts are present and point at (or equal) the current
    /// binary content.
    Wired,
    /// Our wiring is present but points at a different binary path (JSON
    /// hosts) or our reserved artifact content drifted (drop-in hosts) —
    /// silent protection loss until the next `init --yes` self-heals it.
    Stale,
    /// Nothing of ours is on disk for this host.
    NotInstalled,
    /// kitty-code only: a `policy.toml` exists that is not our scaffold —
    /// user policy, healthy by design (the engine embeds via library there).
    UserPolicy,
    /// A JSON-hook host config exists but cannot be parsed as a valid hook
    /// document — our wiring cannot be verified (and `init` would refuse to
    /// touch it).
    Corrupt(String),
}

/// One host's observed wiring state plus its primary artifact path (the
/// config file for JSON-hook hosts, the shim / scaffold for drop-ins).
#[derive(Debug, Clone)]
pub struct HostWiring {
    pub host: &'static str,
    pub path: PathBuf,
    pub state: WiringState,
}

/// Observe the wiring state of all EIGHT hosts against `base_home`, writing
/// nothing (`doctor`). Same path resolution as [`run`] — including
/// `$XDG_CONFIG_HOME`, passed EXPLICITLY so this core stays hermetic like
/// the rest of the module.
pub fn diagnose_hosts(
    base_home: &Path,
    xdg_config_home: Option<&std::ffi::OsStr>,
    exe: &Path,
) -> Vec<HostWiring> {
    let mut out = Vec::with_capacity(8);

    // JSON-hook hosts: classify by parsing the config and scanning markers.
    // Flat-entry hosts (windsurf/cursor) compare against their full spawn
    // line; nested hosts against the bare exe.
    for (host, path, harness) in [
        (
            "claude-code",
            base_home.join(CLAUDE_DIR).join(CLAUDE_FILE),
            None,
        ),
        (
            "codex-code",
            base_home.join(CODEX_DIR).join(CODEX_FILE),
            None,
        ),
        (
            "windsurf",
            base_home
                .join(WINDSURF_DIR)
                .join(WINDSURF_SUBDIR)
                .join(HOOKS_JSON_FILE),
            Some("windsurf"),
        ),
        (
            "cursor",
            base_home.join(CURSOR_DIR).join(HOOKS_JSON_FILE),
            Some("cursor"),
        ),
    ] {
        let state = json_wiring_state(&path, exe, harness);
        out.push(HostWiring { host, path, state });
    }

    // Drop-in hosts: classify by exact-content equality of our reserved
    // artifacts (same read_exact primitive install uses).
    let opencode_shim = plugins_dir(base_home, xdg_config_home, OPENCODE_APP).join(SHIM_FILE_NAME);
    let state = dropin_wiring_state(&[(&opencode_shim, OPENCODE_SHIM)]);
    out.push(HostWiring {
        host: "opencode",
        path: opencode_shim.clone(),
        state,
    });

    let kilo_plugins = plugins_dir(base_home, xdg_config_home, KILO_APP);
    let kilo_shim = kilo_plugins.join(SHIM_FILE_NAME);
    let kilo_guide =
        xdg_config_dir(base_home, xdg_config_home, KILO_APP).join(KILO_GUIDE_FILE_NAME);
    let state = dropin_wiring_state(&[
        (&kilo_shim, OPENCODE_SHIM),
        (&kilo_guide, crate::adapters::kilo::veto_guide()),
    ]);
    out.push(HostWiring {
        host: "kilo",
        path: kilo_shim.clone(),
        state,
    });

    // Antigravity: our plugin hooks.json is generated from the current exe,
    // so exact-content equality IS the staleness check.
    let antigravity_hooks = base_home.join(ANTIGRAVITY_PLUGIN_DIR).join(HOOKS_JSON_FILE);
    let doc = antigravity_plugin_document(exe);
    let state = dropin_wiring_state(&[(&antigravity_hooks, doc.as_str())]);
    out.push(HostWiring {
        host: "antigravity",
        path: antigravity_hooks.clone(),
        state,
    });

    let kitty_policy = plan_kitty_wiring(base_home);
    out.push(kitty_policy);
    out
}

/// Classify one JSON-hook host config (`claude-code`, `codex-code`,
/// `windsurf`, `cursor`) without modifying it. Reuses the SAME parse
/// validation ([`parse_config`]) and marker scan ([`is_wired`] /
/// [`marker_sites`]) as install. `harness` is the flat-entry spawn-line
/// suffix (`Some("windsurf")`) or `None` for nested-envelope hosts.
fn json_wiring_state(path: &Path, exe: &Path, harness: Option<&str>) -> WiringState {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WiringState::NotInstalled,
        Err(e) => WiringState::Corrupt(e.to_string()),
        Ok(bytes) => {
            let root = match parse_config(path, &bytes) {
                Ok(v) => v,
                Err(InitError::CorruptConfig { reason, .. }) => {
                    return WiringState::Corrupt(reason)
                }
                Err(InitError::Io { source, .. }) => {
                    return WiringState::Corrupt(source.to_string())
                }
            };
            if !is_wired(&root) {
                return WiringState::NotInstalled;
            }
            let exe_str = exe.to_string_lossy();
            let fresh = marker_sites(&root)
                .iter()
                .all(|(is_flat, c)| *c == expected_command(*is_flat, exe_str.as_ref(), harness));
            if fresh {
                WiringState::Wired
            } else {
                WiringState::Stale
            }
        }
    }
}

/// Classify a drop-in host from exact-content equality of each artifact:
/// all present and exact ⇒ Wired; anything missing ⇒ NotInstalled; else
/// (all present, ≥1 divergent) ⇒ Stale. An unreadable artifact maps to
/// Stale too? No — an I/O error reading OUR reserved filename is treated as
/// NotInstalled only when it is a NotFound; any other error surfaces as
/// Stale (the artifact is there but unusable — self-heal applies).
fn dropin_wiring_state(files: &[(&Path, &str)]) -> WiringState {
    let mut missing_any = false;
    let mut divergent_any = false;
    for (path, ours) in files {
        match std::fs::read(path) {
            Ok(bytes) if bytes == ours.as_bytes() => {}
            Ok(_) => divergent_any = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing_any = true,
            Err(_) => divergent_any = true,
        }
    }
    if missing_any {
        WiringState::NotInstalled
    } else if divergent_any {
        WiringState::Stale
    } else {
        WiringState::Wired
    }
}

/// kitty-code classification: scaffold-exact ⇒ Wired; user policy ⇒
/// UserPolicy; absent ⇒ NotInstalled (mirrors [`plan_kitty_host`] install
/// detection exactly).
fn plan_kitty_wiring(base_home: &Path) -> HostWiring {
    let path = base_home.join(KITTY_DIR_NAME).join(KITTY_POLICY_FILE_NAME);
    let state = match std::fs::read(&path) {
        Ok(bytes) if bytes == KITTY_SCAFFOLD.as_bytes() => WiringState::Wired,
        Ok(_) => WiringState::UserPolicy,
        Err(_) => WiringState::NotInstalled,
    };
    HostWiring {
        host: "kitty-code",
        path,
        state,
    }
}
