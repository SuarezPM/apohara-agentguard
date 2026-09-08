//! `agentguard init` — wire the apohara-agentguard hook into detected agent
//! host configurations (Claude Code, OpenAI Codex, OpenCode, Kilo Code,
//! kitty-code).
//!
//! The library core is hermetic: every entry point takes an explicit
//! `base_home` (the user home directory) so tests can operate on a tempdir.
//! The CLI wrapper (`src/main.rs`) resolves the real home directory and the
//! currently-running binary. The only environment read is
//! `$XDG_CONFIG_HOME` (once, at [`run`] entry) for the OpenCode/Kilo plugin
//! directories; unset/empty means `<home>/.config`.
//!
//! Two host families:
//!
//! - JSON-hook hosts (`claude-code`, `codex-code`): edit the host's hook
//!   config document (integrity contract below).
//! - Drop-in hosts (`opencode`, `kilo`, `kitty-code`): NO host config file is
//!   parsed or edited at all — a plugin-dir drop-in needs no config edit
//!   (`opencode.json` / Kilo's config are never touched). We copy our own
//!   reserved-name artifacts (shim / guide / scaffold) and manage them by
//!   EXACT CONTENT EQUALITY:
//!   - install writes an artifact when it is missing or divergent (our
//!     reserved filenames are self-healed in place);
//!   - undo removes an artifact ONLY when its content equals ours exactly —
//!     a hand-edited artifact is never deleted;
//!   - kitty-code is DETECTION + SCAFFOLD only (the engine embeds via
//!     library there): an existing non-scaffold `policy.toml` is never
//!     touched.
//!
//! Integrity contract (JSON-hook hosts):
//! - APPEND-ONLY: existing user hooks are never clobbered or reordered; our
//!   matcher groups are appended to the existing event arrays.
//! - IDEMPOTENT + SELF-HEALING: a prior install is detected by scanning every
//!   inner hook's `command` for the binary-name marker. If the wiring already
//!   points at exactly the current executable, a re-run reports "already
//!   wired"; if it points at a stale/relocated path, those entries' `command`
//!   fields are refreshed IN PLACE (no duplicates, user content untouched).
//! - CORRUPT-REFUSAL: a target file that exists but is not valid JSON (or is
//!   not a JSON object / has a malformed `hooks` table) aborts the whole
//!   operation BEFORE any file is modified — every host is planned up-front,
//!   so a corrupt config on one host never leaves any other half-wired. (An
//!   I/O failure during persistence can still leave an earlier host written;
//!   each single write is atomic, cross-host is not transactional.) The
//!   drop-in hosts touch no JSON configs, so they add no new corrupt-config
//!   surface.
//! - UNDO removes only marker-matched inner hooks (plus OUR exact stamped
//!   Codex `description`, never a user-customized one), prunes arrays that
//!   became empty, and leaves every other piece of user content untouched
//!   (`serde_json::Value` round-trip).
//!
//! `${CLAUDE_PLUGIN_ROOT}` deliberately does NOT work in Claude Code's
//! `settings.json`, so the ABSOLUTE path of the running binary is written.

mod doctor;
mod plan;
mod tables;
mod wire;

pub use doctor::{diagnose_hosts, HostWiring, WiringState};
pub use tables::{antigravity_plugin_document, KITTY_SCAFFOLD};

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use plan::{
    plan_dropin_host, plan_host, plan_kitty_host, DropInFile, HostPlan, HostSpec, WireShape,
};
use tables::{
    ANTIGRAVITY_PLUGIN_DIR, CLAUDE_DIR, CLAUDE_FILE, CLAUDE_GROUPS, CODEX_DIR, CODEX_FILE,
    CODEX_GROUPS, CURSOR_DIR, CURSOR_GROUPS, HOOKS_JSON_FILE, KILO_APP, KILO_GUIDE_FILE_NAME,
    OPENCODE_APP, OPENCODE_SHIM, PLUGINS_SUBDIR, SHIM_FILE_NAME, WINDSURF_DIR, WINDSURF_GROUPS,
    WINDSURF_SUBDIR,
};
use wire::{atomic_write, write_config};

/// What `init` should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Append our hook wiring (idempotent).
    Install,
    /// Remove previously-installed wiring (clean no-op when absent).
    Uninstall,
}

/// Errors surfaced by [`run`].
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The target file exists but is not usable JSON. REFUSED: the file is
    /// never modified (fail-closed integrity over silent repair).
    #[error("corrupt agent config {path} (refusing to modify): {reason}")]
    CorruptConfig { path: PathBuf, reason: String },

    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Per-host result of one `init` run.
#[derive(Debug)]
pub struct HostResult {
    /// Host label used in CLI output (`claude-code` / `codex-code` /
    /// `opencode` / `kilo` / `kitty-code`).
    pub host: &'static str,
    /// Absolute path of the host config file.
    pub path: PathBuf,
    pub outcome: Outcome,
}

/// What happened (or would happen, under a dry-run) for one host.
#[derive(Debug)]
pub enum Outcome {
    /// Wiring was appended (or would be). `dir_created` reports DETECTION:
    /// `true` means the host home subdir did NOT pre-exist and was (or would
    /// be) created fresh — i.e. no prior install of the agent was detected.
    Wired { dir_created: bool },
    /// Our marker is present AND already points at exactly the current
    /// executable; nothing was changed.
    AlreadyWired,
    /// Our wiring was present but pointed at a DIFFERENT (stale / relocated)
    /// binary path — silent protection loss. The marker-matched entries'
    /// `command` fields were rewritten IN PLACE to the current executable
    /// (append-only toward user content; args/timeout/matchers untouched).
    Refreshed { updated: usize },
    /// Undo removed this many of our inner hooks.
    Unwired { removed: usize },
    /// Undo found nothing of ours (clean no-op success).
    NothingToUnwire,
    /// kitty-code detection+scaffold: no `policy.toml` existed, so our inert
    /// scaffold was (or would be) written. The engine is embedded via
    /// library — this file is the only artifact.
    Scaffolded { dir_created: bool },
    /// kitty-code detection: a `policy.toml` already exists that is NOT our
    /// exact scaffold — left untouched (detection only; user policy is never
    /// clobbered by a scaffold writer).
    DetectedExisting,
}

/// Run init across all five hosts against `base_home`.
///
/// `exe` is the absolute path of the binary to wire in (the CLI passes the
/// canonicalized `std::env::current_exe()`). With `apply = false` this is a
/// DRY-RUN: planned outcomes are computed and returned but nothing is
/// written. EVERY host is planned BEFORE anything is written, so a corrupt
/// config aborts with [`InitError::CorruptConfig`] and zero writes. That is
/// where atomicity ends: an I/O failure during the phase-3 persistence loop
/// can leave an EARLIER host already written — cross-host transactions are
/// impossible without a journal, and none is attempted. Each individual
/// file write IS atomic (sibling temp file + rename).
pub fn run(
    base_home: &Path,
    exe: &Path,
    mode: Mode,
    apply: bool,
) -> Result<Vec<HostResult>, InitError> {
    // Read ONCE so the library stays hermetic (tests control the env of the
    // process under test; no env mutation happens inside this crate).
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");

    let json_specs = [
        HostSpec {
            host: "claude-code",
            dir: base_home.join(CLAUDE_DIR),
            file_name: CLAUDE_FILE,
            shape: WireShape::Groups,
            groups: CLAUDE_GROUPS,
            harness_arg: None,
            sets_description: false,
        },
        HostSpec {
            host: "codex-code",
            dir: base_home.join(CODEX_DIR),
            file_name: CODEX_FILE,
            shape: WireShape::Groups,
            groups: CODEX_GROUPS,
            harness_arg: None,
            sets_description: true,
        },
        // FASE 4 hosts. Windsurf nests under ~/.codeium/windsurf (user
        // scope); cursor is the flat ~/.cursor/hooks.json.
        HostSpec {
            host: "windsurf",
            dir: base_home.join(WINDSURF_DIR).join(WINDSURF_SUBDIR),
            file_name: HOOKS_JSON_FILE,
            shape: WireShape::Flat,
            groups: WINDSURF_GROUPS,
            harness_arg: Some("windsurf"),
            sets_description: false,
        },
        HostSpec {
            host: "cursor",
            dir: base_home.join(CURSOR_DIR),
            file_name: HOOKS_JSON_FILE,
            shape: WireShape::Flat,
            groups: CURSOR_GROUPS,
            harness_arg: Some("cursor"),
            sets_description: false,
        },
    ];

    // Phase 1 — parse + transform BOTH JSON-hook hosts. Any corrupt config
    // errors out here, before a single byte is written anywhere.
    let json_plans: Vec<HostPlan> = json_specs
        .iter()
        .map(|s| plan_host(s, exe, mode))
        .collect::<Result<_, _>>()?;

    // Phase 2 — plan the drop-in hosts. Pure filesystem-shape planning: no
    // host config is parsed or edited (plugin-dir drop-ins need none).
    let kilo_guide = crate::adapters::kilo::veto_guide();
    let opencode_plugins = plugins_dir(base_home, xdg_config_home.as_deref(), OPENCODE_APP);
    let kilo_plugins = plugins_dir(base_home, xdg_config_home.as_deref(), KILO_APP);
    // Antigravity: a plugin DIRECTORY we own outright — its hooks.json is
    // generated from the current exe (so exact-content equality doubles as
    // staleness detection, mirroring the JSON hosts' refresh semantics).
    let antigravity_dir = base_home.join(ANTIGRAVITY_PLUGIN_DIR);
    let dropin_plans = [
        plan_dropin_host(
            "opencode",
            &opencode_plugins,
            &[DropInFile {
                path: opencode_plugins.join(SHIM_FILE_NAME),
                content: Cow::Borrowed(OPENCODE_SHIM),
            }],
            mode,
        )?,
        plan_dropin_host(
            "kilo",
            &kilo_plugins,
            &[
                DropInFile {
                    path: kilo_plugins.join(SHIM_FILE_NAME),
                    content: Cow::Borrowed(OPENCODE_SHIM),
                },
                DropInFile {
                    path: xdg_config_dir(base_home, xdg_config_home.as_deref(), KILO_APP)
                        .join(KILO_GUIDE_FILE_NAME),
                    content: Cow::Borrowed(kilo_guide),
                },
            ],
            mode,
        )?,
        plan_kitty_host(base_home, mode)?,
        plan_dropin_host(
            "antigravity",
            &antigravity_dir,
            &[DropInFile {
                path: antigravity_dir.join(HOOKS_JSON_FILE),
                content: Cow::Owned(antigravity_plugin_document(exe)),
            }],
            mode,
        )?,
    ];

    // Phase 3 — persist, in host order.
    let mut results = Vec::with_capacity(json_specs.len() + dropin_plans.len());
    for (spec, plan) in json_specs.iter().zip(json_plans) {
        if let Some(new_value) = plan.new_value {
            if apply {
                let path = spec.dir.join(spec.file_name);
                write_config(&path, &new_value)?;
            }
        }
        results.push(HostResult {
            host: spec.host,
            path: spec.dir.join(spec.file_name),
            outcome: plan.outcome,
        });
    }
    for plan in dropin_plans {
        if apply {
            for file in &plan.writes {
                atomic_write(&file.path, file.content.as_bytes())?;
            }
            for file in &plan.removes {
                std::fs::remove_file(&file.path).map_err(|e| InitError::Io {
                    path: file.path.clone(),
                    source: e,
                })?;
            }
        }
        results.push(HostResult {
            host: plan.host,
            path: plan.report_path,
            outcome: plan.outcome,
        });
    }
    Ok(results)
}

/// `<config-root>/<app>/plugins` where `<config-root>` is `$XDG_CONFIG_HOME`
/// when set (and non-empty), else `<home>/.config`.
fn plugins_dir(base_home: &Path, xdg_config_home: Option<&std::ffi::OsStr>, app: &str) -> PathBuf {
    xdg_config_dir(base_home, xdg_config_home, app).join(PLUGINS_SUBDIR)
}

/// `<config-root>/<app>` with `$XDG_CONFIG_HOME` respected.
fn xdg_config_dir(
    base_home: &Path,
    xdg_config_home: Option<&std::ffi::OsStr>,
    app: &str,
) -> PathBuf {
    match xdg_config_home {
        Some(x) if !x.is_empty() => PathBuf::from(x).join(app),
        _ => base_home.join(".config").join(app),
    }
}

#[cfg(test)]
mod doctor_surface_tests {
    use super::tables::{
        CLAUDE_DIR, CLAUDE_FILE, KITTY_DIR_NAME, KITTY_POLICY_FILE_NAME, OPENCODE_APP,
        PLUGINS_SUBDIR, SHIM_FILE_NAME,
    };
    use super::*;
    use std::sync::Mutex;

    static XDG_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentguard-init-diagnose-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn exe_marker() -> String {
        "apohara-agentguard".to_string()
    }

    fn state_of<'a>(wiring: &'a [HostWiring], host: &str) -> &'a WiringState {
        &wiring
            .iter()
            .find(|w| w.host == host)
            .unwrap_or_else(|| panic!("host {host} missing from diagnose_hosts output"))
            .state
    }

    #[test]
    fn empty_home_reports_all_hosts_not_installed() {
        let home = temp_home("empty");
        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        assert_eq!(wiring.len(), 8);
        for host in [
            "claude-code",
            "codex-code",
            "windsurf",
            "cursor",
            "opencode",
            "kilo",
            "antigravity",
            "kitty-code",
        ] {
            assert_eq!(
                state_of(&wiring, host),
                &WiringState::NotInstalled,
                "{host}"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn installed_home_reports_every_host_wired() {
        // Hermetic guard: `run()` reads `$XDG_CONFIG_HOME` from the process
        // env while `diagnose_hosts()` takes it explicitly. Without isolation
        // the two diverge when the runner's env has `XDG_CONFIG_HOME` set
        // (CI failure: opencode NotInstalled vs Wired). Hold a global lock
        // and force the unset/empty ⇒ `<home>/.config` fallback for both.
        let _lock = XDG_ENV_LOCK.lock().unwrap();
        let saved_xdg = std::env::var_os("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");

        let home = temp_home("installed");
        let results =
            run(&home, Path::new(&exe_marker()), Mode::Install, true).expect("init install");
        assert_eq!(results.len(), 8);

        // The exe marker alone makes exe-bearing hosts STALE (their commands
        // / generated docs embed the marker plus flags/suffixes != the bare
        // relocated path) — diagnose must agree with init's refresh
        // semantics. Antigravity's plugin document embeds the absolute exe,
        // so it staleness-checks like a JSON host.
        let wiring = diagnose_hosts(&home, None, Path::new("/real/path/apohara-agentguard"));
        for host in [
            "claude-code",
            "codex-code",
            "windsurf",
            "cursor",
            "antigravity",
        ] {
            assert_eq!(state_of(&wiring, host), &WiringState::Stale, "{host}");
        }
        for host in ["opencode", "kilo", "kitty-code"] {
            assert_eq!(state_of(&wiring, host), &WiringState::Wired, "{host}");
        }

        // Diagnosing with the EXACT marker string as exe ⇒ Wired everywhere
        // (flat entries compare against the FULL regenerated spawn line,
        // which matches what init wrote from the same exe).
        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        for host in [
            "claude-code",
            "codex-code",
            "windsurf",
            "cursor",
            "opencode",
            "kilo",
            "antigravity",
            "kitty-code",
        ] {
            assert_eq!(state_of(&wiring, host), &WiringState::Wired, "{host}");
        }
        let _ = std::fs::remove_dir_all(&home);

        match saved_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn corrupt_json_host_config_surfaces_as_corrupt() {
        let home = temp_home("corrupt");
        let dir = home.join(CLAUDE_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CLAUDE_FILE), b"{ not json").unwrap();

        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        match state_of(&wiring, "claude-code") {
            WiringState::Corrupt(reason) => {
                assert!(!reason.is_empty(), "the corrupt reason must carry detail");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
        // The OTHER host is unaffected.
        assert_eq!(state_of(&wiring, "codex-code"), &WiringState::NotInstalled);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn kitty_user_policy_is_reported_not_stale() {
        let home = temp_home("kitty-user");
        let dir = home.join(KITTY_DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(KITTY_POLICY_FILE_NAME), "# user policy\n").unwrap();

        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        assert_eq!(
            state_of(&wiring, "kitty-code"),
            &WiringState::UserPolicy,
            "a user-customized kitty policy is healthy, not stale"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn json_host_present_but_unwired_is_not_installed() {
        let home = temp_home("unwired-host");
        let dir = home.join(CLAUDE_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CLAUDE_FILE), r#"{"model":"opus"}"#).unwrap();

        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        assert_eq!(
            state_of(&wiring, "claude-code"),
            &WiringState::NotInstalled,
            "a host config without our marker is not-installed (from OUR perspective)"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn dropin_divergent_artifact_is_stale() {
        let home = temp_home("divergent-shim");
        let plugins = home.join(".config").join(OPENCODE_APP).join(PLUGINS_SUBDIR);
        std::fs::create_dir_all(&plugins).unwrap();
        std::fs::write(plugins.join(SHIM_FILE_NAME), "// hand-edited shim\n").unwrap();

        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        assert_eq!(state_of(&wiring, "opencode"), &WiringState::Stale);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn diagnose_respects_xdg_config_home() {
        let home = temp_home("xdg");
        let xdg = home.join("xdg-config");
        let plugins = xdg.join(OPENCODE_APP).join(PLUGINS_SUBDIR);
        std::fs::create_dir_all(&plugins).unwrap();
        std::fs::write(plugins.join(SHIM_FILE_NAME), OPENCODE_SHIM).unwrap();

        // With XDG set: opencode wired via the XDG path.
        let wiring = diagnose_hosts(&home, Some(xdg.as_os_str()), Path::new(&exe_marker()));
        assert_eq!(state_of(&wiring, "opencode"), &WiringState::Wired);

        // Without XDG: the same artifact is invisible ⇒ not installed.
        let wiring = diagnose_hosts(&home, None, Path::new(&exe_marker()));
        assert_eq!(state_of(&wiring, "opencode"), &WiringState::NotInstalled);
        let _ = std::fs::remove_dir_all(&home);
    }
}
