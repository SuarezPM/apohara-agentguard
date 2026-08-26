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

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

/// Substring identifying an apohara-agentguard-installed inner hook: any
/// inner hook whose `command` contains this marker is ours.
pub const MARKER: &str = "apohara-agentguard";

const CLAUDE_DIR: &str = ".claude";
const CLAUDE_FILE: &str = "settings.json";
const CODEX_DIR: &str = ".codex";
const CODEX_FILE: &str = "hooks.json";

// --- FASE 4 (v0.5.0) JSON-hook + drop-in hosts ------------------------------

/// `~/.codeium/windsurf/hooks.json` (user scope).
const WINDSURF_DIR: &str = ".codeium";
const WINDSURF_SUBDIR: &str = "windsurf";
/// `~/.cursor/hooks.json`.
const CURSOR_DIR: &str = ".cursor";
/// Antigravity plugin drop-in dir (we OWN this directory's hooks.json).
const ANTIGRAVITY_PLUGIN_DIR: &str = ".gemini/antigravity-cli/plugins/agentguard";
/// Config file name shared by the three FASE-4 hosts.
const HOOKS_JSON_FILE: &str = "hooks.json";

// --- Drop-in hosts (opencode / kilo / kitty-code) ---------------------------

const OPENCODE_APP: &str = "opencode";
const KILO_APP: &str = "kilo";
const PLUGINS_SUBDIR: &str = "plugins";
/// Reserved plugin filename in the OpenCode/Kilo `plugins/` drop-in dir.
pub const SHIM_FILE_NAME: &str = "agentguard-shim.mjs";
const KILO_GUIDE_FILE_NAME: &str = "agentguard-veto-guide.md";
const KITTY_DIR_NAME: &str = ".kitty-code";
const KITTY_POLICY_FILE_NAME: &str = "policy.toml";

/// Embedded OpenCode/Kilo plugin shim — single source of truth is
/// `packaging/opencode/agentguard-shim.mjs`; init copies it verbatim into
/// each host's `plugins/` directory.
pub const OPENCODE_SHIM: &str = include_str!("../packaging/opencode/agentguard-shim.mjs");

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
use crate::adapters::codex::{
    CODEX_DESCRIPTION, CODEX_PRE_TOOL_USE_MATCHER, HOOK_TIMEOUT, SPAWN_ARGS,
};

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
const CLAUDE_GROUPS: &[(&str, Option<&str>)] = &[
    (
        "PreToolUse",
        Some("Bash|Read|Write|Edit|WebFetch|WebSearch"),
    ),
    ("PostToolUse", Some("Bash")),
    ("UserPromptSubmit", None),
];
const CODEX_GROUPS: &[(&str, Option<&str>)] = &[("PreToolUse", Some(CODEX_PRE_TOOL_USE_MATCHER))];

/// Windsurf hook events (ASSUMPTION documented: the researched wire format
/// exposes these two pre-action events at user scope; entries are flat
/// `{command}` objects, so no matchers are written — a catch-all entry is the
/// tolerant shape and the gate itself decides what to evaluate).
const WINDSURF_GROUPS: &[(&str, Option<&str>)] =
    &[("pre_run_command", None), ("pre_mcp_tool_use", None)];

/// Cursor hook events (flat per-event command arrays; no matcher channel on
/// these two events in the researched format).
const CURSOR_GROUPS: &[(&str, Option<&str>)] =
    &[("beforeShellExecution", None), ("beforeMCPExecution", None)];

/// Antigravity is claude-like (`PreToolUse` + `{tool_name, tool_input}`), so
/// it gets the SAME matcher surface as the Claude wiring. ASSUMPTION: its
/// plugin `hooks.json` accepts the nested matcher-group document; if the
/// loader proves stricter, only [`antigravity_plugin_document`] needs to
/// change (the file is ours by exact content).
const ANTIGRAVITY_MATCHER: &str = "Bash|Read|Write|Edit|WebFetch|WebSearch";

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

struct HostSpec {
    host: &'static str,
    dir: PathBuf,
    file_name: &'static str,
    shape: WireShape,
    groups: &'static [(&'static str, Option<&'static str>)],
    /// `Some("windsurf")` etc. when the spawned command must carry
    /// `hook --harness <name>`; `None` for the legacy `hook`-only hosts.
    harness_arg: Option<&'static str>,
    sets_description: bool,
}

/// Where our inner-hook commands live inside a host's `hooks` document.
///
/// Both shapes coexist in the marker walkers (a document is scanned
/// shape-agnostically so a hand-mixed file can never hide our entries):
/// - [`WireShape::Groups`]: claude/codex nested matcher groups —
///   `hooks.<event>[].hooks[].command` holds the bare exe path.
/// - [`WireShape::Flat`]: windsurf/cursor flat per-event arrays —
///   `hooks.<event>[].command` holds the FULL spawn line
///   (`<exe> hook --harness <name>`), because those runners execute the
///   entry as one shell string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireShape {
    Groups,
    Flat,
}

struct HostPlan {
    /// The new document to write, if any (None = leave the file alone).
    new_value: Option<Value>,
    outcome: Outcome,
}

// --- Drop-in hosts (opencode / kilo / kitty-code) ---------------------------

/// One reserved-name artifact we manage by exact content equality. `content`
/// is a `Cow` because most artifacts are embedded constants, while the
/// antigravity plugin document is GENERATED from the current exe path.
#[derive(Clone)]
struct DropInFile {
    path: PathBuf,
    content: Cow<'static, str>,
}

/// The persistence plan for one drop-in host.
struct DropInPlan {
    host: &'static str,
    /// Path reported in CLI output (the host's primary artifact).
    report_path: PathBuf,
    /// Artifacts to write (install; empty on AlreadyWired / uninstall).
    writes: Vec<DropInFile>,
    /// Exact-match artifacts to remove (uninstall only).
    removes: Vec<DropInFile>,
    outcome: Outcome,
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

/// Plan one multi-artifact drop-in host (`opencode`, `kilo`).
///
/// Install: a missing artifact is written; an artifact that exists with
/// DIFFERENT content is our stale/divergent copy under OUR reserved filename
/// and is self-healed in place (mirrors the JSON hosts' Refreshed semantics).
/// Uninstall: ONLY exact-content artifacts are removed — a hand-edited
/// artifact is never deleted.
///
/// Outcome aggregation across the host's files: all exact ⇒ AlreadyWired;
/// anything missing ⇒ Wired (with `dir_created` from the plugins dir); else
/// (all exist, ≥1 divergent) ⇒ Refreshed.
fn plan_dropin_host(
    host: &'static str,
    anchor_dir: &Path,
    files: &[DropInFile],
    mode: Mode,
) -> Result<DropInPlan, InitError> {
    let report_path = files
        .first()
        .map(|f| f.path.clone())
        .unwrap_or_else(|| anchor_dir.to_path_buf());

    // One read per artifact; decisions derive from the recorded exactness.
    let mut writes = Vec::new();
    let mut removes = Vec::new();
    let mut missing_any = false;
    let mut divergent = 0usize;
    let mut all_exact = true;

    for file in files {
        match read_exact(&file.path, &file.content)? {
            Exactness::Exact => {
                if mode == Mode::Uninstall {
                    removes.push(DropInFile {
                        path: file.path.clone(),
                        content: file.content.clone(),
                    });
                }
            }
            Exactness::Divergent => {
                all_exact = false;
                divergent += 1;
                if mode == Mode::Install {
                    // Our stale/divergent copy under OUR reserved filename:
                    // self-heal in place.
                    writes.push(DropInFile {
                        path: file.path.clone(),
                        content: file.content.clone(),
                    });
                } // uninstall: never delete a hand-edited artifact
            }
            Exactness::Missing => {
                all_exact = false;
                missing_any = true;
                if mode == Mode::Install {
                    writes.push(DropInFile {
                        path: file.path.clone(),
                        content: file.content.clone(),
                    });
                }
            }
        }
    }

    let outcome = match mode {
        Mode::Install => {
            if all_exact {
                Outcome::AlreadyWired
            } else if missing_any {
                Outcome::Wired {
                    dir_created: !anchor_dir.is_dir(),
                }
            } else {
                Outcome::Refreshed { updated: divergent }
            }
        }
        Mode::Uninstall if removes.is_empty() => Outcome::NothingToUnwire,
        Mode::Uninstall => Outcome::Unwired {
            removed: removes.len(),
        },
    };

    Ok(DropInPlan {
        host,
        report_path,
        writes,
        removes,
        outcome,
    })
}

/// Plan the kitty-code host: DETECTION + SCAFFOLD only (the engine embeds via
/// library there).
///
/// Install: write [`KITTY_SCAFFOLD`] ONLY when `policy.toml` is absent; an
/// existing non-scaffold file is user policy and is reported as
/// [`Outcome::DetectedExisting`] untouched. Uninstall: remove ONLY when the
/// content equals our scaffold exactly.
fn plan_kitty_host(base_home: &Path, mode: Mode) -> Result<DropInPlan, InitError> {
    let dir = base_home.join(KITTY_DIR_NAME);
    let path = dir.join(KITTY_POLICY_FILE_NAME);
    let outcome = match mode {
        Mode::Install => match read_exact(&path, KITTY_SCAFFOLD)? {
            Exactness::Exact => Outcome::AlreadyWired,
            Exactness::Divergent => Outcome::DetectedExisting,
            Exactness::Missing => Outcome::Scaffolded {
                dir_created: !dir.is_dir(),
            },
        },
        Mode::Uninstall => {
            if exact_match(&path, KITTY_SCAFFOLD)? {
                Outcome::Unwired { removed: 1 }
            } else {
                Outcome::NothingToUnwire
            }
        }
    };
    let writes = if mode == Mode::Install && matches!(outcome, Outcome::Scaffolded { .. }) {
        vec![DropInFile {
            path: path.clone(),
            content: Cow::Borrowed(KITTY_SCAFFOLD),
        }]
    } else {
        Vec::new()
    };
    let removes = match &outcome {
        Outcome::Unwired { .. } => vec![DropInFile {
            path: path.clone(),
            content: Cow::Borrowed(KITTY_SCAFFOLD),
        }],
        _ => Vec::new(),
    };
    Ok(DropInPlan {
        host: "kitty-code",
        report_path: path,
        writes,
        removes,
        outcome,
    })
}

enum Exactness {
    Missing,
    Exact,
    Divergent,
}

fn read_exact(path: &Path, ours: &str) -> Result<Exactness, InitError> {
    match std::fs::read(path) {
        Ok(bytes) if bytes == ours.as_bytes() => Ok(Exactness::Exact),
        Ok(_) => Ok(Exactness::Divergent),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Exactness::Missing),
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

fn exact_match(path: &Path, ours: &str) -> Result<bool, InitError> {
    Ok(matches!(read_exact(path, ours)?, Exactness::Exact))
}

fn plan_host(spec: &HostSpec, exe: &Path, mode: Mode) -> Result<HostPlan, InitError> {
    let path = spec.dir.join(spec.file_name);
    let dir_existed = spec.dir.is_dir();

    let root = match std::fs::read(&path) {
        Ok(bytes) => Some(parse_config(&path, &bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(InitError::Io { path, source: e }),
    };

    match mode {
        Mode::Install => {
            if let Some(mut root) = root {
                if is_wired(&root) {
                    // Marker present. AlreadyWired ONLY when every
                    // marker-matched entry already equals what the current
                    // exe expects (nested: bare exe; flat: full spawn line);
                    // otherwise the wiring points at a stale/relocated binary
                    // (silent protection loss) and is refreshed IN PLACE.
                    let exe_str = exe.to_string_lossy().into_owned();
                    let stale = marker_sites(&root).iter().any(|(is_flat, cmd)| {
                        *cmd != expected_command(*is_flat, &exe_str, spec.harness_arg)
                    });
                    if !stale {
                        return Ok(HostPlan {
                            new_value: None,
                            outcome: Outcome::AlreadyWired,
                        });
                    }
                    let updated = refresh_marker_commands(&mut root, &exe_str, spec.harness_arg);
                    return Ok(HostPlan {
                        new_value: Some(root),
                        outcome: Outcome::Refreshed { updated },
                    });
                }
                wire_host(
                    &mut root,
                    spec.groups,
                    exe,
                    spec.shape,
                    spec.harness_arg,
                    spec.sets_description,
                );
                return Ok(HostPlan {
                    new_value: Some(root),
                    outcome: Outcome::Wired {
                        dir_created: !dir_existed,
                    },
                });
            }
            let mut root = {
                let mut obj = Map::new();
                if spec.sets_description {
                    obj.insert("description".into(), json!(CODEX_DESCRIPTION));
                }
                obj.insert("hooks".into(), json!({}));
                Value::Object(obj)
            };
            wire_host(
                &mut root,
                spec.groups,
                exe,
                spec.shape,
                spec.harness_arg,
                spec.sets_description,
            );
            Ok(HostPlan {
                new_value: Some(root),
                outcome: Outcome::Wired {
                    dir_created: !dir_existed,
                },
            })
        }
        Mode::Uninstall => {
            let Some(mut root) = root else {
                return Ok(HostPlan {
                    new_value: None,
                    outcome: Outcome::NothingToUnwire,
                });
            };
            let removed = unwire_host(&mut root);
            // False-provenance guard: drop OUR stamped description, but never
            // a user-customized one.
            let description_removed = if spec.sets_description {
                remove_stamped_description(&mut root)
            } else {
                false
            };
            if removed == 0 && !description_removed {
                return Ok(HostPlan {
                    new_value: None,
                    outcome: Outcome::NothingToUnwire,
                });
            }
            Ok(HostPlan {
                new_value: Some(root),
                outcome: Outcome::Unwired { removed },
            })
        }
    }
}

/// Parse + shape-validate a host config. Anything unusable is a loud
/// [`InitError::CorruptConfig`] — never silently discarded, never repaired.
fn parse_config(path: &Path, bytes: &[u8]) -> Result<Value, InitError> {
    let bad = |reason: String| InitError::CorruptConfig {
        path: path.to_path_buf(),
        reason,
    };
    let root: Value =
        serde_json::from_slice(bytes).map_err(|e| bad(format!("invalid JSON: {e}")))?;
    if !root.is_object() {
        return Err(bad("not a JSON object".into()));
    }
    if let Some(hooks) = root.get("hooks") {
        let Some(hooks_obj) = hooks.as_object() else {
            return Err(bad("\"hooks\" is not a JSON object".into()));
        };
        for (event, val) in hooks_obj {
            if !val.is_array() {
                return Err(bad(format!("\"hooks.{event}\" is not a JSON array")));
            }
        }
    }
    Ok(root)
}

/// True when any inner hook's `command` carries our marker.
fn is_wired(root: &Value) -> bool {
    !marker_sites(root).is_empty()
}

/// Every `(is_flat, command)` pair carried by a marker-matched entry of ours,
/// scanning BOTH document shapes:
/// - nested matcher group: `hooks.<event>[].hooks[].command` (claude/codex);
/// - flat per-event entry: `hooks.<event>[].command` (windsurf/cursor).
///
/// A group item is recognized by carrying a `hooks` array; anything else with
/// a string `command` is treated as a flat entry. Non-conforming shapes
/// contribute nothing.
fn marker_sites(root: &Value) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let Some(hooks) = root.get("hooks").and_then(Value::as_object) else {
        return out;
    };
    for event_val in hooks.values() {
        let Some(arr) = event_val.as_array() else {
            continue;
        };
        for item in arr {
            if let Some(inner) = item.get("hooks").and_then(Value::as_array) {
                for h in inner {
                    if let Some(c) = h.get("command").and_then(Value::as_str) {
                        if c.contains(MARKER) {
                            out.push((false, c));
                        }
                    }
                }
            } else if let Some(c) = item.get("command").and_then(Value::as_str) {
                if c.contains(MARKER) {
                    out.push((true, c));
                }
            }
        }
    }
    out
}

/// The full spawn line for one FLAT entry (`windsurf` / `cursor`): those
/// runners execute the entry as ONE shell string, so the harness flag rides
/// inside it. The exe path is shell-quoted when needed so spaces cannot split
/// the invocation.
fn flat_command_line(exe: &str, harness: &str) -> String {
    format!("{} hook --harness {}", quote_shell_token(exe), harness)
}

/// POSIX sh single-quote-when-needed wrapper. Paths made of common safe
/// characters stay verbatim (the overwhelmingly common case), everything else
/// gets the classic `'\''` escape — deterministic both at write and at
/// staleness-comparison time.
fn quote_shell_token(s: &str) -> String {
    let safe = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+'));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The command string one of OUR entries must carry right now: bare exe for
/// nested-group entries (args live in the sibling `args` field), the full
/// quoted spawn line for flat entries.
fn expected_command(is_flat: bool, exe_str: &str, harness: Option<&str>) -> String {
    match (is_flat, harness) {
        (true, Some(h)) => flat_command_line(exe_str, h),
        _ => exe_str.to_string(),
    }
}

/// Rewrite every marker-matched entry IN PLACE to what the CURRENT exe
/// expects (args / timeout / matchers / user hooks untouched). Returns how
/// many entries were rewritten.
fn refresh_marker_commands(root: &mut Value, exe: &str, harness: Option<&str>) -> usize {
    let Some(hooks) = root
        .as_object_mut()
        .and_then(|o| o.get_mut("hooks"))
        .and_then(Value::as_object_mut)
    else {
        return 0;
    };
    let mut updated = 0;
    for event_val in hooks.values_mut() {
        let Some(arr) = event_val.as_array_mut() else {
            continue;
        };
        for item in arr.iter_mut() {
            if let Some(inner) = item.get_mut("hooks").and_then(Value::as_array_mut) {
                // Nested group: command holds the bare exe.
                for h in inner.iter_mut() {
                    let is_ours = h
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.contains(MARKER));
                    if is_ours {
                        if let Some(Value::String(cmd)) = h.get_mut("command") {
                            *cmd = exe.to_string();
                            updated += 1;
                        }
                    }
                }
            } else {
                // Flat entry: command holds the full spawn line.
                let is_ours = item
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains(MARKER));
                if is_ours {
                    let fresh = expected_command(true, exe, harness);
                    if let Some(Value::String(cmd)) = item.get_mut("command") {
                        *cmd = fresh;
                        updated += 1;
                    }
                }
            }
        }
    }
    updated
}

/// Remove the top-level `description` key ONLY when it equals our stamped
/// text exactly (a user-customized description is never touched). Returns
/// whether it was removed.
fn remove_stamped_description(root: &mut Value) -> bool {
    let Some(obj) = root.as_object_mut() else {
        return false;
    };
    if obj.get("description").and_then(Value::as_str) != Some(CODEX_DESCRIPTION) {
        return false;
    }
    obj.remove("description").is_some()
}

/// Append our event entries to the existing `hooks` table (get-or-create at
/// every level; existing user content is never touched). The entry SHAPE
/// follows [`WireShape`]: nested matcher groups for claude/codex, flat
/// per-event command objects for windsurf/cursor.
fn wire_host(
    root: &mut Value,
    groups: &[(&str, Option<&str>)],
    exe: &Path,
    shape: WireShape,
    harness_arg: Option<&'static str>,
    set_description_if_absent: bool,
) {
    let exe_str = exe.to_string_lossy().into_owned();
    let obj = root.as_object_mut().expect("root validated as object");
    if set_description_if_absent && !obj.contains_key("description") {
        obj.insert("description".into(), json!(CODEX_DESCRIPTION));
    }
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    let hooks_obj = hooks.as_object_mut().expect("hooks validated as object");
    for (event, matcher) in groups {
        let arr = hooks_obj
            .entry((*event).to_string())
            .or_insert_with(|| json!([]));
        let entry = match shape {
            WireShape::Groups => hook_group(*matcher, &exe_str),
            WireShape::Flat => flat_hook_entry(&exe_str, harness_arg),
        };
        arr.as_array_mut()
            .expect("event value validated as array")
            .push(entry);
    }
}

/// One nested matcher-group entry: `{"matcher": ..., "hooks": [inner]}` with
/// the canonical spawn envelope (`args`/`timeout` siblings).
fn hook_group(matcher: Option<&str>, exe: &str) -> Value {
    let mut group = Map::new();
    if let Some(m) = matcher {
        group.insert("matcher".into(), json!(m));
    }
    group.insert(
        "hooks".into(),
        json!([{
            "type": "command",
            "command": exe,
            "args": SPAWN_ARGS,
            "timeout": HOOK_TIMEOUT,
        }]),
    );
    Value::Object(group)
}

/// One FLAT per-event entry (`windsurf` / `cursor`): a single shell-string
/// `command` carrying `hook --harness <name>`, plus the shared timeout.
fn flat_hook_entry(exe: &str, harness: Option<&str>) -> Value {
    let line = match harness {
        Some(h) => flat_command_line(exe, h),
        // Defensive: a flat entry without a harness arg degrades to the bare
        // legacy invocation rather than to a malformed line.
        None => quote_shell_token(exe),
    };
    json!({
        "command": line,
        "timeout": HOOK_TIMEOUT,
    })
}

/// Remove every marker-matched entry across BOTH shapes: nested inner hooks
/// and flat per-event command objects. Prunes groups whose inner `hooks`
/// array became empty and event keys whose arrays became empty. Returns the
/// number of entries removed. Everything else is left untouched.
fn unwire_host(root: &mut Value) -> usize {
    let mut removed = 0;
    let Some(obj) = root.as_object_mut() else {
        return 0;
    };
    let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) else {
        return 0;
    };
    let event_keys: Vec<String> = hooks.keys().cloned().collect();
    for event in event_keys {
        let Some(arr) = hooks.get_mut(&event).and_then(Value::as_array_mut) else {
            continue;
        };
        arr.retain_mut(|item| {
            if let Some(inner) = item.get_mut("hooks").and_then(Value::as_array_mut) {
                // Nested matcher group.
                let before = inner.len();
                inner.retain(|h| {
                    !h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.contains(MARKER))
                });
                removed += before - inner.len();
                !inner.is_empty()
            } else if item
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|c| c.contains(MARKER))
            {
                // Flat entry that is ours.
                removed += 1;
                false
            } else {
                true // non-conforming / user entry: leave untouched
            }
        });
        if arr.is_empty() {
            hooks.remove(&event);
        }
    }
    removed
}

/// Pretty-print (2-space, trailing newline) and write ATOMICALLY via
/// [`atomic_write`].
fn write_config(path: &Path, value: &Value) -> Result<(), InitError> {
    // serde_json serialization of a Value cannot fail.
    let mut out = serde_json::to_string_pretty(value).expect("Value serialization is infallible");
    out.push('\n');
    atomic_write(path, out.as_bytes())
}

// ---- Doctor surface: observed wiring state per host (read-only) ------------

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

/// Write `payload` to `path` ATOMICALLY, creating parent dirs: the payload
/// goes to a unique sibling temp file in the SAME directory, then
/// `fs::rename` over the destination (atomic on POSIX; replaces the
/// destination on Windows). A crash mid-write can never leave a torn file
/// behind. On any failure after temp creation the temp file is removed
/// best-effort before returning. Shared by the JSON-hook hosts and the
/// drop-in hosts.
fn atomic_write(path: &Path, payload: &[u8]) -> Result<(), InitError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InitError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let file_name = path.file_name().map_or_else(
        || CLAUDE_FILE.to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = path.with_file_name(format!("{file_name}.agentguard-tmp-{}", std::process::id()));

    let result = (|| {
        std::fs::write(&tmp, payload).map_err(|e| InitError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| InitError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp); // best-effort cleanup
    }
    result
}

#[cfg(test)]
mod doctor_surface_tests {
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
