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

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

/// Substring identifying an apohara-agentguard-installed inner hook: any
/// inner hook whose `command` contains this marker is ours.
pub const MARKER: &str = "apohara-agentguard";

const CLAUDE_DIR: &str = ".claude";
const CLAUDE_FILE: &str = "settings.json";
const CODEX_DIR: &str = ".codex";
const CODEX_FILE: &str = "hooks.json";

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
            groups: CLAUDE_GROUPS,
            sets_description: false,
        },
        HostSpec {
            host: "codex-code",
            dir: base_home.join(CODEX_DIR),
            file_name: CODEX_FILE,
            groups: CODEX_GROUPS,
            sets_description: true,
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
    let dropin_plans = [
        plan_dropin_host(
            "opencode",
            &opencode_plugins,
            &[DropInFile {
                path: opencode_plugins.join(SHIM_FILE_NAME),
                content: OPENCODE_SHIM,
            }],
            mode,
        )?,
        plan_dropin_host(
            "kilo",
            &kilo_plugins,
            &[
                DropInFile {
                    path: kilo_plugins.join(SHIM_FILE_NAME),
                    content: OPENCODE_SHIM,
                },
                DropInFile {
                    path: xdg_config_dir(base_home, xdg_config_home.as_deref(), KILO_APP)
                        .join(KILO_GUIDE_FILE_NAME),
                    content: kilo_guide,
                },
            ],
            mode,
        )?,
        plan_kitty_host(base_home, mode)?,
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
    groups: &'static [(&'static str, Option<&'static str>)],
    sets_description: bool,
}

struct HostPlan {
    /// The new document to write, if any (None = leave the file alone).
    new_value: Option<Value>,
    outcome: Outcome,
}

// --- Drop-in hosts (opencode / kilo / kitty-code) ---------------------------

/// One reserved-name artifact we manage by exact content equality.
struct DropInFile {
    path: PathBuf,
    content: &'static str,
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
        match read_exact(&file.path, file.content)? {
            Exactness::Exact => {
                if mode == Mode::Uninstall {
                    removes.push(DropInFile {
                        path: file.path.clone(),
                        content: file.content,
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
                        content: file.content,
                    });
                } // uninstall: never delete a hand-edited artifact
            }
            Exactness::Missing => {
                all_exact = false;
                missing_any = true;
                if mode == Mode::Install {
                    writes.push(DropInFile {
                        path: file.path.clone(),
                        content: file.content,
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
            content: KITTY_SCAFFOLD,
        }]
    } else {
        Vec::new()
    };
    let removes = match &outcome {
        Outcome::Unwired { .. } => vec![DropInFile {
            path: path.clone(),
            content: KITTY_SCAFFOLD,
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
                    // marker-matched command already equals the current exe;
                    // otherwise the wiring points at a stale/relocated binary
                    // (silent protection loss) and is refreshed IN PLACE.
                    let exe_str = exe.to_string_lossy().into_owned();
                    if marker_commands(&root).iter().all(|c| c == &exe_str) {
                        return Ok(HostPlan {
                            new_value: None,
                            outcome: Outcome::AlreadyWired,
                        });
                    }
                    let updated = refresh_marker_commands(&mut root, &exe_str);
                    return Ok(HostPlan {
                        new_value: Some(root),
                        outcome: Outcome::Refreshed { updated },
                    });
                }
                wire_host(&mut root, spec.groups, exe, spec.sets_description);
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
            wire_host(&mut root, spec.groups, exe, spec.sets_description);
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
    !marker_commands(root).is_empty()
}

/// The `command` strings of every marker-matched inner hook.
fn marker_commands(root: &Value) -> Vec<&str> {
    inner_hooks(root)
        .filter_map(|h| h.get("command").and_then(Value::as_str))
        .filter(|c| c.contains(MARKER))
        .collect()
}

/// Rewrite the `command` of every marker-matched inner hook IN PLACE to
/// `exe` (args / timeout / matchers / user hooks untouched). Returns how
/// many entries were rewritten.
fn refresh_marker_commands(root: &mut Value, exe: &str) -> usize {
    let Some(obj) = root.as_object_mut() else {
        return 0;
    };
    let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) else {
        return 0;
    };
    let mut updated = 0;
    for group_arr in hooks.values_mut() {
        let Some(arr) = group_arr.as_array_mut() else {
            continue;
        };
        for group in arr {
            let Some(inner) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                continue;
            };
            for h in inner {
                let is_ours = h
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains(MARKER));
                if !is_ours {
                    continue;
                }
                if let Some(Value::String(cmd)) = h.get_mut("command") {
                    *cmd = exe.to_string();
                    updated += 1;
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

/// Iterate every inner hook object across all event arrays under `"hooks"`.
/// Non-conforming shapes contribute nothing (they are left untouched by both
/// install and undo).
fn inner_hooks(root: &Value) -> impl Iterator<Item = &Value> {
    root.get("hooks")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|hooks| hooks.values())
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(|group| group.get("hooks"))
        .filter_map(Value::as_array)
        .flatten()
}

/// Append our matcher groups to the existing `hooks` table (get-or-create at
/// every level; existing user content is never touched).
fn wire_host(
    root: &mut Value,
    groups: &[(&str, Option<&str>)],
    exe: &Path,
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
        arr.as_array_mut()
            .expect("event value validated as array")
            .push(hook_group(*matcher, &exe_str));
    }
}

/// One matcher-group entry: `{"matcher": ..., "hooks": [inner]}`.
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

/// Remove every marker-matched inner hook; prune groups whose inner `hooks`
/// array became empty and event keys whose arrays became empty. Returns the
/// number of inner hooks removed. Everything else is left untouched.
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
        arr.retain_mut(|group| {
            let Some(inner) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true; // non-conforming group: leave untouched
            };
            let before = inner.len();
            inner.retain(|h| {
                !h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains(MARKER))
            });
            removed += before - inner.len();
            !inner.is_empty()
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
