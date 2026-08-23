//! `agentguard init` — wire the apohara-agentguard hook into detected agent
//! host configurations (Claude Code, OpenAI Codex).
//!
//! The library core is hermetic: every entry point takes an explicit
//! `base_home` (the user home directory) so tests can operate on a tempdir.
//! The CLI wrapper (`src/main.rs`) resolves the real home directory and the
//! currently-running binary.
//!
//! Integrity contract:
//! - APPEND-ONLY: existing user hooks are never clobbered or reordered; our
//!   matcher groups are appended to the existing event arrays.
//! - IDEMPOTENT + SELF-HEALING: a prior install is detected by scanning every
//!   inner hook's `command` for the binary-name marker. If the wiring already
//!   points at exactly the current executable, a re-run reports "already
//!   wired"; if it points at a stale/relocated path, those entries' `command`
//!   fields are refreshed IN PLACE (no duplicates, user content untouched).
//! - CORRUPT-REFUSAL: a target file that exists but is not valid JSON (or is
//!   not a JSON object / has a malformed `hooks` table) aborts the whole
//!   operation BEFORE any file is modified — both hosts are parsed up-front,
//!   so a corrupt config on one host never leaves the other half-wired. (An
//!   I/O failure during persistence can still leave an earlier host written;
//!   each single write is atomic, cross-host is not transactional.)
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

/// `description` stamped into a Codex `hooks.json` we create (Codex has no
/// equivalent top-level description on Claude settings.json).
pub const CODEX_DESCRIPTION: &str = "Installed by apohara-agentguard init";

/// Per-hook timeout (seconds), matching `packaging/hooks.json`.
const HOOK_TIMEOUT: i64 = 20;

/// Event groups wired per host: `(event key, matcher)`. A `None` matcher is
/// omitted (Claude Code's UserPromptSubmit takes no matcher). Codex stays
/// minimal PreToolUse-only (no PostToolUse/UserPromptSubmit semantics).
const CLAUDE_GROUPS: &[(&str, Option<&str>)] = &[
    (
        "PreToolUse",
        Some("Bash|Read|Write|Edit|WebFetch|WebSearch"),
    ),
    ("PostToolUse", Some("Bash")),
    ("UserPromptSubmit", None),
];
const CODEX_GROUPS: &[(&str, Option<&str>)] =
    &[("PreToolUse", Some("Bash|apply_patch|Edit|Write"))];

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
    /// Host label used in CLI output (`claude-code` / `codex-code`).
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
}

/// Run init across both hosts against `base_home`.
///
/// `exe` is the absolute path of the binary to wire in (the CLI passes the
/// canonicalized `std::env::current_exe()`). With `apply = false` this is a
/// DRY-RUN: planned outcomes are computed and returned but nothing is
/// written. Both hosts are parsed BEFORE either is written, so a corrupt
/// config aborts with [`InitError::CorruptConfig`] and zero writes. That is
/// where atomicity ends: an I/O failure during the phase-2 persistence loop
/// can leave an EARLIER host already written — cross-host transactions are
/// impossible without a journal, and none is attempted. Each individual
/// file write IS atomic (sibling temp file + rename).
pub fn run(
    base_home: &Path,
    exe: &Path,
    mode: Mode,
    apply: bool,
) -> Result<Vec<HostResult>, InitError> {
    let specs = [
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

    // Phase 1 — parse + transform BOTH hosts. Any corrupt config errors out
    // here, before a single byte is written anywhere.
    let plans: Vec<HostPlan> = specs
        .iter()
        .map(|s| plan_host(s, exe, mode))
        .collect::<Result<_, _>>()?;

    // Phase 2 — persist.
    let mut results = Vec::with_capacity(specs.len());
    for (spec, plan) in specs.iter().zip(plans) {
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
            "args": ["hook"],
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

/// Pretty-print (2-space, trailing newline) and write ATOMICALLY, creating
/// parent dirs: the payload goes to a unique sibling temp file in the SAME
/// directory, then `fs::rename` over the destination (atomic on POSIX;
/// replaces the destination on Windows). A crash mid-write can never leave
/// a torn config behind. On any failure after temp creation the temp file
/// is removed best-effort before returning.
fn write_config(path: &Path, value: &Value) -> Result<(), InitError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InitError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    // serde_json serialization of a Value cannot fail.
    let mut out = serde_json::to_string_pretty(value).expect("Value serialization is infallible");
    out.push('\n');

    let file_name = path.file_name().map_or_else(
        || CLAUDE_FILE.to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = path.with_file_name(format!("{file_name}.agentguard-tmp-{}", std::process::id()));

    let result = (|| {
        std::fs::write(&tmp, out.as_bytes()).map_err(|e| InitError::Io {
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
