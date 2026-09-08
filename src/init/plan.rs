//! Up-front planning for `init`: JSON-hook hosts and drop-in hosts.
//! Every host is planned BEFORE anything is written so a corrupt config
//! aborts with zero writes (the integrity contract in `mod.rs`).

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::tables::{KITTY_DIR_NAME, KITTY_POLICY_FILE_NAME, KITTY_SCAFFOLD};
use super::wire::{
    expected_command, is_wired, marker_sites, refresh_marker_commands, remove_stamped_description,
    unwire_host, wire_host,
};
use super::{InitError, Mode, Outcome};
use crate::adapters::codex::CODEX_DESCRIPTION;

pub(super) struct HostSpec {
    pub(super) host: &'static str,
    pub(super) dir: PathBuf,
    pub(super) file_name: &'static str,
    pub(super) shape: WireShape,
    pub(super) groups: &'static [(&'static str, Option<&'static str>)],
    /// `Some("windsurf")` etc. when the spawned command must carry
    /// `hook --harness <name>`; `None` for the legacy `hook`-only hosts.
    pub(super) harness_arg: Option<&'static str>,
    pub(super) sets_description: bool,
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
pub(super) enum WireShape {
    Groups,
    Flat,
}

pub(super) struct HostPlan {
    /// The new document to write, if any (None = leave the file alone).
    pub(super) new_value: Option<Value>,
    pub(super) outcome: Outcome,
}

// --- Drop-in hosts (opencode / kilo / kitty-code) ---------------------------

/// One reserved-name artifact we manage by exact content equality. `content`
/// is a `Cow` because most artifacts are embedded constants, while the
/// antigravity plugin document is GENERATED from the current exe path.
#[derive(Clone)]
pub(super) struct DropInFile {
    pub(super) path: PathBuf,
    pub(super) content: Cow<'static, str>,
}

/// The persistence plan for one drop-in host.
pub(super) struct DropInPlan {
    pub(super) host: &'static str,
    /// Path reported in CLI output (the host's primary artifact).
    pub(super) report_path: PathBuf,
    /// Artifacts to write (install; empty on AlreadyWired / uninstall).
    pub(super) writes: Vec<DropInFile>,
    /// Exact-match artifacts to remove (uninstall only).
    pub(super) removes: Vec<DropInFile>,
    pub(super) outcome: Outcome,
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
pub(super) fn plan_dropin_host(
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
pub(super) fn plan_kitty_host(base_home: &Path, mode: Mode) -> Result<DropInPlan, InitError> {
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

pub(super) enum Exactness {
    Missing,
    Exact,
    Divergent,
}

pub(super) fn read_exact(path: &Path, ours: &str) -> Result<Exactness, InitError> {
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

pub(super) fn exact_match(path: &Path, ours: &str) -> Result<bool, InitError> {
    Ok(matches!(read_exact(path, ours)?, Exactness::Exact))
}

pub(super) fn plan_host(spec: &HostSpec, exe: &Path, mode: Mode) -> Result<HostPlan, InitError> {
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
pub(super) fn parse_config(path: &Path, bytes: &[u8]) -> Result<Value, InitError> {
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
