//! Marker-scanning and document-mutation primitives for JSON-hook hosts,
//! plus the atomic write shared by every host family.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::plan::WireShape;
use super::tables::{CLAUDE_FILE, MARKER};
use super::InitError;
use crate::adapters::codex::{CODEX_DESCRIPTION, HOOK_TIMEOUT, SPAWN_ARGS};

/// True when any inner hook's `command` carries our marker.
pub(super) fn is_wired(root: &Value) -> bool {
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
pub(super) fn marker_sites(root: &Value) -> Vec<(bool, &str)> {
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
pub(super) fn expected_command(is_flat: bool, exe_str: &str, harness: Option<&str>) -> String {
    match (is_flat, harness) {
        (true, Some(h)) => flat_command_line(exe_str, h),
        _ => exe_str.to_string(),
    }
}

/// Rewrite every marker-matched entry IN PLACE to what the CURRENT exe
/// expects (args / timeout / matchers / user hooks untouched). Returns how
/// many entries were rewritten.
pub(super) fn refresh_marker_commands(root: &mut Value, exe: &str, harness: Option<&str>) -> usize {
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
pub(super) fn remove_stamped_description(root: &mut Value) -> bool {
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
pub(super) fn wire_host(
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
pub(super) fn unwire_host(root: &mut Value) -> usize {
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
pub(super) fn write_config(path: &Path, value: &Value) -> Result<(), InitError> {
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
pub(super) fn atomic_write(path: &Path, payload: &[u8]) -> Result<(), InitError> {
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
