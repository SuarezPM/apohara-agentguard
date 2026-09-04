//! Inbound path (child → client): upstream response handling, TOFU pin
//! verdicts, drift application, and synthesized quarantine/error responses.

use std::sync::mpsc;

use serde_json::Value;

use super::{DriftGranularity, PinGate, RelayMode, Shared};
use crate::proxy::pinning::PinVerdict;
use crate::proxy::spoof::{classify_response_id, splice_span, top_level_id_span, IdSpan};

const OVERLOAD_CODE: i64 = -32002;

pub(super) fn overloaded_response(id: &Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": OVERLOAD_CODE,
            "message": "agentguard-proxy overloaded: too many in-flight proxied requests"
        }
    })
    .to_string()
}

/// Classify + act on one line arriving FROM THE UPSTREAM.
///
/// Returns `Some(fatal)` for fail-closed protocol violations. Response lines
/// whose id does not sit EXACTLY in the pending table (unknown, replayed,
/// foreign-format) are silently-dropped-with-warning — never forwarded.
pub(super) fn handle_upstream_line(
    line: &str,
    pin_gate: &mut PinGate,
    shared: &Shared,
    tx_out: &mpsc::Sender<String>,
) -> Option<String> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(format!(
                "non-JSON line from upstream ({e}): {}",
                truncate_for_log(line)
            ))
        }
    };

    // Server-initiated messages (notifications AND server→client requests):
    // they never answer a proxied request and never touch the id table.
    if msg.get("method").is_some() {
        // Manifest-generation invalidation.
        if msg.get("method").and_then(Value::as_str) == Some("notifications/tools/list_changed") {
            pin_gate.on_list_changed();
            eprintln!(
                "agentguard-proxy: tools/list_changed — pin will re-verify on next tools/list"
            );
        }
        let _ = tx_out.send(line.to_string());
        return None;
    }

    // Response-shaped (result or error present)?
    if msg.get("result").is_some() || msg.get("error").is_some() {
        let proxy_id = match classify_response_id(&msg) {
            Ok(Some(pid)) => pid,
            Ok(None) => {
                // A result/error without any id cannot be correlated to a
                // proxied request: fail-closed drop.
                eprintln!(
                    "agentguard-proxy: DROPPED upstream result/error without id (anti-spoofing)"
                );
                return None;
            }
            Err(reason) => {
                eprintln!(
                    "agentguard-proxy: DROPPED upstream response ({reason}): {}",
                    truncate_for_log(line)
                );
                return None;
            }
        };

        let resolved = shared.ids.lock().expect("id mutex").resolve(&proxy_id);
        let Some(entry) = resolved else {
            let label = if shared
                .ids
                .lock()
                .expect("id mutex")
                .recently_consumed(&proxy_id)
            {
                "REPLAYED (already answered)"
            } else {
                "UNKNOWN (never minted)"
            };
            eprintln!("agentguard-proxy: DROPPED upstream response — id {proxy_id} is {label}");
            return None;
        };

        // Locate the id span ON THE RESPONSE LINE for restoration. The parse
        // above guarantees an id exists, so only ambiguity can bite here —
        // and ambiguity fails the session rather than guessing.
        let span = match top_level_id_span(line) {
            IdSpan::Found(s, e) => (s, e),
            other => {
                return Some(format!(
                    "unrestorable upstream response id (span={other:?}): {}",
                    truncate_for_log(line)
                ))
            }
        };

        // tools/list RESULT goes through the pin pipeline.
        if entry.is_tools_list && msg.get("result").is_some() {
            let verdict = pin_gate.on_list_response(msg.get("result").expect("checked"));
            if verdict.is_quarantine() {
                // Tool-granularity drift: only a Mismatch carries per-tool
                // attribution. Other quarantine grades (preseed mismatch,
                // unusable store) have no tool to blame → session handling.
                if shared.granularity == DriftGranularity::Tool {
                    if let PinVerdict::Mismatch {
                        changes,
                        collisions,
                        ..
                    } = &verdict
                    {
                        // Remediation B3: outputSchema-only drift yields an
                        // EMPTY attribution (`tools_hash` includes
                        // outputSchema but the per-tool descriptor hash
                        // deliberately excludes it). Tool-granularity would
                        // strip nothing and block nobody — silently
                        // re-forwarding the drifted manifest. When there is
                        // NO tool to blame, ESCALATE to the session-style
                        // handling below instead.
                        if !changes.is_empty() || !collisions.is_empty() {
                            return apply_tool_granularity_drift(
                                changes, collisions, line, span, &entry, shared, tx_out,
                            );
                        }
                    }
                }
                let reason = verdict.reason();
                // The mode decides between ACT (enforce: quarantine +
                // replace; filter-only: replace but keep calls flowing)
                // and LOG (audit-only: forward the manifest verbatim).
                return match shared.mode {
                    RelayMode::Enforce => {
                        eprintln!(
                            "agentguard-proxy: QUARANTINE: {} — blocking all further tools/call",
                            verdict.reason()
                        );
                        shared.quarantine(reason.clone());
                        let _ =
                            tx_out.send(quarantined_manifest_response(&entry.host_id_raw, &reason));
                        None
                    }
                    RelayMode::FilterOnly => {
                        eprintln!(
                            "agentguard-proxy: FILTERED (mode filter-only): {} — \
                             manifest filtered, tools/call NOT blocked",
                            verdict.reason()
                        );
                        let _ =
                            tx_out.send(quarantined_manifest_response(&entry.host_id_raw, &reason));
                        None
                    }
                    RelayMode::AuditOnly => {
                        eprintln!(
                            "agentguard-proxy: WOULD-FILTER (mode audit-only): {}",
                            verdict.reason()
                        );
                        // Nothing is filtered: the drifted manifest reaches
                        // the client with its ORIGINAL id, bytes otherwise
                        // untouched.
                        let _ = tx_out.send(splice_span(line, span, &entry.host_id_raw));
                        None
                    }
                };
            }
            eprintln!("agentguard-proxy: {}", verdict.reason());
        }

        // Verified / non-pin response: restore the HOST id and forward.
        let _ = tx_out.send(splice_span(line, span, &entry.host_id_raw));
        return None;
    }

    // Neither method-bearing nor response-bearing (e.g. bare junk object
    // that is valid JSON): forwards, as today.
    let _ = tx_out.send(line.to_string());
    None
}

/// Tool-granularity drift handling (`--drift-granularity tool`): the
/// affected tools are stripped from the manifest before it reaches the
/// client, their future calls are blocked (mode-dependent), and the SESSION
/// keeps flowing — the quarantine-on-drift default stays untouched.
///
/// Callers must NOT dispatch here with an EMPTY attribution (no changes, no
/// collisions): that shape means outputSchema-only drift (remediation B3) and
/// escalates to session-style handling instead of a silent no-op.
///
/// The store is NOT updated (the honest baseline is preserved), matching the
/// session-granularity mismatch semantics.
fn apply_tool_granularity_drift(
    changes: &[crate::proxy::pinning::ToolChange],
    collisions: &[crate::proxy::pinning::NameCollision],
    line: &str,
    span: (usize, usize),
    entry: &crate::proxy::spoof::PendingEntry,
    shared: &Shared,
    tx_out: &mpsc::Sender<String>,
) -> Option<String> {
    // Affected tool name → operator-facing why.
    let mut affected: std::collections::BTreeMap<String, String> = changes
        .iter()
        .map(|c| (c.name().to_string(), c.describe()))
        .collect();
    for c in collisions {
        affected.insert(
            c.incoming.clone(),
            format!(
                "NAME COLLISION — folds like pinned tool `{}` (possible visual spoofing)",
                c.known
            ),
        );
    }

    {
        let mut blocked = shared.blocked_tools.lock().expect("blocked-tools mutex");
        for (name, why) in &affected {
            blocked.entry(name.clone()).or_insert_with(|| why.clone());
        }
    }
    for (name, why) in &affected {
        eprintln!("agentguard-proxy: DRIFT-TOOL: `{name}` — {why}");
    }

    match shared.mode {
        RelayMode::AuditOnly => {
            eprintln!(
                "agentguard-proxy: WOULD-FILTER (mode audit-only): {} drifted/colliding tool(s) would be stripped",
                affected.len()
            );
            // Nothing filtered: forward verbatim (host id restored).
            let _ = tx_out.send(splice_span(line, span, &entry.host_id_raw));
            None
        }
        _ => {
            // Enforce AND filter-only both FILTER the list; only the call
            // blocking differs, and that lives on the request side.
            let msg: Value = serde_json::from_str(line).expect("parsed by caller moments ago");
            let mut result = msg.get("result").cloned().unwrap_or(Value::Null);
            if let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) {
                tools.retain(|t| {
                    t.get("name")
                        .and_then(Value::as_str)
                        .is_none_or(|n| !affected.contains_key(n))
                });
            }
            if let Some(obj) = result.as_object_mut() {
                obj.insert(
                    "quarantined_tools".to_string(),
                    Value::Array(affected.keys().map(|n| Value::String(n.clone())).collect()),
                );
            }
            let tpl = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "result": result,
            })
            .to_string();
            let out = match top_level_id_span(&tpl) {
                IdSpan::Found(s, e) => splice_span(&tpl, (s, e), &entry.host_id_raw),
                _ => tpl,
            };
            let _ = tx_out.send(out);
            None
        }
    }
}

/// Build the replacement tools/list response the relay sends INSTEAD of a
/// quarantine-grade manifest: an empty tool list flagged `quarantined` with
/// the neutralized reason. `host_id_raw` (the client's original id BYTES) is
/// spliced in so even exotic id shapes survive the replacement intact.
fn quarantined_manifest_response(host_id_raw: &str, reason: &str) -> String {
    let tpl = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "tools": [],
            "quarantined": true,
            "reason": crate::neutralize_reason(reason),
        }
    })
    .to_string();
    match top_level_id_span(&tpl) {
        IdSpan::Found(s, e) => splice_span(&tpl, (s, e), host_id_raw),
        _ => tpl, // unreachable: the template always carries "id": 0
    }
}

/// Cap hostile/garbage payload excerpts in stderr diagnostics.
pub(super) fn truncate_for_log(line: &str) -> String {
    const CAP: usize = 200;
    if line.len() <= CAP {
        return line.to_string();
    }
    let mut end = CAP;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &line[..end])
}
