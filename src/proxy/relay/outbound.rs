//! Outbound path (client → child): request gating and proxied-id forwarding.

use std::sync::atomic::Ordering;
use std::sync::mpsc;

use serde_json::Value;

use super::inbound::{overloaded_response, truncate_for_log};
use super::{RelayMode, Shared};
use crate::proxy::gate::{blocked_response, evaluate_tool_call, Gates};
use crate::proxy::spoof::{splice_span, top_level_id_span, IdSpan, RegisterError};

pub(super) fn handle_client_line(
    line: &str,
    shared: &Shared,
    tx_in: &mpsc::Sender<String>,
    tx_out: &mpsc::Sender<String>,
    gates: &Gates,
) -> Option<String> {
    // Blank lines are non-JSON: fail-closed, never silently skipped.
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(format!(
                "non-JSON line from client ({e}): {}",
                truncate_for_log(line)
            ))
        }
    };

    // Anti-spoofing span analysis happens BEFORE anything else: an ambiguous
    // (duplicated) top-level id makes parser-dependent behavior unavoidable,
    // which is exactly what a transport attacker wants — refuse the session.
    let id_span = top_level_id_span(line);
    if id_span == IdSpan::Ambiguous {
        return Some(format!(
            "ambiguous client line: duplicate top-level \"id\" member: {}",
            truncate_for_log(line)
        ));
    }
    // Old synthesized-response semantics preserved: a null id gets no reply.
    let has_replyable_id = matches!(msg.get("id"), Some(v) if !v.is_null());

    let method = msg.get("method").and_then(Value::as_str);

    if method == Some("tools/call") {
        // Session quarantine blocks ALL subsequent calls.
        if shared.quarantined.load(Ordering::SeqCst) {
            let reason = shared
                .quarantine_reason()
                .unwrap_or_else(|| "session quarantined".to_string());
            let text = format!("session quarantined: {reason}");
            eprintln!("agentguard-proxy: blocked quarantined tools/call: {text}");
            if has_replyable_id {
                let _ = tx_out.send(blocked_response(
                    msg.get("id").unwrap_or(&Value::Null),
                    &text,
                ));
            }
            return None;
        }

        // tools/call gating: tool-level drift blocks come first (they are a
        // pinning outcome), then policy/deep-check.
        let tool_name = msg
            .pointer("/params/name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if let Some(why) = shared.blocked_tool_reason(&tool_name) {
            return match shared.mode {
                RelayMode::Enforce => {
                    eprintln!("agentguard-proxy: BLOCKED tools/call `{tool_name}`: {why}");
                    if has_replyable_id {
                        let _ = tx_out.send(blocked_response(
                            msg.get("id").unwrap_or(&Value::Null),
                            &format!("tool blocked by agentguard: {why}"),
                        ));
                    }
                    None
                }
                mode => {
                    eprintln!(
                        "agentguard-proxy: WOULD-BLOCK (mode {}) tools/call `{tool_name}`: {why}",
                        mode.as_str()
                    );
                    forward_with_proxied_id(
                        line,
                        id_span,
                        msg.get("id").unwrap_or(&Value::Null),
                        false,
                        shared,
                        tx_in,
                        tx_out,
                    )
                }
            };
        }
        let args = msg
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or(Value::Null);
        let decision = evaluate_tool_call(&tool_name, &args, gates);
        if decision.allowed {
            return forward_with_proxied_id(
                line,
                id_span,
                msg.get("id").unwrap_or(&Value::Null),
                false,
                shared,
                tx_in,
                tx_out,
            );
        }
        // Negative decision: the mode decides between ACT (synthesize the
        // blocked response, never forward) and LOG (forward + loud
        // would-block on stderr).
        return match shared.mode {
            RelayMode::Enforce => {
                eprintln!(
                    "agentguard-proxy: BLOCKED tools/call `{tool_name}`: {}",
                    decision.reason
                );
                if has_replyable_id {
                    let _ = tx_out.send(blocked_response(
                        msg.get("id").unwrap_or(&Value::Null),
                        &decision.reason,
                    ));
                }
                None
            }
            mode => {
                eprintln!(
                    "agentguard-proxy: WOULD-BLOCK (mode {}) tools/call `{tool_name}`: {}",
                    mode.as_str(),
                    decision.reason
                );
                forward_with_proxied_id(
                    line,
                    id_span,
                    msg.get("id").unwrap_or(&Value::Null),
                    false,
                    shared,
                    tx_in,
                    tx_out,
                )
            }
        };
    }

    // Client→server RESPONSE (result/error WITHOUT a method): this answers a
    // SERVER-initiated request (sampling/createMessage, roots/list,
    // elicitation/create). The anti-spoofing table only maps ids the RELAY
    // minted on client→upstream requests, so there is nothing to restore:
    // splice VERBATIM like notifications (remediation B2). Re-minting here
    // would sever the upstream's correlation (silent hang) AND register a
    // pending entry that can never resolve — enough of them saturate the
    // table into spurious -32002s on legitimate traffic. The anti-spoofing
    // gate protects upstream→client; this direction does not need it.
    if method.is_none() && (msg.get("result").is_some() || msg.get("error").is_some()) {
        let _ = tx_in.send(line.to_string());
        return None;
    }

    // Everything else forwards — with its id re-minted if it is a request.
    forward_with_proxied_id(
        line,
        id_span,
        msg.get("id").unwrap_or(&Value::Null),
        method == Some("tools/list"),
        shared,
        tx_in,
        tx_out,
    )
}

/// Forward one client line upstream through the anti-spoofing gate: a
/// request WITH an id gets a relay-minted opaque id (raw span spliced);
/// notifications pass byte-identical. Registration failures degrade to a
/// locally-synthesized answer (-32002 overloaded / fail-closed RNG denial)
/// and NEVER forward.
pub(super) fn forward_with_proxied_id(
    line: &str,
    id_span: IdSpan,
    host_id_value: &Value,
    is_tools_list: bool,
    shared: &Shared,
    tx_in: &mpsc::Sender<String>,
    tx_out: &mpsc::Sender<String>,
) -> Option<String> {
    let span = match id_span {
        // Notification (no id member): nothing to protect, forward verbatim.
        IdSpan::Absent => {
            let _ = tx_in.send(line.to_string());
            return None;
        }
        // Callers pre-filter this; kept exhaustive for safety.
        IdSpan::Ambiguous => {
            return Some(format!(
                "ambiguous client line: duplicate top-level \"id\" member: {}",
                truncate_for_log(line)
            ))
        }
        IdSpan::Found(s, e) => (s, e),
    };
    // The client's EXACT bytes become the restore payload (full precision
    // for ids beyond float range).
    let host_raw = line[span.0..span.1].to_string();
    let quoted_proxy_id = {
        let mut ids = shared.ids.lock().expect("id mutex");
        ids.register(host_raw, is_tools_list)
    };
    match quoted_proxy_id {
        Ok(quoted) => {
            let _ = tx_in.send(splice_span(line, span, &quoted));
            None
        }
        Err(RegisterError::Overloaded) => {
            eprintln!(
                "agentguard-proxy: OVERLOAD: {} in-flight proxied requests — \
                 answering -32002 without forwarding",
                crate::proxy::spoof::MAX_PENDING_REQUESTS
            );
            let _ = tx_out.send(overloaded_response(host_id_value));
            None
        }
        Err(RegisterError::RngUnavailable(e)) => {
            // Fail-closed: no trustworthy id material ⇒ the request is
            // denied, never forwarded with predictable ids.
            eprintln!(
                "agentguard-proxy: secure randomness unavailable ({e}) — \
                 denying request fail-closed"
            );
            let denied = format!("internal error: secure randomness unavailable ({e})");
            let _ = tx_out.send(blocked_response(host_id_value, &denied));
            None
        }
    }
}
