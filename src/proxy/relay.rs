//! Bidirectional stdio relay for the MCP transport proxy (V4-B).
//!
//! Topology (threads + mpsc channels only — no tokio, matching the crate's
//! dependency-free runtime posture):
//!
//! ```text
//!  client stdin ──▶ [main thread] ──tx──▶ [forwarder] ──▶ child stdin
//!                        │   ▲                         │
//!                 gate calls  │                        ▼
//!                        │   │                     child stdout
//!                        ▼   │                         │
//!  client stdout ◀── [writer] ◀──tx── [child-reader] ─┘
//!  own  stderr ◀──────────────────── [stderr pump] ◀── child stderr
//! ```
//!
//! Enforcement points:
//! - **client→child**: `tools/call` requests run through
//!   [`crate::proxy::gate::evaluate_tool_call`] (and the session-quarantine
//!   flag); every other line forwards verbatim.
//! - **child→client**: responses to tracked `tools/list` requests go through
//!   [`PinGate`] (TOFU pin verification). A quarantine-grade verdict replaces
//!   the response with an empty quarantined manifest, raises the session
//!   quarantine flag (blocking ALL subsequent `tools/call`), and alarms on
//!   stderr. `notifications/tools/list_changed` invalidates the verified
//!   generation so the next manifest re-verifies.
//!
//! ## Graduated enforcement modes ([`RelayMode`])
//!
//! The same decision pipeline runs in every mode; only the ACTION taken on a
//! negative decision differs:
//!
//! - `enforce` (default) — today's behavior verbatim: drifted manifests are
//!   replaced and the session quarantined; denied calls are blocked.
//! - `filter-only` — `tools/list` filtering (pin verification + manifest
//!   replacement) still applies, but a call the gates would block is
//!   FORWARDED and the would-block is logged loudly on stderr instead.
//! - `audit-only` — nothing is filtered or blocked: drifted manifests reach
//!   the client VERBATIM and denied calls flow upstream; every would-block /
//!   would-filter is logged to stderr.
//!
//! Modes govern CONTENT policy (gate + pins) only. Transport-integrity
//! defenses (fail-closed framing, request-id anti-spoofing) stay ON in every
//! mode — an audit proxy must not downgrade the channel itself. A startup
//! banner (`mode: <name>` on stderr) makes the active posture visible in
//! captured logs.
//!
//! Fail-closed rules (pinned from the V4-B research notes):
//! - Non-JSON line from EITHER side ⇒ loud stderr log + terminate non-zero.
//!   Never silently skipped.
//! - Oversized line (> `max_line_bytes`) ⇒ same treatment.
//! - Unexpected upstream death ⇒ drain pending output, exit non-zero.
//!
//! Exit mapping ([`RelayOutcome`]): clean end ⇒ 0, session quarantined ⇒ 2,
//! internal/protocol failure ⇒ 74 (EX_IOERR, matching the existing MCP
//! surface's convention). Quarantine-grade outcomes only map to exit 2 in
//! `enforce` mode — the other modes never enter the enforced-quarantine
//! state by definition.
//!
//! ## Ordering & the in-flight window (documented posture)
//!
//! Forwarded traffic preserves upstream order among itself; locally
//! synthesized responses (gate denials, quarantine replacements) interleave
//! by JSON-RPC `id` — semantically correct since responses are matched by
//! id, not position. One consequence is inherent to any transport-level
//! inspector: a `tools/call` the client PIPELINED before the drifted
//! tools/list response arrives is already in flight upstream when the
//! quarantine fires. Pinning guarantees every call issued AFTER the manifest
//! verdict is gated; recalling in-flight traffic would require buffering the
//! whole session, which breaks streaming semantics. This mirrors SSH TOFU:
//! the first verification moment bounds what was already on the wire.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;

use crate::proxy::framing::{write_line, LineReader, MAX_LINE_EXCEEDED};
use crate::proxy::gate::{blocked_response, evaluate_tool_call, Gates};
use crate::proxy::pinning::{
    default_config_base, tools_hash, upstream_identity, PinStore, PinVerdict,
};

/// Pinned replacement reason for a drifted manifest (spec-exact wording).
const DRIFT_REASON: &str = "tool manifest drift — pin mismatch";

/// Graduated enforcement mode for the relay (see the module docs).
///
/// The decision pipeline is identical in every mode; the mode only chooses
/// between ACT and LOG on a negative decision. Default is `enforce` —
/// today's behavior, byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum RelayMode {
    /// Filter drifted manifests and block denied calls (default).
    #[default]
    Enforce,
    /// Filter `tools/list` per policy/pins but NEVER block `tools/call`;
    /// would-blocks are logged to stderr.
    FilterOnly,
    /// Filter nothing, block nothing; log every would-block / would-filter.
    AuditOnly,
}

impl RelayMode {
    /// Canonical lowercase name used by the startup banner and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            RelayMode::Enforce => "enforce",
            RelayMode::FilterOnly => "filter-only",
            RelayMode::AuditOnly => "audit-only",
        }
    }
}

/// Everything the relay needs to run. Injectable fields (`pin_base`) keep
/// tests off the real config directory.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Upstream argv: program + args. Env and cwd are inherited (the proxy
    /// is a transparent wrapper).
    pub server: Vec<String>,
    /// Maximum accepted NDJSON line size in bytes.
    pub max_line_bytes: usize,
    /// Operator pre-seed (`--pin` / `AGENTGUARD_PIN`), `sha256:<hex>`.
    pub expected_pin: Option<String>,
    /// Config base dir override for the pin store; `None` resolves via
    /// `$XDG_CONFIG_HOME` then `$HOME/.config`.
    pub pin_base: Option<std::path::PathBuf>,
    /// Enforcement mode (default [`RelayMode::Enforce`]).
    #[doc(hidden)]
    pub mode: RelayMode,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server: Vec::new(),
            max_line_bytes: crate::proxy::framing::DEFAULT_MAX_LINE_BYTES,
            expected_pin: None,
            pin_base: None,
            mode: RelayMode::Enforce,
        }
    }
}

/// How the relay session ended; the binary maps these to exit codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Client closed stdin, upstream exited cleanly, nothing quarantined.
    Clean,
    /// The session hit a pin quarantine (manifest drift / bad pre-seed /
    /// unusable store). Exit 2.
    Quarantined(String),
    /// Protocol violation (garbage/oversized line), internal I/O failure, or
    /// unexpected upstream death. Exit 74.
    Fatal(String),
}

/// Shared mutable session state between the relay threads.
#[derive(Default)]
struct Shared {
    /// Graduated enforcement mode (fixed for the session lifetime).
    mode: RelayMode,
    /// Set once a quarantine-grade pin verdict fires; blocks every later
    /// `tools/call`. Only ever set in [`RelayMode::Enforce`].
    quarantined: AtomicBool,
    quarantine_reason: Mutex<Option<String>>,
    /// First fatal error observed by any thread (protocol/I/O).
    fatal: Mutex<Option<String>>,
    /// Ids of forwarded `tools/list` requests awaiting their response.
    pending_lists: Mutex<HashSet<String>>,
}

impl Shared {
    fn record_fatal(&self, msg: String) {
        let mut f = self.fatal.lock().expect("fatal mutex");
        if f.is_none() {
            *f = Some(msg);
        }
    }

    fn fatal(&self) -> Option<String> {
        self.fatal.lock().expect("fatal mutex").clone()
    }

    fn quarantine(&self, reason: String) {
        let mut q = self.quarantine_reason.lock().expect("quarantine mutex");
        if q.is_none() {
            *q = Some(reason);
        }
        self.quarantined.store(true, Ordering::SeqCst);
    }

    fn quarantine_reason(&self) -> Option<String> {
        self.quarantine_reason
            .lock()
            .expect("quarantine mutex")
            .clone()
    }
}

/// TOFU pin verification state for ONE relay session.
///
/// Owns the per-generation cache: after a manifest verifies, later
/// `tools/list` responses with the SAME digest within the same generation
/// skip the store round-trip; `notifications/tools/list_changed` drops the
/// cache so the next manifest re-verifies against the store (catching drift
/// that arrives WITHOUT the courtesy notification — the actual attack).
pub struct PinGate {
    store: PinStore,
    upstream_identity: String,
    expected_pin: Option<String>,
    /// Digest verified for the current manifest generation (`None` after a
    /// list_changed or before the first list).
    verified_generation: Option<String>,
}

impl PinGate {
    pub fn new(store: PinStore, upstream_identity: String, expected_pin: Option<String>) -> Self {
        Self {
            store,
            upstream_identity,
            expected_pin,
            verified_generation: None,
        }
    }

    /// Handle one tools/list response body (`result` object). Returns the
    /// pin verdict; a quarantine-grade verdict means the caller must replace
    /// the response and quarantine the session.
    pub fn on_list_response(&mut self, result: &Value) -> PinVerdict {
        let computed = tools_hash(&self.upstream_identity, result);
        if self.verified_generation.as_deref() == Some(computed.as_str()) {
            // Same generation, already verified against the store.
            return PinVerdict::Matched { hash: computed };
        }
        let verdict = self.store.verify_or_record(
            &self.upstream_identity,
            result,
            self.expected_pin.as_deref(),
        );
        if !verdict.is_quarantine() {
            self.verified_generation = Some(computed);
        }
        verdict
    }

    /// Handle `notifications/tools/list_changed`: invalidate the cached
    /// generation so the next tools/list response re-verifies the pin.
    pub fn on_list_changed(&mut self) {
        self.verified_generation = None;
    }
}

/// Run the relay to completion. Blocks until the session ends.
pub fn run(cfg: RelayConfig, gates: &Gates) -> RelayOutcome {
    // The pin key is scoped to (argv vector, resolved child CWD): the proxy
    // inherits the client's cwd, so pins never leak across projects that run
    // the same command string from a different directory (remediation M2).
    let child_cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            return RelayOutcome::Fatal(format!("resolving cwd for upstream pin identity: {e}"))
        }
    };
    let upstream_identity = upstream_identity(&cfg.server, &child_cwd);

    // Fail-closed: without a usable config dir there is nowhere to pin, and
    // an unpinnable proxy silently degrades to a plain pipe.
    let Some(base) = cfg.pin_base.clone().or_else(default_config_base) else {
        return RelayOutcome::Fatal(
            "cannot resolve a config directory for the pin store (set XDG_CONFIG_HOME or HOME)"
                .to_string(),
        );
    };
    let store = PinStore::open(base);
    let mut pin_gate = PinGate::new(store, upstream_identity.clone(), cfg.expected_pin.clone());

    // Startup banner: the active posture must be visible in captured logs.
    eprintln!("agentguard-proxy: mode: {}", cfg.mode.as_str());

    let shared = Arc::new(Shared {
        mode: cfg.mode,
        ..Shared::default()
    });

    let mut child = match std::process::Command::new(&cfg.server[0])
        .args(&cfg.server[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return RelayOutcome::Fatal(format!("spawning upstream {:?}: {e}", cfg.server)),
    };
    let child_stdin = child.stdin.take().expect("child stdin piped");
    let child_stdout = child.stdout.take().expect("child stdout piped");
    let child_stderr = child.stderr.take().expect("child stderr piped");

    // ---- child handle + outbound writer -----------------------------------
    // The child handle sits behind a mutex so any thread can fail-closed
    // kill it during teardown.
    let child = Arc::new(Mutex::new(child));
    let kill_child = |child: &Arc<Mutex<std::process::Child>>| {
        let _ = child.lock().expect("child mutex").kill();
    };

    let (tx_out, rx_out) = mpsc::channel::<String>();
    let writer_shared = Arc::clone(&shared);
    let writer = thread::spawn(move || {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for line in rx_out {
            if write_line(&mut out, &line).is_err() {
                // Client went away; nothing left to protect — record and stop.
                writer_shared.record_fatal("writing to client stdout failed".to_string());
                break;
            }
        }
    });

    // ---- forwarder: main-thread channel -> child stdin --------------------
    let (tx_in, rx_in) = mpsc::channel::<String>();
    let fwd_shared = Arc::clone(&shared);
    let fwd_child = Arc::clone(&child);
    let forwarder = thread::spawn(move || {
        let mut stdin = child_stdin;
        for line in rx_in {
            if write_line(&mut stdin, &line).is_err() {
                // Upstream died (EPIPE is the usual suspect): fatal, and wake
                // the pipeline by killing the process outright.
                fwd_shared
                    .record_fatal("writing to upstream stdin failed (upstream gone?)".to_string());
                let _ = fwd_child.lock().expect("child mutex").kill();
                break;
            }
        }
        // Dropping `stdin` closes the child's stdin pipe (graceful EOF).
    });

    // ---- stderr pump: child stderr -> own stderr, prefixed -----------------
    let pump_child = Arc::clone(&child);
    let pump = thread::spawn(move || {
        let reader = std::io::BufReader::new(child_stderr);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    let err = std::io::stderr();
                    let mut lock = err.lock();
                    let _ = writeln!(lock, "[agentguard-proxy:child] {l}");
                }
                Err(_) => break,
            }
        }
        // Keep the handle alive until EOF; dropping the Arc releases it.
        drop(pump_child);
    });

    // ---- child-reader: child stdout -> gate/pin -> outbound ----------------
    let reader_shared = Arc::clone(&shared);
    let reader_tx_out = tx_out.clone();
    let reader_child = Arc::clone(&child);
    let max_line_bytes = cfg.max_line_bytes;
    let child_reader = thread::spawn(move || {
        // BufReader: LineReader is a byte-at-a-time loop, so the raw
        // ChildStdout must NOT be wrapped directly (a syscall per byte).
        // The client side needs no wrapper — StdinLock is already buffered.
        let mut reader = LineReader::new(BufReader::new(child_stdout));
        loop {
            match reader.read_line(max_line_bytes) {
                Ok(Some(line)) => {
                    if let Some(fatal) =
                        handle_upstream_line(&line, &mut pin_gate, &reader_shared, &reader_tx_out)
                    {
                        reader_shared.record_fatal(fatal);
                        let _ = reader_child.lock().expect("child mutex").kill();
                        break;
                    }
                    if reader_shared.fatal().is_some() {
                        break;
                    }
                }
                Ok(None) => break, // upstream stdout EOF (exit or death)
                Err(e) => {
                    let msg = if e.to_string() == MAX_LINE_EXCEEDED {
                        "upstream sent an oversized line".to_string()
                    } else {
                        format!("reading upstream stdout: {e}")
                    };
                    reader_shared.record_fatal(msg);
                    let _ = reader_child.lock().expect("child mutex").kill();
                    break;
                }
            }
        }
    });

    // ---- main loop: client stdin -> gate -> forwarder ----------------------
    let mut client = LineReader::new(std::io::stdin().lock());
    let mut client_eof = false;
    loop {
        // Read the next client line.
        let read = client.read_line(cfg.max_line_bytes);
        match read {
            Ok(None) => {
                client_eof = true;
                break;
            }
            Ok(Some(line)) => {
                if let Some(fatal) = shared.fatal() {
                    eprintln!("agentguard-proxy: fatal: {fatal}");
                    break;
                }
                if let Some(fatal) = handle_client_line(&line, &shared, &tx_in, &tx_out, gates) {
                    shared.record_fatal(fatal.clone());
                    eprintln!("agentguard-proxy: fatal: {fatal} — terminating (fail-closed)");
                    kill_child(&child);
                    break;
                }
            }
            Err(e) => {
                let msg = if e.to_string() == MAX_LINE_EXCEEDED {
                    format!(
                        "client line exceeds maximum allowed size ({} bytes)",
                        cfg.max_line_bytes
                    )
                } else {
                    format!("reading client stdin: {e}")
                };
                shared.record_fatal(msg.clone());
                eprintln!("agentguard-proxy: fatal: {msg} — terminating (fail-closed)");
                kill_child(&child);
                break;
            }
        }
    }

    // ---- teardown ----------------------------------------------------------
    if client_eof {
        // Graceful: close the child's stdin so it can finish and exit.
        drop(tx_in);
    } else {
        // Fatal path: the child was already killed; release the channel.
        drop(tx_in);
    }
    // Drain: wait for the child-reader to reach upstream EOF, flushing any
    // final responses through the writer.
    let _ = child_reader.join();
    drop(tx_out);
    let _ = forwarder.join();
    let _ = pump.join();
    let _ = writer.join();

    let status = child.lock().expect("child mutex").wait();

    // ---- exit-code resolution ----------------------------------------------
    if let Some(fatal) = shared.fatal() {
        return RelayOutcome::Fatal(fatal);
    }
    if let Some(reason) = shared.quarantine_reason() {
        return RelayOutcome::Quarantined(reason);
    }
    match status {
        Ok(s) if s.success() => RelayOutcome::Clean,
        Ok(s) => RelayOutcome::Fatal(format!("upstream exited with {s}")),
        Err(e) => RelayOutcome::Fatal(format!("waiting on upstream: {e}")),
    }
}

/// Classify + act on one line arriving FROM THE CLIENT.
///
/// Returns `Some(fatal)` for fail-closed protocol violations (garbage /
/// oversized handled by the caller's framing layer; here: non-JSON).
fn handle_client_line(
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

    let method = msg.get("method").and_then(Value::as_str);
    let has_id = msg.get("id").map(|v| !v.is_null()).unwrap_or(false);

    if method == Some("tools/call") {
        // Session quarantine blocks ALL subsequent calls.
        if shared.quarantined.load(Ordering::SeqCst) {
            let reason = shared
                .quarantine_reason()
                .unwrap_or_else(|| "session quarantined".to_string());
            let text = format!("session quarantined: {reason}");
            eprintln!("agentguard-proxy: blocked quarantined tools/call: {text}");
            if has_id {
                let _ = tx_out.send(blocked_response(
                    msg.get("id").unwrap_or(&Value::Null),
                    &text,
                ));
            }
            return None;
        }

        let tool_name = msg
            .pointer("/params/name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let args = msg
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or(Value::Null);
        let decision = evaluate_tool_call(&tool_name, &args, gates);
        if decision.allowed {
            let _ = tx_in.send(line.to_string());
            return None;
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
                if has_id {
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
                let _ = tx_in.send(line.to_string());
                None
            }
        };
    }

    if method == Some("tools/list") && has_id {
        // Track the id so the child-reader recognizes the response.
        if let Some(id) = msg.get("id") {
            shared
                .pending_lists
                .lock()
                .expect("pending mutex")
                .insert(id.to_string());
        }
    }

    // Everything else forwards verbatim (byte-identical line).
    let _ = tx_in.send(line.to_string());
    None
}

/// Classify + act on one line arriving FROM THE UPSTREAM.
///
/// Returns `Some(fatal)` for fail-closed protocol violations.
fn handle_upstream_line(
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

    // tools/list response?
    if msg.get("result").is_some() {
        if let Some(id) = msg.get("id") {
            let key = id.to_string();
            let was_tracked = shared
                .pending_lists
                .lock()
                .expect("pending mutex")
                .remove(&key);
            if was_tracked {
                let verdict = pin_gate.on_list_response(msg.get("result").expect("checked"));
                if verdict.is_quarantine() {
                    let reason = match &verdict {
                        // Spec-exact wording for plain drift.
                        PinVerdict::Mismatch { .. } => DRIFT_REASON.to_string(),
                        other => other.reason(),
                    };
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
                            let _ = tx_out.send(quarantined_manifest_response(id, &reason));
                            None
                        }
                        RelayMode::FilterOnly => {
                            eprintln!(
                                "agentguard-proxy: FILTERED (mode filter-only): {} — \
                                 manifest filtered, tools/call NOT blocked",
                                verdict.reason()
                            );
                            let _ = tx_out.send(quarantined_manifest_response(id, &reason));
                            None
                        }
                        RelayMode::AuditOnly => {
                            eprintln!(
                                "agentguard-proxy: WOULD-FILTER (mode audit-only): {}",
                                verdict.reason()
                            );
                            // Nothing is filtered: the drifted manifest
                            // reaches the client exactly as upstream sent it.
                            let _ = tx_out.send(line.to_string());
                            None
                        }
                    };
                }
                eprintln!("agentguard-proxy: {}", verdict.reason());
                // Verified: forward the response verbatim.
                let _ = tx_out.send(line.to_string());
                return None;
            }
        }
    }

    // Manifest-generation invalidation.
    if msg.get("method").and_then(Value::as_str) == Some("notifications/tools/list_changed") {
        pin_gate.on_list_changed();
        eprintln!("agentguard-proxy: tools/list_changed — pin will re-verify on next tools/list");
    }

    // Everything else forwards verbatim.
    let _ = tx_out.send(line.to_string());
    None
}

/// Build the replacement tools/list response the relay sends INSTEAD of a
/// quarantine-grade manifest: an empty tool list flagged `quarantined` with
/// the neutralized reason, under the request's original id.
fn quarantined_manifest_response(id: &Value, reason: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [],
            "quarantined": true,
            "reason": crate::neutralize_reason(reason),
        }
    })
    .to_string()
}

/// Cap hostile/garbage payload excerpts in stderr diagnostics.
fn truncate_for_log(line: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::pinning::PinStore;
    use serde_json::json;

    fn temp_store(tag: &str) -> (std::path::PathBuf, PinStore) {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "agentguard-relay-test-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        (dir.clone(), PinStore::open(dir))
    }

    fn test_gates() -> Gates {
        Gates {
            config: crate::config::Config::default(),
            policy: crate::policy::engine::PolicySet::default(),
        }
    }

    fn shared_in_mode(mode: RelayMode) -> Shared {
        Shared {
            mode,
            ..Shared::default()
        }
    }

    fn dangerous_call() -> String {
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{"command":"rm -rf /"}}}"#
            .to_string()
    }

    fn manifest(desc: &str) -> Value {
        json!({ "tools": [ {"name": "echo", "description": desc, "inputSchema": {"type": "object"}} ] })
    }

    #[test]
    fn pin_gate_records_first_manifest_and_matches_after() {
        let (_dir, store) = temp_store("gen");
        let mut gate = PinGate::new(store, "srv".into(), None);

        let v1 = gate.on_list_response(&manifest("v1"));
        assert!(matches!(v1, PinVerdict::Recorded { .. }), "{v1:?}");

        // Same generation again: cache hit, no store round-trip needed.
        let v2 = gate.on_list_response(&manifest("v1"));
        assert!(matches!(v2, PinVerdict::Matched { .. }), "{v2:?}");
    }

    #[test]
    fn pin_gate_list_changed_invalidates_generation_so_drift_is_caught() {
        let (_dir, store) = temp_store("invalidate");
        let mut gate = PinGate::new(store, "srv".into(), None);

        assert!(matches!(
            gate.on_list_response(&manifest("original")),
            PinVerdict::Recorded { .. }
        ));

        // Drift WITHIN a generation is caught even without list_changed…
        assert!(matches!(
            gate.on_list_response(&manifest("TAMPERED")),
            PinVerdict::Mismatch { .. }
        ));

        // …and after list_changed the SAME original manifest re-verifies
        // against the store (Matched), proving the cache was dropped.
        gate.on_list_changed();
        assert!(matches!(
            gate.on_list_response(&manifest("original")),
            PinVerdict::Matched { .. }
        ));
    }

    #[test]
    fn pin_gate_preseed_mismatch_quarantines_immediately() {
        let (_dir, store) = temp_store("preseed");
        let mut gate = PinGate::new(store, "srv".into(), Some("sha256:deadbeef".into()));
        let v = gate.on_list_response(&manifest("whatever"));
        assert!(v.is_quarantine(), "{v:?}");
        assert!(matches!(v, PinVerdict::PreseedMismatch { .. }));
    }

    #[test]
    fn client_line_classification_gates_calls_and_tracks_lists() {
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = Gates {
            config: crate::config::Config::default(),
            policy: crate::policy::engine::PolicySet::default(),
        };

        // Benign request forwards verbatim.
        let benign = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert!(handle_client_line(benign, &shared, &tx_in, &tx_out, &gates).is_none());
        assert_eq!(rx_in.recv().expect("forwarded"), benign);

        // Dangerous call is denied and NOT forwarded; a synthesized response
        // appears on the outbound channel instead.
        let danger = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{"command":"rm -rf /"}}}"#;
        assert!(handle_client_line(danger, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(
            rx_in.try_recv().is_err(),
            "denied call must not reach upstream"
        );
        let resp = rx_out.recv().expect("synthesized response");
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 2);
        assert_eq!(v["result"]["isError"], true);

        // tools/list ids get tracked for response matching.
        let list = r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}"#;
        assert!(handle_client_line(list, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(
            shared
                .pending_lists
                .lock()
                .unwrap()
                .contains(&json!(9).to_string()),
            "list id must be tracked"
        );

        // Garbage fails closed.
        assert!(handle_client_line("not json", &shared, &tx_in, &tx_out, &gates).is_some());
    }

    #[test]
    fn quarantined_session_blocks_all_subsequent_calls() {
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = Gates {
            config: crate::config::Config::default(),
            policy: crate::policy::engine::PolicySet::default(),
        };
        shared.quarantine("tool manifest drift — pin mismatch".to_string());

        let call = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"value":"hi"}}}"#;
        assert!(handle_client_line(call, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(
            rx_in.try_recv().is_err(),
            "quarantined call must not forward"
        );
        let resp = rx_out.recv().expect("blocked response");
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["isError"], true);
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("session quarantined"), "{text}");
    }

    #[test]
    fn upstream_drift_response_is_replaced_with_empty_quarantined_manifest() {
        let (_dir, store) = temp_store("replace");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = Shared::default();
        let (tx_out, rx_out) = mpsc::channel();

        // Prime the pin with the ORIGINAL manifest.
        let original = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "tools": [ {"name": "echo", "description": "orig", "inputSchema": {"type": "object"}} ] }
        });
        shared
            .pending_lists
            .lock()
            .unwrap()
            .insert(json!(1).to_string());
        let orig_line = original.to_string();
        assert!(handle_upstream_line(&orig_line, &mut pin_gate, &shared, &tx_out).is_none());
        let forwarded = rx_out.recv().expect("verbatim forward");
        assert_eq!(
            forwarded, orig_line,
            "verified list forwards byte-identical"
        );

        // Tampered manifest on the SAME tracked id ⇒ replaced response.
        let tampered = json!({
            "jsonrpc": "2.0", "id": 2,
            "result": { "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }
        });
        shared
            .pending_lists
            .lock()
            .unwrap()
            .insert(json!(2).to_string());
        let tampered_line = tampered.to_string();
        assert!(
            handle_upstream_line(&tampered_line, &mut pin_gate, &shared, &tx_out).is_none(),
            "drift is a quarantine, not a protocol fatal"
        );
        let replaced = rx_out.recv().expect("replacement");
        let v: Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(v["id"], 2);
        assert_eq!(v["result"]["tools"], json!([]));
        assert_eq!(v["result"]["quarantined"], true);
        assert_eq!(v["result"]["reason"], DRIFT_REASON);
        assert!(shared.quarantined.load(Ordering::SeqCst));

        // Untracked/uninteresting lines pass through untouched.
        let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(handle_upstream_line(note, &mut pin_gate, &shared, &tx_out).is_none());
        assert_eq!(rx_out.recv().expect("passthrough"), note);
    }

    #[test]
    fn upstream_garbage_is_a_protocol_fatal() {
        let (_dir, store) = temp_store("garbage");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = Shared::default();
        let (tx_out, _rx_out) = mpsc::channel();
        assert!(
            handle_upstream_line("\u{7f}junk", &mut pin_gate, &shared, &tx_out).is_some(),
            "non-JSON from upstream must be fatal"
        );
    }

    #[test]
    fn list_changed_notification_passes_through_and_invalidates() {
        let (_dir, store) = temp_store("note");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = Shared::default();
        let (tx_out, rx_out) = mpsc::channel();

        assert!(matches!(
            pin_gate.on_list_response(&manifest("m")),
            PinVerdict::Recorded { .. }
        ));
        let note = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        assert!(handle_upstream_line(note, &mut pin_gate, &shared, &tx_out).is_none());
        assert_eq!(rx_out.recv().expect("notification forwarded"), note);
        // Generation invalidated: an identical manifest re-verifies (Matched
        // via the STORE, observable only in that it is not a quarantine).
        assert!(matches!(
            pin_gate.on_list_response(&manifest("m")),
            PinVerdict::Matched { .. }
        ));
    }

    #[test]
    fn log_excerpt_truncation_caps_hostile_lines() {
        let long = "x".repeat(5000);
        let s = truncate_for_log(&long);
        assert!(s.len() < 250, "{}", s.len());
        assert!(s.ends_with("[truncated]"));
        assert_eq!(truncate_for_log("short"), "short");
    }

    // ---- graduated modes (FASE 5-B mechanism 1) ----------------------------

    #[test]
    fn relay_mode_names_are_canonical() {
        assert_eq!(RelayMode::Enforce.as_str(), "enforce");
        assert_eq!(RelayMode::FilterOnly.as_str(), "filter-only");
        assert_eq!(RelayMode::AuditOnly.as_str(), "audit-only");
        // Default is enforce: today's behavior is untouchable.
        assert_eq!(RelayMode::default(), RelayMode::Enforce);
        assert_eq!(RelayConfig::default().mode, RelayMode::Enforce);
    }

    #[test]
    fn filter_only_never_blocks_a_denied_call_but_still_filters_lists() {
        let shared = shared_in_mode(RelayMode::FilterOnly);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();

        // A call the gates deny FORWARDS upstream in filter-only mode.
        assert!(handle_client_line(&dangerous_call(), &shared, &tx_in, &tx_out, &gates).is_none());
        let forwarded = rx_in.recv().expect("denied call must forward");
        let v: Value = serde_json::from_str(&forwarded).unwrap();
        assert_eq!(v["id"], 2, "same request reaches upstream");
        assert!(rx_out.try_recv().is_err(), "no synthesized response");

        // The session quarantine flag must never be set in this mode: the
        // quarantined-call branch below stays unreachable.
        assert!(!shared.quarantined.load(Ordering::SeqCst));
    }

    #[test]
    fn audit_only_never_blocks_a_denied_call() {
        let shared = shared_in_mode(RelayMode::AuditOnly);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();

        assert!(handle_client_line(&dangerous_call(), &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(rx_in.recv().is_ok(), "audit-only forwards everything");
        assert!(rx_out.try_recv().is_err());
    }

    #[test]
    fn filter_only_replaces_drifted_manifest_without_session_quarantine() {
        let (_dir, store) = temp_store("filter-drift");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = shared_in_mode(RelayMode::FilterOnly);
        let (tx_out, rx_out) = mpsc::channel();

        // Record the honest manifest first.
        pin_gate.on_list_response(&manifest("orig"));

        // Drifted manifest on a tracked list id ⇒ replaced with the empty
        // filtered manifest, but the SESSION must stay un-quarantined.
        let drifted = json!({
            "jsonrpc": "2.0", "id": 2,
            "result": { "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }
        });
        shared
            .pending_lists
            .lock()
            .unwrap()
            .insert(json!(2).to_string());
        let line = drifted.to_string();
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        let replaced = rx_out.recv().expect("filtered replacement");
        let v: Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(v["result"]["tools"], json!([]));
        assert_eq!(v["result"]["quarantined"], true);
        assert!(
            !shared.quarantined.load(Ordering::SeqCst),
            "filter-only must NOT raise the session quarantine flag"
        );
    }

    #[test]
    fn audit_only_forwards_drifted_manifest_verbatim_with_would_log() {
        let (_dir, store) = temp_store("audit-drift");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = shared_in_mode(RelayMode::AuditOnly);
        let (tx_out, rx_out) = mpsc::channel();

        pin_gate.on_list_response(&manifest("orig"));

        let drifted = json!({
            "jsonrpc": "2.0", "id": 3,
            "result": { "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }
        });
        shared
            .pending_lists
            .lock()
            .unwrap()
            .insert(json!(3).to_string());
        let line = drifted.to_string();
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert_eq!(
            rx_out.recv().expect("verbatim forward"),
            line,
            "audit-only must not touch the manifest bytes"
        );
        assert!(!shared.quarantined.load(Ordering::SeqCst));
    }

    #[test]
    fn enforce_mode_still_blocks_denied_calls_and_quarantines() {
        // Guard against accidental mode drift: the default path keeps
        // today's semantics exactly.
        let shared = shared_in_mode(RelayMode::Enforce);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();

        assert!(handle_client_line(&dangerous_call(), &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(rx_in.try_recv().is_err(), "enforce must not forward");
        let resp = rx_out.recv().expect("synthesized block");
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["isError"], true);

        // Upstream drift still raises the session quarantine in enforce.
        let (_dir, store) = temp_store("enforce-drift");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        pin_gate.on_list_response(&manifest("orig"));
        let drifted = json!({
            "jsonrpc": "2.0", "id": 4,
            "result": { "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }
        });
        shared
            .pending_lists
            .lock()
            .unwrap()
            .insert(json!(4).to_string());
        let line = drifted.to_string();
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(shared.quarantined.load(Ordering::SeqCst));
    }
}
