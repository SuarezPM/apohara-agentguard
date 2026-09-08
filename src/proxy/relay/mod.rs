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

use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;

use crate::proxy::framing::{write_line, LineReader, MAX_LINE_EXCEEDED};
use crate::proxy::gate::Gates;
use crate::proxy::pinning::{
    default_config_base, tools_hash, upstream_identity, PinStore, PinVerdict,
};
use crate::proxy::spoof::IdRewriter;

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

/// Blast radius of a pin drift: quarantine the whole SESSION (default,
/// today's behavior) or just the affected TOOLs (`--drift-granularity tool`:
/// drifted/colliding tools are stripped from the manifest and their calls
/// blocked while the rest of the session keeps flowing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum DriftGranularity {
    /// Any manifest drift quarantines the entire session (default).
    #[default]
    Session,
    /// Only the changed/colliding tools are blocked; the session continues.
    Tool,
}

impl DriftGranularity {
    /// Canonical lowercase name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            DriftGranularity::Session => "session",
            DriftGranularity::Tool => "tool",
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
    /// Drift blast radius (default [`DriftGranularity::Session`]).
    #[doc(hidden)]
    pub granularity: DriftGranularity,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server: Vec::new(),
            max_line_bytes: crate::proxy::framing::DEFAULT_MAX_LINE_BYTES,
            expected_pin: None,
            pin_base: None,
            mode: RelayMode::Enforce,
            granularity: DriftGranularity::Session,
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
pub(super) struct Shared {
    /// Graduated enforcement mode (fixed for the session lifetime).
    pub(super) mode: RelayMode,
    /// Drift blast radius (fixed for the session lifetime).
    pub(super) granularity: DriftGranularity,
    /// Set once a quarantine-grade pin verdict fires; blocks every later
    /// `tools/call`. Only ever set in [`RelayMode::Enforce`] with
    /// session-granularity drift.
    pub(super) quarantined: AtomicBool,
    pub(super) quarantine_reason: Mutex<Option<String>>,
    /// Per-tool blocks from tool-granularity drift: tool name → why. Set by
    /// the child-reader thread, consulted by the main loop on tools/call.
    pub(super) blocked_tools: Mutex<std::collections::BTreeMap<String, String>>,
    /// First fatal error observed by any thread (protocol/I/O).
    pub(super) fatal: Mutex<Option<String>>,
    /// Anti-spoofing id table: proxied request ids minted by the relay
    /// (see [`crate::proxy::spoof`]).
    pub(super) ids: Mutex<IdRewriter>,
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

    /// Why this tool is blocked by a tool-granularity drift, if it is.
    fn blocked_tool_reason(&self, tool: &str) -> Option<String> {
        self.blocked_tools
            .lock()
            .expect("blocked-tools mutex")
            .get(tool)
            .cloned()
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
    eprintln!(
        "agentguard-proxy: mode: {} (drift granularity: {})",
        cfg.mode.as_str(),
        cfg.granularity.as_str()
    );

    let shared = Arc::new(Shared {
        mode: cfg.mode,
        granularity: cfg.granularity,
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

mod inbound;
mod outbound;

use inbound::handle_upstream_line;
use outbound::handle_client_line;

#[cfg(test)]
mod tests {
    use super::inbound::truncate_for_log;
    use super::*;
    use crate::proxy::pinning::PinStore;
    use crate::proxy::spoof::PROXY_ID_PREFIX;
    use crate::proxy::spoof::{splice_span, top_level_id_span, IdSpan};
    use serde_json::json;

    /// Pinned PREFIX of the drift reason (production rendering lives in
    /// `PinVerdict::reason`; attribution rides in parentheses after it).
    const DRIFT_REASON: &str = "tool manifest drift — pin mismatch";

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

    /// Push a client tools/list request (raw id text `id_raw`) through
    /// `handle_client_line`; returns the line the upstream would receive and
    /// the minted proxy id.
    fn send_client_list(
        shared: &Shared,
        tx_in: &mpsc::Sender<String>,
        rx_in: &mpsc::Receiver<String>,
        tx_out: &mpsc::Sender<String>,
        id_raw: &str,
    ) -> (String, String) {
        let line =
            format!(r#"{{"jsonrpc":"2.0","id":{id_raw},"method":"tools/list","params":{{}}}}"#);
        assert!(
            handle_client_line(&line, shared, tx_in, tx_out, &test_gates()).is_none(),
            "list requests never fatal"
        );
        let upstream_line = rx_in.recv().expect("forwarded list request");
        let IdSpan::Found(s, e) = top_level_id_span(&upstream_line) else {
            panic!("proxied id span")
        };
        let proxy_id = upstream_line[s..e].trim_matches('"').to_string();
        assert!(proxy_id.starts_with(crate::proxy::spoof::PROXY_ID_PREFIX));
        (upstream_line, proxy_id)
    }

    /// Build an upstream response line carrying `proxy_id` with `result`.
    fn upstream_response(proxy_id: &str, result: Value) -> String {
        json!({"jsonrpc":"2.0","id":proxy_id,"result":result}).to_string()
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
    fn client_line_classification_gates_calls_and_reids_requests() {
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();

        // Benign request forwards WITH a re-minted proxy id (anti-spoofing).
        let benign = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert!(handle_client_line(benign, &shared, &tx_in, &tx_out, &gates).is_none());
        let forwarded = rx_in.recv().expect("forwarded");
        assert_ne!(forwarded, benign, "request ids must be re-minted upstream");
        assert!(forwarded.contains(PROXY_ID_PREFIX), "{forwarded}");
        // Everything except the id stays byte-identical.
        let IdSpan::Found(s, e) = top_level_id_span(benign) else {
            panic!("span")
        };
        let IdSpan::Found(fs, fe) = top_level_id_span(&forwarded) else {
            panic!("forwarded span")
        };
        assert_eq!(
            forwarded,
            splice_span(benign, (s, e), &forwarded[fs..fe]),
            "only the id span may change"
        );

        // Dangerous call is denied and NOT forwarded; a synthesized response
        // appears on the outbound channel instead (host id preserved).
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

        // tools/list ids get tracked in the anti-spoofing table.
        let _ = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "9");
        assert_eq!(shared.ids.lock().unwrap().pending_len(), 2); // init + list

        // Garbage fails closed.
        assert!(handle_client_line("not json", &shared, &tx_in, &tx_out, &gates).is_some());

        // Duplicate top-level id fails closed.
        assert!(
            handle_client_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"m","id":2}"#,
                &shared,
                &tx_in,
                &tx_out,
                &gates
            )
            .is_some(),
            "ambiguous duplicate id member must be fatal"
        );
    }

    #[test]
    fn quarantined_session_blocks_all_subsequent_calls() {
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();
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
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // Client sends a tools/list (id 1); the relay mints a proxy id.
        let (_, pid1) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "1");
        // Prime the pin with the ORIGINAL manifest arriving under that id.
        let orig_line = upstream_response(&pid1, manifest("orig"));
        assert!(handle_upstream_line(&orig_line, &mut pin_gate, &shared, &tx_out).is_none());
        let forwarded = rx_out.recv().expect("restored forward");
        assert_eq!(
            forwarded,
            r#"{"id":1,"jsonrpc":"2.0","result":{"tools":[{"description":"orig","inputSchema":{"type":"object"},"name":"echo"}]}}"#,
            "host id restored; payload otherwise untouched"
        );

        // Tampered manifest on a NEW tracked id ⇒ replaced response carrying
        // the HOST id (2), not the proxied one.
        let (_, pid2) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "2");
        let tampered_line = upstream_response(
            &pid2,
            json!({ "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }),
        );
        assert!(
            handle_upstream_line(&tampered_line, &mut pin_gate, &shared, &tx_out).is_none(),
            "drift is a quarantine, not a protocol fatal"
        );
        let replaced = rx_out.recv().expect("replacement");
        let v: Value = serde_json::from_str(&replaced).unwrap();
        assert_eq!(v["id"], 2);
        assert_eq!(v["result"]["tools"], json!([]));
        assert_eq!(v["result"]["quarantined"], true);
        let reason_text = v["result"]["reason"].as_str().unwrap();
        assert!(
            reason_text.starts_with(DRIFT_REASON),
            "legacy prefix preserved: {reason_text}"
        );
        assert!(
            reason_text.contains("`echo` changed"),
            "rug-pull attribution present: {reason_text}"
        );
        assert!(shared.quarantined.load(Ordering::SeqCst));

        // Untracked/uninteresting lines pass through untouched.
        let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(handle_upstream_line(note, &mut pin_gate, &shared, &tx_out).is_none());
        assert_eq!(rx_out.recv().expect("passthrough"), note);
    }

    // ---- anti-spoofing at the relay level (FASE 5-B mechanism 2) -----------

    #[test]
    fn unknown_and_foreign_response_ids_are_dropped_never_forwarded() {
        let (_dir, store) = temp_store("unknown-id");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // A response whose id was NEVER minted by the relay: dropped.
        let forged = upstream_response("agp-ffffffffffffffffffffffffffffffff", json!({"x":1}));
        assert!(handle_upstream_line(&forged, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(
            rx_out.try_recv().is_err(),
            "forged id must not reach the client"
        );

        // A server echoing the CLIENT's original numeric id back: dropped —
        // only relay-minted ids may come home.
        let echo = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
        assert!(handle_upstream_line(echo, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(rx_out.try_recv().is_err());

        // A result WITHOUT any id: dropped fail-closed.
        let naked = r#"{"jsonrpc":"2.0","result":{}}"#;
        assert!(handle_upstream_line(naked, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(rx_out.try_recv().is_err());

        // Sanity: after all those drops the session is NOT fatal and real
        // traffic still flows.
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "3");
        assert!(rx_out.try_recv().is_err(), "list request has no output yet");
        assert!(pending_len(&shared) == 1);
        handle_upstream_line(
            &upstream_response(&pid, json!({"tools": []})),
            &mut pin_gate,
            &shared,
            &tx_out,
        );
        assert!(rx_out.recv().is_ok(), "legit response still delivered");
    }

    #[test]
    fn replayed_response_is_dropped_as_a_replay() {
        let (_dir, store) = temp_store("replay");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "4");
        let line = upstream_response(&pid, json!({"tools": []}));
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(rx_out.recv().is_ok(), "first delivery succeeds");

        // The SAME line again (captured/replayed): dropped, classified as a
        // replay via the recent-used set.
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(
            rx_out.try_recv().is_err(),
            "replay must never reach the client"
        );
        assert!(
            shared
                .ids
                .lock()
                .unwrap()
                .recently_consumed(pid.trim_matches('"')),
            "the drop path must classify it as a replay"
        );
    }

    #[test]
    fn large_integer_host_ids_survive_with_full_precision() {
        let (_dir, store) = temp_store("big-id");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // An id beyond f64 precision (> 2^53): raw-byte fidelity required.
        let big = "123456789012345678901234567890";
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, big);
        let resp = upstream_response(&pid, json!({"tools": []}));
        assert!(handle_upstream_line(&resp, &mut pin_gate, &shared, &tx_out).is_none());
        let out = rx_out.recv().expect("restored");
        assert!(
            out.contains(&format!("\"id\":{big}")),
            "exact digits must be restored: {out}"
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        // The Value view loses precision but the WIRE bytes do not — that is
        // the contract under test above; this parse just proves validity.
        assert!(v.get("id").is_some());

        // String ids with escapes round-trip too.
        let (_, pid2) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, r#""a\"b""#);
        let resp2 = upstream_response(&pid2, json!({"tools": []}));
        assert!(handle_upstream_line(&resp2, &mut pin_gate, &shared, &tx_out).is_none());
        let out2 = rx_out.recv().expect("restored string id");
        assert!(out2.contains(r#""id":"a\"b""#), "{out2}");
    }

    #[test]
    fn saturation_answers_minus_32002_without_forwarding() {
        let (_dir, _store) = temp_store("saturation");
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();

        for i in 0..crate::proxy::spoof::MAX_PENDING_REQUESTS {
            let line = format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"ping"}}"#);
            assert!(handle_client_line(&line, &shared, &tx_in, &tx_out, &gates).is_none());
            assert!(rx_in.recv().is_ok(), "request {i} forwards");
        }
        assert_eq!(
            shared.ids.lock().unwrap().pending_len(),
            crate::proxy::spoof::MAX_PENDING_REQUESTS
        );

        // One more request ⇒ -32002 to the client, NOTHING upstream.
        let overflow = r#"{"jsonrpc":"2.0","id":"last","method":"ping"}"#;
        assert!(handle_client_line(overflow, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(
            rx_in.try_recv().is_err(),
            "overloaded request must NOT forward"
        );
        let err = rx_out.recv().expect("overload error response");
        let v: Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["id"], "last");
        assert_eq!(v["error"]["code"], -32002);
        assert!(v.get("result").is_none());
    }

    fn pending_len(shared: &Shared) -> usize {
        shared.ids.lock().unwrap().pending_len()
    }

    #[test]
    fn client_responses_to_server_requests_splice_verbatim_without_pending_growth() {
        // Remediation B2: a client answering a SERVER-initiated request
        // (sampling/createMessage, roots/list, elicitation/create) carries a
        // result/error WITHOUT a method. It must reach upstream BYTE-IDENTICAL
        // (the upstream correlates on its own id) and register NOTHING in the
        // pending table.
        let shared = Shared::default();
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();
        let gates = test_gates();
        let before = pending_len(&shared);

        let resp = r#"{"jsonrpc":"2.0","id":900,"result":{"role":"assistant","model":"mock"}}"#;
        assert!(handle_client_line(resp, &shared, &tx_in, &tx_out, &gates).is_none());
        assert_eq!(
            rx_in.recv().expect("forwarded response"),
            resp,
            "response must be spliced verbatim — no re-minted id"
        );
        assert_eq!(pending_len(&shared), before, "no pending entry may appear");
        assert!(rx_out.try_recv().is_err(), "nothing synthesized");

        // Error responses take the same path (elicitation decline etc.).
        let err = r#"{"jsonrpc":"2.0","id":901,"error":{"code":-32601,"message":"declined"}}"#;
        assert!(handle_client_line(err, &shared, &tx_in, &tx_out, &gates).is_none());
        assert_eq!(rx_in.recv().expect("forwarded error response"), err);
        assert_eq!(pending_len(&shared), before);

        // Requests are unaffected: still re-minted and tracked.
        let req = r#"{"jsonrpc":"2.0","id":10,"method":"ping"}"#;
        assert!(handle_client_line(req, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(rx_in.recv().unwrap().contains(PROXY_ID_PREFIX));
        assert_eq!(pending_len(&shared), before + 1);
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
        assert!(
            forwarded.contains(PROXY_ID_PREFIX),
            "forwarded with a re-minted id like every request: {forwarded}"
        );
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
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // Record the honest manifest first.
        pin_gate.on_list_response(&manifest("orig"));

        // Drifted manifest on a tracked list id ⇒ replaced with the empty
        // filtered manifest, but the SESSION must stay un-quarantined.
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "2");
        let line = upstream_response(
            &pid,
            json!({ "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }),
        );
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
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        pin_gate.on_list_response(&manifest("orig"));

        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "3");
        let line = upstream_response(
            &pid,
            json!({ "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }),
        );
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        let out = rx_out.recv().expect("forward with restored id");
        // Byte-identical EXCEPT the id (restored to the client's own).
        assert_eq!(
            out,
            r#"{"id":3,"jsonrpc":"2.0","result":{"tools":[{"description":"EVIL","inputSchema":{"type":"object"},"name":"echo"}]}}"#,
            "audit-only forwards the DRIFTED manifest; {out}"
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
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "4");
        let line = upstream_response(
            &pid,
            json!({ "tools": [ {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}} ] }),
        );
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(shared.quarantined.load(Ordering::SeqCst));
    }

    // ---- drift granularity (FASE 5-B mechanism 3) --------------------------

    fn shared_with(mode: RelayMode, granularity: DriftGranularity) -> Shared {
        Shared {
            mode,
            granularity,
            ..Shared::default()
        }
    }

    #[test]
    fn tool_granularity_strips_drifted_tools_but_session_keeps_flowing() {
        let (_dir, store) = temp_store("tool-gran");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = shared_with(RelayMode::Enforce, DriftGranularity::Tool);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // Pin the honest two-tool manifest.
        pin_gate.on_list_response(&json!({ "tools": [
            {"name": "echo", "description": "honest", "inputSchema": {"type": "object"}},
            {"name": "calc", "description": "calc",   "inputSchema": {"type": "object"}}
        ]}));

        // Drifted manifest: echo tampered + a spoofing `rn` added; calc intact.
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "1");
        let line = upstream_response(
            &pid,
            json!({ "tools": [
                {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}},
                {"name": "rn",   "description": "spoof", "inputSchema": {"type": "object"}},
                {"name": "calc", "description": "calc",  "inputSchema": {"type": "object"}}
            ]}),
        );
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(
            !shared.quarantined.load(Ordering::SeqCst),
            "tool granularity must NOT quarantine the session"
        );

        let out = rx_out.recv().expect("filtered manifest");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["id"], 1);
        let names: Vec<&str> = v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["calc"], "only drifted/colliding tools stripped");
        let flagged: Vec<&str> = v["result"]["quarantined_tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(
            flagged.contains(&"echo") && flagged.contains(&"rn"),
            "{flagged:?}"
        );

        // Calls to the drifted/colliding tools are blocked; calc still flows.
        let gates = test_gates();
        let evil_call = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#;
        assert!(handle_client_line(evil_call, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(
            rx_in.try_recv().is_err(),
            "drifted tool call must not forward"
        );
        let resp = rx_out.recv().expect("blocked");
        let rv: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(rv["result"]["isError"], true);
        assert!(
            shared.blocked_tool_reason("calc").is_none(),
            "intact tool must remain callable"
        );
        let ok_call = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"calc","arguments":{}}}"#;
        assert!(handle_client_line(ok_call, &shared, &tx_in, &tx_out, &gates).is_none());
        assert!(rx_in.recv().is_ok(), "intact tool call forwards");
    }

    #[test]
    fn tool_granularity_in_filter_only_filters_list_and_logs_would_block() {
        let (_dir, store) = temp_store("tool-gran-filter");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = shared_with(RelayMode::FilterOnly, DriftGranularity::Tool);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        pin_gate.on_list_response(&json!({ "tools": [
            {"name": "echo", "description": "honest", "inputSchema": {"type": "object"}}
        ]}));

        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "2");
        let line = upstream_response(
            &pid,
            json!({ "tools": [
                {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}}
            ]}),
        );
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(!shared.quarantined.load(Ordering::SeqCst));
        let out = rx_out.recv().expect("filtered list");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["tools"], json!([]));

        // The drifted tool is flagged, but filter-only NEVER blocks calls.
        let evil_call = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#;
        assert!(handle_client_line(evil_call, &shared, &tx_in, &tx_out, &gates_dummy()).is_none());
        assert!(
            rx_in.recv().is_ok(),
            "filter-only forwards even drift-blocked tools"
        );
    }

    fn gates_dummy() -> Gates {
        test_gates()
    }

    #[test]
    fn output_schema_only_drift_escalates_to_session_handling_in_tool_mode() {
        // Remediation B3: tools_hash includes outputSchema but the per-tool
        // descriptor hash deliberately does NOT, so a manifest whose ONLY
        // drift is an added/changed outputSchema produces Mismatch with an
        // empty attribution. Tool granularity must NOT strip-nothing-and-
        // forward: it escalates to session-style handling (quarantine here).
        let (_dir, store) = temp_store("schema-drift");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = shared_with(RelayMode::Enforce, DriftGranularity::Tool);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // Pinned baseline: echo WITHOUT outputSchema.
        pin_gate.on_list_response(&json!({ "tools": [
            {"name": "echo", "description": "honest", "inputSchema": {"type": "object"}}
        ]}));

        // Drifted manifest: SAME name/description/inputSchema, outputSchema
        // appears. Descriptor hashes are byte-identical ⇒ changes == [].
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "1");
        let line = upstream_response(
            &pid,
            json!({ "tools": [
                {"name": "echo", "description": "honest",
                 "inputSchema": {"type": "object"},
                 "outputSchema": {"type": "object"}}
            ]}),
        );
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(
            shared.quarantined.load(Ordering::SeqCst),
            "outputSchema-only drift must escalate to a session quarantine"
        );
        let out = rx_out.recv().expect("quarantined replacement");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["tools"], json!([]));
        assert_eq!(v["result"]["quarantined"], true);

        // And the blocked-tools map stays EMPTY: no tool was attributed.
        assert!(
            shared.blocked_tools.lock().unwrap().is_empty(),
            "no per-tool attribution exists, so nothing may be tool-blocked"
        );
    }

    #[test]
    fn session_granularity_remains_the_untouched_default() {
        // Default guard: with granularity unset the legacy behavior holds —
        // full session quarantine on any mismatch.
        let (_dir, store) = temp_store("session-default");
        let mut pin_gate = PinGate::new(store, "srv".into(), None);
        let shared = shared_with(RelayMode::Enforce, DriftGranularity::Session);
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        pin_gate.on_list_response(&manifest("orig"));
        let (_, pid) = send_client_list(&shared, &tx_in, &rx_in, &tx_out, "3");
        let line = upstream_response(
            &pid,
            json!({ "tools": [
                {"name": "echo", "description": "EVIL", "inputSchema": {"type": "object"}}
            ]}),
        );
        assert!(handle_upstream_line(&line, &mut pin_gate, &shared, &tx_out).is_none());
        assert!(shared.quarantined.load(Ordering::SeqCst));
        let out = rx_out.recv().expect("replacement");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["tools"], json!([]));
        assert_eq!(v["result"]["quarantined"], true);
    }

    #[test]
    fn rng_failure_denies_the_request_fail_closed_at_relay_level() {
        use crate::proxy::spoof::{IdRewriter, RegisterError};
        let shared = Shared {
            ids: std::sync::Mutex::new(IdRewriter::with_sources(
                Box::new(std::time::Instant::now),
                Box::new(|| Err("urandom gone".to_string())),
            )),
            ..Shared::default()
        };
        let (tx_in, rx_in) = mpsc::channel();
        let (tx_out, rx_out) = mpsc::channel();

        // Sanity-check the injected source really fails.
        assert_eq!(
            shared.ids.lock().unwrap().register("1".into(), false),
            Err(RegisterError::RngUnavailable("urandom gone".to_string()))
        );

        let line = r#"{"jsonrpc":"2.0","id":8,"method":"initialize","params":{}}"#;
        assert!(handle_client_line(line, &shared, &tx_in, &tx_out, &test_gates()).is_none());
        assert!(
            rx_in.try_recv().is_err(),
            "RNG failure must deny: nothing may reach upstream"
        );
        let resp = rx_out.recv().expect("fail-closed denial response");
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 8);
        assert_eq!(v["result"]["isError"], true);
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("randomness unavailable"), "{text}");
    }
}
