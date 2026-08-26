//! Request-id anti-spoofing for the MCP transport relay (FASE 5-B).
//!
//! Before this layer, whatever `id` a client put on a request traveled to the
//! upstream server verbatim, and ANY response id coming back was forwarded to
//! the client. That gives a compromised/malicious upstream two abilities:
//! it can correlate and replay client traffic shapes, and it can FORGE a
//! well-formed response to a request it never received (or to a request
//! another component issued).
//!
//! The defense: the relay MINTS its own opaque request ids. Every client
//! request that carries an `id` is re-id'd before it reaches upstream:
//!
//! ```text
//! client: {"id":7,...}   ──▶ upstream: {"id":"agp-<32 hex>",...}
//!                          ◀─ mapped in pending[agp-… → 7]
//! upstream: {"id":"agp-…",result} ──▶ client: {"id":7,result}
//! ```
//!
//! Rules (fail-closed):
//! - A response is accepted ONLY if its id is a string that sits EXACTLY in
//!   the pending table. Unknown, duplicated, replayed-after-TTL, non-string,
//!   or absent ids on a response ⇒ the line is DROPPED with a stderr warning,
//!   never forwarded.
//! - Consumed ids move to a recent-used set with a ~60 s TTL (amortized
//!   pruning) so a replayed response is recognized and reported as such
//!   instead of silently looking "unknown".
//! - Saturation guard: more than [`MAX_PENDING_REQUESTS`] in-flight requests
//!   ⇒ the request is answered with a JSON-RPC `-32002` overloaded error and
//!   NEVER forwarded.
//! - Randomness failure ⇒ the request is denied (fail-closed); the proxy
//!   never falls back to predictable id material.
//!
//! Notifications (requests WITHOUT an `id` member) and server-initiated
//! messages (lines carrying `method`) pass through untouched in both
//! directions.
//!
//! ## Id fidelity
//!
//! The client's original id bytes are preserved EXACTLY: the relay stores the
//! RAW text span of the id value (not a re-parsed `Value`, which would round
//! integers > 2^53 through `f64`) and splices it back into the response line
//! byte-for-byte. Everything else on the line is untouched too — the rewrite
//! is a pure span splice, so huge numeric ids survive with full precision.
//!
//! A duplicate TOP-LEVEL `id` member (`{"id":1,...,"id":2}`) is ambiguous
//! under different parsers ([`serde_json`] keeps the last, this module's
//! splicer would hit the first) and fails the session closed rather than
//! guessing which one is real.
//!
//! ## Randomness source
//!
//! Proxy ids are `agp-` + 16 cryptographically-random bytes, lowercase hex,
//! read from `/dev/urandom` (the crate targets Linux; there is no runtime dep
//! for userspace CSPRNGs and none is added). Read failures propagate as
//! [`RegisterError::RngUnavailable`] and the caller denies the request.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::Value;

/// Prefix marking relay-minted opaque request ids.
pub const PROXY_ID_PREFIX: &str = "agp-";

/// Maximum simultaneous in-flight (registered-but-unanswered) proxied
/// requests. Above this the relay answers `-32002 overloaded` instead of
/// forwarding — a hostile or buggy client must not be able to balloon the
/// mapping without bound.
pub const MAX_PENDING_REQUESTS: usize = 1024;

/// How long a CONSUMED proxy id stays in the recent-used set for
/// replay classification.
pub const RECENT_TTL: Duration = Duration::from_secs(60);

/// Run the amortized TTL sweep once every N map operations.
const PRUNE_INTERVAL_OPS: u64 = 64;

/// Hard ceiling on the recent-used set; exceeded ⇒ force a sweep (and, if
/// everything is still fresh, shed the oldest entries). Purely a memory
/// backstop for pathological pipelining.
const MAX_RECENT_ENTRIES: usize = 4096;

/// Why a request could not be registered for proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// The pending table is at capacity: answer -32002, do not forward.
    Overloaded,
    /// The secure randomness source failed: deny fail-closed.
    RngUnavailable(String),
}

/// Metadata retained per in-flight proxied request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEntry {
    /// The CLIENT's id exactly as it appeared on the wire (raw JSON scalar
    /// text including quotes) — restored verbatim into the response.
    pub host_id_raw: String,
    /// Whether the request was a `tools/list` (drives the pin pipeline).
    pub is_tools_list: bool,
}

/// Wall-clock injection (tests advance a virtual timeline).
type Clock = Box<dyn Fn() -> Instant + Send>;

/// Secure-bytes generator; fallible so failure can deny fail-closed.
type Rng = Box<dyn FnMut() -> Result<[u8; 16], String> + Send>;

/// Bidirectional id-mapping state for ONE relay session.
///
/// Owned by `Shared` behind a mutex: the main thread registers forwarded
/// requests, the child-reader thread resolves responses.
pub struct IdRewriter {
    /// proxy_id → metadata, for requests forwarded and not yet answered.
    pending: HashMap<String, PendingEntry>,
    /// proxy_id → consumption instant, kept ~[`RECENT_TTL`] so replays are
    /// classified as replays (a sharper diagnostic than "unknown id").
    recent: HashMap<String, Instant>,
    clock: Clock,
    rng: Rng,
    ops: u64,
}

impl Default for IdRewriter {
    fn default() -> Self {
        Self::new()
    }
}

impl IdRewriter {
    /// Production constructor: real clock, `/dev/urandom`.
    pub fn new() -> Self {
        Self::with_sources(Box::new(Instant::now), Box::new(system_urandom))
    }

    /// Injectable constructor (tests).
    pub fn with_sources(clock: Clock, rng: Rng) -> Self {
        Self {
            pending: HashMap::new(),
            recent: HashMap::new(),
            clock,
            rng,
            ops: 0,
        }
    }

    /// Register one outgoing request and mint its opaque proxy id.
    ///
    /// `host_id_raw` is the client's id value EXACTLY as it appeared on the
    /// wire (see [`top_level_id_span`]). On success returns the new proxy id
    /// (already JSON-quoted by [`quote_proxy_id`]).
    pub fn register(
        &mut self,
        host_id_raw: String,
        is_tools_list: bool,
    ) -> Result<String, RegisterError> {
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(RegisterError::Overloaded);
        }
        // Mint a fresh unique id (collision retry is belt-and-braces: 16
        // random bytes colliding is not a realistic event, but uniqueness
        // against BOTH maps is load-bearing for correctness, so verify it).
        let mut proxy_id = String::new();
        for _ in 0..3 {
            let bytes = (self.rng)().map_err(RegisterError::RngUnavailable)?;
            let candidate = format!("{PROXY_ID_PREFIX}{}", hex_encode(&bytes));
            if !self.pending.contains_key(&candidate) && !self.recent.contains_key(&candidate) {
                proxy_id = candidate;
                break;
            }
        }
        if proxy_id.is_empty() {
            // Three collisions in 128 bits of entropy is indistinguishable
            // from a broken/degenerate entropy source: fail closed.
            return Err(RegisterError::RngUnavailable(
                "proxy id space exhausted (repeated collisions)".to_string(),
            ));
        }
        self.pending.insert(
            proxy_id.clone(),
            PendingEntry {
                host_id_raw,
                is_tools_list,
            },
        );
        self.amortized_prune();
        Ok(quote_proxy_id(&proxy_id))
    }

    /// Resolve an incoming response id. Accepts ONLY ids sitting exactly in
    /// the pending table; moves the consumed id into the recent-used set.
    /// Returns `None` for unknown / already-consumed ids (caller drops).
    pub fn resolve(&mut self, proxy_id: &str) -> Option<PendingEntry> {
        let entry = self.pending.remove(proxy_id)?;
        self.recent.insert(proxy_id.to_string(), (self.clock)());
        self.amortized_prune();
        Some(entry)
    }

    /// True iff `proxy_id` was consumed within the recent window (replay
    /// evidence, used for sharper drop diagnostics).
    pub fn recently_consumed(&self, proxy_id: &str) -> bool {
        self.recent.contains_key(proxy_id)
    }

    /// Amortized housekeeping: sweep expired recents every
    /// [`PRUNE_INTERVAL_OPS`] ops or when the set grows past its soft cap.
    fn amortized_prune(&mut self) {
        self.ops = self.ops.wrapping_add(1);
        if self.ops % PRUNE_INTERVAL_OPS != 0 && self.recent.len() < MAX_RECENT_ENTRIES {
            return;
        }
        let now = (self.clock)();
        self.recent
            .retain(|_, seen| now.duration_since(*seen) < RECENT_TTL);
        // Backstop: if everything is somehow still fresh past the hard cap
        // (clock went backwards, absurd pipelining), shed the oldest so the
        // structure stays bounded.
        while self.recent.len() >= MAX_RECENT_ENTRIES {
            let oldest = self
                .recent
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.recent.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Number of in-flight proxied requests (diagnostics/tests).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// Production entropy: 16 bytes from `/dev/urandom`. Any short read or open
/// failure is an ERROR — the caller denies rather than downgrading entropy.
fn system_urandom() -> Result<[u8; 16], String> {
    use std::io::Read;
    let mut f =
        std::fs::File::open("/dev/urandom").map_err(|e| format!("opening /dev/urandom: {e}"))?;
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf)
        .map_err(|e| format!("reading /dev/urandom: {e}"))?;
    Ok(buf)
}

/// Lowercase hex without pulling in a hex crate.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The proxy id formatted as a JSON string literal (ready to splice).
pub fn quote_proxy_id(proxy_id: &str) -> String {
    format!("\"{proxy_id}\"")
}

/// Outcome of locating the top-level `id` member on a JSON object line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdSpan {
    /// No top-level `id` member (notification / server-initiated message).
    Absent,
    /// Byte span `(start, end)` of the id VALUE (exclusive of any trailing
    /// comma/brace), suitable for [`splice_span`].
    Found(usize, usize),
    /// More than one top-level `id` member: parser-dependent semantics ⇒
    /// callers must fail the session closed, never guess.
    Ambiguous,
}

/// Locate the TOP-LEVEL `id` member's value span on a single-line JSON
/// object. String-aware and nesting-aware: an `"id"` key inside `params`,
/// arrays, or nested objects is ignored; string values with escapes are
/// traversed safely.
///
/// This exists so id rewriting/restoration can be done as a pure TEXT SPlice
/// (byte-preserving everywhere except the id itself) instead of a
/// parse→re-serialize cycle, which would corrupt big integer ids (> 2^53
/// round-trip through f64) and rewrite unrelated formatting.
pub fn top_level_id_span(line: &str) -> IdSpan {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    // Depth of nested {} / [] OUTSIDE any string. Top-level members live at
    // depth 1 (inside the root object).
    let mut depth = 0usize;
    let mut found: Option<(usize, usize)> = None;

    while i < n {
        let c = b[i];
        match c {
            b'"' => {
                // A string starts here: if we are at member-key depth, try to
                // read it as `"id"` followed by ':'.
                if depth == 1 {
                    if let Some((key_end, colon_pos)) = scan_key(b, i) {
                        if &b[i + 1..key_end] == b"id" {
                            let vstart = colon_pos + 1;
                            match scan_value_end(b, vstart) {
                                Some(vend) => {
                                    if found.is_some() {
                                        return IdSpan::Ambiguous;
                                    }
                                    found = Some((vstart, vend));
                                    i = vstart; // scan_value_end stopped AT delimiter
                                    continue;
                                }
                                None => return IdSpan::Absent, // malformed value
                            }
                        }
                        // Different key: skip past its colon; the VALUE is
                        // scanned by the main loop below (strings/braces in
                        // it update state normally).
                        i = colon_pos + 1;
                        continue;
                    }
                }
                // Ordinary string (value or nested key): consume it wholly.
                // NOTE: +1 lands PAST the closing quote — stopping ON it
                // would re-enter string mode and swallow the structural
                // bytes up to the next opening quote.
                i = skip_string(b, i) + 1;
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                if depth == 0 {
                    return IdSpan::Absent; // malformed
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    found.map_or(IdSpan::Absent, |(s, e)| IdSpan::Found(s, e))
}

/// Given `b[at] == b'"'` at member-key position, return `(end_quote_index,
/// colon_index)` if this string is immediately followed by `:` (i.e. it IS a
/// key), else `None`. Escape-aware.
fn scan_key(b: &[u8], at: usize) -> Option<(usize, usize)> {
    let end = skip_string(b, at);
    if end >= b.len() {
        return None;
    }
    let mut j = end + 1; // past closing quote
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    if j < b.len() && b[j] == b':' {
        // Position just AFTER the colon (value starts there, modulo ws).
        let mut k = j + 1;
        while k < b.len() && b[k].is_ascii_whitespace() {
            k += 1;
        }
        Some((end, k - 1))
    } else {
        None
    }
}

/// Consume a JSON string starting at `start` (`b[start] == b'"'`), returning
/// the index OF the closing quote. Escape-aware. Malformed input returns
/// `b.len()`.
fn skip_string(b: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2, // skip escaped char (surrogate pairs are ASCII-safe here)
            b'"' => return i,
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// From a value start index, find where the value ENDS: the index of the
/// first `,` or `}` at bracket-depth 0 relative to the value (strings and
/// nested structures skipped). Returns the delimiter index itself.
fn scan_value_end(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut depth = 0usize;
    while i < b.len() {
        match b[i] {
            b'"' => i = skip_string(b, i),
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                if depth == 0 {
                    // Closing the MEMBER (}) — value ended right here.
                    return Some(i);
                }
                depth -= 1;
            }
            b',' if depth == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    // End of line: a bare value with no delimiter (unusual but tolerated by
    // the framing layer's tolerance for unterminated tails) — treat as
    // extending to EOF only if the object actually closed; otherwise
    // malformed.
    None
}

/// Replace the byte span `(start, end)` of `line` with `replacement`,
/// preserving every other byte exactly.
pub fn splice_span(line: &str, span: (usize, usize), replacement: &str) -> String {
    let (start, end) = span;
    debug_assert!(line.is_char_boundary(start) && line.is_char_boundary(end));
    let mut out = String::with_capacity(line.len() + replacement.len());
    out.push_str(&line[..start]);
    out.push_str(replacement);
    out.push_str(&line[end..]);
    out
}

/// Classify an incoming UPSTREAM line's id for the anti-spoofing gate.
///
/// Returns:
/// - `Ok(None)` — no top-level id (notification/server message): passthrough.
/// - `Ok(Some(proxy_id))` — id is a string bearing our prefix; the caller
///   looks it up in the pending table.
/// - `Err(drop_reason)` — the id exists but CANNOT be a legitimate response
///   to a proxied request (absent-but-result-bearing, non-string, foreign
///   prefix): the caller DROPS the line.
pub fn classify_response_id(msg: &Value) -> Result<Option<String>, &'static str> {
    match msg.get("id") {
        None => Ok(None),
        Some(Value::String(s)) => {
            if s.starts_with(PROXY_ID_PREFIX) {
                Ok(Some(s.clone()))
            } else {
                Err("response id lacks the proxy namespace prefix")
            }
        }
        Some(_) => Err("response id is not a string (proxied ids are always strings)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- span extraction ---------------------------------------------------

    #[test]
    fn spans_all_scalar_id_shapes_at_top_level() {
        assert_eq!(
            top_level_id_span(r#"{"id":7,"method":"m"}"#),
            IdSpan::Found(6, 7)
        );
        assert_eq!(
            top_level_id_span(r#"{"id":"abc","method":"m"}"#),
            IdSpan::Found(6, 11)
        );
        assert_eq!(top_level_id_span(r#"{"id":null}"#), IdSpan::Found(6, 10));
        assert_eq!(top_level_id_span(r#"{"id":true}"#), IdSpan::Found(6, 10));
        // Whitespace tolerance around the colon and value. The span ends at
        // the delimiter, so pre-delimiter whitespace rides along — harmless:
        // restoration splices the exact same bytes back.
        assert_eq!(
            top_level_id_span(r#"{ "id" : 42 , "x":1}"#),
            IdSpan::Found(9, 12)
        );
        // Huge integer: the SPAN preserves the raw digits (no float damage).
        let big = r#"{"id":123456789012345678901234567890,"m":1}"#;
        let IdSpan::Found(s, e) = top_level_id_span(big) else {
            panic!("span expected")
        };
        assert_eq!(&big[s..e], "123456789012345678901234567890");
    }

    #[test]
    fn nested_and_value_ids_are_ignored() {
        // "id" inside params must NOT be picked up.
        assert_eq!(
            top_level_id_span(r#"{"method":"m","params":{"id":"nested"},"id":9}"#),
            IdSpan::Found(44, 45)
        );
        // "id" inside an ARRAY element object likewise.
        let line = r#"{"params":[{"id":1},{"id":2}]}"#;
        assert_eq!(top_level_id_span(line), IdSpan::Absent);
        // The literal "id" as a VALUE of another key is not a key.
        assert_eq!(
            top_level_id_span(r#"{"method":"id","params":{}}"#),
            IdSpan::Absent
        );
        // An id-shaped key inside a STRING value does not confuse the scan.
        assert_eq!(
            top_level_id_span(r#"{"note":"{\"id\":3}","id":5}"#),
            IdSpan::Found(26, 27)
        );
    }

    #[test]
    fn duplicate_top_level_id_is_ambiguous_never_guessed() {
        assert_eq!(
            top_level_id_span(r#"{"id":1,"method":"m","id":2}"#),
            IdSpan::Ambiguous
        );
    }

    #[test]
    fn absent_id_detected_for_notifications() {
        assert_eq!(
            top_level_id_span(r#"{"jsonrpc":"2.0","method":"x"}"#),
            IdSpan::Absent
        );
        assert_eq!(top_level_id_span("{}"), IdSpan::Absent);
    }

    #[test]
    fn escaped_string_ids_splice_cleanly() {
        let line = r#"{"id":"a\"b","m":1}"#;
        let IdSpan::Found(s, e) = top_level_id_span(line) else {
            panic!("span expected")
        };
        assert_eq!(&line[s..e], r#""a\"b""#);
    }

    #[test]
    fn splice_preserves_everything_except_the_span() {
        let raw = r#"{"jsonrpc":"2.0","id":7,  "method":"tools/call"}"#;
        let IdSpan::Found(s, e) = top_level_id_span(raw) else {
            panic!("span expected")
        };
        let out = splice_span(raw, (s, e), r#""agp-deadbeef""#);
        assert_eq!(
            out, r#"{"jsonrpc":"2.0","id":"agp-deadbeef",  "method":"tools/call"}"#,
            "everything outside the id span must be byte-identical"
        );
    }

    // ---- id table ----------------------------------------------------------

    fn fixed_rng(pattern: u8) -> Rng {
        let mut counter = 0u64;
        Box::new(move || {
            counter += 1;
            let mut b = [pattern; 16];
            b[..8].copy_from_slice(&counter.to_le_bytes());
            Ok(b)
        })
    }

    fn failing_rng() -> Rng {
        Box::new(|| Err("device gone".to_string()))
    }

    #[test]
    fn minted_ids_are_prefixed_unique_hex() {
        let mut t = IdRewriter::with_sources(Box::new(Instant::now), fixed_rng(0xab));
        let p1 = t.register("1".into(), false).expect("reg");
        let p2 = t.register("2".into(), false).expect("reg");
        for p in [&p1, &p2] {
            let unquoted = p.trim_matches('"');
            assert!(unquoted.starts_with(PROXY_ID_PREFIX), "{p}");
            assert_eq!(unquoted.len(), PROXY_ID_PREFIX.len() + 32, "{p}");
            assert!(unquoted[4..].bytes().all(|c| c.is_ascii_hexdigit()), "{p}");
        }
        assert_ne!(p1, p2, "ids must be unique");
        assert_eq!(t.pending_len(), 2);
    }

    #[test]
    fn resolve_accepts_exactly_once_then_classifies_replay() {
        let mut t = IdRewriter::with_sources(Box::new(Instant::now), fixed_rng(1));
        let quoted = t.register("9".into(), true).expect("reg");
        let pid = quoted.trim_matches('"').to_string();

        let e = t.resolve(&pid).expect("first resolve");
        assert_eq!(e.host_id_raw, "9");
        assert!(e.is_tools_list);

        assert!(t.resolve(&pid).is_none(), "duplicate must be rejected");
        assert!(
            t.recently_consumed(&pid),
            "duplicate must be CLASSIFIED as a replay"
        );
    }

    #[test]
    fn unknown_foreign_ids_resolve_to_nothing() {
        let mut t = IdRewriter::default();
        assert!(t.resolve("agp-does-not-exist").is_none());
        assert!(!t.recently_consumed("agp-does-not-exist"));
    }

    #[test]
    fn replay_after_ttl_expiry_still_drops_but_loses_the_replay_label() {
        // Manual mutable clock shared with the test.
        let start = Instant::now();
        let shared_now = std::sync::Arc::new(std::sync::Mutex::new(start));
        let clock_box: Clock = {
            let s = std::sync::Arc::clone(&shared_now);
            Box::new(move || *s.lock().unwrap())
        };
        let mut t = IdRewriter::with_sources(clock_box, fixed_rng(2));
        let quoted = t.register("3".into(), false).expect("reg");
        let pid = quoted.trim_matches('"').to_string();

        assert!(t.resolve(&pid).is_some());

        // Advance past the TTL: the sweep (triggered by further ops) evicts.
        *shared_now.lock().unwrap() += Duration::from_secs(61);
        for i in 0..PRUNE_INTERVAL_OPS {
            let _ = t.register(format!("x{}", i), false);
        }
        assert!(
            !t.recently_consumed(&pid),
            "after TTL + sweep the replay label expires"
        );
        assert!(t.resolve(&pid).is_none(), "but the id is still unusable");
    }

    #[test]
    fn saturation_answers_overloaded_without_registering() {
        let mut t = IdRewriter::with_sources(Box::new(Instant::now), fixed_rng(3));
        for i in 0..MAX_PENDING_REQUESTS {
            t.register(i.to_string(), false)
                .unwrap_or_else(|e| panic!("register {i} failed: {e:?}"));
        }
        assert_eq!(t.pending_len(), MAX_PENDING_REQUESTS);
        assert_eq!(
            t.register("overflow".into(), false),
            Err(RegisterError::Overloaded)
        );
    }

    #[test]
    fn rng_failure_denies_fail_closed() {
        let mut t = IdRewriter::with_sources(Box::new(Instant::now), failing_rng());
        assert_eq!(
            t.register("1".into(), false),
            Err(RegisterError::RngUnavailable("device gone".to_string()))
        );
        assert_eq!(t.pending_len(), 0, "nothing may be half-registered");
    }

    // ---- response classification -------------------------------------------

    #[test]
    fn classify_routes_notifications_strings_and_hostiles() {
        // Notification / server-initiated: passthrough.
        assert_eq!(classify_response_id(&json!({"method":"x"})), Ok(None));
        // Our namespace: resolvable.
        assert_eq!(
            classify_response_id(&json!({"id": "agp-aabbccdd", "result": {}})),
            Ok(Some("agp-aabbccdd".to_string()))
        );
        // Hostile shapes: must be dropped by the caller.
        assert!(classify_response_id(&json!({"id": 7, "result": {}})).is_err());
        assert!(classify_response_id(&json!({"id": null, "result": {}})).is_err());
        assert!(classify_response_id(&json!({"id": ["agp-x"], "result": {}})).is_err());
        assert!(
            classify_response_id(&json!({"id": "client-7", "result": {}})).is_err(),
            "foreign-prefixed string ids are not our mints"
        );
    }
}
