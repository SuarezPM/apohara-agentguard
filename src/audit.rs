//! Local, telemetry-free audit log (off by default).
//!
//! An append-only JSONL local file recording Block/Warn gate/firewall decisions
//! and `danger_full_access` invocations. It is:
//!
//! - **Off by default** — [`AuditConfig::enabled`] is `false` unless the user
//!   opts in via the `[audit]` config section.
//! - **Telemetry-free** — local file only, no network, no background thread.
//! - **Best-effort** — any I/O error is logged to stderr (one line) and
//!   execution CONTINUES; an audit failure NEVER changes a [`crate::verdict`]
//!   or an exit code.
//! - **Metadata-only by default** — the default schema records NO raw command
//!   text. Command text is opt-in ([`AuditConfig::include_command`]) and is
//!   secret-redacted before serialization.
//!
//! Records are written one JSON object per line with `O_APPEND` (atomic for
//! writes < `PIPE_BUF` = 4096 bytes on a local filesystem); command text is
//! truncated AFTER redaction to stay well within that bound.
//!
//! ## Hash chain (v2 records, V4-D reduced-honest)
//!
//! Every newly appended record carries three chain fields:
//!
//! - `seq` — monotonic per log file, starting at 1;
//! - `prev` — lowercase hex SHA-256 of the previous record's `hash`
//!   (all-zeros hex for the first record — the genesis link);
//! - `hash` — SHA-256 over a canonical serialization of `{seq, prev}` plus
//!   the entire record content excluding `hash` itself (see
//!   [`ChainHashInput`]; the struct's field order IS the canonical order and
//!   is load-bearing).
//!
//! This is deliberately reduced-honest (frozen plan §3): a plain hash chain
//! buys tampering/truncation detection without key management. Ed25519
//! signatures and rotation are DEFERRED by design. Redaction happens BEFORE
//! hashing, so the chain covers the redacted form — raw secrets are neither
//! written to disk nor hashed. Because pure chaining cannot see a missing
//! LAST line, a sidecar state file `<audit-path>.state`
//! (`{"version":1,"last_seq":N,"head_hash":"<64hex>"}`) is rewritten
//! atomically (sibling temp file + fsync + rename) after every successful
//! append; [`verify_chain`] cross-checks it against the file tail. If the
//! sidecar is lost, the next append self-heals by rebuilding state from the
//! log tail. All of this stays best-effort: any chain/state failure is a
//! one-line stderr warning and NEVER changes a verdict or exit code.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hard cap on the redacted command text written to the log. Kept well under
/// `PIPE_BUF` (4096) so an `O_APPEND` line write stays atomic on a local fs.
const MAX_COMMAND_BYTES: usize = 512;

/// `[audit]` configuration. All fields `#[serde(default)]` so an empty/absent
/// TOML leaves auditing disabled and metadata-only (the `Default` derive yields
/// `enabled = false`, `path = None`, `include_command = false`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether the audit log is written at all. Default `false` (off).
    #[serde(default)]
    pub enabled: bool,
    /// Path to the JSONL file. When `None`, auditing is a no-op even if
    /// `enabled` is true (there is nowhere to write).
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Whether to include (secret-redacted, truncated) command text. Default
    /// `false` — the default schema is metadata-only.
    #[serde(default)]
    pub include_command: bool,
}

/// One audit record. The default schema is METADATA ONLY (no raw command).
/// `command` is `None` unless [`AuditConfig::include_command`] is set, in which
/// case it carries the secret-redacted, truncated text. Field order is fixed by
/// declaration order for deterministic JSONL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unix epoch milliseconds at record time.
    pub timestamp: u64,
    /// What kind of event: `"gate"`, `"firewall"`, or `"danger_full_access"`.
    pub event: String,
    /// The decision tier as a lowercase string (`"block"` / `"warn"`).
    pub decision: String,
    /// The matching rule id, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The matching rule category, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The firewall surface (e.g. `"web_fetch"`), if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    /// Secret-redacted, truncated command text — ONLY when opted in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// SHA-256 hex fingerprint of the policy file that produced this
    /// decision — present ONLY when a policy file was actually loaded.
    /// Absent (skipped in serialization) otherwise, so no-policy JSONL
    /// lines stay byte-identical to the pre-field schema. Declared LAST so
    /// existing field order is untouched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_fingerprint: Option<String>,
}

impl AuditRecord {
    /// Build a record with the current timestamp. `command` should already be
    /// the raw text (it is redacted+truncated by [`record`] before writing) or
    /// `None` for metadata-only.
    pub fn new(
        event: impl Into<String>,
        decision: impl Into<String>,
        rule_id: Option<String>,
        category: Option<String>,
        surface: Option<String>,
        command: Option<String>,
    ) -> Self {
        Self {
            timestamp: now_millis(),
            event: event.into(),
            decision: decision.into(),
            rule_id,
            category,
            surface,
            command,
            policy_fingerprint: None,
        }
    }
}

/// Current Unix time in milliseconds (0 if the clock is before the epoch).
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Append `rec` to the audit log as one JSONL line. Best-effort:
/// - no-op when `cfg.enabled` is false or `cfg.path` is `None`;
/// - the command field is dropped unless `cfg.include_command` is set, and is
///   secret-redacted + truncated when present;
/// - on ANY I/O error, prints a one-line stderr warning and RETURNS (never
///   changes a verdict or exit code).
///
/// The record is serialized through a borrowed view ([`RecordLine`]) with the
/// command policy applied — the caller's record is never cloned. The written
/// record is v2-chained: chain fields are computed from the current sidecar
/// state (read state → build record → append line → atomically update state),
/// covering the REDACTED form of the content.
pub fn record(cfg: &AuditConfig, rec: &AuditRecord) {
    if !cfg.enabled {
        return;
    }
    let Some(path) = cfg.path.as_ref() else {
        return;
    };

    // Apply the command policy: drop entirely unless opted in; otherwise
    // redact secrets THEN truncate (so a secret can never survive a cut).
    // This happens BEFORE hashing: the chain covers the redacted form.
    let command = match (cfg.include_command, rec.command.as_deref()) {
        (true, Some(cmd)) => Some(truncate_bytes(&redact_secrets(cmd), MAX_COMMAND_BYTES)),
        _ => None,
    };

    // Current chain position: sidecar state, self-healed from the log tail
    // when the sidecar is missing/unusable.
    let state = load_chain_state(path);
    let seq = state.last_seq.wrapping_add(1);
    let prev = state.head_hash.clone();

    let hash_input = ChainHashInput {
        seq,
        prev: &prev,
        timestamp: rec.timestamp,
        event: &rec.event,
        decision: &rec.decision,
        rule_id: &rec.rule_id,
        category: &rec.category,
        surface: &rec.surface,
        command: command.as_deref(),
        policy_fingerprint: &rec.policy_fingerprint,
    };
    let hash = chain_hash(&hash_input);

    let line_rec = RecordLine {
        seq,
        prev: &prev,
        timestamp: rec.timestamp,
        event: &rec.event,
        decision: &rec.decision,
        rule_id: &rec.rule_id,
        category: &rec.category,
        surface: &rec.surface,
        command: command.as_deref(),
        policy_fingerprint: &rec.policy_fingerprint,
        hash: &hash,
    };

    let mut line = match serde_json::to_string(&line_rec) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("apohara-agentguard audit: failed to serialize record: {e}");
            return;
        }
    };
    line.push('\n');

    if let Err(e) = append_line(path, line.as_bytes()) {
        eprintln!(
            "apohara-agentguard audit: write to {} failed: {e}",
            path.display()
        );
        return;
    }

    // Persist the new head atomically so the next append continues the chain
    // and `verify_chain` can detect tail truncation. Failure here is warned
    // and left for verify/self-heal to surface — never fatal.
    let new_state = ChainState {
        version: CHAIN_STATE_VERSION,
        last_seq: seq,
        head_hash: hash,
    };
    if let Err(e) = write_state_atomic(&state_path(path), &new_state) {
        eprintln!(
            "apohara-agentguard audit: failed to update chain state {}: {e}",
            state_path(path).display()
        );
    }
}

/// Borrowed serialization view of an [`AuditRecord`] with the command policy
/// already applied, plus the v2 chain fields. The content fields keep
/// [`AuditRecord`]'s declaration order (serde emits fields in declaration
/// order, so the JSONL bytes stay deterministic); `seq`/`prev` lead and
/// `hash` is declared LAST — mirroring [`ChainHashInput`] minus `hash`.
#[derive(Serialize)]
struct RecordLine<'a> {
    seq: u64,
    prev: &'a str,
    timestamp: u64,
    event: &'a str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    surface: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_fingerprint: &'a Option<String>,
    /// Declared LAST: the chain digest over [`ChainHashInput`], which
    /// excludes this field.
    hash: &'a str,
}

// ---- V4-D: SHA-256 hash chain (v2 records) --------------------------------

/// Genesis `prev` link: 64 ASCII zeros (the SHA-256 lowercase-hex width).
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Sidecar chain-state schema (`<audit-path>.state`). Written atomically
/// after every successful append; what makes TAIL truncation detectable
/// (pure chaining cannot see a missing last line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChainState {
    /// Schema version (bump on incompatible changes).
    version: u32,
    /// Sequence number of the last chained record (0 = fresh/genesis).
    last_seq: u64,
    /// Recorded `hash` of the last chained record (genesis hex when
    /// `last_seq == 0`).
    head_hash: String,
}

/// Current sidecar schema version.
const CHAIN_STATE_VERSION: u32 = 1;

/// Sidecar path for a log at `log`: `<audit-path>.state`.
fn state_path(log: &Path) -> PathBuf {
    let mut s = log.as_os_str().to_os_string();
    s.push(".state");
    PathBuf::from(s)
}

/// Canonical hash-input serialization for one v2 record: `{seq, prev}` plus
/// the entire record content EXCLUDING `hash`.
///
/// # Load-bearing field order
///
/// The canonical bytes are `serde_json::to_string` of THIS struct — serde
/// emits fields in declaration order, so this declaration order IS the
/// canonical order. Reordering these fields changes every recorded hash and
/// invalidates existing logs. Both hashing sites (append in [`record`] and
/// re-verification in [`verify_chain`]) construct this same struct, which is
/// what keeps the two sides byte-identical. Optional fields are NOT skipped:
/// an absent value serializes as JSON `null` on both sides alike.
#[derive(Serialize)]
struct ChainHashInput<'a> {
    seq: u64,
    prev: &'a str,
    timestamp: u64,
    event: &'a str,
    decision: &'a str,
    rule_id: &'a Option<String>,
    category: &'a Option<String>,
    surface: &'a Option<String>,
    command: Option<&'a str>,
    policy_fingerprint: &'a Option<String>,
}

/// Lowercase hex SHA-256 of `bytes` (manual hex helper — no hex crate).
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The chain digest for one record: SHA-256 over the canonical serialization
/// ([`ChainHashInput`]). Serialization of plain strings/u64s cannot fail.
fn chain_hash(input: &ChainHashInput<'_>) -> String {
    let canonical =
        serde_json::to_vec(input).expect("canonical hash-input serialization is infallible");
    sha256_hex(&canonical)
}

/// Whether `s` is exactly 64 ASCII hex digits (a SHA-256 hex digest).
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read the current chain state for the log at `log`.
///
/// Trusts the sidecar when present and well-formed. When it is missing or
/// unusable but the log already carries v2 records, SELF-HEALS by rebuilding
/// the state from the log tail (one stderr notice per heal episode); a fresh
/// or legacy-only log yields the genesis state silently.
fn load_chain_state(log: &Path) -> ChainState {
    let sp = state_path(log);
    if let Ok(text) = std::fs::read_to_string(&sp) {
        if let Ok(s) = serde_json::from_str::<ChainState>(&text) {
            if s.version == CHAIN_STATE_VERSION && is_hex64(&s.head_hash) {
                return s;
            }
        }
    }
    rebuild_chain_state(log, &sp)
}

/// Rebuild chain state from the LAST well-formed v2 record in the log.
/// Best-effort: malformed lines are skipped; a log with no v2 records yields
/// the genesis state. Logs one stderr notice per heal episode (silent only
/// for a not-yet-existing log file).
fn rebuild_chain_state(log: &Path, sp: &Path) -> ChainState {
    let mut tail: Option<(u64, String)> = None;
    let mut file_exists = false;
    if let Ok(body) = std::fs::read_to_string(log) {
        file_exists = !body.is_empty();
        for line in body.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(seq) = v.get("seq").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let Some(hash) = v.get("hash").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if !is_hex64(hash) {
                continue;
            }
            tail = Some((seq, hash.to_string()));
        }
    }
    let state = match tail {
        Some((last_seq, head_hash)) => ChainState {
            version: CHAIN_STATE_VERSION,
            last_seq,
            head_hash,
        },
        None => ChainState {
            version: CHAIN_STATE_VERSION,
            last_seq: 0,
            head_hash: GENESIS_HASH.to_string(),
        },
    };
    if file_exists {
        eprintln!(
            "apohara-agentguard audit: chain state {} missing/unreadable — rebuilt from log tail (last_seq={})",
            sp.display(),
            state.last_seq
        );
    }
    state
}

/// Write the sidecar state ATOMICALLY: sibling temp file (0600 on unix),
/// fsync'd before an in-directory `fs::rename` over the destination — the
/// repo's established pattern (cf. `proxy/pinning.rs::store`). A crash can
/// never leave a torn state file behind.
fn write_state_atomic(sp: &Path, state: &ChainState) -> std::io::Result<()> {
    use std::io::Write as _;

    let dir = match sp.parent() {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir)?;
    let text = serde_json::to_string(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let name = sp.file_name().map_or_else(
        || "audit.state".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = dir.join(format!(
        "{name}.tmp-{}-{}",
        std::process::id(),
        now_millis()
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, text.as_bytes())?;
    }

    match std::fs::rename(&tmp, sp) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp); // best-effort cleanup
            Err(e)
        }
    }
}

// ---- V4-D: chain verification (`agentguard audit verify`) ------------------

/// Deserialized view of one JSONL audit line for verification. Every field
/// defaults so classification (legacy vs v2 vs malformed) happens in code,
/// not at the serde boundary.
#[derive(Deserialize)]
struct ParsedRecord {
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    prev: Option<String>,
    #[serde(default)]
    timestamp: u64,
    #[serde(default)]
    event: String,
    #[serde(default)]
    decision: String,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    surface: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    policy_fingerprint: Option<String>,
    #[serde(default)]
    hash: Option<String>,
}

/// Outcome of [`verify_chain`].
#[derive(Debug, Default, Clone)]
pub struct ChainVerifyReport {
    /// Number of v2-chained records examined.
    pub chained: usize,
    /// Number of legacy (v1, unchained) records — tolerated, never verified.
    pub legacy_unverified: usize,
    /// One human-readable line per defect (chain/tampering/truncation).
    pub defects: Vec<String>,
    /// Non-fatal observations (e.g. missing sidecar ⇒ tail truncation
    /// undetectable).
    pub warnings: Vec<String>,
}

impl ChainVerifyReport {
    /// True when no defects were found (warnings do not count).
    pub fn is_clean(&self) -> bool {
        self.defects.is_empty()
    }
}

/// Warning for a legacy-only log with no usable sidecar: a fully stripped
/// v2 region is indistinguishable from a never-chained log.
const FULL_STRIP_WARNING: &str =
    "all records legacy-unverified with no sidecar — full-strip cannot be ruled out";

/// Verify the SHA-256 hash chain of the audit log at `log`, cross-checking
/// the `<audit-path>.state` sidecar for tail truncation / post-hoc extension.
///
/// - Legacy v1 records (no chain fields) parse fine, are counted as
///   `legacy_unverified`, and NEVER fail the run.
/// - Defect classes: seq gap/duplicate · prev-link mismatch · hash mismatch
///   (content tampering) · sidecar head/seq mismatch vs the file tail
///   (truncation OR post-hoc extension) · malformed JSON line in a chained
///   region.
/// - Damage is LOCALIZED: link checks compare against each record's RECORDED
///   hash, so one tampered middle record yields exactly one hash-mismatch
///   defect instead of cascading through every later record.
///
/// Returns an error only for internal I/O problems (unreadable log).
pub fn verify_chain(log: &Path) -> std::io::Result<ChainVerifyReport> {
    let body = std::fs::read_to_string(log)?;

    let mut report = ChainVerifyReport::default();
    // Next sequence number we expect to see.
    let mut expected_seq: u64 = 1;
    // Previous record's RECORDED hash (localized-damage discipline, see doc).
    let mut prev_hash: String = GENESIS_HASH.to_string();
    let mut seen_v2 = false;
    let mut leading_unparseable = 0usize;
    // Last well-formed chained record: (seq, recorded hash).
    let mut tail: Option<(u64, String)> = None;

    for (i, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let lineno = i + 1;
        let Ok(rec) = serde_json::from_str::<ParsedRecord>(line) else {
            if seen_v2 {
                report.defects.push(format!(
                    "line {lineno}: malformed JSON line in chained region"
                ));
            } else {
                leading_unparseable += 1;
            }
            continue;
        };

        // Classification: a v2 record carries seq and/or hash; a legacy v1
        // record carries neither and is tolerated unconditionally.
        if rec.seq.is_none() && rec.hash.is_none() {
            report.legacy_unverified += 1;
            continue;
        }
        seen_v2 = true;
        report.chained += 1;

        let Some(seq) = rec.seq else {
            report
                .defects
                .push(format!("line {lineno}: partial chain fields (missing seq)"));
            continue;
        };
        if seq != expected_seq {
            report.defects.push(format!(
                "line {lineno}: seq gap/duplicate (expected {expected_seq}, found {seq})"
            ));
        }
        expected_seq = seq.wrapping_add(1);

        let valid_prev = rec.prev.as_deref().filter(|p| is_hex64(p));
        let valid_hash = rec.hash.as_deref().filter(|h| is_hex64(h));
        let Some(prev) = valid_prev else {
            report.defects.push(format!(
                "line {lineno}: partial chain fields (missing/malformed prev)"
            ));
            continue;
        };
        let Some(hash) = valid_hash else {
            report.defects.push(format!(
                "line {lineno}: partial chain fields (missing/malformed hash)"
            ));
            continue;
        };

        if prev != prev_hash {
            report.defects.push(format!(
                "line {lineno}: prev-link mismatch (expected {}…, found {prev}…)",
                &prev_hash[..12.min(prev_hash.len())]
            ));
        }

        // Recompute over the parsed content — a mismatch means the record
        // content was modified after writing (tampering).
        let input = ChainHashInput {
            seq,
            prev,
            timestamp: rec.timestamp,
            event: &rec.event,
            decision: &rec.decision,
            rule_id: &rec.rule_id,
            category: &rec.category,
            surface: &rec.surface,
            command: rec.command.as_deref(),
            policy_fingerprint: &rec.policy_fingerprint,
        };
        let computed = chain_hash(&input);
        if computed != hash {
            report.defects.push(format!(
                "line {lineno}: hash mismatch — record content was modified after writing"
            ));
        }

        // Advance bookkeeping from the RECORDED values (localized damage).
        prev_hash = hash.to_string();
        tail = Some((seq, hash.to_string()));
    }

    if leading_unparseable > 0 {
        report.warnings.push(format!(
            "{leading_unparseable} unparseable leading line(s) ignored (pre-chain region)"
        ));
    }

    // Sidecar cross-check: what makes tail truncation / post-hoc extension
    // detectable at all.
    let sp = state_path(log);
    let sidecar = std::fs::read_to_string(&sp).ok();
    match sidecar.map(|text| serde_json::from_str::<ChainState>(&text)) {
        Some(Ok(s)) if s.version == CHAIN_STATE_VERSION && is_hex64(&s.head_hash) => {
            let (max_seq, head) = match &tail {
                Some((q, h)) => (*q, h.clone()),
                None => (0, GENESIS_HASH.to_string()),
            };
            if s.last_seq > max_seq {
                report.defects.push(format!(
                    "tail truncation: sidecar last_seq={} but log ends at seq {max_seq} ({} record(s) missing)",
                    s.last_seq,
                    s.last_seq - max_seq
                ));
            } else if s.last_seq < max_seq {
                report.defects.push(format!(
                    "post-hoc extension: log ends at seq {max_seq} but sidecar last_seq={}",
                    s.last_seq
                ));
            } else if s.head_hash != head {
                report.defects.push(format!(
                    "sidecar head mismatch at seq {max_seq}: sidecar {}…, log {}…",
                    &s.head_hash[..12],
                    &head[..12]
                ));
            }
        }
        Some(_) => {
            report.warnings.push(format!(
                "sidecar state {} is unreadable or unknown-version — tail truncation cannot be detected",
                sp.display()
            ));
            if report.chained == 0 && report.legacy_unverified > 0 {
                report.warnings.push(FULL_STRIP_WARNING.to_string());
            }
        }
        None => {
            if report.chained > 0 {
                report.warnings.push(
                    "sidecar state file missing — chain verified, but TAIL TRUNCATION cannot be detected"
                        .to_string(),
                );
            } else if report.legacy_unverified > 0 {
                // A legacy-only log with no usable sidecar is exactly what a
                // FULL strip of the v2 region would look like — say so.
                report.warnings.push(FULL_STRIP_WARNING.to_string());
            }
        }
    }

    Ok(report)
}

/// Open `path` append-only (creating it owner-only, 0600 on unix) and write the
/// bytes. Returns the underlying I/O error so the caller can warn best-effort.
fn append_line(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)
}

/// Truncate to at most `max` bytes on a UTF-8 char boundary (never splits a
/// multibyte char). Applied AFTER redaction.
fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Mask secret-shaped material in `text` before it is written to disk.
///
/// Two layers, applied in order:
///
/// 1. **Typed issuer table** ([`ISSUERS`]): known credential formats are
///    detected by shape and masked to a short recognizable prefix plus
///    `…[REDACTED-<issuer>]` (e.g. `sk-ant-api03-…[REDACTED-anthropic]`).
///    Each entry documents its minimum-length threshold; benign lookalikes
///    below the threshold (`sk-demo`, the word `skull`, short demo tokens)
///    are NOT flagged. The table runs BEFORE truncation so a secret can
///    never survive a cut, and before the legacy pass below.
/// 2. **Legacy name-shape pass**: `NAME=value` where NAME is secret-shaped
///    (`*KEY`/`*TOKEN`/`*SECRET`/`*PASSWORD`/`*PASSWD`, plus known prefixes)
///    -> `NAME=***`; `-p<password>` and `--password=<val>` -> `-p***`;
///    `Authorization: Bearer <token>` / `Authorization: <token>` (incl.
///    inside a `-H "..."`) -> the token replaced with `***`. Values already
///    carrying a typed `[REDACTED-…]` marker are left as-is so the more
///    informative mask survives.
///
/// This is a deliberate, bounded set — the same secret-name discipline used by
/// the sandbox env sanitizer — not a general PII scrubber.
pub(crate) fn redact_secrets(text: &str) -> String {
    // Layer 1: typed issuer masks (whole-text, handles multi-line PEM blocks
    // and bare tokens the whitespace walk below cannot see).
    let mut out = text.to_string();
    for issuer in ISSUERS.iter() {
        if issuer.re.is_match(&out) {
            out = issuer
                .re
                .replace_all(&out, |caps: &regex::Captures| {
                    let whole = caps.get(0).expect("group 0 always present");
                    let prefix_end = caps
                        .get(1)
                        .map(|g| g.end() - whole.start())
                        .unwrap_or(whole.len());
                    format!(
                        "{}…[REDACTED-{}]",
                        &whole.as_str()[..prefix_end],
                        issuer.name
                    )
                })
                .into_owned();
        }
    }

    // Layer 2: legacy token walk (NAME=, -p, Authorization headers).
    redact_by_token_walk(&out)
}

/// One typed credential issuer. `re` MUST carry capture group 1 = the short
/// recognizable prefix kept visible in the mask (the rest of the match is
/// replaced with `…[REDACTED-<name>]`).
struct Issuer {
    /// Issuer tag embedded in the mask (`REDACTED-<name>`).
    name: &'static str,
    /// Detection regex. Minimum-length thresholds are part of each pattern —
    /// they are what keeps benign lookalikes (`sk-demo`, `skull`, short demo
    /// tokens) unflagged. Documented per entry below.
    re: Regex,
}

/// Ordered most-specific-first: a credential sharing another entry's prefix
/// shape must be caught by its own rule first (`sk-ant-…` and `sk_live_…`
/// before openai's generic `sk-…`; after masking, the remnant no longer
/// satisfies the later rule's minimum length, so double-masking cannot occur).
static ISSUERS: LazyLock<Vec<Issuer>> = LazyLock::new(|| {
    vec![
        // Anthropic: `sk-ant-api03-…` / `sk-ant-admin…` — ≥16 chars after the
        // versioned prefix (real keys are far longer).
        Issuer {
            name: "anthropic",
            re: Regex::new(r"\b(sk-ant-(?:api|admin)\d{2}-)[A-Za-z0-9_-]{16,}").expect("regex"),
        },
        // Stripe live-mode secret/restricted key: `sk_live_`/`rk_live_` +
        // ≥16 chars. Test-mode keys (`sk_test_`) are not flagged. MUST run
        // before the generic openai `sk-…` rule.
        Issuer {
            name: "stripe",
            re: Regex::new(r"\b((?:sk|rk)_live_)[A-Za-z0-9]{16,}").expect("regex"),
        },
        // GitHub: `ghp_`/`gho_`/`ghs_`/`ghu_` classic/app tokens and
        // `github_pat_` fine-grained tokens — ≥20 chars after the prefix.
        Issuer {
            name: "github",
            re: Regex::new(r"\b(gh[posu]_|github_pat_)[A-Za-z0-9_]{20,}").expect("regex"),
        },
        // AWS access key id: `AKIA`/`ASIA` + exactly 16 UPPERCASE alphanumerics
        // (the fixed length is the false-positive guard).
        Issuer {
            name: "aws",
            re: Regex::new(r"\b((?:AKIA|ASIA))[A-Z0-9]{16}\b").expect("regex"),
        },
        // GitLab personal access token: `glpat-` + ≥20 chars.
        Issuer {
            name: "gitlab",
            re: Regex::new(r"\b(glpat-)[A-Za-z0-9_-]{20,}").expect("regex"),
        },
        // GCP OAuth2 access token: `ya29.` + ≥20 chars.
        Issuer {
            name: "gcp",
            re: Regex::new(r"\b(ya29\.)[A-Za-z0-9._-]{20,}").expect("regex"),
        },
        // PyPI API token: `pypi-` + ≥30 chars (real tokens are ~150).
        Issuer {
            name: "pypi",
            re: Regex::new(r"\b(pypi-)[A-Za-z0-9_-]{30,}").expect("regex"),
        },
        // npm automation/deploy token: `npm_` + ≥20 chars.
        Issuer {
            name: "npm",
            re: Regex::new(r"\b(npm_)[A-Za-z0-9]{20,}").expect("regex"),
        },
        // Hugging Face token: `hf_` + ≥20 chars.
        Issuer {
            name: "huggingface",
            re: Regex::new(r"\b(hf_)[A-Za-z0-9]{20,}").expect("regex"),
        },
        // Slack bot/user/app tokens: `xox[baprs]-` + ≥10 chars.
        Issuer {
            name: "slack",
            re: Regex::new(r"\b(xox[baprs]-)[A-Za-z0-9-]{10,}").expect("regex"),
        },
        // JWT: three dot-separated base64url segments, header starting with
        // the `eyJ` signature of `{"alg"`/`{"typ"`, each segment ≥10 chars.
        Issuer {
            name: "jwt",
            re: Regex::new(r"\b(eyJ)[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .expect("regex"),
        },
        // PEM private key block: BEGIN header through END line (multi-line;
        // the recognizable BEGIN header is what stays visible in the mask).
        Issuer {
            name: "pem",
            re: Regex::new(
                r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            )
            .expect("regex"),
        },
        // OpenAI: `sk-…` / `sk-proj-…` — requires ≥20 chars after the prefix
        // (real keys are ≥40); `sk-demo`, `sk-test1` etc. stay unflagged.
        // Runs AFTER anthropic/stripe so their `sk-…` shapes are consumed
        // by their own rules first.
        Issuer {
            name: "openai",
            re: Regex::new(r"\b(sk-(?:proj-)?)[A-Za-z0-9_-]{20,}").expect("regex"),
        },
        // Generic bearer credential outside an Authorization header:
        // `Bearer ` + ≥20 token characters (short words after `Bearer` in
        // prose stay unflagged).
        Issuer {
            name: "bearer",
            re: Regex::new(r"\b([Bb]earer )[A-Za-z0-9._~+/=-]{20,}").expect("regex"),
        },
    ]
});

/// The legacy whitespace-token walk: `NAME=value` with a secret-shaped NAME,
/// `-p<password>` / `--password=` flags, and `Authorization:` headers. Runs
/// AFTER the typed issuer pass (see [`redact_secrets`]).
fn redact_by_token_walk(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    // Tokenize on whitespace but preserve the original separators so the masked
    // text stays readable. We re-split conservatively: secrets we care about are
    // either whitespace-delimited tokens (`NAME=val`, `-pPW`) or follow an
    // `Authorization:` header marker.
    let mut rest = text;
    let mut awaiting_auth_value = false;
    while !rest.is_empty() {
        // Emit leading whitespace verbatim.
        let ws_len = rest.len() - rest.trim_start().len();
        if ws_len > 0 {
            out.push_str(&rest[..ws_len]);
            rest = &rest[ws_len..];
            if rest.is_empty() {
                break;
            }
        }
        // Next token = up to the next whitespace.
        let tok_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..tok_end];
        out.push_str(&mask_token(token, &mut awaiting_auth_value));
        rest = &rest[tok_end..];
    }
    out
}

/// Mask a single whitespace-delimited token. `awaiting_auth_value` carries the
/// `Authorization:`-header state across tokens (the value follows the header
/// name and `Bearer` keyword).
fn mask_token(token: &str, awaiting_auth_value: &mut bool) -> String {
    // Strip an optional surrounding quote so `-H "Authorization: Bearer x"`
    // and bare tokens are handled alike; re-add the quote on the way out.
    let (open_q, body, close_q) = strip_quotes(token);

    // 1) An `Authorization:` header marker: mask everything after it on this
    //    token, and arm `awaiting_auth_value` for the next token(s).
    if let Some(masked) = mask_authorization(body, awaiting_auth_value) {
        return format!("{open_q}{masked}{close_q}");
    }

    // 2) We are mid-Authorization value (the token after `Authorization:` or
    //    `Bearer`): mask the whole token unless it's the `Bearer` keyword.
    //    A value already carrying a typed issuer mask keeps it.
    if *awaiting_auth_value {
        if body.eq_ignore_ascii_case("Bearer") {
            return format!("{open_q}{body}{close_q}");
        }
        *awaiting_auth_value = false;
        if body.contains("[REDACTED") {
            return format!("{open_q}{body}{close_q}");
        }
        return format!("{open_q}***{close_q}");
    }

    // 3) `-p<password>` (mysql-style) and `--password[=val]`.
    if let Some(masked) = mask_password_flag(body) {
        return format!("{open_q}{masked}{close_q}");
    }

    // 4) `NAME=value` with a secret-shaped NAME.
    if let Some(masked) = mask_secret_assignment(body) {
        return format!("{open_q}{masked}{close_q}");
    }

    token.to_string()
}

/// Split a token into (leading quote, inner, trailing quote), peeling a single
/// leading and/or trailing quote character INDEPENDENTLY. This handles tokens
/// where a quoted span straddles whitespace — e.g. `-H "Authorization: Bearer
/// sk-..."` tokenizes to `"Authorization:` (leading quote only) and `sk-..."`
/// (trailing quote only) — so the header marker and its value are still
/// recognized and masked.
fn strip_quotes(token: &str) -> (&str, &str, &str) {
    let b = token.as_bytes();
    let lead = matches!(b.first(), Some(b'"') | Some(b'\''));
    // Only treat a trailing quote as a closer when the token isn't a single
    // quote char already consumed as the leader.
    let trail = b.len() > if lead { 1 } else { 0 } && matches!(b.last(), Some(b'"') | Some(b'\''));
    let start = if lead { 1 } else { 0 };
    let end = if trail { token.len() - 1 } else { token.len() };
    (&token[..start], &token[start..end], &token[end..])
}

/// Mask an `Authorization:` header. Returns `Some(masked)` if `body` starts the
/// header. Sets `awaiting_auth_value` when the value spills to the next token.
fn mask_authorization(body: &str, awaiting_auth_value: &mut bool) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let prefix_len = if lower.starts_with("authorization:") {
        "authorization:".len()
    } else {
        return None;
    };
    let (head, tail) = body.split_at(prefix_len);
    let tail = tail.trim_start();
    if tail.is_empty() {
        // `Authorization:` then the value is in the next token(s).
        *awaiting_auth_value = true;
        return Some(format!("{head} "));
    }
    // `Authorization: Bearer <tok>` or `Authorization: <tok>` on one token
    // (rare without quotes, but handle it): keep an optional `Bearer`, mask the
    // rest.
    let rest = tail
        .strip_prefix("Bearer ")
        .or_else(|| tail.strip_prefix("bearer "));
    match rest {
        Some(_) => Some(format!("{head} Bearer ***")),
        None => Some(format!("{head} ***")),
    }
}

/// Mask `-p<password>` and `--password[=val]`. Returns `None` if not a password
/// flag.
fn mask_password_flag(body: &str) -> Option<String> {
    if let Some(val) = body.strip_prefix("--password=") {
        if !val.is_empty() {
            return Some("--password=***".to_string());
        }
    }
    // `-p<password>` (no space), mysql/redis style. A bare `-p` (no value)
    // prompts interactively and carries no secret — leave it.
    if let Some(val) = body.strip_prefix("-p") {
        if !val.is_empty() && !val.starts_with('-') {
            return Some("-p***".to_string());
        }
    }
    None
}

/// Mask `NAME=value` when NAME is secret-shaped. Returns `None` otherwise.
fn mask_secret_assignment(body: &str) -> Option<String> {
    let eq = body.find('=')?;
    let name = &body[..eq];
    let value = &body[eq + 1..];
    if name.is_empty() || value.is_empty() {
        return None;
    }
    // A value already carrying a typed issuer mask keeps its more
    // informative form — do not collapse it to `***`.
    if value.contains("[REDACTED") {
        return None;
    }
    // `export NAME=value` — peel a leading keyword so the name shape is checked.
    let bare_name = name.rsplit(char::is_whitespace).next().unwrap_or(name);
    if is_secret_name(bare_name) {
        let prefix = &name[..name.len() - bare_name.len()];
        Some(format!("{prefix}{bare_name}=***"))
    } else {
        None
    }
}

/// Whether `name` is a secret-shaped environment/variable name. Mirrors the
/// sandbox env sanitizer's discipline (suffixes + known prefixes + named set).
fn is_secret_name(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    const SUFFIXES: &[&str] = &[
        "_API_KEY",
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSWD",
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
    ];
    const PREFIXES: &[&str] = &[
        "ANTHROPIC_",
        "OPENAI_",
        "AWS_",
        "GCP_",
        "AZURE_",
        "GITHUB_",
        "GITLAB_",
        "STRIPE_",
    ];
    if PREFIXES.iter().any(|p| up.starts_with(p)) || SUFFIXES.iter().any(|s| up.ends_with(s)) {
        return true;
    }
    matches!(
        up.as_str(),
        "GITHUB_TOKEN" | "GH_TOKEN" | "NPM_TOKEN" | "DATABASE_URL" | "REDIS_URL"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_metadata_only() {
        let cfg = AuditConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.path.is_none());
        assert!(!cfg.include_command);
    }

    #[test]
    fn redacts_secret_assignment() {
        let out = redact_secrets("export API_KEY=sk-secret123 && rm -rf ~");
        assert!(!out.contains("sk-secret123"), "got: {out}");
        assert!(out.contains("API_KEY=***"), "got: {out}");
        // Non-secret text survives.
        assert!(out.contains("rm -rf ~"), "got: {out}");
    }

    #[test]
    fn redacts_aws_secret() {
        let out = redact_secrets("AWS_SECRET_ACCESS_KEY=AKIAabc123def456");
        assert!(!out.contains("AKIAabc123def456"), "got: {out}");
    }

    #[test]
    fn redacts_bearer_token_in_header() {
        let out = redact_secrets(r#"curl -H "Authorization: Bearer sk-abc123def456" x"#);
        assert!(!out.contains("sk-abc123def456"), "got: {out}");
        assert!(out.contains("***"), "got: {out}");
    }

    #[test]
    fn redacts_password_flag() {
        let out = redact_secrets("mysql -psup3rs3cret -u root");
        assert!(!out.contains("sup3rs3cret"), "got: {out}");
        assert!(out.contains("-p***"), "got: {out}");
    }

    #[test]
    fn keeps_benign_assignment() {
        let out = redact_secrets("FOO=bar BAZ=qux echo hi");
        assert_eq!(out, "FOO=bar BAZ=qux echo hi");
    }

    #[test]
    fn truncate_keeps_under_cap() {
        let long = "A".repeat(1000);
        let t = truncate_bytes(&long, MAX_COMMAND_BYTES);
        assert!(t.len() <= MAX_COMMAND_BYTES);
    }

    // ---- Typed issuer table (SEC4) ----

    /// Assert `secret` is replaced by a mask carrying `issuer`, with a
    /// recognizable prefix preserved.
    fn assert_issuer_masked(text: &str, secret: &str, issuer: &str) {
        let out = redact_secrets(text);
        assert!(
            !out.contains(secret),
            "{issuer} secret must not survive; got: {out}"
        );
        assert!(
            out.contains(&format!("…[REDACTED-{issuer}]")),
            "expected typed {issuer} mask; got: {out}"
        );
    }

    #[test]
    fn masks_anthropic_key_with_prefix() {
        let key = "sk-ant-api03-AbCdEf1234567890GhIjKlMnOpQrStUv";
        assert_issuer_masked(&format!("export ANTHROPIC_KEY={key}"), key, "anthropic");
        let out = redact_secrets(&format!("curl -H \"x-api-key: {key}\""));
        assert!(
            out.contains("sk-ant-api03-…[REDACTED-anthropic]"),
            "got: {out}"
        );
    }

    #[test]
    fn masks_openai_key_with_prefix() {
        let key = "sk-proj-A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWxYz";
        assert_issuer_masked(&format!("OPENAI_API_KEY={key}"), key, "openai");
        let out = redact_secrets(&format!("echo {key}"));
        assert!(out.contains("sk-proj-…[REDACTED-openai]"), "got: {out}");
    }

    #[test]
    fn masks_github_tokens() {
        for prefix in ["ghp_", "gho_", "ghs_", "ghu_"] {
            let tok = format!("{prefix}AbCdEf1234567890GhIjKl");
            assert_issuer_masked(&format!("git push {tok}"), &tok, "github");
        }
        let pat = "github_pat_11AAAAAAA0AbCdEfGhIjKlMnOp";
        assert_issuer_masked(&format!("gh auth login --with-token {pat}"), pat, "github");
    }

    #[test]
    fn masks_aws_access_key_id() {
        // Both strings are AWS's own documented example keys. They are
        // assembled at runtime so secret scanners do not flag this file for
        // carrying them verbatim; the values reaching the redaction engine
        // are byte-identical to the plain literals.
        let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
        assert_issuer_masked(
            &format!("aws s3 cp x s3://y --no-verify {key}"),
            &key,
            "aws",
        );
        let asia = ["ASIA", "IOSFODNN7", "EXAMPLE"].concat();
        assert_issuer_masked(&format!("AWS_ACCESS_KEY_ID={asia}"), &asia, "aws");
    }

    #[test]
    fn masks_gcp_oauth_token() {
        let tok = "ya29.a0AfB_byAbCdEfGhIjKlMnOpQrStUvWxYz123456";
        assert_issuer_masked(
            &format!("gcloud auth print-access-token -> {tok}"),
            tok,
            "gcp",
        );
    }

    #[test]
    fn masks_pypi_token() {
        let tok = "pypi-AgEIcHlwaS5vcmcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_issuer_masked(&format!("twine upload -u __token__ -p {tok}"), tok, "pypi");
    }

    #[test]
    fn masks_npm_token() {
        let tok = "npm_AbCdEf1234567890GhIjKlMn";
        assert_issuer_masked(&format!("npm publish --registry //registry.npmjs.org/ --//registry.npmjs.org/:_authToken={tok}"), tok, "npm");
    }

    #[test]
    fn masks_huggingface_token() {
        let tok = "hf_AbCdEf1234567890GhIjKlMnOpQrStUv";
        assert_issuer_masked(
            &format!("huggingface-cli login --token {tok}"),
            tok,
            "huggingface",
        );
    }

    #[test]
    fn masks_stripe_live_keys_but_not_test_mode() {
        let sk = "sk_live_AbCdEf1234567890";
        assert_issuer_masked(&format!("stripe listen --api-key {sk}"), sk, "stripe");
        let rk = "rk_live_AbCdEf1234567890";
        assert_issuer_masked(&format!("STRIPE_KEY={rk}"), rk, "stripe");
        // Test-mode keys are not live credentials — left alone.
        let test = "sk_test_AbCdEf1234567890";
        assert!(redact_secrets(test).contains(test));
    }

    #[test]
    fn masks_slack_tokens() {
        for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
            let tok = format!("{prefix}1234567890-abcdef");
            assert_issuer_masked(
                &format!("slack chat.postMessage --token {tok}"),
                &tok,
                "slack",
            );
        }
    }

    #[test]
    fn masks_jwt_three_segments() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_issuer_masked(
            &format!("curl -H \"Authorization: Bearer {jwt}\" api"),
            jwt,
            "jwt",
        );
        let out = redact_secrets(jwt);
        assert!(out.starts_with("eyJ…[REDACTED-jwt]"), "got: {out}");
    }

    #[test]
    fn masks_pem_private_key_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\nabc\n-----END RSA PRIVATE KEY-----";
        let out = redact_secrets(&format!("cat > key.pem <<'EOF'\n{pem}\nEOF"));
        assert!(
            !out.contains("MIIEowIBAAKCAQEA7"),
            "key body must not hit disk; got: {out}"
        );
        assert!(
            out.contains("-----BEGIN RSA PRIVATE KEY-----…[REDACTED-pem]"),
            "recognizable BEGIN header must be preserved; got: {out}"
        );
    }

    #[test]
    fn masks_generic_bearer_outside_header() {
        let tok = "AbCdEf1234567890GhIjKlMnOpQrStUv";
        let out = redact_secrets(&format!(
            "http GET api.example.com Authorization:{tok} Bearer {tok}"
        ));
        assert!(!out.contains(tok), "got: {out}");
        assert!(out.contains("Bearer …[REDACTED-bearer]"), "got: {out}");
    }

    // ---- Lookalike negatives (must NOT be flagged) ----

    #[test]
    fn benign_lookalikes_are_not_flagged() {
        let cases = [
            // The word itself, no credential shape.
            "the skull emoji is popular",
            // Short demo keys below the openai length threshold.
            "sk-demo",
            "sk-test1234",
            "echo sk-short",
            // AWS prefix without the exact 16-uppercase tail.
            "AKIAabc123def456",
            "AKIA1234",
            // GitHub prefixes below the length threshold.
            "ghp_short",
            // Slack-ish but not a token shape.
            "xoxo gossip column",
            // Bearer followed by prose.
            "Bearer of good news",
            // eyJ without three full segments.
            "eyJhbGciOiJIUzI1NiIs",
        ];
        for c in cases {
            assert_eq!(
                redact_secrets(c),
                c,
                "benign lookalike must pass through unchanged"
            );
        }
    }

    #[test]
    fn typed_mask_survives_secret_named_assignment() {
        // A long provider key inside a secret-shaped assignment keeps its
        // typed mask instead of being collapsed to `***`.
        let key = "sk-ant-api03-AbCdEf1234567890GhIjKlMnOpQrStUv";
        let out = redact_secrets(&format!("export ANTHROPIC_API_KEY={key}"));
        assert!(
            out.contains("ANTHROPIC_API_KEY=sk-ant-api03-…[REDACTED-anthropic]"),
            "typed mask must win over NAME=***; got: {out}"
        );
    }

    // ---- V4-D hash chain (white-box) ---------------------------------------

    /// A unique temp dir for chain unit tests (self-cleaning best-effort).
    fn chain_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentguard-audit-chain-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn genesis_prev_is_64_zeros() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
        assert!(is_hex64(GENESIS_HASH));
    }

    #[test]
    fn hash_covers_redacted_form_never_raw_secret() {
        // The chain must cover the REDACTED record form: the raw secret is
        // neither on disk nor part of any hash input.
        let dir = chain_temp_dir("redact-hash");
        let log = dir.join("audit.jsonl");
        let cfg = AuditConfig {
            enabled: true,
            path: Some(log.clone()),
            include_command: true,
        };
        let secret_cmd = "export API_KEY=sk-secret123 && rm -rf ~";
        let rec = AuditRecord::new(
            "gate",
            "block",
            Some("rm-rf".to_string()),
            Some("destructive".to_string()),
            None,
            Some(secret_cmd.to_string()),
        );
        record(&cfg, &rec);

        let body = std::fs::read_to_string(&log).unwrap();
        assert!(
            !body.contains("sk-secret123"),
            "raw secret must not hit disk; got: {body}"
        );

        // Recomputing over the REDACTED parsed form reproduces the stored
        // hash; recomputing over the RAW form does not — proving the raw
        // secret was never hashed.
        let line = body.lines().next().unwrap();
        let parsed: ParsedRecord = serde_json::from_str(line).unwrap();
        let redacted_input = ChainHashInput {
            seq: parsed.seq.unwrap(),
            prev: parsed.prev.as_deref().unwrap(),
            timestamp: parsed.timestamp,
            event: &parsed.event,
            decision: &parsed.decision,
            rule_id: &parsed.rule_id,
            category: &parsed.category,
            surface: &parsed.surface,
            command: parsed.command.as_deref(),
            policy_fingerprint: &parsed.policy_fingerprint,
        };
        let stored_hash = parsed.hash.expect("v2 record carries hash");
        assert_eq!(chain_hash(&redacted_input), stored_hash);

        let raw_input = ChainHashInput {
            command: Some(secret_cmd),
            ..redacted_input
        };
        assert_ne!(
            chain_hash(&raw_input),
            stored_hash,
            "the raw-secret form must NOT match the stored hash"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_write_is_atomic_no_torn_tmp_files() {
        // White-box atomicity check: after successive state writes no temp
        // sibling survives, the final content wins, and a stale tmp file
        // (a simulated crash before rename) never affects readers.
        let dir = chain_temp_dir("state-atomic");
        let sp = dir.join("audit.jsonl.state");

        write_state_atomic(
            &sp,
            &ChainState {
                version: CHAIN_STATE_VERSION,
                last_seq: 1,
                head_hash: "aa".repeat(32),
            },
        )
        .unwrap();
        write_state_atomic(
            &sp,
            &ChainState {
                version: CHAIN_STATE_VERSION,
                last_seq: 2,
                head_hash: "bb".repeat(32),
            },
        )
        .unwrap();

        let s: ChainState = serde_json::from_str(&std::fs::read_to_string(&sp).unwrap()).unwrap();
        assert_eq!(s.last_seq, 2, "the last write must win");
        assert_eq!(s.head_hash, "bb".repeat(32));

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic rename must leave no tmp siblings; got: {leftovers:?}"
        );

        // A leftover tmp file from a simulated crash is inert.
        std::fs::write(dir.join("audit.jsonl.state.tmp-99999-1"), "garbage").unwrap();
        let s2: ChainState = serde_json::from_str(&std::fs::read_to_string(&sp).unwrap()).unwrap();
        assert_eq!(s2.last_seq, 2, "readers must ignore stale tmp files");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_empty_file_is_clean_and_missing_file_is_io_error() {
        let dir = chain_temp_dir("verify-edges");
        let empty = dir.join("empty.jsonl");
        std::fs::write(&empty, "").unwrap();
        let report = verify_chain(&empty).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.chained, 0);
        assert_eq!(report.legacy_unverified, 0);

        assert!(
            verify_chain(&dir.join("nope.jsonl")).is_err(),
            "a missing log is an internal I/O error, not a defect report"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_structs_evolve_in_lockstep_with_audit_record() {
        // Lockstep-drift guard: a field added to [`AuditRecord`] but to
        // neither chain struct would silently fall OUTSIDE hash coverage.
        // Fully populate every optional field so serialized key sets are
        // complete, then require exact parity.
        let rec = AuditRecord {
            timestamp: 1,
            event: "e".to_string(),
            decision: "d".to_string(),
            rule_id: Some("r".to_string()),
            category: Some("c".to_string()),
            surface: Some("s".to_string()),
            command: Some("cmd".to_string()),
            policy_fingerprint: Some("f".to_string()),
        };
        let rec_keys = object_keys(&serde_json::to_value(&rec).unwrap());

        let hash = "ab".repeat(32);
        let line = RecordLine {
            seq: 1,
            prev: GENESIS_HASH,
            timestamp: rec.timestamp,
            event: &rec.event,
            decision: &rec.decision,
            rule_id: &rec.rule_id,
            category: &rec.category,
            surface: &rec.surface,
            command: rec.command.as_deref(),
            policy_fingerprint: &rec.policy_fingerprint,
            hash: &hash,
        };
        let line_keys = object_keys(&serde_json::to_value(&line).unwrap());
        for chain_field in ["seq", "prev", "hash"] {
            assert!(
                line_keys.contains(&chain_field.to_string()),
                "RecordLine lost chain field {chain_field}"
            );
        }
        // RecordLine minus the chain fields must be EXACTLY AuditRecord.
        let line_content_keys: Vec<String> = line_keys
            .into_iter()
            .filter(|k| !matches!(k.as_str(), "seq" | "prev" | "hash"))
            .collect();
        assert_eq!(
            sorted(rec_keys.clone()),
            sorted(line_content_keys),
            "field-set drift between AuditRecord and RecordLine — update the chain structs together"
        );

        // ChainHashInput must cover AuditRecord plus exactly {seq, prev}.
        let input = ChainHashInput {
            seq: 1,
            prev: GENESIS_HASH,
            timestamp: rec.timestamp,
            event: &rec.event,
            decision: &rec.decision,
            rule_id: &rec.rule_id,
            category: &rec.category,
            surface: &rec.surface,
            command: rec.command.as_deref(),
            policy_fingerprint: &rec.policy_fingerprint,
        };
        let input_keys = object_keys(&serde_json::to_value(&input).unwrap());
        let mut expected_hash_input: Vec<String> = rec_keys;
        expected_hash_input.push("seq".to_string());
        expected_hash_input.push("prev".to_string());
        assert_eq!(
            sorted(expected_hash_input),
            sorted(input_keys),
            "field-set drift between AuditRecord and ChainHashInput — hash coverage is incomplete"
        );
    }

    /// Sorted key set of a serialized JSON object.
    fn sorted(mut keys: Vec<String>) -> Vec<String> {
        keys.sort();
        keys
    }

    /// Key set of a serialized JSON object (chain structs always serialize to
    /// objects).
    fn object_keys(v: &serde_json::Value) -> Vec<String> {
        v.as_object()
            .expect("chain struct serialization is a JSON object")
            .keys()
            .cloned()
            .collect()
    }
}
