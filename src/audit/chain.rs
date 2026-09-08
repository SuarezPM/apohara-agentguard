//! V4-D SHA-256 hash chain for v2 audit records, plus the sidecar state and
//! the `audit verify` engine. Field order in [`ChainHashInput`] is
//! load-bearing: it IS the canonical hash serialization.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::now_millis;

// ---- V4-D: SHA-256 hash chain (v2 records) --------------------------------

/// Genesis `prev` link: 64 ASCII zeros (the SHA-256 lowercase-hex width).
pub(super) const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Sidecar chain-state schema (`<audit-path>.state`). Written atomically
/// after every successful append; what makes TAIL truncation detectable
/// (pure chaining cannot see a missing last line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ChainState {
    /// Schema version (bump on incompatible changes).
    pub(super) version: u32,
    /// Sequence number of the last chained record (0 = fresh/genesis).
    pub(super) last_seq: u64,
    /// Recorded `hash` of the last chained record (genesis hex when
    /// `last_seq == 0`).
    pub(super) head_hash: String,
}

/// Current sidecar schema version.
pub(super) const CHAIN_STATE_VERSION: u32 = 1;

/// Sidecar path for a log at `log`: `<audit-path>.state`.
pub(super) fn state_path(log: &Path) -> PathBuf {
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
pub(super) struct ChainHashInput<'a> {
    pub(super) seq: u64,
    pub(super) prev: &'a str,
    pub(super) timestamp: u64,
    pub(super) event: &'a str,
    pub(super) decision: &'a str,
    pub(super) rule_id: &'a Option<String>,
    pub(super) category: &'a Option<String>,
    pub(super) surface: &'a Option<String>,
    pub(super) command: Option<&'a str>,
    pub(super) policy_fingerprint: &'a Option<String>,
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
pub(super) fn chain_hash(input: &ChainHashInput<'_>) -> String {
    let canonical =
        serde_json::to_vec(input).expect("canonical hash-input serialization is infallible");
    sha256_hex(&canonical)
}

/// Whether `s` is exactly 64 ASCII hex digits (a SHA-256 hex digest).
pub(super) fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read the current chain state for the log at `log`.
///
/// Trusts the sidecar when present and well-formed. When it is missing or
/// unusable but the log already carries v2 records, SELF-HEALS by rebuilding
/// the state from the log tail (one stderr notice per heal episode); a fresh
/// or legacy-only log yields the genesis state silently.
pub(super) fn load_chain_state(log: &Path) -> ChainState {
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
pub(super) fn rebuild_chain_state(log: &Path, sp: &Path) -> ChainState {
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
pub(super) fn write_state_atomic(sp: &Path, state: &ChainState) -> std::io::Result<()> {
    #[cfg(unix)]
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
pub(super) struct ParsedRecord {
    #[serde(default)]
    pub(super) seq: Option<u64>,
    #[serde(default)]
    pub(super) prev: Option<String>,
    #[serde(default)]
    pub(super) timestamp: u64,
    #[serde(default)]
    pub(super) event: String,
    #[serde(default)]
    pub(super) decision: String,
    #[serde(default)]
    pub(super) rule_id: Option<String>,
    #[serde(default)]
    pub(super) category: Option<String>,
    #[serde(default)]
    pub(super) surface: Option<String>,
    #[serde(default)]
    pub(super) command: Option<String>,
    #[serde(default)]
    pub(super) policy_fingerprint: Option<String>,
    #[serde(default)]
    pub(super) hash: Option<String>,
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
