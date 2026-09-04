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

mod chain;
mod redact;

pub use chain::{verify_chain, ChainVerifyReport};

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use chain::{
    chain_hash, load_chain_state, state_path, write_state_atomic, ChainHashInput, ChainState,
    CHAIN_STATE_VERSION,
};
use redact::redact_secrets;

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

#[cfg(test)]
mod tests {
    use super::chain::{is_hex64, ParsedRecord, GENESIS_HASH};
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
