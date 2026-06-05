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

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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
pub fn record(cfg: &AuditConfig, rec: &AuditRecord) {
    if !cfg.enabled {
        return;
    }
    let Some(path) = cfg.path.as_ref() else {
        return;
    };

    // Apply the command policy: drop entirely unless opted in; otherwise
    // redact secrets THEN truncate (so a secret can never survive a cut).
    let mut rec = rec.clone();
    rec.command = match (cfg.include_command, rec.command.take()) {
        (true, Some(cmd)) => Some(truncate_bytes(&redact_secrets(&cmd), MAX_COMMAND_BYTES)),
        _ => None,
    };

    let mut line = match serde_json::to_string(&rec) {
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
    }
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

/// Mask secret-shaped material in `text` before it is written to disk. Covers:
/// - `NAME=value` where NAME is secret-shaped (`*KEY`/`*TOKEN`/`*SECRET`/
///   `*PASSWORD`/`*PASSWD`, plus the known prefixes) -> `NAME=***`;
/// - `-p<password>` and `--password=<val>` / `--password <val>` -> `-p***`;
/// - `Authorization: Bearer <token>` / `Authorization: <token>` (incl. inside a
///   `-H "..."`) -> the token replaced with `***`.
///
/// This is a deliberate, bounded set — the same secret-name discipline used by
/// the sandbox env sanitizer — not a general PII scrubber.
pub fn redact_secrets(text: &str) -> String {
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
    if *awaiting_auth_value {
        if body.eq_ignore_ascii_case("Bearer") {
            return format!("{open_q}{body}{close_q}");
        }
        *awaiting_auth_value = false;
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
}
