//! Canary sentinel: exfiltration-by-effect detection (US-Bemit / US-Bscan).
//!
//! OPT-IN, off by default. When `[canary] enabled = true`, apohara-agentguard
//! emits a random sentinel into the session context at `SessionStart`
//! ([`emit_token`]) and later warns — *after the fact* — if that same sentinel
//! appears verbatim in tool output ([`read_token`] + a `contains` scan in the
//! PostToolUse path). This DETECTS-and-WARNS only; it never blocks and makes no
//! prevention claim.
//!
//! ## Token
//! A >=128-bit sentinel rendered as 32 lowercase hex chars, derived by hashing
//! `pid || session_id || a process-local counter || a nanosecond timestamp`
//! with the already-vendored `sha2` (NO new dependency, NO `rand`). This is not
//! a cryptographic secret — it only needs to be unguessable-enough and unique
//! per session so a verbatim echo is a meaningful signal.
//!
//! ## Persistence
//! The token is written to `${TMPDIR:-/tmp}/agentguard/canary-<session_id>` so
//! the SessionStart emitter and the PostToolUse scanner (separate hook
//! invocations / processes) share it. On unix the directory is created `0700`
//! and the file `0600`. On non-unix the permission hardening is skipped (the
//! mechanism still works); if persistence fails for any reason the canary
//! degrades to *unavailable* (a silent no-op), never an error.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Process-local monotonic counter feeding token entropy. Combined with pid +
/// session_id + a nanosecond timestamp it keeps tokens distinct per session
/// even within a single process.
static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Number of hex chars in a token. 32 hex = 128 bits.
const TOKEN_HEX_LEN: usize = 32;

/// Generate, persist, and return the canary sentinel for `session_id`.
///
/// Best-effort: if the token cannot be persisted (e.g. an unwritable TMPDIR)
/// the freshly generated sentinel is still returned so the caller may seed the
/// session context — the later scan simply won't have a stored token to match.
pub(crate) fn emit_token(session_id: &str) -> String {
    let token = generate_token(session_id);
    let _ = persist_token(session_id, &token);
    token
}

/// Read the persisted canary sentinel for `session_id`, if one exists and looks
/// like a token. Returns `None` when no token was emitted, the file is absent,
/// or it cannot be read (the canary then simply does not fire).
pub(crate) fn read_token(session_id: &str) -> Option<String> {
    let path = token_path(session_id)?;
    let raw = std::fs::read_to_string(path).ok()?;
    let token = raw.trim().to_string();
    if token.len() >= TOKEN_HEX_LEN && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(token)
    } else {
        None
    }
}

/// Derive a 32-hex-char (128-bit) sentinel from pid + session_id + counter +
/// nanosecond timestamp. Not a cryptographic secret; see the module docs.
fn generate_token(session_id: &str) -> String {
    let pid = std::process::id();
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut hasher = Sha256::new();
    hasher.update(pid.to_le_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(nanos.to_le_bytes());
    let digest = hasher.finalize();

    // First 16 bytes -> 32 hex chars (128 bits).
    let mut hex = String::with_capacity(TOKEN_HEX_LEN);
    for b in &digest[..TOKEN_HEX_LEN / 2] {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// `${TMPDIR:-/tmp}/agentguard` — the per-session canary directory.
fn canary_dir() -> PathBuf {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("agentguard")
}

/// Validate whether `session_id` is a safe filename component (prevents path traversal).
/// Must be non-empty, <= 128 characters, and contain only ASCII alphanumeric characters,
/// hyphens, or underscores.
fn is_safe_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= 128
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Full path of the token file for `session_id`, or `None` when `session_id`
/// is empty or unsafe (we never key on an empty or path-traversing id).
fn token_path(session_id: &str) -> Option<PathBuf> {
    if !is_safe_session_id(session_id) {
        return None;
    }
    Some(canary_dir().join(format!("canary-{session_id}")))
}

/// Create the canary dir (0700 on unix) and write the token file (0600 on
/// unix). Returns the I/O error so the best-effort caller can ignore it.
fn persist_token(session_id: &str, token: &str) -> std::io::Result<()> {
    let path = token_path(session_id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid or unsafe session_id",
        )
    })?;
    let dir = canary_dir();
    create_dir_private(&dir)?;
    write_file_private(&path, token.as_bytes())
}

/// Create `dir` (recursively) with owner-only `0700` perms on unix.
fn create_dir_private(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        if dir.exists() {
            return Ok(());
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `bytes` to `path`, truncating, owner-only `0600` on unix.
fn write_file_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)
}

/// Test-only lock serializing every test that mutates the process-global
/// `TMPDIR`. Cargo runs tests in parallel threads of ONE process, so the hook
/// tests (a sibling module) reuse THIS lock to avoid clobbering each other's
/// `TMPDIR` mid-test.
#[cfg(test)]
pub(crate) static TMPDIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// Isolate each test's TMPDIR so persisted tokens never collide across
    /// tests or with a real session. Returns the held lock guard plus the
    /// unique session id to use; the guard must outlive the persistence calls.
    fn isolated_session(tag: &str) -> (std::sync::MutexGuard<'static, ()>, String) {
        let guard = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "agentguard-canary-test-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: the held guard makes this the only thread touching TMPDIR for
        // the test's duration.
        unsafe {
            std::env::set_var("TMPDIR", &dir);
        }
        (guard, format!("sess-{tag}"))
    }

    #[test]
    fn token_is_at_least_128_bits() {
        let token = generate_token("abc");
        assert_eq!(token.len(), TOKEN_HEX_LEN, "32 hex chars == 128 bits");
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn tokens_distinct_per_session() {
        let a = generate_token("session-a");
        let b = generate_token("session-b");
        assert_ne!(a, b, "different sessions must yield different tokens");
        // Even the same session id yields distinct tokens (counter + nanos).
        let a2 = generate_token("session-a");
        assert_ne!(a, a2, "successive tokens must differ");
    }

    #[test]
    fn emit_then_read_round_trips() {
        let (_guard, session) = isolated_session("roundtrip");
        let emitted = emit_token(&session);
        let read = read_token(&session).expect("token persisted");
        assert_eq!(emitted, read);
        assert_eq!(read.len(), TOKEN_HEX_LEN);
    }

    #[test]
    fn read_absent_token_is_none() {
        let (_guard, _session) = isolated_session("absent");
        assert!(read_token("never-emitted").is_none());
    }

    #[test]
    fn empty_session_id_is_not_keyed() {
        let (_guard, _session) = isolated_session("emptyid");
        assert!(token_path("").is_none());
        // Emitting with an empty id still returns a token but persists nothing.
        let token = emit_token("");
        assert_eq!(token.len(), TOKEN_HEX_LEN);
        assert!(read_token("").is_none());
    }

    #[test]
    fn path_traversal_session_ids_are_rejected() {
        let (guard, _session) = isolated_session("traversal");
        let tmp_dir = canary_dir().parent().unwrap().to_path_buf();

        let malicious_ids = [
            "../../.bashrc",
            "../traversal_target",
            "/../etc/shadow",
            "sub/dir",
            "sess\\win",
            "sess\0null",
            "sess ID with spaces",
            "../",
            "..",
            ".",
        ];

        for bad_id in malicious_ids {
            assert!(
                token_path(bad_id).is_none(),
                "token_path must return None for unsafe session_id `{bad_id}`"
            );
            assert!(
                read_token(bad_id).is_none(),
                "read_token must return None for unsafe session_id `{bad_id}`"
            );

            // Emitting with an unsafe session_id must not write to any file.
            let token = emit_token(bad_id);
            assert_eq!(token.len(), TOKEN_HEX_LEN);
        }

        // Verify that no traversal target file was created in tmp_dir.
        let target_file = tmp_dir.join("traversal_target");
        assert!(
            !target_file.exists(),
            "path traversal file must not be created on disk"
        );

        drop(guard);
    }

    #[test]
    fn oversized_session_id_is_rejected() {
        let (_guard, _session) = isolated_session("oversized");
        let long_id = "a".repeat(129);
        assert!(token_path(&long_id).is_none());
        assert!(read_token(&long_id).is_none());

        let ok_id = "a".repeat(128);
        assert!(token_path(&ok_id).is_some());
    }
}
