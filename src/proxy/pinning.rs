//! Tool-manifest pinning for the MCP transport proxy (V4-C).
//!
//! A tools/list manifest is pinned per upstream server: the FIRST time an
//! upstream is seen its manifest is hashed and recorded; every later session
//! re-verifies. Any drift ⇒ [`PinVerdict::Mismatch`] ⇒ the relay quarantines
//! the session (fail-closed). This is the TOFU ("trust on first use") model
//! known from SSH host keys, applied to MCP tool manifests.
//!
//! ## What is pinned (and what is deliberately NOT)
//!
//! Only the stable identity fields enter the hash:
//! `tools[].name`, `description`, `inputSchema`, `outputSchema`.
//!
//! Everything else (`annotations`, `title`, icons, TTL-style metadata) is
//! EXCLUDED: those fields are volatile or client-decorative, and hashing them
//! would turn cosmetic upstream churn into constant false quarantines.
//!
//! ## Canonicalization
//!
//! SHA-256 is computed over a canonical JSON rendering: tools sorted by name,
//! object keys sorted recursively, compact separators. Two semantically
//! identical manifests therefore always produce the same digest regardless of
//! upstream key order or whitespace.
//!
//! ## Pin store
//!
//! `<config_dir>/agentguard/mcp-pins.json` where `config_dir` is
//! `$XDG_CONFIG_HOME` (falling back to `$HOME/.config`); tests inject the base
//! directory directly. Entries are keyed by [`upstream_identity`] — a digest
//! over the length-prefixed ARGV VECTOR plus the resolved child CWD — so
//! re-pinning is scoped to the exact server invocation IN ONE PROJECT
//! DIRECTORY: the same command string from a different cwd is a different
//! upstream with its own first-sighting alarm, and argv element boundaries
//! can never collide. The file is written 0600 (unix) and fsync'd before the
//! atomic rename. Format version 2; a legacy v1 store is treated as absent
//! (entries re-recorded with a stderr note), never trusted.
//!
//! ## Pre-seeded expectation
//!
//! An operator may declare the expected pin up front via `--pin sha256:<hex>`
//! or the `AGENTGUARD_PIN` env var. A pre-seed that does not match the actual
//! manifest is [`PinVerdict::PreseedMismatch`] — immediate quarantine, before
//! any store logic runs.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Store schema version. Bumped on any incompatible layout change so old
/// files fail loudly instead of being silently misread.
///
/// **v2** keys pins by an identity digest over the LENGTH-PREFIXED ARGV
/// VECTOR plus the resolved child CWD (see [`upstream_identity`]); v1 keyed
/// by a whitespace join of the argv, which collided across element
/// boundaries (`["a b"]` vs `["a","b"]`) and inherited pins across projects
/// running the same command string from a different directory. A v1 store is
/// therefore treated as ABSENT: its entries are never trusted, and everything
/// is re-recorded under v2 identities with a loud stderr note.
const STORE_VERSION: u32 = 2;

/// Domain-separation tag prefixed to the upstream identity key material so
/// hashed argv/cwd bytes can never be confused with another encoding.
const IDENTITY_TAG: &[u8] = b"agentguard-proxy-upstream-identity-v2\0";

/// Compute the upstream identity used as the pin key: SHA-256 over the
/// length-prefixed ARGV VECTOR plus the resolved child CWD.
///
/// Length prefixes make element boundaries unambiguous (a `python3 a b.py`
/// invocation can never collide with `python3 "a b.py"`), and folding the
/// CWD in scopes every pin to ONE project directory: the same command string
/// run from a different checkout is a DIFFERENT upstream with its own
/// first-sighting alarm, never a silent inheritance of another project's
/// recorded manifest.
pub fn upstream_identity(argv: &[String], cwd: &Path) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(IDENTITY_TAG);
    material.extend_from_slice(&(argv.len() as u64).to_le_bytes());
    for elem in argv {
        material.extend_from_slice(&(elem.len() as u64).to_le_bytes());
        material.extend_from_slice(elem.as_bytes());
    }
    let cwd_text = cwd.to_string_lossy();
    material.extend_from_slice(&(cwd_text.len() as u64).to_le_bytes());
    material.extend_from_slice(cwd_text.as_bytes());
    hash_hex(&material)
}

/// One recorded upstream pin.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PinEntry {
    /// SHA-256 hex of the upstream command string (the pin key).
    pub upstream_cmd_hash: String,
    /// SHA-256 hex of the canonical tools manifest at last verification.
    pub tools_hash: String,
    /// First-seen timestamp (unix epoch seconds).
    pub first_seen: u64,
    /// Last successful verification timestamp (unix epoch seconds).
    pub last_verified: u64,
}

/// On-disk pin store document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PinStoreDoc {
    version: u32,
    pins: Vec<PinEntry>,
}

/// The outcome of verifying a tools/list manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerdict {
    /// First sighting of this upstream: the manifest was recorded. Not a
    /// verification — the operator should review the recorded pin (surfaced
    /// on stderr by the relay). `note` carries an operator-relevant caveat
    /// (e.g. a legacy v1 store was ignored and everything re-recorded).
    Recorded {
        hash: String,
        /// Caveat surfaced alongside the recording (stderr note).
        note: Option<String>,
    },
    /// Manifest matches the stored pin.
    Matched { hash: String },
    /// Manifest drifted from the stored pin. `expected` is the stored hash,
    /// `actual` the computed one. Fail-closed: the store is NOT updated.
    Mismatch { expected: String, actual: String },
    /// The operator-supplied pre-seed (`--pin` / `AGENTGUARD_PIN`) does not
    /// match the actual manifest. Immediate quarantine.
    PreseedMismatch { expected: String, actual: String },
    /// The pin store itself is unreadable/corrupt. Fail-closed: without a
    /// trustworthy store, "matches" cannot be distinguished from "drifted".
    /// (Extension beyond the four core verdicts: quarantine-grade outcome
    /// with a human-readable reason.)
    StoreUnavailable { reason: String },
}

impl PinVerdict {
    /// Whether this verdict must quarantine the session.
    pub fn is_quarantine(&self) -> bool {
        !matches!(
            self,
            PinVerdict::Recorded { .. } | PinVerdict::Matched { .. }
        )
    }

    /// Human-readable explanation for stderr alarms and quarantine reasons.
    pub fn reason(&self) -> String {
        match self {
            PinVerdict::Recorded { hash, note } => {
                let base = format!("pin recorded (first sighting) sha256:{hash}");
                match note {
                    Some(n) => format!("{base}; note: {n}"),
                    None => base,
                }
            }
            PinVerdict::Matched { hash } => format!("pin matched sha256:{hash}"),
            PinVerdict::Mismatch { expected, actual } => format!(
                "tool manifest drift — stored pin sha256:{expected}, actual sha256:{actual}"
            ),
            PinVerdict::PreseedMismatch { expected, actual } => format!(
                "pre-seeded pin mismatch — expected sha256:{expected}, actual sha256:{actual}"
            ),
            PinVerdict::StoreUnavailable { reason } => {
                format!("pin store unavailable (fail-closed): {reason}")
            }
        }
    }
}

/// Resolve the config base directory used for the pin store.
///
/// `$XDG_CONFIG_HOME` when set (and non-empty), else `$HOME/.config`. Returns
/// `None` when neither variable is usable — the caller fails closed.
pub fn default_config_base() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    let home = std::env::var_os("HOME");
    config_base_from(xdg.as_deref(), home.as_deref())
}

/// Pure core of [`default_config_base`] (injectable inputs keep the
/// precedence logic testable without mutating process-global env state).
fn config_base_from(
    xdg: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(xdg) = xdg {
        let p = PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return Some(p);
        }
    }
    home.filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".config"))
}

/// Full path of the pin store file under config base `base`.
pub fn pin_store_path(base: &Path) -> PathBuf {
    base.join("agentguard").join("mcp-pins.json")
}

/// The pin store: JSON document at `<base>/agentguard/mcp-pins.json`.
#[derive(Debug, Clone)]
pub struct PinStore {
    path: PathBuf,
}

impl PinStore {
    /// Open (lazily create) the store rooted at config base directory `base`
    /// (e.g. `~/.config`). Injectable so tests never touch the real config dir.
    pub fn open(base: impl Into<PathBuf>) -> Self {
        Self {
            path: pin_store_path(&base.into()),
        }
    }

    /// The store file path (exposed for diagnostics/tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify the manifest of `upstream_identity` (the [`upstream_identity`]
    /// digest of the child argv + cwd) against the store (and the optional
    /// operator pre-seed), recording it on first sight.
    ///
    /// Order of checks (pinned):
    /// 1. **Pre-seed** (`expected_pin`, `sha256:<hex>`, case-insensitive
    ///    hex): a mismatch is an immediate [`PinVerdict::PreseedMismatch`] —
    ///    the operator declared what they expect; anything else is hostile
    ///    regardless of store state.
    /// 2. **Store lookup**: matching entry ⇒ [`Matched`] (with
    ///    `last_verified` refreshed); differing entry ⇒ [`Mismatch`] (store
    ///    untouched); no entry ⇒ record ⇒ [`Recorded`].
    pub fn verify_or_record(
        &self,
        upstream_identity: &str,
        tools_result: &Value,
        expected_pin: Option<&str>,
    ) -> PinVerdict {
        let actual = tools_hash(upstream_identity, tools_result);

        // 1. Operator pre-seed takes precedence over everything. Hex is
        //    normalized to lowercase so `SHA256:<HEX>` pre-seeds match the
        //    lowercase digests this module emits (case trap, remediation N1).
        if let Some(expected) = expected_pin {
            let expected_norm = expected.trim().to_ascii_lowercase();
            if expected_norm != format!("sha256:{actual}") {
                return PinVerdict::PreseedMismatch {
                    expected: expected_norm.trim_start_matches("sha256:").to_string(),
                    actual,
                };
            }
        }

        // 2. Store logic. Any store-level failure is fail-closed. A legacy
        //    v1 store is treated as ABSENT (its entries are never trusted);
        //    re-recording carries a loud note instead.
        let (mut doc, legacy_note) = match self.load() {
            Ok(pair) => pair,
            Err(reason) => return PinVerdict::StoreUnavailable { reason },
        };
        let key = hash_hex(upstream_identity.as_bytes());
        let now = unix_now();
        if let Some(entry) = doc.pins.iter_mut().find(|e| e.upstream_cmd_hash == key) {
            if entry.tools_hash == actual {
                entry.last_verified = now;
                // Best-effort refresh; a failed write here does not invalidate
                // the MATCH (the security decision already passed).
                let _ = self.store(&doc);
                return PinVerdict::Matched { hash: actual };
            }
            return PinVerdict::Mismatch {
                expected: entry.tools_hash.clone(),
                actual,
            };
        }
        doc.pins.push(PinEntry {
            upstream_cmd_hash: key,
            tools_hash: actual.clone(),
            first_seen: now,
            last_verified: now,
        });
        if let Err(reason) = self.store(&doc) {
            return PinVerdict::StoreUnavailable { reason };
        }
        PinVerdict::Recorded {
            hash: actual,
            note: legacy_note,
        }
    }

    /// Load + parse the store. Returns the document plus an operator note
    /// when a LEGACY v1 store was found and ignored (its entries are treated
    /// as absent and everything re-records under v2 identities).
    ///
    /// Missing file ⇒ empty document (fresh install). Present-but-unreadable
    /// or corrupt ⇒ Err (fail-closed). A FUTURE version (> 2) also fails
    /// closed: a newer writer may have changed semantics we cannot interpret.
    fn load(&self) -> Result<(PinStoreDoc, Option<String>), String> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((
                    PinStoreDoc {
                        version: STORE_VERSION,
                        pins: Vec::new(),
                    },
                    None,
                ));
            }
            Err(e) => return Err(format!("reading {}: {e}", self.path.display())),
        };
        let doc: PinStoreDoc = serde_json::from_str(&text)
            .map_err(|e| format!("parsing {}: {e}", self.path.display()))?;
        match doc.version {
            STORE_VERSION => Ok((doc, None)),
            // Legacy v1: whitespace-join argv keys + no cwd scoping — entries
            // are meaningless under v2 identity rules. Ignore, never trust.
            1 => Ok((
                PinStoreDoc {
                    version: STORE_VERSION,
                    pins: Vec::new(),
                },
                Some(
                    "legacy v1 pin store ignored (pre-cwd-scoping format) — \
                     all upstreams re-recorded as first sightings"
                        .to_string(),
                ),
            )),
            other => Err(format!(
                "unsupported pin-store version {other} (this build supports {STORE_VERSION})"
            )),
        }
    }

    /// Atomically-ish persist the store: write temp + rename in the same
    /// directory so a crash never leaves a truncated pin file behind.
    ///
    /// Hardening (remediation N2): the temp file is created with mode 0600
    /// (unix — no permission window at umask-derived modes) and fsync'd
    /// before the rename, matching the durability care of the audit sink.
    fn store(&self, doc: &PinStoreDoc) -> Result<(), String> {
        use std::io::Write as _;
        let dir = self
            .path
            .parent()
            .ok_or_else(|| format!("pin store path has no parent: {}", self.path.display()))?;
        fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let text =
            serde_json::to_string_pretty(doc).map_err(|e| format!("serializing pin store: {e}"))?;
        let tmp = dir.join(format!(
            ".mcp-pins.json.tmp-{}-{}",
            std::process::id(),
            unix_now()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            f.write_all(text.as_bytes())
                .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            f.sync_all()
                .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp, text).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("renaming pin store into place: {e}")
        })
    }
}

/// Canonicalize a tools/list `result` object and hash it together with the
/// upstream command string.
///
/// Domain separation (`upstream\0manifest`) keeps two different servers that
/// happen to ship identical manifests from sharing pin entries implicitly —
/// although entries are keyed by the upstream hash anyway, folding the
/// upstream into the digest makes any cross-server confusion evident in the
/// pin value itself.
pub fn tools_hash(upstream_cmd: &str, tools_result: &Value) -> String {
    let canonical = canonical_tools_json(upstream_cmd, tools_result);
    hash_hex(canonical.as_bytes())
}

/// Build the canonical JSON string for a tools/list result:
/// `{"upstream":<cmd>,"tools":[<subset>…]}` with tools sorted by name, keys
/// sorted recursively, compact separators.
pub fn canonical_tools_json(upstream_cmd: &str, tools_result: &Value) -> String {
    let tools = tools_result
        .get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut subset: Vec<Value> = tools.iter().map(pin_subset).collect();
    subset.sort_by(|a, b| {
        let ka = a.get("name").and_then(Value::as_str).unwrap_or("");
        let kb = b.get("name").and_then(Value::as_str).unwrap_or("");
        ka.cmp(kb)
    });

    let mut root = Map::new();
    root.insert(
        "upstream".to_string(),
        Value::String(upstream_cmd.to_string()),
    );
    root.insert("tools".to_string(), Value::Array(subset));
    // serde_json serializes maps compactly; key order is handled by
    // `sort_keys_recursively` below so the canonical form does not depend on
    // the map implementation (guards against a future preserve_order feature
    // unification changing bytes out from under existing pins).
    let mut value = Value::Object(root);
    sort_keys_recursively(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Extract ONLY the pinned identity fields from a tool descriptor:
/// `name`, `description`, `inputSchema`, `outputSchema` (present fields only).
fn pin_subset(tool: &Value) -> Value {
    let mut m = Map::new();
    for key in ["name", "description", "inputSchema", "outputSchema"] {
        if let Some(v) = tool.get(key) {
            m.insert(key.to_string(), v.clone());
        }
    }
    Value::Object(m)
}

/// Recursively sort object keys in place (see `canonical_tools_json`).
fn sort_keys_recursively(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let mut sorted = Map::new();
            for k in keys {
                let mut val = map.remove(&k).expect("key just read");
                sort_keys_recursively(&mut val);
                sorted.insert(k, val);
            }
            *map = sorted;
        }
        Value::Array(items) => {
            for item in items {
                sort_keys_recursively(item);
            }
        }
        _ => {}
    }
}

/// Lowercase hex SHA-256 of `bytes` (manual hex helper — no hex crate).
pub fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Seconds since the unix epoch (pin timestamps). Falls back to 0 if the
/// clock is before the epoch — pins stay functional, timestamps degrade.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tools_result(pairs: &[(&str, &str)]) -> Value {
        let tools: Vec<Value> = pairs
            .iter()
            .map(|(name, desc)| {
                json!({
                    "name": name,
                    "description": desc,
                    "inputSchema": {"type": "object"},
                    "annotations": {"readOnlyHint": true},
                    "title": name
                })
            })
            .collect();
        json!({ "tools": tools })
    }

    #[test]
    fn canonical_form_excludes_unpinned_fields_and_sorts_by_name() {
        let r = tools_result(&[("zeta", "Z"), ("alpha", "A")]);
        let canon = canonical_tools_json("srv", &r);
        assert!(
            !canon.contains("annotations") && !canon.contains("readOnlyHint"),
            "volatile fields must be excluded: {canon}"
        );
        assert!(
            !canon.contains("\"title\""),
            "title must be excluded: {canon}"
        );
        let alpha_pos = canon.find("alpha").expect("alpha present");
        let zeta_pos = canon.find("zeta").expect("zeta present");
        assert!(
            alpha_pos < zeta_pos,
            "tools must be sorted by name: {canon}"
        );
    }

    #[test]
    fn canonical_form_is_order_and_whitespace_insensitive() {
        let a = json!({"tools":[{"name":"t","description":"d","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]});
        let b = json!({ "tools" : [ { "inputSchema" : {"properties":{"x":{"type":"string"}},"type":"object"}, "description":"d", "name":"t" } ] });
        assert_eq!(
            canonical_tools_json("srv", &a),
            canonical_tools_json("srv", &b),
            "key order/whitespace must not change the canonical form"
        );
    }

    #[test]
    fn description_change_changes_the_hash() {
        let h1 = tools_hash("srv", &tools_result(&[("t", "original")]));
        let h2 = tools_hash("srv", &tools_result(&[("t", "TAMPERED")]));
        assert_ne!(h1, h2);
    }

    #[test]
    fn upstream_is_part_of_the_digest() {
        let r = tools_result(&[("t", "d")]);
        assert_ne!(tools_hash("server-a", &r), tools_hash("server-b", &r));
    }

    #[test]
    fn hash_hex_is_lowercase_sha256() {
        // Well-known vector: SHA-256("") =
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    struct TempBase(PathBuf);
    impl TempBase {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "agentguard-pin-test-{tag}-{}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn verify_records_then_matches_then_mismatches() {
        let base = TempBase::new("tofu");
        let store = PinStore::open(&base.0);
        let r1 = tools_result(&[("echo", "Echoes input")]);

        let v1 = store.verify_or_record("python3 srv.py", &r1, None);
        assert!(
            matches!(&v1, PinVerdict::Recorded { .. }),
            "first sighting records: {v1:?}"
        );

        let v2 = store.verify_or_record("python3 srv.py", &r1, None);
        assert!(
            matches!(&v2, PinVerdict::Matched { .. }),
            "second sighting matches: {v2:?}"
        );

        let tampered = tools_result(&[("echo", "EVIL")]);
        let v3 = store.verify_or_record("python3 srv.py", &tampered, None);
        match &v3 {
            PinVerdict::Mismatch { expected, actual } => {
                let PinVerdict::Recorded { hash, .. } = &v1 else {
                    panic!("unreachable shape")
                };
                assert_eq!(expected, hash, "expected carries the STORED hash");
                assert_ne!(actual, hash);
            }
            other => panic!("drift must mismatch, got {other:?}"),
        }

        // The store must still hold the ORIGINAL pin after a mismatch.
        let v4 = store.verify_or_record("python3 srv.py", &r1, None);
        assert!(matches!(v4, PinVerdict::Matched { .. }), "{v4:?}");
    }

    #[test]
    fn different_upstreams_pin_independently() {
        let base = TempBase::new("multi");
        let store = PinStore::open(&base.0);
        let r = tools_result(&[("t", "d")]);
        assert!(matches!(
            store.verify_or_record("a", &r, None),
            PinVerdict::Recorded { .. }
        ));
        assert!(matches!(
            store.verify_or_record("b", &r, None),
            PinVerdict::Recorded { .. }
        ));
        assert!(matches!(
            store.verify_or_record("a", &r, None),
            PinVerdict::Matched { .. }
        ));
    }

    #[test]
    fn preseed_match_passes_and_mismatch_quarantines() {
        let base = TempBase::new("preseed");
        let store = PinStore::open(&base.0);
        let r = tools_result(&[("t", "d")]);
        let good = format!("sha256:{}", tools_hash("srv", &r));

        let ok = store.verify_or_record("srv", &r, Some(&good));
        assert!(matches!(ok, PinVerdict::Recorded { .. }), "{ok:?}");

        let bad = store.verify_or_record("srv", &r, Some("sha256:deadbeef"));
        assert_eq!(
            bad,
            PinVerdict::PreseedMismatch {
                expected: "deadbeef".to_string(),
                actual: tools_hash("srv", &r)
            }
        );
        assert!(bad.is_quarantine());
    }

    #[test]
    fn preseed_hex_is_case_insensitive() {
        // Remediation N1: an UPPERCASE operator pre-seed must match the
        // lowercase digests this module emits (no case trap).
        let base = TempBase::new("preseed-case");
        let store = PinStore::open(&base.0);
        let r = tools_result(&[("t", "d")]);
        let upper = format!("SHA256:{}", tools_hash("srv", &r).to_uppercase());
        let v = store.verify_or_record("srv", &r, Some(&upper));
        assert!(
            matches!(v, PinVerdict::Recorded { .. }),
            "uppercase pre-seed must match, got {v:?}"
        );
    }

    #[test]
    fn upstream_identity_scopes_by_cwd_and_argv_element_boundaries() {
        // Remediation M2: the pin key must be a digest over the ARGV VECTOR
        // (length-prefixed elements) + the resolved CWD — never a whitespace
        // join of the argv.
        let argv = vec!["python3".to_string(), "srv.py".to_string()];
        let cwd_a = Path::new("/home/dev/project-a");
        let cwd_b = Path::new("/home/dev/project-b");

        // Same argv, different cwd ⇒ DIFFERENT identities (no cross-project
        // inheritance of a legitimate project's pin).
        assert_ne!(
            upstream_identity(&argv, cwd_a),
            upstream_identity(&argv, cwd_b)
        );
        // Identical inputs ⇒ identical identity.
        assert_eq!(
            upstream_identity(&argv, cwd_a),
            upstream_identity(&argv, cwd_a)
        );

        // Element-boundary collision the old join had: ["python3", "a b.py"]
        // vs ["python3", "a", "b.py"] both join to "python3 a b.py" but are
        // different programs. Length prefixes keep them distinct.
        let x = vec!["python3".to_string(), "a b.py".to_string()];
        let y = vec!["python3".to_string(), "a".to_string(), "b.py".to_string()];
        assert_ne!(
            upstream_identity(&x, cwd_a),
            upstream_identity(&y, cwd_a),
            "argv element boundaries must be unambiguous"
        );
    }

    #[test]
    fn legacy_v1_store_is_ignored_and_rerecorded_never_trusted() {
        // Remediation M2(c): a v1 store (pre-cwd-scoping keys) is treated as
        // ABSENT — its entries must never produce a silent Matched.
        let base = TempBase::new("legacy-v1");
        let store = PinStore::open(&base.0);
        fs::create_dir_all(store.path().parent().unwrap()).expect("dir");
        let r = tools_result(&[("echo", "honest")]);
        let v1 = serde_json::json!({
            "version": 1,
            "pins": [{
                "upstream_cmd_hash": hash_hex(b"python3 srv.py"),
                "tools_hash": hash_hex(b"whatever-the-old-format-was"),
                "first_seen": 1,
                "last_verified": 1
            }]
        });
        fs::write(
            store.path(),
            serde_json::to_string_pretty(&v1).expect("serialize v1"),
        )
        .expect("write v1 store");

        let first = store.verify_or_record("srv-identity", &r, None);
        match &first {
            PinVerdict::Recorded { note, .. } => {
                assert!(note.is_some(), "re-recording over v1 must carry a note");
                assert!(note.as_deref().unwrap().contains("legacy v1"), "{note:?}");
            }
            other => panic!("v1 entries must be ignored ⇒ Recorded, got {other:?}"),
        }
        // The store on disk is now v2 with OUR entry; the next verification
        // matches normally with no note.
        let stored: Value =
            serde_json::from_str(&fs::read_to_string(store.path()).expect("read")).unwrap();
        assert_eq!(stored["version"], 2);
        let second = store.verify_or_record("srv-identity", &r, None);
        assert!(matches!(&second, PinVerdict::Matched { .. }), "{second:?}");
    }

    #[test]
    fn future_store_version_fails_closed() {
        let base = TempBase::new("future-version");
        let store = PinStore::open(&base.0);
        fs::create_dir_all(store.path().parent().unwrap()).expect("dir");
        fs::write(store.path(), r#"{"version":99,"pins":[]}"#).expect("write future store");
        let v = store.verify_or_record("srv", &tools_result(&[("t", "d")]), None);
        assert!(
            matches!(&v, PinVerdict::StoreUnavailable { reason } if reason.contains("version")),
            "unknown future version must fail closed, got {v:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pin_store_file_mode_is_0600() {
        // Remediation N2: the pin store holds integrity-critical digests and
        // must not be world/group-readable (matches the audit sink's care).
        let base = TempBase::new("mode");
        let store = PinStore::open(&base.0);
        let v = store.verify_or_record("srv", &tools_result(&[("t", "d")]), None);
        assert!(matches!(v, PinVerdict::Recorded { .. }), "{v:?}");
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(store.path())
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "pin store must be 0600");
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let base = TempBase::new("corrupt");
        let store = PinStore::open(&base.0);
        fs::create_dir_all(store.path().parent().unwrap()).expect("dir");
        fs::write(store.path(), "{not json").expect("write corrupt store");

        let v = store.verify_or_record("srv", &tools_result(&[("t", "d")]), None);
        assert!(
            matches!(&v, PinVerdict::StoreUnavailable { .. }),
            "corrupt store must fail closed, got {v:?}"
        );
        assert!(v.is_quarantine());
    }

    #[test]
    fn missing_store_dir_is_a_fresh_install_not_an_error() {
        let base = TempBase::new("fresh");
        let store = PinStore::open(base.0.join("deeply").join("nested"));
        let v = store.verify_or_record("srv", &tools_result(&[("t", "d")]), None);
        assert!(matches!(v, PinVerdict::Recorded { .. }), "{v:?}");
        assert!(store.path().exists(), "store file created");
    }

    #[test]
    fn default_config_base_prefers_xdg_then_home() {
        use std::ffi::OsStr;
        // XDG wins when set (even with HOME absent).
        assert_eq!(
            config_base_from(Some(OsStr::new("/xdg")), None),
            Some(PathBuf::from("/xdg"))
        );
        // HOME fallback appends `.config`.
        assert_eq!(
            config_base_from(None, Some(OsStr::new("/home"))),
            Some(PathBuf::from("/home/.config"))
        );
        // XDG precedence over HOME.
        assert_eq!(
            config_base_from(Some(OsStr::new("/xdg")), Some(OsStr::new("/home"))),
            Some(PathBuf::from("/xdg"))
        );
        // Empty XDG falls through to HOME; both empty ⇒ None (fail-closed).
        assert_eq!(
            config_base_from(Some(OsStr::new("")), Some(OsStr::new("/home"))),
            Some(PathBuf::from("/home/.config"))
        );
        assert_eq!(config_base_from(Some(OsStr::new("")), None), None);
    }
}
