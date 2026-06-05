//! Minimal test helpers shared across the sandbox integration tests.
//!
//! We don't pull in the `tempfile` crate for this — a tiny self-cleaning temp
//! directory is all the sandbox tests need.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp directory under the system temp dir, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh, uniquely-named temp dir tagged with `label`.
    pub fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agentguard-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        // Canonicalize so the path matches what the runner resolves (e.g. when
        // /tmp is itself a symlink). Falls back to the raw path if that fails.
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Faithful reimplementation of the FLAWED legacy fixed-list gate
/// (`inv_bash_scope.rs:64-110`): split on separators, then substring-match each
/// leg against a fixed 12-item list. No variable expansion, no base64 decode,
/// and the `| sh` entries are dead after splitting (the pipe is gone). This is
/// the hookify-class baseline apohara-agentguard is measured against.
///
/// Returns `true` if the legacy gate would flag the command (Unsafe), `false`
/// for Safe. Shared by `headline_bypass.rs` (the side-by-side contrast) and
/// `benchmark.rs` (the FP/FN benchmark) so both measure the IDENTICAL baseline.
pub fn naive_fixed_list(cmd: &str) -> bool {
    // The exact fixed list from inv_bash_scope.rs:64-77.
    const DANGEROUS: &[&str] = &[
        "rm -rf",
        "rm -fr",
        "| bash",
        "| sh",
        "|bash",
        "|sh",
        "curl ",
        "wget ",
        "eval ",
        "dd if=",
        "chmod 777",
        "mkfs",
    ];

    // Naive separator split (the legacy gate's quote-aware splitter, simplified
    // to the separators that matter: ; && || | & newline).
    let legs = naive_split(cmd);
    for leg in &legs {
        let lower = leg.to_ascii_lowercase();
        for pat in DANGEROUS {
            if lower.contains(pat) {
                return true; // Unsafe
            }
        }
    }
    false // Safe
}

/// Separator-aware split matching the legacy parser's leg boundaries: `;`,
/// `&&`, `||`, `|`, `&`, newline. Crucially, splitting on `|` destroys the
/// `| sh` / `|sh` substrings the fixed list relies on — the dead-check the
/// plan calls out.
fn naive_split(cmd: &str) -> Vec<String> {
    let mut legs = Vec::new();
    let mut current = String::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let two = bytes.get(i + 1).copied();
        if (c == b'&' && two == Some(b'&')) || (c == b'|' && two == Some(b'|')) {
            push(&mut current, &mut legs);
            i += 2;
            continue;
        }
        if c == b';' || c == b'|' || c == b'&' || c == b'\n' {
            push(&mut current, &mut legs);
            i += 1;
            continue;
        }
        current.push(c as char);
        i += 1;
    }
    push(&mut current, &mut legs);
    legs
}

fn push(current: &mut String, legs: &mut Vec<String>) {
    let t = current.trim();
    if !t.is_empty() {
        legs.push(t.to_string());
    }
    current.clear();
}
