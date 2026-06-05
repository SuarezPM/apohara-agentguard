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
