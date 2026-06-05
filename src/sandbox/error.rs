//! Sandbox error type, shared across platforms.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SandboxError>;

/// Errors surfaced by the sandbox runner and its layers.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The sandbox is not available on this platform (non-Linux). Fail-closed.
    #[error("sandbox unavailable on this platform: refusing to run unconfined")]
    Unavailable,

    /// Namespace setup (unshare / uid_map / gid_map) failed.
    #[error("namespace setup failed: {0}")]
    Namespace(String),

    /// seccomp filter build or apply failed.
    #[error("seccomp error: {0}")]
    Seccomp(String),

    /// Landlock ruleset build or apply failed, or the kernel can't enforce it.
    #[error("landlock error: {0}")]
    Landlock(String),

    /// Workdir / workspace_root validation failed (escape, dangling, etc.).
    #[error("workdir validation failed: {0}")]
    Workdir(String),

    /// Generic runner-level failure (fork, pipe, waitpid, ...).
    #[error("runner error: {0}")]
    Runner(String),
}
