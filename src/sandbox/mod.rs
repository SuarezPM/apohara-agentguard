//! Local process sandbox: seccomp-bpf + Landlock LSM defense-in-depth.
//!
//! On Linux, [`SandboxRunner::run`] executes a command confined by three
//! independent layers: a user/mount/PID namespace bundle, a Landlock
//! filesystem ruleset scoped to the workspace root, and a per-tier seccomp-bpf
//! syscall allowlist. The install order is pinned (NNP -> Landlock -> seccomp);
//! see `linux::runner` for why.
//!
//! On non-Linux platforms there is no sandbox, so `run` fails closed with
//! [`SandboxError::Unavailable`] (see [`fallback`]).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

pub mod error;
pub mod pathsafe;
pub mod permission;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(target_os = "linux"))]
pub mod fallback;

pub use error::{Result, SandboxError};
pub use permission::PermissionTier;

/// A request to run a command under the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRequest {
    /// argv of the command to run. `command[0]` is resolved via `$PATH`.
    pub command: Vec<String>,
    /// Root the command is confined to. The process `chdir`s here and Landlock
    /// grants access only beneath this path.
    pub workspace_root: PathBuf,
    /// Permission tier driving the seccomp + Landlock policy.
    pub tier: PermissionTier,
    /// Optional wall-clock timeout (not yet enforced; reserved).
    #[serde(default)]
    pub timeout: Option<Duration>,
}

/// The outcome of a sandboxed run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    /// Human-readable notes about setup/exec failures or signals.
    pub violations: Vec<String>,
}

/// Entry point for running a command under the sandbox.
pub struct SandboxRunner;

impl SandboxRunner {
    pub fn new() -> Self {
        Self
    }

    /// Run `req` to completion. Linux: namespace + Landlock + seccomp. Other
    /// platforms: [`SandboxError::Unavailable`].
    pub fn run(&self, req: SandboxRequest) -> Result<SandboxResult> {
        #[cfg(target_os = "linux")]
        {
            linux::runner::run_linux(&req)
        }
        #[cfg(not(target_os = "linux"))]
        {
            fallback::run(&req)
        }
    }
}

impl Default for SandboxRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serde_roundtrip() {
        let req = SandboxRequest {
            command: vec!["echo".into(), "hi".into()],
            workspace_root: PathBuf::from("/tmp"),
            tier: PermissionTier::ReadOnly,
            timeout: Some(Duration::from_millis(5000)),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SandboxRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.command, back.command);
        assert_eq!(req.tier, back.tier);
        assert_eq!(req.timeout, back.timeout);
    }
}
