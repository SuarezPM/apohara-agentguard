//! Non-Linux fallback: there is no seccomp/Landlock sandbox, so we fail closed.
//!
//! This module is only compiled on `cfg(not(target_os = "linux"))`. The Linux
//! build excludes it entirely, so it does not affect the Linux compile.

use crate::sandbox::error::{Result, SandboxError};
use crate::sandbox::{SandboxRequest, SandboxResult};

/// Always refuse: running unconfined would silently drop the sandbox.
pub fn run(_req: &SandboxRequest) -> Result<SandboxResult> {
    Err(SandboxError::Unavailable)
}
