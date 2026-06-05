//! TODO(US-005): SandboxRunner::run(req) -> SandboxResult; off-Linux fail-closed.

pub mod pathsafe;
pub mod permission;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(target_os = "linux"))]
pub mod fallback;
