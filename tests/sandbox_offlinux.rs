//! Non-Linux fail-closed behavior.
//!
//! On a non-Linux target the sandbox must REFUSE to run (no seccomp, no
//! Landlock => running unconfined would silently drop all confinement). The
//! Linux build excludes this file via the cfg gate; the fallback module it
//! exercises is itself only compiled on non-Linux, so the Linux toolchain never
//! type-checks it. Documented limitation: we can't cross-compile to a non-Linux
//! target in this environment, so this asserts the contract on whatever
//! non-Linux host runs it.

#![cfg(not(target_os = "linux"))]

use apohara_agentguard::sandbox::{PermissionTier, SandboxError, SandboxRequest, SandboxRunner};
use std::path::PathBuf;

#[test]
fn run_is_unavailable_off_linux() {
    let req = SandboxRequest {
        command: vec!["echo".into(), "hi".into()],
        workspace_root: PathBuf::from("."),
        tier: PermissionTier::WorkspaceWrite,
        timeout: None,
    };
    let err = SandboxRunner::new().run(req).unwrap_err();
    assert!(matches!(err, SandboxError::Unavailable), "got: {err:?}");
}
