//! A1 fail-closed regression tests (Linux): the two production `unreachable!`
//! abort vectors are removed, so the grandchild exec-failure path reports the
//! error and `_exit`s (fail-closed) instead of panicking/aborting across the
//! forked address space.

#![cfg(target_os = "linux")]

use apohara_agentguard::sandbox::{PermissionTier, SandboxRequest, SandboxRunner};

mod common;
use common::TempDir;

/// A non-existent command exercises the post-fork exec-failure path (the former
/// `unreachable!("execvpe returned Ok")` site). The run must complete WITHOUT a
/// panic/abort, return a non-zero exit code, and surface the exec error as a
/// violation rather than a successful unconfined run.
#[test]
fn nonexistent_command_fails_closed_no_panic() {
    let dir = TempDir::new("failclosed-noexec");
    let req = SandboxRequest {
        command: vec!["this-binary-does-not-exist-agentguard".to_string()],
        workspace_root: dir.path().to_path_buf(),
        tier: PermissionTier::WorkspaceWrite,
        timeout: None,
    };

    // The runner itself must NOT error at setup on this capable box: setup
    // succeeds, the exec fails inside the grandchild.
    let result = SandboxRunner::new()
        .run(req)
        .expect("setup must succeed; the FAILURE is the exec, surfaced as a violation");

    // Non-zero exit: the exec-failure path uses _exit(126).
    assert_ne!(
        result.exit_code, 0,
        "a failed exec must never look like a successful (exit 0) run; result={result:?}"
    );

    // The exec error is surfaced as a violation, proving the errno reached the
    // parent via the exec-error pipe (no panic ate it).
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.contains("execve_failed")),
        "expected an execve_failed violation; violations={:?}",
        result.violations
    );
}
