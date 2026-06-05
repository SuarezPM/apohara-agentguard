//! Linux namespace isolation: user + mount + PID unshare bundle.
//!
//! Establishes a fresh user, mount, and PID namespace so the sandboxed child
//! can't see host PIDs or affect host mounts. Combined with seccomp + Landlock,
//! a sandboxed agent that calls `kill(orchestrator_pid, ...)` simply can't
//! resolve that PID — it isn't visible in the new PID namespace.
//!
//! ## Unprivileged design
//!
//! Plain `unshare(CLONE_NEWPID | CLONE_NEWNS)` needs `CAP_SYS_ADMIN`. We run as
//! the invoking user, so we bundle `CLONE_NEWUSER` in the same `unshare(2)`
//! call: an unprivileged process gets a new user-ns and the bundled PID + mount
//! namespaces become creatable inside it without root.
//!
//! After `unshare`, three writes are required before the user-ns is usable:
//!   1. `/proc/self/setgroups` <- `"deny"` (must precede gid_map),
//!   2. `/proc/self/uid_map`   <- `"0 <host_uid> 1"`,
//!   3. `/proc/self/gid_map`   <- `"0 <host_gid> 1"`.
//!
//! ## When to call
//!
//! [`enter_isolated_namespaces`] runs inside the middle child. The PID-ns
//! reparenting only takes effect for the caller's *future* children, so the
//! sequence is: parent forks -> middle child unshares -> middle child forks ->
//! grandchild is PID 1 in the new PID namespace.

use nix::sched::{unshare, CloneFlags};
use nix::unistd::{getgid, getuid};
use std::fs::OpenOptions;
use std::io::Write;

use crate::sandbox::error::{Result, SandboxError};

/// Enter a fresh user + mount + PID namespace bundle and write the uid/gid maps.
pub fn enter_isolated_namespaces() -> Result<()> {
    let host_uid = getuid().as_raw();
    let host_gid = getgid().as_raw();

    let flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID;

    unshare(flags).map_err(|e| {
        SandboxError::Namespace(format!(
            "unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID) failed: {e}. \
             Hint: requires unprivileged user namespaces \
             (sysctl kernel.unprivileged_userns_clone=1, user.max_user_namespaces > 0)."
        ))
    })?;

    write_proc_self("setgroups", "deny")?;
    write_proc_self("uid_map", &format!("0 {host_uid} 1"))?;
    write_proc_self("gid_map", &format!("0 {host_gid} 1"))?;

    Ok(())
}

/// Overwrite a `/proc/self/<name>` mapping file. These accept exactly one write
/// of the mapping line, so we truncate rather than append.
fn write_proc_self(name: &str, contents: &str) -> Result<()> {
    let path = format!("/proc/self/{name}");
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| SandboxError::Namespace(format!("open {path}: {e}")))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| SandboxError::Namespace(format!("write {path}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_proc_self_nonexistent_is_namespace_error() {
        let err = write_proc_self("agentguard_bogus_xyz", "anything").unwrap_err();
        match err {
            SandboxError::Namespace(msg) => {
                assert!(msg.contains("agentguard_bogus_xyz"), "got: {msg}");
            }
            other => panic!("expected Namespace error, got {other:?}"),
        }
    }
}
