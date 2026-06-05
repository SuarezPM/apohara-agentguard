//! HARD seccomp-bpf tests (Linux). None are `#[ignore]` — they run for real.
//!
//! Asserts the network-denial and fail-closed posture of the seccomp filter:
//!   - `socket(AF_INET, ...)` returns EPERM (network creation denied),
//!   - an unlisted syscall returns EPERM (default mismatch_action).

#![cfg(target_os = "linux")]

use apohara_agentguard::sandbox::{PermissionTier, SandboxRequest, SandboxRunner};
use std::path::PathBuf;

mod common;
use common::TempDir;

fn run(
    tier: PermissionTier,
    root: &std::path::Path,
    argv: &[&str],
) -> apohara_agentguard::sandbox::SandboxResult {
    let req = SandboxRequest {
        command: argv.iter().map(|s| s.to_string()).collect(),
        workspace_root: root.to_path_buf(),
        tier,
        timeout: None,
    };
    SandboxRunner::new()
        .run(req)
        .expect("sandbox run should not fail at setup on this Linux box")
}

fn python3() -> Option<PathBuf> {
    for p in ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"] {
        if std::path::Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

#[test]
fn inet_socket_is_denied_under_workspace_write() {
    let Some(py) = python3() else {
        eprintln!("SKIP inet_socket_is_denied: python3 not found");
        return;
    };
    let dir = TempDir::new("seccomp-net");
    // The script reports OPEN if it could create an AF_INET socket, DENIED if
    // the kernel returned PermissionError (our seccomp EPERM).
    let script = "import socket,sys\n\
                  try:\n\
                  \x20 s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
                  \x20 print('OPEN')\n\
                  except PermissionError:\n\
                  \x20 print('DENIED')\n\
                  except OSError as e:\n\
                  \x20 print('DENIED' if e.errno in (1,13) else 'OTHER:%d' % (e.errno or -1))\n";
    let r = run(
        PermissionTier::WorkspaceWrite,
        dir.path(),
        &[py.to_str().unwrap(), "-c", script],
    );
    assert!(
        r.stdout.contains("DENIED"),
        "expected socket(AF_INET) to be DENIED by seccomp; stdout={:?} stderr={:?} violations={:?}",
        r.stdout,
        r.stderr,
        r.violations
    );
    assert!(
        !r.stdout.contains("OPEN"),
        "AF_INET socket was created — network is NOT confined! stdout={:?}",
        r.stdout
    );
}

#[test]
fn unlisted_syscall_returns_eperm_not_kill() {
    // `unshare(2)` is deliberately NOT in any allowlist. Under our filter it
    // must return EPERM (mismatch_action), and the process must NOT be killed
    // by SIGSYS — i.e. the shell keeps running and reports a normal failure.
    let Some(py) = python3() else {
        eprintln!("SKIP unlisted_syscall: python3 not found");
        return;
    };
    let dir = TempDir::new("seccomp-unlisted");
    // CLONE_NEWUSER unshare via ctypes; expect EPERM (errno 1), printed as DENIED.
    let script = "import ctypes,ctypes.util,sys\n\
                  libc=ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)\n\
                  CLONE_NEWUSER=0x10000000\n\
                  r=libc.unshare(CLONE_NEWUSER)\n\
                  e=ctypes.get_errno()\n\
                  print('DENIED' if r!=0 and e in (1,13) else 'ALLOWED:%d:%d'%(r,e))\n";
    let r = run(
        PermissionTier::WorkspaceWrite,
        dir.path(),
        &[py.to_str().unwrap(), "-c", script],
    );
    assert!(
        r.stdout.contains("DENIED"),
        "expected unshare() to be EPERM'd (not allowed, not SIGSYS-killed); \
         stdout={:?} stderr={:?} violations={:?}",
        r.stdout,
        r.stderr,
        r.violations
    );
}
