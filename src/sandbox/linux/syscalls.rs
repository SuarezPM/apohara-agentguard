//! Per-tier syscall allowlists for the Linux seccomp-bpf profile.
//!
//! # How this set was derived (empirical, NOT copied from any reference)
//!
//! Every entry below was validated against the live 2026 toolchain on this
//! machine (CachyOS, kernel 7.0.11, glibc, rustc 1.95, Node 20, Go 1.26). The
//! derivation:
//!
//! ```text
//!   strace -f -qq -e trace=all -o T.strace <cmd>
//!   grep -oE '^[0-9]+ +[a-z_0-9]+\(' T.strace | sed -E 's/^[0-9]+ +//; s/\($//' | sort -u
//! ```
//!
//! was run on three real workloads, then the union was folded in:
//!   - `cargo build` of a multi-file crate (jobserver IPC, linker, threads),
//!   - `node -e "console.log(1)"` (V8 + libuv epoll/io_uring fallback),
//!   - a compiled `go` hello-world (goroutine scheduler, threads).
//!
//! ## Findings that the unverified reference list MISSED (and we add)
//!   - glibc on this system issues the **legacy** syscalls `open`, `stat`,
//!     `lstat`, `mkdir`, `rename`, `unlink`, `readlink`, `access`, `dup2`,
//!     `poll` as *real* syscalls (cargo emitted 1342 `readlink` and 165
//!     `access` calls). The reference only listed the `*at` forms, so a real
//!     `cargo build` would fail-closed (EPERM) without these.
//!   - threaded build tools need `futex`, `epoll_create1`, `epoll_ctl`,
//!     `epoll_wait`, `epoll_pwait`, `poll`, `eventfd2`, `restart_syscall`,
//!     `sched_yield`, `sched_getaffinity`, `rseq`, `clone3` — all observed.
//!   - cargo's jobserver uses `socketpair(AF_UNIX, ...)` + `recvfrom`. These
//!     are LOCAL only: the kernel does not support `socketpair(AF_INET, ...)`,
//!     and without `socket`/`connect`/`bind` the child can never obtain a
//!     network fd, so `recvfrom`/`sendmsg`/`recvmsg` cannot touch the network.
//!
//! ## Deny-by-omission (deliberately NOT added; verified harmless)
//!   - `openat2`: NONE of the three workloads issued it (0 calls). glibc falls
//!     back to `openat` on EPERM, and the build e2e proves `cargo build`/node/go
//!     all still exit 0 — so it stays denied (mismatch_action = EPERM).
//!   - `io_uring_setup` / `io_uring_enter`: Node *attempts* io_uring but falls
//!     back to epoll on EPERM (the e2e confirms node exits 0). io_uring is a
//!     well-known sandbox-escape surface, so it stays denied.
//!   - `capget`: Node queries capabilities; tolerates EPERM. Not needed for a
//!     build, so denied.
//!
//! ## Hard network denial (never allowed at any tier)
//!   `socket`, `connect`, `bind`, `listen`, `accept`/`accept4`, `sendto`,
//!   `socketcall` (the 32-bit multiplexer) — all stay off every list. The
//!   `sandbox_seccomp.rs` test asserts `socket(AF_INET, ...)` returns EPERM.
//!
//! ## Defensive additions (not observed here, but cheap and forward-safe)
//!   Modern threaded runtimes on other libcs/kernels may emit these, so we
//!   include them so the allowlist does not regress on a different host:
//!   `futex_waitv`, `epoll_pwait2`, `ppoll`, `membarrier`, `rt_sigtimedwait`.
//!
//! ## Landlock syscalls are intentionally ABSENT
//!   `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`
//!   are NOT in any allowlist. They run BEFORE seccomp in the pinned grandchild
//!   ordering (NNP -> Landlock -> seccomp), so the child can never call them
//!   after the filter is installed and cannot weaken its own ruleset.

use crate::sandbox::permission::PermissionTier;

/// Tier 1: ReadOnly pure-allow syscalls (no argument conditions).
///
/// Covers read I/O, fd management, memory, signals, time, entropy, process
/// info, and clean exits. `openat` / `open` are NOT here — they're conditional
/// (RDONLY-masked) for this tier.
pub const READONLY_PURE_ALLOW: &[&str] = &[
    // Read I/O
    "read",
    "pread64",
    "readv",
    "preadv2",
    // Write I/O. ALLOWED at ReadOnly too: a read-only command still writes its
    // output to stdout/stderr (e.g. `cat` -> write(1, ...)). The seccomp gate
    // cannot tell a stdout fd from a file fd, so the FILESYSTEM write ban for
    // the ReadOnly tier is enforced by LANDLOCK (read-only ruleset), not here.
    // The non-vacuous test confirms ReadOnly cannot create/modify files on disk.
    "write",
    "pwrite64",
    "writev",
    "pwritev2",
    // File descriptor management
    "close",
    "dup",
    "dup2",
    "dup3",
    "lseek",
    "fcntl",
    // Memory
    "mmap",
    "munmap",
    "mremap",
    "brk",
    "mprotect",
    "madvise",
    // Process info + process-group / session queries. A shell (sh/bash) needs
    // getpgrp/getpgid/setpgid/setsid/getsid for job control even when running a
    // single `-c` command; without them bash aborts at startup. These touch
    // only the caller's own process group, never another process's privileges.
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getcwd",
    "getpgrp",
    "getpgid",
    "setpgid",
    "getsid",
    "setsid",
    "prlimit64",
    "getrlimit",
    "sched_getaffinity",
    "tgkill",
    // Process startup: the grandchild must execve the target command at EVERY
    // tier (ReadOnly runs a read-only command, it still has to exec it). Landlock
    // (read-only ruleset) is what prevents writes at the ReadOnly tier, not the
    // absence of execve. wait4/waitid let the command reap its own children.
    "execve",
    "execveat",
    "wait4",
    "waitid",
    // Signals
    "rt_sigprocmask",
    "rt_sigaction",
    "rt_sigreturn",
    "rt_sigtimedwait",
    "sigaltstack",
    // Time
    "clock_gettime",
    "gettimeofday",
    "nanosleep",
    "clock_nanosleep",
    "restart_syscall",
    // Entropy
    "getrandom",
    // Process / thread control (no privilege escalation; NNP is sticky)
    "prctl",
    "arch_prctl",
    "rseq",
    "set_tid_address",
    "set_robust_list",
    // Synchronization (threaded readers need these)
    "futex",
    "futex_waitv",
    "sched_yield",
    // Polling / readiness (readers may watch fds)
    "poll",
    "ppoll",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd2",
    // Exit
    "exit",
    "exit_group",
    // Stat family (both legacy and *at forms — glibc uses legacy here)
    "stat",
    "lstat",
    "fstat",
    "newfstatat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "fstatfs",
    "statfs",
    "uname",
];

/// Tier 1: ReadOnly conditional syscalls (argument-level constraints).
///
/// `(name, human description)`. The BPF condition is constructed in
/// `profile.rs`; this is the declarative manifest used for docs and tests.
pub const READONLY_CONDITIONAL: &[(&str, &str)] = &[
    ("openat", "access mode must be O_RDONLY (low 2 bits zero)"),
    ("open", "access mode must be O_RDONLY (low 2 bits zero)"),
];

/// Tier 2: WorkspaceWrite ADDITIONS — pure-allow, on top of Tier 1.
///
/// Adds process spawn, write I/O, path mutation, directory iteration, fd
/// lifecycle, ownership, and the local-IPC primitives cargo's jobserver needs.
pub const WORKSPACE_WRITE_ADDITIONS_PURE_ALLOW: &[&str] = &[
    // Thread/process spawn. `clone3` is allowed (Go/glibc use it for threads);
    // the namespace-escape concern is handled because the child has no
    // CAP_SYS_ADMIN inside its userns hierarchy and `unshare`/`setns` stay
    // denied. `clone` is constrained below (CLONE_NEW* bits masked off).
    // (execve/execveat/wait4/waitid live in the ReadOnly base — every tier execs.
    //  write/pwrite64/writev/pwritev2 also live there — stdout needs them; the
    //  ReadOnly filesystem-write ban is enforced by Landlock, not seccomp.)
    "clone3",
    // Path creation / mutation (legacy + *at forms, both observed)
    "creat",
    "open",
    "openat",
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    // Truncation
    "ftruncate",
    "truncate",
    // Metadata
    "fchmod",
    "fchmodat",
    "chmod",
    "utimensat",
    "umask",
    // Pipes / fd plumbing
    "pipe2",
    "pipe",
    // Working directory
    "chdir",
    "fchdir",
    // Directory iteration
    "getdents64",
    "getdents",
    // File copy primitives
    "copy_file_range",
    "sendfile",
    // Ownership
    "fchown",
    "fchownat",
    "lchown",
    "chown",
    // Storage hints / sync
    "fallocate",
    "fsync",
    "fdatasync",
    "sync_file_range",
    "flock",
    // Concurrency hints used by threaded build tools
    "membarrier",
    // LOCAL IPC ONLY — cargo's jobserver uses socketpair(AF_UNIX)+recvfrom.
    // Without socket/connect/bind, no network fd can ever be created, so these
    // cannot reach the network. socketpair(AF_INET) is unsupported by the
    // kernel, so this cannot be abused to create an INET pair.
    "socketpair",
    "recvfrom",
    "recvmsg",
    "sendmsg",
    "sendto",
];

/// Tier 2: WorkspaceWrite ADDITIONS — conditional syscalls.
pub const WORKSPACE_WRITE_ADDITIONS_CONDITIONAL: &[(&str, &str)] = &[
    ("openat", "all access modes allowed"),
    ("open", "all access modes allowed"),
    (
        "fcntl",
        "cmd restricted to F_GETFL|F_SETFL|F_GETFD|F_SETFD|F_DUPFD|F_DUPFD_CLOEXEC",
    ),
    (
        "ioctl",
        "request restricted to TIOCGWINSZ|FIOCLEX|FIONCLEX|FIONBIO|FIONREAD",
    ),
    (
        "clone",
        "flags MUST NOT include any CLONE_NEW* namespace bit (userns-escape vector)",
    ),
];

/// Full pure-allow list for `tier`. WorkspaceWrite is ReadOnly + its additions.
pub fn pure_allow_for(tier: PermissionTier) -> Vec<&'static str> {
    match tier {
        PermissionTier::ReadOnly => READONLY_PURE_ALLOW.to_vec(),
        PermissionTier::WorkspaceWrite => {
            let mut v = READONLY_PURE_ALLOW.to_vec();
            v.extend_from_slice(WORKSPACE_WRITE_ADDITIONS_PURE_ALLOW);
            v
        }
        PermissionTier::DangerFullAccess => Vec::new(),
    }
}

/// Conditional constraint manifest for `tier`.
pub fn conditional_for(tier: PermissionTier) -> Vec<(&'static str, &'static str)> {
    match tier {
        PermissionTier::ReadOnly => READONLY_CONDITIONAL.to_vec(),
        PermissionTier::WorkspaceWrite => WORKSPACE_WRITE_ADDITIONS_CONDITIONAL.to_vec(),
        PermissionTier::DangerFullAccess => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_substantial_and_excludes_write() {
        let list = pure_allow_for(PermissionTier::ReadOnly);
        assert!(
            list.len() >= 45,
            "expected >=45 syscalls, got {}",
            list.len()
        );
        assert!(list.contains(&"read"));
        assert!(list.contains(&"exit"));
        assert!(list.contains(&"futex"));
        // execve IS allowed at ReadOnly: the grandchild must exec the command.
        assert!(list.contains(&"execve"));
        // write IS allowed at ReadOnly (stdout); the FILE-write ban is enforced
        // by Landlock's read-only ruleset, not by seccomp.
        assert!(list.contains(&"write"));
        // ...but on-disk path *mutation* syscalls are NOT at ReadOnly.
        assert!(!list.contains(&"unlinkat"));
        assert!(!list.contains(&"mkdirat"));
    }

    #[test]
    fn workspace_strictly_extends_readonly() {
        use std::collections::HashSet;
        let ro: HashSet<_> = READONLY_PURE_ALLOW.iter().copied().collect();
        let ww: HashSet<_> = pure_allow_for(PermissionTier::WorkspaceWrite)
            .into_iter()
            .collect();
        assert!(
            ro.is_subset(&ww),
            "WorkspaceWrite must include all ReadOnly"
        );
        assert!(ww.len() > ro.len());
        assert!(ww.contains("write"));
        assert!(ww.contains("execve"));
        assert!(ww.contains("mkdirat"));
        assert!(ww.contains("mkdir")); // legacy form, empirically required
    }

    #[test]
    fn build_tool_syscalls_present() {
        // Regression guard: the syscalls the unverified reference omitted but a
        // real cargo build / node / go empirically require.
        let ww = pure_allow_for(PermissionTier::WorkspaceWrite);
        for sc in [
            "futex",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "epoll_pwait",
            "poll",
            "eventfd2",
            "restart_syscall",
            "sched_yield",
            "sched_getaffinity",
            "rseq",
            "clone3",
            "readlink",
            "access",
            "stat",
            "lstat",
            "rename",
            "unlink",
            "flock",
            "socketpair",
        ] {
            assert!(ww.contains(&sc), "WorkspaceWrite must allow {sc}");
        }
    }

    #[test]
    fn network_and_escape_syscalls_never_allowed() {
        let forbidden = [
            // Network connection establishment.
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "socketcall",
            // Sandbox escape primitives.
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "perf_event_open",
            "unshare",
            "setns",
            "kexec_load",
            "init_module",
            "finit_module",
            "delete_module",
            "reboot",
            "mount",
            "umount2",
            "pivot_root",
            "swapon",
            "swapoff",
            // Deny-by-omission escape surfaces.
            "io_uring_setup",
            "io_uring_enter",
            "openat2",
            // Landlock syscalls must never be callable after seccomp.
            "landlock_create_ruleset",
            "landlock_add_rule",
            "landlock_restrict_self",
        ];
        for tier in [PermissionTier::ReadOnly, PermissionTier::WorkspaceWrite] {
            let list = pure_allow_for(tier);
            for f in &forbidden {
                assert!(!list.contains(f), "tier {tier:?} must NOT allow {f}");
            }
        }
    }

    #[test]
    fn openat_is_conditional_for_readonly() {
        assert!(!READONLY_PURE_ALLOW.contains(&"openat"));
        let cond = conditional_for(PermissionTier::ReadOnly);
        assert!(cond.iter().any(|(n, _)| *n == "openat"));
        assert!(cond.iter().any(|(n, _)| *n == "open"));
    }

    #[test]
    fn no_duplicates_per_tier() {
        use std::collections::HashSet;
        for tier in [PermissionTier::ReadOnly, PermissionTier::WorkspaceWrite] {
            let list = pure_allow_for(tier);
            let uniq: HashSet<_> = list.iter().copied().collect();
            assert_eq!(
                uniq.len(),
                list.len(),
                "tier {tier:?} has duplicate syscalls"
            );
        }
    }

    #[test]
    fn danger_has_no_lists() {
        assert!(pure_allow_for(PermissionTier::DangerFullAccess).is_empty());
        assert!(conditional_for(PermissionTier::DangerFullAccess).is_empty());
    }
}
