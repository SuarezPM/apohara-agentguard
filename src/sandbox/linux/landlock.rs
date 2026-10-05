//! Landlock LSM filesystem confinement per permission tier.
//!
//! Builds and applies a Landlock ruleset that confines the calling process to
//! the workspace root:
//!   - ReadOnly: read-only access rights over `workspace_root`.
//!   - WorkspaceWrite: read + write/create/remove over `workspace_root`;
//!     everything outside is denied.
//!   - DangerFullAccess: no ruleset (Landlock skipped entirely).
//!
//! Access matrix outside the workspace (both enforcing tiers):
//!   - READ + EXECUTE over `SYSTEM_RX_PATHS` (FHS system dirs incl. `/opt`,
//!     loader files, scoped /etc subtrees, /dev null-ish devices, /proc/self)
//!     and over env-resolved toolchain roots (`RUSTUP_HOME`, `CARGO_HOME`,
//!     `GOROOT`, `GOMODCACHE`, `GOPATH`). Execute is required for the tier
//!     promise "the requested tool runs"; it is granted read-only so system
//!     toolchains can be executed but never modified.
//!   - WRITE (full) over `GOCACHE` (default `~/.cache/go-build`) at
//!     WorkspaceWrite only.
//!   - Everything else outside the workspace: DENIED (fail-closed), including
//!     `/etc/passwd` and `$HOME/.ssh`.
//!
//! Both enforcing tiers require Landlock ABI v3. This is the first ABI that
//! mediates `truncate(2)`, `ftruncate(2)`, `creat(2)`, and `open(2)` with
//! `O_TRUNC`. Older kernels are rejected rather than silently dropping that
//! access right and running with weaker confinement.
//!
//! ## Fail-closed errno taxonomy
//!
//! If the kernel can't enforce Landlock we REFUSE to run (never silently
//! unconfined). The kernel error is mapped to an actionable message:
//!   - ENOSYS  -> "Landlock unavailable (need ABI v3 or newer)"
//!   - EOPNOTSUPP -> "Landlock disabled at boot; add lsm=landlock to the
//!     kernel cmdline"
//!   - EPERM on a Landlock syscall -> "internal: seccomp installed before
//!     Landlock (ordering bug)" — self-diagnoses the pinned-ordering invariant.
//!
//! This module must run BEFORE the seccomp filter is installed (the runner
//! enforces NNP -> Landlock -> seccomp). The Landlock syscalls are deliberately
//! absent from every seccomp allowlist, so once seccomp is in place the child
//! cannot weaken its own ruleset.

use landlock::{
    Access, AccessError, AccessFs, BitFlags, CompatError, CompatLevel, Compatible, Errno,
    HandleAccessError, HandleAccessesError, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus, ABI,
};
use std::os::unix::io::{AsFd, AsRawFd};
use std::path::Path;

use crate::sandbox::error::{Result, SandboxError};
use crate::sandbox::permission::PermissionTier;
use crate::sandbox::REQUIRED_LANDLOCK_ABI;

/// Minimum Landlock ABI we target. V3 adds `AccessFs::Truncate`; requesting it
/// with `HardRequirement` prevents silent downgrade on ABI v1/v2 kernels.
const TARGET_ABI: ABI = ABI::V3;

/// Read-only rights for directory FDs (`Execute | ReadFile | ReadDir`).
fn dir_rx() -> BitFlags<AccessFs> {
    AccessFs::from_read(TARGET_ABI)
}

/// Read-only rights for non-directory FDs: `from_read` minus dir-only bits
/// (`ReadDir`, `Refer`, …). Attaching dir-only rights to a file FD makes the
/// kernel (and the `landlock` crate's `PathBeneath` consistency check) reject
/// the whole rule with `EINVAL` / `DirectoryAccess`.
fn file_rx() -> BitFlags<AccessFs> {
    AccessFs::Execute | AccessFs::ReadFile
}

/// Full rights for non-directory FDs: `from_all` minus dir-only bits.
/// Valid file rights at V3 are `ReadFile | WriteFile | Execute | Truncate`
/// (`IoctlDev`/`ResolveUnix` arrive in later ABIs and are not requested here).
fn file_rw() -> BitFlags<AccessFs> {
    AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
}

/// `true` when `fd` points at a directory (via `fstat`, so symlinks are
/// already resolved to their target). A failed `fstat` returns `false`, which
/// selects the narrower file-only grant — fail-closed, never `EINVAL`.
fn fd_is_dir(fd: &impl AsFd) -> bool {
    // SAFETY: `fstat` on a borrowed, live FD with a zeroed out-param.
    unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_fd().as_raw_fd(), &mut stat) != 0 {
            return false;
        }
        (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
    }
}

/// Pick the directory vs file grant for an already-opened [`PathFd`].
fn access_for_fd(
    fd: &PathFd,
    dir: BitFlags<AccessFs>,
    file: BitFlags<AccessFs>,
) -> BitFlags<AccessFs> {
    if fd_is_dir(fd) {
        dir
    } else {
        file
    }
}

/// System paths the sandboxed process needs READ + EXECUTE access to in order to
/// run *any* binary at all: the binary itself, the dynamic loader, shared
/// libraries, locales, and a few read-only device/proc entries.
///
/// These are granted read-only (no write/create/remove), so the child can
/// execute system tools (cargo/node/go/sh) but cannot tamper with them. We do
/// NOT grant blanket `/etc` access — only the specific files the loader needs —
/// so `/etc/passwd` (and `$HOME/.ssh/...`) stay DENIED, which the non-vacuous
/// test asserts. Missing paths are skipped (PathFd::new fails -> ignored): the
/// list is a superset for portability across distros.
const SYSTEM_RX_PATHS: &[&str] = &[
    "/usr", // bins, libs, locales, gconv (on Arch /bin and /lib symlink here)
    "/bin",
    "/sbin",
    "/lib",
    "/lib64", // separate-/usr distros
    "/opt",   // /opt-rooted toolchains: GitHub hostedtoolcache (/usr/bin/go is a
    // symlink into /opt/hostedtoolcache/go/... on ubuntu-24.04 runners),
    // /opt-installed SDKs. Read+execute only, so /opt stays untamperable.
    "/etc/ld.so.cache",   // dynamic loader cache (single file, not all of /etc)
    "/etc/ld.so.preload", // loader preload list (single file)
    "/etc/alternatives",  // Debian/Ubuntu binary alternatives
    // TLS / runtime config that toolchains read at startup. These are scoped to
    // specific subtrees/files so /etc/passwd, /etc/shadow, /etc/sudoers, and the
    // like stay DENIED (the non-vacuous test asserts /etc/passwd is unreadable).
    "/etc/ssl",
    "/etc/openssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/ca-certificates.conf",
    "/etc/crypto-policies",
    "/etc/gitconfig",
    "/etc/malloc.conf",
    "/etc/rustup",
    "/etc/localtime",
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/urandom",
    "/dev/random",
    "/dev/tty",
    "/proc/self",                     // many runtimes read /proc/self/{maps,exe,...}
    "/proc/sys/vm/overcommit_memory", // some allocators probe this
    "/sys/kernel/mm/transparent_hugepage", // go/jemalloc probe THP
];

/// Toolchain support dirs that build tools READ (but never write) outside the
/// workspace: the rust toolchains, the cargo registry, the go module cache, the
/// go root. Resolved at runtime from the standard env vars (with HOME-relative
/// fallbacks) so the build e2e works without hardcoding a user's layout. These
/// are granted read+execute ONLY — never write — and are specific subtrees, so
/// `$HOME/.ssh` stays denied (the non-vacuous test asserts that).
fn toolchain_read_paths() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let from_env_or = |var: &str, rel: &str| -> Option<PathBuf> {
        if let Some(v) = std::env::var_os(var) {
            return Some(PathBuf::from(v));
        }
        home.as_ref().map(|h| h.join(rel))
    };
    let mut paths = Vec::new();
    if let Some(p) = from_env_or("RUSTUP_HOME", ".rustup") {
        paths.push(p);
    }
    if let Some(p) = from_env_or("CARGO_HOME", ".cargo") {
        paths.push(p);
    }
    if let Some(v) = std::env::var_os("GOROOT") {
        paths.push(PathBuf::from(v));
    }
    if let Some(p) = from_env_or("GOMODCACHE", "go/pkg/mod") {
        paths.push(p);
    }
    // GOPATH default ~/go contains bin/pkg the toolchain reads.
    if let Some(p) = from_env_or("GOPATH", "go") {
        paths.push(p);
    }
    paths
}

/// Cache dirs build tools must WRITE outside the workspace (go build cache).
/// Granted full access. Scoped to the specific cache subtree, not all of HOME.
fn toolchain_write_paths() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut paths = Vec::new();
    if let Some(v) = std::env::var_os("GOCACHE") {
        paths.push(PathBuf::from(v));
    } else if let Some(h) = &home {
        paths.push(h.join(".cache/go-build"));
    }
    paths
}

/// Apply the Landlock ruleset for `tier`, confining the process to
/// `workspace_root`. No-op for DangerFullAccess.
///
/// `workspace_root` must already be canonicalized (the runner does this before
/// calling). Returns a [`SandboxError::Landlock`] carrying an actionable
/// taxonomy message if the kernel can't enforce Landlock.
pub(crate) fn apply(tier: PermissionTier, workspace_root: &Path) -> Result<()> {
    if matches!(tier, PermissionTier::DangerFullAccess) {
        return Ok(());
    }

    // Rights we want to *handle* (deny unless explicitly granted) and the
    // rights we *grant* over the workspace root.
    let handled = AccessFs::from_all(TARGET_ABI);
    let granted = match tier {
        PermissionTier::ReadOnly => AccessFs::from_read(TARGET_ABI),
        PermissionTier::WorkspaceWrite => AccessFs::from_all(TARGET_ABI),
        // DangerFullAccess early-returns Ok(()) at the top of this fn, so this
        // arm is dead today. Make the invariant explicit and fail-closed (a
        // propagated Err -> the runner maps it to a setup-error refusal) rather
        // than an `unreachable!` panic in the post-fork grandchild.
        PermissionTier::DangerFullAccess => {
            return Err(SandboxError::Landlock(
                "DangerFullAccess has no ruleset".into(),
            ))
        }
    };

    let root_fd = PathFd::new(workspace_root).map_err(|e| {
        SandboxError::Landlock(format!(
            "cannot open workspace_root {} for Landlock: {e}",
            workspace_root.display()
        ))
    })?;

    // Read + execute over system paths so the child can actually run a binary;
    // the exact rights are intersected with `handled` by the kernel.
    // NOTE: a per-rule `BestEffort` does NOT help here — the parent ruleset is
    // `HardRequirement` and `tailored_compat_level` takes the max (most
    // constrained), so a file FD with dir-only bits would still hard-error.
    // Split the grant by FD type instead (see `file_rx`).
    let system_rx_dir = dir_rx();
    let system_rx_file = file_rx();

    let mut created: RulesetCreated = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(map_ruleset_err)?
        .create()
        .map_err(map_ruleset_err)?
        // Grant the tier's rights over the workspace root.
        .add_rule(PathBeneath::new(root_fd, granted))
        .map_err(map_ruleset_err)?;

    // Grant read+execute over each existing system path. A path that doesn't
    // exist on this distro is skipped (it can't be a confinement hole).
    // `SYSTEM_RX_PATHS` intentionally mixes directories (`/usr`, `/etc/ssl`)
    // with regular files (`/etc/ld.so.cache`) and devices (`/dev/null`):
    // dir-only rights (`ReadDir`, `Refer`, …) on a file FD are `EINVAL`, so
    // select the grant from the FD's own `fstat` type.
    for p in SYSTEM_RX_PATHS {
        if let Ok(fd) = PathFd::new(p) {
            let access = access_for_fd(&fd, system_rx_dir, system_rx_file);
            created = created
                .add_rule(PathBeneath::new(fd, access))
                .map_err(map_ruleset_err)?;
        }
    }

    // Read+execute on toolchain support dirs so build tools can run.
    for p in toolchain_read_paths() {
        if let Ok(fd) = PathFd::new(&p) {
            let access = access_for_fd(&fd, system_rx_dir, system_rx_file);
            created = created
                .add_rule(PathBeneath::new(fd, access))
                .map_err(map_ruleset_err)?;
        }
    }

    // Read+write on the few cache dirs build tools must write outside the
    // workspace (e.g. the go build cache). Only at WorkspaceWrite — ReadOnly
    // never needs to write a cache.
    if matches!(tier, PermissionTier::WorkspaceWrite) {
        let cache_rw_dir = AccessFs::from_all(TARGET_ABI);
        let cache_rw_file = file_rw();
        for p in toolchain_write_paths() {
            // Best-effort create so the rule has a real dir to attach to.
            let _ = std::fs::create_dir_all(&p);
            if let Ok(fd) = PathFd::new(&p) {
                let access = access_for_fd(&fd, cache_rw_dir, cache_rw_file);
                created = created
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(map_ruleset_err)?;
            }
        }
    }

    let status = created.restrict_self().map_err(map_ruleset_err)?;

    // Inspect the enforcement result. A capable kernel must FullyEnforce; a
    // kernel that lacks Landlock surfaces here as NotImplemented / NotEnabled
    // and we fail-closed with the taxonomy message.
    match status.landlock {
        LandlockStatus::NotImplemented => Err(SandboxError::Landlock(format!(
            "Landlock refused (ENOSYS): unavailable; need ABI v{REQUIRED_LANDLOCK_ABI} or newer \
                 (normally Linux >= 6.2)"
        ))),
        LandlockStatus::NotEnabled => Err(SandboxError::Landlock(
            "Landlock refused (EOPNOTSUPP): Landlock disabled at boot; \
             add lsm=landlock to the kernel cmdline"
                .into(),
        )),
        LandlockStatus::Available { effective_abi, .. } => {
            // Loud ABI gate: `handle_access(HardRequirement)` already rejects
            // v1/v2 kernels at build time, but a `PartiallyEnforced` status
            // (best-effort downgrade) must never be accepted silently either.
            // Truncate confinement needs ABI v3; anything less refuses loudly.
            if effective_abi < TARGET_ABI {
                Err(SandboxError::Landlock(format!(
                    "Landlock refused: kernel ABI v{effective_abi:?} (< v3) cannot confine \
                     truncate/ftruncate; need ABI v{REQUIRED_LANDLOCK_ABI} or newer \
                     (normally Linux >= 6.2; 5.13–6.1 only provide ABI v1/v2)"
                )))
            } else if status.ruleset != RulesetStatus::FullyEnforced {
                Err(SandboxError::Landlock(format!(
                    "Landlock refused: ruleset not fully enforced ({:?}; need FullyEnforced \
                     at ABI v{REQUIRED_LANDLOCK_ABI}) — refusing to run unconfined",
                    status.ruleset
                )))
            } else if !status.no_new_privs {
                // restrict_self requires NO_NEW_PRIVS; the runner sets it before
                // calling us. If it's missing, the ordering invariant broke.
                Err(SandboxError::Landlock(
                    "Landlock enforced but NO_NEW_PRIVS not set — internal ordering bug \
                     (NNP must be set before Landlock)"
                        .into(),
                ))
            } else {
                // The Landlock self-restrict verification is the
                // RUNNER-level Landlock_Allowed list: `landlock_*`
                // syscalls are NOT in the seccomp allowlist (the
                // child can't call them after seccomp is installed).
                // The property "Landlock is one-way" is enforced by
                // the kernel semantics: subsequent `restrict_self`
                // calls INTERSECT the new ruleset with the existing
                // one (always more restrictive, never loosens). The
                // post-restrict check is therefore the kernel's own
                // status inspection above (FullyEnforced + NNP set),
                // not a separate "can the child re-restrict"
                // assertion — that test would be kernel-version
                // dependent and is covered by the seccomp side (the
                // child can't even REACH landlock_* after seccomp
                // install).
                Ok(())
            }
        }
    }
}

// POST_RESTRICT_SKIP_CHECK is no longer used (the runner-level
// Landlock self-check was removed; the kernel's own status
// inspection is the assertion). The dead-code marker is a
// documented forward-compat hook in case a kernel-specific check
// becomes necessary. Kept `pub` + `doc(hidden)` for ABI stability
// with the integration test that imported it; the test no longer
// calls it.
#[doc(hidden)]
#[allow(dead_code)]
pub static POST_RESTRICT_SKIP_CHECK: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);
#[doc(hidden)]
#[allow(dead_code)]
pub fn set_post_restrict_skip_check(skip: bool) {
    POST_RESTRICT_SKIP_CHECK.store(
        if skip { 1 } else { 0 },
        std::sync::atomic::Ordering::SeqCst,
    );
}

/// Map a `landlock::RulesetError` into our taxonomy. The crate's `Errno` helper
/// extracts the underlying kernel errno; EPERM on a Landlock syscall is the
/// self-diagnosing signal that seccomp was (wrongly) installed first.
fn map_ruleset_err(err: RulesetError) -> SandboxError {
    if matches!(
        &err,
        RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
            CompatError::Access(
                AccessError::Incompatible { .. } | AccessError::PartiallyCompatible { .. }
            )
        )))
    ) {
        return SandboxError::Landlock(format!(
            "Landlock refused: need ABI v{REQUIRED_LANDLOCK_ABI} or newer \
             (normally Linux >= 6.2) to confine truncate/ftruncate; the running kernel \
             does not support all required filesystem access rights"
        ));
    }

    let display = err.to_string();
    let errno = *Errno::from(err);
    match errno {
        libc::ENOSYS => SandboxError::Landlock(format!(
            "Landlock refused (ENOSYS): unavailable; need ABI v{REQUIRED_LANDLOCK_ABI} or newer \
                 (normally Linux >= 6.2)"
        )),
        libc::EOPNOTSUPP => SandboxError::Landlock(
            "Landlock refused (EOPNOTSUPP): Landlock disabled at boot; \
             add lsm=landlock to the kernel cmdline"
                .into(),
        ),
        libc::EPERM => SandboxError::Landlock(
            "Landlock refused (EPERM): internal: seccomp installed before Landlock \
             (ordering bug) — the pinned NNP->Landlock->seccomp order was violated"
                .into(),
        ),
        other => {
            SandboxError::Landlock(format!("Landlock setup failed (errno={other}): {display}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn danger_is_noop() {
        // DangerFullAccess never touches the kernel; any path is fine.
        apply(PermissionTier::DangerFullAccess, Path::new("/nonexistent")).unwrap();
    }

    #[test]
    fn target_abi_handles_truncate() {
        assert_eq!(TARGET_ABI as u32, REQUIRED_LANDLOCK_ABI);
        assert!(AccessFs::from_all(TARGET_ABI).contains(AccessFs::Truncate));
    }
}
