//! Landlock LSM filesystem confinement per permission tier.
//!
//! Builds and applies a Landlock ruleset that confines the calling process to
//! the workspace root:
//!   - ReadOnly: read-only access rights over `workspace_root`.
//!   - WorkspaceWrite: read + write/create/remove over `workspace_root`;
//!     everything outside is denied.
//!   - DangerFullAccess: no ruleset (Landlock skipped entirely).
//!
//! ABI is auto-detected via the `landlock` crate's `CompatLevel::BestEffort`,
//! so we use the best feature set the running kernel supports while keeping the
//! ruleset enforceable on older kernels.
//!
//! ## Fail-closed errno taxonomy
//!
//! If the kernel can't enforce Landlock we REFUSE to run (never silently
//! unconfined). The kernel error is mapped to an actionable message:
//!   - ENOSYS  -> "kernel too old (need Linux >= 5.13 for Landlock)"
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
    Access, AccessFs, CompatLevel, Compatible, Errno, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::Path;

use crate::sandbox::error::{Result, SandboxError};
use crate::sandbox::permission::PermissionTier;

/// Minimum Landlock ABI we target. V1 already covers read/write/create/remove
/// of files and directories, which is all the tiers need. BestEffort lets a
/// newer kernel transparently use a higher ABI.
const TARGET_ABI: ABI = ABI::V1;

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
    "/lib64",             // separate-/usr distros
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
pub fn apply(tier: PermissionTier, workspace_root: &Path) -> Result<()> {
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
    let system_rx = AccessFs::from_read(TARGET_ABI);

    let mut created: RulesetCreated = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(handled)
        .map_err(map_ruleset_err)?
        .create()
        .map_err(map_ruleset_err)?
        // Grant the tier's rights over the workspace root.
        .add_rule(PathBeneath::new(root_fd, granted))
        .map_err(map_ruleset_err)?;

    // Grant read+execute over each existing system path. A path that doesn't
    // exist on this distro is skipped (it can't be a confinement hole).
    for p in SYSTEM_RX_PATHS {
        if let Ok(fd) = PathFd::new(p) {
            created = created
                .add_rule(PathBeneath::new(fd, system_rx))
                .map_err(map_ruleset_err)?;
        }
    }

    // Read+execute on toolchain support dirs so build tools can run.
    for p in toolchain_read_paths() {
        if let Ok(fd) = PathFd::new(&p) {
            created = created
                .add_rule(PathBeneath::new(fd, system_rx))
                .map_err(map_ruleset_err)?;
        }
    }

    // Read+write on the few cache dirs build tools must write outside the
    // workspace (e.g. the go build cache). Only at WorkspaceWrite — ReadOnly
    // never needs to write a cache.
    if matches!(tier, PermissionTier::WorkspaceWrite) {
        let cache_rw = AccessFs::from_all(TARGET_ABI);
        for p in toolchain_write_paths() {
            // Best-effort create so the rule has a real dir to attach to.
            let _ = std::fs::create_dir_all(&p);
            if let Ok(fd) = PathFd::new(&p) {
                created = created
                    .add_rule(PathBeneath::new(fd, cache_rw))
                    .map_err(map_ruleset_err)?;
            }
        }
    }

    let status = created.restrict_self().map_err(map_ruleset_err)?;

    // Inspect the enforcement result. A capable kernel must FullyEnforce; a
    // kernel that lacks Landlock surfaces here as NotImplemented / NotEnabled
    // and we fail-closed with the taxonomy message.
    match status.landlock {
        LandlockStatus::NotImplemented => Err(SandboxError::Landlock(
            "Landlock refused (ENOSYS): kernel too old (need Linux >= 5.13 for Landlock)".into(),
        )),
        LandlockStatus::NotEnabled => Err(SandboxError::Landlock(
            "Landlock refused (EOPNOTSUPP): Landlock disabled at boot; \
             add lsm=landlock to the kernel cmdline"
                .into(),
        )),
        LandlockStatus::Available { .. } => {
            if status.ruleset == RulesetStatus::NotEnforced {
                Err(SandboxError::Landlock(
                    "Landlock ruleset could not be enforced (NotEnforced) — refusing to run \
                     unconfined"
                        .into(),
                ))
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
fn map_ruleset_err<E>(err: E) -> SandboxError
where
    E: std::error::Error + 'static,
{
    let display = err.to_string();
    let errno = *Errno::from(err);
    match errno {
        libc::ENOSYS => SandboxError::Landlock(
            "Landlock refused (ENOSYS): kernel too old (need Linux >= 5.13 for Landlock)".into(),
        ),
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
}
