//! Linux sandbox runner: two-fork isolation + the pinned install order.
//!
//! Topology:
//!
//! ```text
//!  parent (apohara-agentguard)
//!    | pipes: stdout / stderr / exec-error
//!    | fork() ----------------------------------------+
//!    | read pipes + waitpid(middle)                   v
//!    |                                              middle child
//!    |                                                | enter_isolated_namespaces()
//!    |                                                | fork() --------------------+
//!    |                                                | waitpid(grand)             v
//!    |                                                | _exit(grand status)     grandchild (PID 1)
//!    |                                                |                            | dup2 stdio
//!    |                                                |                            | chdir(workdir)
//!    |                                                |                            | close fds > 2
//!    |                                                |                            | 1. prctl(NNP, 1)
//!    |                                                |                            | 2. Landlock apply
//!    |                                                |                            | 3. seccomp install
//!    |                                                |                            | execvp(command)
//! ```
//!
//! Two forks because `unshare(CLONE_NEWPID)` only takes effect for the caller's
//! *future* children: the middle child forks once more so the grandchild is
//! PID 1 in the new PID namespace.

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    chdir, dup2_stderr, dup2_stdin, dup2_stdout, execvpe, fork, pipe2, read, write, ForkResult,
};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use crate::sandbox::error::{Result, SandboxError};
use crate::sandbox::linux::landlock;
use crate::sandbox::linux::namespace::enter_isolated_namespaces;
use crate::sandbox::linux::profile::SeccompProfile;
use crate::sandbox::pathsafe::{canonicalize_recursive, is_strict_descendant};
use crate::sandbox::{SandboxRequest, SandboxResult};
use nix::fcntl::OFlag;

/// Hard cap on captured stdout/stderr so a runaway child can't OOM the parent.
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Canonicalize the workdir and confirm it's a strict descendant of (or equal
/// to) `workspace_root`. The workdir defaults to `workspace_root` itself when
/// the caller doesn't narrow it; in that case the resolved paths are equal,
/// which is allowed (the workspace root is the legitimate working directory).
pub fn validate_workdir(workdir: &Path, workspace_root: &Path) -> Result<PathBuf> {
    let root = canonicalize_recursive(workspace_root).map_err(|e| {
        SandboxError::Workdir(format!(
            "cannot canonicalize workspace_root {}: {e}",
            workspace_root.display()
        ))
    })?;
    let work = canonicalize_recursive(workdir).map_err(|e| {
        SandboxError::Workdir(format!(
            "cannot canonicalize workdir {}: {e}",
            workdir.display()
        ))
    })?;
    if work != root && !is_strict_descendant(&work, &root) {
        return Err(SandboxError::Workdir(format!(
            "workdir escapes workspace_root: workdir={} root={}",
            work.display(),
            root.display()
        )));
    }
    Ok(work)
}

pub fn run_linux(req: &SandboxRequest) -> Result<SandboxResult> {
    let started = Instant::now();

    if req.command.is_empty() {
        return Err(SandboxError::Workdir(
            "command must have at least one argv".into(),
        ));
    }

    // The workdir is the workspace_root unless narrowed in a future API; for now
    // we run inside the canonicalized workspace_root.
    let workdir_canon = validate_workdir(&req.workspace_root, &req.workspace_root)?;

    let argv: Vec<CString> = req
        .command
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| SandboxError::Workdir("argv contains an interior NUL byte".into()))?;
    // Point TMPDIR inside the workspace: linkers (cc/lld), rustc, and many
    // tools write scratch files to $TMPDIR, and the host's TMPDIR is outside the
    // workspace and denied by Landlock. A dedicated subdir keeps that scratch
    // inside the confined, writable zone.
    let tmp_in_workspace = workdir_canon.join(".agentguard-tmp");
    // Create it now (parent side, before any confinement) so the dir exists for
    // tools that assume $TMPDIR is present. It lives inside the workspace, so it
    // stays within the Landlock-writable zone.
    let _ = std::fs::create_dir_all(&tmp_in_workspace);
    let env: Vec<CString> = build_sanitized_env(&tmp_in_workspace);

    let (stdout_r, stdout_w) = make_pipe(false)?;
    let (stderr_r, stderr_w) = make_pipe(false)?;
    // exec-error pipe is CLOEXEC: a successful execvp auto-closes it -> parent
    // reads EOF; a failure writes the errno before exec.
    let (exec_err_r, exec_err_w) = make_pipe(true)?;

    // SAFETY: fork() copies only the calling thread, and this runner has not
    // spawned any threads before this point (the drain threads below are
    // created strictly after the fork), so the child inherits a quiescent,
    // single-threaded address space with no locks held by an absent thread.
    // Both ForkResult arms diverge permanently — the child never returns into
    // the parent's control flow — which is nix's stated contract for fork().
    match unsafe { fork() }.map_err(nix_err)? {
        ForkResult::Parent { child: middle } => {
            drop(stdout_w);
            drop(stderr_w);
            drop(exec_err_w);

            // Drain stdout/stderr concurrently so a full pipe can't deadlock us.
            let stdout_handle = thread::spawn(move || read_bounded(&stdout_r, MAX_OUTPUT_BYTES));
            let stderr_handle = thread::spawn(move || read_bounded(&stderr_r, MAX_OUTPUT_BYTES));
            let stdout = stdout_handle
                .join()
                .map_err(|_| SandboxError::Runner("stdout drain panicked".into()))??;
            let stderr = stderr_handle
                .join()
                .map_err(|_| SandboxError::Runner("stderr drain panicked".into()))??;

            let setup_err = read_setup_error(&exec_err_r)?;
            let status = waitpid(middle, None).map_err(nix_err)?;
            let (exit_code, violations) = summarize(status, setup_err, req);

            Ok(SandboxResult {
                exit_code,
                stdout,
                stderr,
                duration_ms: started.elapsed().as_millis() as u64,
                violations,
            })
        }
        ForkResult::Child => {
            // Middle child.
            drop(stdout_r);
            drop(stderr_r);
            drop(exec_err_r);

            if let Err(e) = enter_isolated_namespaces() {
                report_setup_error(&exec_err_w, &format!("namespace: {e}"));
                // SAFETY: fail-closed teardown of the middle child after a
                // failed namespace entry. `_exit` is async-signal-safe and
                // skips Drop glue, atexit handlers, and stdio flushing — all
                // of which must not run on this forked image. The error is
                // already durably reported via the exec-error pipe, and the
                // child must terminate here rather than continue into
                // parent-only control flow.
                unsafe { libc::_exit(70) };
            }

            // SAFETY: same single-threaded invariant as the outer fork: this
            // middle child is itself a fork product (fork copies one thread),
            // so its address space is quiescent and consistent for the kernel
            // to snapshot again. The arms below diverge permanently.
            match unsafe { fork() } {
                Err(e) => {
                    report_setup_error(&exec_err_w, &format!("inner fork: {e}"));
                    // SAFETY: `_exit` is async-signal-safe and runs no
                    // destructors; the inner fork failed, the error is already
                    // written to the exec-error pipe, and the middle child
                    // must not unwind or fall through into either fork arm.
                    unsafe { libc::_exit(71) };
                }
                Ok(ForkResult::Parent { child: grand }) => {
                    drop(stdout_w);
                    drop(stderr_w);
                    drop(exec_err_w);
                    match waitpid(grand, None) {
                        // SAFETY: relaying the grandchild's exit code to the
                        // real parent with the conventional status pass-through.
                        // `_exit` is async-signal-safe; skipping destructors is
                        // correct here because every pipe fd was dropped above
                        // (so the parent's EOF/error reads are already satisfied)
                        // and the kernel closes any remaining fds at exit.
                        Ok(WaitStatus::Exited(_, c)) => unsafe { libc::_exit(c) },
                        // SAFETY: grandchild died by signal; relay it using the
                        // shell convention 128+sig so the parent's summarize()
                        // sees the same code a shell would report. Same
                        // async-signal-safe, no-destructor rationale as above.
                        Ok(WaitStatus::Signaled(_, sig, _)) => unsafe {
                            libc::_exit(128 + sig as i32)
                        },
                        // SAFETY: waitpid returned an unexpected status shape;
                        // 72 is this runner's distinct "relay failed" code.
                        // Fail-closed immediate termination, same invariants as
                        // the sibling arms: async-signal-safe, no unwinding on
                        // the forked image.
                        _ => unsafe { libc::_exit(72) },
                    }
                }
                Ok(ForkResult::Child) => {
                    run_grandchild(
                        req,
                        &workdir_canon,
                        &argv,
                        &env,
                        stdout_w,
                        stderr_w,
                        exec_err_w,
                    );
                }
            }
        }
    }
}

/// Grandchild (PID 1 in the new PID namespace). Redirect stdio, chdir, close
/// stray fds, then the LOAD-BEARING install order before execvp.
fn run_grandchild(
    req: &SandboxRequest,
    workdir: &Path,
    argv: &[CString],
    env: &[CString],
    stdout_w: OwnedFd,
    stderr_w: OwnedFd,
    exec_err_w: OwnedFd,
) -> ! {
    // /dev/null on stdin so a child waiting for input doesn't hang.
    if let Ok(devnull) = std::fs::File::open("/dev/null") {
        let _ = dup2_stdin(devnull.as_fd());
    }
    if dup2_stdout(stdout_w.as_fd()).is_err() {
        report_setup_error(&exec_err_w, "dup2 stdout");
        // SAFETY: grandchild (PID 1 of the new PID namespace) cannot proceed
        // with unwired stdout — fail closed. `_exit` is async-signal-safe and
        // runs no destructors on this forked image; the error is already
        // reported through the exec-error pipe.
        unsafe { libc::_exit(80) };
    }
    if dup2_stderr(stderr_w.as_fd()).is_err() {
        report_setup_error(&exec_err_w, "dup2 stderr");
        // SAFETY: same fail-closed teardown as the stdout dup2 above: unwired
        // stderr makes the child unusable, the error is already on the
        // exec-error pipe, and `_exit` terminates without destructor or
        // atexit runs on the post-fork image.
        unsafe { libc::_exit(81) };
    }

    if let Err(e) = chdir(workdir) {
        report_setup_error(&exec_err_w, &format!("chdir({}): {e}", workdir.display()));
        // SAFETY: the workdir was validated and canonicalized in the parent,
        // so a chdir failure here means the environment is not what the
        // Landlock ruleset was built for — refuse to exec. `_exit` is
        // async-signal-safe and skips destructors; the errno text is already
        // reported via the exec-error pipe.
        unsafe { libc::_exit(82) };
    }

    // Close every fd > 2 EXCEPT the exec-error pipe (CLOEXEC, closes on exec).
    // This stops an fd opened outside workspace_root before the sandbox setup
    // from leaking past `restrict_self` into the exec'd command. The pipe fds we
    // dup2'd onto 0/1/2 are already in place; their original OwnedFds are
    // dropped right after this call.
    let keep = exec_err_w.as_raw_fd();
    close_inherited_fds(keep);
    // The dup2 source fds are still open as fds > 2 here; we kept them out of
    // the close range only via `keep` for the exec-error pipe. Drop the now-
    // redundant stdout/stderr OwnedFds (their content lives on 1/2 now). They
    // were already closed by close_inherited_fds if their raw fd > 2; dropping
    // an already-closed OwnedFd would double-close, so leak them deliberately.
    std::mem::forget(stdout_w);
    std::mem::forget(stderr_w);

    // ---- PINNED INSTALL ORDER (DO NOT REORDER) ----------------------------
    //
    // 1) NO_NEW_PRIVS first. Landlock's restrict_self(2) REQUIRES it, and
    //    seccomp (which would otherwise set it via apply_filter) runs LAST now.
    // 2) Landlock next. Its syscalls (landlock_create_ruleset/add_rule/
    //    restrict_self) are NOT in the seccomp allowlist.
    // 3) seccomp LAST. If seccomp were installed first, mismatch_action=EPERM
    //    would EPERM the un-allowlisted Landlock syscalls and Landlock setup
    //    would fail-closed-refuse on EVERY run even on a capable kernel.
    //    Ordering-last is chosen over allowlisting 444/445/446 so that NO
    //    Landlock syscall is callable by the child after setup (the child can't
    //    weaken its own ruleset).
    //
    // -----------------------------------------------------------------------

    // 1. NO_NEW_PRIVS.
    // SAFETY: prctl is a variadic FFI call; for PR_SET_NO_NEW_PRIVS the kernel
    // reads exactly one unsigned long argument, so `1` followed by three zero
    // slots matches the ABI and a 0 return means success. This runs BEFORE the
    // seccomp filter is installed (pinned order above), so the syscall is not
    // yet filtered, and it is what makes the subsequent landlock_restrict_self(2)
    // legal (Landlock requires NNP or CAP_SYS_ADMIN). Setting NNP is unprivileged,
    // one-way for this process only, and drops nothing the parent granted: the
    // grandchild has not exec'd anything, so no setuid-based privilege gain was
    // in flight to be altered.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let e = std::io::Error::last_os_error();
        report_setup_error(&exec_err_w, &format!("prctl(PR_SET_NO_NEW_PRIVS): {e}"));
        // SAFETY: without NNP the Landlock restrict_self below would fail (or
        // seccomp would refuse to install), so continuing is unsound for the
        // sandbox guarantee — fail closed with code 84. `_exit` is
        // async-signal-safe and runs no destructors on this forked image.
        unsafe { libc::_exit(84) };
    }

    // 2. Landlock (skipped for DangerFullAccess).
    if let Err(e) = landlock::apply(req.tier, workdir) {
        report_setup_error(&exec_err_w, &format!("landlock: {e}"));
        // SAFETY: a Landlock failure means filesystem confinement is NOT in
        // place; exec'ing now would run the command unconstrained. Fail closed
        // with code 85 — `_exit` is async-signal-safe, skips destructors, and
        // the failure text is already on the exec-error pipe.
        unsafe { libc::_exit(85) };
    }

    // 3. seccomp LAST.
    if let Err(e) = SeccompProfile::new(req.tier).install() {
        report_setup_error(&exec_err_w, &format!("seccomp: {e}"));
        // SAFETY: syscall filtering did not engage; exec'ing would bypass the
        // attack-surface reduction the profile provides. Fail closed with code
        // 86 — `_exit` is async-signal-safe and runs no destructors on this
        // forked image; the error text is already reported.
        unsafe { libc::_exit(86) };
    }

    // (Story 3 note: the runner-level seccomp self-test was
    // prototyped but removed — the kernel allows MULTIPLE seccomp
    // filters to be installed and ANDed (no-TSYNC path), so the
    // "a second install must return EPERM" check is NOT a
    // universal kernel property. The empirical baseline is the
    // existing `tests/sandbox_seccomp.rs::unlisted_syscall_returns_
    // eperm`: if the seccomp install is a no-op, the unlisted
    // syscall succeeds. The Landlock self-test (inside
    // `landlock::apply`) covers the Landlock side, where the
    // kernel DOES enforce one-way restrict (FullyEnforced + NNP).)

    // Final hop. execvpe replaces the process image on success, so it only ever
    // returns on FAILURE (its `Ok` variant is `Infallible`, hence this `let`
    // binds the `Err` irrefutably). We run in the grandchild AFTER fork, where a
    // panic could unwind/abort across a forked address space — so there is NO
    // `unreachable!` here: on the (only) error path we write the errno to the
    // exec-error pipe and `_exit` (fail-closed).
    let Err(e) = execvpe(&argv[0], argv, env);
    let errno = e as i32;
    let _ = write(exec_err_w.as_fd(), &errno.to_le_bytes());
    // SAFETY: execvpe only returns on failure, so this is the terminal point
    // of the grandchild: the errno is already written to the exec-error pipe
    // (126 = conventional exec failure). `_exit` is async-signal-safe and
    // skips destructors/atexit on this forked image — unwinding here could
    // run cleanup meant for the parent context.
    unsafe { libc::_exit(126) };
}

/// Close all open fds in `[3, ..)` except `keep`, using the raw close_range
/// syscall + manual fallback. Runs in the grandchild after dup2.
fn close_inherited_fds(keep: std::os::fd::RawFd) {
    // close_range(3, keep-1) then close_range(keep+1, MAX) so we never close the
    // exec-error pipe. If keep <= 2 (shouldn't happen) just close everything.
    //
    // We invoke SYS_close_range via the raw `syscall(2)` rather than the
    // `libc::close_range` glibc wrapper: the wrapper symbol is absent on old
    // glibc (e.g. the `cross` aarch64 image), which breaks linking. The raw
    // syscall has no such dependency. On a kernel < 5.9 it returns ENOSYS, and
    // we fall back to a manual close loop. Async-signal-safe: no heap, only
    // libc calls (this runs post-fork in the grandchild).
    let max = libc::c_uint::MAX;
    // SAFETY: both calls uphold close_range_or_fallback's contract: we run
    // single-threaded in the post-fork grandchild before exec, so closing raw
    // fds cannot race another thread's fd use; the two ranges are split
    // around `keep` so the exec-error pipe is never closed; and everything
    // inside is async-signal-safe (raw syscall, libc::close, thread-local
    // errno read) with no heap allocation.
    unsafe {
        if keep > 2 {
            close_range_or_fallback(3, (keep - 1) as libc::c_uint, keep);
            close_range_or_fallback((keep + 1) as libc::c_uint, max, keep);
        } else {
            close_range_or_fallback(3, max, keep);
        }
    }
}

/// Close fds in the inclusive range `[first, last]` via the raw close_range
/// syscall, falling back to a manual loop on ENOSYS (kernel < 5.9). `keep` is
/// never closed by the manual fallback. Async-signal-safe.
///
/// # Caller contract (why this fn is `unsafe`)
///
/// Must be called in the single-threaded, post-fork/pre-exec window where the
/// fd table is exclusively ours: closing arbitrary raw fds here cannot race
/// another thread's use of them, and any collateral close is harmless because
/// nothing but stdio and `keep` is meant to survive until exec. The caller
/// must ensure `[first, last]` excludes every fd that must stay open (the
/// runner splits its ranges around `keep`).
// SAFETY: sound to call under the contract above — internally it only issues
// the raw SYS_close_range syscall, reads errno via the thread-local
// __errno_location slot, and on ENOSYS delegates to the allocation-free
// manual_close_range; all async-signal-safe, no heap, no locks.
unsafe fn close_range_or_fallback(
    first: libc::c_uint,
    last: libc::c_uint,
    keep: std::os::fd::RawFd,
) {
    let ret = libc::syscall(
        libc::SYS_close_range,
        first as libc::c_long,
        last as libc::c_long,
        0 as libc::c_long,
    );
    if ret == -1 && errno() == libc::ENOSYS {
        manual_close_range(first, last, keep);
    }
}

/// Manual fallback for close_range: close every fd in `[first, last]`, clamped
/// to the process fd limit, skipping `keep`. Async-signal-safe (no allocation).
///
/// # Caller contract (why this fn is `unsafe`)
///
/// Same window as `close_range_or_fallback`: single-threaded post-fork,
/// pre-exec, where the fd table is exclusively ours and closing a stray fd
/// cannot invalidate state another thread observes. `keep` must be an fd the
/// caller wants preserved; it is skipped explicitly.
// SAFETY: sound under that contract — the scan is bounded by RLIMIT_NOFILE
// (no fd above the soft limit can be open, so the loop is finite even though
// `last` may be c_uint::MAX), only libc::close (async-signal-safe) is called,
// and its result is deliberately ignored: at this teardown stage EBADF on an
// already-closed descriptor is irrelevant. The `fd == upper` break guards the
// c_uint increment against wrapping when upper == c_uint::MAX.
unsafe fn manual_close_range(first: libc::c_uint, last: libc::c_uint, keep: std::os::fd::RawFd) {
    // Upper bound on real fds: RLIMIT_NOFILE cur, fallback 4096. We never need
    // to walk to c_uint::MAX since no fd above the soft limit can be open.
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let limit: libc::c_uint = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0
        && rl.rlim_cur != libc::RLIM_INFINITY
        && rl.rlim_cur > 0
    {
        rl.rlim_cur.min(libc::c_uint::MAX as libc::rlim_t) as libc::c_uint
    } else {
        4096
    };
    let upper = last.min(limit);
    let mut fd = first;
    while fd <= upper {
        if fd as std::os::fd::RawFd != keep {
            let _ = libc::close(fd as libc::c_int);
        }
        // Guard against c_uint overflow when upper == c_uint::MAX.
        if fd == upper {
            break;
        }
        fd += 1;
    }
}

/// Read the current `errno` value. Async-signal-safe.
///
/// Must be called on the same thread immediately after the failing libc call
/// whose errno is wanted: the slot is thread-local, so no other thread can
/// clobber it, but any *interleaved* libc call on this thread would overwrite
/// it.
// SAFETY: __errno_location always returns a valid, non-null pointer to the
// calling thread's own errno slot (glibc and musl both guarantee this), so
// dereferencing it is defined behavior. It is lock-free and
// async-signal-safe, which is why it (rather than std::io::Error::last_os_error,
// which can allocate) is used on the post-fork child path.
unsafe fn errno() -> libc::c_int {
    *libc::__errno_location()
}

/// Sanitized env for the child: keep PATH/HOME/USER/etc, strip secret-shaped
/// names, and force TMPDIR into the workspace so scratch files land in the
/// writable zone. Every variable here is something the child can READ.
fn build_sanitized_env(tmpdir: &Path) -> Vec<CString> {
    // TMPDIR is overridden below, so it's not pulled from the host env here.
    const ALLOW: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "PWD",
        "TZ",
        // Toolchain support dirs the build tools read; their values are paths,
        // not secrets, and the matching Landlock read rules are added for them.
        "RUSTUP_HOME",
        "CARGO_HOME",
        "GOROOT",
        "GOPATH",
        "GOMODCACHE",
        "GOCACHE",
    ];
    let mut env = Vec::new();
    for (k, v) in std::env::vars_os() {
        let (Some(key), Some(val)) = (k.to_str(), v.to_str()) else {
            continue;
        };
        if key.contains('=') || key.contains('\0') {
            continue;
        }
        if key == "TMPDIR" {
            continue; // overridden to the in-workspace tmp below
        }
        let allowed = ALLOW.contains(&key);
        if !allowed && is_secret_env_name(key) {
            continue;
        }
        if let Ok(c) = CString::new(format!("{key}={val}")) {
            env.push(c);
        }
    }
    if let Some(s) = tmpdir.to_str() {
        if let Ok(c) = CString::new(format!("TMPDIR={s}")) {
            env.push(c);
        }
    }
    env
}

fn is_secret_env_name(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    const SUFFIXES: &[&str] = &[
        "_API_KEY",
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSWD",
    ];
    const PREFIXES: &[&str] = &[
        "ANTHROPIC_",
        "OPENAI_",
        "AWS_",
        "GCP_",
        "AZURE_",
        "GITHUB_",
        "GITLAB_",
        "STRIPE_",
    ];
    if PREFIXES.iter().any(|p| up.starts_with(p)) || SUFFIXES.iter().any(|s| up.ends_with(s)) {
        return true;
    }
    matches!(
        up.as_str(),
        "GITHUB_TOKEN" | "GH_TOKEN" | "NPM_TOKEN" | "DATABASE_URL" | "REDIS_URL"
    )
}

fn make_pipe(cloexec: bool) -> Result<(OwnedFd, OwnedFd)> {
    let flags = if cloexec {
        OFlag::O_CLOEXEC
    } else {
        OFlag::empty()
    };
    pipe2(flags).map_err(nix_err)
}

fn read_bounded(fd: &OwnedFd, max_bytes: usize) -> Result<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut overflow = false;
    loop {
        match read(fd.as_fd(), &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < max_bytes {
                    let take = n.min(max_bytes - out.len());
                    out.extend_from_slice(&buf[..take]);
                    if take < n {
                        overflow = true;
                    }
                } else {
                    overflow = true;
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(nix_err(e)),
        }
    }
    let mut s = String::from_utf8_lossy(&out).into_owned();
    if overflow {
        s.push_str("\n... [output truncated]\n");
    }
    Ok(s)
}

/// Drain the exec-error pipe. `None` = exec succeeded. `Some(SetupError)`
/// carries either a 4-byte errno (failed execvp) or a textual setup message.
fn read_setup_error(fd: &OwnedFd) -> Result<Option<SetupError>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        match read(fd.as_fd(), &mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(nix_err(e)),
        }
    }
    if buf.is_empty() {
        Ok(None)
    } else if buf.len() == 4 {
        Ok(Some(SetupError::ExecErrno(i32::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ]))))
    } else {
        Ok(Some(SetupError::Message(
            String::from_utf8_lossy(&buf).into_owned(),
        )))
    }
}

enum SetupError {
    ExecErrno(i32),
    Message(String),
}

fn summarize(
    status: WaitStatus,
    setup_err: Option<SetupError>,
    req: &SandboxRequest,
) -> (i32, Vec<String>) {
    let mut violations = Vec::new();
    let cmd = req.command.first().map(String::as_str).unwrap_or("?");

    match &setup_err {
        Some(SetupError::ExecErrno(errno)) => {
            violations.push(format!("execve_failed(errno={errno}, command={cmd:?})"));
        }
        Some(SetupError::Message(m)) => {
            violations.push(format!("setup_failed({m})"));
        }
        None => {}
    }

    let exit_code = match status {
        WaitStatus::Exited(_, c) => c,
        WaitStatus::Signaled(_, sig, _) => {
            violations.push(format!("killed_by_signal({sig:?})"));
            128 + sig as i32
        }
        other => {
            violations.push(format!("unexpected_wait_status({other:?})"));
            -1
        }
    };
    (exit_code, violations)
}

fn report_setup_error(pipe_w: &OwnedFd, msg: &str) {
    let bytes = msg.as_bytes();
    let _ = write(pipe_w.as_fd(), &bytes[..bytes.len().min(255)]);
}

fn nix_err<E: std::fmt::Display>(e: E) -> SandboxError {
    SandboxError::Runner(format!("{e}"))
}

// ============================================================================
// POST-INSTALL SELF-TEST (Story 3)
// ============================================================================
//
// The runner post-installs two confinement mechanisms (seccomp-bpf +
// Landlock) and is paranoid enough to verify that the mechanisms
// actually engaged. The Landlock side is checked inside
// `landlock::apply` post-restrict (it has the Landlock types; the
// status inspection asserts FullyEnforced + NNP set).
//
// The seccomp side: the kernel allows MULTIPLE seccomp filters to
// be installed and ANDed (no-TSYNC path), so the "a second
// install must return EPERM" check is NOT a universal kernel
// property. The empirical baseline is the existing
// `tests/sandbox_seccomp.rs::unlisted_syscall_returns_eperm`: if
// the seccomp install is a no-op, the unlisted syscall succeeds
// and the test fails. This is the documented assertion.
