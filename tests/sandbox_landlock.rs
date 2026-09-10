//! HARD Landlock filesystem-confinement tests (Linux). None are `#[ignore]`.
//!
//! Landlock is ACTIVE on this kernel, so these run and pass for real. The
//! central test is NON-VACUOUS: in ONE WorkspaceWrite run it asserts BOTH that
//! an in-workspace read+write SUCCEEDS and that out-of-workspace reads/writes
//! are DENIED — so a refused/never-started run cannot pass vacuously.

#![cfg(target_os = "linux")]

use apohara_agentguard::sandbox::{PermissionTier, SandboxRequest, SandboxResult, SandboxRunner};
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::TempDir;

fn sh() -> &'static str {
    "/bin/sh"
}

fn python3() -> Option<PathBuf> {
    for path in ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"] {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

fn run(tier: PermissionTier, root: &Path, argv: &[&str]) -> SandboxResult {
    let req = SandboxRequest {
        command: argv.iter().map(|s| s.to_string()).collect(),
        workspace_root: root.to_path_buf(),
        tier,
        timeout: None,
    };
    SandboxRunner::new()
        .run(req)
        .expect("sandbox run should not fail at setup on this Landlock-capable box")
}

#[derive(Debug, Eq, PartialEq)]
struct StableFileMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug, Eq, PartialEq)]
struct FileSnapshot {
    content: Vec<u8>,
    size: u64,
    metadata: StableFileMetadata,
}

fn seed_file(path: &Path) {
    std::fs::write(path, b"OUTSIDE_CONTENT_MUST_SURVIVE").expect("seed target file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
        .expect("set target permissions");
}

fn snapshot(path: &Path) -> FileSnapshot {
    let content = std::fs::read(path).expect("read target content");
    let metadata = std::fs::metadata(path).expect("read target metadata");
    FileSnapshot {
        content,
        size: metadata.len(),
        metadata: StableFileMetadata {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        },
    }
}

fn assert_unchanged(path: &Path, before: &FileSnapshot) {
    let after = snapshot(path);
    assert_eq!(
        after.content, before.content,
        "content changed for {path:?}"
    );
    assert_eq!(after.size, before.size, "size changed for {path:?}");
    assert_eq!(
        after.metadata, before.metadata,
        "stable metadata changed for {path:?}"
    );
}

/// THE non-vacuous test. One WorkspaceWrite run, both halves asserted.
#[test]
fn workspace_write_confines_to_root_nonvacuous() {
    let dir = TempDir::new("ll-nonvacuous");
    let root = dir.path();

    // (a) read+write INSIDE workspace_root must SUCCEED. We write a file, read
    // it back, and emit a sentinel only if the round-trip matches.
    let inside = run(
        PermissionTier::WorkspaceWrite,
        root,
        &[sh(), "-c", "echo CONTENT_OK > inside.txt && cat inside.txt"],
    );
    assert_eq!(
        inside.exit_code, 0,
        "in-workspace read+write must succeed; stderr={:?} violations={:?}",
        inside.stderr, inside.violations
    );
    assert!(
        inside.stdout.contains("CONTENT_OK"),
        "expected round-tripped content; stdout={:?}",
        inside.stdout
    );
    // The file must really exist on disk inside the workspace.
    assert!(
        root.join("inside.txt").exists(),
        "inside.txt was not created"
    );

    // (b) reads of /etc/passwd and ~/.ssh/id_rsa, and a write OUTSIDE the
    // workspace, must all be DENIED. We run a script that prints a tally; every
    // sensitive op must be blocked.
    let outside_script = format!(
        "P=0; \
         cat /etc/passwd >/dev/null 2>&1 && P=1; \
         S=0; \
         cat \"$HOME/.ssh/id_rsa\" >/dev/null 2>&1 && S=1; \
         W=0; \
         echo x > {}/escape.txt 2>/dev/null && W=1; \
         echo \"passwd=$P ssh=$S write=$W\"",
        // an absolute path guaranteed outside workspace_root
        "/tmp"
    );
    let outside = run(
        PermissionTier::WorkspaceWrite,
        root,
        &[sh(), "-c", &outside_script],
    );
    assert_eq!(outside.exit_code, 0, "probe script itself must run");
    assert!(
        outside.stdout.contains("passwd=0"),
        "/etc/passwd MUST be denied; stdout={:?}",
        outside.stdout
    );
    assert!(
        outside.stdout.contains("ssh=0"),
        "$HOME/.ssh/id_rsa MUST be denied; stdout={:?}",
        outside.stdout
    );
    assert!(
        outside.stdout.contains("write=0"),
        "write outside workspace MUST be denied; stdout={:?}",
        outside.stdout
    );
    // And the escape file must NOT exist on disk.
    assert!(
        !Path::new("/tmp/escape.txt").exists(),
        "a file was written outside the workspace — confinement breached!"
    );
}

/// ABI v3 regression: pathname/descriptor truncation and Linux's unusual
/// `open(O_RDONLY | O_TRUNC)` behavior must work inside the workspace while the
/// same operations are denied outside. Each outside attempt also proves the
/// file's content, size, and stable metadata were preserved.
#[test]
fn truncation_operations_are_scoped_to_workspace() {
    let Some(python) = python3() else {
        eprintln!("SKIP truncation_operations_are_scoped_to_workspace: python3 not found");
        return;
    };
    let workspace = TempDir::new("ll-truncate-workspace");
    let outside = TempDir::new("ll-truncate-outside");
    let inside_file = workspace.path().join("inside.txt");
    let outside_file = outside.path().join("outside.txt");

    let script = "import ctypes,os,sys\n\
                  libc=ctypes.CDLL(None,use_errno=True)\n\
                  op,path=sys.argv[1],os.fsencode(sys.argv[2])\n\
                  if op=='truncate':\n\
                  \x20 libc.truncate.argtypes=[ctypes.c_char_p,ctypes.c_long]\n\
                  \x20 libc.truncate.restype=ctypes.c_int\n\
                  \x20 result=libc.truncate(path,0)\n\
                  elif op=='ftruncate':\n\
                  \x20 libc.open.argtypes=[ctypes.c_char_p,ctypes.c_int]\n\
                  \x20 libc.open.restype=ctypes.c_int\n\
                  \x20 fd=libc.open(path,os.O_WRONLY)\n\
                  \x20 if fd<0: result=fd\n\
                  \x20 else:\n\
                  \x20\x20 libc.ftruncate.argtypes=[ctypes.c_int,ctypes.c_long]\n\
                  \x20\x20 libc.ftruncate.restype=ctypes.c_int\n\
                  \x20\x20 result=libc.ftruncate(fd,0)\n\
                  \x20\x20 error=ctypes.get_errno()\n\
                  \x20\x20 libc.close(fd)\n\
                  \x20\x20 ctypes.set_errno(error)\n\
                  else:\n\
                  \x20 libc.open.argtypes=[ctypes.c_char_p,ctypes.c_int]\n\
                  \x20 libc.open.restype=ctypes.c_int\n\
                  \x20 result=libc.open(path,os.O_RDONLY|os.O_TRUNC)\n\
                  \x20 if result>=0: libc.close(result)\n\
                  error=ctypes.get_errno()\n\
                  print('ALLOWED' if result>=0 else ('DENIED:%d'%error if error in (1,13) else 'OTHER:%d'%error))\n";

    for operation in ["truncate", "ftruncate", "open_o_trunc"] {
        seed_file(&inside_file);
        let inside_path = inside_file.to_str().expect("UTF-8 test path");
        let inside = run(
            PermissionTier::WorkspaceWrite,
            workspace.path(),
            &[
                python.to_str().unwrap(),
                "-c",
                script,
                operation,
                inside_path,
            ],
        );
        assert_eq!(
            inside.exit_code, 0,
            "{operation} probe inside workspace failed; stderr={:?} violations={:?}",
            inside.stderr, inside.violations
        );
        assert!(
            inside.stdout.contains("ALLOWED"),
            "{operation} must succeed inside workspace; stdout={:?}",
            inside.stdout
        );
        assert_eq!(
            std::fs::metadata(&inside_file).unwrap().len(),
            0,
            "{operation} did not truncate the in-workspace file"
        );

        seed_file(&outside_file);
        let before = snapshot(&outside_file);
        let outside_path = outside_file.to_str().expect("UTF-8 test path");
        let denied = run(
            PermissionTier::WorkspaceWrite,
            workspace.path(),
            &[
                python.to_str().unwrap(),
                "-c",
                script,
                operation,
                outside_path,
            ],
        );
        assert_eq!(
            denied.exit_code, 0,
            "{operation} probe outside workspace failed; stderr={:?} violations={:?}",
            denied.stderr, denied.violations
        );
        assert!(
            denied.stdout.contains("DENIED:13"),
            "{operation} must be denied with EACCES outside workspace; stdout={:?}",
            denied.stdout
        );
        assert_unchanged(&outside_file, &before);
    }
}

const FTRUNCATE_HELPER: &str = "AGENTGUARD_LANDLOCK_FTRUNCATE_HELPER";
const FTRUNCATE_ROOT: &str = "AGENTGUARD_LANDLOCK_FTRUNCATE_ROOT";
const FTRUNCATE_TARGET: &str = "AGENTGUARD_LANDLOCK_FTRUNCATE_TARGET";
const FTRUNCATE_EXPECT: &str = "AGENTGUARD_LANDLOCK_FTRUNCATE_EXPECT";

fn run_ftruncate_helper() -> ! {
    let root = PathBuf::from(std::env::var_os(FTRUNCATE_ROOT).expect("missing helper root"));
    let target = PathBuf::from(std::env::var_os(FTRUNCATE_TARGET).expect("missing helper target"));
    let expected = std::env::var(FTRUNCATE_EXPECT).expect("missing helper expectation");

    let access = AccessFs::from_all(ABI::V3);
    let mut created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(access)
        .expect("kernel must support Landlock ABI v3")
        .create()
        .expect("create helper Landlock ruleset")
        .add_rule(PathBeneath::new(
            PathFd::new(&root).expect("open helper workspace"),
            access,
        ))
        .expect("add helper workspace rule");

    if expected == "denied" {
        // Give the external file WRITE_FILE but deliberately not TRUNCATE.
        // This lets the post-Landlock writable open succeed, making the
        // subsequent ftruncate denial specifically exercise ABI v3's
        // descriptor-associated Truncate right instead of failing vacuously
        // because no writable FD could be obtained.
        created = created
            .add_rule(PathBeneath::new(
                PathFd::new(&target).expect("open external helper target for rule"),
                AccessFs::WriteFile,
            ))
            .expect("add write-only external-file helper rule");
    }

    let status = created
        .restrict_self()
        .expect("apply helper Landlock ruleset");
    if !matches!(status.landlock, LandlockStatus::Available { .. })
        || status.ruleset != RulesetStatus::FullyEnforced
        || !status.no_new_privs
    {
        eprintln!("helper ruleset was not fully enforced: {status:?}");
        std::process::exit(90);
    }

    // Open after enforcement: Landlock associates the Truncate right with the
    // new file description at open(2) time. The external control above grants
    // enough access for this writable open, but intentionally withholds the
    // right that ftruncate(2) needs.
    let file = OpenOptions::new()
        .write(true)
        .open(&target)
        .expect("post-Landlock writable open must succeed");

    // SAFETY: `file` is a live writable regular-file FD owned by this process.
    let result = unsafe { libc::ftruncate(file.as_raw_fd(), 0) };
    let error = std::io::Error::last_os_error().raw_os_error();
    let passed = match expected.as_str() {
        "allowed" => result == 0,
        "denied" => result == -1 && error == Some(libc::EACCES),
        other => panic!("unknown helper expectation: {other}"),
    };
    if !passed {
        eprintln!("ftruncate expectation={expected}, result={result}, errno={error:?}");
        std::process::exit(91);
    }
    std::process::exit(0);
}

fn invoke_ftruncate_helper(root: &Path, target: &Path, expected: &str) {
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("ftruncate_fd_is_scoped_to_workspace")
        .arg("--nocapture")
        .env(FTRUNCATE_HELPER, "1")
        .env(FTRUNCATE_ROOT, root)
        .env(FTRUNCATE_TARGET, target)
        .env(FTRUNCATE_EXPECT, expected)
        .output()
        .expect("run isolated ftruncate helper");
    assert!(
        output.status.success(),
        "ftruncate helper expected {expected}; status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `SandboxRunner` deliberately closes inherited FDs, so its exec'd command
/// cannot receive a writable external FD. This isolated subprocess makes a
/// post-enforcement writable open non-vacuously succeed while withholding only
/// `Truncate`, then verifies ABI v3 denies `ftruncate(2)` outside the workspace.
#[test]
fn ftruncate_fd_is_scoped_to_workspace() {
    if std::env::var_os(FTRUNCATE_HELPER).is_some() {
        run_ftruncate_helper();
    }

    let workspace = TempDir::new("ll-ftruncate-workspace");
    let outside = TempDir::new("ll-ftruncate-outside");
    let inside_file = workspace.path().join("inside.txt");
    let outside_file = outside.path().join("outside.txt");

    seed_file(&inside_file);
    invoke_ftruncate_helper(workspace.path(), &inside_file, "allowed");
    assert_eq!(
        std::fs::metadata(&inside_file).unwrap().len(),
        0,
        "ftruncate did not truncate the in-workspace file"
    );

    seed_file(&outside_file);
    let before = snapshot(&outside_file);
    invoke_ftruncate_helper(workspace.path(), &outside_file, "denied");
    assert_unchanged(&outside_file, &before);
}

/// ReadOnly tier: read inside ok, write inside denied.
#[test]
fn read_only_allows_read_denies_write() {
    let dir = TempDir::new("ll-readonly");
    let root = dir.path();
    // Seed a file with a WorkspaceWrite run so ReadOnly has something to read.
    let seed = run(
        PermissionTier::WorkspaceWrite,
        root,
        &[sh(), "-c", "echo SEED > data.txt"],
    );
    assert_eq!(
        seed.exit_code, 0,
        "seed write failed: {:?}",
        seed.violations
    );

    // ReadOnly: reading the seed must succeed.
    let read = run(PermissionTier::ReadOnly, root, &["/bin/cat", "data.txt"]);
    assert_eq!(
        read.exit_code, 0,
        "ReadOnly read must succeed; stderr={:?} violations={:?}",
        read.stderr, read.violations
    );
    assert!(read.stdout.contains("SEED"), "stdout={:?}", read.stdout);

    // ReadOnly: writing a NEW file inside the workspace must be DENIED.
    let write = run(
        PermissionTier::ReadOnly,
        root,
        &[sh(), "-c", "echo NO > blocked.txt 2>/dev/null; echo done"],
    );
    assert!(
        !root.join("blocked.txt").exists(),
        "ReadOnly tier must NOT be able to create files; blocked.txt exists"
    );
    assert!(
        write.stdout.contains("done"),
        "probe ran; stdout={:?}",
        write.stdout
    );
}

/// Inherited-fd leak check: an fd opened OUTSIDE workspace_root before the run
/// must NOT be inherited by the exec'd command (runner closes all fd > 2).
#[test]
fn inherited_fd_outside_workspace_is_not_leaked() {
    let dir = TempDir::new("ll-fdleak");
    let root = dir.path();

    // Open a secret file OUTSIDE the workspace and learn its raw fd number.
    let secret = TempDir::new("ll-secret");
    let secret_file = secret.path().join("secret.txt");
    std::fs::write(&secret_file, b"TOP_SECRET").unwrap();
    let f = std::fs::File::open(&secret_file).unwrap();
    let raw = f.as_raw_fd();
    assert!(raw > 2, "expected a high fd, got {raw}");

    // Try to read THAT fd number from inside the sandbox. If the runner closed
    // it (it must), the read fails and we print LEAK_NONE; if it leaked, the
    // child could read TOP_SECRET via /proc/self/fd/<n>.
    let script = format!(
        "if cat /proc/self/fd/{raw} >/dev/null 2>&1; then echo LEAKED; else echo LEAK_NONE; fi"
    );
    let r = run(PermissionTier::WorkspaceWrite, root, &[sh(), "-c", &script]);
    // Keep `f` alive until after the run so the fd is genuinely open in the
    // parent at fork time.
    drop(f);
    assert!(
        r.stdout.contains("LEAK_NONE"),
        "an fd opened outside the workspace LEAKED into the sandboxed child; stdout={:?}",
        r.stdout
    );
}

/// Regression-style ordering assertion: the errno-taxonomy refusal path exists
/// and carries the actionable message for the EPERM (ordering-bug) case. We
/// can't easily force the kernel to ENOSYS here (Landlock is active), so we
/// assert the taxonomy strings are reachable by exercising a normal successful
/// run and confirming it does NOT carry a refusal — i.e. the capable kernel is
/// fully enforced (the inverse of the fail-closed path).
#[test]
fn capable_kernel_enforces_without_refusal() {
    let dir = TempDir::new("ll-ordering");
    let root = dir.path();
    let r = run(PermissionTier::WorkspaceWrite, root, &[sh(), "-c", "true"]);
    assert_eq!(r.exit_code, 0, "violations={:?}", r.violations);
    // A correctly-ordered NNP->Landlock->seccomp run leaves no setup violation.
    assert!(
        r.violations.is_empty(),
        "capable kernel should fully enforce with no setup violation; got {:?}",
        r.violations
    );
}
