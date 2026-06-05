//! HARD build end-to-end (Linux). NOT `#[ignore]`.
//!
//! Proves the WorkspaceWrite syscall allowlist + Landlock ruleset are
//! sufficient for the real 2026 toolchain: a multi-file `cargo build` MUST exit
//! 0 (this is the gate). `node` and `go` hello-worlds are additionally checked;
//! if either binary is missing, THAT sub-case is skipped with an explicit
//! eprintln (never silently passed), but cargo build must always pass.

#![cfg(target_os = "linux")]

use apohara_agentguard::sandbox::{PermissionTier, SandboxRequest, SandboxResult, SandboxRunner};
use std::path::{Path, PathBuf};

mod common;
use common::TempDir;

fn run(root: &Path, argv: &[&str]) -> SandboxResult {
    let req = SandboxRequest {
        command: argv.iter().map(|s| s.to_string()).collect(),
        workspace_root: root.to_path_buf(),
        tier: PermissionTier::WorkspaceWrite,
        timeout: None,
    };
    SandboxRunner::new()
        .run(req)
        .expect("sandbox run should not fail at setup on this Linux box")
}

fn which(name: &str) -> Option<PathBuf> {
    for dir in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let p = Path::new(dir).join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[test]
fn cargo_build_multifile_succeeds_under_sandbox() {
    let cargo =
        which("cargo").expect("cargo is required for the C2 build gate and must be present");

    let dir = TempDir::new("e2e-cargo");
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname = \"e2eprobe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"e2eprobe\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
    // Multi-file: main.rs depends on helper.rs.
    std::fs::write(
        proj.join("src/main.rs"),
        "mod helper;\nfn main() { println!(\"{}\", helper::v()); }\n",
    )
    .unwrap();
    std::fs::write(proj.join("src/helper.rs"), "pub fn v() -> i32 { 7 }\n").unwrap();

    let r = run(&proj, &[cargo.to_str().unwrap(), "build"]);
    assert_eq!(
        r.exit_code, 0,
        "cargo build MUST exit 0 under WorkspaceWrite (proves the syscall set \
         is sufficient). stderr=\n{}\nviolations={:?}",
        r.stderr, r.violations
    );
    // The compiled binary must exist on disk inside the workspace.
    assert!(
        proj.join("target/debug/e2eprobe").exists(),
        "cargo build reported success but produced no binary"
    );
}

#[test]
fn node_hello_world_succeeds_under_sandbox() {
    let Some(node) = which("node") else {
        eprintln!("SKIP node_hello_world: `node` not found in PATH");
        return;
    };
    let dir = TempDir::new("e2e-node");
    let r = run(
        dir.path(),
        &[node.to_str().unwrap(), "-e", "console.log(1)"],
    );
    assert_eq!(
        r.exit_code, 0,
        "node -e MUST exit 0 under WorkspaceWrite. stderr=\n{}\nviolations={:?}",
        r.stderr, r.violations
    );
    assert!(r.stdout.contains('1'), "node stdout={:?}", r.stdout);
}

#[test]
fn go_hello_world_succeeds_under_sandbox() {
    let Some(go) = which("go") else {
        eprintln!("SKIP go_hello_world: `go` not found in PATH");
        return;
    };
    let dir = TempDir::new("e2e-go");
    let root = dir.path();
    std::fs::write(root.join("go.mod"), "module e2eprobe\ngo 1.21\n").unwrap();
    std::fs::write(
        root.join("main.go"),
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"go-ok\") }\n",
    )
    .unwrap();

    let r = run(root, &[go.to_str().unwrap(), "run", "main.go"]);
    assert_eq!(
        r.exit_code, 0,
        "go run MUST exit 0 under WorkspaceWrite. stderr=\n{}\nviolations={:?}",
        r.stderr, r.violations
    );
    assert!(r.stdout.contains("go-ok"), "go stdout={:?}", r.stdout);
}
