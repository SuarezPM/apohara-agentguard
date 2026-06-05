//! Linux seccomp-bpf filter builder.
//!
//! Compiles a per-tier syscall allowlist (from [`super::syscalls`]) into a real
//! BPF program via the `seccompiler` crate's JSON frontend.
//!
//! Filter shape:
//!   - `mismatch_action = errno(EPERM)` — an unlisted syscall returns `-EPERM`
//!     to the child rather than killing it with SIGSYS, so the caller can
//!     surface a recoverable violation instead of a signal-killed worker.
//!   - `match_action = allow`.
//!   - ReadOnly's `openat`/`open` are constrained to `O_RDONLY` (low 2 bits of
//!     the flags arg must be zero). WorkspaceWrite allows them unconditionally,
//!     narrows `fcntl`/`ioctl` to safe command allowlists, and allows `clone`
//!     only when no `CLONE_NEW*` namespace bit is set.
//!   - DangerFullAccess installs no filter.
//!
//! Per-arch: the filter is compiled for the running arch (x86_64 / aarch64)
//! using seccompiler's `name -> number` mapping for that arch.
//!
//! NOTE on NO_NEW_PRIVS: `seccompiler::apply_filter` sets `PR_SET_NO_NEW_PRIVS`
//! internally, but we do NOT rely on that here — the runner sets it explicitly
//! BEFORE Landlock, because seccomp now runs LAST and Landlock's
//! `restrict_self(2)` needs NNP already in place. See `runner.rs`.

use seccompiler::{apply_filter, compile_from_json, BpfMap, BpfProgram, TargetArch};
use serde_json::{json, Map, Value};

use crate::sandbox::error::{Result, SandboxError};
use crate::sandbox::linux::syscalls;
use crate::sandbox::permission::PermissionTier;

/// A compiled-or-empty seccomp profile for a permission tier.
pub struct SeccompProfile {
    tier: PermissionTier,
}

impl SeccompProfile {
    pub fn new(tier: PermissionTier) -> Self {
        Self { tier }
    }

    /// Compile the BPF program for this tier. `None` for DangerFullAccess.
    pub fn build_filter(&self) -> Result<Option<BpfProgram>> {
        if matches!(self.tier, PermissionTier::DangerFullAccess) {
            return Ok(None);
        }

        let arch: TargetArch = std::env::consts::ARCH
            .try_into()
            .map_err(|e| SandboxError::Seccomp(format!("unsupported target arch: {e}")))?;

        let spec = self.build_json_spec();
        let bytes = serde_json::to_vec(&spec)
            .map_err(|e| SandboxError::Seccomp(format!("json serialize: {e}")))?;

        let map: BpfMap = compile_from_json(bytes.as_slice(), arch)
            .map_err(|e| SandboxError::Seccomp(format!("compile_from_json: {e}")))?;

        let program = map
            .get("main_thread")
            .ok_or_else(|| SandboxError::Seccomp("compiled map missing 'main_thread'".into()))?
            .clone();
        Ok(Some(program))
    }

    /// Install the filter into the calling process. No-op for DangerFullAccess.
    pub fn install(&self) -> Result<()> {
        match self.build_filter()? {
            None => Ok(()),
            Some(filter) => apply_filter(&filter)
                .map_err(|e| SandboxError::Seccomp(format!("apply_filter: {e}"))),
        }
    }

    /// Build the seccompiler JSON spec. Exposed for tests.
    pub fn build_json_spec(&self) -> Value {
        let mut rules: Vec<Value> = Vec::new();

        for syscall in syscalls::pure_allow_for(self.tier) {
            // Skip any syscall that also has a conditional rule below; an
            // unconditional allow would shadow (and seccompiler rejects a
            // duplicate syscall key with conflicting shapes).
            if self.has_conditional(syscall) {
                continue;
            }
            rules.push(json!({ "syscall": syscall }));
        }

        rules.extend(self.conditional_rules());

        let mut main = Map::new();
        main.insert(
            "mismatch_action".into(),
            json!({ "errno": libc::EPERM as u32 }),
        );
        main.insert("match_action".into(), Value::String("allow".into()));
        main.insert("filter".into(), Value::Array(rules));

        let mut root = Map::new();
        root.insert("main_thread".into(), Value::Object(main));
        Value::Object(root)
    }

    fn has_conditional(&self, syscall: &str) -> bool {
        syscalls::conditional_for(self.tier)
            .iter()
            .any(|(name, _)| *name == syscall)
    }

    /// Argument-level rules per tier.
    fn conditional_rules(&self) -> Vec<Value> {
        match self.tier {
            PermissionTier::ReadOnly => {
                // openat: flags arg index 2; open: flags arg index 1. The low 2
                // bits encode the access mode; (flags & O_ACCMODE) == 0 means
                // O_RDONLY. seccompiler's masked_eq carries the mask in the op.
                vec![
                    json!({
                        "syscall": "openat",
                        "args": [{
                            "index": 2, "type": "dword",
                            "op": { "masked_eq": libc::O_ACCMODE as u64 },
                            "val": 0u64,
                        }]
                    }),
                    json!({
                        "syscall": "open",
                        "args": [{
                            "index": 1, "type": "dword",
                            "op": { "masked_eq": libc::O_ACCMODE as u64 },
                            "val": 0u64,
                        }]
                    }),
                ]
            }
            PermissionTier::WorkspaceWrite => {
                let mut rules = vec![json!({ "syscall": "openat" }), json!({ "syscall": "open" })];

                for cmd in [
                    libc::F_GETFL,
                    libc::F_SETFL,
                    libc::F_GETFD,
                    libc::F_SETFD,
                    libc::F_DUPFD,
                    libc::F_DUPFD_CLOEXEC,
                ] {
                    rules.push(json!({
                        "syscall": "fcntl",
                        "args": [{ "index": 1, "type": "dword", "op": "eq", "val": cmd as u64 }]
                    }));
                }

                for req in [
                    libc::TIOCGWINSZ,
                    libc::FIOCLEX,
                    libc::FIONCLEX,
                    libc::FIONBIO,
                    libc::FIONREAD,
                ] {
                    // libc ioctl request constants are c_ulong (== u64) on Linux.
                    rules.push(json!({
                        "syscall": "ioctl",
                        "args": [{ "index": 1, "type": "dword", "op": "eq", "val": req }]
                    }));
                }

                // clone is allowed only with no CLONE_NEW* namespace bit set.
                // CLONE_NEWNS 0x00020000, CLONE_NEWCGROUP 0x02000000,
                // CLONE_NEWUTS 0x04000000, CLONE_NEWIPC 0x08000000,
                // CLONE_NEWUSER 0x10000000, CLONE_NEWPID 0x20000000,
                // CLONE_NEWNET 0x40000000  =>  mask 0x7E020000.
                // (flags & mask) == 0 means "no namespace bits set".
                let clone_ns_mask: u64 = 0x7E02_0000;
                rules.push(json!({
                    "syscall": "clone",
                    "args": [{
                        "index": 0, "type": "dword",
                        "op": { "masked_eq": clone_ns_mask },
                        "val": 0u64,
                    }]
                }));

                rules
            }
            PermissionTier::DangerFullAccess => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn danger_builds_no_filter() {
        let p = SeccompProfile::new(PermissionTier::DangerFullAccess);
        assert!(p.build_filter().unwrap().is_none());
    }

    #[test]
    fn readonly_compiles() {
        let p = SeccompProfile::new(PermissionTier::ReadOnly);
        assert!(p.build_filter().unwrap().is_some());
    }

    #[test]
    fn workspace_write_compiles() {
        let p = SeccompProfile::new(PermissionTier::WorkspaceWrite);
        assert!(p.build_filter().unwrap().is_some());
    }

    #[test]
    fn json_spec_shape() {
        let p = SeccompProfile::new(PermissionTier::ReadOnly);
        let spec = p.build_json_spec();
        let main = spec.get("main_thread").unwrap();
        assert_eq!(
            main.get("match_action").and_then(|v| v.as_str()),
            Some("allow")
        );
        let mismatch = main
            .get("mismatch_action")
            .and_then(|v| v.get("errno"))
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(mismatch, libc::EPERM as u64);
        let names: Vec<&str> = main
            .get("filter")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|r| r.get("syscall").and_then(|s| s.as_str()))
            .collect();
        assert!(names.contains(&"read"));
        assert!(names.contains(&"openat")); // present as conditional
        assert!(names.contains(&"write")); // allowed (stdout); FS write banned by Landlock
                                           // on-disk path mutation stays out of the ReadOnly seccomp filter
        assert!(!names.contains(&"unlinkat"));
        assert!(!names.contains(&"mkdirat"));
    }
}
