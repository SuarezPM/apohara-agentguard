//! Three-tier permission model for the local sandbox.
//!
//! The tier drives both the seccomp-bpf syscall allowlist (`linux::syscalls`)
//! and the Landlock filesystem ruleset (`linux::landlock`). `DangerFullAccess`
//! installs neither and therefore requires an explicit opt-in flag at the CLI.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Permission tier selecting the strength of sandbox confinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionTier {
    /// Read files inside the workspace, stat, exit. No write, no network.
    ReadOnly,
    /// ReadOnly + write/create/remove inside the workspace root. No network.
    /// The default tier for agent work that mutates code in a worktree.
    WorkspaceWrite,
    /// No seccomp filter and no Landlock ruleset. Requires the explicit
    /// `--i-know-what-im-doing` flag at the CLI.
    DangerFullAccess,
}

impl PermissionTier {
    /// Canonical snake_case identifier, matching the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WorkspaceWrite => "workspace_write",
            Self::DangerFullAccess => "danger_full_access",
        }
    }
}

/// Error returned when a tier string can't be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTierError(pub String);

impl fmt::Display for ParseTierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid permission tier {:?} (expected read_only, workspace_write, or danger_full_access)",
            self.0
        )
    }
}

impl std::error::Error for ParseTierError {}

impl FromStr for PermissionTier {
    type Err = ParseTierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read_only" | "readonly" => Ok(Self::ReadOnly),
            "workspace_write" => Ok(Self::WorkspaceWrite),
            "danger_full_access" | "danger" => Ok(Self::DangerFullAccess),
            other => Err(ParseTierError(other.to_string())),
        }
    }
}

impl fmt::Display for PermissionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_uses_snake_case() {
        assert_eq!(PermissionTier::ReadOnly.to_string(), "read_only");
        assert_eq!(
            PermissionTier::WorkspaceWrite.to_string(),
            "workspace_write"
        );
        assert_eq!(
            PermissionTier::DangerFullAccess.to_string(),
            "danger_full_access"
        );
    }

    #[test]
    fn parse_roundtrip() {
        for t in [
            PermissionTier::ReadOnly,
            PermissionTier::WorkspaceWrite,
            PermissionTier::DangerFullAccess,
        ] {
            assert_eq!(PermissionTier::from_str(&t.to_string()).unwrap(), t);
        }
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(
            PermissionTier::from_str("readonly").unwrap(),
            PermissionTier::ReadOnly
        );
        assert_eq!(
            PermissionTier::from_str("danger").unwrap(),
            PermissionTier::DangerFullAccess
        );
    }

    #[test]
    fn parse_invalid() {
        assert!(PermissionTier::from_str("bogus").is_err());
    }

    #[test]
    fn serde_json_uses_snake_case() {
        let json = serde_json::to_string(&PermissionTier::WorkspaceWrite).unwrap();
        assert_eq!(json, "\"workspace_write\"");
        let back: PermissionTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PermissionTier::WorkspaceWrite);
    }
}
