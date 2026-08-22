//! Read/Write/Edit path-guard integration points.
//!
//! Bridges the event dispatch ([`super::dispatch`]) to the pure deny-glob
//! evaluator ([`super::pathguard::check_path`]): extracts the file path from a
//! Read/Write/Edit `tool_input` and maps it to a [`Verdict`]. No path present
//! (or an unexpected shape) fails open with Allow.

use crate::contract::HookInput;
use crate::verdict::Verdict;

use super::pathguard;

/// Path-guard a Read/Write/Edit input; allow when no path is present.
pub(super) fn path_verdict(input: &HookInput, tool: &str, write: bool) -> Verdict {
    match input.file_path() {
        Some(p) => pathguard::check_path(tool, p, write),
        None => Verdict::allow(),
    }
}
