//! Read/Write/Edit path-guard: cross-platform deny-globs for secrets.
//!
//! [`check_path`] maps a (tool, path, write?) triple to a [`Verdict`] without
//! touching the filesystem. It guards two classes of access:
//! 1. **Reading secrets** — `.env`/`.env.*`, `*.pem`, `*.key`, `id_rsa`/
//!    `id_ed25519`, `*credentials*`, anything under `~/.ssh/`, and `/etc/*`.
//! 2. **Writing sensitive targets** — under `~/.ssh/`, `/etc/*`, and shell
//!    profile files (`~/.bashrc`, `~/.zshrc`, `~/.profile`, …).
//!
//! Cross-platform normalization: matching is **case-insensitive** (NTFS/APFS are
//! case-insensitive, so `.ENV` must match `.env`); `~`, `$HOME`, and
//! `%USERPROFILE%` expand to the home dir; both `/` and `\` are accepted as
//! separators. `/etc/*` rules are DROPPED on Windows (meaningless there).

use std::path::Path;

use crate::verdict::Verdict;

/// Evaluate access to `path` by `tool`. `write` is true for Write/Edit-style
/// (mutating) tools, false for Read-style access.
///
/// Returns [`Verdict::block`] for a forbidden access, otherwise
/// [`Verdict::allow`]. Pure function — never reads the filesystem (tests pass
/// literal paths to stay hermetic).
pub fn check_path(tool: &str, path: &str, write: bool) -> Verdict {
    let norm = normalize(path);

    if write {
        if let Some(reason) = sensitive_write_target(&norm) {
            return Verdict::block(format!(
                "{tool} write to sensitive path `{path}` blocked: {reason}"
            ));
        }
        // A write to a secret file (e.g. overwriting `.env`) is also blocked.
        if let Some(reason) = secret_read_target(&norm) {
            return Verdict::block(format!(
                "{tool} write to secret path `{path}` blocked: {reason}"
            ));
        }
        return Verdict::allow();
    }

    if let Some(reason) = secret_read_target(&norm) {
        return Verdict::block(format!("{tool} of secret path `{path}` blocked: {reason}"));
    }
    Verdict::allow()
}

/// Normalized path: lowercased (case-insensitive match), `~`/`$HOME`/
/// `%USERPROFILE%` expanded, and backslashes folded to `/`.
fn normalize(path: &str) -> String {
    let expanded = expand_home(path);
    let slashed = expanded.replace('\\', "/");
    slashed.to_lowercase()
}

/// Expand a leading `~`, `$HOME`, or `%USERPROFILE%` to the home directory.
///
/// When the home dir is unknown the token is left in place; the deny-globs still
/// match on the `~/.ssh/…` shape directly, so guarding does not depend on a
/// resolvable `$HOME`.
fn expand_home(path: &str) -> String {
    let home = home_dir();

    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return match &home {
            Some(h) => join_home(h, rest),
            None => format!("~/{}", rest.replace('\\', "/")),
        };
    }
    if path == "~" {
        return home.unwrap_or_else(|| "~".to_string());
    }

    for token in ["$HOME", "%USERPROFILE%"] {
        if let Some(rest) = strip_home_token(path, token) {
            return match &home {
                Some(h) => join_home(h, rest),
                None => format!("~/{}", rest.replace('\\', "/")),
            };
        }
    }

    path.to_string()
}

/// Strip a leading home token (`$HOME` / `%USERPROFILE%`) plus one separator.
fn strip_home_token<'a>(path: &'a str, token: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(token)?;
    Some(
        rest.strip_prefix('/')
            .or_else(|| rest.strip_prefix('\\'))
            .unwrap_or(rest),
    )
}

/// Join `home` with a relative `rest`, normalizing separators.
fn join_home(home: &str, rest: &str) -> String {
    let home = home.trim_end_matches(['/', '\\']);
    format!("{}/{}", home, rest.replace('\\', "/"))
}

/// Best-effort home directory from the environment, lowercased downstream.
fn home_dir() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("USERPROFILE").ok().filter(|s| !s.is_empty()))
}

/// If `norm` (already normalized) is a secret to protect on read, return why.
fn secret_read_target(norm: &str) -> Option<&'static str> {
    let file = file_name(norm);

    // Anywhere under ~/.ssh/ (private keys, authorized_keys, known_hosts).
    if contains_dir(norm, "/.ssh/") {
        return Some("path under ~/.ssh");
    }
    // /etc/* — system config & secrets (POSIX only; Windows has no /etc).
    if !cfg!(windows) && norm.starts_with("/etc/") {
        return Some("system path under /etc");
    }

    // Dotenv: `.env`, `.env.local`, `.env.production`, …
    if file == ".env" || file.starts_with(".env.") {
        return Some("dotenv file");
    }
    // Key material by extension.
    if file.ends_with(".pem") || file.ends_with(".key") {
        return Some("key material (.pem/.key)");
    }
    // Common private key file names.
    if file == "id_rsa" || file == "id_ed25519" || file == "id_dsa" || file == "id_ecdsa" {
        return Some("ssh private key");
    }
    // Credential stores.
    if file.contains("credentials") {
        return Some("credentials file");
    }

    None
}

/// If `norm` (already normalized) is a sensitive WRITE target, return why.
fn sensitive_write_target(norm: &str) -> Option<&'static str> {
    if contains_dir(norm, "/.ssh/") {
        return Some("path under ~/.ssh");
    }
    if !cfg!(windows) && norm.starts_with("/etc/") {
        return Some("system path under /etc");
    }

    // Shell profile / rc files (persistence vector if overwritten).
    let file = file_name(norm);
    const PROFILES: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
    ];
    if PROFILES.contains(&file) {
        return Some("shell profile file");
    }

    None
}

/// The final path component of a `/`-normalized path.
fn file_name(norm: &str) -> &str {
    Path::new(norm)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(norm)
}

/// Whether `norm` contains `segment` as a directory boundary, also matching when
/// it begins the path (e.g. `.ssh/...` with no leading slash after `~` drop).
fn contains_dir(norm: &str, segment: &str) -> bool {
    if norm.contains(segment) {
        return true;
    }
    // Handle a path that *starts* with the bare dir (segment without lead slash).
    let bare = segment.trim_start_matches('/');
    norm.starts_with(bare)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Tier;

    #[test]
    fn read_dotenv_blocks() {
        assert_eq!(check_path("Read", ".env", false).tier, Tier::Block);
        assert_eq!(
            check_path("Read", "config/.env.local", false).tier,
            Tier::Block
        );
        assert_eq!(
            check_path("Read", "/home/u/proj/.env.production", false).tier,
            Tier::Block
        );
    }

    #[test]
    fn read_ordinary_source_allows() {
        assert_eq!(check_path("Read", "src/main.rs", false).tier, Tier::Allow);
        assert_eq!(
            check_path("Read", "/home/u/proj/README.md", false).tier,
            Tier::Allow
        );
    }

    #[test]
    fn read_key_material_blocks() {
        assert_eq!(check_path("Read", "server.pem", false).tier, Tier::Block);
        assert_eq!(
            check_path("Read", "/etc/ssl/private.key", false).tier,
            Tier::Block
        );
        assert_eq!(check_path("Read", "id_rsa", false).tier, Tier::Block);
        assert_eq!(
            check_path("Read", "/home/u/.ssh/id_ed25519", false).tier,
            Tier::Block
        );
        assert_eq!(
            check_path("Read", "aws_credentials.txt", false).tier,
            Tier::Block
        );
    }

    #[test]
    fn write_to_ssh_blocks() {
        assert_eq!(
            check_path("Write", "~/.ssh/authorized_keys", true).tier,
            Tier::Block
        );
    }

    #[test]
    fn write_to_profile_blocks() {
        assert_eq!(check_path("Write", "~/.bashrc", true).tier, Tier::Block);
        assert_eq!(check_path("Edit", "/home/u/.zshrc", true).tier, Tier::Block);
    }

    #[test]
    fn write_to_ordinary_file_allows() {
        assert_eq!(check_path("Write", "src/lib.rs", true).tier, Tier::Allow);
    }

    #[test]
    fn case_insensitive_match() {
        // NTFS/APFS case-insensitivity: `.ENV` must be caught like `.env`.
        assert_eq!(check_path("Read", ".ENV", false).tier, Tier::Block);
        assert_eq!(check_path("Read", "ID_RSA", false).tier, Tier::Block);
        assert_eq!(check_path("Read", "Server.PEM", false).tier, Tier::Block);
    }

    #[test]
    fn tilde_expansion_in_ssh_path() {
        // Whether or not $HOME resolves, the ~/.ssh shape must be guarded.
        assert_eq!(check_path("Read", "~/.ssh/id_rsa", false).tier, Tier::Block);
        assert_eq!(
            check_path("Read", "~\\.ssh\\known_hosts", false).tier,
            Tier::Block
        );
    }

    #[test]
    fn windows_userprofile_ssh_blocks() {
        assert_eq!(
            check_path("Read", "%USERPROFILE%\\.ssh\\id_rsa", false).tier,
            Tier::Block
        );
    }

    #[test]
    fn writing_a_secret_is_also_blocked() {
        // Overwriting .env counts as a write to a secret target.
        assert_eq!(check_path("Write", ".env", true).tier, Tier::Block);
    }
}
