//! `agentguard doctor` — installation health diagnostics.
//!
//! One read-only sweep over everything the zero-touch install promises:
//! binary identity, config loadability, policy parseability, the parent
//! directories we write into (MCP pin store, audit log), the per-host hook
//! wiring installed by [`crate::init`], and a best-effort Landlock
//! capability probe. Every check yields PASS / WARN / FAIL plus a one-line
//! detail; exit code semantics live in the CLI wrapper (`main.rs`):
//!
//! - exit **0** when every check is PASS/WARN;
//! - exit **1** when at least one check FAILs.
//!
//! Severity contract (what each status MEANS):
//!
//! - **PASS** — verified healthy.
//! - **WARN** — suboptimal but functional: a host that is simply not
//!   installed, a lazily-created directory that does not exist yet, a
//!   kernel without Landlock (the sandbox fails closed there anyway).
//! - **FAIL** — something genuinely broken that needs user action: an
//!   unloadable config (the gate refuses to run fail-closed), an
//!   unparseable policy, an unwritable data directory, STALE wiring (our
//!   marker points at a different/relocated binary — silent protection
//!   loss until `init --yes` self-heals it), or an unusable host config
//!   that `init` would refuse to touch.
//!
//! Like [`crate::init`], the core is HERMETIC: every entry point receives
//! explicit inputs (`home`, `exe`, `$XDG_CONFIG_HOME`, policy override)
//! resolved once by the CLI wrapper, so tests never mutate process-global
//! state.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::Config;
use crate::init::{self, WiringState};
use crate::policy::engine::PolicySet;

/// Severity of one diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Verified healthy.
    Pass,
    /// Suboptimal but functional (see module docs for the contract).
    Warn,
    /// Broken; requires user action. Any Fail makes `doctor` exit 1.
    Fail,
}

impl Status {
    /// Fixed-width human label used by [`Report::render`].
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

/// One diagnostic result: a stable id (`version`, `config`, `policy`,
/// `pins-dir`, `audit-dir`, `wiring/<host>`, `sandbox`) plus severity and a
/// single-line human detail. The id doubles as the machine-readable key in
/// `--json` output.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub status: Status,
    pub detail: String,
}

/// The full diagnostic report, in fixed check order.
#[derive(Debug, Clone)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether ANY check failed — the sole driver of the exit code.
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }

    /// Human-readable rendering (one line per check + summary line).
    pub fn render(&self) -> String {
        let width = self
            .checks
            .iter()
            .map(|c| c.id.len())
            .max()
            .unwrap_or_default();
        let mut out = String::from("apohara-agentguard doctor\n");
        for c in &self.checks {
            out.push_str(&format!(
                "{:<4} {:<width$} {}\n",
                c.status.label(),
                c.id,
                c.detail,
                width = width
            ));
        }
        let (mut p, mut w, mut f) = (0usize, 0usize, 0usize);
        for c in &self.checks {
            match c.status {
                Status::Pass => p += 1,
                Status::Warn => w += 1,
                Status::Fail => f += 1,
            }
        }
        let verdict = if f > 0 { "NOT HEALTHY" } else { "healthy" };
        out.push_str(&format!(
            "result: {p} pass, {w} warn, {f} fail — {verdict}\n"
        ));
        out
    }
}

/// Inputs resolved once by the CLI wrapper (hermetic core).
pub struct Env<'a> {
    /// The user home directory (`$HOME` with passwd fallback).
    pub home: &'a Path,
    /// Canonicalized absolute path of the RUNNING binary — the exact value
    /// `init` wired into the hosts, so staleness comparison is apples to
    /// apples.
    pub exe: &'a Path,
    /// `$XDG_CONFIG_HOME` verbatim (None/unset ⇒ `<home>/.config`).
    pub xdg_config_home: Option<&'a OsStr>,
    /// `--policy` CLI/env override applied ON TOP of the config's own
    /// `[policy] file` (same precedence as every other subcommand).
    pub policy_override: Option<&'a Path>,
}

/// Run every diagnostic check and assemble the report.
///
/// Check order is FIXED (version → config → policy → audit-dir → pins-dir →
/// wiring ×5 → sandbox) so `--json` consumers get a stable schema.
pub fn run(env: &Env) -> Report {
    let mut checks: Vec<Check> = Vec::with_capacity(11);
    checks.push(version_check(env.exe));

    // Config-dependent checks. A failed config load must NOT hide the other
    // rows (stable JSON schema); they degrade to honest "unknown" warns.
    match Config::load_default_locations() {
        Ok(config) => {
            checks.push(config_check());
            checks.push(policy_check(
                env.policy_override,
                config.policy.file.as_deref(),
            ));
            checks.push(audit_dir_check(
                config.audit.path.as_deref(),
                config.audit.enabled,
            ));
        }
        Err(e) => {
            checks.push(fail_check(
                "config",
                format!(
                    "agentguard.toml failed to load (fail-closed): {}",
                    one_line(&e.to_string())
                ),
            ));
            checks.push(warn_check(
                "policy",
                "unknown — the config failed to load (fix the config first)",
            ));
            checks.push(warn_check(
                "audit-dir",
                "unknown — the config failed to load (fix the config first)",
            ));
        }
    }

    checks.push(pins_dir_check(env.home, env.xdg_config_home));
    checks.extend(wiring_checks(
        &init::diagnose_hosts(env.home, env.xdg_config_home, env.exe),
        env.exe,
    ));
    checks.push(sandbox_check());

    Report { checks }
}

// ---- Check constructors -----------------------------------------------------

fn pass_check(id: &str, detail: impl Into<String>) -> Check {
    Check {
        id: id.to_string(),
        status: Status::Pass,
        detail: detail.into(),
    }
}

fn warn_check(id: &str, detail: impl Into<String>) -> Check {
    Check {
        id: id.to_string(),
        status: Status::Warn,
        detail: detail.into(),
    }
}

fn fail_check(id: &str, detail: impl Into<String>) -> Check {
    Check {
        id: id.to_string(),
        status: Status::Fail,
        detail: detail.into(),
    }
}

/// Collapse a possibly multi-line error rendering into ONE line (error
/// frames embed newlines; check details must stay single-line).
fn one_line(text: &str) -> String {
    let collapsed = text.replace(['\n', '\r'], " ");
    let trimmed = collapsed.trim();
    // Collapse runs of spaces introduced by the newline substitution.
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for ch in trimmed.chars() {
        let space = ch == ' ';
        if !(space && prev_space) {
            out.push(ch);
        }
        prev_space = space;
    }
    out
}

// ---- Individual checks ------------------------------------------------------

/// (a) Binary identity. Running `doctor` IS proof of a runnable binary; the
/// check pins WHICH build answered.
fn version_check(exe: &Path) -> Check {
    pass_check(
        "version",
        format!(
            "apohara-agentguard v{} ({})",
            env!("CARGO_PKG_VERSION"),
            exe.display()
        ),
    )
}

/// Effective config path under the documented resolution rule (project
/// `./agentguard.toml` wins over the user-layer candidate). Mirrors
/// [`Config::load_default_locations`] exactly; the candidates themselves are
/// single-sourced in [`crate::config::default_config_paths`].
fn config_effective_path() -> Option<PathBuf> {
    let paths = crate::config::default_config_paths();
    let project = paths.first().filter(|p| p.exists());
    let user = paths.iter().skip(1).find(|p| p.exists());
    project.or(user).cloned()
}

/// (b) Config loadability. Reaches here ONLY on the Ok arm of the loader
/// (the Err arm emits its own Fail row), so this is always PASS and just
/// reports WHERE the config came from.
fn config_check() -> Check {
    match config_effective_path() {
        Some(p) => pass_check("config", format!("loaded {}", p.display())),
        None => pass_check(
            "config",
            "no config file found — built-in defaults in effect",
        ),
    }
}

/// (c) Policy parseability + size. Only meaningful when a policy file is
/// configured (CLI override > `[policy] file`). With none configured the
/// engine is a no-op combine — healthy by definition.
fn policy_check(override_path: Option<&Path>, configured: Option<&Path>) -> Check {
    match override_path.or(configured) {
        None => pass_check(
            "policy",
            "no policy file configured — engine is a no-op combine",
        ),
        Some(p) => match PolicySet::load(Some(p)) {
            Ok(set) => pass_check(
                "policy",
                format!("loaded {} ({} rule(s))", p.display(), set.rule_count()),
            ),
            Err(e) => fail_check(
                "policy",
                format!(
                    "{} failed to load: {}",
                    p.display(),
                    one_line(&e.to_string())
                ),
            ),
        },
    }
}

/// Config-base directory for the MCP pin store: `$XDG_CONFIG_HOME` when set
/// (and non-empty), else `<home>/.config`. Mirrors
/// [`crate::proxy::pinning::default_config_base`] exactly (kept local so the
/// core stays hermetic and injectable).
fn config_base(home: &Path, xdg_config_home: Option<&OsStr>) -> PathBuf {
    match xdg_config_home {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => home.join(".config"),
    }
}

/// Writability probe WITHOUT side effects on existing content: create a NEW
/// uniquely-named probe file (O_EXCL via `create_new`), then remove it.
fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".agentguard-doctor-probe-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Classify one directory: missing ⇒ WARN (both stores create their dirs
/// lazily on demand); present+writable ⇒ PASS; present+unwritable ⇒ FAIL
/// (writes WILL fail at enforcement time).
fn dir_check(id: &str, label: &str, dir: &Path, missing_hint: &str) -> Check {
    if !dir.is_dir() {
        return warn_check(
            id,
            format!(
                "{label}: {} does not exist yet{missing_hint}",
                dir.display()
            ),
        );
    }
    if writable(dir) {
        pass_check(id, format!("{label}: {} writable", dir.display()))
    } else {
        fail_check(id, format!("{label}: {} NOT writable", dir.display()))
    }
}

/// (d, pins) Parent directory of the MCP pin store (`<base>/agentguard`,
/// beside `mcp-pins.json`). Missing is only a WARN: the proxy creates it on
/// first pin; unwritable is a FAIL (the proxy fails closed without it).
fn pins_dir_check(home: &Path, xdg_config_home: Option<&OsStr>) -> Check {
    let dir = config_base(home, xdg_config_home).join("agentguard");
    dir_check(
        "pins-dir",
        "pin store dir",
        &dir,
        " (created on first proxy use)",
    )
}

/// (d, audit) Parent directory of the configured audit log. No path
/// configured ⇒ auditing is off — healthy. A missing/unwritable parent
/// means every future record write fails (best-effort surface, but the
/// user asked for the log).
fn audit_dir_check(audit_path: Option<&Path>, enabled: bool) -> Check {
    let Some(path) = audit_path else {
        return pass_check("audit-dir", "no audit log configured ([audit] off)");
    };
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut check = dir_check("audit-dir", "audit log dir", &dir, "");
    if matches!(check.status, Status::Pass) && !enabled {
        check.detail.push_str(" ([audit] currently disabled)");
    }
    check
}

/// Map one host's observed wiring state to a doctor row.
fn wiring_check(host_wiring: &init::HostWiring, exe: &Path) -> Check {
    let id = format!("wiring/{}", host_wiring.host);
    let path = host_wiring.path.display();
    match &host_wiring.state {
        WiringState::Wired => pass_check(&id, format!("wired ({path})")),
        WiringState::UserPolicy => pass_check(
            &id,
            format!("{path} — existing kitty-code policy detected (engine embeds via library)"),
        ),
        WiringState::NotInstalled => warn_check(
            &id,
            format!(
                "not installed — run '{}' init --yes if you use this host",
                exe.display()
            ),
        ),
        WiringState::Stale => fail_check(
            &id,
            format!(
                "stale wiring at {path} — points at a different binary/content \
                 (silent protection loss); run '{}' init --yes to refresh",
                exe.display()
            ),
        ),
        WiringState::Corrupt(reason) => {
            fail_check(&id, format!("host config {path} unusable: {reason}"))
        }
    }
}

fn wiring_checks(hosts: &[init::HostWiring], exe: &Path) -> Vec<Check> {
    hosts.iter().map(|h| wiring_check(h, exe)).collect()
}

// ---- Sandbox capability probe (best-effort) ---------------------------------

/// (f) Sandbox capability probe. BEST-EFFORT by design: any failure to
/// PROBE degrades to WARN, never Fail — the sandbox itself already fails
/// closed at run time regardless of what doctor thinks.
#[cfg(target_os = "linux")]
fn sandbox_check() -> Check {
    match landlock_abi_probe() {
        Ok(version) => pass_check(
            "sandbox",
            format!(
                "Landlock available (kernel ABI v{version}) — tiers enforce seccomp + Landlock"
            ),
        ),
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOSYS) => warn_check(
                "sandbox",
                "Landlock unavailable: kernel too old (need Linux >= 5.13); \
                 sandbox commands will refuse to run (fail-closed)",
            ),
            Some(libc::EOPNOTSUPP) => warn_check(
                "sandbox",
                "Landlock disabled at boot — add lsm=landlock to the kernel cmdline; \
                 sandbox commands will refuse to run (fail-closed)",
            ),
            _ => warn_check(
                "sandbox",
                format!("Landlock probe failed (best-effort): {e}"),
            ),
        },
    }
}

/// Non-mutating Landlock capability query: ask the kernel for its highest
/// supported Landlock ABI version via `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)`. Per UAPI this allocates nothing and
/// restricts nothing — unlike a full `Ruleset::create().restrict_self()`
/// round-trip, which would confine the doctor process itself.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
fn landlock_abi_probe() -> std::io::Result<u32> {
    // Landlock landed in 5.13 with UNIFIED syscall numbers across the
    // modern-arch ports listed above (444..=446).
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

    // SAFETY: pure VERSION query per UAPI: ruleset_attr = NULL, size = 0,
    // flags = LANDLOCK_CREATE_RULESET_VERSION. The kernel performs no
    // allocation and does not touch the caller's confinement.
    let v = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if v < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(v as u32)
    }
}

/// Other Linux architectures: the syscall number table differs; degrade to
/// the generic best-effort WARN instead of guessing a number.
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))
))]
fn landlock_abi_probe() -> std::io::Result<u32> {
    Err(std::io::Error::other(
        "Landlock probe unsupported on this architecture",
    ))
}

/// Off-Linux: the sandbox layer is a documented fail-closed refusal, so
/// doctor reports it as WARN context, not a defect.
#[cfg(not(target_os = "linux"))]
fn sandbox_check() -> Check {
    warn_check(
        "sandbox",
        "seccomp/Landlock sandbox unavailable on this platform (commands fail closed)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Status / aggregation / render --------------------------------------

    #[test]
    fn has_failures_is_true_only_for_fail() {
        let mk = |status| Check {
            id: "x".into(),
            status,
            detail: String::new(),
        };
        assert!(!Report {
            checks: vec![mk(Status::Pass), mk(Status::Warn)]
        }
        .has_failures());
        assert!(Report {
            checks: vec![mk(Status::Warn), mk(Status::Fail)]
        }
        .has_failures());
        assert!(!Report { checks: vec![] }.has_failures());
    }

    #[test]
    fn render_lists_every_check_and_a_summary_line() {
        let report = Report {
            checks: vec![
                pass_check("version", "v0.0.0"),
                warn_check("pins-dir", "missing"),
                fail_check("wiring/claude-code", "stale"),
            ],
        };
        let out = report.render();
        assert!(out.starts_with("apohara-agentguard doctor"), "{out}");
        assert!(out.contains("PASS version"), "{out}");
        assert!(out.contains("WARN pins-dir"), "{out}");
        assert!(out.contains("FAIL wiring/claude-code"), "{out}");
        assert!(
            out.contains("result: 1 pass, 1 warn, 1 fail — NOT HEALTHY"),
            "{out}"
        );

        let healthy = Report {
            checks: vec![pass_check("version", "v0.0.0")],
        }
        .render();
        assert!(healthy.contains("— healthy"), "{healthy}");
    }

    // ---- JSON shape ----------------------------------------------------------

    #[test]
    fn json_serializes_lowercase_statuses_and_stable_fields() {
        let check = fail_check("wiring/kilo", "stale");
        let value = serde_json::to_value(&check).expect("serialize Check");
        assert_eq!(value["id"], "wiring/kilo");
        assert_eq!(value["status"], "fail");
        assert_eq!(value["detail"], "stale");

        let warn = serde_json::to_value(warn_check("sandbox", "old kernel")).unwrap();
        assert_eq!(warn["status"], "warn");
        let pass = serde_json::to_value(pass_check("config", "ok")).unwrap();
        assert_eq!(pass["status"], "pass");
    }

    // ---- config_base precedence (mirrors proxy::pinning) ----------------------

    #[test]
    fn config_base_prefers_xdg_then_home_dot_config() {
        let home = Path::new("/home/u");
        assert_eq!(
            config_base(home, Some(OsStr::new("/xdg"))),
            PathBuf::from("/xdg")
        );
        // Empty XDG falls through to ~/.config (same rule as the proxy).
        assert_eq!(
            config_base(home, Some(OsStr::new(""))),
            PathBuf::from("/home/u/.config")
        );
        assert_eq!(config_base(home, None), PathBuf::from("/home/u/.config"));
    }

    // ---- dir classification ----------------------------------------------------

    #[test]
    fn dir_check_passes_on_existing_writable_temp_dir() {
        let dir = std::env::temp_dir().join(format!(
            "agentguard-doctor-dirs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let check = dir_check("d", "probe", &dir, "");
        assert_eq!(check.status, Status::Pass, "{}", check.detail);
        assert!(check.detail.contains("writable"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_check_warns_on_missing_dir() {
        let missing = Path::new("/nonexistent/agentguard-doctor-missing-dir");
        let check = dir_check("d", "probe", missing, " (created later)");
        assert_eq!(check.status, Status::Warn);
        assert!(
            check.detail.contains("does not exist yet"),
            "{}",
            check.detail
        );
        assert!(check.detail.contains("(created later)"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dir_check_fails_on_unwritable_dir() {
        // Root bypasses mode bits — the assertion below would be vacuous.
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "agentguard-doctor-ro-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o555))
            .unwrap();
        let check = dir_check("d", "probe", &dir, "");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(check.status, Status::Fail, "{}", check.detail);
        assert!(check.detail.contains("NOT writable"));
    }

    // ---- wiring mapping ----------------------------------------------------------

    #[test]
    fn wiring_states_map_to_the_documented_severities() {
        let exe = Path::new("/bin/apohara-agentguard");
        let mk = |host: &'static str, state: WiringState| init::HostWiring {
            host,
            path: PathBuf::from("/p"),
            state,
        };
        assert_eq!(
            wiring_check(&mk("opencode", WiringState::Wired), exe).status,
            Status::Pass
        );
        assert_eq!(
            wiring_check(&mk("kitty-code", WiringState::UserPolicy), exe).status,
            Status::Pass
        );
        assert_eq!(
            wiring_check(&mk("kilo", WiringState::NotInstalled), exe).status,
            Status::Warn
        );
        assert_eq!(
            wiring_check(&mk("claude-code", WiringState::Stale), exe).status,
            Status::Fail
        );
        let corrupt = wiring_check(
            &mk("codex-code", WiringState::Corrupt("bad json".into())),
            exe,
        );
        assert_eq!(corrupt.status, Status::Fail);
        assert!(corrupt.detail.contains("bad json"));

        // Ids are namespaced per host so --json consumers can key on them.
        assert_eq!(
            wiring_check(&mk("kitty-code", WiringState::Wired), exe).id,
            "wiring/kitty-code"
        );
    }

    // ---- one_line ------------------------------------------------------------------

    #[test]
    fn one_line_collapses_newlines_and_space_runs() {
        assert_eq!(one_line("a\nb"), "a b");
        assert_eq!(one_line("a\r\n  b"), "a b");
        assert_eq!(one_line("plain"), "plain");
        assert_eq!(one_line("  spaced  out  "), "spaced out");
    }
}
