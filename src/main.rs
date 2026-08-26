//! apohara-agentguard CLI entry point.
//!
//! Thin clap (derive) dispatch over the subcommands: `version`, `hook`,
//! `sandbox`, `scan`, `check`, `mcp`, `audit verify`, `init`, and `doctor`.

use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use apohara_agentguard::audit::{self, AuditRecord};
use apohara_agentguard::config::Config;
use apohara_agentguard::hook;
use apohara_agentguard::hook::Harness;
use apohara_agentguard::init::{self, InitError, Mode, Outcome};
use apohara_agentguard::sandbox::{PermissionTier, SandboxRequest, SandboxRunner};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "apohara-agentguard", version, about)]
struct Cli {
    /// Path to a TOML policy file (CLI > AGENTGUARD_POLICY env > [policy]
    /// file in config). Applies to every subcommand that consults the
    /// engine (`hook`, `check`, `scan`, `mcp`). With no value, the
    /// engine is a no-op combine (the empty-TOML invariant).
    #[arg(long, global = true, env = "AGENTGUARD_POLICY")]
    policy: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the apohara-agentguard version.
    Version,
    /// Run as an agent harness hook (reads stdin JSON, emits a decision).
    /// The `--harness` flag selects the wire contract: `claude` (default,
    /// byte-identical to the pre-0.5 behavior, also correct for Codex),
    /// `windsurf`, `cursor`, or `antigravity` — each with its own stdin
    /// normalization and response shaping over the SAME decision pipeline.
    Hook(HookArgs),
    /// Run a command inside the local seccomp + Landlock sandbox.
    Sandbox(SandboxArgs),
    /// Scan stdin content through the input firewall (prints a verdict).
    Scan,
    /// Check a command through the anti-bypass gate (prints a verdict).
    Check(CheckArgs),
    /// Run the full decision pipeline (gate + policy engine) on a single
    /// command and print the verdict (allow / warn / block / ask). The
    /// operator introspection surface: lets a user see the verdict
    /// before relying on it. Mirrors `check`; differs in that it
    /// consults the policy engine when a policy is loaded (so a
    /// `default-deny` policy can produce an `ask` here that `check`
    /// would not).
    Ask(CheckArgs),
    /// Serve the gate + firewall as MCP tools over stdio (JSON-RPC 2.0).
    Mcp,
    /// Audit-trail operations on the local JSONL log.
    Audit(AuditArgs),
    /// Detect supported agent hosts (Claude Code, OpenAI Codex, OpenCode,
    /// Kilo Code, kitty-code) and wire the apohara-agentguard hook into
    /// their configs / plugin dirs (append-only, idempotent). WITHOUT
    /// `--yes` this is a DRY-RUN: it prints the planned changes and modifies
    /// nothing. `--undo` removes previously-installed wiring instead
    /// (applied immediately — the flag IS the consent). A corrupt host
    /// config aborts with exit code 2 and no modification.
    Init(InitArgs),
    /// Diagnose installation health: binary identity, config loadability,
    /// policy parseability, data-directory writability (MCP pin store +
    /// audit log), per-host wiring status (wired / stale / not installed
    /// across all five hosts), and a best-effort Landlock capability probe.
    /// Exit 0 when everything is PASS/WARN; exit 1 on any FAIL.
    /// `--json` emits the same report as structured JSON.
    Doctor {
        /// Emit a machine-readable JSON report instead of human text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct CheckArgs {
    /// The command to evaluate against the gate.
    command: String,
}

/// Arguments of the `hook` subcommand.
#[derive(Args)]
struct HookArgs {
    /// Which harness wire contract to speak on stdin/stdout. The default
    /// (`claude`) is byte-identical to the pre-0.5 single-harness behavior
    /// (and covers Codex, whose hook format mirrors Claude's).
    #[arg(long, value_enum, default_value_t = HarnessArg::Claude)]
    harness: HarnessArg,
}

/// CLI mirror of [`Harness`] for clap's value-enum parsing (`kebab-case`
/// names: `--harness windsurf`). Mapped 1:1 onto the lib enum; a unit test
/// pins every variant against `Harness::from_name` so the two lists cannot
/// drift.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum HarnessArg {
    Claude,
    Codex,
    Windsurf,
    Cursor,
    Antigravity,
}

impl From<HarnessArg> for Harness {
    fn from(a: HarnessArg) -> Harness {
        match a {
            HarnessArg::Claude => Harness::Claude,
            HarnessArg::Codex => Harness::Codex,
            HarnessArg::Windsurf => Harness::Windsurf,
            HarnessArg::Cursor => Harness::Cursor,
            HarnessArg::Antigravity => Harness::Antigravity,
        }
    }
}

#[derive(Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify the audit log's SHA-256 hash chain (tampering / truncation
    /// detection). Legacy v1 records are tolerated and counted. Exit 0 when
    /// clean, 2 on any defect, 74 on an internal I/O error.
    Verify {
        /// Path to the JSONL audit log (default: the configured [audit] path
        /// from the standard config loader; --file overrides).
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Args)]
struct InitArgs {
    /// Apply the installation. Without this flag, `init` is a DRY-RUN: it
    /// prints the planned changes and modifies nothing (exit 0).
    #[arg(long)]
    yes: bool,
    /// Remove previously-installed apohara-agentguard wiring instead of
    /// installing (applied immediately; preserving all other user content).
    /// Mutually exclusive with `--yes`.
    #[arg(long, conflicts_with = "yes")]
    undo: bool,
}

#[derive(Args)]
struct SandboxArgs {
    /// Permission tier: read_only | workspace_write | danger_full_access.
    #[arg(long, default_value = "workspace_write")]
    tier: String,
    /// Workspace root the command is confined to (default: current directory).
    #[arg(long)]
    workspace_root: Option<PathBuf>,
    /// Required acknowledgement for the danger_full_access (no-sandbox) tier.
    #[arg(long = "i-know-what-im-doing")]
    i_know_what_im_doing: bool,
    /// The command to run, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("apohara-agentguard {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Hook(args) => run_hook(args.harness, cli.policy.as_deref()),
        Command::Sandbox(args) => run_sandbox(args),
        Command::Scan => run_scan(cli.policy.as_deref()),
        Command::Check(args) => run_check(args, cli.policy.as_deref()),
        Command::Ask(args) => run_ask(args, cli.policy.as_deref()),
        Command::Mcp => run_mcp(cli.policy.as_deref()),
        Command::Audit(args) => match args.command {
            AuditCommand::Verify { file } => run_audit_verify(file),
        },
        Command::Init(args) => run_init(args),
        Command::Doctor { json } => run_doctor(json, cli.policy.as_deref()),
    }
}

/// Apply the CLI / env policy-path override to a config, with the
/// documented precedence (CLI > env > config). The env override
/// (`AGENTGUARD_POLICY`) is folded into `cli.policy` by clap's
/// `env = "..."` attribute on the global flag, so by the time this is
/// called, `cli_path` is either the CLI value OR the env value OR None.
fn apply_policy_override(config: &mut Config, cli_path: Option<&std::path::Path>) {
    if let Some(p) = cli_path {
        config.policy.file = Some(p.to_path_buf());
    }
}

/// Load the user config from the default locations, FAIL-CLOSED.
///
/// Missing-vs-malformed split:
/// - No config file in any default location ⇒ silent [`Config::default`]
///   (the empty-config byte-identical invariant).
/// - A file exists but fails to parse/deserialize ⇒ loud one-line stderr
///   diagnostic carrying the underlying error (the offending key/field
///   name), then exit 2. For `hook`, exit 2 IS the deny signal, so a
///   malformed config can never silently disable the gate.
fn load_config_fail_closed(subcommand: &str) -> Config {
    match Config::load_default_locations() {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "apohara-agentguard {subcommand}: invalid agentguard.toml (failing closed): {e:#}"
            );
            std::process::exit(2);
        }
    }
}

/// Read all of stdin, run the hook for the selected harness, print the
/// stdout JSON (if any), mirror the harness's stderr line (if any), and exit
/// with the returned code.
///
/// The `claude`/`codex` paths keep the historical belt-and-suspenders shape:
/// on a blocking exit (code 2) the decision JSON is printed to stdout AND
/// mirrored to stderr (exit 2 + stderr is the effective block signal even if
/// JSON is ignored). Windsurf blocks through that same stderr channel; Cursor
/// and Antigravity keep exit 0 with their verdict carried in the JSON body.
fn run_hook(harness: HarnessArg, cli_policy: Option<&std::path::Path>) -> ExitCode {
    let mut stdin_json = String::new();
    if std::io::stdin().read_to_string(&mut stdin_json).is_err() {
        // Fail OPEN: an unreadable stdin must not block the user's tool.
        return ExitCode::SUCCESS;
    }

    let mut config = load_config_fail_closed("hook");
    apply_policy_override(&mut config, cli_policy);
    let em = hook::harness::run(harness.into(), &stdin_json, &config);

    if let Some(line) = &em.stderr {
        eprintln!("{line}");
    }
    if let Some(json) = &em.stdout {
        println!("{json}");
    }

    ExitCode::from(em.exit.clamp(0, 255) as u8)
}

/// Render an operator-facing verdict reason for the terminal.
///
/// Routes through the lib's display-layer neutralization — the SAME
/// transform the MCP surface applies to `verdict.reason` — so hostile-shaped
/// content (hidden control characters, chat-role impersonation, pseudo-tags,
/// markdown fence runs) embedded in a reason never reaches the terminal raw.
/// Format-neutral: callers keep their `warn: ` / `block: ` / `ask: ` prefixes.
fn display_reason(reason: &str) -> String {
    apohara_agentguard::neutralize_reason(reason)
}

/// Scan stdin content through the input firewall (manual / debugging use).
///
/// Surface-agnostic: scans the raw text with default thresholds and prints the
/// verdict. Exit 2 on a Block so it composes in shell pipelines; 0 otherwise.
fn run_scan(cli_policy: Option<&std::path::Path>) -> ExitCode {
    let mut content = String::new();
    if std::io::stdin().read_to_string(&mut content).is_err() {
        eprintln!("apohara-agentguard scan: could not read stdin");
        return ExitCode::from(2);
    }
    let mut config = load_config_fail_closed("scan");
    apply_policy_override(&mut config, cli_policy);
    let verdict = apohara_agentguard::firewall::scan_content(&content, &Default::default());
    use apohara_agentguard::verdict::Tier;
    // `scan` invokes the firewall's `scan_content` (severity_to_tier
    // output), which never returns Tier::Ask in v0.3 (Ask is a POLICY
    // decision, not a severity-tier mapping — F3' sub-step). The Ask arm
    // is unreachable in this code path; Story 4's `ask` subcommand
    // provides a separate surface for policy-engine-produced Ask.
    match verdict.tier {
        Tier::Allow => {
            println!("allow");
            ExitCode::SUCCESS
        }
        Tier::Warn => {
            println!("warn: {}", display_reason(&verdict.reason));
            ExitCode::SUCCESS
        }
        Tier::Block => {
            eprintln!("block: {}", display_reason(&verdict.reason));
            ExitCode::from(2)
        }
        Tier::Ask => unreachable!("scan does not invoke the policy engine"),
    }
}

/// Check a command through the anti-bypass gate with the loaded user config.
///
/// Prints the verdict and exits 2 on a Block (so it composes in shell
/// pipelines), 0 otherwise (Allow/Warn). The config supplies allow_list,
/// custom_blocks, thresholds, and the disable kill-switch.
fn run_check(args: CheckArgs, cli_policy: Option<&std::path::Path>) -> ExitCode {
    let mut config = load_config_fail_closed("check");
    apply_policy_override(&mut config, cli_policy);
    let verdict = apohara_agentguard::gate::evaluate(&args.command, &config);
    use apohara_agentguard::verdict::Tier;
    // `check` invokes the gate's `evaluate` (severity_to_tier output),
    // which never returns Tier::Ask in v0.3 (Ask is a POLICY decision,
    // not a severity-tier mapping — F3' sub-step). The Ask arm is
    // unreachable in this code path; Story 4's `ask` subcommand
    // provides a separate surface for policy-engine-produced Ask.
    match verdict.tier {
        Tier::Allow => {
            println!("allow");
            ExitCode::SUCCESS
        }
        Tier::Warn => {
            println!("warn: {}", display_reason(&verdict.reason));
            ExitCode::SUCCESS
        }
        Tier::Block => {
            eprintln!("block: {}", display_reason(&verdict.reason));
            ExitCode::from(2)
        }
        Tier::Ask => unreachable!("check does not invoke the policy engine"),
    }
}

/// Run the full decision pipeline (gate + policy engine) on a single
/// command and print the verdict. The operator introspection surface
/// for the v0.3 capability gating; lets a user see the verdict
/// BEFORE relying on the hook's automatic decision. Mirrors `check`
/// but additionally consults the policy engine when a policy is
/// loaded — so a `default-deny` policy can produce an `ask` here
/// that `check` would not.
///
/// With no policy loaded, the policy engine is a no-op combine
/// (`Verdict::allow()`) and the result is byte-identical to `check`.
/// This is the empty-TOML invariant for the `ask` subcommand.
fn run_ask(args: CheckArgs, cli_policy: Option<&std::path::Path>) -> ExitCode {
    let mut config = load_config_fail_closed("ask");
    apply_policy_override(&mut config, cli_policy);

    // Gate verdict (existing surface, v0.2).
    let gate_v = apohara_agentguard::gate::evaluate(&args.command, &config);
    // Policy engine verdict (v0.3). The engine consults the loaded
    // policy (per `Config.policy.file`, overridden by the CLI flag);
    // when no policy is loaded, the engine is a no-op combine and
    // `policy_v == Verdict::allow()` — the empty-TOML invariant.
    let policy_v =
        match apohara_agentguard::policy::engine::PolicySet::load(config.policy.file.as_deref()) {
            Ok(set) => set.evaluate(
                &apohara_agentguard::contract::HookInput {
                    hook_event_name: "PreToolUse".to_string(),
                    session_id: None,
                    tool_name: Some("Bash".to_string()),
                    tool_input: serde_json::json!({ "command": &args.command }),
                    prompt: None,
                    tool_response: serde_json::Value::Null,
                },
                &config,
            ),
            // Fail-closed: a load error is a hard refusal.
            Err(e) => apohara_agentguard::verdict::Verdict::block(format!(
                "policy load error (fail-closed): {e}"
            )),
        };
    // Compose: the MORE SEVERE wins (Block > Ask > Warn > Allow).
    // Inlined rank so we don't depend on a `pub(crate)` symbol from
    // the lib crate (main.rs is a separate crate that links the
    // lib, and `tier_rank` is `pub(crate)` to the lib).
    fn rank(t: apohara_agentguard::verdict::Tier) -> u8 {
        use apohara_agentguard::verdict::Tier;
        match t {
            Tier::Allow => 0,
            Tier::Warn => 1,
            Tier::Ask => 2,
            Tier::Block => 3,
        }
    }
    let verdict = if rank(policy_v.tier) > rank(gate_v.tier) {
        policy_v
    } else {
        gate_v
    };
    use apohara_agentguard::verdict::Tier;
    match verdict.tier {
        Tier::Allow => {
            println!("allow");
            ExitCode::SUCCESS
        }
        Tier::Warn => {
            println!("warn: {}", display_reason(&verdict.reason));
            ExitCode::SUCCESS
        }
        Tier::Block => {
            eprintln!("block: {}", display_reason(&verdict.reason));
            ExitCode::from(2)
        }
        Tier::Ask => {
            // Ask is a UI prompt (not an error); exit 0.
            println!("ask: {}", display_reason(&verdict.reason));
            ExitCode::SUCCESS
        }
    }
}

/// Serve the gate + firewall as MCP tools over stdio (newline-delimited
/// JSON-RPC 2.0). Short-lived request/response: reads stdin, answers on stdout,
/// and exits when stdin closes. The gate uses the loaded user config (same
/// loader as `check`/`scan`). A stdin/stdout I/O error exits non-zero.
fn run_mcp(cli_policy: Option<&std::path::Path>) -> ExitCode {
    let mut config = load_config_fail_closed("mcp");
    apply_policy_override(&mut config, cli_policy);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match apohara_agentguard::mcp::serve(stdin.lock(), stdout.lock(), &config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("apohara-agentguard mcp: {e}");
            ExitCode::from(74)
        }
    }
}

/// Verify the audit log's hash chain (`agentguard audit verify`).
///
/// Prints one line per warning/defect plus a summary; exits 0 when clean,
/// 2 on any defect (or when no log path is available), 74 on an internal
/// I/O error reading the log. The `--file` flag overrides the configured
/// `[audit]` path; with neither, the standard config loader supplies the
/// default (fail-closed, like every other subcommand).
fn run_audit_verify(file: Option<PathBuf>) -> ExitCode {
    let path = match file {
        Some(p) => p,
        None => match load_config_fail_closed("audit verify").audit.path {
            Some(p) => p,
            None => {
                eprintln!(
                    "apohara-agentguard audit verify: no --file given and no [audit] path configured"
                );
                return ExitCode::from(2);
            }
        },
    };

    match audit::verify_chain(&path) {
        Ok(report) => {
            for w in &report.warnings {
                println!("warning: {w}");
            }
            for d in &report.defects {
                println!("defect: {d}");
            }
            if report.is_clean() {
                println!(
                    "ok: {} chained, {} legacy-unverified",
                    report.chained, report.legacy_unverified
                );
                ExitCode::SUCCESS
            } else {
                println!(
                    "FAILED: {} defect(s), {} chained, {} legacy-unverified",
                    report.defects.len(),
                    report.chained,
                    report.legacy_unverified
                );
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!(
                "apohara-agentguard audit verify: i/o error on {}: {e}",
                path.display()
            );
            ExitCode::from(74)
        }
    }
}

/// Detect the agent hosts and wire (or unwire) the apohara-agentguard hook
/// into their user-level configs. One output line per host; exit 0 on
/// success / dry-run / clean no-op, 2 on a corrupt-config refusal, 1 on an
/// environment or I/O failure.
fn run_init(args: InitArgs) -> ExitCode {
    let mode = if args.undo {
        Mode::Uninstall
    } else {
        Mode::Install
    };
    // Consent model: `--yes` applies an install; `--undo` IS the consent for
    // removal (applied immediately). The two flags are mutually exclusive.
    let apply = args.yes || args.undo;

    // `home_dir` was un-deprecated in Rust 1.85 (the MSRV); it reads $HOME /
    // %USERPROFILE% with a passwd fallback and no deprecation warning.
    let Some(home) = std::env::home_dir() else {
        eprintln!("apohara-agentguard init: could not determine the user home directory");
        return ExitCode::from(1);
    };
    // ${CLAUDE_PLUGIN_ROOT} does not work in settings.json — write the
    // absolute path of THIS binary instead.
    let exe = match std::env::current_exe().map(std::fs::canonicalize) {
        Ok(Ok(p)) => p,
        _ => {
            eprintln!("apohara-agentguard init: could not resolve the running binary path");
            return ExitCode::from(1);
        }
    };

    match init::run(&home, &exe, mode, apply) {
        Ok(results) => {
            let mut codex_note = false;
            let mut opencode_note = false;
            for r in &results {
                let line = match &r.outcome {
                    Outcome::Wired { dir_created } => {
                        if r.host == "codex-code" {
                            codex_note = true;
                        }
                        if r.host == "opencode" {
                            opencode_note = true;
                        }
                        let create_note = if *dir_created {
                            let dir = r.path.parent().unwrap_or(&r.path).display();
                            if apply {
                                format!(" (created {dir})")
                            } else {
                                format!(" (would create {dir})")
                            }
                        } else {
                            String::new()
                        };
                        let verb = if apply { "wired" } else { "would wire" };
                        format!("{}: {verb} ({}){create_note}", r.host, r.path.display())
                    }
                    Outcome::AlreadyWired => format!("{}: already wired", r.host),
                    Outcome::Refreshed { .. } => {
                        if r.host == "opencode" {
                            opencode_note = true;
                        }
                        let verb = if apply { "refreshed" } else { "would refresh" };
                        format!("{}: {verb} ({})", r.host, r.path.display())
                    }
                    Outcome::Unwired { .. } => {
                        format!("{}: unwired ({})", r.host, r.path.display())
                    }
                    Outcome::NothingToUnwire => format!("{}: nothing to undo", r.host),
                    Outcome::Scaffolded { dir_created } => {
                        let create_note = if *dir_created {
                            let dir = r.path.parent().unwrap_or(&r.path).display();
                            if apply {
                                format!(" (created {dir})")
                            } else {
                                format!(" (would create {dir})")
                            }
                        } else {
                            String::new()
                        };
                        let verb = if apply {
                            "scaffolded"
                        } else {
                            "would scaffold"
                        };
                        format!(
                            "{}: {verb} ({}){create_note} — embedded via library — policy scaffold written",
                            r.host,
                            r.path.display()
                        )
                    }
                    Outcome::DetectedExisting => format!(
                        "{}: existing policy detected, untouched ({})",
                        r.host,
                        r.path.display()
                    ),
                };
                println!("{line}");
            }
            if codex_note {
                println!(
                    "note: Codex may require reviewing trusted hooks via /hooks on next start"
                );
            }
            if opencode_note {
                println!(
                    "note: opencode.json was not modified — the plugins/ drop-in needs no config edit"
                );
            }
            ExitCode::SUCCESS
        }
        Err(InitError::CorruptConfig { path, reason }) => {
            eprintln!(
                "apohara-agentguard init: refusing to modify corrupt config ({}): {reason}",
                path.display()
            );
            ExitCode::from(2)
        }
        Err(InitError::Io { path, source }) => {
            eprintln!(
                "apohara-agentguard init: i/o error on {}: {source}",
                path.display()
            );
            ExitCode::from(1)
        }
    }
}

/// Run the installation health diagnostics (`agentguard doctor`).
///
/// Resolves the same environment inputs `init` uses (home dir, canonicalized
/// running binary, `$XDG_CONFIG_HOME`) plus the global `--policy` override,
/// hands them to the hermetic [`apohara_agentguard::doctor`] core, prints
/// the report (human text or `--json`), and maps failures to exit 1.
fn run_doctor(json: bool, cli_policy: Option<&std::path::Path>) -> ExitCode {
    // Same home/exe resolution contract as `run_init` — the wiring-staleness
    // comparison must see the EXACT path `init` wrote.
    let Some(home) = std::env::home_dir() else {
        eprintln!("apohara-agentguard doctor: could not determine the user home directory");
        return ExitCode::from(1);
    };
    let exe = match std::env::current_exe().map(std::fs::canonicalize) {
        Ok(Ok(p)) => p,
        _ => {
            eprintln!("apohara-agentguard doctor: could not resolve the running binary path");
            return ExitCode::from(1);
        }
    };
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");

    let env = apohara_agentguard::doctor::Env {
        home: &home,
        exe: &exe,
        xdg_config_home: xdg_config_home.as_deref(),
        policy_override: cli_policy,
    };
    let report = apohara_agentguard::doctor::run(&env);

    if json {
        let payload = serde_json::json!({
            "ok": !report.has_failures(),
            "checks": report.checks,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .expect("doctor report serialization is infallible")
        );
    } else {
        print!("{}", report.render());
    }

    if report.has_failures() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print a loud, multi-line, unmissable warning for the `danger_full_access`
/// tier to STDERR, and record the invocation to the audit log (if enabled).
/// Called only when the tier is DangerFullAccess and the user already passed
/// `--i-know-what-im-doing`.
fn warn_danger_full_access(command: &[String]) {
    eprintln!();
    eprintln!("============================================================");
    eprintln!("  !!!  DANGER_FULL_ACCESS  —  THE SANDBOX IS DISABLED  !!!");
    eprintln!("============================================================");
    eprintln!("  This tier installs NO seccomp filter AND NO Landlock");
    eprintln!("  ruleset. The command runs with your FULL host access:");
    eprintln!("  it can read, write, and delete ANY file you can, and");
    eprintln!("  make unrestricted network connections.");
    eprintln!();
    eprintln!("  There is NO confinement of any kind. Only proceed if you");
    eprintln!("  fully trust this command.");
    eprintln!();
    eprintln!("  This invocation is being logged to the audit log");
    eprintln!("  (if one is configured).");
    eprintln!("============================================================");
    eprintln!();

    // Record the danger invocation (best-effort; never affects the exit code).
    // Command text is opt-in + secret-redacted per the audit config; the
    // default (metadata-only) records no command.
    let config = load_config_fail_closed("sandbox");
    let rec = AuditRecord::new(
        "danger_full_access",
        "warn",
        None,
        Some("danger".to_string()),
        None,
        Some(command.join(" ")),
    );
    audit::record(&config.audit, &rec);
}

/// Run a command under the sandbox. `danger_full_access` requires the explicit
/// `--i-know-what-im-doing` flag. On non-Linux, the runner fails closed and we
/// print an explicit refusal and exit non-zero.
fn run_sandbox(args: SandboxArgs) -> ExitCode {
    let tier: PermissionTier = match args.tier.parse() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("apohara-agentguard sandbox: {e}");
            return ExitCode::from(2);
        }
    };

    if matches!(tier, PermissionTier::DangerFullAccess) && !args.i_know_what_im_doing {
        eprintln!(
            "apohara-agentguard sandbox: refusing danger_full_access without --i-know-what-im-doing \
             (this tier installs NO seccomp filter and NO Landlock ruleset)"
        );
        return ExitCode::from(2);
    }

    // Loud, unmissable warning for the danger tier (the --i-know-what-im-doing
    // flag is present at this point). Printed to STDERR BEFORE running, and the
    // invocation is recorded to the audit log (if enabled).
    if matches!(tier, PermissionTier::DangerFullAccess) {
        warn_danger_full_access(&args.command);
    }

    let workspace_root = match args.workspace_root {
        Some(p) => p,
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("apohara-agentguard sandbox: cannot determine current directory: {e}");
                return ExitCode::from(2);
            }
        },
    };

    let req = SandboxRequest {
        command: args.command,
        workspace_root,
        tier,
        timeout: None,
    };

    match SandboxRunner::new().run(req) {
        Ok(result) => {
            print!("{}", result.stdout);
            eprint!("{}", result.stderr);
            for v in &result.violations {
                eprintln!("apohara-agentguard sandbox: violation: {v}");
            }
            ExitCode::from(result.exit_code.clamp(0, 255) as u8)
        }
        Err(e) => {
            // Fail-closed: a setup error (incl. non-Linux Unavailable) must
            // never be mistaken for a successful unconfined run.
            eprintln!("apohara-agentguard sandbox: REFUSED (fail-closed): {e}");
            ExitCode::from(70)
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests compose the gate + policy engine directly to verify the
    // `ask` subcommand's verdict logic (the helper functions
    // mirror `run_ask` line-by-line).

    #[test]
    fn harness_arg_variants_match_the_lib_name_table() {
        // Anti-drift pin: every clap value-enum variant must map onto a lib
        // `Harness` reachable through the SAME kebab-case name that
        // `--harness` accepts (and vice versa).
        let args = [
            crate::HarnessArg::Claude,
            crate::HarnessArg::Codex,
            crate::HarnessArg::Windsurf,
            crate::HarnessArg::Cursor,
            crate::HarnessArg::Antigravity,
        ];
        assert_eq!(
            args.len(),
            apohara_agentguard::hook::harness::NAMES.len(),
            "the CLI enum and the lib name table must stay in lockstep"
        );
        for a in args {
            let name = clap::ValueEnum::to_possible_value(&a)
                .expect("value enum variant has a name")
                .get_name()
                .to_string();
            assert_eq!(
                apohara_agentguard::hook::Harness::from_name(&name),
                Some(a.into()),
                "--harness {name} must resolve to its lib variant"
            );
        }
    }

    /// Run `run_ask` with `cli_policy = None` (the default-TOML invariant:
    /// the engine is a no-op combine, and the result is byte-identical
    /// to `run_check`).
    fn ask_no_policy(cmd: &str) -> (String, String, i32) {
        // Capture stdout + stderr by redirecting the file descriptors for
        // the test thread. The simplest approach: call run_ask and rely
        // on the fact that it writes to stdout/stderr — we then re-derive
        // the verdict from the tier via a re-run. To avoid the round
        // trip, we test the VERDICT directly via `gate::evaluate` and
        // `policy::engine::PolicySet::default()` composition.
        let cfg = apohara_agentguard::config::Config::default();
        let gate_v = apohara_agentguard::gate::evaluate(cmd, &cfg);
        let policy_v = apohara_agentguard::policy::engine::PolicySet::default().evaluate(
            &apohara_agentguard::contract::HookInput {
                hook_event_name: "PreToolUse".to_string(),
                session_id: None,
                tool_name: Some("Bash".to_string()),
                tool_input: serde_json::json!({ "command": cmd }),
                prompt: None,
                tool_response: serde_json::Value::Null,
            },
            &cfg,
        );
        let rank = |t: apohara_agentguard::verdict::Tier| -> u8 {
            use apohara_agentguard::verdict::Tier;
            match t {
                Tier::Allow => 0,
                Tier::Warn => 1,
                Tier::Ask => 2,
                Tier::Block => 3,
            }
        };
        let chosen = if rank(policy_v.tier) > rank(gate_v.tier) {
            policy_v
        } else {
            gate_v
        };
        let (out, err) = match chosen.tier {
            apohara_agentguard::verdict::Tier::Allow => ("allow".to_string(), String::new()),
            apohara_agentguard::verdict::Tier::Warn => {
                (format!("warn: {}", chosen.reason), String::new())
            }
            apohara_agentguard::verdict::Tier::Block => {
                (String::new(), format!("block: {}", chosen.reason))
            }
            apohara_agentguard::verdict::Tier::Ask => {
                (format!("ask: {}", chosen.reason), String::new())
            }
        };
        let code = if matches!(chosen.tier, apohara_agentguard::verdict::Tier::Block) {
            2
        } else {
            0
        };
        (out, err, code)
    }

    #[test]
    fn run_ask_returns_allow_for_benign() {
        // No policy loaded, benign command => Allow (no-op combine).
        let (stdout, _stderr, code) = ask_no_policy("ls -la");
        assert_eq!(stdout, "allow");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_ask_returns_block_for_dangerous() {
        // No policy loaded, dangerous command => Block (the gate
        // catches it; the policy engine is a no-op combine).
        let (stdout, stderr, code) = ask_no_policy("rm -rf ~");
        assert_eq!(code, 2);
        assert!(stderr.starts_with("block: "), "stderr was {stderr:?}");
        assert_eq!(stdout, "", "stdout should be empty on Block");
    }

    #[test]
    fn run_ask_returns_ask_for_policy_default_deny() {
        // A default-deny policy with no [[tools]] entry for Bash =>
        // engine returns Block (default-deny). Composed with the
        // gate's Allow, the final verdict is Block (safer wins). To
        // test the Ask path, we need a policy that produces an Ask
        // verdict. The simplest: a budget-cap policy where the
        // second invocation is Ask. The first invocation is Allow.
        let dir = std::env::temp_dir().join(format!(
            "agentguard-ask-test-{pid}-{nanos}",
            pid = std::process::id(),
            nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.toml");
        std::fs::write(
            &policy_path,
            r#"
schema_version = 1
[defaults]
default_action = "allow"
[budgets.per_tool.Bash]
max_invocations = 1
"#,
        )
        .unwrap();
        let mut cfg = apohara_agentguard::config::Config::default();
        cfg.policy.file = Some(policy_path.clone());

        // First call: within budget => Allow (engine returns Allow
        // since no rule matched + no default-deny + budget OK).
        // Same PolicySet instance for both calls so the budget
        // counter accumulates (the engine's counters are per-set).
        let set = apohara_agentguard::policy::engine::PolicySet::load(cfg.policy.file.as_deref())
            .unwrap();
        let make_input = || apohara_agentguard::contract::HookInput {
            hook_event_name: "PreToolUse".to_string(),
            session_id: Some("ask-test".to_string()),
            tool_name: Some("Bash".to_string()),
            tool_input: serde_json::json!({ "command": "ls" }),
            prompt: None,
            tool_response: serde_json::Value::Null,
        };
        let gate_v1 = apohara_agentguard::gate::evaluate("ls", &cfg);
        let policy_v1 = set.evaluate(&make_input(), &cfg);
        assert_eq!(
            policy_v1.tier,
            apohara_agentguard::verdict::Tier::Allow,
            "first Bash call within budget"
        );
        // Compose: Allow (engine) + Allow (gate) = Allow.
        let rank = |t: apohara_agentguard::verdict::Tier| -> u8 {
            use apohara_agentguard::verdict::Tier;
            match t {
                Tier::Allow => 0,
                Tier::Warn => 1,
                Tier::Ask => 2,
                Tier::Block => 3,
            }
        };
        let first = if rank(policy_v1.tier) > rank(gate_v1.tier) {
            policy_v1
        } else {
            gate_v1
        };
        assert_eq!(first.tier, apohara_agentguard::verdict::Tier::Allow);

        // Second call: over budget => Ask (engine returns Ask; gate
        // returns Allow; Ask wins the composition).
        let gate_v2 = apohara_agentguard::gate::evaluate("ls", &cfg);
        let policy_v2 = set.evaluate(&make_input(), &cfg);
        assert_eq!(
            policy_v2.tier,
            apohara_agentguard::verdict::Tier::Ask,
            "second Bash call over budget => Ask"
        );
        let second = if rank(policy_v2.tier) > rank(gate_v2.tier) {
            policy_v2
        } else {
            gate_v2
        };
        assert_eq!(second.tier, apohara_agentguard::verdict::Tier::Ask);
        assert!(
            second.reason.contains("budget"),
            "reason: {}",
            second.reason
        );

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
