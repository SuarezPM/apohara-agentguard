//! apohara-agentguard CLI entry point.
//!
//! Thin clap (derive) dispatch over the subcommands: `version`, `hook`,
//! `sandbox`, `scan`, and `check`.

use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use apohara_agentguard::audit::{self, AuditRecord};
use apohara_agentguard::config::Config;
use apohara_agentguard::hook;
use apohara_agentguard::sandbox::{PermissionTier, SandboxRequest, SandboxRunner};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "apohara-agentguard", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the apohara-agentguard version.
    Version,
    /// Run as a Claude Code hook (reads stdin JSON, emits a decision).
    Hook,
    /// Run a command inside the local seccomp + Landlock sandbox.
    Sandbox(SandboxArgs),
    /// Scan stdin content through the input firewall (prints a verdict).
    Scan,
    /// Check a command through the anti-bypass gate (prints a verdict).
    Check(CheckArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// The command to evaluate against the gate.
    command: String,
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
        Command::Hook => run_hook(),
        Command::Sandbox(args) => run_sandbox(args),
        Command::Scan => run_scan(),
        Command::Check(args) => run_check(args),
    }
}

/// Read all of stdin, run the hook, print the stdout JSON (if any), and exit
/// with the returned code. On a blocking exit (code 2) the decision JSON is
/// printed to stdout AND the reason is mirrored to stderr (belt-and-suspenders:
/// exit 2 + stderr is the effective block signal even if JSON is ignored).
fn run_hook() -> ExitCode {
    let mut stdin_json = String::new();
    if std::io::stdin().read_to_string(&mut stdin_json).is_err() {
        // Fail OPEN: an unreadable stdin must not block the user's tool.
        return ExitCode::SUCCESS;
    }

    let config = Config::load_default_locations().unwrap_or_default();
    let (stdout_json, code) = hook::run(&stdin_json, &config);

    if let Some(json) = stdout_json {
        if code == 2 {
            // Mirror to stderr: on exit 2 the harness feeds stderr to Claude.
            eprintln!("{json}");
        }
        println!("{json}");
    }

    ExitCode::from(code as u8)
}

/// Scan stdin content through the input firewall (manual / debugging use).
///
/// Surface-agnostic: scans the raw text with default thresholds and prints the
/// verdict. Exit 2 on a Block so it composes in shell pipelines; 0 otherwise.
fn run_scan() -> ExitCode {
    let mut content = String::new();
    if std::io::stdin().read_to_string(&mut content).is_err() {
        eprintln!("apohara-agentguard scan: could not read stdin");
        return ExitCode::from(2);
    }
    let verdict = apohara_agentguard::firewall::scan_content(&content, &Default::default());
    use apohara_agentguard::verdict::Tier;
    match verdict.tier {
        Tier::Allow => {
            println!("allow");
            ExitCode::SUCCESS
        }
        Tier::Warn => {
            println!("warn: {}", verdict.reason);
            ExitCode::SUCCESS
        }
        Tier::Block => {
            eprintln!("block: {}", verdict.reason);
            ExitCode::from(2)
        }
    }
}

/// Check a command through the anti-bypass gate with the loaded user config.
///
/// Prints the verdict and exits 2 on a Block (so it composes in shell
/// pipelines), 0 otherwise (Allow/Warn). The config supplies allow_list,
/// custom_blocks, thresholds, and the disable kill-switch.
fn run_check(args: CheckArgs) -> ExitCode {
    let config = Config::load_default_locations().unwrap_or_default();
    let verdict = apohara_agentguard::gate::evaluate(&args.command, &config);
    use apohara_agentguard::verdict::Tier;
    match verdict.tier {
        Tier::Allow => {
            println!("allow");
            ExitCode::SUCCESS
        }
        Tier::Warn => {
            println!("warn: {}", verdict.reason);
            ExitCode::SUCCESS
        }
        Tier::Block => {
            eprintln!("block: {}", verdict.reason);
            ExitCode::from(2)
        }
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
    let config = Config::load_default_locations().unwrap_or_default();
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
