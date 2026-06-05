//! agentguard CLI entry point.
//!
//! Thin clap (derive) dispatch. Subcommands are stubs filled in by later
//! stories; only `version` is wired for the US-000 scaffold.

use std::io::Read as _;
use std::process::ExitCode;

use agentguard::config::Config;
use agentguard::hook;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentguard", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the agentguard version.
    Version,
    /// Run as a Claude Code hook (reads stdin JSON, emits a decision).
    Hook,
    /// Run a command inside the local sandbox. TODO(US-005).
    Sandbox,
    /// Scan content through the input firewall. TODO(US-006).
    Scan,
    /// Check a command through the anti-bypass gate. TODO(US-003).
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("agentguard {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Hook => run_hook(),
        Command::Sandbox => {
            println!("sandbox: not yet implemented");
            ExitCode::SUCCESS
        }
        Command::Scan => {
            println!("scan: not yet implemented");
            ExitCode::SUCCESS
        }
        Command::Check => {
            println!("check: not yet implemented");
            ExitCode::SUCCESS
        }
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
