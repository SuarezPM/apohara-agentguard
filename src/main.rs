//! agentguard CLI entry point.
//!
//! Thin clap (derive) dispatch. Subcommands are stubs filled in by later
//! stories; only `version` is wired for the US-000 scaffold.

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
    /// Run as a Claude Code hook (reads stdin JSON). TODO(US-004).
    Hook,
    /// Run a command inside the local sandbox. TODO(US-005).
    Sandbox,
    /// Scan content through the input firewall. TODO(US-006).
    Scan,
    /// Check a command through the anti-bypass gate. TODO(US-003).
    Check,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("agentguard {}", env!("CARGO_PKG_VERSION"));
        }
        Command::Hook => {
            println!("hook: not yet implemented");
        }
        Command::Sandbox => {
            println!("sandbox: not yet implemented");
        }
        Command::Scan => {
            println!("scan: not yet implemented");
        }
        Command::Check => {
            println!("check: not yet implemented");
        }
    }
}
