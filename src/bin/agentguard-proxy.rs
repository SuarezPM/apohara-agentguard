//! `agentguard-proxy` — transparent MCP transport proxy (V4-B/V4-C).
//!
//! The client's MCP server command becomes:
//!
//! ```text
//! agentguard-proxy [--exec] [--policy <path>] [--pin sha256:<hex>]
//!                  [--mode <enforce|filter-only|audit-only>]
//!                  [--max-line-bytes <n>] -- <server-cmd> <args…>
//! ```
//!
//! (`--exec` and `--` are interchangeable spellings for the same thing: the
//! rest of the command line is the REAL server, spawned as a child.)
//!
//! Enforcement is graduated via `--mode`: `enforce` (default) filters drifted
//! manifests and blocks denied calls; `filter-only` filters but never blocks;
//! `audit-only` only logs would-block/would-filter events. A startup banner
//! (`mode: <name>`) lands on stderr in every session.
//!
//! Exit codes:
//! - `0`  — clean session (client EOF, upstream exited successfully).
//! - `2`  — the session was QUARANTINED by pin verification (manifest drift,
//!   pre-seed mismatch, unusable pin store).
//! - `74` — internal/protocol failure (garbage or oversized line from either
//!   side, I/O error, unexpected upstream death), EX_IOERR per the existing
//!   MCP surface convention. Startup failures (config/policy load) also exit
//!   74 fail-closed rather than starting ungated.

use std::process::ExitCode;

use clap::Parser;

use apohara_agentguard::proxy::framing::DEFAULT_MAX_LINE_BYTES;
use apohara_agentguard::proxy::gate::Gates;
use apohara_agentguard::proxy::relay::{run, RelayConfig, RelayMode, RelayOutcome};

#[derive(Debug, Parser)]
#[command(
    name = "agentguard-proxy",
    about = "Transparent MCP stdio transport proxy: gates tools/call and pins tools/list manifests.",
    after_help = "Exit codes: 0 clean · 2 quarantined (pin drift) · 74 internal/protocol failure.",
    trailing_var_arg = true
)]
struct Args {
    /// Spelling sugar for the server command (`agentguard-proxy --exec srv …`
    /// ≡ `agentguard-proxy -- srv …`). Purely cosmetic; the command itself is
    /// everything after the first non-flag token.
    #[arg(long)]
    exec: bool,

    /// TOML policy file override (default: `policy.file` from the layered
    /// agentguard config). A policy that fails to load aborts startup (exit
    /// 74) — never an ungated proxy.
    #[arg(long, value_name = "PATH")]
    policy: Option<std::path::PathBuf>,

    /// Expected tools-manifest pin, `sha256:<hex>` (64 hex chars). Overrides
    /// the `AGENTGUARD_PIN` env var. A mismatch quarantines the session.
    #[arg(long, value_name = "SHA256:<HEX>")]
    pin: Option<String>,

    /// Enforcement mode: `enforce` filters manifests and blocks denied calls
    /// (default); `filter-only` filters tools/list but never blocks
    /// tools/call; `audit-only` blocks and filters nothing, logging every
    /// would-block / would-filter to stderr.
    #[arg(long, value_enum, default_value_t = RelayMode::Enforce)]
    mode: RelayMode,

    /// Maximum accepted NDJSON line size in bytes (fail-closed above it).
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,

    /// The real MCP server command and its arguments.
    #[arg(required = true)]
    server: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if args.server.is_empty() {
        eprintln!("agentguard-proxy: no server command given after --exec/--");
        return ExitCode::from(74);
    }

    // Pre-seed precedence: CLI flag wins over AGENTGUARD_PIN.
    let expected_pin = args.pin.clone().or_else(|| {
        std::env::var("AGENTGUARD_PIN")
            .ok()
            .filter(|v| !v.trim().is_empty())
    });

    if let Some(pin) = &expected_pin {
        if let Err(problem) = validate_pin(pin) {
            eprintln!("agentguard-proxy: invalid --pin/AGENTGUARD_PIN value {pin:?}: {problem}");
            return ExitCode::from(2);
        }
    }

    // Fail-closed startup: a config/policy that cannot be loaded means the
    // proxy would run ungated; refuse instead (exit 74).
    let gates = match Gates::load(args.policy.as_deref()) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("agentguard-proxy: refusing to start (fail-closed): {e}");
            return ExitCode::from(74);
        }
    };

    let cfg = RelayConfig {
        server: args.server.clone(),
        max_line_bytes: args.max_line_bytes,
        expected_pin,
        pin_base: None, // resolve via XDG_CONFIG_HOME / HOME (fail-closed if neither is set)
        mode: args.mode,
    };

    match run(cfg, &gates) {
        RelayOutcome::Clean => ExitCode::SUCCESS,
        RelayOutcome::Quarantined(reason) => {
            eprintln!("agentguard-proxy: session quarantined: {reason}");
            ExitCode::from(2)
        }
        RelayOutcome::Fatal(reason) => {
            eprintln!("agentguard-proxy: fatal: {reason}");
            ExitCode::from(74)
        }
    }
}

/// Validate `sha256:<hex>` pre-seed syntax up front so a typo'd pin fails at
/// startup instead of silently quarantining every session forever.
///
/// Case-insensitive throughout (remediation N1): the `sha256:` prefix and the
/// hex digest both accept any case; downstream comparison lowercases before
/// matching against this module's lowercase digests.
fn validate_pin(pin: &str) -> Result<(), String> {
    let lowered = pin.to_ascii_lowercase();
    let hex = lowered
        .strip_prefix("sha256:")
        .ok_or("must start with `sha256:` (case-insensitive)")?;
    if hex.len() != 64 {
        return Err(format!("digest must be 64 hex chars, got {}", hex.len()));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("digest contains non-hex characters".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_validation_accepts_wellformed_and_rejects_malformed() {
        let good = format!("sha256:{}", "a".repeat(64));
        assert!(validate_pin(&good).is_ok());
        assert!(validate_pin(&format!("sha256:{}", "A".repeat(64))).is_ok());
        // Case-insensitive prefix + digest (remediation N1).
        assert!(validate_pin(&format!("SHA256:{}", "A".repeat(64))).is_ok());
        assert!(validate_pin(&format!("Sha256:{}", "aB".repeat(32))).is_ok());
        assert!(validate_pin("beef").is_err(), "missing prefix");
        assert!(validate_pin("sha256:short").is_err(), "too short");
        assert!(
            validate_pin(&format!("sha256:{}", "g".repeat(64))).is_err(),
            "non-hex"
        );
        assert!(validate_pin("sha256:").is_err(), "empty digest");
    }
}
