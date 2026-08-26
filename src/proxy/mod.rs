//! MCP transport proxy (V4-B) + tool-manifest pinning (V4-C).
//!
//! The proxy is a **transparent wrapper command**: an MCP client spawns
//! `agentguard-proxy [--exec|--] <server-cmd> <args…>` as its MCP server
//! command; the proxy spawns the REAL server as a piped child and relays
//! newline-delimited JSON-RPC in both directions, enforcing:
//!
//! - **tools/call gating** — policy rules + the anti-bypass deep check run
//!   before anything reaches upstream; denied calls get a synthesized
//!   `isError` result and are never forwarded ([`gate`]).
//! - **tools/list pinning** — the manifest is canonicalized (identity fields
//!   only), SHA-256-pinned per upstream command, and re-verified every
//!   session; drift quarantines the session with an empty manifest and
//!   blocks all further calls ([`pinning`], [`relay::PinGate`]).
//! - **Fail-closed framing** — NDJSON only, 16 MiB line cap, non-JSON lines
//!   from either side terminate the session loudly ([`framing`]).
//!
//! - **Request-id anti-spoofing** — every client request id is replaced by a
//!   relay-minted opaque id (`agp-<hex>`) upstream; responses are accepted
//!   only when their id sits exactly in the pending map (replays, foreign
//!   and unknown ids are dropped), then the original id bytes are restored.
//!   ([`spoof`]).
//!
//! The user-facing entry point is the `agentguard-proxy` binary
//! (`src/bin/agentguard-proxy.rs`); [`relay::run`] is the library-level
//! session driver so integration tests can exercise real sessions.

pub mod framing;
pub mod gate;
pub mod pinning;
pub mod relay;
pub mod spoof;
