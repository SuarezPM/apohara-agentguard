//! Provider-agnostic adapter foundation (PLAN-V05-UNIVERSAL §1.2/§1.3).
//!
//! This module is TYPES + TABLE only in Wave U1: the canonical IR every host
//! adapter normalizes into ([`ir`]) and the per-host/per-OS capability matrix
//! plus the fixed Ask-degradation rule ([`capabilities`]). Actual host
//! adapters (Claude, Codex, OpenCode, Kilo, Kitty embed, MCP gateway) land in
//! Wave U2′ and will live beside these definitions.
//!
//! Design decisions honored here (plan §1.1):
//! - #2: `AGENTGUARD_HOOK_VERSION` pins the wire envelope version; the Claude
//!   PreToolUse snake_case shape is canonical for subprocess transports.
//! - #3: the wire IR carries RAW strings; typed spans live inside the engine,
//!   never in these types.
//! - #5: Ask degradation is fixed (Ask→Deny when the host cannot ask).

pub mod capabilities;
pub mod ir;

pub use capabilities::{capabilities_for, degrade, Capabilities, TargetOs};
pub use ir::{
    CanonicalTool, Decision, HookEvent, HostId, HostOutput, Invocation, AGENTGUARD_HOOK_VERSION,
};
