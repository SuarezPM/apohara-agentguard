//! Pure-Rust TOML policy file evaluator (v0.3).
//!
//! The engine is loaded from a TOML policy file (zero new runtime deps: the
//! existing `toml` crate is the parser) and produces [`Verdict`]s that
//! compose with the gate/firewall/pathguard/tool-rules via
//! [`crate::hook::max_verdict`] in the hook dispatch.
//!
//! ## Module shape
//!
//! - [`schema`]: the on-disk serde structs (`schema_version`, `defaults`,
//!   `[[tools]]`, `[budgets.*]`).
//! - [`matcher`]: the glob/pattern helper. The same `*`-substring semantics
//!   the gate's `custom_block_matches` and the hook's `tool_rule_verdict`
//!   use — re-exported `pub(crate)` so the hook and the policy engine
//!   share a SINGLE source of truth (no drift).
//! - [`engine`]: the [`PolicySet`] type. Loads, evaluates, and tracks
//!   in-memory per-session budget counters.
//!
//! ## Fail-closed posture
//!
//! [`PolicySet::load`] returns [`PolicyError`] on any IO/parse/schema
//! problem. The dispatcher in `hook/mod.rs` maps the error to
//! [`Verdict::block`] so a misconfigured policy is a hard refusal, never a
//! silent Allow (matches the `sandbox_failclosed.rs` posture).
//!
//! ## Default behavior (the empty-TOML invariant)
//!
//! With no policy file loaded, [`PolicySet::default()`] is a no-op combine
//! (`Verdict::allow()`), so the hook dispatch stays byte-identical to the
//! pre-Story-2 baseline (asserted by
//! `engine_byte_identical_when_no_policy_loaded`).
//!
//! ## v0.3 scope limits (documented)
//!
//! - Budget heuristic: `tokens = max(1, chars / 4)` (rounded). v0.3 charges
//!   tokens on `Bash` commands + `UserPromptSubmit` prompts ONLY. Other
//!   events (Read/Write/Edit/WebFetch/WebSearch) are free of charge; a
//!   follow-up may extend the per-tool billing if demand emerges.
//! - Budget state: in-memory per-process, keyed by `session_id`. No
//!   cross-process persistence (v0.3 is a single-policy-per-process;
//!   persistence is a v0.4+ follow-up if the demand emerges).
//! - Schema: TOML with `schema_version = 1`. A future migration is a
//!   separate, separately-justified change.

pub mod engine;
pub mod matcher;
pub mod schema;
