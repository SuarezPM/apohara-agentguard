//! TOML configuration: allow-list, custom blocks, severity thresholds.
//!
//! Loading is FAIL-CLOSED with a strict missing-vs-malformed split:
//!
//! - **No config file in any default location** ⇒ silent
//!   [`Config::default`] (the empty-config byte-identical invariant).
//! - **A config file exists but fails to parse/deserialize** ⇒
//!   [`Err`](anyhow::Err) carrying the offending key/field name in the error
//!   context. Callers (see `main.rs`) print a loud diagnostic and exit 2 — a
//!   broken config must never be silently discarded by a security gate.
//!
//! A present file may otherwise be partial: every field carries
//! `#[serde(default)]`, so an empty TOML still parses to the defaults.
//! Unknown keys are rejected (`#[serde(deny_unknown_fields)]` on every struct
//! here) so a typo'd key fails loudly instead of silently doing nothing.
//! [`Thresholds`] lives in [`crate::verdict`] (single source of truth) and is
//! re-exported here.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

pub use crate::audit::AuditConfig;
pub use crate::verdict::Thresholds;
use crate::verdict::{severity_to_tier, Tier};

/// A user-added block pattern with its severity and category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomBlock {
    /// Pattern to match against a command (substring/`*`-glob).
    pub pattern: String,
    /// Severity that drives the resulting tier (see [`Thresholds`]).
    pub severity: u8,
    /// Category label for reporting.
    pub category: String,
}

/// Per-tool argument gating policy (consumed later by US-I). Matches a
/// `pattern` against the value of argument `arg` for a given `tool` and, on
/// match, contributes `severity` (a numeric severity in the same scale as
/// [`CustomBlock::severity`], driving the resulting tier via [`Thresholds`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// Tool name the rule applies to (e.g. `"web_fetch"`).
    pub tool: String,
    /// Argument name whose value is matched against `pattern`.
    pub arg: String,
    /// Pattern to match against the argument value (substring/`*`-glob).
    pub pattern: String,
    /// Severity that drives the resulting tier (see [`Thresholds`]). Same
    /// numeric scale as [`CustomBlock::severity`].
    #[serde(default)]
    pub severity: u8,
}

/// `[canary]` configuration. Opt-in canary toggle (consumed by US-Bemit /
/// US-Bscan). All fields `#[serde(default)]` so an empty/absent TOML leaves the
/// canary OFF (the `Default` derive yields `enabled = false`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    /// Whether the canary feature is active. Default `false` (off).
    #[serde(default)]
    pub enabled: bool,
}

/// `[policy]` configuration (v0.3+). Optional path to a TOML policy file
/// consumed by the policy file evaluator. Absent / empty / `file = None` ⇒ no
/// policy is loaded; the engine is a no-op combine (`Verdict::allow()`), so the
/// empty-TOML / `Config::default()` byte-equivalence is preserved.
///
/// Layered loading (CLI > env > config) is the runtime concern of the engine
/// in `src/policy/`; this struct only owns the on-disk `Config` surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Path to a TOML policy file. When `None`, no policy is loaded.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

/// `[community_packs]` configuration (V5-A): opt-in COMMUNITY rule packs
/// loaded at runtime from `*.toml` pack files (see
/// `crate::gate::packs::community` for the file format). Off by default: an
/// empty/absent section enables nothing and the gate is byte-identical to the
/// no-community-packs build.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommunityPacksConfig {
    /// Names of community packs to enable (the `pack.name` declared in their
    /// TOML files). Empty/absent ⇒ OFF. An enabled name that matches no loaded
    /// pack file produces a one-time stderr warning, never an error.
    ///
    /// Layering note (Story D3): PROTECTION-ADDITIVE with UNION semantics —
    /// the project layer may only ADD names; dropping a user-enabled name is
    /// a loud error (see [`merge_tightening`]).
    #[serde(default)]
    pub enabled: Vec<String>,
    /// Directory holding the `*.toml` community pack files. Resolution order:
    /// `AGENTGUARD_COMMUNITY_PACKS_DIR` env > this key > none (nothing loads).
    /// A missing directory is silent (opt-in surface).
    ///
    /// Layering note (Story D3): IMMUTABLE once set by the user layer (same
    /// reasoning as `policy.file`) — swapping the directory swaps WHICH
    /// rulesets are enforced.
    #[serde(default)]
    pub dir: Option<PathBuf>,
}

/// User-facing configuration that overrides built-in defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Commands / path-globs that short-circuit to Allow.
    #[serde(default)]
    pub allow_list: Vec<String>,
    /// User-added block patterns.
    #[serde(default)]
    pub custom_blocks: Vec<CustomBlock>,
    /// Severity-to-tier cutoffs.
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Kill-switch: when true, apohara-agentguard emits Allow and gets out of the way.
    #[serde(default)]
    pub disable: bool,
    /// Whether the in-place normalization pre-pass (ANSI-C / echo-substitution /
    /// IFS / line-continuation evasion-closing) runs. Default `true`; set
    /// `normalize = false` to emergency-disable the pre-pass if a field false
    /// positive surfaces, without disabling the rest of the gate.
    #[serde(default = "default_true")]
    pub normalize: bool,
    /// Local audit-log settings (`[audit]`). Off by default; metadata-only
    /// unless `include_command` is set. See [`AuditConfig`].
    ///
    /// Layering note (Story D3): the project layer MAY disable auditing
    /// last-match-wins. Accepted BY DESIGN: audit is a detection/
    /// observability surface, not pre-execution enforcement, so it sits
    /// outside the monotonic-tightening contract (unlike gate/policy fields,
    /// a project cannot use it to let a dangerous command through).
    #[serde(default)]
    pub audit: AuditConfig,
    /// Names of enabled domain packs (consumed later by US-C). Default empty.
    #[serde(default)]
    pub packs: Vec<String>,
    /// Per-tool argument gating policy (consumed later by US-I). Default empty.
    #[serde(default)]
    pub tool_rules: Vec<ToolRule>,
    /// Component names to disable (consumed later by US-F1). Default empty. This
    /// is distinct from [`Config::disable`], which disables ALL gating.
    #[serde(default)]
    pub disabled: Vec<String>,
    /// Severity preset name (consumed later by US-F1, maps to [`Thresholds`]).
    /// Default `None`.
    #[serde(default)]
    pub level: Option<String>,
    /// Canary toggle (`[canary]`). Off by default. See [`CanaryConfig`].
    ///
    /// Layering note (Story D3): the project layer MAY disable the canary
    /// last-match-wins. Accepted BY DESIGN: the canary is a detection/
    /// observability surface (it detects exfiltration of planted secrets), not
    /// pre-execution enforcement, so it sits outside the monotonic-tightening
    /// contract.
    #[serde(default)]
    pub canary: CanaryConfig,
    /// Policy file evaluator settings (`[policy]`). Off by default (no policy
    /// file loaded). See [`PolicyConfig`].
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Community rule packs (`[community_packs]`, V5-A). Off by default
    /// (empty enabled list, no directory). See [`CommunityPacksConfig`].
    ///
    /// Layering note (Story D3): `community_packs.enabled` is
    /// protection-additive (the project layer may only ADD names);
    /// `community_packs.dir` is immutable once the user layer sets it.
    #[serde(default)]
    pub community_packs: CommunityPacksConfig,
}

/// Default for [`Config::normalize`] — the pre-pass is on by default.
fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allow_list: Vec::new(),
            custom_blocks: Vec::new(),
            thresholds: Thresholds::default(),
            disable: false,
            // The normalization pre-pass is ON by default (matches the serde
            // `default_true`), so `Config::default()` and an empty TOML agree.
            normalize: true,
            // Audit log off by default, metadata-only.
            audit: AuditConfig::default(),
            // Forward-compat fields (consumed by later stories): all empty/off
            // by default so `Config::default()` and an empty TOML agree.
            packs: Vec::new(),
            tool_rules: Vec::new(),
            disabled: Vec::new(),
            level: None,
            // Canary off by default.
            canary: CanaryConfig::default(),
            // Policy file evaluator off by default (no file loaded). The engine
            // is a no-op combine; empty-TOML / `Config::default()` agree.
            policy: PolicyConfig::default(),
            // Community packs off by default (nothing enabled, no directory).
            community_packs: CommunityPacksConfig::default(),
        }
    }
}

/// Upper bound of the documented severity scale (`0..=9`, see
/// `examples/agentguard.toml`). A configured severity above this bound can
/// never be distinguished from the maximum and is treated as a typo.
const MAX_SEVERITY: u8 = 9;

impl Config {
    /// Load config from `path` if given and existing; otherwise return defaults.
    pub fn load(path: Option<&Path>) -> Result<Config> {
        match path {
            Some(p) if p.exists() => {
                let text = fs::read_to_string(p)
                    .with_context(|| format!("reading config file {}", p.display()))?;
                let cfg: Config = toml::from_str(&text)
                    .with_context(|| format!("parsing config file {}", p.display()))?;
                // Fail-closed on invalid cross-field combinations: a config that
                // PARSES but makes no sense (e.g. warn_at > block_at) must fail
                // loudly here, not silently misbehave at evaluation time. The
                // caller (see `main.rs`) surfaces the error with the same loud
                // diagnostic + exit 2 treatment as a parse error.
                cfg.validate()
                    .with_context(|| format!("invalid configuration in {}", p.display()))?;
                Ok(cfg)
            }
            _ => Ok(Config::default()),
        }
    }

    /// Load from the default locations, LAYERED (Story D3).
    ///
    /// Layers:
    /// 1. **User layer** — `$XDG_CONFIG_HOME/agentguard/config.toml`
    ///    (falling back to `~/.config/agentguard/config.toml`). The BASE.
    /// 2. **Project layer** — `./agentguard.toml`. An OVERLAY validated
    ///    tightening-only on top of the user layer.
    ///
    /// Monotonic-tightening contract (applied ONLY when BOTH layers exist):
    /// the project file may TIGHTEN protection fields but never loosen them
    /// (see [`merge_tightening`] for the per-field rules). Any violation is
    /// a loud error naming the offending field ⇒ callers fail closed with
    /// exit 2.
    ///
    /// Single-layer behavior is byte-identical to the pre-D3 loader:
    /// - Only the project file exists ⇒ load it alone (old first-match-wins).
    /// - Only the user file exists ⇒ load it alone.
    /// - Neither exists ⇒ silent [`Config::default`] (the empty-config
    ///   byte-identical invariant).
    ///
    /// Missing-vs-malformed split (fail-closed contract):
    /// - NO config file found ⇒ `Ok(Config::default())` silently.
    /// - A file EXISTS but fails to read/parse/deserialize/validate ⇒ `Err`
    ///   with the file path in the context and the offending key/field name
    ///   in the underlying error. Callers must surface it (see `main.rs`:
    ///   loud stderr diagnostic + exit 2), never discard a malformed config.
    pub fn load_default_locations() -> Result<Config> {
        let paths = default_config_paths();
        // paths[0] is the project-local candidate; the rest are user-level
        // candidates (XDG first, then $HOME/.config).
        let project = paths.first().filter(|p| p.exists());
        let user = paths.iter().skip(1).find(|p| p.exists());
        match (project, user) {
            (None, None) => Ok(Config::default()),
            (Some(p), None) => Self::load(Some(p)),
            (None, Some(u)) => Self::load(Some(u)),
            (Some(p), Some(u)) => Self::load_layered(u, p),
        }
    }

    /// Layered load: the user config is the BASE, the project config an
    /// OVERLAY validated tightening-only on top of it (Story D3).
    fn load_layered(user_path: &Path, project_path: &Path) -> Result<Config> {
        let base = Self::load(Some(user_path))?;
        let text = fs::read_to_string(project_path)
            .with_context(|| format!("reading config file {}", project_path.display()))?;
        let overlay: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", project_path.display()))?;
        let presence = TighteningPresence::from_toml(&text)
            .with_context(|| format!("parsing config file {}", project_path.display()))?;
        let merged = merge_tightening(base, overlay, &presence).with_context(|| {
            format!(
                "project config {} may only TIGHTEN the user config {}",
                project_path.display(),
                user_path.display()
            )
        })?;
        // The merged result must satisfy the same cross-field invariants as
        // any single-layer load (e.g. warn_at <= block_at after merging).
        merged
            .validate()
            .with_context(|| format!("invalid configuration in {}", project_path.display()))?;
        Ok(merged)
    }

    /// Whether `command` matches the allow-list (substring or `*`-glob).
    pub(crate) fn is_allowed(&self, command: &str) -> bool {
        self.allow_list
            .iter()
            .any(|pattern| glob_match(pattern, command))
    }

    /// Whether a named component is disabled (US-F1 granular kill-switch).
    ///
    /// The effective disabled-set is the UNION of three inputs:
    /// 1. [`Config::disable`] (the legacy all-off flag) — when `true`, EVERY
    ///    component is disabled.
    /// 2. [`Config::disabled`] — explicit component names from the TOML.
    /// 3. The `AGENTGUARD_DISABLE` hook-process env var, parsed as a comma list
    ///    of component names (or `1`/`true` for ALL) — read by the caller in
    ///    [`crate::hook`] and passed in via `env_disabled`.
    ///
    /// `component` and the configured/env names are compared case-insensitively
    /// after trimming. Unknown names simply never match (not an error).
    pub(crate) fn is_component_disabled(&self, component: &str, env_disabled: &EnvDisable) -> bool {
        if self.disable || env_disabled.all {
            return true;
        }
        let want = component.trim().to_ascii_lowercase();
        // `env_disabled.names` are already lowercased + trimmed by
        // `EnvDisable::parse`; `config.disabled` is raw TOML so normalize it here.
        self.disabled
            .iter()
            .any(|c| c.trim().to_ascii_lowercase() == want)
            || env_disabled.names.contains(&want)
    }

    /// The effective severity [`Thresholds`], applying the [`Config::level`]
    /// preset when set, otherwise the configured/default [`Config::thresholds`].
    ///
    /// `level` is a named preset built ON TOP of the single-source [`Thresholds`]
    /// type (it does not replace it). When `level` is `None` the configured
    /// `thresholds` (default `block_at = 8`, `warn_at = 5`) are returned
    /// unchanged, keeping the default path byte-identical.
    pub fn effective_thresholds(&self) -> Thresholds {
        match self.level.as_deref().map(level_preset) {
            Some(Some(preset)) => preset,
            // No preset, or an unrecognized name: fall back to configured thresholds.
            _ => self.thresholds,
        }
    }

    /// Enforce the cross-field invariants of a parsed [`Config`].
    ///
    /// Called from BOTH load paths ([`Config::load`] and, through it,
    /// [`Config::load_default_locations`]) right AFTER deserialization, so an
    /// invalid combination fails closed with the same loud diagnostic + exit 2
    /// treatment as a parse error (the D1 channel in `main.rs`). A `Config`
    /// built directly in memory (e.g. `Config::default()`, or a struct literal
    /// in tests) is NOT routed through this check — only on-disk configs are.
    ///
    /// Invariants:
    /// 1. **Thresholds ordering** — `thresholds.warn_at <= thresholds.block_at`.
    ///    An inverted pair silently reclassifies Block-tier severities as Warn.
    /// 2. **Severity presets within bounds** —
    ///    (a) `level`, when set, must name a known preset (`strict`, `high`,
    ///    or `critical`; case-insensitive). An unrecognized name would
    ///    otherwise be silently ignored — a typo'd preset must fail loudly,
    ///    mirroring the `deny_unknown_fields` posture for keys.
    ///    (b) every configured severity (`custom_blocks[].severity`,
    ///    `tool_rules[].severity`) stays within the documented `0..=9` scale
    ///    (see `examples/agentguard.toml`).
    /// 3. **Budget caps positive where applicable** — not applicable here:
    ///    budget caps are not part of `Config` (they live in the policy-file
    ///    schema and are validated by `PolicySet::load`).
    /// 4. **custom_blocks patterns non-empty** — an empty pattern matches
    ///    EVERY command (substring semantics), silently widening the block
    ///    list into a blanket deny.
    pub fn validate(&self) -> Result<()> {
        if self.thresholds.warn_at > self.thresholds.block_at {
            anyhow::bail!(
                "thresholds.warn_at ({}) must be <= thresholds.block_at ({})",
                self.thresholds.warn_at,
                self.thresholds.block_at
            );
        }
        if let Some(level) = &self.level {
            if level_preset(level).is_none() {
                anyhow::bail!(
                    "unknown severity preset `level = \"{level}\"` \
                     (expected \"strict\", \"high\", or \"critical\")"
                );
            }
        }
        for block in &self.custom_blocks {
            if block.pattern.is_empty() {
                anyhow::bail!(
                    "custom_blocks.pattern must not be empty (it would match everything)"
                );
            }
            if block.severity > MAX_SEVERITY {
                anyhow::bail!(
                    "custom_blocks.severity ({}) is out of range 0..={MAX_SEVERITY}",
                    block.severity
                );
            }
        }
        for rule in &self.tool_rules {
            if rule.severity > MAX_SEVERITY {
                anyhow::bail!(
                    "tool_rules.severity ({}) is out of range 0..={MAX_SEVERITY}",
                    rule.severity
                );
            }
        }
        Ok(())
    }
}

/// The `AGENTGUARD_DISABLE` env var parsed into a disabled-component set.
///
/// Parsed from the HOOK PROCESS env only (see the anti-self-disarm note in
/// [`crate::hook`]). `1`/`true` (case-insensitive) means ALL components; any
/// other value is treated as a comma-separated list of component names. Unknown
/// tokens are kept verbatim (lowercased) and simply never match a real
/// component, so they are effectively ignored without being an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EnvDisable {
    /// All components disabled (`AGENTGUARD_DISABLE=1` / `true`).
    pub(crate) all: bool,
    /// Explicit component names (lowercased, trimmed).
    pub(crate) names: Vec<String>,
}

impl EnvDisable {
    /// Parse a raw `AGENTGUARD_DISABLE` value. An absent var maps to `None` at
    /// the call site; here `raw` is the present value.
    pub(crate) fn parse(raw: &str) -> Self {
        let trimmed = raw.trim().to_ascii_lowercase();
        if trimmed == "1" || trimmed == "true" {
            return Self {
                all: true,
                names: Vec::new(),
            };
        }
        let names = trimmed
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        Self { all: false, names }
    }
}

/// Map a severity-preset `level` name to a [`Thresholds`] preset.
///
/// Presets are ordered from least to most aggressive blocking (lower
/// `block_at` blocks MORE):
/// - `"strict"`  -> `block_at = 7`, `warn_at = 4` (mildest of the three)
/// - `"high"`    -> `block_at = 6`, `warn_at = 3`
/// - `"critical"`-> `block_at = 5`, `warn_at = 2` (most aggressive: blocks the most)
///
/// An unrecognized name returns `None` so the caller falls back to the
/// configured/default thresholds. Comparison is case-insensitive.
fn level_preset(level: &str) -> Option<Thresholds> {
    match level.trim().to_ascii_lowercase().as_str() {
        "strict" => Some(Thresholds {
            block_at: 7,
            warn_at: 4,
        }),
        "high" => Some(Thresholds {
            block_at: 6,
            warn_at: 3,
        }),
        "critical" => Some(Thresholds {
            block_at: 5,
            warn_at: 2,
        }),
        _ => None,
    }
}

/// Candidate config paths in lookup order (see [`Config::load_default_locations`]).
///
/// Public so the `doctor` subcommand can report the EFFECTIVE config path
/// (the first existing candidate per the documented resolution rule) without
/// duplicating the candidate list.
pub fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("agentguard.toml")];

    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));

    if let Some(home) = config_home {
        paths.push(home.join("agentguard").join("config.toml"));
    }

    paths
}

// ---- Story D3: monotonic tightening (layered user + project configs) -------

/// Which top-level keys an overlay config file EXPLICITLY sets (Story D3).
///
/// Overlay semantics need presence tracking: a key ABSENT from the project
/// file means "inherit the user layer's value", not "reset to the built-in
/// default". Serde alone cannot distinguish those two (every field carries
/// `#[serde(default)]`), so the raw TOML table is inspected alongside the
/// typed parse.
///
/// # MUST-BE-UPDATED (drift tripwire, m15)
///
/// When a PROTECTION field joins [`Config`], you MUST also:
/// 1. add its flag here and populate it in [`TighteningPresence::from_toml`],
/// 2. list its key in [`TighteningPresence::TRACKED_KEYS`],
/// 3. give it a monotonicity rule in [`merge_tightening`] (and a row in that
///    function's doc table).
///
/// Skipping any step makes the layered loader silently last-match the new
/// field — a weakening hole. The test
/// `tightening_presence_tracks_every_protection_field` pins this contract
/// against [`PROTECTION_CONFIG_FIELDS`].
#[derive(Debug, Default)]
struct TighteningPresence {
    // Protection fields.
    thresholds_block_at: bool,
    thresholds_warn_at: bool,
    allow_list: bool,
    custom_blocks: bool,
    tool_rules: bool,
    disable: bool,
    disabled: bool,
    normalize: bool,
    level: bool,
    // Protection-adjacent (M1): opt-in packs + enforced ruleset identity.
    packs: bool,
    policy: bool,
    // Protection-adjacent (V5-A): opt-in community packs (union-additive
    // enabled list; dir immutable once set).
    community_packs_enabled: bool,
    community_packs_dir: bool,
    // Non-protection fields (project wins last-match, no validation).
    audit: bool,
    canary: bool,
}

impl TighteningPresence {
    /// Every key this tracker inspects. Kept as data so the drift-tripwire
    /// test can assert that each protection field of [`Config`] is covered.
    #[cfg(test)]
    const TRACKED_KEYS: &'static [&'static str] = &[
        "thresholds.block_at",
        "thresholds.warn_at",
        "allow_list",
        "custom_blocks",
        "tool_rules",
        "disable",
        "disabled",
        "normalize",
        "level",
        "packs",
        "policy",
        "community_packs.enabled",
        "community_packs.dir",
        "audit",
        "canary",
    ];

    /// Inspect the raw TOML text of an overlay file for explicitly-set keys.
    fn from_toml(text: &str) -> Result<Self> {
        let tbl: toml::Table = toml::from_str(text)?;
        let thresholds = tbl.get("thresholds").and_then(toml::Value::as_table);
        let community_packs = tbl.get("community_packs").and_then(toml::Value::as_table);
        Ok(Self {
            thresholds_block_at: thresholds.is_some_and(|t| t.contains_key("block_at")),
            thresholds_warn_at: thresholds.is_some_and(|t| t.contains_key("warn_at")),
            allow_list: tbl.contains_key("allow_list"),
            custom_blocks: tbl.contains_key("custom_blocks"),
            tool_rules: tbl.contains_key("tool_rules"),
            disable: tbl.contains_key("disable"),
            disabled: tbl.contains_key("disabled"),
            normalize: tbl.contains_key("normalize"),
            level: tbl.contains_key("level"),
            packs: tbl.contains_key("packs"),
            policy: tbl.contains_key("policy"),
            community_packs_enabled: community_packs.is_some_and(|t| t.contains_key("enabled")),
            community_packs_dir: community_packs.is_some_and(|t| t.contains_key("dir")),
            audit: tbl.contains_key("audit"),
            canary: tbl.contains_key("canary"),
        })
    }
}

/// The protection fields of [`Config`] (incl. M1's packs/policy) that MUST be
/// covered by a [`TighteningPresence`] flag + a monotonicity rule in
/// [`merge_tightening`]. Test-only drift-tripwire list — see
/// `tightening_presence_tracks_every_protection_field`.
#[cfg(test)]
const PROTECTION_CONFIG_FIELDS: &[&str] = &[
    "thresholds.block_at",
    "thresholds.warn_at",
    "allow_list",
    "custom_blocks",
    "tool_rules",
    "disable",
    "disabled",
    "normalize",
    "level",
    "packs",
    "policy",
    "community_packs.enabled",
    "community_packs.dir",
];

/// Rank a [`Tier`] on the Allow < Warn < Ask < Block lattice. Local copy of
/// `crate::hook::tier_rank` so `config` does not grow a dependency on `hook`
/// (mirrors it exactly; Ask is unreachable from [`severity_to_tier`] but the
/// arm keeps the match exhaustive).
fn action_rank(t: Tier) -> u8 {
    match t {
        Tier::Allow => 0,
        Tier::Warn => 1,
        Tier::Ask => 2,
        Tier::Block => 3,
    }
}

/// Merge a parsed project OVERLAY onto a validated user BASE under the
/// monotonic-tightening contract (Story D3). Returns the merged config; any
/// loosening attempt is a loud error naming the offending field (callers fail
/// closed with exit 2).
///
/// Per-field rules — protection fields ONLY; every other key is project-wins
/// last-match with no validation:
///
/// | field          | rule (project vs user)                                                        |
/// |----------------|-------------------------------------------------------------------------------|
/// | thresholds     | resolved block/warn cutoffs must be <= the user's (lower = tighter); `level` presets resolve to concrete values FIRST, then the same rule applies |
/// | allow_list     | every project entry must exist in the user list (subset ⇒ intersection semantics via validation) |
/// | custom_blocks  | project must carry every USER PATTERN (matched by pattern only, so the project may raise a block's severity); new patterns additive |
/// | tool_rules     | per rule identity `(tool, arg, pattern)`: the mapped action rank Allow<Warn<Ask<Block must not decrease; new identities are additive and always fine |
/// | disable        | user `false` → project `true` rejected (`true`→`false` fine)                  |
/// | disabled       | ADDING a component rejected; removing fine                                    |
/// | normalize      | turning OFF what the user has ON rejected                                     |
/// | packs          | project must keep every user-opted-in pack (superset); new packs additive      |
/// | policy.file    | IMMUTABLE once set by the user layer: never cleared or replaced (project may only SET it when the user layer has none — additive bootstrap) |
/// | community_packs.enabled | UNION-additive: project must keep every user-enabled pack name; merged list = user names first, then project additions |
/// | community_packs.dir     | IMMUTABLE once set by the user layer: never cleared or replaced (project may only SET it when the user layer has none) |
///
/// Absent keys INHERIT the user layer's value (overlay semantics); presence
/// is tracked by [`TighteningPresence`]. Detection/observability surfaces
/// (`audit`, `canary`) are deliberately OUTSIDE this table: the project layer
/// may disable them last-match-wins — accepted by design (see the field docs
/// on [`Config::audit`] / [`Config::canary`]).
fn merge_tightening(base: Config, overlay: Config, p: &TighteningPresence) -> Result<Config> {
    let mut merged = base.clone();
    let user_eff = base.effective_thresholds();

    // --- thresholds + level presets (resolve FIRST, then compare) ------------
    if p.level {
        // The preset resolves to concrete cutoffs; the tightening rule
        // applies to the RESOLVED values.
        let proj_eff = overlay.effective_thresholds();
        if proj_eff.block_at > user_eff.block_at {
            anyhow::bail!(
                "thresholds.block_at: project preset resolves to {} which raises the user cutoff {}",
                proj_eff.block_at,
                user_eff.block_at
            );
        }
        if proj_eff.warn_at > user_eff.warn_at {
            anyhow::bail!(
                "thresholds.warn_at: project preset resolves to {} which raises the user cutoff {}",
                proj_eff.warn_at,
                user_eff.warn_at
            );
        }
        merged.level = overlay.level.clone();
        merged.thresholds = proj_eff;
    } else if p.thresholds_block_at || p.thresholds_warn_at {
        // Partial override: unspecified cutoffs inherit the USER's effective
        // values (not the built-in defaults).
        let mut t = user_eff;
        if p.thresholds_block_at {
            t.block_at = overlay.thresholds.block_at;
        }
        if p.thresholds_warn_at {
            t.warn_at = overlay.thresholds.warn_at;
        }
        if t.block_at > user_eff.block_at {
            anyhow::bail!(
                "thresholds.block_at ({}) raises the user cutoff ({})",
                t.block_at,
                user_eff.block_at
            );
        }
        if t.warn_at > user_eff.warn_at {
            anyhow::bail!(
                "thresholds.warn_at ({}) raises the user cutoff ({})",
                t.warn_at,
                user_eff.warn_at
            );
        }
        // The user preset has been resolved into concrete values; carrying
        // `level` over would re-apply the unresolved preset on top of the
        // merged cutoffs.
        merged.level = None;
        merged.thresholds = t;
    } // else: inherit the user layer's thresholds/level wholesale.

    // --- allow_list: subset-only ----------------------------------------------
    if p.allow_list {
        for entry in &overlay.allow_list {
            if !base.allow_list.contains(entry) {
                anyhow::bail!(
                    "allow_list entry {entry:?} is not present in the user config allow_list \
                     (adding an allowance would weaken the gate)"
                );
            }
        }
        merged.allow_list = overlay.allow_list.clone();
    }

    // --- custom_blocks: superset by PATTERN only -------------------------------
    // (N1) Matching on the pattern alone lets the project RAISE the severity
    // of a user block (a tightening) without rejection; dropping a user
    // pattern entirely is still a weakening and rejected.
    if p.custom_blocks {
        for ub in &base.custom_blocks {
            if !overlay
                .custom_blocks
                .iter()
                .any(|pb| pb.pattern == ub.pattern)
            {
                anyhow::bail!(
                    "custom_blocks is missing the user pattern {:?} — dropping a block would \
                     weaken the gate",
                    ub.pattern
                );
            }
        }
        merged.custom_blocks = overlay.custom_blocks.clone();
    }

    // --- tool_rules: per-identity rank monotonicity; additions fine ------------
    if p.tool_rules {
        let eff = merged.effective_thresholds();
        for pr in &overlay.tool_rules {
            if let Some(ur) = base
                .tool_rules
                .iter()
                .find(|ur| ur.tool == pr.tool && ur.arg == pr.arg && ur.pattern == pr.pattern)
            {
                let user_rank = action_rank(severity_to_tier(ur.severity, &eff));
                let proj_rank = action_rank(severity_to_tier(pr.severity, &eff));
                if proj_rank < user_rank {
                    anyhow::bail!(
                        "tool_rules[tool={:?}, arg={:?}, pattern={:?}]: severity {} maps to a \
                         weaker action than the user's severity {} for the same rule",
                        pr.tool,
                        pr.arg,
                        pr.pattern,
                        pr.severity,
                        ur.severity
                    );
                }
            }
            // New rule identity: additive tightening, always fine.
        }
        // Union semantics: user rules survive unless the project overrides
        // their exact identity; project additions are appended.
        let mut rules = base.tool_rules.clone();
        for pr in overlay.tool_rules {
            match rules
                .iter_mut()
                .find(|ur| ur.tool == pr.tool && ur.arg == pr.arg && ur.pattern == pr.pattern)
            {
                Some(slot) => *slot = pr,
                None => rules.push(pr),
            }
        }
        merged.tool_rules = rules;
    }

    // --- disable: the global kill-switch may only be turned ON by the user -----
    if p.disable {
        if !base.disable && overlay.disable {
            anyhow::bail!("disable = true would turn OFF the whole gate the user config leaves on");
        }
        merged.disable = overlay.disable;
    }

    // --- disabled: component kill-list is subset-only ---------------------------
    if p.disabled {
        for c in &overlay.disabled {
            let known = base
                .disabled
                .iter()
                .any(|u| u.trim().eq_ignore_ascii_case(c.trim()));
            if !known {
                anyhow::bail!(
                    "disabled component {c:?} is not disabled in the user config — disabling \
                     another component would weaken the gate"
                );
            }
        }
        // (N4) Carry the USER layer's canonical casing for inherited entries:
        // validation just proved every overlay entry case-insensitively
        // matches a user entry, so the lookup below always succeeds.
        merged.disabled = overlay
            .disabled
            .iter()
            .map(|c| {
                base.disabled
                    .iter()
                    .find(|u| u.trim().eq_ignore_ascii_case(c.trim()))
                    .expect("validated above: every overlay entry exists in the user list")
                    .clone()
            })
            .collect();
    }

    // --- normalize: the pre-pass may not be switched off by the project --------
    if p.normalize {
        if base.normalize && !overlay.normalize {
            anyhow::bail!(
                "normalize = false would turn OFF the normalization pre-pass the user config \
                 leaves on"
            );
        }
        merged.normalize = overlay.normalize;
    }

    // --- packs: opt-in rule packs are PROTECTION (superset-only) ---------------
    // (M1b) A plain last-match replace would let `packs = []` in the project
    // layer silently drop the user's opted-in pack rules from enforcement.
    // The project list must keep every user pack; new packs are additive.
    if p.packs {
        for up in &base.packs {
            if !overlay.packs.contains(up) {
                anyhow::bail!(
                    "packs is missing the user-opted-in pack {up:?} — dropping a rule pack \
                     would weaken the gate"
                );
            }
        }
        merged.packs = overlay.packs;
    }

    // --- community_packs: opt-in community packs are PROTECTION (V5-A) --------
    // enabled: UNION-additive. The project list must keep every user-enabled
    // name (dropping one would silently remove those rules from enforcement);
    // additions are always fine. The merged list is the union with USER order
    // first, then project-only names appended.
    if p.community_packs_enabled {
        for up in &base.community_packs.enabled {
            if !overlay.community_packs.enabled.contains(up) {
                anyhow::bail!(
                    "community_packs.enabled is missing the user-opted-in pack {up:?} — \
                     dropping a community pack would weaken the gate"
                );
            }
        }
        let mut enabled = base.community_packs.enabled.clone();
        for name in overlay.community_packs.enabled {
            if !enabled.contains(&name) {
                enabled.push(name);
            }
        }
        merged.community_packs.enabled = enabled;
    }
    // dir: IMMUTABLE once the user layer sets it (same reasoning as
    // policy.file): swapping the directory swaps WHICH pack files are loaded,
    // and an explicit-empty project section must not clear it.
    if p.community_packs_dir {
        match (&base.community_packs.dir, &overlay.community_packs.dir) {
            (Some(user_dir), Some(proj_dir)) if proj_dir != user_dir => {
                anyhow::bail!(
                    "community_packs.dir {proj_dir:?} cannot replace the user layer's \
                     community packs directory {user_dir:?} — swapping the loaded pack \
                     directory would weaken the gate"
                );
            }
            // User dir set: keep it verbatim (explicit-empty project included).
            (Some(_), _) => {}
            // No user dir: the project may bootstrap one.
            (None, Some(proj_dir)) => merged.community_packs.dir = Some(proj_dir.clone()),
            (None, None) => {}
        }
    }

    // --- audit / canary: detection & observability, accepted-by-design ---------
    // The project layer MAY disable these last-match-wins: they are
    // detection/observability surfaces, not pre-execution enforcement, and
    // are deliberately outside the monotonic-tightening contract (see the
    // field docs on Config::audit / Config::canary).
    if p.audit {
        merged.audit = overlay.audit;
    }
    if p.canary {
        merged.canary = overlay.canary;
    }

    // --- policy.file: IMMUTABLE once the user layer sets it ---------------------
    // (M1a) `[policy].file` decides WHICH ruleset the engine enforces. A
    // plain replace would let the project swap the user's ruleset for its
    // own; an explicit empty `[policy]` would clear it and silently turn the
    // engine into a no-op (a default-deny user policy gone). So: never
    // cleared, never replaced — the project may only SET the file when the
    // user layer has none (additive bootstrap).
    if p.policy {
        match (&base.policy.file, &overlay.policy.file) {
            (Some(user_file), Some(proj_file)) if proj_file != user_file => {
                anyhow::bail!(
                    "policy.file {proj_file:?} cannot replace the user layer's policy file \
                     {user_file:?} — swapping the enforced ruleset would weaken the gate"
                );
            }
            // User file set: keep it verbatim (explicit-empty project included).
            (Some(_), _) => {}
            // No user file: the project may bootstrap one.
            (None, Some(proj_file)) => merged.policy.file = Some(proj_file.clone()),
            (None, None) => {}
        }
    }

    Ok(merged)
}

/// Minimal glob match: `*` is a wildcard over any run of characters; a pattern
/// with no `*` matches when it is a substring of `text`.
fn glob_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return text.contains(pattern);
    }

    // Anchor logic: leading/trailing `*` relax the respective anchor.
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();

    if parts.is_empty() {
        // Pattern is only `*`s — matches anything.
        return true;
    }

    let mut cursor = 0usize;
    for (i, part) in parts.iter().enumerate() {
        match text[cursor..].find(part) {
            Some(pos) => {
                let abs = cursor + pos;
                if i == 0 && anchored_start && abs != 0 {
                    return false;
                }
                cursor = abs + part.len();
            }
            None => return false,
        }
    }

    if anchored_end && cursor != text.len() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_default_config() -> Config {
        Config {
            allow_list: vec!["git status".to_string(), "cargo *".to_string()],
            custom_blocks: vec![CustomBlock {
                pattern: "shutdown".to_string(),
                severity: 9,
                category: "system".to_string(),
            }],
            thresholds: Thresholds {
                block_at: 9,
                warn_at: 4,
            },
            disable: true,
            // Non-default (default is true) so the round-trip exercises the field.
            normalize: false,
            // Non-default audit settings so the round-trip exercises [audit].
            audit: AuditConfig {
                enabled: true,
                path: Some(PathBuf::from("/tmp/agentguard-audit.jsonl")),
                include_command: true,
            },
            // Non-default forward-compat fields so the round-trip exercises
            // each new field (otherwise toml_round_trip is a false green).
            packs: vec!["aws".to_string(), "k8s".to_string()],
            tool_rules: vec![ToolRule {
                tool: "web_fetch".to_string(),
                arg: "url".to_string(),
                pattern: "*169.254.169.254*".to_string(),
                severity: 9,
            }],
            disabled: vec!["firewall".to_string()],
            level: Some("strict".to_string()),
            // Non-default (default is false) so the round-trip exercises [canary].
            canary: CanaryConfig { enabled: true },
            // Non-default (default is None) so the round-trip exercises [policy].
            policy: PolicyConfig {
                file: Some(PathBuf::from("/etc/agentguard/policy.toml")),
            },
            // Non-default (default is empty/off) so the round-trip exercises
            // [community_packs].
            community_packs: CommunityPacksConfig {
                enabled: vec!["my-org-infra".to_string()],
                dir: Some(PathBuf::from("/opt/agentguard/packs-community")),
            },
        }
    }

    #[test]
    fn toml_round_trip() {
        let cfg = non_default_config();
        let text = toml::to_string(&cfg).expect("serialize");
        let parsed: Config = toml::from_str(&text).expect("deserialize");
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn no_config_is_defaults() {
        let cfg = Config::load(None).expect("load none");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn empty_toml_is_defaults() {
        let cfg: Config = toml::from_str("").expect("parse empty");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn empty_toml_keeps_audit_disabled() {
        // The new [audit] field must default to disabled + metadata-only when
        // absent from the TOML.
        let cfg: Config = toml::from_str("").expect("parse empty");
        assert!(!cfg.audit.enabled);
        assert!(cfg.audit.path.is_none());
        assert!(!cfg.audit.include_command);
    }

    #[test]
    fn partial_toml_omitting_new_fields_is_default() {
        // A TOML that sets only pre-existing fields must leave every
        // forward-compat field (packs/tool_rules/disabled/level/canary/policy)
        // at its default — proving the empty-TOML invariant survives schema
        // growth.
        let text = r#"
            allow_list = ["git status"]
            disable = false
        "#;
        let cfg: Config = toml::from_str(text).expect("parse partial");
        assert!(cfg.packs.is_empty());
        assert!(cfg.tool_rules.is_empty());
        assert!(cfg.disabled.is_empty());
        assert!(cfg.level.is_none());
        assert!(!cfg.canary.enabled);
        assert_eq!(cfg.policy, PolicyConfig::default());
        assert!(cfg.policy.file.is_none());
    }

    #[test]
    fn audit_section_round_trips() {
        let text = r#"
            [audit]
            enabled = true
            path = "/tmp/x.jsonl"
            include_command = true
        "#;
        let cfg: Config = toml::from_str(text).expect("parse [audit]");
        assert!(cfg.audit.enabled);
        assert_eq!(cfg.audit.path, Some(PathBuf::from("/tmp/x.jsonl")));
        assert!(cfg.audit.include_command);
    }

    // ---- v0.3 [policy] section ----

    #[test]
    fn partial_toml_omitting_policy_is_default() {
        // The per-story empty-TOML invariant for the new v0.3 [policy] field:
        // a TOML that omits [policy] entirely must parse to
        // `Config::default()` with `policy == PolicyConfig::default()`. This
        // is the v0.3 equivalent of `partial_toml_omitting_new_fields_is_default`,
        // called out by name in the plan so a future regression in the
        // serde-default behavior fails this test BEFORE it can fail the
        // higher-level hook/policy tests.
        let text = r#"
            allow_list = ["git status"]
        "#;
        let cfg: Config = toml::from_str(text).expect("parse partial");
        assert_eq!(cfg.policy, PolicyConfig::default());
        assert!(cfg.policy.file.is_none());
    }

    #[test]
    fn policy_section_round_trips() {
        // Set every [policy] key, serialize, deserialize, assert equality.
        // This is the `policy` analogue of `audit_section_round_trips`. If a
        // future field is added to PolicyConfig without `#[serde(default)]`
        // (or a round-trip is broken), this test fails BEFORE the policy
        // engine (Story 2) can ship a broken schema.
        let text = r#"
            [policy]
            file = "/etc/agentguard/policy.toml"
        "#;
        let cfg: Config = toml::from_str(text).expect("parse [policy]");
        assert_eq!(
            cfg.policy,
            PolicyConfig {
                file: Some(PathBuf::from("/etc/agentguard/policy.toml")),
            }
        );
        // Round-trip: serialize and re-parse; must match the in-memory value.
        let serialized = toml::to_string(&cfg).expect("serialize [policy]");
        let reparsed: Config = toml::from_str(&serialized).expect("re-parse [policy]");
        assert_eq!(reparsed.policy, cfg.policy);
    }

    #[test]
    fn non_default_config_exercises_every_new_field() {
        // The non_default_config() fixture must set EVERY Config field to a
        // non-default value, so toml_round_trip actually exercises every
        // schema growth. This test is the canary the v0.2 plan's F2 finding
        // called out: a fixture that accidentally leaves a field at its
        // default is a false-green for that field's round-trip.
        let cfg = non_default_config();
        // Pre-existing defaults baseline.
        assert_ne!(cfg.allow_list, Config::default().allow_list);
        assert_ne!(cfg.custom_blocks, Config::default().custom_blocks);
        assert_ne!(cfg.thresholds, Config::default().thresholds);
        assert_ne!(cfg.audit, Config::default().audit);
        // v0.1.x forward-compat fields.
        assert_ne!(cfg.packs, Config::default().packs);
        assert_ne!(cfg.tool_rules, Config::default().tool_rules);
        assert_ne!(cfg.disabled, Config::default().disabled);
        assert_ne!(cfg.level, Config::default().level);
        assert_ne!(cfg.canary, Config::default().canary);
        // v0.3 [policy] field.
        assert_ne!(cfg.policy, Config::default().policy);
        assert!(cfg.policy.file.is_some());
        // V5-A [community_packs] field.
        assert_ne!(cfg.community_packs, Config::default().community_packs);
        assert!(!cfg.community_packs.enabled.is_empty());
        assert!(cfg.community_packs.dir.is_some());
    }

    #[test]
    fn normalize_defaults_to_true() {
        // Both the struct default and an absent TOML field must be `true`.
        assert!(Config::default().normalize);
        let cfg: Config = toml::from_str("").expect("parse empty");
        assert!(cfg.normalize);
    }

    #[test]
    fn normalize_can_be_disabled_via_toml() {
        let cfg: Config = toml::from_str("normalize = false").expect("parse");
        assert!(!cfg.normalize);
    }

    #[test]
    fn allow_list_short_circuit() {
        let cfg = non_default_config();
        assert!(cfg.is_allowed("git status"));
        assert!(!cfg.is_allowed("rm -rf /"));
        // `cargo *` glob entry.
        assert!(cfg.is_allowed("cargo build --release"));
        assert!(!cfg.is_allowed("npm install"));
    }

    // ---- US-F1: granular kill-switch + severity presets ----

    #[test]
    fn default_disabled_set_is_empty_and_thresholds_unchanged() {
        // INVARIANT: the default config disables nothing and keeps today's
        // thresholds, so an empty env + empty TOML is byte-identical to before.
        let cfg = Config::default();
        let env = EnvDisable::default();
        assert!(!env.all);
        assert!(env.names.is_empty());
        for component in ["gate", "firewall", "pathguard", "canary"] {
            assert!(
                !cfg.is_component_disabled(component, &env),
                "{component} must be enabled by default"
            );
        }
        assert_eq!(cfg.effective_thresholds(), Thresholds::default());
    }

    #[test]
    fn env_disable_parses_all_truthy() {
        for raw in ["1", "true", "TRUE", " True "] {
            let env = EnvDisable::parse(raw);
            assert!(env.all, "{raw:?} must mean ALL");
            assert!(env.names.is_empty());
        }
    }

    #[test]
    fn env_disable_parses_comma_list_case_insensitive() {
        let env = EnvDisable::parse(" Gate , FIREWALL ,, unknown ");
        assert!(!env.all);
        assert_eq!(env.names, vec!["gate", "firewall", "unknown"]);
    }

    #[test]
    fn is_component_disabled_union_of_config_and_env() {
        // config.disabled lists firewall; env lists gate. Both are disabled, the
        // others stay enabled.
        let cfg = Config {
            disabled: vec!["firewall".to_string()],
            ..Config::default()
        };
        let env = EnvDisable::parse("gate");
        assert!(cfg.is_component_disabled("gate", &env));
        assert!(cfg.is_component_disabled("firewall", &env));
        assert!(!cfg.is_component_disabled("pathguard", &env));
        assert!(!cfg.is_component_disabled("canary", &env));
    }

    #[test]
    fn disable_bool_disables_all_components() {
        // Back-compat: the legacy all-off flag disables every component.
        let cfg = Config {
            disable: true,
            ..Config::default()
        };
        let env = EnvDisable::default();
        for component in ["gate", "firewall", "pathguard", "canary"] {
            assert!(cfg.is_component_disabled(component, &env));
        }
    }

    #[test]
    fn env_all_disables_all_components() {
        let cfg = Config::default();
        let env = EnvDisable::parse("1");
        for component in ["gate", "firewall", "pathguard", "canary"] {
            assert!(cfg.is_component_disabled(component, &env));
        }
    }

    #[test]
    fn unknown_component_token_is_ignored() {
        // An unknown name in config.disabled / env never matches a real
        // component and is not an error.
        let cfg = Config {
            disabled: vec!["bogus".to_string()],
            ..Config::default()
        };
        let env = EnvDisable::parse("nonsense");
        for component in ["gate", "firewall", "pathguard", "canary"] {
            assert!(!cfg.is_component_disabled(component, &env));
        }
    }

    #[test]
    fn level_presets_map_to_thresholds() {
        let preset = |name: &str| {
            Config {
                level: Some(name.to_string()),
                ..Config::default()
            }
            .effective_thresholds()
        };
        assert_eq!(
            preset("strict"),
            Thresholds {
                block_at: 7,
                warn_at: 4
            }
        );
        assert_eq!(
            preset("high"),
            Thresholds {
                block_at: 6,
                warn_at: 3
            }
        );
        assert_eq!(
            preset("critical"),
            Thresholds {
                block_at: 5,
                warn_at: 2
            }
        );
        // Case-insensitive.
        assert_eq!(preset("CRITICAL"), preset("critical"));
    }

    #[test]
    fn level_none_uses_configured_thresholds() {
        // No preset => the configured thresholds win (default here).
        assert_eq!(
            Config::default().effective_thresholds(),
            Thresholds::default()
        );
        // An unrecognized preset name also falls back to configured thresholds.
        let cfg = Config {
            level: Some("bogus".to_string()),
            thresholds: Thresholds {
                block_at: 9,
                warn_at: 4,
            },
            ..Config::default()
        };
        assert_eq!(
            cfg.effective_thresholds(),
            Thresholds {
                block_at: 9,
                warn_at: 4
            }
        );
    }

    #[test]
    fn custom_blocks_parse_from_toml() {
        let text = r#"
            [[custom_blocks]]
            pattern = "rm -rf"
            severity = 9
            category = "destructive"

            [[custom_blocks]]
            pattern = "dd if="
            severity = 8
            category = "destructive"
        "#;
        let cfg: Config = toml::from_str(text).expect("parse custom_blocks");
        assert_eq!(cfg.custom_blocks.len(), 2);
        assert_eq!(cfg.custom_blocks[0].pattern, "rm -rf");
        assert_eq!(cfg.custom_blocks[0].severity, 9);
        assert_eq!(cfg.custom_blocks[1].category, "destructive");
        // Other fields remain at defaults.
        assert_eq!(cfg.thresholds, Thresholds::default());
        assert!(!cfg.disable);
    }

    // ---- Story D1: unknown keys are rejected (deny_unknown_fields) ----

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let err = toml::from_str::<Config>("bogus_key = true").expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("bogus_key"),
            "error must name the offending key: {msg}"
        );
    }

    #[test]
    fn unknown_key_in_sub_table_is_rejected() {
        let text = r#"
            [canary]
            enabled = false
            typo_key = true
        "#;
        let err = toml::from_str::<Config>(text).expect_err("must reject");
        assert!(
            format!("{err:#}").contains("typo_key"),
            "error must name the offending key"
        );
    }

    #[test]
    fn unknown_key_in_custom_block_entry_is_rejected() {
        let text = r#"
            [[custom_blocks]]
            pattern = "shutdown"
            severity = 9
            category = "system"
            severitiy = 9
        "#;
        assert!(toml::from_str::<Config>(text).is_err(), "must reject");
    }

    // ---- Story M5: Config::validate() cross-field invariants ----

    #[test]
    fn validate_accepts_default_config() {
        // The default config (and by extension an empty TOML) must always pass.
        Config::default().validate().expect("defaults are valid");
    }

    #[test]
    fn validate_accepts_valid_non_default_config() {
        // The round-trip fixture exercises every field with sane values; it
        // must pass validation (level preset known, severities in range,
        // warn_at <= block_at, patterns non-empty).
        non_default_config().validate().expect("fixture is valid");
    }

    #[test]
    fn validate_accepts_equal_thresholds_boundary() {
        // warn_at == block_at is allowed (<=): severity == block_at blocks,
        // everything below allows — a coherent (if coarse) configuration.
        let cfg = Config {
            thresholds: Thresholds {
                block_at: 6,
                warn_at: 6,
            },
            ..Config::default()
        };
        cfg.validate().expect("equal thresholds are valid");
    }

    #[test]
    fn validate_rejects_inverted_thresholds() {
        let cfg = Config {
            thresholds: Thresholds {
                block_at: 5,
                warn_at: 8,
            },
            ..Config::default()
        };
        let err = cfg.validate().expect_err("inverted thresholds must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("warn_at") && msg.contains("block_at"),
            "error must name both offending fields: {msg}"
        );
    }

    #[test]
    fn validate_rejects_unknown_level_preset() {
        let cfg = Config {
            level: Some("strick".to_string()),
            ..Config::default()
        };
        let err = cfg.validate().expect_err("typo'd preset must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("strick") && msg.contains("strict"),
            "error must name the bad value and a valid option: {msg}"
        );
    }

    #[test]
    fn validate_rejects_empty_custom_block_pattern() {
        let cfg = Config {
            custom_blocks: vec![CustomBlock {
                pattern: String::new(),
                severity: 9,
                category: "oops".to_string(),
            }],
            ..Config::default()
        };
        let err = cfg.validate().expect_err("empty pattern must fail");
        assert!(
            format!("{err:#}").contains("custom_blocks.pattern"),
            "error must name the offending field"
        );
    }

    #[test]
    fn validate_rejects_out_of_range_severities() {
        // custom_blocks severity above the documented 0..=9 scale.
        let cfg = Config {
            custom_blocks: vec![CustomBlock {
                pattern: "boom".to_string(),
                severity: 10,
                category: "scale".to_string(),
            }],
            ..Config::default()
        };
        assert!(cfg.validate().is_err(), "severity 10 must fail");

        // tool_rules severity far out of range.
        let cfg = Config {
            tool_rules: vec![ToolRule {
                tool: "Bash".to_string(),
                arg: "command".to_string(),
                pattern: "boom".to_string(),
                severity: 200,
            }],
            ..Config::default()
        };
        let err = cfg.validate().expect_err("severity 200 must fail");
        assert!(
            format!("{err:#}").contains("tool_rules.severity"),
            "error must name the offending field: {err:#}"
        );
    }

    #[test]
    fn load_fails_closed_on_invalid_cross_field_combo() {
        // A config that PARSES but violates an invariant must fail the LOAD
        // path (same loud Err as a parse error), not silently load.
        let dir = std::env::temp_dir().join(format!(
            "agentguard-validate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agentguard.toml");
        std::fs::write(&path, "[thresholds]\nblock_at = 5\nwarn_at = 8\n").unwrap();
        let err = Config::load(Some(&path)).expect_err("invalid combo must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid configuration") && msg.contains("warn_at"),
            "error must carry the file context and the invariant: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Story D3: monotonic tightening (merge_tightening unit tests) ----

    /// Parse an overlay TOML text and merge it onto `base`, for tests.
    fn merge_text(base: Config, overlay_text: &str) -> Result<Config> {
        let overlay: Config = toml::from_str(overlay_text).expect("overlay parses");
        let presence = TighteningPresence::from_toml(overlay_text).expect("presence");
        merge_tightening(base, overlay, &presence)
    }

    fn user_base() -> Config {
        Config {
            allow_list: vec!["ls *".to_string(), "git *".to_string()],
            custom_blocks: vec![CustomBlock {
                pattern: "shutdown".to_string(),
                severity: 9,
                category: "system".to_string(),
            }],
            thresholds: Thresholds {
                block_at: 7,
                warn_at: 4,
            },
            disabled: vec!["canary".to_string()],
            ..Config::default()
        }
    }

    #[test]
    fn merge_rejects_allow_list_addition() {
        let err = merge_text(user_base(), "allow_list = [\"ls *\", \"docker *\"]")
            .expect_err("adding an allowance must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("allow_list") && msg.contains("docker *"),
            "error must name the field and the offending entry: {msg}"
        );
    }

    #[test]
    fn merge_accepts_narrowed_allow_list() {
        let merged = merge_text(user_base(), "allow_list = [\"ls *\"]").expect("subset is fine");
        assert_eq!(merged.allow_list, vec!["ls *".to_string()]);
    }

    #[test]
    fn merge_absent_protection_keys_inherit_user_values() {
        // The overlay only narrows allow_list; thresholds/custom_blocks/
        // disabled must come from the USER layer, not the built-in defaults.
        let merged = merge_text(user_base(), "allow_list = [\"ls *\"]").expect("merge");
        assert_eq!(
            merged.thresholds,
            Thresholds {
                block_at: 7,
                warn_at: 4
            }
        );
        assert_eq!(merged.custom_blocks.len(), 1);
        assert_eq!(merged.disabled, vec!["canary".to_string()]);
    }

    #[test]
    fn merge_rejects_raised_threshold_cutoffs() {
        // NOTE: the schema requires BOTH cutoffs inside [thresholds] (no
        // per-field serde defaults), so a partial table fails at PARSE time;
        // these tests exercise the tightening rule on complete tables.
        let err = merge_text(user_base(), "[thresholds]\nblock_at = 9\nwarn_at = 4\n")
            .expect_err("raising block_at must be rejected");
        assert!(
            format!("{err:#}").contains("block_at"),
            "error must name the offending cutoff: {err:#}"
        );
        // Raising warn_at is equally rejected.
        let err = merge_text(user_base(), "[thresholds]\nblock_at = 7\nwarn_at = 5\n")
            .expect_err("raising warn_at must be rejected");
        assert!(format!("{err:#}").contains("warn_at"), "{err:#}");
    }

    #[test]
    fn merge_accepts_lowered_threshold_cutoffs() {
        // Lowering block_at tightens legitimately; warn_at kept equal to the
        // user's. The merged config carries concrete values with no preset.
        let merged = merge_text(user_base(), "[thresholds]\nblock_at = 6\nwarn_at = 4\n")
            .expect("tightening cutoffs is fine");
        assert_eq!(
            merged.thresholds,
            Thresholds {
                block_at: 6,
                warn_at: 4
            }
        );
        assert!(merged.level.is_none());
    }

    #[test]
    fn merge_resolves_level_presets_before_comparing() {
        // critical (5/2) is tighter than the user's 7/4: accepted, and the
        // preset survives on the merged config.
        let merged = merge_text(user_base(), "level = \"critical\"").expect("tighter preset ok");
        assert_eq!(merged.level.as_deref(), Some("critical"));
        assert_eq!(merged.effective_thresholds().block_at, 5);
        // strict (7/4) equals the user's effective cutoffs: allowed boundary.
        merge_text(user_base(), "level = \"strict\"").expect("equal preset ok");
        // A preset LOOSER than the user's effective values: rejected.
        let base = Config {
            thresholds: Thresholds {
                block_at: 5,
                warn_at: 2,
            },
            ..Config::default()
        };
        let err =
            merge_text(base, "level = \"strict\"").expect_err("looser preset must be rejected");
        assert!(
            format!("{err:#}").contains("thresholds.block_at"),
            "{err:#}"
        );
    }

    #[test]
    fn merge_rejects_custom_blocks_missing_user_entry() {
        let err = merge_text(
            user_base(),
            "[[custom_blocks]]\npattern = \"kubectl delete\"\nseverity = 9\ncategory = \"k8s\"\n",
        )
        .expect_err("dropping a user block must be rejected");
        assert!(format!("{err:#}").contains("custom_blocks"), "{err:#}");
    }

    #[test]
    fn merge_accepts_custom_blocks_superset() {
        let merged = merge_text(
            user_base(),
            "[[custom_blocks]]\npattern = \"shutdown\"\nseverity = 9\ncategory = \"system\"\n\
             [[custom_blocks]]\npattern = \"kubectl delete\"\nseverity = 9\ncategory = \"k8s\"\n",
        )
        .expect("superset of user blocks is fine");
        assert_eq!(merged.custom_blocks.len(), 2);
    }

    #[test]
    fn merge_tool_rules_weakening_rejected_tightening_and_additions_fine() {
        let base = Config {
            tool_rules: vec![ToolRule {
                tool: "web_fetch".to_string(),
                arg: "url".to_string(),
                pattern: "*169.254.169.254*".to_string(),
                severity: 5,
            }],
            ..Config::default()
        };
        // Same identity with a LOWER severity (Warn -> Allow under defaults):
        // rejected.
        let err = merge_text(
            base.clone(),
            "[[tool_rules]]\ntool = \"web_fetch\"\narg = \"url\"\npattern = \"*169.254.169.254*\"\nseverity = 2\n",
        )
        .expect_err("weakening a rule must be rejected");
        assert!(
            format!("{err:#}").contains("tool_rules"),
            "error must name the field: {err:#}"
        );
        // Same identity, HIGHER severity: fine.
        merge_text(
            base.clone(),
            "[[tool_rules]]\ntool = \"web_fetch\"\narg = \"url\"\npattern = \"*169.254.169.254*\"\nseverity = 9\n",
        )
        .expect("tightening a rule is fine");
        // New identity: additive, fine — AND the user rule survives (union).
        let merged = merge_text(
            base,
            "[[tool_rules]]\ntool = \"web_fetch\"\narg = \"url\"\npattern = \"*metadata.google*\"\nseverity = 9\n",
        )
        .expect("additive rules are fine");
        assert_eq!(merged.tool_rules.len(), 2, "union keeps the user rule");
    }

    #[test]
    fn merge_rejects_disable_true_from_project() {
        let err = merge_text(Config::default(), "disable = true")
            .expect_err("the project may not turn the gate off");
        assert!(
            format!("{err:#}").contains("disable"),
            "error must name the field: {err:#}"
        );
        // true -> false is a TIGHTENING (the gate comes back on): fine.
        let base = Config {
            disable: true,
            ..Config::default()
        };
        let merged = merge_text(base, "disable = false").expect("re-enabling is fine");
        assert!(!merged.disable);
    }

    #[test]
    fn merge_disabled_list_is_subset_only() {
        // Adding a component the user did not disable: rejected.
        let err = merge_text(user_base(), "disabled = [\"canary\", \"firewall\"]")
            .expect_err("disabling another component must be rejected");
        assert!(
            format!("{err:#}").contains("disabled") && format!("{err:#}").contains("firewall"),
            "{err:#}"
        );
        // Removing (subset): fine.
        let merged = merge_text(user_base(), "disabled = []").expect("removal is fine");
        assert!(merged.disabled.is_empty());
    }

    #[test]
    fn merge_rejects_normalize_off() {
        let err = merge_text(Config::default(), "normalize = false")
            .expect_err("the project may not switch the pre-pass off");
        assert!(
            format!("{err:#}").contains("normalize"),
            "error must name the field: {err:#}"
        );
    }

    #[test]
    fn merge_non_protection_keys_are_project_wins() {
        // Only audit/canary remain project-wins (M1 moved packs/policy under
        // the tightening contract). The project may disable detection/
        // observability last-match — accepted by design.
        let base = Config {
            canary: CanaryConfig { enabled: true },
            ..user_base()
        };
        let merged = merge_text(base, "[canary]\nenabled = false\n")
            .expect("detection surfaces are project-wins by design");
        assert!(!merged.canary.enabled);
        // Absent non-protection keys inherit the user layer.
        assert!(!merged.audit.enabled);
    }

    // ---- M1: packs + policy.file are protection, not project-wins ----------

    #[test]
    fn merge_rejects_project_packs_dropping_user_pack() {
        let base = Config {
            packs: vec!["aws".to_string()],
            ..user_base()
        };
        let err = merge_text(base, "packs = []").expect_err("dropping a pack must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("packs") && msg.contains("aws"),
            "error must name the field and the dropped pack: {msg}"
        );
    }

    #[test]
    fn merge_accepts_project_packs_superset_union_active() {
        let base = Config {
            packs: vec!["aws".to_string()],
            ..user_base()
        };
        let merged = merge_text(base, "packs = [\"aws\", \"k8s\"]")
            .expect("adding a pack is additive and fine");
        assert_eq!(merged.packs, vec!["aws".to_string(), "k8s".to_string()]);
    }

    #[test]
    fn merge_project_empty_policy_section_keeps_user_policy_file() {
        // An explicit EMPTY [policy] table in the project layer must NOT
        // clear the user's policy file (that would silently no-op the engine,
        // dropping e.g. a default-deny user policy).
        let base = Config {
            policy: PolicyConfig {
                file: Some(PathBuf::from("/user/policy.toml")),
            },
            ..user_base()
        };
        let merged = merge_text(base, "[policy]\n").expect("empty [policy] inherits the user file");
        assert_eq!(
            merged.policy.file,
            Some(PathBuf::from("/user/policy.toml")),
            "user policy file is immutable once set"
        );
    }

    #[test]
    fn merge_rejects_replacing_user_policy_file() {
        let base = Config {
            policy: PolicyConfig {
                file: Some(PathBuf::from("/user/policy.toml")),
            },
            ..user_base()
        };
        let err = merge_text(base, "[policy]\nfile = \"/project/policy.toml\"\n")
            .expect_err("swapping the enforced ruleset must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("policy.file"),
            "error must name the field: {msg}"
        );
    }

    #[test]
    fn merge_allows_policy_file_bootstrap_when_user_has_none() {
        // Additive bootstrap: with NO user-layer policy file, the project may
        // set one (that can only add enforcement).
        let merged = merge_text(user_base(), "[policy]\nfile = \"/project/policy.toml\"\n")
            .expect("bootstrapping a policy file is additive");
        assert_eq!(
            merged.policy.file,
            Some(PathBuf::from("/project/policy.toml"))
        );
    }

    // ---- V5-A: [community_packs] schema + D3 union tightening --------------

    #[test]
    fn partial_toml_omitting_community_packs_is_default() {
        let text = r#"
            allow_list = ["git status"]
        "#;
        let cfg: Config = toml::from_str(text).expect("parse partial");
        assert_eq!(cfg.community_packs, CommunityPacksConfig::default());
        assert!(cfg.community_packs.enabled.is_empty());
        assert!(cfg.community_packs.dir.is_none());
    }

    #[test]
    fn community_packs_section_round_trips() {
        let text = r#"
            [community_packs]
            enabled = ["iac-terraform", "k8s-helm"]
            dir = "/opt/agentguard/packs-community"
        "#;
        let cfg: Config = toml::from_str(text).expect("parse [community_packs]");
        assert_eq!(
            cfg.community_packs.enabled,
            vec!["iac-terraform".to_string(), "k8s-helm".to_string()]
        );
        assert_eq!(
            cfg.community_packs.dir,
            Some(PathBuf::from("/opt/agentguard/packs-community"))
        );
        let serialized = toml::to_string(&cfg).expect("serialize [community_packs]");
        let reparsed: Config = toml::from_str(&serialized).expect("re-parse [community_packs]");
        assert_eq!(reparsed.community_packs, cfg.community_packs);
    }

    #[test]
    fn unknown_key_in_community_packs_is_rejected() {
        let text = "[community_packs]\nenabled = [\"x\"]\ntypo = true\n";
        let err = toml::from_str::<Config>(text).expect_err("must reject");
        assert!(
            format!("{err:#}").contains("typo"),
            "error must name the offending key: {err:#}"
        );
    }

    #[test]
    fn merge_accepts_project_community_pack_addition_union() {
        // Project ADDS a pack name: protection-additive, accepted. The merged
        // list is the UNION with user order first.
        let base = Config {
            community_packs: CommunityPacksConfig {
                enabled: vec!["user-pack".to_string()],
                dir: Some(PathBuf::from("/user/packs")),
            },
            ..user_base()
        };
        let merged = merge_text(
            base,
            "[community_packs]\nenabled = [\"user-pack\", \"project-pack\"]\n",
        )
        .expect("adding a community pack is additive and fine");
        assert_eq!(
            merged.community_packs.enabled,
            vec!["user-pack".to_string(), "project-pack".to_string()]
        );
        // Absent dir key inherits the user layer's value.
        assert_eq!(
            merged.community_packs.dir,
            Some(PathBuf::from("/user/packs"))
        );
    }

    #[test]
    fn merge_rejects_project_community_pack_drop() {
        let base = Config {
            community_packs: CommunityPacksConfig {
                enabled: vec!["user-pack".to_string()],
                dir: None,
            },
            ..user_base()
        };
        let err = merge_text(base, "[community_packs]\nenabled = []\n")
            .expect_err("dropping a user-enabled community pack must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("community_packs.enabled") && msg.contains("user-pack"),
            "error must name the field and the dropped pack: {msg}"
        );
    }

    #[test]
    fn merge_project_enabled_only_does_not_lose_user_dir_and_vv() {
        // Presence is tracked PER SUB-KEY: a project overlay setting only
        // `enabled` inherits the user `dir`, and vice versa.
        let base = Config {
            community_packs: CommunityPacksConfig {
                enabled: vec!["user-pack".to_string()],
                dir: Some(PathBuf::from("/user/packs")),
            },
            ..user_base()
        };
        let merged = merge_text(
            base.clone(),
            "[community_packs]\nenabled = [\"user-pack\"]\ndir = \"/user/packs\"\n",
        )
        .expect("identical sub-keys are a no-op");
        assert_eq!(merged.community_packs, base.community_packs);

        // Only `dir` set in the project (bootstrap onto a user layer without
        // one): enabled list untouched.
        let base_no_dir = Config {
            community_packs: CommunityPacksConfig {
                enabled: vec!["user-pack".to_string()],
                dir: None,
            },
            ..user_base()
        };
        let merged = merge_text(base_no_dir, "[community_packs]\ndir = \"/project/packs\"\n")
            .expect("bootstrapping only the dir is additive");
        assert_eq!(
            merged.community_packs.enabled,
            vec!["user-pack".to_string()],
            "enabled list must inherit the user layer when the project omits it"
        );
        assert_eq!(
            merged.community_packs.dir,
            Some(PathBuf::from("/project/packs"))
        );
    }

    #[test]
    fn merge_rejects_replacing_user_community_packs_dir() {
        let base = Config {
            community_packs: CommunityPacksConfig {
                enabled: vec!["p".to_string()],
                dir: Some(PathBuf::from("/user/packs")),
            },
            ..user_base()
        };
        let err = merge_text(
            base,
            "[community_packs]\nenabled = [\"p\"]\ndir = \"/project/packs\"\n",
        )
        .expect_err("swapping the pack directory must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("community_packs.dir"),
            "error must name the field: {msg}"
        );
    }

    // ---- N1: custom_blocks superset compares PATTERN only ------------------

    #[test]
    fn merge_custom_blocks_severity_raise_accepted() {
        // Same pattern, HIGHER severity in the project layer: a tightening,
        // accepted — and the merged config carries the raised severity.
        let merged = merge_text(
            user_base(),
            "[[custom_blocks]]\npattern = \"shutdown\"\nseverity = 9\ncategory = \"system\"\n",
        )
        .expect("raising severity over the same pattern is fine");
        assert_eq!(merged.custom_blocks.len(), 1);
        assert_eq!(merged.custom_blocks[0].pattern, "shutdown");
        assert_eq!(
            merged.custom_blocks[0].severity, 9,
            "project's raised severity wins"
        );
    }

    // ---- N4: disabled list keeps the USER layer's canonical casing ---------

    #[test]
    fn merge_disabled_preserves_user_casing() {
        let base = Config {
            disabled: vec!["CANARY".to_string()],
            ..user_base()
        };
        let merged = merge_text(base, "disabled = [\"canary\"]")
            .expect("case-insensitive subset match is fine");
        assert_eq!(
            merged.disabled,
            vec!["CANARY".to_string()],
            "inherited entries keep the user layer's canonical casing"
        );
    }

    // ---- N2: TighteningPresence drift tripwire ------------------------------

    #[test]
    fn tightening_presence_tracks_every_protection_field() {
        // The tracker's keys and the protection-field list must be EQUAL AS
        // SETS once the deliberately NON-protection keys are carved out —
        // checked BIDIRECTIONALLY: every protection field of Config MUST be
        // tracked by TighteningPresence (a field without a presence flag
        // would be silently last-matched by the layered loader — a weakening
        // hole), and every tracked key MUST correspond to a protection-field
        // entry or to a declared non-protection key (else the tracker drifts
        // from the contract it documents). A one-directional subset check let
        // a key join one list without the other and still pass green. Sorted
        // comparison makes any missing or extra key visible directly in the
        // assertion diff. See the MUST-BE-UPDATED note on
        // TighteningPresence.
        //
        // Non-protection carve-out: `audit` / `canary` are detection/
        // observability surfaces the project layer MAY disable
        // last-match-wins — accepted by design (see the field docs on
        // [`Config::audit`] / [`Config::canary`]), so they live ONLY in
        // TRACKED_KEYS, never in PROTECTION_CONFIG_FIELDS.
        const NON_PROTECTION_KEYS: &[&str] = &["audit", "canary"];
        let mut protection: Vec<&str> = PROTECTION_CONFIG_FIELDS.to_vec();
        let mut tracked_protection: Vec<&str> = TighteningPresence::TRACKED_KEYS
            .iter()
            .copied()
            .filter(|key| !NON_PROTECTION_KEYS.contains(key))
            .collect();
        protection.sort_unstable();
        tracked_protection.sort_unstable();
        assert_eq!(
            protection, tracked_protection,
            "PROTECTION_CONFIG_FIELDS and TighteningPresence::TRACKED_KEYS drifted apart — \
             a protection key was added to one list without the other (and is neither \
             covered by the non-protection carve-out {NON_PROTECTION_KEYS:?}); \
             the diff above shows exactly which keys are missing/extra"
        );
        // And the tracker actually FLIPS for every tracked key when set.
        // NOTE: every TOP-LEVEL key must precede any table header — TOML
        // attaches bare keys after a header to that table.
        let text = concat!(
            "allow_list = [\"x\"]\n",
            "disable = true\ndisabled = [\"gate\"]\nnormalize = true\nlevel = \"strict\"\n",
            "packs = [\"aws\"]\n",
            "[thresholds]\nblock_at = 1\nwarn_at = 1\n",
            "[[custom_blocks]]\npattern = \"p\"\nseverity = 1\ncategory = \"c\"\n",
            "[[tool_rules]]\ntool = \"t\"\narg = \"a\"\npattern = \"p\"\nseverity = 1\n",
            "[policy]\nfile = \"/p.toml\"\n[audit]\nenabled = true\n",
            "[canary]\nenabled = true\n",
            "[community_packs]\nenabled = [\"cp\"]\ndir = \"/cp\"\n",
        );
        let presence = TighteningPresence::from_toml(text).expect("presence parses");
        assert!(presence.thresholds_block_at && presence.thresholds_warn_at);
        assert!(presence.allow_list && presence.custom_blocks && presence.tool_rules);
        assert!(presence.disable && presence.disabled && presence.normalize && presence.level);
        assert!(presence.packs && presence.policy && presence.audit && presence.canary);
        assert!(
            presence.community_packs_enabled && presence.community_packs_dir,
            "community_packs sub-keys must be tracked individually"
        );
    }
}
