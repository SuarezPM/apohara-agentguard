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
    #[serde(default)]
    pub canary: CanaryConfig,
    /// Policy file evaluator settings (`[policy]`). Off by default (no policy
    /// file loaded). See [`PolicyConfig`].
    #[serde(default)]
    pub policy: PolicyConfig,
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
        }
    }
}

impl Config {
    /// Load config from `path` if given and existing; otherwise return defaults.
    pub fn load(path: Option<&Path>) -> Result<Config> {
        match path {
            Some(p) if p.exists() => {
                let text = fs::read_to_string(p)
                    .with_context(|| format!("reading config file {}", p.display()))?;
                let cfg: Config = toml::from_str(&text)
                    .with_context(|| format!("parsing config file {}", p.display()))?;
                Ok(cfg)
            }
            _ => Ok(Config::default()),
        }
    }

    /// Load from the first existing default location, else built-in defaults.
    ///
    /// Missing-vs-malformed split (fail-closed contract):
    /// - NO config file found in any default location ⇒ `Ok(Config::default())`
    ///   silently (the empty-config byte-identical invariant).
    /// - A file EXISTS but fails to read/parse/deserialize ⇒ `Err` with the
    ///   file path in the context and the offending key/field name in the
    ///   underlying error. Callers must surface it (see `main.rs`: loud
    ///   stderr diagnostic + exit 2), never discard a malformed config.
    ///
    /// Lookup order:
    /// 1. `./agentguard.toml` (project-local, highest priority)
    /// 2. `$XDG_CONFIG_HOME/agentguard/config.toml`
    ///    (falling back to `~/.config/agentguard/config.toml`)
    pub fn load_default_locations() -> Result<Config> {
        for candidate in default_config_paths() {
            if candidate.exists() {
                return Config::load(Some(&candidate));
            }
        }
        Ok(Config::default())
    }

    /// Whether `command` matches the allow-list (substring or `*`-glob).
    pub fn is_allowed(&self, command: &str) -> bool {
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
    pub fn is_component_disabled(&self, component: &str, env_disabled: &EnvDisable) -> bool {
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
}

/// The `AGENTGUARD_DISABLE` env var parsed into a disabled-component set.
///
/// Parsed from the HOOK PROCESS env only (see the anti-self-disarm note in
/// [`crate::hook`]). `1`/`true` (case-insensitive) means ALL components; any
/// other value is treated as a comma-separated list of component names. Unknown
/// tokens are kept verbatim (lowercased) and simply never match a real
/// component, so they are effectively ignored without being an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvDisable {
    /// All components disabled (`AGENTGUARD_DISABLE=1` / `true`).
    pub all: bool,
    /// Explicit component names (lowercased, trimmed).
    pub names: Vec<String>,
}

impl EnvDisable {
    /// Parse a raw `AGENTGUARD_DISABLE` value. An absent var maps to `None` at
    /// the call site; here `raw` is the present value.
    pub fn parse(raw: &str) -> Self {
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
fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("agentguard.toml")];

    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));

    if let Some(home) = config_home {
        paths.push(home.join("agentguard").join("config.toml"));
    }

    paths
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
}
