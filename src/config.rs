//! TOML configuration: allow-list, custom blocks, severity thresholds.
//!
//! An absent config file means [`Config::default`] (built-in defaults). A
//! present file may be partial: every field carries `#[serde(default)]`, so an
//! empty TOML still parses to the defaults. [`Thresholds`] lives in
//! [`crate::verdict`] (single source of truth) and is re-exported here.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

pub use crate::audit::AuditConfig;
pub use crate::verdict::Thresholds;

/// A user-added block pattern with its severity and category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct CanaryConfig {
    /// Whether the canary feature is active. Default `false` (off).
    #[serde(default)]
    pub enabled: bool,
}

/// User-facing configuration that overrides built-in defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        // forward-compat field (packs/tool_rules/disabled/level/canary) at its
        // default — proving the empty-TOML invariant survives schema growth.
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
}
