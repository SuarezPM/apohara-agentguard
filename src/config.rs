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
    /// Kill-switch: when true, agentguard emits Allow and gets out of the way.
    #[serde(default)]
    pub disable: bool,
    /// Whether the in-place normalization pre-pass (ANSI-C / echo-substitution /
    /// IFS / line-continuation evasion-closing) runs. Default `true`; set
    /// `normalize = false` to emergency-disable the pre-pass if a field false
    /// positive surfaces, without disabling the rest of the gate.
    #[serde(default = "default_true")]
    pub normalize: bool,
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
