//! Community rule packs: user-supplied `*.toml` pack files loaded at RUNTIME
//! (V5-A), as opposed to the compiled-in in-tree packs ([`super`] cloud /
//! container / db).
//!
//! # Pack file format (schema_version 1)
//!
//! A community pack is a single `*.toml` file inside the community-packs
//! directory. Full grammar:
//!
//! ```toml
//! schema_version = 1              # REQUIRED, must be exactly 1
//!
//! [pack]
//! name = "my-org-infra"           # REQUIRED, kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$),
//!                                 # unique across all packs in the directory
//! version = "1.0.0"               # REQUIRED, free-form version string
//! description = "..."             # optional free-form text
//!
//! [[rules]]
//! id = "infra-terraform-destroy"  # REQUIRED, non-empty, unique WITHIN the pack
//! pattern = "terraform destroy"   # REQUIRED, non-empty; substring or `*`-glob
//! severity = 8                    # REQUIRED, 0..=9 (>= 8 blocks under the
//!                                 # default thresholds, see crate::verdict)
//! category = "iac"                # REQUIRED, free-form label for reporting
//! ```
//!
//! At least one `[[rules]]` table is required — a rule-less pack is an
//! authoring error and is refused, not silently loaded as a no-op.
//!
//! # Pattern semantics
//!
//! Patterns use the SAME matcher semantics as `custom_blocks`: a pattern with
//! no `*` is a SUBSTRING match; a pattern containing `*` splits on `*` and
//! every non-empty part must appear IN ORDER (an unanchored `*`-glob). Patterns
//! are deliberately NOT regexes: they come from untrusted files, so the
//! ReDoS-prone regex engine is kept out of the community surface. Matching is
//! case-sensitive and runs per resolved/decoded leg against the verb-aware
//! match text (see [`crate::gate::taxonomy::effective_match_text`]), exactly
//! like the built-in taxonomy and custom blocks.
//!
//! # Loader contract (fail-closed)
//!
//! - STRICT schema: `deny_unknown_fields` on every struct plus the explicit
//!   checks listed above. ANY malformed pack file ⇒ that pack is REFUSED
//!   WHOLE with a loud one-line stderr diagnostic naming file + reason — a
//!   malformed pack never half-loads (either the whole pack loads valid or
//!   nothing from it).
//! - Two files claiming the same `pack.name`: the LATER file (sorted path
//!   order) is refused with a diagnostic; ambiguity must be loud.
//! - Missing directory ⇒ empty set, SILENT (the whole surface is opt-in).
//! - An `enabled` name that matches no loaded pack ⇒ one stderr warning per
//!   missing name PER PROCESS (long-running consumers are not spammed).
//! - Resolution order for the directory:
//!   `AGENTGUARD_COMMUNITY_PACKS_DIR` env > `[community_packs].dir` > none.
//!
//! # Off-by-default invariant
//!
//! With `community_packs.enabled` empty (the default), [`active_rules`]
//! returns an empty vector WITHOUT touching the environment or the filesystem,
//! so the gate is byte-identical to the no-community-packs build.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;

use crate::config::CommunityPacksConfig;

/// Environment variable overriding `[community_packs].dir`.
const ENV_DIR_VAR: &str = "AGENTGUARD_COMMUNITY_PACKS_DIR";

/// The only supported pack-file `schema_version`.
const SCHEMA_VERSION: u32 = 1;

/// Upper bound of the documented severity scale (mirrors `config::MAX_SEVERITY`).
const MAX_SEVERITY: u8 = 9;

// ---- Loaded (runtime) types -------------------------------------------------

/// One community rule loaded from a pack file. Data-driven counterpart of
/// [`crate::gate::taxonomy::DestructiveRule`] (whose matcher is a compile-time
/// `fn` pointer and therefore cannot represent runtime-loaded patterns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommunityRule {
    /// Stable identifier (unique within its pack) for reporting.
    pub(crate) id: String,
    /// Substring or `*`-glob pattern (see module docs).
    pub(crate) pattern: String,
    /// Severity driving the verdict tier (see [`crate::verdict::Thresholds`]).
    pub(crate) severity: u8,
    /// Category label for reporting.
    pub(crate) category: String,
}

impl CommunityRule {
    /// True iff this rule's pattern matches `text` (substring / `*`-glob).
    pub(crate) fn matches(&self, text: &str) -> bool {
        pattern_matches(&self.pattern, text)
    }
}

/// A validated community pack: its declared name plus its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommunityPack {
    /// The `pack.name` declared in the file (kebab-case, dir-unique).
    pub(crate) name: String,
    /// The pack's rules, in file order.
    pub(crate) rules: Vec<CommunityRule>,
}

// ---- On-disk (serde) types --------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    schema_version: u32,
    pack: PackMeta,
    /// Absent `[[rules]]` maps to an empty vec here and is refused by the
    /// explicit validation below (with a clearer message than serde's
    /// "missing field").
    #[serde(default)]
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackMeta {
    name: String,
    /// Required by the schema (serde rejects a pack file without it), but not
    /// consumed at runtime yet — reserved for future reporting surfaces.
    #[allow(dead_code)]
    version: String,
    /// Optional free-form text; deserialized only so the schema accepts it
    /// cleanly under `deny_unknown_fields`.
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    id: String,
    pattern: String,
    severity: u8,
    category: String,
}

/// Parse + validate one pack file's text. The SINGLE gate for every structural
/// rule in the module docs; returns the loaded pack or a one-line reason.
fn parse_pack(text: &str) -> Result<CommunityPack, String> {
    let file: PackFile = toml::from_str(text).map_err(|e| e.to_string())?;
    if file.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {} (this build supports only {SCHEMA_VERSION})",
            file.schema_version
        ));
    }
    if !is_kebab_case(&file.pack.name) {
        return Err(format!(
            "pack.name {:?} is not kebab-case (lowercase a-z / 0-9 groups joined by single hyphens)",
            file.pack.name
        ));
    }
    if file.rules.is_empty() {
        return Err(
            "no [[rules]] defined — a pack without rules is an authoring error".to_string(),
        );
    }
    let mut rules: Vec<CommunityRule> = Vec::with_capacity(file.rules.len());
    for def in file.rules {
        if def.id.is_empty() {
            return Err("rules[].id must not be empty".to_string());
        }
        if def.pattern.is_empty() {
            return Err(format!(
                "rule {:?}: pattern must not be empty (it would match every command)",
                def.id
            ));
        }
        if def.severity > MAX_SEVERITY {
            return Err(format!(
                "rule {:?}: severity {} is out of range 0..={MAX_SEVERITY}",
                def.id, def.severity
            ));
        }
        if rules.iter().any(|r| r.id == def.id) {
            return Err(format!("duplicate rule id {:?}", def.id));
        }
        rules.push(CommunityRule {
            id: def.id,
            pattern: def.pattern,
            severity: def.severity,
            category: def.category,
        });
    }
    Ok(CommunityPack {
        name: file.pack.name,
        rules,
    })
}

/// Kebab-case check WITHOUT a regex dependency: non-empty, lowercase ASCII
/// alphanumeric groups separated by single hyphens, no leading/trailing
/// hyphen (`my-org-infra` ok; `My-Org`, `-x`, `x-`, `a--b`, `a_b` refused).
fn is_kebab_case(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut after_hyphen = true; // the first char must be alphanumeric
    for c in name.chars() {
        match c {
            'a'..='z' | '0'..='9' => after_hyphen = false,
            '-' => {
                if after_hyphen {
                    return false;
                }
                after_hyphen = true;
            }
            _ => return false,
        }
    }
    !after_hyphen
}

/// The shared substring / `*`-glob matcher for community rules AND custom
/// blocks (single semantic point — see the module docs). A pattern without `*`
/// is a substring match; with `*`, every non-empty `*`-separated part must
/// appear in order (unanchored).
pub(crate) fn pattern_matches(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return text.contains(pattern);
    }

    let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
    let mut cursor = 0usize;
    for part in parts {
        match text[cursor..].find(part) {
            Some(pos) => cursor += pos + part.len(),
            None => return false,
        }
    }
    true
}

// ---- Directory loading ------------------------------------------------------

/// Load every `*.toml` pack in `dir`. Returns the valid packs (sorted path
/// order) plus one-line refusal diagnostics for every malformed/colliding
/// file — the caller prints them to stderr. A MISSING directory yields an
/// empty result with no diagnostics (opt-in surface stays silent); a directory
/// that exists but cannot be read is diagnosed loudly instead.
pub(crate) fn load_dir(dir: &Path) -> (Vec<CommunityPack>, Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Opt-in surface: no directory configured/present ⇒ empty, silent.
            return (Vec::new(), Vec::new());
        }
        Err(e) => {
            return (
                Vec::new(),
                vec![format!(
                    "refusing community packs from {}: unreadable directory: {e}",
                    dir.display()
                )],
            );
        }
    };

    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort(); // deterministic load/refusal order
    let mut packs = Vec::new();
    let mut diags = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    for path in paths {
        if !path.is_file() || path.extension().is_none_or(|ext| ext != "toml") {
            continue; // only *.toml files are pack candidates
        }
        match std::fs::read_to_string(&path) {
            Err(e) => diags.push(format!(
                "refusing community pack {}: unreadable: {e}",
                path.display()
            )),
            Ok(text) => match parse_pack(&text) {
                Err(reason) => diags.push(format!(
                    "refusing community pack {}: {reason}",
                    path.display()
                )),
                Ok(pack) => {
                    if !seen_names.insert(pack.name.clone()) {
                        diags.push(format!(
                            "refusing community pack {}: duplicate pack name {:?} \
                             (already loaded from another file in this directory)",
                            path.display(),
                            pack.name
                        ));
                        continue;
                    }
                    packs.push(pack);
                }
            },
        }
    }
    (packs, diags)
}

/// Resolve the community-packs directory:
/// `AGENTGUARD_COMMUNITY_PACKS_DIR` env > `configured` (`[community_packs].dir`)
/// > `None`. An empty env value counts as unset (falls through to the config).
pub(crate) fn resolve_dir(configured: Option<&Path>) -> Option<PathBuf> {
    resolve_dir_from_env(std::env::var_os(ENV_DIR_VAR), configured)
}

/// Pure core of [`resolve_dir`] (env injected) so precedence is unit-testable
/// without mutating process-global state.
fn resolve_dir_from_env(env: Option<OsString>, configured: Option<&Path>) -> Option<PathBuf> {
    match env {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => configured.map(Path::to_path_buf),
    }
}

// ---- Warn-once bookkeeping --------------------------------------------------

/// Names already warned about in this process (one warning per missing name,
/// so a long-running consumer evaluating many commands is not spammed).
static WARNED_MISSING: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn warn_missing_pack_once(name: &str) {
    let warned = WARNED_MISSING.get_or_init(|| Mutex::new(HashSet::new()));
    let should_warn = warned
        .lock()
        .expect("warned-missing-names lock poisoned")
        .insert(name.to_string());
    if should_warn {
        eprintln!(
            "apohara-agentguard: community pack {name:?} is enabled in [community_packs] \
             but no pack file with that name was found in the community packs directory"
        );
    }
}

// ---- Gate entry point -------------------------------------------------------

/// The community rules ACTIVE for this evaluation: every rule of every loaded
/// pack whose name appears in `cfg.enabled`, in enabled-name order.
///
/// With `cfg.enabled` empty (the DEFAULT) this returns an empty vector without
/// touching the environment or the filesystem — the off-by-default invariant.
/// Diagnostics (malformed packs) and missing-name warnings go to stderr.
pub(crate) fn active_rules(cfg: &CommunityPacksConfig) -> Vec<CommunityRule> {
    if cfg.enabled.is_empty() {
        return Vec::new();
    }
    let Some(dir) = resolve_dir(cfg.dir.as_deref()) else {
        // Names enabled but nowhere to load from: every name is missing.
        for name in &cfg.enabled {
            warn_missing_pack_once(name);
        }
        return Vec::new();
    };
    let (packs, diags) = load_dir(&dir);
    for diag in &diags {
        eprintln!("apohara-agentguard: {diag}");
    }
    let mut rules = Vec::new();
    for name in &cfg.enabled {
        match packs.iter().find(|p| &p.name == name) {
            Some(pack) => rules.extend(pack.rules.iter().cloned()),
            None => warn_missing_pack_once(name),
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_pack: acceptance ----

    #[test]
    fn parses_minimal_valid_pack() {
        let text = r#"
            schema_version = 1
            [pack]
            name = "my-org-infra"
            version = "1.0.0"
            [[rules]]
            id = "infra-terraform-destroy"
            pattern = "terraform destroy"
            severity = 8
            category = "iac"
        "#;
        let pack = parse_pack(text).expect("valid pack must parse");
        assert_eq!(pack.name, "my-org-infra");
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rules[0].id, "infra-terraform-destroy");
        assert_eq!(pack.rules[0].severity, 8);
        assert_eq!(pack.rules[0].category, "iac");
    }

    #[test]
    fn description_is_optional() {
        let text = r#"
            schema_version = 1
            [pack]
            name = "bare"
            version = "0.1.0"
            [[rules]]
            id = "r"
            pattern = "boom"
            severity = 9
            category = "c"
        "#;
        assert!(parse_pack(text).is_ok());
    }

    // ---- parse_pack: refusals ----

    fn parse_err(text: &str) -> String {
        parse_pack(text).expect_err("must be refused")
    }

    #[test]
    fn refuses_wrong_schema_version() {
        let text = r#"
            schema_version = 2
            [pack]
            name = "x"
            version = "1.0.0"
            [[rules]]
            id = "r"
            pattern = "boom"
            severity = 8
            category = "c"
        "#;
        let err = parse_err(text);
        assert!(err.contains("schema_version") && err.contains('2'), "{err}");
    }

    #[test]
    fn refuses_non_kebab_case_names() {
        for bad in ["My-Org", "my_org", "-lead", "trail-", "double--hyphen", ""] {
            let text = format!(
                r#"
                schema_version = 1
                [pack]
                name = "{bad}"
                version = "1.0.0"
                [[rules]]
                id = "r"
                pattern = "boom"
                severity = 8
                category = "c"
            "#
            );
            let err = parse_err(&text);
            assert!(
                err.contains("kebab-case"),
                "name {bad:?} must be refused as non-kebab-case: {err}"
            );
        }
    }

    #[test]
    fn accepts_kebab_case_names() {
        for good in ["a", "iac-terraform", "my-org-infra-2", "k8s-helm"] {
            let text = format!(
                r#"
                schema_version = 1
                [pack]
                name = "{good}"
                version = "1.0.0"
                [[rules]]
                id = "r"
                pattern = "boom"
                severity = 8
                category = "c"
            "#
            );
            assert!(parse_pack(&text).is_ok(), "{good:?} must be accepted");
        }
    }

    #[test]
    fn refuses_ruleless_pack() {
        let text = r#"
            schema_version = 1
            [pack]
            name = "empty-pack"
            version = "1.0.0"
        "#;
        let err = parse_err(text);
        assert!(err.contains("no [[rules]]"), "{err}");
    }

    #[test]
    fn refuses_duplicate_rule_ids() {
        let text = r#"
            schema_version = 1
            [pack]
            name = "dup"
            version = "1.0.0"
            [[rules]]
            id = "same"
            pattern = "a"
            severity = 8
            category = "c"
            [[rules]]
            id = "same"
            pattern = "b"
            severity = 8
            category = "c"
        "#;
        let err = parse_err(text);
        assert!(err.contains("duplicate rule id"), "{err}");
    }

    #[test]
    fn refuses_out_of_range_severity() {
        let text = r#"
            schema_version = 1
            [pack]
            name = "sev"
            version = "1.0.0"
            [[rules]]
            id = "r"
            pattern = "boom"
            severity = 10
            category = "c"
        "#;
        let err = parse_err(text);
        assert!(err.contains("severity") && err.contains("10"), "{err}");
    }

    #[test]
    fn refuses_empty_pattern_and_empty_id() {
        let empty_pattern = r#"
            schema_version = 1
            [pack]
            name = "ep"
            version = "1.0.0"
            [[rules]]
            id = "r"
            pattern = ""
            severity = 8
            category = "c"
        "#;
        assert!(parse_err(empty_pattern).contains("pattern must not be empty"));

        let empty_id = r#"
            schema_version = 1
            [pack]
            name = "ei"
            version = "1.0.0"
            [[rules]]
            id = ""
            pattern = "boom"
            severity = 8
            category = "c"
        "#;
        assert!(parse_err(empty_id).contains("id must not be empty"));
    }

    #[test]
    fn refuses_unknown_fields_everywhere() {
        // Unknown key at the top level.
        let top = r#"
            schema_version = 1
            bogus = true
            [pack]
            name = "u1"
            version = "1.0.0"
            [[rules]]
            id = "r"
            pattern = "boom"
            severity = 8
            category = "c"
        "#;
        assert!(parse_pack(top).is_err());
        // Unknown key inside [pack].
        let meta = r#"
            schema_version = 1
            [pack]
            name = "u2"
            version = "1.0.0"
            typo = 1
            [[rules]]
            id = "r"
            pattern = "boom"
            severity = 8
            category = "c"
        "#;
        assert!(parse_pack(meta).is_err());
        // Unknown key inside [[rules]].
        let rule = r#"
            schema_version = 1
            [pack]
            name = "u3"
            version = "1.0.0"
            [[rules]]
            id = "r"
            pattern = "boom"
            severity = 8
            category = "c"
            severitiy = 8
        "#;
        assert!(parse_pack(rule).is_err());
    }

    #[test]
    fn refuses_missing_required_fields() {
        // Missing severity.
        let text = r#"
            schema_version = 1
            [pack]
            name = "m"
            version = "1.0.0"
            [[rules]]
            id = "r"
            pattern = "boom"
            category = "c"
        "#;
        assert!(parse_pack(text).is_err());
        // Missing [pack] entirely.
        let text = "schema_version = 1\n";
        assert!(parse_pack(text).is_err());
    }

    // ---- pattern_matches ----

    #[test]
    fn substring_semantics_without_star() {
        assert!(pattern_matches(
            "terraform destroy",
            "terraform destroy -auto-approve"
        ));
        assert!(!pattern_matches("terraform destroy", "terraform plan"));
    }

    #[test]
    fn glob_semantics_ordered_parts_unanchored() {
        assert!(pattern_matches(
            "kubectl delete *--all*",
            "kubectl delete pods --all"
        ));
        assert!(pattern_matches(
            "terraform apply *-auto-approve*",
            "terraform apply -var-file=prod.tfvars -auto-approve"
        ));
        // Parts must appear in ORDER.
        assert!(!pattern_matches("b*a", "ab"));
        // Missing part: no match.
        assert!(!pattern_matches(
            "kubectl delete *--all*",
            "kubectl get pods --all"
        ));
    }

    #[test]
    fn star_only_pattern_matches_everything() {
        assert!(pattern_matches("*", "anything at all"));
    }

    // ---- resolve_dir precedence ----

    #[test]
    fn env_wins_over_config_dir() {
        let resolved = resolve_dir_from_env(
            Some(OsString::from("/env/packs")),
            Some(Path::new("/cfg/packs")),
        );
        assert_eq!(resolved, Some(PathBuf::from("/env/packs")));
    }

    #[test]
    fn empty_env_counts_as_unset() {
        let resolved =
            resolve_dir_from_env(Some(OsString::from("")), Some(Path::new("/cfg/packs")));
        assert_eq!(resolved, Some(PathBuf::from("/cfg/packs")));
    }

    #[test]
    fn config_dir_used_when_env_absent() {
        let resolved = resolve_dir_from_env(None, Some(Path::new("/cfg/packs")));
        assert_eq!(resolved, Some(PathBuf::from("/cfg/packs")));
    }

    #[test]
    fn neither_env_nor_config_yields_none() {
        assert_eq!(resolve_dir_from_env(None, None), None);
    }

    // ---- load_dir ----

    /// Unique temp dir (pid + nanos), following the existing config-test pattern.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentguard-community-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const GOOD_PACK: &str = r#"
        schema_version = 1
        [pack]
        name = "good-pack"
        version = "1.0.0"
        [[rules]]
        id = "good-nuke"
        pattern = "good-pack-nuke"
        severity = 9
        category = "test"
    "#;

    #[test]
    fn missing_dir_is_silent_empty() {
        let (packs, diags) = load_dir(Path::new("/nonexistent/agentguard-packs-xyz"));
        assert!(packs.is_empty());
        assert!(diags.is_empty(), "missing dir must stay silent: {diags:?}");
    }

    #[test]
    fn loads_valid_pack_and_skips_non_toml_files() {
        let dir = temp_dir("valid");
        std::fs::write(dir.join("good.toml"), GOOD_PACK).unwrap();
        std::fs::write(dir.join("notes.txt"), "not a pack").unwrap();
        std::fs::write(dir.join("README.md"), "also not a pack").unwrap();
        let (packs, diags) = load_dir(&dir);
        assert!(diags.is_empty(), "{diags:?}");
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].name, "good-pack");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_pack_refused_whole_with_named_diagnostic() {
        let dir = temp_dir("malformed");
        std::fs::write(dir.join("good.toml"), GOOD_PACK).unwrap();
        std::fs::write(
            dir.join("bad.toml"),
            r#"
            schema_version = 1
            [pack]
            name = "bad-pack"
            version = "1.0.0"
            [[rules]]
            id = "r1"
            pattern = "ok"
            severity = 8
            category = "c"
            [[rules]]
            id = "r1"
            pattern = "dup"
            severity = 8
            category = "c"
        "#,
        )
        .unwrap();
        let (packs, diags) = load_dir(&dir);
        assert_eq!(packs.len(), 1, "only the valid pack loads");
        assert_eq!(packs[0].name, "good-pack");
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0].contains("bad.toml") && diags[0].contains("duplicate rule id"),
            "diagnostic must name file + reason: {}",
            diags[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_pack_name_across_files_refuses_later_file() {
        let dir = temp_dir("collision");
        // Sorted order: a-first.toml < z-second.toml.
        std::fs::write(dir.join("a-first.toml"), GOOD_PACK).unwrap();
        std::fs::write(
            dir.join("z-second.toml"),
            r#"
            schema_version = 1
            [pack]
            name = "good-pack"
            version = "2.0.0"
            [[rules]]
            id = "other"
            pattern = "other"
            severity = 8
            category = "c"
        "#,
        )
        .unwrap();
        let (packs, diags) = load_dir(&dir);
        assert_eq!(packs.len(), 1, "first file wins, later duplicate refused");
        assert_eq!(packs[0].name, "good-pack");
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0].contains("z-second.toml") && diags[0].contains("duplicate pack name"),
            "{}",
            diags[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- active_rules ----

    #[test]
    fn disabled_config_touches_nothing_and_returns_empty() {
        let cfg = CommunityPacksConfig::default();
        assert!(cfg.enabled.is_empty());
        // No dir set, no env guaranteed: must still return empty without IO.
        assert!(active_rules(&cfg).is_empty());
    }

    #[test]
    fn enabled_rules_pull_their_packs_rules_in_order() {
        let dir = temp_dir("active");
        std::fs::write(dir.join("good.toml"), GOOD_PACK).unwrap();
        let cfg = CommunityPacksConfig {
            enabled: vec!["good-pack".to_string()],
            dir: Some(dir.clone()),
        };
        let rules = active_rules(&cfg);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "good-nuke");
        assert!(rules[0].matches("echo good-pack-nuke now"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
