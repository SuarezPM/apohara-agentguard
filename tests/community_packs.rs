//! End-to-end tests for COMMUNITY packs (V5-A): the `*.toml` pack format, the
//! directory loader, and their wiring through `gate::evaluate` via
//! `[community_packs]`.
//!
//! Discipline mirrors `tests/benchmark_packs.rs`: each shipped example pack
//! runs with ONLY that pack enabled over its own `{benign,dangerous}_<pack>.txt`
//! corpus with ABSOLUTE gates — FP_block == 0 on benign, FN == 0 on dangerous.
//!
//! The env-var precedence (`AGENTGUARD_COMMUNITY_PACKS_DIR` > config dir) is
//! covered by unit tests in `src/gate/packs/community.rs`
//! (`resolve_dir_from_env`) — mutating process-global env here would race the
//! parallel test threads.

use std::path::{Path, PathBuf};

use apohara_agentguard::config::{CommunityPacksConfig, Config};
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::verdict::Tier;

/// The repo's shipped example-pack directory.
fn repo_pack_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packs-community")
}

/// A config with exactly the given community packs enabled against `dir`.
fn cfg_with(enabled: &[&str], dir: &Path) -> Config {
    Config {
        community_packs: CommunityPacksConfig {
            enabled: enabled.iter().map(|s| s.to_string()).collect(),
            dir: Some(dir.to_path_buf()),
        },
        ..Config::default()
    }
}

/// Parse a corpus file into logical commands: `#`-prefixed and blank lines are
/// ignored (same loader discipline as `tests/benchmark_packs.rs`).
fn parse_corpus(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Run one community pack's corpora and assert 0-FP / 0-FN through
/// `gate::evaluate` with ONLY that pack enabled.
fn assert_community_pack(pack: &str, benign_raw: &str, dangerous_raw: &str) {
    let cfg = cfg_with(&[pack], &repo_pack_dir());
    let benign = parse_corpus(benign_raw);
    let dangerous = parse_corpus(dangerous_raw);

    assert!(
        benign.len() >= 5,
        "[{pack}] benign corpus must have >= 5 commands, got {}",
        benign.len()
    );
    assert!(
        dangerous.len() >= 5,
        "[{pack}] dangerous corpus must have >= 5 commands, got {}",
        dangerous.len()
    );

    let fp: Vec<&String> = benign
        .iter()
        .filter(|c| evaluate(c, &cfg).tier == Tier::Block)
        .collect();
    let fn_: Vec<&String> = dangerous
        .iter()
        .filter(|c| evaluate(c, &cfg).tier != Tier::Block)
        .collect();

    assert_eq!(
        fp.len(),
        0,
        "[{pack}] GATE 1 FAILED: {} false positive(s) (benign that BLOCK): {fp:?}",
        fp.len()
    );
    assert_eq!(
        fn_.len(),
        0,
        "[{pack}] GATE 2 FAILED: {} false negative(s) (dangerous NOT blocked): {fn_:?}",
        fn_.len()
    );
}

// ---- Shipped example packs: load + fire + corpus gates ----------------------

#[test]
fn iac_terraform_pack_zero_fp_zero_fn() {
    assert_community_pack(
        "iac-terraform",
        include_str!("corpus/benign_iac-terraform.txt"),
        include_str!("corpus/dangerous_iac-terraform.txt"),
    );
}

#[test]
fn k8s_helm_pack_zero_fp_zero_fn() {
    assert_community_pack(
        "k8s-helm",
        include_str!("corpus/benign_k8s-helm.txt"),
        include_str!("corpus/dangerous_k8s-helm.txt"),
    );
}

#[test]
fn ml_pipeline_pack_zero_fp_zero_fn() {
    assert_community_pack(
        "ml-pipeline",
        include_str!("corpus/benign_ml-pipeline.txt"),
        include_str!("corpus/dangerous_ml-pipeline.txt"),
    );
}

#[test]
fn shipped_example_packs_load_and_fire_through_evaluate() {
    // One representative dangerous command per shipped pack must Block when
    // that pack is enabled — proving the loader → gate wiring end to end.
    let dir = repo_pack_dir();
    let cases: &[(&str, &str)] = &[
        ("iac-terraform", "terraform destroy -auto-approve"),
        ("k8s-helm", "kubectl delete namespace prod"),
        ("ml-pipeline", "huggingface-cli delete my-org/model"),
    ];
    for (pack, cmd) in cases {
        let cfg = cfg_with(&[pack], &dir);
        assert_eq!(
            evaluate(cmd, &cfg).tier,
            Tier::Block,
            "community pack {pack} enabled but `{cmd}` did not Block"
        );
    }
}

// ---- Off-by-default invariant -----------------------------------------------

#[test]
fn community_packs_off_by_default_allow_pack_targets() {
    // With NO community packs configured (the default), a pack-only destructive
    // command is NOT blocked — the surface is strictly opt-in.
    let cfg = Config::default();
    assert!(cfg.community_packs.enabled.is_empty());
    for cmd in [
        "terraform destroy",
        "kubectl delete namespace prod",
        "helm uninstall api",
        "huggingface-cli delete my-org/model",
    ] {
        assert_eq!(
            evaluate(cmd, &cfg).tier,
            Tier::Allow,
            "with community packs OFF, `{cmd}` must Allow (opt-in invariant)"
        );
    }
}

#[test]
fn empty_config_invariant_intact() {
    // An empty TOML parses to Config::default() (byte-identical invariant),
    // and the parsed default leaves every community target untouched.
    let cfg: Config = toml::from_str("").expect("parse empty");
    assert_eq!(cfg.community_packs, CommunityPacksConfig::default());
    assert_eq!(evaluate("terraform destroy", &cfg).tier, Tier::Allow);
}

// ---- Loader fail-closed behavior --------------------------------------------

/// Unique temp dir (pid + nanos), following the existing config-test pattern.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agentguard-community-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const GOOD_PACK_TOML: &str = r#"
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

/// Every malformed fixture: a TOML that must be REFUSED WHOLE, plus a probe
/// command only its rules would catch.
fn malformed_fixtures() -> Vec<(&'static str, &'static str, &'static str)> {
    // (file name, file content, probe command unique to the bad pack)
    vec![
        (
            "bad-schema.toml",
            r#"
schema_version = 2
[pack]
name = "bad-schema"
version = "1.0.0"
[[rules]]
id = "r"
pattern = "badpack-nuke-alpha"
severity = 9
category = "t"
"#,
            "badpack-nuke-alpha",
        ),
        (
            "bad-name.toml",
            r#"
schema_version = 1
[pack]
name = "Bad_Name"
version = "1.0.0"
[[rules]]
id = "r"
pattern = "badpack-nuke-beta"
severity = 9
category = "t"
"#,
            "badpack-nuke-beta",
        ),
        (
            "bad-severity.toml",
            r#"
schema_version = 1
[pack]
name = "bad-severity"
version = "1.0.0"
[[rules]]
id = "r"
pattern = "badpack-nuke-gamma"
severity = 10
category = "t"
"#,
            "badpack-nuke-gamma",
        ),
        (
            "bad-dup-ids.toml",
            r#"
schema_version = 1
[pack]
name = "bad-dup-ids"
version = "1.0.0"
[[rules]]
id = "same"
pattern = "badpack-nuke-delta"
severity = 9
category = "t"
[[rules]]
id = "same"
pattern = "unrelated"
severity = 9
category = "t"
"#,
            "badpack-nuke-delta",
        ),
        (
            "bad-empty-pattern.toml",
            r#"
schema_version = 1
[pack]
name = "bad-empty-pattern"
version = "1.0.0"
[[rules]]
id = "r"
pattern = ""
severity = 9
category = "t"
"#,
            "",
        ),
        (
            "bad-unknown-field.toml",
            r#"
schema_version = 1
[pack]
name = "bad-unknown-field"
version = "1.0.0"
[[rules]]
id = "r"
pattern = "badpack-nuke-epsilon"
severity = 9
category = "t"
severitiy = 9
"#,
            "badpack-nuke-epsilon",
        ),
        (
            "bad-ruleless.toml",
            r#"
schema_version = 1
[pack]
name = "bad-ruleless"
version = "1.0.0"
"#,
            "",
        ),
    ]
}

#[test]
fn malformed_packs_refused_whole_valid_pack_still_loads() {
    for (file_name, bad_toml, bad_probe) in malformed_fixtures() {
        let dir = temp_dir("malformed");
        std::fs::write(dir.join("good.toml"), GOOD_PACK_TOML).unwrap();
        std::fs::write(dir.join(file_name), bad_toml).unwrap();

        let cfg = cfg_with(&["good-pack", "bad"], &dir);
        // The valid sibling pack still loads and fires...
        assert_eq!(
            evaluate("good-pack-nuke everything", &cfg).tier,
            Tier::Block,
            "{file_name}: valid pack must still load alongside a malformed one"
        );
        // ...while NOTHING from the malformed pack loads (no half-load).
        if !bad_probe.is_empty() {
            assert_eq!(
                evaluate(bad_probe, &cfg).tier,
                Tier::Allow,
                "{file_name}: malformed pack must be refused WHOLE, yet its rule fired"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn missing_directory_is_silent_noop() {
    // Enabled names pointing at a nonexistent directory: no panic, no rules,
    // core gate unaffected (a stderr warning per missing name is emitted once).
    let cfg = cfg_with(&["ghost-pack"], Path::new("/nonexistent/agentguard-packs"));
    assert_eq!(evaluate("rm -rf ~", &cfg).tier, Tier::Block);
    assert_eq!(evaluate("terraform destroy", &cfg).tier, Tier::Allow);
}

#[test]
fn unknown_enabled_name_leaves_gate_unaffected() {
    // A typo'd enabled name warns (once, on stderr) but never errors and never
    // disturbs the rest of the gate or other valid packs.
    let cfg = cfg_with(&["iac-terraform", "ghost-pack"], &repo_pack_dir());
    assert_eq!(evaluate("terraform destroy", &cfg).tier, Tier::Block);
    assert_eq!(evaluate("git status", &cfg).tier, Tier::Allow);
}
