//! Proves `examples/agentguard.toml` is not stale: it must parse against the
//! REAL `Config` (every key matching a real serde field). The shipped example
//! has all overrides commented out, so it parses to the defaults — but that
//! still exercises the `[audit]` section and every top-level key serde-wise.

use agentguard::config::Config;

#[test]
fn example_config_parses_to_a_valid_config() {
    let text = include_str!("../examples/agentguard.toml");
    let cfg: Config =
        toml::from_str(text).expect("examples/agentguard.toml must parse against the real Config");
    // The shipped example leaves every override commented out, so it equals the
    // built-in defaults. If someone uncomments an example with a typo'd key,
    // serde would reject it above; if they change a default's shape, this guards
    // it.
    assert_eq!(
        cfg,
        Config::default(),
        "the shipped example has all overrides commented out, so it must equal Config::default()"
    );
    // Audit is off + metadata-only by default (the [audit] section is present but
    // sets only the defaults).
    assert!(!cfg.audit.enabled);
    assert!(cfg.audit.path.is_none());
    assert!(!cfg.audit.include_command);
    assert!(cfg.normalize);
}

#[test]
fn example_config_with_overrides_uncommented_still_parses() {
    // A representative override of EVERY field, proving the documented keys are
    // the real serde field names (a typo here would fail to deserialize).
    let text = r#"
        allow_list = ["git status", "cargo *"]

        [[custom_blocks]]
        pattern = "shutdown"
        severity = 9
        category = "system"

        [thresholds]
        block_at = 8
        warn_at = 5

        disable = false
        normalize = true

        [audit]
        enabled = true
        path = "/tmp/agentguard-audit.jsonl"
        include_command = true
    "#;
    let cfg: Config =
        toml::from_str(text).expect("every documented key must be a real serde field");
    assert_eq!(cfg.allow_list.len(), 2);
    assert_eq!(cfg.custom_blocks.len(), 1);
    assert_eq!(cfg.custom_blocks[0].pattern, "shutdown");
    assert!(cfg.audit.enabled);
    assert!(cfg.audit.include_command);
    assert_eq!(
        cfg.audit
            .path
            .as_deref()
            .map(|p| p.to_string_lossy().into_owned()),
        Some("/tmp/agentguard-audit.jsonl".to_string())
    );
}
