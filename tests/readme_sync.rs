//! Doc-sync regression net: the README "Now caught (v0.1.x)" / "Still out of
//! scope" lists must not drift ahead of the pinning reality in
//! `tests/gate_evasions.rs`. This is a REAL test (not `#[ignore]`d): a README
//! that claims an evasion is closed while `gate_evasions.rs` still pins it
//! Allow — or vice versa — fails the build.
//!
//! It is deliberately ROBUST to formatting: it works on lowercased substrings /
//! keywords and on the actual gate verdict, not on exact line text, so cosmetic
//! edits don't make it brittle. Each closed evasion is verified THREE ways:
//!   1. the README "Now caught" section names it (keyword present),
//!   2. `gate_evasions.rs` has a `*_blocks` pin for it (no `is_not_caught`),
//!   3. the LIVE gate actually Blocks the canonical sample.
//!
//! Each out-of-scope item is verified TWO ways: named in the "Still out of
//! scope" section, and NOT present in the "Now caught" section.

use apohara_agentguard::config::Config;
use apohara_agentguard::gate::evaluate;
use apohara_agentguard::verdict::Tier;

use std::fs;
use std::path::Path;

const README: &str = include_str!("../README.md");
const GATE_EVASIONS: &str = include_str!("gate_evasions.rs");

/// A closed evasion: a human-facing keyword that must appear in the README
/// "Now caught" section, a `gate_evasions.rs` substring proving it is Block-
/// pinned, and a canonical command the live gate must Block.
struct ClosedEvasion {
    /// Keyword(s) (lowercased) that must appear in the "Now caught" section.
    readme_keyword: &'static str,
    /// A snippet that must appear in gate_evasions.rs proving a Block pin.
    evasions_block_marker: &'static str,
    /// A canonical sample the live gate must Block.
    sample: &'static str,
}

/// The four v0.1.x normalization-closed evasions.
const CLOSED: &[ClosedEvasion] = &[
    ClosedEvasion {
        readme_keyword: "ansi-c",
        evasions_block_marker: "fn ansi_c_quoting_blocks",
        sample: r"$'\x72\x6d' -rf ~",
    },
    ClosedEvasion {
        readme_keyword: "command-substitution",
        evasions_block_marker: "fn cmdsubst_echo_verb_blocks",
        sample: "$(echo rm) -rf ~",
    },
    ClosedEvasion {
        readme_keyword: "ifs",
        evasions_block_marker: "fn ifs_reassignment_blocks",
        sample: "IFS=X; cmdXrmX-rfX~",
    },
    ClosedEvasion {
        readme_keyword: "line-continuation",
        evasions_block_marker: "fn backslash_line_continuation_blocks",
        sample: "r\\\nm -rf ~",
    },
];

/// Out-of-scope keywords that must appear in the "Still out of scope" section
/// and must NOT be presented as caught.
const OUT_OF_SCOPE: &[&str] = &[
    "nested",        // nested / chained encoders
    "here-document", // real here-document parsing
    "parameter expansion",
    "non-literal", // non-literal command substitutions ($(curl ...))
];

/// Lowercased slice of the README between two heading markers (by substring).
fn section<'a>(haystack: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let lower = haystack;
    let start = lower
        .find(start_marker)
        .unwrap_or_else(|| panic!("README missing section start marker: {start_marker:?}"));
    let after = &lower[start..];
    match after.find(end_marker) {
        Some(end) => &after[..end],
        None => after,
    }
}

#[test]
fn readme_now_caught_matches_gate_evasions_block_pins() {
    let readme_lower = README.to_lowercase();
    let now_caught = section(&readme_lower, "now caught (v0.1.x)", "still out of scope");

    for ev in CLOSED {
        // 1. README "Now caught" section names it.
        assert!(
            now_caught.contains(ev.readme_keyword),
            "README 'Now caught' section must mention `{}` (closed evasion); \
             keep README and gate_evasions.rs in sync",
            ev.readme_keyword
        );
        // 2. gate_evasions.rs pins it as Block (the `*_blocks` test exists) and
        //    does NOT still carry an `is_not_caught` gap pin for it.
        assert!(
            GATE_EVASIONS.contains(ev.evasions_block_marker),
            "gate_evasions.rs must contain the Block-pin `{}` for a closed evasion",
            ev.evasions_block_marker
        );
        // 3. The live gate actually Blocks the canonical sample — the README
        //    claim is backed by real behavior, not just by a comment.
        assert_eq!(
            evaluate(ev.sample, &Config::default()).tier,
            Tier::Block,
            "README claims `{}` is now caught, but the live gate did NOT Block `{:?}`",
            ev.readme_keyword,
            ev.sample
        );
    }
}

#[test]
fn readme_out_of_scope_items_are_listed_and_not_claimed_caught() {
    let readme_lower = README.to_lowercase();
    let now_caught = section(&readme_lower, "now caught (v0.1.x)", "still out of scope");
    let still_out = section(&readme_lower, "still out of scope", "## ");

    for kw in OUT_OF_SCOPE {
        assert!(
            still_out.contains(kw),
            "README 'Still out of scope' section must honestly list `{kw}`"
        );
        // Robustness: an out-of-scope item must not be presented in the same
        // "Now caught" claim list (the `non-literal` form is the dangerous one
        // to misclaim).
        assert!(
            !now_caught.contains(kw),
            "`{kw}` is out of scope but appears in the 'Now caught' section — drift"
        );
    }
}

#[test]
fn gate_evasions_has_no_stale_not_caught_pins_for_closed_forms() {
    // Belt-and-suspenders: if a future edit reintroduces an `is_not_caught`
    // (Allow-pin) for one of the four closed forms, this surfaces it.
    for ev in CLOSED {
        // The old gap-pin names ended in `_is_not_caught`; ensure none survive
        // for the closed forms by checking the Block-pin marker is the one
        // present (asserted above) AND there's no contradicting Allow assert for
        // the same sample wording. We rely on the canonical Block-pin existing.
        assert!(
            !GATE_EVASIONS.contains(&format!(
                "{}_is_not_caught",
                ev.evasions_block_marker
                    .trim_start_matches("fn ")
                    .trim_end_matches("_blocks")
            )),
            "a stale `_is_not_caught` pin survives for a closed evasion ({})",
            ev.readme_keyword
        );
    }
}

// ---------------------------------------------------------------------------
// Version sync across release manifests
// ---------------------------------------------------------------------------

/// Take the contents between a leading `"` and its closing `"`; panic loudly
/// otherwise (a changed file shape must fail the parse, not silently pass).
fn quoted(value: &str, what: &str) -> String {
    let rest = value
        .strip_prefix('"')
        .unwrap_or_else(|| panic!("{what}: expected a quoted value, got {value:?}"));
    match rest.find('"') {
        Some(end) => rest[..end].to_string(),
        None => panic!("{what}: unterminated quoted value {value:?}"),
    }
}

/// Extract `[package] version = "x.y.z"` from Cargo.toml text.
fn cargo_toml_package_version(raw: &str) -> String {
    let section = raw
        .split("[package]")
        .nth(1)
        .unwrap_or_else(|| panic!("Cargo.toml: missing [package] section"));
    // Confine the search to the [package] section (stop at the next table).
    let section = section
        .split_once("\n[")
        .map(|(head, _)| head)
        .unwrap_or(section);
    for line in section.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "version" {
                return quoted(value.trim(), "Cargo.toml [package] version");
            }
        }
    }
    panic!("Cargo.toml: no `version` key in [package] section")
}

/// Extract the top-level `"version": "x.y.z"` value from JSON text (first
/// occurrence; both manifests place it before any nested objects).
fn json_version_field(raw: &str) -> String {
    const KEY: &str = "\"version\"";
    let pos = raw
        .find(KEY)
        .unwrap_or_else(|| panic!("json manifest: missing {KEY} key"));
    let after_key = &raw[pos + KEY.len()..];
    let (_, after_colon) = after_key
        .split_once(':')
        .unwrap_or_else(|| panic!("json manifest: {KEY} without a value"));
    quoted(after_colon.trim_start(), "json manifest .version")
}

/// Extract the pinned default from `VERSION="${AGENTGUARD_VERSION:-x.y.z}"`.
/// Also accepts a plain `VERSION="x.y.z"` literal.
fn install_sh_default_version(raw: &str) -> String {
    let line = raw
        .lines()
        .map(str::trim_start)
        .find(|l| l.starts_with("VERSION="))
        .unwrap_or_else(|| panic!("install.sh: missing VERSION= assignment"));
    let value = quoted(
        line.trim_start_matches("VERSION=").trim_start(),
        "install.sh VERSION",
    );
    let default = match value.rsplit_once(":-") {
        Some((_, d)) => d,
        None => &value,
    };
    default.strip_suffix('}').unwrap_or(default).to_string()
}

/// Extract `const VERSION = "x.y.z";` from the npx launcher.
fn js_const_version(raw: &str) -> String {
    const MARKER: &str = "const VERSION";
    let pos = raw
        .find(MARKER)
        .unwrap_or_else(|| panic!("npx launcher: missing `{MARKER}`"));
    let after = &raw[pos + MARKER.len()..];
    let (_, after_eq) = after
        .split_once('=')
        .unwrap_or_else(|| panic!("npx launcher: `{MARKER}` without an assignment"));
    quoted(after_eq.trim_start(), "npx launcher VERSION")
}

#[test]
fn version_sync_across_manifests() {
    // Every user-facing release surface must carry ONE version. Drift here
    // ships installers/wrappers that download a different release than the
    // crate was published as. Plain fs + string parsing on purpose: no new
    // dependencies, and each parser panics if its file's shape changes.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| {
        fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
    };

    let cargo_toml = read("Cargo.toml");
    let marketplace = read(".claude-plugin/marketplace.json");
    let install_sh = read("packaging/install.sh");
    let pkg_json = read("packaging/npx-wrapper/package.json");
    let launcher_js = read("packaging/npx-wrapper/bin/apohara-agentguard.js");

    let cargo_version = cargo_toml_package_version(&cargo_toml);
    let marketplace_version = json_version_field(&marketplace);
    let install_version = install_sh_default_version(&install_sh);
    let pkg_version = json_version_field(&pkg_json);
    let js_version = js_const_version(&launcher_js);

    assert_eq!(
        cargo_version, marketplace_version,
        ".claude-plugin/marketplace.json version ({marketplace_version}) \
         drifted from Cargo.toml ({cargo_version})"
    );
    assert_eq!(
        cargo_version, install_version,
        "packaging/install.sh default VERSION ({install_version}) \
         drifted from Cargo.toml ({cargo_version})"
    );
    assert_eq!(
        cargo_version, pkg_version,
        "packaging/npx-wrapper/package.json version ({pkg_version}) \
         drifted from Cargo.toml ({cargo_version})"
    );
    assert_eq!(
        cargo_version, js_version,
        "packaging/npx-wrapper/bin/apohara-agentguard.js VERSION ({js_version}) \
         drifted from Cargo.toml ({cargo_version})"
    );

    println!("all five release manifests agree on v{cargo_version}");
}
