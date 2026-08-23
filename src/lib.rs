//! apohara-agentguard library crate.
//!
//! Public module surface for the CLI binary and integration tests.

pub mod adapters;
pub mod audit;
pub mod config;
pub mod contract;
pub mod firewall;
pub mod gate;
pub mod hook;
pub mod init;
pub mod mcp;
mod neutralize;
pub mod policy;
pub mod sandbox;
pub mod verdict;

/// Narrow public seam for the bin crate: route operator-facing verdict
/// reasons through the lib-private display-layer neutralization (the same
/// transform the MCP surface applies). See [`neutralize`].
pub use neutralize::neutralize_reason;

// ---- Corpus-overfit detector (Story T9, TEST-ONLY, informational) ----------
//
// LODO-inspired, adapted to deterministic rules: for EVERY registered
// destructive rule/pattern (gate taxonomy incl. all packs; firewall DJL +
// OWASP + two-stage), count how many DISTINCT corpora it fires on across the
// eval cases and the committed text corpora. A rule that fires on exactly ONE
// corpus and nowhere else is flagged as a potential overfit — a rule tuned to
// a single fixture is suspect.
//
// Placement note: the rule tables are `pub(crate)` behind private modules, so
// this must live INSIDE the crate (integration tests cannot reach them). The
// per-module registries are `gate::overfit_detector_rules` and
// `firewall::overfit_detector_patterns`, both `#[cfg(test)]`.
//
// This is a DETECTOR/REPORT, not a failure gate: only structural sanity is
// asserted (unique ids, non-empty tables, non-empty corpora).

/// Test-only match predicate for one registered rule/pattern (Story T9).
#[cfg(test)]
pub(crate) type OverfitMatcher = Box<dyn Fn(&str) -> bool>;

#[cfg(test)]
mod corpus_overfit_detector {
    use super::OverfitMatcher;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// One registered corpus: a stable name plus its parsed entries.
    struct Corpus {
        name: String,
        entries: Vec<String>,
    }

    /// One rule's measurement row.
    struct Row {
        id: &'static str,
        /// Distinct corpora with at least one firing entry.
        corpora_fired: BTreeSet<String>,
        /// Total entries fired on across ALL corpora.
        hits: usize,
    }

    /// Parse a corpus file into logical entries — same loader discipline as
    /// tests/benchmark.rs: skip blank lines and `#` comments; rejoin shell
    /// line-continuations (`\<newline>`) into one entry.
    fn parse_entries(raw: &str) -> Vec<String> {
        let mut entries = Vec::new();
        let mut pending: Option<String> = None;
        for line in raw.lines() {
            if let Some(mut acc) = pending.take() {
                acc.push('\n');
                acc.push_str(line);
                if ends_with_odd_backslash(line) {
                    pending = Some(acc);
                } else {
                    entries.push(acc);
                }
                continue;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if ends_with_odd_backslash(line) {
                pending = Some(line.to_string());
            } else {
                entries.push(line.to_string());
            }
        }
        if let Some(acc) = pending {
            entries.push(acc);
        }
        entries
    }

    fn ends_with_odd_backslash(line: &str) -> bool {
        line.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
    }

    fn repo_path(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    /// Load a single-file corpus. Structural sanity: every registered corpus
    /// must parse to at least one entry.
    fn load_file_corpus(rel: &str) -> Corpus {
        let path = repo_path(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("corpus {} unreadable: {e}", path.display()));
        let entries = parse_entries(&raw);
        assert!(
            !entries.is_empty(),
            "structural sanity: corpus {rel} parsed to zero entries"
        );
        Corpus {
            name: rel.to_string(),
            entries,
        }
    }

    /// Load every eval case under `cases_dir` (one corpus per case, from its
    /// `input.txt`). Structural sanity: the directory must exist and be
    /// non-empty.
    fn load_eval_corpora(cases_dir: &str) -> Vec<Corpus> {
        let dir = repo_path(cases_dir);
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("eval cases dir {} unreadable: {e}", dir.display()))
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert!(
            !names.is_empty(),
            "structural sanity: no eval cases found under {cases_dir}"
        );
        names
            .into_iter()
            .map(|case| load_file_corpus(&format!("{cases_dir}/{case}/input.txt")))
            .collect()
    }

    /// Every corpus the detector measures against: the gate eval cases, the
    /// firewall eval cases, and every top-level tests/corpus/*.txt (benign /
    /// dangerous / pack / ask / policy corpora).
    fn load_all_corpora() -> Vec<Corpus> {
        let mut corpora = Vec::new();
        corpora.extend(load_eval_corpora("evals/gate/cases"));
        corpora.extend(load_eval_corpora("evals/firewall/cases"));
        let corpus_dir = repo_path("tests/corpus");
        let mut txts: Vec<String> = std::fs::read_dir(&corpus_dir)
            .unwrap_or_else(|e| panic!("tests/corpus unreadable: {e}"))
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".txt"))
            .collect();
        txts.sort();
        assert!(
            !txts.is_empty(),
            "structural sanity: no *.txt corpora in tests/corpus"
        );
        for f in txts {
            corpora.push(load_file_corpus(&format!("tests/corpus/{f}")));
        }
        corpora
    }

    /// Measure one table against every corpus. Each rule is tested on every
    /// entry of every corpus via its exact match predicate (for gate rules,
    /// `overfit_rule_fires` mirrors post-split matching).
    fn measure(
        rules: Vec<(&'static str, OverfitMatcher)>,
        fire: impl Fn(&dyn Fn(&str) -> bool, &str) -> bool,
        corpora: &[Corpus],
    ) -> Vec<Row> {
        rules
            .into_iter()
            .map(|(id, matcher)| {
                let mut row = Row {
                    id,
                    corpora_fired: BTreeSet::new(),
                    hits: 0,
                };
                for corpus in corpora {
                    for entry in &corpus.entries {
                        if fire(&*matcher, entry) {
                            row.hits += 1;
                            row.corpora_fired.insert(corpus.name.clone());
                        }
                    }
                }
                row
            })
            .collect()
    }

    /// The detector itself: informational table to stdout + structural-sanity
    /// assertions ONLY. NOT a failure gate — a flag is a review hint, never a
    /// test failure.
    #[test]
    fn corpus_overfit_report() {
        let corpora = load_all_corpora();

        // ---- structural sanity -------------------------------------------------
        let gate_rules = crate::gate::overfit_detector_rules();
        let fw_patterns = crate::firewall::overfit_detector_patterns();
        assert!(
            !gate_rules.is_empty(),
            "structural sanity: gate rule table is empty"
        );
        assert!(
            !fw_patterns.is_empty(),
            "structural sanity: firewall pattern table is empty"
        );
        let mut all_ids: Vec<&str> = gate_rules
            .iter()
            .map(|(id, _)| *id)
            .chain(fw_patterns.iter().map(|(id, _)| *id))
            .collect();
        let unique_count = {
            all_ids.sort_unstable();
            all_ids.dedup();
            all_ids.len()
        };
        assert_eq!(
            unique_count,
            gate_rules.len() + fw_patterns.len(),
            "structural sanity: duplicate rule/pattern id detected"
        );

        // ---- measurement -------------------------------------------------------
        let mut rows = measure(gate_rules, crate::gate::overfit_rule_fires, &corpora);
        rows.extend(measure(fw_patterns, |m, e| m(e), &corpora));
        // Worst offenders first: fewest distinct corpora, then most hits within
        // that (a heavily-hit single-corpus rule is the strongest overfit hint),
        // then id for determinism.
        rows.sort_by(|x, y| {
            x.corpora_fired
                .len()
                .cmp(&y.corpora_fired.len())
                .then(y.hits.cmp(&x.hits))
                .then(x.id.cmp(y.id))
        });

        // ---- report (informational) --------------------------------------------
        println!();
        println!("== Corpus-overfit detector (informational, NOT a failure gate) ==");
        println!(
            "Measured {} rules/patterns against {} corpora.",
            rows.len(),
            corpora.len()
        );
        println!(
            "{:<36} {:>9} {:>8}  status",
            "rule/pattern id", "corpora", "hits"
        );
        for row in &rows {
            let status = match row.corpora_fired.len() {
                0 => "uncovered",
                1 => "OVERFIT?",
                _ => "ok",
            };
            println!(
                "{:<36} {:>9} {:>8}  {}",
                row.id,
                row.corpora_fired.len(),
                row.hits,
                status
            );
        }

        let suspects: Vec<&Row> = rows.iter().filter(|r| r.corpora_fired.len() == 1).collect();
        println!();
        println!(
            "Potential overfits (fire on exactly ONE corpus): {} of {} rules/patterns.",
            suspects.len(),
            rows.len()
        );
        for s in &suspects {
            let corpus = s.corpora_fired.iter().next().expect("exactly one");
            println!("  - {} fires only on {corpus} ({} hit(s))", s.id, s.hits);
        }
        println!();
    }
}
