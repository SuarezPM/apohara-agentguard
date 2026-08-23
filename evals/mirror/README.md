# evals/mirror — Mirror paraphrase corpus (external-style benchmark #2)

Paraphrase stress-test for the prompt-injection **firewall** (`firewall::scan_content`,
default thresholds). Motivation: the documented weakness of any signature-based
detector is paraphrasing — see BENCHMARK.md §TensorTrust (external #1, 94.8% FN)
and the README evasion scorecard.

## What this corpus is

- `attacks.jsonl` — 30 prompt-injection attacks that KEEP the semantic intent of
  well-known attack patterns (the families covered by `evals/firewall/cases/`
  and the DJL/OWASP rule tables) but are LEXICALLY REWRITTEN: synonyms,
  syntactic restructuring, indirect framing, translation-flavored phrasing, and
  encoding-lite tricks (letter spacing, punctuation substitution, leetspeak,
  hyphen chaining) that a human attacker would plausibly type.
- `benign.jsonl` — 15 matched benign controls. Each mirrors the STRUCTURE of an
  attack class (same verbs, same near-miss vocabulary) while being unambiguously
  safe. These measure the false-positive cost of tightening against paraphrases.

## What this corpus is NOT

- Not part of the `tests/eval_harness.rs` characterization net (that harness
  walks only `evals/{gate,firewall,policy}/cases/*/`). Nothing here pins a
  verdict; the measured numbers ARE the result.
- Not read by the corpus-overfit detector (`src/lib.rs`, test-only), which scans
  `evals/{gate,firewall}/cases/*/input.txt` and `tests/corpus/*.txt` only.
- Not a red-team state-of-the-art set. Attacks are author-written paraphrases of
  PUBLIC canonical patterns — deliberately reproducible and dependency-free.

## Record schema

```json
{"id":"M-01","class":"instruction-override","text":"..."}
```

- `id`: stable, unique across BOTH files (`M-*` attacks, `B-*` benign).
- `class`: one of `instruction-override | exfiltration | role-hijack |
  prompt-extraction | guardrail-bypass | obfuscation-lite`.
- `text`: the raw content handed to `scan_content`.

## Runner

```sh
cargo test --test mirror_benchmark -- --nocapture
```

Structural sanity is asserted (corpus parses, counts intact, ids unique);
per-class FN rate (attacks not Blocked) and FP rate (benign flagged) are
printed as the publishable measurement. Results are transcribed to BENCHMARK.md
§"Mirror paraphrase benchmark (external #2)".

## Provenance

Author-written 2026-08 by the apohara-agentguard maintainers, derived from the
attack FAMILIES already covered by the committed firewall corpora (DJL rule
descriptions, OWASP ASI patterns, `evals/firewall/cases/`). No external dataset
is vendored; no real user content is included. License: same as the repository.
