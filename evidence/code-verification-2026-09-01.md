# Code Verification — apohara-agentguard (2026-09-01)

**Baseline:** `evidence/baseline-2026-09-01.md`
**Verification date:** 2026-09-01

---

## 1. T9 Rules Verification

### Rule Sources

| Source | Location | Count |
|--------|----------|-------|
| Gate taxonomy (hardcoded Rust) | `src/gate/taxonomy.rs:223` | 15 rules |
| DJL firewall (TOML) | `src/firewall/djl_rules.toml` | 78 rules |
| OWASP patterns (Rust) | `src/firewall/owasp.rs:50` | 24 patterns |
| Built-in packs (cloud/container/db) | `src/gate/packs/` | ~8 rules |
| **Total measured by detector** | | **125 rules/patterns** |

Community packs (45 rules across 4 files) are opt-in and NOT included in measurement.

### Corpus

- `tests/corpus/` — 20 .txt files (895 lines)
- `evals/gate/cases/` — 10 eval cases
- `evals/firewall/cases/` — 8 eval cases
- **Total corpora measured: 38**

### Single-Corpus (Overfit) Rules: 19

**Correction vs original estimate:** 19 rules, NOT 18. Split: **9 generalized** + **10 pack-scoped**.

#### Gate pack-scoped (10):
| Rule | Corpus | Hits |
|------|--------|------|
| `aws-delete` | dangerous_cloud.txt | 7 |
| `docker-rm-force` | dangerous_container.txt | 7 |
| `drop-database` | dangerous_db.txt | 6 |
| `chmod-777` | dangerous.txt | 4 |
| `chmod-recursive` | dangerous.txt | 4 |
| `chmod-recursive-777-root` | dangerous.txt | 4 |
| `az-delete` | dangerous_cloud.txt | 3 |
| `fork-bomb` | dangerous.txt | 3 |
| `gcloud-delete` | dangerous_cloud.txt | 3 |
| `aws-s3-rb-force` | dangerous_cloud.txt | 2 |

#### Firewall DJL generalized (7):
| Rule | Corpus | Hits |
|------|--------|------|
| `DJL-MIS-006` | policy_dangerous.txt | 5 |
| `DJL-PII-006` | benign_reverse-shell.txt | 3 |
| `DJL-MIS-008` | dangerous_reverse-shell.txt | 2 |
| `DJL-EXF-004` | exfil-directive-user-prompt-warns | 1 |
| `DJL-MIS-007` | dangerous.txt | 1 |
| `DJL-PI-010` | homoglyph-cluster-user-prompt-warns | 1 |
| `DJL-SQLI-002` | sql-injection-read-file-blocks | 1 |

#### Firewall OWASP (2):
| Rule | Corpus | Hits |
|------|--------|------|
| `asi05_etc_sensitive_path` | policy_dangerous.txt | 2 |
| `asi01_bypass_safety_guardrails` | guardrail-bypass-web-search-blocks | 1 |

### LODO Detector

- **Location:** `src/lib.rs:48` (`mod corpus_overfit_detector`)
- **Nature:** `#[cfg(test)]` only — informational report, NOT a failure gate
- **Test:** `corpus_overfit_report()` at `src/lib.rs:206`
- **Status:** All tests pass ✅

### Uncovered Rules
- ~63 DJL rules fire on zero corpora (expected — covers PII, SQLi, XSS, exfiltration, harm, policy without dedicated test fixtures)

---

## 2. CLI Neutralization Verification

### Neutralization Chain

| Function | Location | Purpose |
|----------|----------|---------|
| `neutralize()` | `src/neutralize.rs:68` | Core: 4 rules (bidi, role-line, pseudo-tags, fences) |
| `neutralize_reason()` | `src/neutralize.rs:105` | Public seam for binary crate |
| `display_reason()` | `src/main.rs:261` | Thin wrapper calling `neutralize_reason()` |

### CLI Commands — All Neutralized ✅

| Command | Lines | Tiers covered |
|---------|-------|---------------|
| `check` | `src/main.rs:322,326` | Warn, Block |
| `scan` | `src/main.rs:290,294` | Warn, Block |
| `ask` | `src/main.rs:397,401,406` | Warn, Block, Ask |

### Additional Neutralization Surfaces

- MCP proxy relay: `src/proxy/relay.rs:1036`
- MCP gate: `src/proxy/gate.rs:289`
- Hook harness: `src/hook/harness.rs:725` (test)

### Test Coverage: 26 tests ✅

**Unit tests (16):** `src/neutralize.rs:160-377` — bidi (3), role-line (7), pseudo-tags (3), fences (3), identity (2), combined (1)

**Integration tests (2):** `tests/check_cli.rs:212,247` — hostile content neutralization, identity passthrough

**Cross-module tests (8):** contract (2), hook/harness (1), proxy/gate (1), mcp (1), + 3 more

### Verdict

| Check | Status |
|-------|--------|
| T9 rules classified | ✅ 19 single-corpus (corrected from 18) |
| LODO detector functional | ✅ Informationary, not a gate |
| CLI neutralization | ✅ All 3 commands neutralize before printing |
| Neutralization tests | ✅ 26/26 pass |
| No regressions | ✅ 691 tests total, 0 failures |
