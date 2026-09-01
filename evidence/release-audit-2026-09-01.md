# Release Provenance Audit — apohara-agentguard (2026-09-01)

**Audit date:** 2026-09-01
**Auditor:** Deepwork release-governance-evidence

---

## 1. Attestation Summary

| Release | SHA256SUMS | .intoto.jsonl | .sigstore.json | SBOM | Packs |
|---------|-----------|---------------|----------------|------|-------|
| v0.2.0 | ✅ 5 binaries | ❌ None | ❌ None | ❌ None | ❌ None |
| v0.3.0 | ✅ 7+2 files | ✅ 7 per-target | ❌ None | ❌ None | ❌ None |
| v0.4.0 | ✅ 7+2 files | ⚠️ 7 (wrong naming: `sha256.*.jsonl`) | ❌ None | ❌ None | ❌ None |
| v0.4.1 | ✅ 7+packs | ✅ 7 per-target | ❌ None | ❌ None | ✅ tar.gz |
| v0.5.1 | ✅ 14+packs+SBOM | ⚠️ **1 DUMMY** | ✅ 14 per-binary | ✅ 119KB | ✅ tar.gz |

---

## 2. Critical Finding: v0.5.1 Dummy Intoto Attestation

The single `apohara-agentguard-v0.5.1.intoto.jsonl` (245 bytes) is a **placeholder**:

```json
{"_type":"https://in-toto.io/Statement/v1",
 "predicateType":"https://slsa.dev/provenance/v1",
 "subject":[{"name":"dummy","digest":{"sha256":"abc"}}],
 "predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1"}}}
```

- Subject: `"name":"dummy","sha256":"abc"` — attests **nothing real**
- The per-target SLSA provenance from v0.3.0/v0.4.1 was **lost** in the v0.5.1 restructuring
- The workflow's `verify-attestations` job only checks "≥2 intoto bundles exist" — a dummy passes

**Impact:** Users relying on `.intoto.jsonl` for offline SLSA verification will find it useless.

---

## 3. Attestation Pipeline Evolution

| Version | Pipeline | Attestation Type |
|---------|----------|-----------------|
| v0.2.0 | None | SHA256 only |
| v0.3.0 | Inline provenance | 7 per-target `.intoto.jsonl` (real) |
| v0.4.0 | Broken naming | 7 `sha256.*.jsonl` (non-standard) |
| v0.4.1 | Fixed naming | 7 per-target `.intoto.jsonl` (real) |
| v0.5.1 | Isolated reusable workflow (`_attest.yml`) | 1 dummy intoto + 14 sigstore + SBOM |

---

## 4. Security Assessment

| Aspect | Status | Detail |
|--------|--------|--------|
| SHA256SUMS | ✅ All releases | Covers all shipped binaries |
| SLSA provenance (intoto) | ⚠️ Mixed | v0.3.0/v0.4.1: real. v0.4.0: wrong naming. v0.5.1: **dummy** |
| Sigstore per-binary | ✅ v0.5.1 only | 14 bundles, keyless OIDC |
| SLSA Build L3 | ✅ Current workflow | Isolated attest job, but dummy intoto undercuts it |
| CycloneDX SBOM | ✅ v0.5.1 only | 119KB from committed Cargo.lock |
| E2E verification gate | ⚠️ Too lenient | Checks count but not subject content |

---

## 5. Gaps and Recommendations

1. **Fix v0.5.1 dummy intoto** — Regenerate per-target `.intoto.jsonl` for next release
2. **v0.4.0 naming regression** — `sha256.*.jsonl` won't be picked up by Scorecard
3. **No sigstore for v0.3.0–v0.4.1** — Only latest release has per-binary cosign
4. **v0.2.0 completely unsigned** — No provenance whatsoever
5. **Verify gate too lenient** — Should check subject[].name matches real binaries

---

## 6. ECC PR #34 Investigation

**Finding:** Windows test cancelled due to GitHub Actions runner timeout (6h), NOT code issue.

- PR adds 11 config files (`.claude/`, `.codex/`, `.agents/`) — no Rust code changes
- 10/11 CI checks passed (including clippy, fmt, tests on Ubuntu/macOS, coverage, purity)
- Windows job hung during `cargo check` for exactly 6h (runner default timeout)
- **Recommendation:** Safe to merge. Re-trigger workflow for clean Windows run.

---

## 7. Verdict

| Check | Status |
|-------|--------|
| Provenance pipeline exists | ✅ Since v0.3.0 |
| Per-target attestation | ✅ v0.3.0/v0.4.1. ❌ v0.5.1 (dummy) |
| Per-binary Sigstore | ✅ v0.5.1 only |
| SBOM | ✅ v0.5.1 only |
| Scorecard compatibility | ⚠️ v0.4.0 naming breaks it |
| ECC #34 safe to merge | ✅ Config-only, CI flake |
