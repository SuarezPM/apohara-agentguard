# OpenSSF Best Practices — Passing + Silver criteria evidence

Project: **apohara-agentguard** · badge entry **registration in progress**
(replace `PROJECT_ID` once the project is registered at
<https://www.bestpractices.dev/>).

This maps every **Passing** and **Silver** criterion
([bestpractices.dev/en/criteria/0](https://www.bestpractices.dev/en/criteria/0),
[criteria/1](https://www.bestpractices.dev/en/criteria/1)) to its status and the
exact evidence, so both questionnaires can be answered quickly. Status is honest:
**Met**, **N/A** (with justification), **Justified unmet** (a SHOULD/SUGGESTED we
consciously do not meet), or **Human action** (something only the maintainer can
do — completing the web form, holding off-site recovery keys). Silver requires the
**Passing** badge first.

> **Coverage figure** referenced below: **≈89.7% line coverage** (89.67% lines /
> 88.89% regions / 90.85% functions), measured with `cargo llvm-cov
> --summary-only` (default suite). Honest note: the main uncovered areas are the
> seccomp + Landlock sandbox runner/Landlock paths and the CLI `main.rs` dispatch
> — the sandbox kernel-capability tests need an unprivileged user namespace +
> Landlock and run as a non-blocking CI step. ≥80% is comfortably met. Re-run to
> refresh.

> **What makes this project's mapping different from its siblings:** unlike the
> purely-offline sibling tools, apohara-agentguard **does** open a network
> connection — the firewall's SSRF-guarded, out-of-band re-fetch of web content a
> tool is about to act on, over HTTPS (`ureq` + rustls). The whole `crypto_*` /
> TLS family is therefore **Met, not N/A** (see *Security* below). The project
> also **exceeds** the siblings on two analysis criteria: `dynamic_analysis` is
> **Met** (a `cargo-fuzz` target drives `gate::evaluate`), and `signed_releases`
> is **Met at SLSA Build L3** (isolated reusable attestation workflow), not merely
> L2.

---

## Passing — readiness

The repository satisfies the Passing criteria; completing the form is the only
remaining step. Highlights (the full Silver table below subsumes the rest):

| Criterion | Status | Evidence |
|---|---|---|
| `description_good`, `interact`, `contribution`, `contribution_requirements` | Met | `README.md`, GitHub Issues/PRs, `CONTRIBUTING.md`. |
| `floss_license`, `license_location` | Met | MIT OR Apache-2.0. A top-level [`LICENSE`](../LICENSE) file (the standard location the BadgeApp scanner recognizes) declares the dual license and points to the full texts in `LICENSE-MIT` + `LICENSE-APACHE` (Rust convention). |
| `documentation_basics`, `documentation_interface` | Met | `README.md` (Quick Start, Features, How it works) + the subcommand reference (`check`/`sandbox`/`scan`/`hook`/`mcp`). |
| `repo_public`, `repo_track`, `repo_distributed` | Met | Public Git on GitHub; full history; standard Git. |
| `version_unique`, `version_semver`, `version_tags` | Met | SemVer; `vX.Y.Z` tags (`v0.1.0`, `v0.2.0`); `CHANGELOG.md`. |
| `report_tracker`, `report_process`, `report_responses` | Met | GitHub Issues; `CONTRIBUTING.md`; maintainer triage. |
| `vulnerability_report_process`, `vulnerability_report_private` | Met | `SECURITY.md` (private GitHub Security Advisories). |
| `build`, `build_common_tools`, `build_floss_tools` | Met | `cargo build` with the FLOSS Rust toolchain. |
| `test`, `test_invocation`, `test_continuous_integration` | Met | `cargo test`; CI on every push/PR (`.github/workflows/ci.yml`), across Linux/macOS/Windows. |
| `warnings`, `warnings_fixed` | Met | `clippy -D warnings` + `cargo fmt --check` in CI. |
| `static_analysis` | Met | `clippy` + `cargo-deny` (licenses + advisories) + CodeQL + OpenSSF Scorecard. |
| `crypto_*` | Met | The firewall's out-of-band re-fetch uses HTTPS (`ureq` + rustls) with cert verification on; SHA-256 for the canary token; keyless release signing (see *Security* below). |
| `release_notes` | Met | `CHANGELOG.md` (Keep a Changelog). |
| `installation_common` | Met | `cargo install apohara-agentguard` (crates.io), `npx apohara-agentguard`, or the GitHub Release binaries. |

| Criterion | Status | Evidence |
|---|---|---|
| `achieve_passing` (Silver prerequisite) | **Human action** | Complete the Passing questionnaire on bestpractices.dev. The repo satisfies it (FLOSS MIT/Apache, public Git, SemVer tags, build+test CI, `SECURITY.md`, signed releases, static analysis). |

---

## Silver

### Basics
| Criterion | Status | Evidence |
|---|---|---|
| `contribution_requirements` | Met | `CONTRIBUTING.md` — quality gate + coding standards + testing policy + acceptable-contribution requirements. |
| `bus_factor` (SHOULD) | Justified unmet | Single maintainer today; `GOVERNANCE.md` documents continuity and an open invitation to co-maintainers. SHOULD, not MUST. |
| `access_continuity` | Met (+ human follow-through) | `GOVERNANCE.md` § Access continuity: credential custody + off-site break-glass recovery + keyless releases + fork-ability + reproducible-from-source. Human half: keep off-site recovery copies with a trusted party. |
| `roles_responsibilities` | Met | `GOVERNANCE.md` § Roles and responsibilities (table). |
| `code_of_conduct` | Met | `CODE_OF_CONDUCT.md` (Contributor Covenant 3.0). |
| `governance` | Met | `GOVERNANCE.md` § Governance model. |
| `dco` (SHOULD) | Met | `CONTRIBUTING.md` § Developer Certificate of Origin (`git commit -s`). |
| `documentation_roadmap` | Met | `README.md` § Roadmap. |
| `documentation_architecture` | Met | `ARCHITECTURE.md` (request flow, verdict model, gate pipeline, sandbox order) + `README.md` § Repository layout; `docs/ASSURANCE.md` (trust boundaries). |
| `documentation_security` | Met | `SECURITY.md` (threat model) + `docs/ASSURANCE.md` (assurance case). |
| `documentation_quick_start` | Met | `README.md` § Quick Start. |
| `documentation_current` | Met | Docs are versioned with the code and updated in the same change (the `tests/readme_sync.rs` test fails the build if the README evasion lists drift from reality); `CHANGELOG.md` per release; `cargo doc` is kept warning-free. |
| `documentation_achievements` | Met (pending id) | `README.md` badge block links the OpenSSF Best Practices badge; the numeric `PROJECT_ID` is filled in once registration completes (currently a "registration pending" placeholder badge). |
| `accessibility_best_practices` (SHOULD) | Met | Plain-Markdown docs (semantic headings, no custom widgets) and a plain-text CLI / stdio interface; no GUI to make inaccessible. |
| `internationalization` (SHOULD) | N/A | The CLI/hook/MCP server emits no localized end-user text and does no human-language-specific sorting. |
| `sites_password_security` | N/A | The project operates no website and stores no user passwords (no auth server). |

### Change Control
| Criterion | Status | Evidence |
|---|---|---|
| `maintenance_or_update` | Met | SemVer + `CHANGELOG.md`; the empty-config default is kept byte-identical across versions, and new behavior is opt-in (packs, canary, severity presets), so an existing config keeps working across upgrades. |

### Reporting
| Criterion | Status | Evidence |
|---|---|---|
| `report_tracker` | Met | GitHub Issues. |
| `vulnerability_response_process` | Met | `SECURITY.md` — private GitHub Security Advisories, **5-business-day acknowledgement** commitment, coordinated disclosure, and a fix or documented won't-fix once the issue is understood. |
| `vulnerability_report_credit` | N/A | No vulnerabilities resolved in the last 12 months. |

### Quality
| Criterion | Status | Evidence |
|---|---|---|
| `coding_standards` | Met | `CONTRIBUTING.md` § Coding standards (rustfmt + clippy). |
| `coding_standards_enforced` | Met | CI runs `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` (`.github/workflows/ci.yml`). |
| `build_repeatable` | Met (justified) | `Cargo.lock` pins every dependency and `rust-toolchain.toml` pins the channel, so a build is deterministic **given an identical toolchain version**. Full bit-for-bit reproducibility across compiler versions is **not** guaranteed (standard for Rust release builds: embedded paths, codegen across patch releases); the channel is rolling `stable`. OpenSSF permits this as a justified partial. |
| `build_non_recursive` | N/A | Cargo build; no recursive Make with cross-dependencies. |
| `build_preserve_debug` (SHOULD) | Met | Cargo honors profile debug settings; the release profile's `strip = true` is the project's deliberate hardening choice for the shipped binary, not a removal of debug info a consumer requested. |
| `build_standard_variables` | Met | Cargo honors `RUSTFLAGS`; the project has no bundled C dependency in the default build, so there is no `CFLAGS` surface to mishandle. |
| `installation_development_quick` | Met | `cargo build` / `cargo test` set up the full dev + test environment (`CONTRIBUTING.md`). |
| `installation_standard_variables` | N/A | Distributed via `cargo install` / prebuilt Release binaries / `npx`; no POSIX `DESTDIR`-style installer. |
| `installation_common` | Met | `cargo install apohara-agentguard`, `npx apohara-agentguard`, or the GitHub Release binaries. |
| `interfaces_current` | Met | Dependencies tracked by `cargo-deny`; no deprecated/obsolete APIs where FLOSS alternatives exist. |
| `external_dependencies` | Met | External dependencies are listed in a computer-processable form: `Cargo.toml` + the fully-resolved `Cargo.lock`; `cargo metadata` emits the complete graph as JSON. |
| `dependency_monitoring` | Met | `cargo deny check advisories` (RUSTSEC) **and** `cargo deny check licenses` run in CI on every push/PR (`.github/workflows/ci.yml`); Dependabot opens update PRs weekly (`.github/dependabot.yml`). `deny.toml` enforces a crates.io-only source policy. |
| `updateable_reused_components` | Met | All reused components are standard crates.io crates pinned in `Cargo.lock`, updatable with `cargo update`; nothing is vendored or forked. |
| `test_statement_coverage80` | **Met** | ≈89.7% line coverage (89.67% lines / 88.89% regions / 90.85% functions) measured with `cargo llvm-cov --summary-only` (reproducible locally; the criterion does not require it as a CI gate). |
| `regression_tests_added50` | Met | Bug fixes ship with regression tests added to the suite (e.g. the canary/firewall echo-test isolation fix, the parallel env-var kill-switch race fix, the POSIX pathsafe Windows gating); the `tests/gate_evasions.rs` honesty net pins every closed/open evasion. |
| `automated_integration_testing` | Met | `cargo test` (+ `cargo test --benches`) runs on every push/PR across Linux/macOS/Windows (`.github/workflows/ci.yml`) and reports pass/fail. |
| `tests_documented_added` | Met | `CONTRIBUTING.md` § Testing policy (new functionality must add tests; the honesty rule mandates pinning behavior changes). |
| `test_policy_mandated` | Met | `CONTRIBUTING.md` § Testing policy (written, mandatory). |
| `warnings_strict` | Met | `clippy -D warnings` (no warning tolerated; `RUSTFLAGS: "-D warnings"` in CI). |

### Security
| Criterion | Status | Evidence |
|---|---|---|
| `implement_secure_design` | Met | `docs/ASSURANCE.md` § 3 (secure-design principles: deterministic/offline, fail-toward-safety by component, least surface, bounded-by-construction, audited narrow `unsafe`, anti-self-disarm). |
| `input_validation` | Met | `docs/ASSURANCE.md` § 4: untrusted Bash is parsed **structurally** with a bounded normalize pre-pass (64 KiB / ≤64 splices / 4× cap — no parse-by-crash); the firewall uses a **ReDoS-guarded linear `RegexSet`** (no nested quantifiers, benched sub-ms); the path-guard validates named paths; malformed hook JSON fails open, never crashes. |
| `crypto_used_network` (SHOULD) | Met | The firewall's out-of-band re-fetch uses **HTTPS only** (`ureq` + rustls); no FTP/telnet/plaintext-HTTP/SSLv3 transport anywhere (`src/firewall/refetch.rs`). |
| `crypto_certificate_verification` | Met | `ureq` is built with rustls (`features = ["tls"]`); rustls certificate verification is on by default and is **never disabled** anywhere in the tree. |
| `crypto_tls12` (SHOULD) | Met | rustls negotiates **TLS 1.2+** (no SSLv3/TLS<1.2). |
| `crypto_verification_private` | Met | Certificate verification happens before any byte of a re-fetched body is read; there is no insecure/"accept-invalid-certs" path. |
| `crypto_weaknesses` | Met | The only hash in the tree is **SHA-256** (`sha2`), used for the non-secret canary token (`src/hook/canary.rs`); no MD5, SHA-1, or weak/CBC cipher is used. |
| `crypto_credential_agility` | N/A | The tool stores no user credentials/passwords and runs no auth server; the only "credential" is the keyless OIDC release-signing identity, which has nothing to store or rotate. |
| `crypto_algorithm_agility` (SHOULD) | N/A | There is no negotiated cryptographic protocol of the project's own to make algorithm-agile; TLS algorithm selection is rustls', and the canary's SHA-256 is a fixed, non-security hash. |
| `assurance_case` | Met | `docs/ASSURANCE.md` (security requirements + threat model + trust boundaries + secure-design + countered weaknesses incl. input-validation/crypto/dependency-hygiene/static-analysis + residual risk + evidence index). |
| `hardening` (SHOULD) | Met | Memory-safe Rust; the sandbox **adds** seccomp + Landlock confinement; release profile (`lto` + `strip`); the only shipped `unsafe` is the narrow, audited Linux sandbox FFI/syscall surface (`src/sandbox/linux/runner.rs`) — documented in `docs/ASSURANCE.md` § 3. |
| `version_tags_signed` (SUGGESTED) | Justified unmet | Git tags are not GPG-signed, but **release artifacts carry SLSA Build L3 provenance** (Sigstore keyless), verifiable with `gh attestation verify`. Signing tags is a possible future addition. |
| `signed_releases` | Met (SLSA Build L3) | Release binaries are signed via **SLSA v1.0 Build Level 3** provenance (Sigstore keyless — no on-site signing key), generated by an **isolated reusable workflow** (`.github/workflows/_attest.yml`) the build jobs cannot influence; verified end-to-end with `gh attestation verify --signer-workflow …` (the wrong signer is rejected). Documented in `SECURITY.md` + `README.md`. |

### Analysis
| Criterion | Status | Evidence |
|---|---|---|
| `static_analysis_common_vulnerabilities` | Met | `clippy` + `cargo-deny` (licenses + advisories) + a **CodeQL** workflow (Rust SAST, `.github/workflows/codeql.yml`) in CI, plus an OpenSSF Scorecard workflow. |
| `dynamic_analysis` (SUGGESTED) | **Met** | A **`cargo-fuzz`** target (`fuzz/fuzz_targets/gate_evaluate.rs`) drives arbitrary bytes through the live pipeline (`normalize → split → gate::evaluate`), enforcing a never-panic invariant and a conservative "a constructed `rm -rf` leg is never Allowed" invariant. A ReDoS bench (`benches/regex_redos.rs`) additionally guards pathological firewall inputs. |
| `dynamic_analysis_unsafe` (SHOULD) | Met | The fuzz target above exercises the gate's parsing on adversarial input; the only shipped `unsafe` is the Linux sandbox FFI/syscall surface (`src/sandbox/linux/runner.rs`), which is covered by the seccomp/Landlock/build-e2e runtime tests (`tests/sandbox_*.rs`) — it is thin C-ABI/syscall glue, not pointer arithmetic on attacker data. |

---

## Summary

Every Silver criterion is **Met** or justifiably **N/A**, except the items that
require a human — (1) completing the **Passing** then **Silver** questionnaires on
bestpractices.dev (and filling in the badge `PROJECT_ID`), and (2) the **off-site
custody** half of the access-continuity plan — and two honestly-documented
**SHOULD/SUGGESTED** gaps: `bus_factor` (single maintainer, continuity
documented) and `version_tags_signed` (artifacts carry SLSA L3 provenance
instead). Relative to its siblings this project additionally reaches **Met** on
the full `crypto_*`/TLS family (it really does open an HTTPS connection),
`dynamic_analysis` (cargo-fuzz), and `signed_releases` at **SLSA Build L3**. No
criterion is marked Met that is not genuinely satisfied.
