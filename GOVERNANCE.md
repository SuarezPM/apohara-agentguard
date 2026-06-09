# Governance

This document describes how **apohara-agentguard** is governed: how decisions are
made, who holds which roles, and how the project continues if the maintainer
becomes unavailable. It is intentionally lightweight and honest about the
project's current size (a single maintainer with outside contributors welcome).

## Governance model

apohara-agentguard follows a **single-maintainer (BDFL-style) model** with open,
consensus-seeking discussion:

- **Proposals and decisions happen in the open.** Features, changes, and bug
  reports are discussed in GitHub [Issues](https://github.com/SuarezPM/apohara-agentguard/issues)
  and [Pull Requests](https://github.com/SuarezPM/apohara-agentguard/pulls). Anyone may
  open an issue or PR.
- **The maintainer is the final decision-maker** on what is merged and released,
  but seeks consensus with contributors and prefers the least-surprising,
  best-justified option. Disagreements are resolved by discussion in the relevant
  issue/PR; the maintainer's decision is final if consensus is not reached.
- **Non-negotiable design principles** constrain every decision; a change that
  weakens them is rejected on principle:
  - **Deterministic, offline, zero-model at scan time.** The gate and firewall
    detection logic make **no network call, use no model, and need no API key**
    at scan time. Same input ⇒ same verdict ⇒ same bytes out — auditable and
    reproducible. The *only* network the tool ever opens is the firewall's
    SSRF-guarded, out-of-band re-fetch of content a web tool is about to act on,
    over HTTPS (`ureq` + rustls) — never to a model or telemetry endpoint.
  - **Fail-closed, honestly.** The seccomp + Landlock sandbox **refuses to run**
    rather than run unconfined on a kernel that cannot enforce it; a fetch
    error/timeout fails closed to Warn; malformed hook input fails *open* (allow)
    so a schema surprise can never brick the user's tools. Each posture is the
    documented, deliberate choice — not an accident.
  - **Honesty over hype.** Precision is **measured, not asserted**: a committed
    CI gate asserts `0` false positives and `0` false negatives on the curated
    corpus (`tests/benchmark.rs`), the README publishes an evasion scorecard
    naming exactly what is still out of scope, and the **external** Tensor Trust
    human-attack benchmark is published with its honest 94.8% firewall
    false-negative rate — see [`BENCHMARK.md`](BENCHMARK.md) and the README
    *How it works / honesty* section. No claim ships that a test cannot back.
  - **Lean, one binary.** No required external service, daemon, database, or
    account; a single self-contained Rust binary (10 cross-platform + 4
    Linux-gated dependencies). The MCP form is a short-lived stdio process, not a
    daemon. A CI **purity guard** keeps the default build free of any
    model/wasm/eBPF runtime (with a mandatory negative self-test).

## Roles and responsibilities

| Role | Who | Responsibilities |
|------|-----|------------------|
| **Maintainer** | [@SuarezPM](https://github.com/SuarezPM) (Pablo Suarez) | Reviews and merges changes; cuts releases; triages issues and security reports; owns the crates.io / GitHub credentials; final decision-maker. |
| **Security contact** | the maintainer, via [`SECURITY.md`](SECURITY.md) | Receives and responds to vulnerability reports (private GitHub Security Advisories). |
| **Code of Conduct moderator** | the maintainer, via [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Receives and acts on conduct reports. |
| **Contributors** | anyone | Open issues/PRs; contributions are accepted per [`CONTRIBUTING.md`](CONTRIBUTING.md) and dual-licensed MIT OR Apache-2.0. |

There is currently **one maintainer**; the project actively welcomes additional
maintainers. A contributor with a sustained track record of high-quality,
on-principle contributions may be invited by the maintainer to become a
co-maintainer (gaining merge/release rights and credential access under the
continuity plan below).

## Access continuity (bus factor)

The project must be able to continue — create and close issues, accept changes,
and publish releases — within about a week even if the maintainer becomes
unavailable. The continuity plan:

- **Credential custody.** The credentials required to operate the project — the
  GitHub account (and repository admin) and the crates.io API token — are stored
  in the maintainer's password manager, **with recovery/break-glass copies kept
  off-site** so a designated trusted party can recover access if the maintainer
  is incapacitated.
- **No on-site secret is load-bearing for users or releases.** Release binaries
  are signed via **keyless** Sigstore attestation (SLSA Build L3 provenance via
  GitHub OIDC — *no long-lived signing key to lose or rotate*; see
  [`SECURITY.md`](SECURITY.md) and the README). A downstream user keeps building
  from source, verifying, and running the tool regardless of the project's
  operational state.
- **Reproducible from source.** The repository is the single source of truth;
  anyone with the credentials can rebuild and re-publish from a clean checkout
  (`cargo build --release`, then a `vMAJOR.MINOR.PATCH` tag that drives the
  release + attestation workflows). `Cargo.lock` + `rust-toolchain.toml` pin the
  dependency graph and channel.
- **Fork-ability.** Under the permissive MIT OR Apache-2.0 license, the community
  can fork and continue the project without the maintainer's involvement if ever
  required.

> Maintainer action (kept current out-of-band): ensure the break-glass recovery
> copies are held by a trusted second party. This is the human half of the bus
> factor and is not something the repository can enforce on its own.

## Releases

Releases follow [Semantic Versioning](https://semver.org); each release is a git
tag (`vMAJOR.MINOR.PATCH`) that drives the release workflow
([`.github/workflows/release.yml`](.github/workflows/release.yml)) — per-target
prebuilt binaries on a GitHub Release — and the crates.io publish workflow
([`.github/workflows/publish.yml`](.github/workflows/publish.yml),
`cargo install apohara-agentguard`). The release **binaries** carry a **SLSA
Build L3** provenance attestation (Sigstore keyless), generated by an isolated
reusable workflow ([`.github/workflows/_attest.yml`](.github/workflows/_attest.yml))
that holds the signing permissions the build jobs do not — so a build job cannot
forge its own provenance. The attestation is verifiable with `gh attestation
verify --signer-workflow …`; the git tags themselves are not GPG-signed. The
changes per release are recorded in [`CHANGELOG.md`](CHANGELOG.md).

## Changing this document

Changes to governance are proposed via pull request and decided by the maintainer
in the open, like any other change.
