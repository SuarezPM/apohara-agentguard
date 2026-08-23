# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-23

### Added

- **Provider-agnostic adapters over a canonical IR** (`src/adapters/`): Claude
  Code, Codex, and Kilo Code are parsed and formatted through one intermediate
  representation with capability-driven output — the Ask→Deny degradation on
  hosts that cannot ask is fixed by construction instead of per-host special
  cases.
- **`agentguard init` extended to five hosts** (`claude-code`, `codex-code`,
  `opencode`, `kilo`, `kitty-code`): dry-run by default, `--yes` applies,
  `--undo` removes immediately; writes are atomic and a corrupt host config is
  refused with exit 2 and zero writes.
- **OpenCode / Kilo Code plugin shim** (`packaging/opencode/agentguard-shim.mjs`):
  a spawn-per-call bridge so plugin-only hosts reach the same binary the hooks
  use.
- **`agentguard-proxy` MCP transport proxy**: a second binary that sits between
  agent and MCP server — TOFU SHA-256 pinning of the tools/list manifest with
  quarantine-on-drift, NDJSON strict framing, and policy-gated `tools/call`
  with a role-split deep check routing command/script-shaped arguments through
  the anti-bypass gate.
- **SHA-256 hash-chained audit trail** with `agentguard audit verify`: tamper
  and tail-truncation detection over the decision log (Ed25519 signatures and
  key rotation deferred until compliance demand).
- **Community rule packs**: TOML-format rule files behind a fail-closed loader
  with schema validation; three example packs ship in-tree.
- **Measured MCP tool-call corpus** (`evals/mcp/`, 43 cases): a 87.5%
  dangerous-shell block rate at 0% added false positives, including the
  authoring class — closing what was an open measurement for the proxy.
- **Mirror paraphrase benchmark published** (`evals/mirror/`): 100% FN on
  paraphrased attacks / 0% FP on benign controls — the honest signature-ceiling
  worst case, now measured ([BENCHMARK.md](BENCHMARK.md)).
- **eBPF / BPF-LSM go/no-go decision documented**
  ([docs/ebpf-spike-go-nogo.md](docs/ebpf-spike-go-nogo.md)): NO-GO for the
  default build, with the five conditions that would flip it recorded.

### Changed

- **Typed spans on every policy-load error** (D2): rustc-style code frames,
  zero new dependencies.
- **Monotonic config tightening** (D3): layered user + project loading where
  the project layer can only harden the user posture, never loosen it.
- **CLI `scan` / `check` / `ask` reasons neutralized** like the MCP surface.
- **Landlock grants execute on `/opt` toolcache paths**, so GitHub Actions
  runners can execute hosted toolchains inside the sandbox.

## [0.3.0] - 2026-08-22

### Added

- **Ask corpus + benchmark** (v0.3, Story 6): pre-committed
  `tests/corpus/ask_{benign,dangerous}.txt` (30 benign / 18
  dangerous) + `tests/ask_corpus.rs` integration test with a
  pre-committed 0-FP / 0-FN gate on the Ask tier (mirrors
  `tests/benchmark.rs:121` shape). The policy uses
  `budgets.per_tool.Bash.max_invocations = 0` to escalate every
  Bash call to Ask; the benign corpus contains only non-Bash
  tools (Read / Write / Edit / WebFetch / UserPromptSubmit) so
  the engine's budget is never charged and the engine returns
  Allow. `--test ask_corpus` registered in `ci.yml`'s explicit
  `--test` list (the v0.2 F4 lesson).
- **`apohara-agentguard ask '<cmd>'` CLI subcommand** (v0.3): runs the
  full decision pipeline (gate + policy engine) on a single
  command and prints the verdict (`allow` / `warn` / `block` /
  `ask`). The operator introspection surface for capability
  gating; the policy engine can produce `ask` here that `check`
  would not. With no policy loaded, the result is byte-identical
  to `check` (the empty-TOML invariant).
- **musl Linux release binaries** (v0.3): `x86_64-unknown-linux-musl`
  and `aarch64-unknown-linux-musl` added to the release matrix
  (5 → 7 targets). Both attested via the existing SLSA L3
  reusable workflow; the `verify-attestations` job is GREEN for
  all 7 targets.
- **Claude Code plugin marketplace listing metadata**
  (`.claude-plugin/marketplace.json`): added per the
  marketplace's submission format. **The submission to the
  marketplace directory itself is gated on Pablo** (a public
  registration is a publish-class action).
- **Sandbox escape closures** (v0.3): the Landlock ruleset
  enforces an explicit no-write on `/proc`, closing 2 of 3
  documented escape surfaces — the `/proc/self/root`
  filesystem-via-proc alias (`sandbox_proc_self_root_write_is_denied`)
  and the ELF-linker trick of writing to `/proc/self/exe`
  (`sandbox_elf_linker_tricks_are_denied`). The empirical
  baseline (`tests/sandbox_build_e2e.rs`: `cargo build` /
  `node -e` / `go run` exit 0) is preserved as the
  non-regression gate. The seccomp self-disable side is
  covered by the existing `unlisted_syscall_returns_eperm`
  test in `tests/sandbox_seccomp.rs` (the kernel allows
  multiple ANDed seccomp filters; the "lock" property is not
  a universal kernel feature). `SECURITY.md` "Known
  limitations" updated.
- **`Tier::Ask` + `permissionDecision: "ask"`** (v0.3): the 4th decision tier
  (`Block > Ask > Warn > Allow`) surfaces a UI prompt via Claude Code's
  documented `permissionDecision: "ask"` contract (exit 0 on
  `PreToolUse`; graceful downgrade to a Warn on
  `PostToolUse` / `UserPromptSubmit`). The new tier is wired through
  `audit_decision` (`decision = "ask"`) and the precedence test
  `ask_tier_rank_above_warn_below_block` is the canonical reference
  for the rank order.
- **Pure-Rust TOML policy engine** (v0.3, star item): per-tool
  `[[tools]]` rule patterns, `defaults.default_action = "deny"`
  posture, and per-session + per-tool budget caps with the
  `tokens = max(1, chars / 4)` heuristic on Bash commands and
  `UserPromptSubmit` prompts. Loaded via `--policy <path>` (global
  flag, CLI > `AGENTGUARD_POLICY` env > `[policy] file` in
  config). Composes with the gate / firewall / pathguard / tool
  rules via `max_verdict`. **Fail-closed**: any load / parse /
  `schema_version` error is mapped to `Verdict::block`. The
  pre-committed `tests/policy_engine.rs` 0-FP / 0-FN gates (66
  benign / 33 dangerous) are asserted on every push; the
  `tests/benchmark.rs` v0.2 baseline stays green (the engine is
  a no-op combine when no policy is loaded).
- **Project governance & OpenSSF Best Practices artifacts**:
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) (Contributor Covenant 3.0),
  [`GOVERNANCE.md`](GOVERNANCE.md), this changelog, a top-level
  [`LICENSE`](LICENSE) declaration (the dual MIT OR Apache-2.0 file the
  bestpractices.dev scanner recognizes, pointing to `LICENSE-MIT` /
  `LICENSE-APACHE`), [`docs/ASSURANCE.md`](docs/ASSURANCE.md) (assurance case),
  and [`docs/best-practices-silver.md`](docs/best-practices-silver.md) (criteria
  evidence map).
- **`cargo deny check advisories` in CI** — the `deny` job now runs the RUSTSEC
  advisory check alongside the license gate, so a new advisory against a
  dependency is surfaced on every push/PR (`dependency_monitoring`).

## [0.2.0] - 2026-06-06

### Added

- **Opt-in domain packs** — `cloud` (AWS/GCP/Azure destructive ops), `db`
  (`DROP`/`TRUNCATE` DDL), and `container` (`docker … prune -af`,
  `kubectl delete --all`) rule packs, off by default, each shipping its own
  committed `0-FP / 0-FN` corpus so the default benchmark stays untouched
  (`tests/benchmark_packs.rs`).
- **Canary exfiltration detection** (`PostToolUse`, opt-in, warn-only): seeds a
  per-session sentinel (a `sha2`-derived, non-secret token) into the agent's
  context at `SessionStart` and **warns** if it resurfaces verbatim in tool
  output — detection-after-execution, never blocks, bypassed by any output
  transform (documented honestly).
- **MCP tool form** (`apohara-agentguard mcp`): exposes `check_command` and
  `scan_prompt` as read-only MCP tools over a short-lived stdio JSON-RPC process
  (not a daemon), so any MCP client can call the gate and firewall.
- **Granular, tiered control**: a per-component kill-switch
  (`AGENTGUARD_DISABLE=gate,firewall,pathguard,canary` / config `disabled = […]`)
  with **anti-self-disarm** (read from the hook *process* env, not the inspected
  command), severity presets (`level = "strict"|"high"|"critical"`), and
  config-driven **tool-level gating** (gate *which* MCP tool and *which*
  arguments, not just `Bash.command`). The empty-config default stays
  byte-identical.
- **Codex `PreToolUse` hook compatibility** alongside the Claude Code hook
  contract.
- **External Tensor Trust human-attack benchmark** published with its honest
  94.8% firewall false-negative rate (`tests/benchmark_tensortrust.rs`,
  [`BENCHMARK.md`](BENCHMARK.md)) — the documented motivation for a v0.3 semantic
  tier.
- **Default-build purity guard** in CI: proves the lean default build pulls in no
  model/wasm/eBPF runtime, with a mandatory negative self-test that injects a
  denylisted crate and asserts the guard goes red.
- **SLSA v1.0 Build Level 3** signed release binaries: provenance is generated by
  an **isolated reusable workflow** (`.github/workflows/_attest.yml`) the build
  jobs cannot influence, verified end-to-end with
  `gh attestation verify --signer-workflow …` (the wrong signer is rejected).
- **Published to crates.io** (`cargo install apohara-agentguard`) via a
  maintainer-triggered publish workflow.

### Changed

- README, `SECURITY.md`, and the roadmap updated to reflect the v0.2 capability
  set and the verified SLSA Build L3 posture; OpenSSF Scorecard hardening
  (token-permissions, SHA-pinned Actions, Dependabot, CodeQL SAST).

## [0.1.0] - 2026-06-05

Initial release of **apohara-agentguard** — a deterministic, offline, no-model
safety layer for AI coding agents: one Rust binary, no network at scan time.

### Added

- **Anti-bypass command gate** (`check`): a structural Bash compound parser plus
  a **bounded in-place normalization pre-pass** (64 KiB buffer, ≤ 64 splices, 4×
  per-span expansion cap) that resolves variable aliases, decodes base64,
  expands ANSI-C quotes, splices literal `$(echo …)` verbs, follows `IFS` tricks
  and line-continuations — keyed on a verb-aware destructive taxonomy. Never
  panics (parser-bounded; hardened by a `cargo-fuzz` target).
- **seccomp + Landlock sandbox** (`sandbox`, Linux-only): a default-deny
  seccomp-bpf syscall filter and a Landlock filesystem ruleset scoping the
  process to one workspace root with the network denied by omission. **Fail-closed**
  — refuses to run on a kernel that cannot enforce it. Three tiers (`read_only`,
  `workspace_write`, `danger_full_access`).
- **Prompt-injection firewall** (`scan`): deterministic OWASP/DJL/two-stage
  `RegexSet` rules (ReDoS-guarded, linear, benched) over tool inputs and outputs,
  with an **SSRF-guarded out-of-band re-fetch** (`ureq` + rustls over HTTPS;
  denies private/loopback/link-local/ULA/cloud-metadata resolved IPs, re-checks
  every redirect hop).
- **Claude Code plugin** packaging: manifest + hook config wiring
  `apohara-agentguard hook` to `PreToolUse`/`PostToolUse`/`UserPromptSubmit`,
  with SHA256-verified installers.
- **Committed FP/FN precision gate** (`tests/benchmark.rs`): asserts `0 / 73`
  false positives and `0 / 33` false negatives against a naive substring baseline
  on the curated corpus.
- **Honest benchmark** ([`BENCHMARK.md`](BENCHMARK.md)): per-layer catch/miss and
  latency percentiles over a 100% synthetic, author-curated corpus.
- **Dual license**: MIT OR Apache-2.0; third-party licenses enumerated in
  `THIRD-PARTY-LICENSES` and gated by `cargo deny check licenses`.

[Unreleased]: https://github.com/SuarezPM/apohara-agentguard/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/SuarezPM/apohara-agentguard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SuarezPM/apohara-agentguard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SuarezPM/apohara-agentguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SuarezPM/apohara-agentguard/releases/tag/v0.1.0
