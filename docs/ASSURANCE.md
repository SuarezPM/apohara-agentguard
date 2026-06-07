# Assurance Case

This is apohara-agentguard's **assurance case**: a structured argument for *why
its security requirements are met*. It states the security requirements, the
threat model and trust boundaries, the secure-design principles applied, and how
common implementation weaknesses are countered — each with pointers to the code,
tests, and CI that back the claim. It consolidates and does not restate
[`SECURITY.md`](../SECURITY.md) (the full "Covers / does NOT cover" threat
model); where the two differ, `SECURITY.md` wins on the threat model and this
document wins on the design argument.

## 1. Security requirements (what we promise)

apohara-agentguard is a **deterministic, offline** safety layer for AI coding
agents: a single Rust binary that gates the shell commands an agent runs,
confines the code it executes, and inspects the text it ingests — **with no
model, no API key, and no network call at scan time**. Its security
requirements:

1. **Surface, never miss, an obfuscated destructive command.** The gate turns a
   raw Bash command into Allow / Warn / Block by parsing *structure*, not
   grepping substrings, so a destructive leg cannot hide behind variable
   aliasing, `echo`/`printf` command-substitution verbs, ANSI-C quoting, `IFS`
   reassignment, line-continuation, or single-level base64 — within the
   documented, parser-bounded scope.
2. **Never panic, never hang, on any input.** Untrusted command text is
   normalized and parsed by **bounded** pure functions (64 KiB buffer, ≤ 64
   splices, 4× per-span expansion cap); there is no parse-by-crash path.
3. **Confine fail-closed.** The seccomp + Landlock sandbox scopes a process to
   one workspace root with the network denied by omission, and **refuses to run**
   (non-zero exit) rather than run unconfined on a kernel that cannot enforce it.
4. **Inspect ingested content without becoming an attack surface.** The firewall
   re-fetches web content **out-of-band** behind an SSRF guard (resolve-then-check,
   re-checked on every redirect hop) over HTTPS only, with size/time caps, and
   fails closed to Warn on error.
5. **Never self-disarm.** The kill-switch is read from the **hook process's**
   environment, not the inspected command's, so a malicious command cannot turn
   the gate off.
6. **Stay honest.** Precision is measured, not asserted: a CI gate pins `0` false
   positives and `0` false negatives on the curated corpus, and the residual
   blind spots are published rather than hidden.

Non-requirements (explicitly out of scope, documented so they are not
over-read): being a **sandbox-escape-proof jail**; defending a host or agent that
is **already compromised**; reconstructing arbitrary nested encoders or a full
Bash grammar; and eliminating the re-fetch/TOCTOU gap inherent to inspecting web
content out-of-band. See
[`SECURITY.md`](../SECURITY.md) (§ "What apohara-agentguard is (and is not)" and
the per-component "Does NOT cover" lists).

## 2. Threat model and trust boundaries

### Actors and assets
- **User** (trusted): installs the binary and wires it as a hook with their own
  privileges.
- **AI coding agent** (semi-trusted): the user chose to run it, but its actions
  are the attack surface — a prompt injection or a hostile instruction can make
  it *attempt* a destructive command, read a secret path, or fetch hostile web
  content.
- **Inspected command / prompt / web content** (untrusted *data*): every byte
  reaching the gate, the firewall, or the sandbox is attacker-influenceable.
- **Remote web host** (untrusted): the target of an agent `WebFetch`/`WebSearch`,
  re-fetched out-of-band by the firewall.
- **Assets:** the user's host and workspace integrity, process liveness while
  parsing untrusted command text, confinement of agent-run code to the workspace
  root, and the local audit log's confidentiality.

### Trust boundaries
- **Boundary A — the command gate (`src/gate`).** The raw Bash command is
  attacker-influenced. It is normalized and split by bounded pure functions
  ([`normalize.rs`](../src/gate/normalize.rs),
  [`compound.rs`](../src/gate/compound.rs)) and matched against a verb-aware
  destructive taxonomy ([`taxonomy.rs`](../src/gate/taxonomy.rs)) — never
  executed by the gate.
- **Boundary B — the path-guard (`src/hook/pathguard.rs`).** A `Read`/`Write`/`Edit`
  target path the agent names is checked against secret-bearing path shapes
  *before* the tool runs.
- **Boundary C — the sandbox (`src/sandbox`, Linux).** Agent-generated code runs
  in a post-fork grandchild under NO_NEW_PRIVS → Landlock → seccomp (installed
  in that pinned order), confined to a workspace root with no network fd
  obtainable.
- **Boundary D — the firewall (`src/firewall`).** Prompts, read files, command
  output, and re-fetched web content are scored against a deterministic
  `RegexSet`; web content crosses an SSRF guard before any byte is read
  ([`refetch.rs`](../src/firewall/refetch.rs)).
- **Boundary E — the kill-switch.** Read from the hook process env, never the
  inspected command, so it cannot be flipped by the input it guards.

### Threats considered and mitigations
| Threat | Mitigation |
|--------|------------|
| Obfuscated destructive command slips a substring blocklist | structural compound split + bounded normalize pre-pass (variable alias, `$(echo rm)` verb splice, ANSI-C `$'…'`, `IFS`, line-continuation, single-level base64) before a verb-aware taxonomy match ([`gate/`](../src/gate)); pinned in `tests/gate_evasions.rs`, `tests/headline_bypass.rs` |
| Benign command that merely *mentions* a destructive token is blocked (false positive) | verb-aware effective-text: a destructive substring inside a quoted arg to a non-executing verb (`git commit -m`, `echo`) is treated as data, not a command ([`taxonomy.rs`](../src/gate/taxonomy.rs)); `0`-FP gate (`tests/gate_fp.rs`, `tests/benchmark.rs`) |
| Adversarial input crashes/hangs the gate | normalize + split are bounded pure functions (64 KiB / ≤64 splices / 4× cap) with no `unwrap` on parse; a **`cargo-fuzz` target** (`fuzz/fuzz_targets/gate_evaluate.rs`) drives arbitrary bytes through `normalize → split → evaluate` asserting never-panic |
| Agent-run code reaches the network or escapes the workspace | seccomp denies socket-creation syscalls by omission and Landlock scopes the filesystem; pinned install order; `tests/sandbox_seccomp.rs` asserts `socket(AF_INET,…)` → EPERM, `tests/sandbox_landlock.rs` asserts `/etc/passwd` / `$HOME/.ssh` stay denied |
| Sandbox silently runs unconfined on an incapable kernel | fail-closed setup: any namespace/Landlock/seccomp failure `_exit`s with a setup error; `tests/sandbox_failclosed.rs`, `tests/sandbox_offlinux.rs` (macOS/Windows refusal) |
| Firewall re-fetch is abused for SSRF / DNS rebinding | resolve-then-check SSRF guard denies private/loopback/link-local/ULA/cloud-metadata *resolved* IPs and re-fires on every redirect hop ([`refetch.rs`](../src/firewall/refetch.rs) `ssrf_check_ip`); pure, fully unit-tested |
| ReDoS via a crafted firewall input | rules compile into a linear `RegexSet` (no nested quantifiers); a ReDoS bench (`benches/regex_redos.rs`) runs as a regression gate under `cargo test --benches` |
| Malicious command self-disarms the gate | kill-switch read from the hook *process* env, not the command; `tests/kill_switch_env.rs` |
| Secret leaks into the audit log | off by default, metadata-only by default; command text is opt-in, secret-redacted *then* truncated, mode 0600 ([`audit.rs`](../src/audit.rs)) |
| Tampered prebuilt binary (separate acquisition path) | release artifacts carry **SLSA Build L3** provenance (Sigstore keyless, isolated `_attest.yml`); `gh attestation verify --signer-workflow …` checks them |

## 3. Secure-design principles applied

- **Deterministic, not AI.** Every component derives a verdict from a numeric
  severity via fixed thresholds ([`verdict.rs`](../src/verdict.rs)); the same
  input always yields the same verdict and the same bytes out. No model, no API
  key, no network call at scan time. Auditable and reproducible.
- **Fail toward safety, by component.** The sandbox **fails closed** (refuses to
  run unconfined); a fetch error/timeout **fails closed to Warn**; an executing
  verb that is not clearly non-executing is treated as executing (fail toward
  Block); a malformed *hook event* **fails open** (allow) so a schema surprise
  cannot brick the user's tools, with the kill-switch checked *before* any
  parsing. Each posture is a deliberate, documented choice (see
  [`ARCHITECTURE.md`](../ARCHITECTURE.md)).
- **Least surface.** No daemon, no server socket, no external database, no
  credentials, no telemetry. The MCP form is a short-lived stdio JSON-RPC
  process, not a long-running service. The only optional state is a local,
  off-by-default JSONL audit log.
- **Bounded by construction.** The normalize pre-pass cannot run away: a 64 KiB
  rewrite buffer, ≤ 64 splices, a per-span 4× expansion cap, and bounded
  base64-decode recursion. A grammar-based tokenizer is the deferred upgrade
  path, kept out until the evasion set justifies the dependency.
- **Memory safety with a small, audited `unsafe` surface.** The shipped code is
  safe Rust except for the **Linux sandbox FFI/syscall paths**
  ([`src/sandbox/linux/runner.rs`](../src/sandbox/linux/runner.rs)): `fork`,
  `libc::_exit` across the forked address space (chosen precisely because a panic
  across a forked address space is the most dangerous failure mode), `prctl`,
  and a `close_range` syscall with a manual fallback. None does pointer
  arithmetic on attacker data; each is a thin, necessary C-ABI call confined to
  the post-fork grandchild. (The only other `unsafe` in the tree is `set_var` in
  *test* helpers, not shipped code.)
- **Anti-self-disarm.** The kill-switch is a break-glass control read from the
  hook process environment, structurally unreachable by the command it inspects.

## 4. Common implementation weaknesses — countered

- **Input validation (untrusted input).** The untrusted input classes are
  handled explicitly. (a) **Bash command text** is parsed *structurally* by
  bounded pure functions — there is no parse-by-crash and no `unwrap` on the
  parse result; the normalize pre-pass is hard-capped (64 KiB / ≤64 splices / 4×)
  and disablable (`normalize = false`) without disabling the rest of the gate.
  (b) **Firewall content** is matched by a **ReDoS-guarded linear `RegexSet`**
  (no nested quantifiers; the `benches/regex_redos.rs` gate keeps matching
  sub-millisecond). (c) **Named tool paths** drive the path-guard's secret-shape
  check, not a shell-out. (d) **Hook event JSON** that does not match the
  expected schema fails open (allow), never crashes. Non-literal/edge constructs
  the gate deliberately leaves out of scope are enumerated in
  [`SECURITY.md`](../SECURITY.md) (§ "Does NOT cover") and pinned in
  `tests/gate_evasions.rs`.
- **Cryptography & TLS (the firewall's out-of-band re-fetch).** The firewall's
  re-fetch ([`refetch.rs`](../src/firewall/refetch.rs)) opens the **only** network
  connection in the project, and it does so safely:
  - **HTTPS only, real cert verification.** It uses `ureq` with **rustls**
    (`default-features = false, features = ["tls"]` in `Cargo.toml`). Certificate
    verification is rustls' default and is **never disabled** anywhere in the
    tree; TLS 1.2+ is negotiated (no SSLv3 / TLS < 1.2). No FTP/telnet/plaintext
    transport is used.
  - **No weak primitives.** The only hash in the tree is **SHA-256** (`sha2`),
    used to derive the non-secret canary token ([`src/hook/canary.rs`](../src/hook/canary.rs));
    there is no MD5, SHA-1, or weak/CBC cipher anywhere.
  - **No long-lived signing key.** Release signing is **keyless** (Sigstore +
    GitHub OIDC), so there is no private key to protect, rotate, or lose.
  - **SSRF as a first-class control.** Resolve-then-check denies internal
    resolved IPs and re-fires on every redirect hop — a real security mechanism,
    unit-tested directly (`metadata_ipv4_refused`, `loopback_refused`,
    `rfc1918_refused`, `link_local_refused`, `ula_refused`, …).
- **Dependency risk.** `cargo deny check licenses` (allowlist gate) **and**
  `cargo deny check advisories` (RUSTSEC) run in CI on every push/PR
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)); `deny.toml`
  enforces a crates.io-only source policy (a git/path source is a hard error).
  Dependabot opens update PRs weekly ([`.github/dependabot.yml`](../.github/dependabot.yml)).
  The dependency set is intentionally **lean** (10 cross-platform + 4
  Linux-gated), and a CI **purity guard** with a mandatory negative self-test
  keeps the default build free of any model/wasm/eBPF runtime.
- **Static analysis.** `clippy` with `-D warnings` (no warning tolerated) and
  `cargo fmt --check` on every change, a **CodeQL** workflow (Rust SAST,
  [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml)), and an
  **OpenSSF Scorecard** workflow ([`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml))
  feeding the supply-chain badge. All workflow Actions are pinned to commit SHAs
  and run with least-privilege token permissions (top-level `contents: read`,
  write elevated per-job only where needed).
- **Dynamic analysis.** A **`cargo-fuzz` target** (`fuzz/fuzz_targets/gate_evaluate.rs`)
  drives arbitrary bytes through the exact live pipeline
  (`normalize → split → gate::evaluate`), enforcing the never-panic contract and
  a conservative "a constructed `rm -rf` leg is never Allowed" invariant.

## 5. Residual risk (honest)

- **Parser-bounded by design.** The gate is exactly as good as its compound
  parser and rule set. Nested/chained encoders, word-concatenation split tokens
  (`` $(printf '\x72')m -rf ``), real here-document parsing, deliberate parameter
  expansion, and non-literal command-substitution verbs are **out of scope** and
  named as such in `SECURITY.md` and the README evasion scorecard.
- **The sandbox is not an escape-proof jail.** `/proc/self`, abstract unix
  sockets, and ptrace blind spots are not exhaustively closed; the allowlist is
  scoped to run build tools, not to resist a determined in-process escape.
  `danger_full_access` installs **no** confinement at all (gated behind
  `--i-know-what-im-doing`, loud warning, audited).
- **Re-fetch TOCTOU & WebSearch nondeterminism.** A server can serve clean bytes
  to the hook and malicious bytes to the agent; the URL is fetched twice; the
  WebSearch re-run is best-effort. The load-bearing guarantees are the per-surface
  posture and the SSRF guard, not byte-identical results.
- **The firewall misses most novel human attacks.** The external Tensor Trust
  benchmark shows a **94.8% false-negative rate** — published, not hidden, as the
  motivation for a future opt-in semantic tier ([`BENCHMARK.md`](../BENCHMARK.md)).
- **Coverage gaps.** Measured line coverage is ≈ 89.7%; the main uncovered areas
  are the sandbox seccomp/Landlock runner paths (which need a userns + Landlock
  kernel and run as a non-blocking CI step) and the CLI `main.rs` dispatch.

These are documented, intentional limitations, not undisclosed gaps.

## 6. Evidence index

| Claim | Evidence |
|-------|----------|
| Obfuscated destructive command surfaces | `src/gate/` (`normalize.rs`, `compound.rs`, `resolve.rs`, `taxonomy.rs`); `tests/gate_evasions.rs`, `tests/headline_bypass.rs`, `tests/gate_normalize.rs` |
| 0-FP / 0-FN precision | `tests/benchmark.rs` (`0/73`, `0/33`), `tests/gate_fp.rs`, `tests/benchmark_packs.rs` |
| Never panics / never hangs | `fuzz/fuzz_targets/gate_evaluate.rs` (`cargo-fuzz`); bounded normalize (`src/gate/normalize.rs`) |
| Sandbox confines + fails closed | `src/sandbox/linux/runner.rs`; `tests/sandbox_seccomp.rs`, `tests/sandbox_landlock.rs`, `tests/sandbox_failclosed.rs`, `tests/sandbox_offlinux.rs`, `tests/sandbox_build_e2e.rs` |
| SSRF guard / HTTPS-only re-fetch | `src/firewall/refetch.rs` (`ssrf_check_ip`, rustls TLS); in-module SSRF tests |
| ReDoS resistance | `benches/regex_redos.rs` (run under `cargo test --benches`) |
| Anti-self-disarm kill-switch | `src/hook/mod.rs`; `tests/kill_switch_env.rs` |
| Audit-log secret hygiene | `src/audit.rs`; `tests/audit.rs` |
| Dependency hygiene | CI `deny` job (`licenses` + `advisories`); `deny.toml`; `.github/dependabot.yml` |
| Static analysis | CI `clippy -D warnings` + `fmt --check`; `codeql.yml`; `scorecard.yml` |
| Test coverage | ≈89.7% line coverage (`cargo llvm-cov --summary-only`); see [`best-practices-silver.md`](best-practices-silver.md) |
| Signed releases (SLSA L3) | `.github/workflows/_attest.yml` (isolated reusable workflow); `gh attestation verify --signer-workflow …`; `SECURITY.md` § Release integrity |
