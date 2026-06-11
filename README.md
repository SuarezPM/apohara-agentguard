<p align="center">
  <img src="assets/banner.svg" alt="APOHARA · AgentGuard — catch the obfuscated destructive command your agent runs" width="100%">
</p>

<div align="center">

# apohara-agentguard

**Catch the obfuscated destructive command your agent _runs_ — then confine what it _touches_.**

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-agentguard/release.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-agentguard/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge)](#-license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-0.3.0-purple?style=for-the-badge)](https://github.com/SuarezPM/apohara-agentguard/releases)
[![Sandbox](https://img.shields.io/badge/sandbox-seccomp%2BLandlock-success?style=for-the-badge)](#-how-it-works--honesty)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/SuarezPM/apohara-agentguard/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-agentguard)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13128/badge?style=for-the-badge)](https://www.bestpractices.dev/projects/13128)

<sub>OpenSSF Passing + Silver criteria mapping: [docs/best-practices-silver.md](docs/best-practices-silver.md)</sub>

**[Quick Start](#-quick-start)** · **[Features](#-features)** · **[How it works](#-how-it-works--honesty)** · **[Roadmap](#-roadmap)**

A deterministic, offline Rust safety layer for AI coding agents: an **anti-bypass command gate** that parses Bash structure instead of grepping for substrings, a **seccomp + Landlock sandbox** for the code an agent actually runs, and a **prompt-injection input firewall** — no model, no network at scan time.

</div>

<!-- demo GIF placeholder: recorded separately -->

---

```console
$ apohara-agentguard check '$(echo rm) -rf ~'
block: blocked dangerous leg `rm -rf ~` (destructive [rm-rf])          # exit 2

$ apohara-agentguard check 'x=rm; $x -rf ~'
block: blocked dangerous leg `rm -rf ~` (destructive [rm-rf])          # exit 2

$ apohara-agentguard check 'find . -delete'
block: blocked dangerous leg `find . -delete` (destructive [find-delete])   # exit 2

$ apohara-agentguard check 'git commit -m "fix the rm -rf helper"'
allow                                                                  # exit 0
```

> Real output from the committed binary (`cargo run --release -- check …`). Three obfuscated destructive commands a naive substring blocklist lets through — variable alias, `echo`-substitution verb, an `rm`-less `find . -delete` — all Block; the benign `git commit` whose _message_ merely mentions `rm -rf` Allows. The gate keys on structure, not tokens.

---

## 💡 Concept

> [!NOTE]
> **The agent's commands are the attack surface.** When an AI coding agent runs a shell command — one an attacker or a prompt injection smuggled past its safety check — two common defenses each leave a hole. **Regex blocklists are defeated by trivial obfuscation:** a gate that greps for `rm -rf` never sees `x=rm; $x -rf ~`, a base64 blob piped to `sh`, or `find . -delete`, because there is no literal token to match. **Pattern-matchers don't isolate execution:** even when a check fires, a command that slips through runs with full host access — detecting danger and _containing_ it are different jobs.

`apohara-agentguard` does both, deterministically and offline. The gate parses Bash **structure** so an obfuscated compound command surfaces its destructive leg; the sandbox confines the code an agent runs to one workspace root with the network denied by default; the firewall inspects tool inputs and outputs for injection and exfiltration signatures. Same input, same verdict — no model, no API key, no network call at scan time.

---

## ✨ Features

| | |
|---|---|
| 🧬 **Anti-bypass command gate** | Parses Bash _structure_ (`check`), not substrings: resolves variable aliases, decodes base64, expands ANSI-C quotes, evaluates live `$(…)` in double quotes, follows `IFS` tricks and line-continuations — keyed on a verb-aware destructive taxonomy, so `find . -delete` is caught with no `rm` token in sight. |
| 🔒 **seccomp + Landlock sandbox** | A real `seccomp-bpf` + Landlock LSM jail (`sandbox`) for agent-generated code. Default-deny: network denied by omission, filesystem confined to one workspace root. **Fail-closed** — on a kernel without Landlock it refuses to run rather than run unconfined. Tiers: `read_only`, `workspace_write`, `danger_full_access`. |
| 🧱 **Prompt-injection firewall** | Deterministic regex rules over tool inputs and outputs (`scan`) — prompts, fetched web content, read files, command output — inspected out-of-band on `PreToolUse` for injection, exfiltration, and harmful-content signatures, with an SSRF-guarded out-of-band re-fetch. |
| 🦀 **Offline, deterministic, no model** | Pure Rust, MSRV 1.85, single binary. No network at scan time, no API keys, no telemetry. Same input ⇒ same bytes out — auditable and reproducible. |
| 🔌 **Claude Code plugin** | Ships a plugin manifest + hook config wiring `apohara-agentguard hook` to `PreToolUse`/`PostToolUse`/`UserPromptSubmit`. A `PreToolUse` block emits `permissionDecision: "deny"` and exits 2. Codex `PreToolUse` hooks are supported too. |
| 🕵️ **Canary exfiltration detection** | Opt-in (off by default): seeds a per-session sentinel into the agent's context at `SessionStart` and **warns** if it resurfaces verbatim in `PostToolUse` tool output — catching context exfiltration _by effect_, after every pattern layer. Detection-after-execution, never blocks; bypassed by any output transform (documented honestly). |
| ☁️ **Opt-in domain packs** | `cloud` (AWS/GCP/Azure destructive ops), `db` (`DROP`/`TRUNCATE` DDL), and `container` (`docker … prune -af`, `kubectl delete --all`) rule packs — off by default, each shipping its own committed `0-FP / 0-FN` corpus so the default benchmark stays untouched. |
| 🧰 **MCP tool form** | `apohara-agentguard mcp` exposes `check_command` and `scan_prompt` as read-only MCP tools over a short-lived stdio JSON-RPC process (not a daemon), so any MCP client — not only the Claude Code hook — can call the gate and firewall. |
| 🎚️ **Granular, tiered control** | Per-component kill-switch (`AGENTGUARD_DISABLE=gate,firewall,pathguard,canary`), severity presets (`level = "strict"\|"high"\|"critical"`), and config-driven **tool-level gating** — gate _which_ MCP tool and _which_ arguments, not just `Bash.command`. The empty-config default stays byte-identical. |
| 🤚 **`Tier::Ask` decision tier** (v0.3) | A 4th verdict — `Block > Ask > Warn > Allow` — surfaces a UI prompt via Claude Code's `permissionDecision: "ask"` contract (exit 0 on `PreToolUse`; graceful downgrade to `Warn` on `PostToolUse`/`UserPromptSubmit`). The `apohara-agentguard ask '<cmd>'` CLI subcommand is the operator introspection surface — see the verdict before relying on the hook. |
| 📜 **Pure-Rust policy engine** (v0.3) | TOML-loaded, per-tool `[[tools]]` rule patterns, `defaults.default_action = "deny"` posture, per-session + per-tool budget caps with the `tokens = max(1, chars / 4)` heuristic (charged on `Bash` + `UserPromptSubmit` only). Loaded via `--policy <path>` (CLI > `AGENTGUARD_POLICY` env > `[policy] file` in config). Fail-closed on any load / parse / schema-version error. **Zero new runtime deps** — reuses the existing `toml` crate, purity guard stays GREEN. |
| 🛡️ **Sandbox escape closures** (v0.3) | The Landlock ruleset now explicitly denies writes on `/proc`, closing 2 of 3 documented escape surfaces: the `/proc/self/root` filesystem-via-proc alias and the ELF-linker trick of writing to `/proc/self/exe` (`tests/sandbox_escape.rs`). The empirical build baseline (`cargo build` / `node -e` / `go run` exiting 0) is preserved as the non-regression gate. |
| 🐧 **musl Linux release binaries** (v0.3) | The release matrix grew from 5 to **7** targets with the addition of `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` — static binaries for Alpine, Void, and any musl-based container base. Both attested via the existing SLSA L3 reusable workflow. |
| ⚖️ **Dual-licensed** | MIT **OR** Apache-2.0, at your option. Third-party licenses enumerated and gated by `cargo deny`. |

---

## 🚀 Quick Start

```sh
# 1. Install the binary (builds from source — lowest-trust path)
cargo install apohara-agentguard

# 2. Check a command through the anti-bypass gate (exit 2 on a block)
apohara-agentguard check 'x=rm; $x -rf ~'

# 3. Run agent-generated code in the seccomp + Landlock sandbox (Linux)
apohara-agentguard sandbox --tier workspace_write -- cargo build

# 4. Scan untrusted text through the input firewall
echo "some untrusted text" | apohara-agentguard scan

# 5. Preview the full decision pipeline (gate + policy engine) — v0.3
apohara-agentguard ask 'kubectl get pods'
# -> "ask: <reason>" (budget exceeded) / "block: <reason>" / "allow"

# 6. Install as a Claude Code plugin (resolves + SHA256-verifies the binary)
curl -fsSL https://raw.githubusercontent.com/SuarezPM/apohara-agentguard/main/packaging/install.sh | sh
```

<details>
<summary><b>Advanced usage</b> — subcommands, sandbox tiers, the hook, the kill-switch</summary>

```sh
# Confine the sandbox to a chosen workspace root (default: current directory)
apohara-agentguard sandbox --tier read_only --workspace-root "$PWD" -- ./build.sh

# The no-confinement tier requires an explicit, logged acknowledgement
apohara-agentguard sandbox --tier danger_full_access --i-know-what-im-doing -- ./installer.sh

# Run as a Claude Code hook: reads the event JSON on stdin, emits a decision
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x=rm; $x -rf ~"}}' \
  | apohara-agentguard hook ; echo "exit=$?"   # -> permissionDecision=deny, exit 2

# Emergency kill-switch (read from the HOOK process env, not the inspected command)
export AGENTGUARD_DISABLE=1   # or: disable = true in the config file

apohara-agentguard version
```

**Subcommands:** `check <cmd>` (gate) · `ask <cmd>` (v0.3: gate + policy engine) · `sandbox --tier <t> [--workspace-root <p>] -- <cmd>` · `scan` (stdin → firewall) · `hook` (stdin event → decision) · `mcp` (stdio JSON-RPC server: `check_command` + `scan_prompt`) · `version`.

**Other acquisition paths.** A thin `npx apohara-agentguard` launcher resolves the release binary by platform × arch × libc; `cargo install --git https://github.com/SuarezPM/apohara-agentguard apohara-agentguard --locked` builds from source (the supported path for musl Linux and any platform without a pinned artifact; the package is named so cargo skips the in-repo fuzz crate).

> [!WARNING]
> Downloading a pre-built binary is itself a supply-chain surface — the very risk this tool exists to flag. The `npx` and install-script paths resolve the artifact, verify its **SHA256 against a pinned manifest**, and **refuse to run on a mismatch**. Prefer `cargo install` and build from source when in doubt.

</details>

---

## 📋 Known evasions: an honest scorecard

The gate's soundness is parser-bounded. Publishing exactly where the boundary sits is part of the product — it is the difference between a safety claim and a marketing claim.

### Now caught (v0.1.x)

A bounded, in-place normalization pre-pass (`gate::normalize`) closes four forms the v0.1 gate let through. Each is spliced contiguously into the command before splitting, so the destructive leg surfaces and **Blocks**:

| Construct | Example | What `normalize` does |
|---|---|---|
| 🔤 **ANSI-C quoting** | `$'\x72\x6d' -rf ~` | hex/octal/`\u`/named escapes decoded in place |
| 🪄 **Command-substitution-produced verbs** | `$(echo rm) -rf ~`, `` `echo rm` -rf ~ `` | leg-head `echo`/`printf` literal substitution spliced into the verb it emits |
| 💬 **Live command substitution in a double-quoted argument** | `echo "$(rm -rf ~)"`, `git commit -m "$(rm -rf ~)"` | body extracted and scanned as a command; `$(curl … \| sh)` Blocks too. A literal-emitter like `git commit -m "$(echo rm -rf)"` Allows; single quotes (`'literal $(rm -rf ~)'`) stay literal and Allow |
| 🧮 **IFS reassignment** | `IFS=X; cmdXrmX-rfX~` | recorded separator word-joined into later legs and re-scanned — gated on surfacing a hit, so benign `IFS` loops/`read`s never false-positive |
| ↩️ **Backslash line-continuation** | `r\`<newline>`m -rf ~` | the continuation is joined |

Variable assignment (`x=rm; $x …`) and single-level base64 decode-and-rescan were already caught in v0.1. The pre-pass is bounded (64 KiB buffer, ≤ 64 splices, 4× per-span expansion cap) and can be disabled with `normalize = false` without disabling the rest of the gate.

### Still out of scope (v0.1)

These remain honestly uncaught (parser-bounded):

- 🪜 **Nested / chained encoders** — hex/rot13/gzip layered beyond the single decode level, or word-concatenation like `` $(printf '\x72')m -rf ``.
- 🧷 **Deliberate parameter expansion** — beyond the incidental cases below.
- 📄 **Real here-document parsing** — the body is matched incidentally, not parsed.
- 🌐 **Non-literal command-substitutions** — a substitution in _command (verb) position_ whose output is not a literal `echo`/`printf`, e.g. `$(curl ...) -rf ~`. (An `$(curl … | sh)` in _argument_ position inside double quotes **is** now scanned and Blocks; only the verb-producing case remains out of scope.)

Two forms Block **incidentally** — as a side effect of leg matching, not by deliberate handling, so do not rely on them: parameter expansion with defaults (`${x:-rm}` / `${x:=rm}`) survives as a literal `rm` in the leg, and here-documents (`<<EOF … EOF`) have their body line treated as its own leg.

---

## 🔬 How it works / honesty

> [!WARNING]
> **This is a safety _hook_, not an escape-proof jail.** Detection is **deterministic, not AI** — it is exactly as good as the compound parser and the rule set, and makes no "blocks 100% of attacks" claim. `seccomp` + Landlock are **Linux-only** (needs **Linux ≥ 5.13 with Landlock enabled**); on macOS/Windows the sandbox fails closed. The web firewall re-fetches out-of-band, so there is a **re-fetch / TOCTOU** gap (a server can serve clean bytes to the hook and malicious bytes to the agent). The whole thing is **parser-bounded** — see the [evasion scorecard](#-known-evasions-an-honest-scorecard) for exactly where the boundary sits.

**Measured, gated precision.** A committed CI harness runs the **real** gate over the **same** author-curated corpus as a naive substring baseline (the hookify-class fixed-list gate) on every `cargo test`. A false positive is a benign command that Blocks; a false negative is a dangerous command that slips:

| Engine (same corpus) | False positives | False negatives |
|---|---|---|
| Naive substring baseline (hookify-class) | 8 / 73 (11%) | 11 / 33 (33%) |
| apohara-agentguard (gate, v0.2 baseline) | **0 / 73** | **0 / 33** |
| apohara-agentguard (policy engine, v0.3) | **0 / 66** | **0 / 33** |
| apohara-agentguard (Ask tier, v0.3) | **0 / 30** | **0 / 18** |

The build asserts `FP == 0`, `FN == 0`, and `FN < naive FN` for every corpus — the corpora are **not** tuned to make them pass; a benign Block or a missed danger is a real bug. Each capability (gate / policy engine / Ask tier / sandbox closures) has its own pre-committed corpus and pre-committed 0-FP / 0-FN gate in [BENCHMARK.md](BENCHMARK.md).

> [!NOTE]
> The corpus is **author-curated and 100% synthetic** (73 benign + 33 dangerous), and the dangerous set _deliberately_ includes the obfuscation constructs apohara-agentguard is built to catch — so the FN gap is a demonstration of the design, not a neutral sample. No real agent session is committed or used. Reproduce it yourself:
> ```sh
> cargo test benchmark -- --nocapture
> ```
> The full honest scorecard — per-layer catch/miss, latency percentiles, and the **external** Tensor Trust human-attack benchmark (where the firewall misses 94.8%, motivating an **opt-in sidecar** rather than a default tier) — lives in [BENCHMARK.md](BENCHMARK.md).

**Kill-switch.** apohara-agentguard ships an all-or-nothing emergency kill-switch so a fail-closed bug can never brick your Bash tool: `export AGENTGUARD_DISABLE=1` (or `disable = true` in the config) immediately allows everything and exits 0, disabling the gate, path-guard, **and** firewall together. It is read from the **hook process's** environment, not the inspected command's — a malicious Bash command that sets `AGENTGUARD_DISABLE=1` runs in a _different_ process and **cannot self-disarm** the gate. A **granular** form now ships: `AGENTGUARD_DISABLE=gate,firewall,pathguard,canary` disables only the named components (and config-side `disabled = [...]`), while severity presets (`level = "strict"|"high"|"critical"`) tune the thresholds — both opt-in, with the empty-config default byte-identical to before.

**Release integrity (signed binaries).** The release binaries are **signed and carry a build-provenance attestation** generated keylessly in CI (Sigstore + GitHub OIDC). Provenance is produced by an **isolated reusable workflow** (`_attest.yml`), separated from the build steps so a build job cannot forge its own provenance — meeting **SLSA v1.0 Build Level 3**. Verify a downloaded binary, asserting it was signed by that workflow:
> ```sh
> gh attestation verify <downloaded-binary> -R SuarezPM/apohara-agentguard \
>   --signer-workflow SuarezPM/apohara-agentguard/.github/workflows/_attest.yml
> ```
> A non-zero exit means the binary is unsigned, tampered with, or not built by this repo's signing workflow — don't run it. The release workflow runs this same check over every target as an E2E gate (`gh attestation verify` with the wrong signer-workflow is rejected).

**Known limitations.** Web re-fetch is a double-fetch (added latency); TOCTOU on web content; WebSearch is best-effort (the load-bearing guarantee is the per-surface posture + SSRF guard, not byte-identical results); the SSRF guard denies private/loopback/link-local/ULA/cloud-metadata _resolved_ IPs and re-checks every redirect hop; the sandbox is Linux-only and fails closed elsewhere. The full threat model lives in [SECURITY.md](SECURITY.md).

---

## 🏗️ Repository layout

```text
apohara-agentguard/
├── src/
│   ├── gate/                # anti-bypass command gate
│   │   ├── normalize.rs     # bounded in-place de-obfuscation pre-pass
│   │   ├── compound.rs      # Bash compound/leg splitter
│   │   ├── decode.rs        # base64 / ANSI-C decode + rescan
│   │   ├── resolve.rs       # variable-alias resolution
│   │   ├── taxonomy.rs      # verb-aware destructive taxonomy
│   │   └── packs/           # opt-in cloud / DB DDL / container rule packs
│   ├── hook/                # Claude Code hook contract + path-guard + canary
│   ├── mcp/                 # MCP stdio JSON-RPC server (check_command / scan_prompt)
│   ├── sandbox/linux/       # seccomp-bpf + Landlock jail (fail-closed)
│   ├── firewall/            # prompt-injection firewall + SSRF re-fetch
│   ├── policy/              # v0.3: pure-Rust TOML policy engine
│   │   ├── schema.rs        #   schema_version, defaults, [[tools]], [budgets]
│   │   ├── matcher.rs       #   the canonical `*`-substring pattern matcher
│   │   └── engine.rs        #   PolicySet::load + ::evaluate + budget counters
│   ├── verdict.rs           # 4-tier Allow / Warn / Ask / Block model (v0.3)
│   └── main.rs              # clap CLI: check · ask · sandbox · scan · hook · mcp · version
├── tests/                   # incl. committed FP/FN gates (gate / policy / ask / sandbox) + evasion regression net
├── benches/                 # ReDoS guard for the rule regexes
├── fuzz/                    # cargo-fuzz target over gate::evaluate
├── .claude-plugin/          # v0.3: marketplace.json (submission itself GATED on Pablo)
└── packaging/               # Claude Code plugin manifest, hooks, npx + install.sh
```

---

## 🗺️ Roadmap

**Why this order.** The 2026 field has converged on the bet this project started with: deterministic, system-enforced pre-action authorization + sandboxed execution is the load-bearing layer of agent safety (NIST/IEEE RFI Mar 2026, the "Before the Tool Call" paper, the canonical 4-layer alignment → pre-action → sandbox → post-hoc stack). But the niche has **also** gotten crowded — `ptuf` (Rust, v0.3.0) covers six hosts and ships ask/monitor/plugins/MCP-path gating; native platform sandboxing (Cursor, Claude Code) is absorbing the firewall. **The durable differentiator is the depth of the deterministic pre-action layer + a real seccomp/Landlock sandbox + a published honest scorecard** — not injection detection, which is commoditized and brittle. Items below are ordered by that thesis, not by feature parity.

### v0.3 — Decision tier + capability gating

- [x] **Ask / monitor decision tier** — non-blocking "confirm with the human" mode (alongside the existing Allow / Block). `Tier::Ask` with `permissionDecision: "ask"` hook output + `apohara-agentguard ask '<cmd>'` CLI subcommand.
- [x] **Declarative policy engine** — pure-Rust TOML (no Cedar/OPA, zero new runtime deps). Default-deny posture, per-session + per-tool budget caps with `tokens = max(1, chars / 4)` heuristic, per-tool `[[tools]]` rule patterns. Fail-closed on any load/parse/schema-version error.
- [x] **Sandbox hardening** — Landlock ruleset extension closes 2 of 3 documented escape surfaces (`/proc/self/root` write alias + `/proc/self/exe` ELF-linker trick); the seccomp self-disable side is covered by the empirical baseline (`tests/sandbox_seccomp.rs::unlisted_syscall_returns_eperm`).
- [x] **Claude Code plugin marketplace listing** — `.claude-plugin/marketplace.json` added; **submission to the directory itself is gated on Pablo**.
- [x] **musl Linux release binaries** — `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` added to the release matrix (5 → 7 targets). x86_64 verified locally (5.4M static-pie); aarch64 uses the `ghcr.io/cross-rs/aarch64-unknown-linux-musl:main` image (4.4M static). Both attested via the existing SLSA L3 reusable workflow.

### v0.4 — Multi-host + transport-layer MCP

- [ ] **Adapters for Cursor / Copilot / Cline / Kiro** — currently Claude Code + Codex only
- [ ] **MCP as a transport proxy** — default-deny, hide destructive tools, budget / spending caps between the agent and the MCP server (not just a tool form)
- [ ] **Cryptographically-signed per-action audit trail** — every gated action emits a verifiable record

### v0.5+ — Polish, depth, honest opt-ins

- [ ] **Community policy / plugin packs** — a registry of declarative policies others can import
- [ ] **MiniBERT semantic-classifier tier** — **opt-in isolated sidecar only**; honestly framed as "raises paraphrase recall, not prevention" (gated on an accuracy ship-gate that beats today's 379 / 400 TensorTrust FN; default build stays model-free)
- [ ] **eBPF / BPF-LSM enforcement** — real enforcement path, not just telemetry

### Transversal

- [x] **Default-build purity guard** — CI keeps the lean default free of any model / wasm / eBPF runtime (`cargo tree -e normal` denial set)
- [x] **External Tensor Trust** human-attack benchmark — 379 / 400 = 94.8% FN published
- [ ] **Add the Mirror paraphrase corpus** as a second external benchmark — stress-test paraphrasing, the documented weakness of any regex/injection detector

### Done (since v0.1)

- [x] Anti-bypass command gate (structural Bash parsing + normalization pre-pass)
- [x] seccomp + Landlock sandbox (fail-closed, three permission tiers)
- [x] Prompt-injection input firewall (SSRF-guarded out-of-band re-fetch)
- [x] `cargo-fuzz` target over `gate::evaluate`
- [x] Committed FP/FN precision gate (`0 / 73`, `0 / 33`)
- [x] Claude Code plugin packaging (manifest + hooks + verified installers)
- [x] Signed release binaries with keyless build-provenance attestation (Sigstore + OIDC)
- [x] **SLSA v1.0 Build Level 3** — provenance generated by an isolated reusable workflow (`_attest.yml`); verified end-to-end with `gh attestation verify --signer-workflow` (wrong signer is rejected)
- [x] Publish to crates.io (`cargo install apohara-agentguard`)
- [x] MCP tool form — `check_command` / `scan_prompt` over a short-lived stdio JSON-RPC process (not a long-running daemon)
- [x] Granular per-component kill-switch (`AGENTGUARD_DISABLE=gate,firewall,…`) + severity presets
- [x] Canary exfiltration detection (`PostToolUse`, opt-in, warn-only)
- [x] Opt-in domain packs (cloud / DB DDL / container, each with a `0-FP / 0-FN` corpus)
- [x] Tool-level gating (gate _which_ MCP tool and _which_ arguments)
- [x] Codex `PreToolUse` hook compatibility
- [x] **`Tier::Ask` + `permissionDecision: "ask"`** (v0.3) — the 4th verdict; surfaces a UI prompt to the human via Claude Code's documented contract
- [x] **`apohara-agentguard ask '<cmd>'` CLI subcommand** (v0.3) — operator introspection surface for the full decision pipeline (gate + policy engine)
- [x] **Pure-Rust TOML policy engine** (v0.3) — per-tool `[[tools]]` rules, `defaults.default_action = "deny"`, per-session + per-tool budget caps, fail-closed on any load / parse / schema-version error
- [x] **Policy engine corpora** (v0.3) — `tests/corpus/policy_{benign,dangerous}.txt` (66/33) with pre-committed 0-FP / 0-FN gate (`tests/policy_engine.rs`)
- [x] **Ask corpus + benchmark** (v0.3) — `tests/corpus/ask_{benign,dangerous}.txt` (30/18) with pre-committed 0-FP / 0-FN gate (`tests/ask_corpus.rs`)
- [x] **Sandbox escape closures** (v0.3) — Landlock explicitly denies writes on `/proc`; closes the `/proc/self/root` filesystem-via-proc alias and the `/proc/self/exe` ELF-linker trick (`tests/sandbox_escape.rs`)
- [x] **musl Linux release binaries** (v0.3) — `x86_64-unknown-linux-musl` + `aarch64-unknown-linux-musl` (release matrix 5 → 7); both SLSA L3-attested
- [x] **Claude Code marketplace metadata** (v0.3) — `.claude-plugin/marketplace.json` added; submission to the directory itself deferred

---

## 🤝 Contributing

Contributions are welcome.

1. **Fork** the repository.
2. Create a feature **branch** (`git checkout -b feature/my-change`).
3. Make your change and run the tests: `cargo test` (the FP/FN gate and the evasion regression net run here).
4. Open a **pull request**.

> Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build/test/lint flow and how to add a rule, [ARCHITECTURE.md](ARCHITECTURE.md) for the verdict model and pipeline order, and [SECURITY.md](SECURITY.md) for the threat model and responsible disclosure. Third-party dependency licenses are enumerated in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) and gated by `cargo deny check licenses`.

---

## 📄 License

Licensed under either of **[MIT](LICENSE-MIT)** or **[Apache-2.0](LICENSE-APACHE)**, at your option.

Maintained by **[SuarezPM](https://github.com/SuarezPM)**.
