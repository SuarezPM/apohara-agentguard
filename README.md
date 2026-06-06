<div align="center">

# apohara-agentguard

**Catch the obfuscated destructive command your agent _runs_ — then confine what it _touches_.**

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-agentguard/release.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-agentguard/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge)](#-license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-0.1.0-purple?style=for-the-badge)](https://github.com/SuarezPM/apohara-agentguard/releases)
[![Sandbox](https://img.shields.io/badge/sandbox-seccomp%2BLandlock-success?style=for-the-badge)](#-how-it-works--honesty)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/SuarezPM/apohara-agentguard/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-agentguard)
<!-- OpenSSF Best Practices (CII) badge: gated on a public maintainer registration at https://www.bestpractices.dev/. After registering this project, replace PROJECT_ID below with the assigned numeric id and uncomment the badge so it renders a real score instead of a broken/false one.
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/PROJECT_ID/badge?style=for-the-badge)](https://www.bestpractices.dev/projects/PROJECT_ID)
-->
[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF%20Best%20Practices-registration%20pending-lightgrey?style=for-the-badge)](https://www.bestpractices.dev/)

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
| 🔌 **Claude Code plugin** | Ships a plugin manifest + hook config wiring `apohara-agentguard hook` to `PreToolUse`/`PostToolUse`/`UserPromptSubmit`. A `PreToolUse` block emits `permissionDecision: "deny"` and exits 2. |
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

# 5. Install as a Claude Code plugin (resolves + SHA256-verifies the binary)
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

**Subcommands:** `check <cmd>` (gate) · `sandbox --tier <t> [--workspace-root <p>] -- <cmd>` · `scan` (stdin → firewall) · `hook` (stdin event → decision) · `version`.

**Other acquisition paths.** A thin `npx apohara-agentguard` launcher resolves the release binary by platform × arch × libc; `cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked` builds from source (the supported path for musl Linux and any platform without a pinned artifact).

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
| apohara-agentguard | **0 / 73** | **0 / 33** |

The build asserts `FP == 0`, `FN == 0`, and `FN < naive FN` — the corpus is **not** tuned to make it pass; a benign Block or a missed danger is a real bug.

> [!NOTE]
> The corpus is **author-curated and 100% synthetic** (73 benign + 33 dangerous), and the dangerous set _deliberately_ includes the obfuscation constructs apohara-agentguard is built to catch — so the FN gap is a demonstration of the design, not a neutral sample. No real agent session is committed or used. Reproduce it yourself:
> ```sh
> cargo test benchmark -- --nocapture
> ```
> The full honest scorecard — per-layer catch/miss, latency percentiles, and the **external** Tensor Trust human-attack benchmark (where the firewall misses 94.8%, the documented motivation for a v0.3 semantic tier) — lives in [BENCHMARK.md](BENCHMARK.md).

**Kill-switch.** apohara-agentguard ships an all-or-nothing emergency kill-switch so a fail-closed bug can never brick your Bash tool: `export AGENTGUARD_DISABLE=1` (or `disable = true` in the config) immediately allows everything and exits 0, disabling the gate, path-guard, **and** firewall together. It is read from the **hook process's** environment, not the inspected command's — a malicious Bash command that sets `AGENTGUARD_DISABLE=1` runs in a _different_ process and **cannot self-disarm** the gate. A granular form (`AGENTGUARD_DISABLE=gate,firewall`) is a planned v0.2 follow-up.

**Release integrity (signed binaries).** The release binaries are **signed and carry a build-provenance attestation** generated keylessly in CI (Sigstore + GitHub OIDC). This is **SLSA v1.0 Build Level 2 — not Level 3.** Per GitHub's docs: _"Artifact attestations by itself provides SLSA v1.0 Build Level 2."_ Verify a downloaded binary with the GitHub CLI:
> ```sh
> gh attestation verify <downloaded-binary> -R SuarezPM/apohara-agentguard
> ```
> A non-zero exit means the binary is unsigned, tampered with, or not built by this repo — don't run it. The release workflow runs this same check over every target as an E2E gate. **SLSA Build L3** (a hardened reusable-workflow refactor) is a documented **v0.3 follow-up**, not a current claim.

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
│   │   └── taxonomy.rs      # verb-aware destructive taxonomy
│   ├── hook/                # Claude Code hook contract + path-guard
│   ├── sandbox/linux/       # seccomp-bpf + Landlock jail (fail-closed)
│   ├── firewall/            # prompt-injection firewall + SSRF re-fetch
│   ├── verdict.rs           # 3-tier Allow / Warn / Block model
│   └── main.rs              # clap CLI: check · sandbox · scan · hook · version
├── tests/                   # incl. committed FP/FN gate + evasion regression net
├── benches/                 # ReDoS guard for the rule regexes
├── fuzz/                    # cargo-fuzz target over gate::evaluate
└── packaging/               # Claude Code plugin manifest, hooks, npx + install.sh
```

---

## 🗺️ Roadmap

- [x] Anti-bypass command gate (structural Bash parsing + normalization pre-pass)
- [x] seccomp + Landlock sandbox (fail-closed, three permission tiers)
- [x] Prompt-injection input firewall (SSRF-guarded out-of-band re-fetch)
- [x] `cargo-fuzz` target over `gate::evaluate`
- [x] Committed FP/FN precision gate (`0 / 73`, `0 / 33`)
- [x] Claude Code plugin packaging (manifest + hooks + verified installers)
- [x] Signed release binaries with build-provenance attestation (SLSA Build **L2**)
- [ ] SLSA Build **L3** via a reusable-workflow refactor (v0.3 follow-up)
- [ ] Publish to crates.io + the Claude Code plugin marketplace
- [ ] MCP tool form (expose the gate/firewall as MCP tools)
- [ ] Granular kill-switch (`AGENTGUARD_DISABLE=gate,firewall`)
- [ ] musl Linux release binaries

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
