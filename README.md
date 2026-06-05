# agentguard

**A deterministic, offline safety layer for AI coding agents** — it catches the
obfuscated destructive commands that regex blocklists miss, and confines the code
an agent actually runs.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
&nbsp;`offline` · `no model` · `single Rust binary` · Claude Code plugin

<!-- Real license badge above. The badges below activate AFTER the repo is
     published — left commented so we never ship a fabricated "passing" shield.
     Uncomment each as its service goes live. -->
<!-- [![CI](https://github.com/SuarezPM/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/SuarezPM/agentguard/actions) -->
<!-- [![crates.io](https://img.shields.io/crates/v/agentguard.svg)](https://crates.io/crates/agentguard) -->
<!-- [![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-orange.svg)](https://github.com/SuarezPM/agentguard) -->

<!-- demo GIF placeholder: recorded separately -->

---

## The problem

An AI coding agent will run whatever shell command ends up in its plan — including
one an attacker, or a prompt injection, smuggled past its safety check. The two
common defenses each leave a hole:

- **Regex blocklists are defeated by trivial obfuscation.** A gate that greps for
  `rm -rf` never sees `x=rm; $x -rf ~`, a base64 blob piped to `sh`, or
  `find . -delete` — there is no literal token to match.
- **Pattern-matchers don't isolate execution.** Even when a check fires, a command
  that slips through runs with full host access. Detecting danger and *containing*
  it are different jobs.

agentguard does both, and it does them without a model and without a network call
at scan time.

## What it does

Three capabilities, one self-contained binary:

**1 · Anti-bypass command gate.** It parses Bash *structure* rather than scanning
for substrings, so obfuscated compound commands surface their destructive leg.
It resolves variable aliases (`x=rm; $x -rf ~`), decodes and rescans base64
(`… | base64 -d | sh`), expands ANSI-C quotes (`$'\x72\x6d'`), evaluates live
`$(...)` inside double-quoted arguments, follows `IFS` tricks and
line-continuations, and keys on a verb-aware destructive taxonomy — so
`find . -delete` is caught with no `rm` token in sight.

**2 · Local sandbox (Linux).** A real `seccomp-bpf` + Landlock LSM jail for running
agent-generated code. Default-deny: the network is denied by omission, the
filesystem is confined to one workspace root, and it is **fail-closed** — on a
kernel without Landlock it refuses to run rather than run unconfined. Three tiers:
`read_only`, `workspace_write`, `danger_full_access`.

**3 · Prompt-injection input firewall.** Deterministic regex rules over tool
inputs and outputs — prompts, fetched web content, read files, command output —
inspected out-of-band on `PreToolUse` for injection, exfiltration, and
harmful-content signatures.

> [!NOTE]
> agentguard is a **structural, deterministic complement** to model-based safety,
> not a replacement for it. Detection is parser-bounded — exactly as good as the
> compound parser and the rule set — and it makes no "blocks 100% of attacks"
> claim. See [Known limitations](#known-limitations) and the honest
> [evasion scorecard](#known-evasions-an-honest-scorecard).

## See it in one screen

The three headline bypasses, side by side. A naive regex blocklist (the
hookify-class fixed-substring gate) **lets all three through**; agentguard
**blocks** them:

```text
  command                              naive regex     agentguard
  -----------------------------------  --------------  -----------
  x=rm; $x -rf ~                       PASS (allow)    BLOCK   (variable alias resolved)
  echo cm0gLXJmIH4K | base64 -d | sh   PASS (allow)    BLOCK   (base64 decoded + rescanned)
  find . -delete                       PASS (allow)    BLOCK   (no `rm` token to key on)
```

## Benchmark

Both engines run over the **same** author-curated corpus — 73 benign + 33
dangerous commands:

| Engine | Benign (FP) | FP rate | Dangerous (FN) | FN rate |
|---|---:|---:|---:|---:|
| **agentguard** | 0 / 73 | **0.0%** | 0 / 33 | **0.0%** |
| naive regex baseline (hookify-class) | 8 / 73 | 11.0% | 11 / 33 | 33.3% |

> [!NOTE]
> **Read this honestly.** The dangerous set *deliberately* includes the
> obfuscation constructs agentguard is built to catch, so the FN gap is a
> demonstration of the design, not a neutral sample. Both engines see the
> identical corpus. Reproduce it yourself:
>
> ```sh
> cargo test benchmark -- --nocapture
> ```

## Quickstart

agentguard is a Claude Code plugin. Pick one install path; each puts the same
`agentguard` binary on disk and wires the hook.

```sh
# 1 · npx — thin launcher, no toolchain. Resolves the release binary by
#     platform × arch × libc, verifies its SHA256 against a pinned manifest,
#     and refuses to run on a mismatch (musl Linux: use cargo, below).
npx agentguard --help

# 2 · install script — same checksum discipline; drops the binary +
#     plugin/hook config under ~/.local/share/agentguard.
curl -fsSL https://raw.githubusercontent.com/SuarezPM/agentguard/main/packaging/install.sh | sh

# 3 · cargo — builds from source. The supported path for musl Linux and any
#     platform without a pinned release artifact.
cargo install --git https://github.com/SuarezPM/agentguard --locked
```

> [!WARNING]
> A security tool must never execute an unverified binary. The npx and script
> paths SHA256-verify the download against a pinned manifest and **refuse on
> mismatch**.

Check a command through the gate:

```sh
$ agentguard check 'x=rm; $x -rf ~'
block: destructive command (variable alias resolved)   # exit 2

$ agentguard check 'git status'
allow                                                  # exit 0
```

Scan untrusted text through the firewall:

```sh
echo "some untrusted text" | agentguard scan   # prints allow / warn / block
```

Run agent-generated code in the sandbox (Linux):

```sh
# Confine a build to the current directory: seccomp + Landlock, network denied.
agentguard sandbox --tier workspace_write --workspace-root "$PWD" -- cargo build
```

> [!WARNING]
> The `danger_full_access` tier installs **no** seccomp filter and **no** Landlock
> ruleset — the command runs with your full host access. It requires the explicit
> `--i-know-what-im-doing` flag and is logged to the audit log if one is
> configured.

### As a Claude Code hook

The shipped plugin manifest (`packaging/plugin.json`) and hook config
(`packaging/hooks.json`) wire `agentguard hook` to every relevant tool surface:

- **PreToolUse** — `Bash` (gate), `Read`/`Write`/`Edit` (secret-path guard +
  file-content firewall), `WebFetch`/`WebSearch` (out-of-band re-fetch + firewall).
- **PostToolUse** — `Bash` (scan command output, warn-only).
- **UserPromptSubmit** — scan the prompt text (warn-only).

The hook reads the event JSON on stdin and emits a decision via the nested
`hookSpecificOutput` shape; a `PreToolUse` block sets `permissionDecision: "deny"`
and exits 2 with the reason on stderr. Sanity-check it by hand:

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x=rm; $x -rf ~"}}' \
  | agentguard hook ; echo "exit=$?"   # -> permissionDecision=deny, exit 2
```

## Known evasions: an honest scorecard

The gate's soundness is parser-bounded. The list below is part of the product —
knowing exactly where the boundary sits is the difference between a safety claim
and a marketing claim.

### Now caught (v0.1.x)

A bounded, in-place normalization pre-pass (`gate::normalize`) closes four forms
the v0.1 gate let through. Each is spliced contiguously into the command before
splitting, so the destructive leg surfaces and **Blocks**:

- **ANSI-C quoting** — `$'\x72\x6d' -rf ~` (hex/octal/`\u`/named escapes decoded in
  place).
- **Command-substitution-produced verbs** — `$(echo rm) -rf ~` and the backtick
  `` `echo rm` -rf ~ `` (a leg-head `echo`/`printf` literal substitution is spliced
  into the verb it emits).
- **Live command substitutions inside a double-quoted argument** — a
  `$(...)`/backtick inside a **double**-quoted argument to a non-executing verb is
  live Bash: the shell runs the body and interpolates the result, so
  `echo "$(rm -rf ~)"` and `git commit -m "$(rm -rf ~)"` really delete the home
  dir. The body is extracted and scanned as a command — `$(rm -rf ~)` Blocks,
  `$(curl … | sh)` Blocks. Only a harmless literal-emitter Allows:
  `git commit -m "$(echo rm -rf)"` is safe (the body runs `echo`, not `rm`).
  Inside **single** quotes a `$()` is literal, so
  `git commit -m 'literal $(rm -rf ~)'` is also safe.
- **IFS reassignment** — `IFS=X; cmdXrmX-rfX~` (the recorded separator is
  word-joined into subsequent legs and re-scanned — gated on surfacing a hit, so
  benign `IFS`-driven loops and `read`s never false-positive).
- **Backslash line-continuation** — `r\<newline>m -rf ~` (the continuation is
  joined).

Variable assignment (`x=rm; $x …`) and single-level base64 decode-and-rescan were
already caught in v0.1. The pre-pass is bounded (64 KiB buffer, ≤ 64 splices, 4×
per-span expansion cap) and can be disabled with `normalize = false` in the config
without disabling the rest of the gate.

### Still out of scope (parser-bounded)

These remain honestly uncaught:

- **Nested / chained encoders** — hex/rot13/gzip layered beyond the single decode
  level, or word-concatenation like `` $(printf '\x72')m -rf ``.
- **Deliberate parameter expansion** — beyond the incidental cases below.
- **Real here-document parsing** — the body is matched incidentally, not parsed.
- **Non-literal command-substitution-produced verbs** — a substitution in
  *command (verb) position* whose output is not a literal `echo`/`printf`, e.g.
  `$(curl ...) -rf ~` where fetched text becomes the verb. (A substitution in
  *argument* position inside double quotes — `echo "$(curl … | sh)"` — **is** now
  scanned and Blocks; only the verb-producing case remains out of scope.)

Two forms Block **incidentally** — as a side effect of leg matching, not by
deliberate handling, so do not rely on them: parameter expansion with defaults
(`${x:-rm}` / `${x:=rm}`) survives as a literal `rm` in the leg, and here-documents
(`<<EOF … EOF`) have their body line treated as its own leg.

## Known limitations

- **Web re-fetch is a double-fetch.** For `WebFetch`/`WebSearch` the hook
  re-fetches the URL out-of-band to scan it before the tool runs, so the URL is
  fetched twice — adding latency and load.
- **TOCTOU on web content.** The content the hook scans may differ from what the
  agent fetches next (a time-of-check/time-of-use gap): a server can serve clean
  bytes to the hook and malicious bytes to the agent.
- **WebSearch nondeterminism.** agentguard cannot reproduce the agent's search
  backend, so it does a best-effort plain `GET` against the query URL. The
  load-bearing guarantee is the per-surface posture and the SSRF guard, not
  byte-identical search results.
- **SSRF guard and its bounds.** The out-of-band fetcher resolves the hostname and
  denies the request if any resolved IP is private (RFC1918), loopback,
  link-local, ULA, or a cloud-metadata address (`169.254.169.254`). It checks the
  *resolved* IP — not the hostname — to defeat DNS rebinding, and re-checks every
  redirect hop.
- **seccomp + Landlock are Linux-only.** The sandbox needs **Linux ≥ 5.13 with
  Landlock enabled** (`lsm=landlock` on the kernel cmdline). On macOS and Windows
  the sandbox subcommand fails closed; the gate, path-guard, and firewall still
  work.

## Kill-switch

agentguard ships an all-or-nothing emergency kill-switch so a fail-closed bug can
never brick your Bash tool:

```sh
export AGENTGUARD_DISABLE=1      # or: disable = true  in the config file
```

When set, the hook immediately allows everything and exits 0 — disabling the gate,
path-guard, **and** firewall together.

It is read from the **hook process's** environment, not the inspected command's
environment. A malicious Bash command that sets `AGENTGUARD_DISABLE=1` runs in a
*different* process and therefore **cannot self-disarm** the gate. A granular form
(e.g. `AGENTGUARD_DISABLE=gate,firewall`) is a planned v0.2 follow-up.

## Documentation

| Doc | What's in it |
|---|---|
| [SECURITY.md](SECURITY.md) | Responsible disclosure + the explicit threat model — what each component does and does **not** defend against. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The 3-tier verdict model, the gate pipeline order, the hook contract, and the pinned sandbox install order. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build / test / lint, how to add a rule, and the dual-license clause. |
| [examples/agentguard.toml](examples/agentguard.toml) | A fully commented config. |
| [docs/demo.md](docs/demo.md) | The bypass-resistance demo script and the seccomp / Landlock demonstrations. |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

Third-party dependency licenses are enumerated in
[THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) (produced by `cargo about`) and gated
by `cargo deny check licenses` against an explicit allowlist.
