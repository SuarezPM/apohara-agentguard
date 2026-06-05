# agentguard

**Stop AI coding agents from running obfuscated destructive commands — and
isolate the ones that do run.**

<!-- Badges (human-only: wire CI / crates.io / marketplace post-publish; the
     license badge is real). -->
<!-- TODO(Pablo): enable these once the repo is published. -->
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
<!-- [![CI](https://github.com/SuarezPM/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/SuarezPM/agentguard/actions) -->
<!-- [![crates.io](https://img.shields.io/crates/v/agentguard.svg)](https://crates.io/crates/agentguard) -->
<!-- [![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-orange.svg)](https://github.com/SuarezPM/agentguard) -->

**The problem.** Coding agents will happily run a shell command an attacker (or a
prompt injection) smuggled past their safety check. The common defenses both
fail: **regex blocklists are defeated by trivial obfuscation** (`x=rm; $x -rf ~`,
base64, `$(echo rm)`), and the tools that *do* pattern-match still **don't
isolate** the process — a "blocked" command that slips through has full host
access.

agentguard is one self-contained Rust binary (a Claude Code plugin) with three
capabilities:

1. **Catch obfuscated destructive commands** — a structural Bash compound parser
   with variable-assignment resolution, base64 decode-and-rescan, a bounded
   normalization pre-pass, and a verb-aware destructive taxonomy. It blocks
   bypasses naive fixed-list regex gates let through.
2. **Isolate what runs** — a local seccomp + Landlock sandbox on Linux:
   default-deny seccomp-bpf (network denied by omission, `EPERM` fail-closed)
   **and** Landlock LSM filesystem confinement to a workspace root. (Linux-only —
   see *Known limitations*.)
3. **Scan untrusted content** — a deterministic injection firewall: 78 DJL rules
   + 24 OWASP ASI patterns over prompts, fetched web content, read files, and
   command output for prompt-injection / exfiltration / harmful-content
   signatures.

## See it

The three headline bypasses, side-by-side — a naive regex blocklist (the
hookify-class fixed substring list) **lets them through**; agentguard **blocks**
all three:

```text
  command                              naive regex     agentguard
  -----------------------------------  --------------  -----------
  x=rm; $x -rf ~                       PASS (allow)    BLOCK   (variable alias resolved)
  echo cm0gLXJmIH4K | base64 -d | sh   PASS (allow)    BLOCK   (base64 decoded + rescanned)
  find . -delete                       PASS (allow)    BLOCK   (no `rm` token to key on)
```

<!-- TODO(Pablo): demo GIF here -->

## Benchmark: agentguard vs a naive regex baseline

Both engines run over the **same** corpus (73 benign + 31 dangerous commands):

| Engine | Benign (FP) | FP rate | Dangerous (FN) | FN rate |
|---|---:|---:|---:|---:|
| agentguard | 0 / 73 | 0.0% | 0 / 31 | 0.0% |
| naive regex baseline (hookify-class) | 8 / 73 | 11.0% | 11 / 31 | 35.5% |

*Provenance:* author-curated corpus, the **same** 73 benign + 31 dangerous
commands run through both engines. `dangerous.txt` deliberately includes
constructs agentguard targets (so the FN comparison is read honestly, not as a
neutral sample); the naive baseline is the hookify-class fixed substring list.
Reproduce with `cargo test benchmark -- --nocapture`.

## Docs

- [SECURITY.md](SECURITY.md) — responsible disclosure + the explicit threat model
  (what each component does and does **not** defend against).
- [ARCHITECTURE.md](ARCHITECTURE.md) — the 3-tier verdict model, the gate
  pipeline order, the hook contract, and the pinned sandbox install order.
- [CONTRIBUTING.md](CONTRIBUTING.md) — build/test/lint, how to add a rule, and
  the dual-license clause.
- [examples/agentguard.toml](examples/agentguard.toml) — a fully commented config.

## Positioning (the honest version)

agentguard is **deterministic and offline**: the scanning logic is pure regex +
structural parsing with **no model, no ML, no network call at scan time**. The
only network use is the firewall's optional out-of-band re-fetch (described
below), which is the *inspection mechanism* for web content, not part of the
scoring. Detection is **parser-bounded**: it is exactly as good as the compound
parser and the rule set, and it makes no "blocks 100% of attacks" claim. The
seccomp + Landlock sandbox is **Linux-only**; on macOS and Windows the sandbox
subcommand fails closed (refuses to run) while the gate, path-guard, and firewall
remain fully functional.

This is a structural-and-deterministic complement to model-based safety, not a
replacement for it.

## Install

### Via npx (recommended)

```sh
npx agentguard --help
```

The npm package is a thin launcher: it resolves the right release binary by
platform × arch × libc, **downloads it, verifies its SHA256 against a pinned
manifest, and refuses to run on a checksum mismatch** (a security tool must never
execute an unverified binary). musl Linux is detected and refused in v0.1 — use
`cargo install` instead.

### Via the install script

```sh
curl -fsSL https://raw.githubusercontent.com/SuarezPM/agentguard/main/packaging/install.sh | sh
```

Same checksum discipline: detects the platform, downloads, SHA256-verifies, and
places the binary under `~/.local/share/agentguard` along with the plugin/hook
config.

### Via cargo (builds from source)

```sh
cargo install --git https://github.com/SuarezPM/agentguard --locked
```

This is the supported path for **musl Linux** and any platform without a pinned
release artifact.

## Usage

### As a Claude Code hook

agentguard ships a plugin manifest (`packaging/plugin.json`) and hook config
(`packaging/hooks.json`) that wire the `agentguard hook` binary to every relevant
tool surface:

- **PreToolUse**: `Bash` (gate), `Read`/`Write`/`Edit` (secret-path guard +
  file-content firewall), `WebFetch`/`WebSearch` (out-of-band re-fetch + firewall).
- **PostToolUse**: `Bash` (scan command output, warn-only).
- **UserPromptSubmit**: scan the prompt text (warn-only).

The hook reads the event JSON on stdin and emits a decision via the nested
`hookSpecificOutput` shape. A block on a `PreToolUse` event sets
`permissionDecision: "deny"` (and also exits 2 with the reason on stderr).

Manual sanity check:

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x=rm; $x -rf ~"}}' \
  | agentguard hook ; echo "exit=$?"   # -> permissionDecision=deny, exit 2
```

### Sandbox subcommand (Linux)

```sh
# Run a command confined to the current directory with seccomp + Landlock.
agentguard sandbox --tier workspace_write --workspace-root "$PWD" -- cargo build

# Tiers: read_only | workspace_write (default) | danger_full_access
# danger_full_access installs NO seccomp filter and NO Landlock ruleset and
# REQUIRES the explicit acknowledgement flag:
agentguard sandbox --tier danger_full_access --i-know-what-im-doing -- some-command
```

On a kernel without Landlock, the sandbox **fails closed** with an actionable
message (it never runs unconfined). On macOS/Windows it refuses with a clear
message and a non-zero exit.

### Scan subcommand

```sh
echo "some untrusted text" | agentguard scan   # prints allow / warn / block
```

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
[THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES), generated by `cargo about` and
gated by `cargo deny check licenses` against an explicit allowlist.

## Known limitations

- **C1 re-fetch double-fetch and latency.** For `WebFetch`/`WebSearch` the hook
  re-fetches the URL out-of-band to scan it before the tool runs. The URL is
  therefore fetched twice (once by the hook, once by Claude), adding latency and
  load.
- **TOCTOU on web content.** The content the hook scans may differ from what
  Claude fetches on its subsequent request (a time-of-check/time-of-use gap). A
  server can serve clean content to the hook and malicious content to Claude.
- **WebSearch re-run nondeterminism.** agentguard cannot reproduce Claude's
  search backend, so it performs a best-effort plain GET against the query URL.
  Results may differ from Claude's; the load-bearing guarantee is the per-surface
  posture and the SSRF guard, not byte-identical search results.
- **SSRF mitigation (and its bounds).** The out-of-band fetcher resolves the
  hostname and **denies** the request if any resolved IP is private (RFC1918),
  loopback, link-local (`169.254.0.0/16`, `fe80::/10`), ULA (`fc00::/7`), or a
  cloud-metadata address (`169.254.169.254`). It checks the *resolved* IP (not
  the hostname) to defeat DNS rebinding, and re-checks every redirect hop.
- **seccomp + Landlock are Linux-only.** The sandbox requires **Linux ≥ 5.13 with
  Landlock enabled** (`lsm=landlock` on the kernel cmdline). On macOS/Windows the
  sandbox subcommand fails closed; the gate, path-guard, and firewall still work.

## Known evasions / out-of-scope (v0.1.x)

The command gate's soundness is parser-bounded.

**Now caught (v0.1.x).** A bounded, in-place normalization pre-pass
(`gate::normalize`) deliberately closes four forms the v0.1 gate let through —
they are spliced contiguously into the command before splitting, so the
destructive leg surfaces and Blocks:

- **ANSI-C quoting** — `$'\x72\x6d' -rf ~` (hex/octal/`\u`/named escapes are
  decoded in place).
- **Command-substitution-produced verbs** — `$(echo rm) -rf ~` and the backtick
  `` `echo rm` -rf ~ `` (a leg-head `echo`/`printf` literal substitution is
  spliced into the verb it emits; argument-position substitutions are left
  untouched, so a commit message like `git commit -m "$(echo rm -rf)"` is safe).
- **IFS reassignment** — `IFS=X; cmdXrmX-rfX~` (the recorded separator is
  word-joined into subsequent legs and re-scanned, gated on surfacing a hit so
  benign `IFS`-driven loops/`read`s never false-positive).
- **Backslash line-continuation** — `r\<newline>m -rf ~` (the continuation is
  joined).

Variable assignment (`x=rm; $x ...`) and single-level base64 decode-and-rescan
were already caught in v0.1.

The pre-pass is bounded (64 KiB buffer, ≤ 64 splices, 4× per-span expansion cap)
and can be disabled with `normalize = false` in the config if a field false
positive ever surfaces, without disabling the rest of the gate.

**Still out of scope (parser-bounded).** These remain honestly uncaught:

- **Nested / chained encoders** — hex/rot13/gzip layered beyond the single
  decode level, or word-concatenation like `` $(printf '\x72')m -rf ``.
- **Deliberate parameter expansion** — beyond the incidental cases below.
- **Real here-document parsing** — the body is matched incidentally, not parsed.
- **Non-literal command substitutions** — `$(curl ...)`-produced verbs and any
  substitution whose body is not a literal `echo`/`printf`.

Two forms are caught **incidentally** (not by deliberate construct handling, so
do not rely on them): parameter expansion with defaults (`${x:-rm}` / `${x:=rm}`)
Blocks because the literal `rm` survives in the leg and the destructive taxonomy
matches it; here-documents (`<<EOF ... EOF`) Block because the compound splitter
treats the body line as its own leg.

## Disabling / kill-switch

agentguard has an **all-or-nothing emergency kill-switch** so a fail-closed bug
can never brick your Bash tool:

```sh
export AGENTGUARD_DISABLE=1      # or: disable = true  in the config file
```

When set, the hook immediately allows everything and exits 0 — it disables the
gate, path-guard, **and** firewall together.

It is read from the **hook process's environment**, not the inspected (agent)
command's environment. A malicious Bash command that sets
`AGENTGUARD_DISABLE=1` runs in a *different* process and therefore **cannot
self-disarm** the gate. A granular form (e.g. `AGENTGUARD_DISABLE=gate,firewall`)
is a planned v0.2 follow-up.

## Demo

See [docs/demo.md](docs/demo.md) for the bypass-resistance demo script (three
obfuscated destructive commands shown side-by-side against a naive regex, plus
the seccomp network-deny and Landlock `/etc/passwd`-deny demonstrations).
