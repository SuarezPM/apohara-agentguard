# Architecture

apohara-agentguard is one self-contained Rust binary that ships as a Claude Code plugin.
It combines four independent, deterministic defenses behind a single hook
contract: a **command gate**, a **path-guard**, a Linux **seccomp + Landlock
sandbox**, and an **injection firewall**. This document describes the design and,
where a choice is load-bearing, *why* it is the way it is.

It is a **total reimplementation in Rust** — see
[Independence](#independence-total-reimplementation).

## Request flow

```text
                 Claude Code tool event (JSON on stdin)
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  hook::run (dispatch)   │
                    │  kill-switch checked    │
                    │  FIRST (env or config)  │
                    └────────────┬────────────┘
            ┌────────────────────┼─────────────────────────────┐
            ▼                    ▼                              ▼
   PreToolUse + Bash     PreToolUse + Read/Write/Edit   PreToolUse + WebFetch/Search
        │                       │                              │
        ▼                       ▼                              ▼
  gate::evaluate          pathguard::check_path          firewall::scan_surface
  (Allow/Warn/Block)      (then, for Read, a             (out-of-band re-fetch +
        │                  firewall CONTENT scan)         SSRF guard, then scan)
        │                       │                              │
        └───────────────────────┴──────────────┬───────────────┘
                                                ▼
                              audit_decision (best-effort, Block/Warn only)
                                                │
                                                ▼
                       contract::emit  →  (stdout JSON, exit code)
                  Allow → (none, 0)   Warn → additionalContext, 0
                  Block(PreToolUse) → permissionDecision=deny, exit 2

   PostToolUse + Bash  → firewall scan of stdout (WARN-only; cannot block)
   UserPromptSubmit    → firewall scan of prompt (WARN-only; exit 2 erases it)

   apohara-agentguard sandbox <cmd>  (separate subcommand, Linux)
        │ two forks → grandchild (PID 1 in new namespaces)
        ▼
   NO_NEW_PRIVS  →  Landlock  →  seccomp (LAST)  →  execvpe
```

## The 3-tier verdict model

Every component returns the same [`Verdict`](src/verdict.rs): a `Tier` plus a
reason and optional agent-facing feedback.

| Tier      | Meaning                                  | Hook effect (PreToolUse)        |
|-----------|------------------------------------------|---------------------------------|
| **Allow** | permit the action                        | no output, exit 0               |
| **Warn**  | permit, but surface a caution            | `additionalContext`, exit 0     |
| **Block** | refuse the action                        | `permissionDecision=deny`, exit 2 |

The tier is derived from a numeric **severity** via `severity_to_tier`, using
`Thresholds { block_at, warn_at }` (defaults: `sev >= 8` → Block, `5..=7` →
Warn, else Allow). Severity is the single tunable spine: a destructive taxonomy
rule, a custom block, or a firewall rule each carries a severity, and the worst
(max) hit wins. This is what makes the model **deterministic, not AI**: the same
input always yields the same verdict.

## Command gate pipeline (pinned order)

`gate::evaluate` runs a fixed, ordered pipeline. The order is load-bearing —
each stage assumes the previous one's output.

1. **Kill-switch** (`config.disable`) → immediate Allow.
2. **Allow-list short-circuit on the RAW command.** The allow-list matches the
   *user-authored* text, never a rewritten form, so a user's explicit "yes, this
   exact command is fine" can never be undermined by normalization.
3. **Normalize pre-pass** (if `config.normalize`, the default) — an *in-place
   textual splice* over one shared buffer so the passes compose:
   1. **line-continuation join** (`\<newline>` → ``) — `r\<nl>m` becomes `rm`.
   2. **ANSI-C `$'…'` decode** — `$'\x72\x6d'` is decoded to `rm` in place.
   3. **echo/printf command-substitution splice (leg-head/verb position only)** —
      `$(echo rm) -rf ~` becomes `rm -rf ~`. It fires *only* in verb position, so
      an argument-position substitution (`git commit -m "$(echo rm)"`) is left
      untouched — that is the difference between closing an evasion and creating a
      false positive.
   4. **IFS reassignment** — records an `IFS=<char>` as an extra top-level
      separator (no splice yet); applied later, *gated on surfacing a hit*.

   **Why a splice, not a tokenizer?** Each pass writes the decoded text
   contiguously where the construct stood, producing a normal command line that
   the existing splitter tokenizes exactly as a hand-typed command. This keeps
   four small, independently-testable, bounded pure functions instead of a full
   bash grammar (irregular, ReDoS-adjacent, a large dependency). Bounds:
   64 KiB buffer, ≤ 64 splices, per-span 4× expansion cap. A grammar-based
   tokenizer is the deferred upgrade path if the evasion set ever grows large
   enough to justify it.
4. **Pre-split fetch-pipe analysis** — `curl … | sh` is a *pipe relationship*
   that disappears once the command is split into legs, so it is analysed on the
   whole (normalized) command. Fork bombs are detected pre-split for the same
   reason (`:(){ :|:& };:` spans `;`/`|`/`&`).
5. **Pre-split base64 decode/rescan** — `echo <b64> | base64 -d | sh` is also a
   pipe relationship; the payload is decoded (bounded recursion) and re-split.
6. **Split into legs** (`split_compound`, with the IFS extra-separator set).
7. **Resolve variable assignments** — `x=rm; $x -rf ~` → the resolved leg.
8. **Per-leg taxonomy (verb-aware) + custom blocks**, with bounded per-leg base64
   decode-and-rescan. Verb-awareness computes an *effective match text*: for a
   non-executing verb the quoted argument spans are stripped (data, not command);
   for an executing verb they are kept (it runs them). Anything not clearly
   non-executing is treated as executing — **fail toward Block**, preserving
   false-negative resistance.
9. **Gated IFS re-split** — only folded in if re-splitting on the recorded IFS
   char actually surfaces a Block-tier hit, so a benign `IFS= read` loop is never
   mangled into a false positive.
10. **Max severity → tier** via the thresholds.

## Hook contract

The hook reads the event JSON on stdin and emits a decision as the **nested
`hookSpecificOutput`** shape required by Claude Code (a bare top-level
`additionalContext` is ignored by the harness). Output is always
serde-serialized, never string-concatenated, and every free-text field is capped
at 4096 bytes.

- **PreToolUse** uses `permissionDecision` (`allow`/`deny`/`ask`) +
  `permissionDecisionReason`. A Block sets `permissionDecision: "deny"` **and**
  exits 2 (belt-and-suspenders; exit 2 is the effective enforcement signal).
- **PostToolUse** cannot block — a Block gracefully downgrades to a Warn
  (`additionalContext`, exit 0).
- **UserPromptSubmit** can technically block, but exit 2 there *erases the
  prompt*, so apohara-agentguard only ever Warns (downgrade to `additionalContext`,
  exit 0).
- **Malformed input fails OPEN** (allow): a schema surprise must never brick the
  user's tools. The kill-switch is checked *before* any parsing.

## Sandbox: the pinned install order

The Linux sandbox runs the target command in a **grandchild** after two forks
(so the grandchild is PID 1 in a new PID namespace — `unshare(CLONE_NEWPID)`
only affects *future* children). In that grandchild, after redirecting stdio,
`chdir`, and closing stray fds, three confinement steps run in a **strictly
pinned order**:

```text
1. prctl(PR_SET_NO_NEW_PRIVS, 1)   ← first
2. Landlock ruleset (restrict_self) ← second
3. seccomp-bpf filter install       ← LAST
```

**Why this exact order (the EPERM-collision rationale):**

- **NO_NEW_PRIVS must be first** because Landlock's `restrict_self(2)`
  *requires* it. (seccompiler would also set NNP internally, but seccomp now
  runs last, so the runner sets NNP explicitly up front.)
- **seccomp must be LAST.** The Landlock syscalls
  (`landlock_create_ruleset` / `add_rule` / `restrict_self`, numbers 444–446)
  are deliberately **absent from every seccomp allowlist**. If seccomp were
  installed first, its `mismatch_action = EPERM` would EPERM those
  un-allowlisted Landlock syscalls, Landlock setup would fail, and — because
  setup failure **fails closed** — apohara-agentguard would refuse *every* run, even on
  a fully capable kernel. Ordering seccomp last (rather than allowlisting
  444–446) is the deliberate choice: it means **no Landlock syscall is callable
  by the child after setup**, so the child cannot weaken its own ruleset. The
  Landlock errno taxonomy even self-diagnoses a violation: an EPERM on a
  Landlock syscall maps to "internal: seccomp installed before Landlock
  (ordering bug)".

**Network denial by omission.** No tier allowlists `socket`, `connect`, `bind`,
`listen`, `accept`/`accept4`, `sendto`, or the 32-bit `socketcall`. Without a way
to create a network fd, the child can never reach the network — even
`recvfrom`/`sendmsg` (allowed for cargo's local `socketpair(AF_UNIX)` jobserver)
cannot touch it, because `socketpair(AF_INET)` is unsupported by the kernel. The
seccomp filter uses `mismatch_action = EPERM` (a recoverable errno to the child)
rather than SIGSYS-killing it.

**Fail-closed.** Any setup failure — namespace, Landlock (kernel too old /
disabled at boot), seccomp install — makes the grandchild `_exit` with a setup
error and the sandbox refuses; it never falls back to running unconfined. The two
post-fork abort vectors that once existed (`unreachable!` in the Landlock builder
and after `execvpe`) were removed in favor of propagated errors / a direct
`_exit`, because a panic across a forked address space is the most dangerous
failure mode.

**`danger_full_access`** skips Landlock *and* seccomp entirely (full host
access). It requires `--i-know-what-im-doing`, prints a loud multi-line stderr
warning naming "NO seccomp" and "NO Landlock" and "FULL host access", and records
the invocation to the audit log when enabled.

## Firewall surfaces + posture

`scan_content` is **surface-agnostic**: it scores text (max severity over the DJL
+ OWASP `RegexSet` pre-match plus the two-stage rules) and never decides posture.
`scan_surface` wraps it with **per-surface posture**:

- **Read / WebFetch / WebSearch** (PreToolUse) are **BLOCK-capable**: content is
  obtained **out-of-band** via the `ContentSource` (SSRF / size / timeout
  controls inside `refetch`), then scanned. An SSRF refusal is a hard Block
  *without fetching*; a fetch timeout / I/O error **fails closed to Warn** (never
  hangs, never silently allows).
- **UserPrompt** and **BashStdout** are **WARN-only** — a Block is clamped to
  Warn (exit 2 on UserPromptSubmit erases the prompt; PostToolUse runs after the
  tool and cannot block).

## Independence (self-contained)

apohara-agentguard is **a fully self-contained, dependency-free implementation** (no
external policy engine, no shared runtime, no network at scan time) — no link, no
path dependency, and no vendored code. The destructive taxonomy, the DJL/OWASP
rule sets, the verdict spine, and the path utilities are all implemented in-tree
(e.g. `canonicalize_recursive` in `src/sandbox/pathsafe.rs` is a from-scratch
path resolver). The project is
dual-licensed **MIT OR Apache-2.0** (`LICENSE-MIT` + `LICENSE-APACHE`, no single
`LICENSE`); third-party dependency licenses are enumerated in
`THIRD-PARTY-LICENSES` and gated by `cargo deny check licenses`.
