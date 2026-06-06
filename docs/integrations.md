# Integrations

apohara-agentguard's hook (`apohara-agentguard hook`) reads a tool-use event as
JSON on **stdin** and emits a decision on **stdout** plus an exit code:

- **Allow** -> no output, exit `0`.
- **Warn** -> nested `hookSpecificOutput.additionalContext`, exit `0`.
- **Block** (PreToolUse) -> nested `hookSpecificOutput.permissionDecision="deny"`
  + `permissionDecisionReason`, **exit `2`** (the effective block signal).

This contract is Claude Code's. The same single binary also plugs into
**OpenAI Codex**, which ships a Claude-compatible hook system.

---

## Claude Code

See the [Quick Start](../README.md#-quick-start) (`packaging/install.sh` or the
plugin manifest) for the canonical wiring.

---

## OpenAI Codex (PreToolUse)

> [!IMPORTANT]
> **Assumption to re-verify.** This section reflects the OpenAI Codex hooks
> documentation as of **2026-06**
> (<https://developers.openai.com/codex/hooks>). Codex's hook system is
> experimental and evolving; **re-verify the field spellings and the config
> shape against the current Codex hooks documentation** before relying on this.
> No live end-to-end Codex run is asserted here — only that a representative
> Codex-shaped payload parses and dispatches correctly through the same engine
> (see `tests/codex_hook.rs`).

Codex's PreToolUse hook deliberately mirrors Claude Code's wire format. The
documented release payload is **snake_case and identical** to the JSON
apohara-agentguard already consumes:

```json
{
  "session_id": "…",
  "turn_id": "…",
  "cwd": "/work",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5-codex",
  "permission_mode": "default",
  "tool_name": "Bash",
  "tool_use_id": "…",
  "tool_input": { "command": "rm -rf ~" }
}
```

The extra Codex fields (`turn_id`, `model`, `permission_mode`, `tool_use_id`,
`transcript_path`) are ignored — `HookInput` carries no `deny_unknown_fields`.
Codex also accepts the exact `hookSpecificOutput` deny shape and the `exit 2` +
stderr convention apohara-agentguard already emits, so **no engine change is
required**.

### Register the hook

Add a `PreToolUse` matcher group in `~/.codex/hooks.json` (or the inline
`[hooks]` table in `~/.codex/config.toml`) that pipes the event to the binary:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "apohara-agentguard hook",
            "statusMessage": "apohara-agentguard: checking command"
          }
        ]
      }
    ]
  }
}
```

Equivalent inline TOML in `~/.codex/config.toml`:

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "apohara-agentguard hook"
statusMessage = "apohara-agentguard: checking command"
```

Codex requires you to review and trust a non-managed hook before it runs — use
`/hooks` in the Codex CLI to trust the entry. A dangerous command then blocks
with `permissionDecision: "deny"` and exit 2, exactly as under Claude Code.

### Scope and limitations (honest)

- **Bash gate is the core surface and works identically** across Claude Code and
  Codex (same `tool_name: "Bash"`, same `tool_input.command`).
- **File-edit guarding does not fire on Codex.** Codex's canonical tool name for
  file edits is `apply_patch` (with `Edit`/`Write` matcher aliases), but
  apohara-agentguard's dispatch table only routes `Read`/`Write`/`Edit`. A Codex
  `apply_patch` event is not currently mapped to the pathguard surface. Treat
  Codex wiring as **Bash-command protection** today.
- **Codex output extensions are not used.** Codex supports `updatedInput` (tool
  rewrite) and a legacy `{ "decision": "block", "reason": … }` shape;
  apohara-agentguard emits only the nested `hookSpecificOutput` deny + exit 2,
  which Codex honors.
- The `AGENTGUARD_DISABLE` kill-switch is read from the **hook process env**, so
  it behaves the same regardless of which harness invokes the hook.
