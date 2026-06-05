# apohara-agentguard demo script

This is the **script** for the bypass-resistance demo. Recording (asciinema /
video) is done separately; this file is just the commands and the expected
output so the demo is reproducible.

All commands assume a release build:

```sh
cargo build --release
BIN=./target/release/apohara-agentguard
```

---

## Part 1 — Anti-bypass gate vs. a naive regex

The differentiator: three obfuscated destructive commands that a naive
fixed-list regex gate (substring-match a list like `rm -rf`, `mkfs`, …) treats as
**safe**, while apohara-agentguard **blocks** all three.

### Block 1 — variable-assignment resolution

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x=rm; $x -rf ~"}}' \
  | $BIN hook ; echo "exit=$?"
```

Expected: `permissionDecision":"deny"` in the JSON, **exit 2**.
A naive regex never sees the literal `rm -rf` because the verb is hidden behind
`$x`. apohara-agentguard resolves the `x=rm` assignment across compound legs first.

### Block 2 — base64 decode + rescan

```sh
# cm0gLXJmIH4K is base64 for "rm -rf ~"
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo cm0gLXJmIH4K | base64 -d | sh"}}' \
  | $BIN hook ; echo "exit=$?"
```

Expected: **deny / exit 2**.
A naive regex sees only `echo`, `base64`, `sh` — all benign. apohara-agentguard decodes
the literal base64 payload and rescans the decoded `rm -rf ~`.

### Block 3 — `find -delete`

```sh
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"find . -delete"}}' \
  | $BIN hook ; echo "exit=$?"
```

Expected: **deny / exit 2**.
`find . -delete` contains no `rm` at all; a fixed `rm`-centric list misses it
entirely. apohara-agentguard's destructive taxonomy includes `find … -delete`.

### Side-by-side proof

`tests/headline_bypass.rs` asserts a naive fixed-list matcher returns *Safe* for
all three while `apohara_agentguard::gate::evaluate` returns *Block*. Run it live:

```sh
cargo test --test headline_bypass -- --nocapture
```

---

## Part 2 — Sandbox: seccomp network-deny (Linux)

Show that a sandboxed command cannot open a network socket — the seccomp filter
default-denies and returns `EPERM`.

```sh
# Outside the sandbox: curl reaches the network.
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com   # e.g. 200

# Inside the sandbox: the connect is denied (EPERM), curl fails.
$BIN sandbox --tier workspace_write --workspace-root "$PWD" -- \
  curl -sS https://example.com ; echo "exit=$?"                 # non-zero
```

Expected: the sandboxed `curl` fails (no network); the unsandboxed one succeeds.

---

## Part 3 — Sandbox: Landlock `/etc/passwd`-deny (Linux)

Show real filesystem confinement: a command confined to the workspace can read
and write **inside** it, but **cannot** read `/etc/passwd` or your SSH key.

```sh
# (a) read+write INSIDE the workspace SUCCEEDS — proves confinement is active,
#     not vacuously passing on a refused run.
$BIN sandbox --tier workspace_write --workspace-root "$PWD" -- \
  bash -c 'echo ok > ./inside.txt && cat ./inside.txt' ; echo "exit=$?"   # exit 0, prints "ok"

# (b) reading OUTSIDE the workspace is DENIED by Landlock.
$BIN sandbox --tier workspace_write --workspace-root "$PWD" -- \
  cat /etc/passwd ; echo "exit=$?"                                        # non-zero (denied)

$BIN sandbox --tier workspace_write --workspace-root "$PWD" -- \
  cat "$HOME/.ssh/id_rsa" ; echo "exit=$?"                                # non-zero (denied)
```

Expected: (a) succeeds and prints `ok`; (b) both fail because Landlock confines
reads to `workspace_root`.

On a kernel without Landlock, every sandbox run instead **refuses** (fail-closed)
with an actionable message:
- `ENOSYS` → "kernel too old (need Linux ≥ 5.13 for Landlock)"
- `EOPNOTSUPP` → "Landlock disabled at boot; add `lsm=landlock` to the kernel cmdline"

---

## Part 4 — Kill-switch

Show the emergency bypass: with `AGENTGUARD_DISABLE=1` even an obviously
destructive command is allowed (exit 0), so a fail-closed bug can't lock you out.

```sh
AGENTGUARD_DISABLE=1 sh -c \
  'echo "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf ~\"}}" | '"$BIN"' hook' \
  ; echo "exit=$?"
```

Expected: no decision JSON, **exit 0** (hook disabled).
