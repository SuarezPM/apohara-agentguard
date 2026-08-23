/**
 * apohara-agentguard plugin shim for OpenCode (≥1.18) and Kilo Code.
 *
 * Both harnesses load this file as a plugin and invoke its
 * `tool.execute.before` handler before every tool execution (Kilo Code's CLI
 * is an OpenCode fork: same plugin API). Plain modern JavaScript — runs under
 * Bun/OpenCode AND plain node (`node --experimental-vm-modules` not needed;
 * plain `node runner.mjs` works) so the contract tests drive it directly.
 *
 * ---------------------------------------------------------------------------
 * MUTATION-PROPAGATION CAVEAT (load-bearing, do not "fix"):
 * `tool.execute.before` receives `input.args` BY REFERENCE. In-place property
 * mutation of `input.args` propagates back to the harness; REPLACING the args
 * object (`input.args = {...}`) does NOT — the harness keeps its original.
 * This shim therefore NEVER mutates and NEVER replaces args: v1 is strictly
 * block / warn / allow. REWRITE is intentionally NOT supported through the
 * shim: the Claude-envelope rewrite channel (`updatedInput`) has different
 * mutation semantics than in-place arg editing, and bridging the two safely
 * (in-place arg rewrite) is a U2′ follow-up if demanded.
 *
 * Throwing from this handler blocks the tool BEFORE permission evaluation,
 * which makes the block YOLO-immune (auto-approve modes cannot wave it
 * through).
 *
 * Budget note: the ≤50ms p99 plan budget applies to the SHIM-side overhead.
 * The spawned hook child gets a generous internal timeout (default 500ms,
 * override with AGENTGUARD_SHIM_TIMEOUT_MS) so a cold binary start never
 * turns into a spurious block.
 * ---------------------------------------------------------------------------
 */

import { spawnSync } from "node:child_process";

/** Default child timeout (ms) — generous; the shim-side budget is separate. */
const DEFAULT_TIMEOUT_MS = 500;

/**
 * OpenCode V1 plugin entry point. Shape-compatible with the documented
 * plugin API: an (async) factory returning the hooks object.
 */
export default async function agentguardPlugin() {
  return {
    tool: {
      execute: {
        before: toolExecuteBefore,
      },
    },
  };
}

/**
 * `tool.execute.before` handler.
 *
 * @param {{ tool: string, args: object }} input - the pending tool call.
 * @param {{ sessionID?: string }} [context] - plugin call context.
 * @returns {Promise<undefined>} undefined when the tool may proceed (Allow,
 *   or Warn after mirroring the warning to stderr). Never returns a value:
 *   returning one would imply arg mutation, which v1 does not do.
 * @throws {Error} `blocked by agentguard: <reason>` when the engine denies
 *   (exit 2 or nested permissionDecision deny — and ask, degraded, see
 *   below), or `agentguard unavailable — failing closed (...)` when the
 *   engine itself could not be consulted (timeout / spawn error / crash).
 */
export async function toolExecuteBefore(input, context) {
  // 1. Build the canonical Claude PreToolUse envelope our hook binary reads
  //    on stdin. Serialization failure (e.g. circular args) fails CLOSED.
  let payload;
  try {
    payload = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: input?.tool ?? null,
      tool_input: input?.args ?? null,
      cwd: process.cwd(),
      session_id: context?.sessionID ?? null,
    });
  } catch (e) {
    throw new Error(
      `agentguard unavailable — failing closed (cannot serialize tool args: ${
        e?.message ?? e
      })`,
    );
  }

  const bin = process.env.AGENTGUARD_BIN || "apohara-agentguard";
  const timeout = parseTimeoutMs(process.env.AGENTGUARD_SHIM_TIMEOUT_MS);

  // 2. Spawn-per-call: `apohara-agentguard hook` reads the envelope on stdin
  //    and answers with exit code + nested decision JSON.
  let res;
  try {
    res = spawnSync(bin, ["hook"], {
      input: payload,
      encoding: "utf8",
      timeout,
    });
  } catch (e) {
    throw new Error(
      `agentguard unavailable — failing closed (spawn ${bin}: ${e?.message ?? e})`,
    );
  }

  // 3. Fail-closed triage FIRST: anything that means "we do not know the
  //    verdict" must block, never silently pass.
  if (res.error) {
    throw failClosed(bin, res);
  }
  if (res.signal) {
    // Includes the SIGTERM our own timeout sends on a hung child.
    throw failClosed(bin, res);
  }
  if (typeof res.status !== "number" || (res.status !== 0 && res.status !== 2)) {
    // Unexpected exit codes (70/74/…) mean the guard itself is unhealthy.
    throw failClosed(bin, res);
  }

  const hso = parseHookSpecificOutput(res.stdout);

  // 4. Block: exit 2 is the effective deny signal; the nested deny JSON (or
  //    stderr mirror) carries the human-readable reason.
  if (res.status === 2) {
    const reason =
      hso?.permissionDecision === "deny" && hso.permissionDecisionReason
        ? hso.permissionDecisionReason
        : firstLine(res.stderr) || "blocked (hook exit code 2)";
    throw new Error(`blocked by agentguard: ${reason}`);
  }

  // Exit 0 — honor an explicit nested decision if one is present anyway.
  if (hso?.permissionDecision === "deny") {
    throw new Error(
      `blocked by agentguard: ${hso.permissionDecisionReason || "denied"}`,
    );
  }
  if (hso?.permissionDecision === "ask") {
    // This host cannot surface an interactive approval prompt (capabilities
    // matrix: can_ask=false). Mirror the library's degrade() doctrine:
    // Ask degrades to Deny on cannot-ask hosts — never to a silent Allow.
    const reason = hso.permissionDecisionReason
      ? `requires manual approval (ask degraded to deny on this host): ${hso.permissionDecisionReason}`
      : "requires manual approval (ask degraded to deny on this host)";
    throw new Error(`blocked by agentguard: ${reason}`);
  }

  // 5. Warn ⇒ mirror to stderr and proceed. Allow ⇒ return undefined (no
  //    mutation — see the caveat above).
  if (typeof hso?.additionalContext === "string" && hso.additionalContext) {
    console.error(`[agentguard] warn: ${hso.additionalContext}`);
  }
  return undefined;
}

/** Parse the nested `hookSpecificOutput` object out of child stdout (null if absent/unparseable). */
function parseHookSpecificOutput(stdout) {
  try {
    const v = JSON.parse(stdout);
    return v && typeof v === "object" ? v.hookSpecificOutput ?? null : null;
  } catch {
    return null;
  }
}

/** Build the fail-closed error with as much diagnostic detail as we have. */
function failClosed(bin, res) {
  const detail = res.error
    ? `${res.error.code ?? ""} ${res.error.message}`.trim()
    : res.signal
      ? `terminated by signal ${res.signal} (timeout?)`
      : `unexpected exit status ${res.status}`;
  return new Error(`agentguard unavailable — failing closed (${bin}: ${detail})`);
}

/** Integer > 0 or the default. */
function parseTimeoutMs(raw) {
  const n = Number.parseInt(raw ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

/** First non-empty line of a string (stderr mirrors can be multi-line JSON). */
function firstLine(s) {
  if (typeof s !== "string") return "";
  const line = s.split("\n").find((l) => l.trim().length > 0);
  return line ? line.trim() : "";
}
