# Evals — structured evaluation harness

Every security-relevant behavior gets a **case directory** with an explicit
expectation file, and one runner (`tests/eval_harness.rs`) executes them all,
computes per-component precision/recall, and fails on any mismatch. This is the
characterization net: a refactor that shifts a pinned verdict turns a case red
instead of passing silently.

## Layout

```
evals/
  README.md                      this file
  gate/cases/<case-id>/          anti-bypass command gate
    input.txt                    raw command string, single line
    _expected.json               expectation (schema below)
  firewall/cases/<case-id>/      prompt-injection firewall
    input.txt                    prompt/content text, may be multiline
    _expected.json
  policy/cases/<case-id>/        TOML policy engine
    input.json                   HookInput JSON payload
    policy.toml                  the policy under test for this case
    _expected.json
```

Run:

```sh
cargo test --test eval_harness -- --nocapture   # --nocapture shows the summary table
```

## `_expected.json` schema

Common fields:

```json
{
  "expected_tier": "block",       // required: "block" | "warn" | "ask" | "allow"
  "reason_contains": "<optional substring that must appear in the verdict reason>",
  "notes": "<free text, ignored by the runner>"
}
```

Component-specific optional fields:

- **firewall** — `"surface"`: which posture to apply. One of `user_prompt`
  (default), `bash_stdout`, `read_file`, `web_fetch`, `web_search`. WARN-only
  surfaces (`user_prompt`, `bash_stdout`) clamp Block down to Warn, so an
  injection on `user_prompt` expects `"warn"` while the same text on
  `read_file` expects `"block"`. Content is always scanned inline (hermetic;
  no fetch happens).
- **policy** — `"repeat"`: evaluate the input N times against the same loaded
  `PolicySet` (default 1). Budget counters accumulate across repeats, so a
  budget-exhaustion case uses `"repeat": 2` with a cap of 1 and expects `"ask"`.
  A malformed `policy.toml` is pinned as `"block"`: load errors are fail-closed,
  exactly like the hook dispatcher.

## How to add a case

1. Create `evals/<component>/cases/<case-id>/` (kebab-case id).
2. Add the input file(s) shown above.
3. Add `_expected.json` with the tier the component returns **today** if you are
   pinning existing behavior, or the tier it **must** return if you are writing
   a spec-first case (the runner will stay red until the code catches up).
4. Run the harness. If your expectation disagrees with reality, the mismatch
   line names the case id, expected vs actual tier, and the reason substring
   that did not match.

Rules of thumb:

- Draw inputs from behaviors already proven elsewhere (unit/integration tests)
  so cases document reality rather than guesses.
- One behavior per case; put the "why" in `notes`.
- Do not delete or weaken a failing case to make the suite green — a mismatch
  is either a real regression or a deliberate behavior change that deserves a
  visible spec update in the same commit.

## Summary output

The runner prints, per component: total / matched / mismatches, plus
precision and recall over the binary **flagged** view (`block`/`warn` count as
flagged; `ask`/`allow` do not). It then asserts zero mismatches.
