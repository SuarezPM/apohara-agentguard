# apohara-agentguard fuzzing

`cargo-fuzz` (libFuzzer) harness that hardens the gate's core soundness claim
("parser-bounded"): the gate must **never panic / never hang** on arbitrary
input, and it must **always surface a real destructive leg**.

This is a **separate crate** (its own `[workspace]`) so it never enters the main
build graph — `cargo build` / `cargo test` at the repo root are unaffected, and
the nightly-only flags libFuzzer needs never leak into the stable workspace.

## Target

- `gate_evaluate` — drives arbitrary bytes (lossy → `&str`) through the exact
  pipeline the live hook uses: `gate::normalize::normalize_command` →
  `gate::compound::split_compound` → `gate::evaluate(s, &Config::default())`.

### Invariants

1. **Never panic / never hang** (implicit, primary). libFuzzer reports any
   panic as a crash and enforces its own timeout, so exercising the gate on
   adversarial UTF-8 proves the never-abort contract that "parser-bounded"
   rests on.
2. **A real `rm -rf <path>` leg is never Allowed** (explicit, conservative).
   Asserting this on arbitrary input would crash on benign inputs, so the check
   is *constructed*: the harness splices a known-dangerous, unquoted
   `rm -rf <path>` leg (as its own `;`-separated top-level leg) onto sanitized
   fuzzer bytes, then asserts the verdict is never `Tier::Allow`. The fuzzer may
   mutate the prefix/path freely, but the destructive verb+flags+target shape
   is fixed, so the gate's surfacing contract must hold.

## Requirements

- A **nightly** toolchain: `rustup toolchain install nightly`
- `cargo-fuzz`: `cargo install cargo-fuzz`

## Run

From the **repo root**:

```sh
# Build the target (compile-only smoke check).
cargo +nightly fuzz build gate_evaluate

# Bounded campaign (60 seconds). Should complete with zero crashes.
cargo +nightly fuzz run gate_evaluate -- -max_total_time=60

# Open-ended campaign (Ctrl-C to stop).
cargo +nightly fuzz run gate_evaluate
```

A crash is written to `fuzz/artifacts/gate_evaluate/`. Reproduce with:

```sh
cargo +nightly fuzz run gate_evaluate fuzz/artifacts/gate_evaluate/<crash-file>
```

If the fuzzer finds a real panic in the gate, that is a genuine bug — fix the
underlying gate, do not weaken the target.

## Compile-only fallback

If nightly / cargo-fuzz cannot be installed, the target is still structurally
valid and can be checked with `cargo +nightly fuzz check` once a nightly is
present. The bounded 60s run is the preferred path and is what CI / handoff
executes.
