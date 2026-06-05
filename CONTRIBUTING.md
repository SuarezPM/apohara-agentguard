# Contributing to agentguard

Thanks for considering a contribution. agentguard is a security tool, so two
rules are non-negotiable: **the build stays green** and **every claim is
code-verifiable** (no doc or README assertion ships without a test that pins it).

## Build, test, lint

```sh
cargo build                              # build the binary + library
cargo test                               # all unit + integration tests
cargo test --benches                     # also run the harness=false benches
                                         #   (regex_redos as a regression gate)
cargo clippy --all-targets -- -D warnings   # lints are errors
cargo fmt --check                        # formatting must be clean
cargo deny check licenses                # dependency-license allowlist
```

A change is not done until `cargo test`, `cargo test --benches`,
`cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass.

### Fuzzing (nightly)

The gate has a `cargo-fuzz` target over `split_compound` + `gate::evaluate`. It
lives in a separate `fuzz/` crate (outside the default workspace), so it does not
affect `cargo build`/`cargo test`.

```sh
rustup toolchain install nightly         # one-time
cargo install cargo-fuzz                 # one-time
cargo +nightly fuzz run gate_evaluate -- -max_total_time=60   # a 60s campaign
```

The target enforces two invariants: the gate never panics on any input, and a
clearly-destructive `rm -rf` leg always surfaces/Blocks. A crash is a real bug.
When nightly/cargo-fuzz is unavailable, `cargo +nightly fuzz build` (compile-only)
is the documented fallback.

## Adding a destructive taxonomy rule (the command gate)

Destructive command rules live in [`src/gate/taxonomy.rs`](src/gate/taxonomy.rs).

1. Add a matcher `fn m_<name>(s: &str) -> bool` (use the `re!` macro for a
   compile-constant regex; **no nested quantifiers** — the ReDoS bench guards
   sub-ms matching).
2. Register a `DestructiveRule { id, severity, category, matcher }` in `rules()`.
   Severity drives the tier: clearly destructive ⇒ `>= 8` (Block), ambiguous ⇒
   `5..=7` (Warn).
3. **Required fixtures (both directions):**
   - **Positive:** the dangerous form Blocks (add to `tests/corpus/dangerous.txt`
     and/or a unit test in `taxonomy.rs`).
   - **Negative:** a *benign* lookalike Allows (add to `tests/corpus/benign.txt`
     and/or `tests/gate_fp.rs`). State the **false-positive risk** of your regex
     in a comment — what benign command might it bite, and why it does not.
4. If the rule interacts with verb-awareness (executing vs. non-executing
   verbs), add a case to both `effective_text_*` tests.

The FP/FN benchmark (`tests/benchmark.rs`) asserts **0% FP and 0% FN on the
curated corpus**; a benign command that Blocks is a real bug to fix, not a number
to relax.

## Adding a firewall rule

Firewall rules live in [`src/firewall/djl.rs`](src/firewall/djl.rs) (the 78 DJL
rules) and [`src/firewall/owasp.rs`](src/firewall/owasp.rs) (the OWASP ASI
patterns); lookaround patterns the Rust `regex` crate cannot compile go through
[`src/firewall/two_stage.rs`](src/firewall/two_stage.rs).

1. Add the rule with a stable `id`, a `severity`, a `category`, and — for DJL
   rules — an **`fp_risk`** note describing what benign content could match and
   why the severity is set where it is.
2. **Required fixtures (both directions):** a positive case that Blocks/Warns and
   a benign negative case that Allows (extend `tests/firewall_posture.rs` or the
   in-module tests).
3. If the regex needs lookaround, route it through `two_stage` (broad regex +
   Rust post-validation) — it is not expressible in the shared `RegexSet`.

## Honesty rule (mandatory)

**When you change gate/firewall/sandbox behavior, update the honesty net in the
SAME change:**

- If you close (or open) a gate evasion, update
  [`tests/gate_evasions.rs`](tests/gate_evasions.rs) so it *pins the new
  reality* (Block vs. Allow/incidental), **and** update the README "Now caught
  (v0.1.x)" / "Still out of scope" lists. The `tests/readme_sync.rs` test
  asserts these two stay consistent — a drift fails the build.
- If you change the threat model, update `SECURITY.md` so its "Covers / does NOT
  cover" still matches reality.
- All tests must stay green (`cargo test` **and** `cargo test --benches`).

No claim ships that a test cannot back.

## License (dual-license contribution clause)

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
