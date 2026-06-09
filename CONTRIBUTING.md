# Contributing to apohara-agentguard

Thanks for considering a contribution. apohara-agentguard is a security tool, so two
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

The three subcommands are also the quickest way to exercise a change by hand: the
**gate** (`cargo run -- check 'x=rm; $x -rf ~'`), the **sandbox**
(`cargo run -- sandbox --tier workspace_write -- cargo build`, Linux only), and
the **firewall** (`echo "untrusted text" | cargo run -- scan`).

## Quality gate

Every commit MUST keep the following green. CI enforces all of them; please run
them locally before opening a PR:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --benches            # the ReDoS bench is a regression gate
cargo deny check licenses       # dependency-license allowlist
cargo deny check advisories     # RUSTSEC advisories
```

Pull requests that break `cargo test`, introduce clippy warnings, or relax the
`0-FP / 0-FN` benchmark will not be merged.

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

## Coding standards

The project's **required coding style is enforced automatically**, so there is no
style guide to memorize:

- **Formatting:** `rustfmt` with the repository defaults (`cargo fmt`). All code
  MUST be `rustfmt`-clean; CI runs `cargo fmt --check`.
- **Linting:** `clippy` with **warnings denied**
  (`cargo clippy --all-targets -- -D warnings`). Contributions MUST be
  clippy-clean; CI denies any warning (`RUSTFLAGS: "-D warnings"`).
- **Language:** code and comments are in **English**; comment the *why*, not the
  *what*. A new firewall rule carries an `fp_risk` note (what benign content
  could match and why the severity is set where it is).

Because both tools run in CI and are required to pass, compliance is checked on
every change rather than left to reviewer discretion.

## Testing policy

Tests are part of the change, not an afterthought:

- **Major new functionality MUST add tests** to the automated suite in the same
  change. A feature without tests is not considered complete and will not be
  merged. A new gate/firewall rule MUST ship fixtures in **both directions** (a
  positive case that Blocks/Warns and a benign negative that Allows) — see *Adding
  a destructive taxonomy rule* and *Adding a firewall rule* above.
- **Bug fixes SHOULD add a regression test** that fails before the fix and passes
  after, so the bug cannot silently return.
- The automated suite runs **on every push and pull request** (CI, across
  Linux/macOS/Windows) and reports success/failure; a red suite blocks the merge.
- Precision is **measured, not asserted** — the FP/FN benchmark
  (`tests/benchmark.rs`) asserts **`0` false positives and `0` false negatives**
  on the curated corpus; a benign command that Blocks or a missed danger is a real
  bug to fix, **not a number to relax**.

Statement coverage is measured with
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)
(`cargo llvm-cov --summary-only`); see
[`docs/best-practices-silver.md`](docs/best-practices-silver.md) for the current
figure.

## Pull requests

The `main` branch is **protected**: it cannot be pushed to directly, and
force-push and branch deletion are disabled. Every change — including the
maintainer's — lands through a pull request that **must pass the full CI suite**
(rustfmt, clippy `-D warnings`, `cargo-deny` licenses + advisories, the
clean-install independence gate, the default-build purity guard, and the test
matrix on Linux/macOS/Windows) before it can be merged.

- Keep changes focused; one logical change per PR.
- Update [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]` when your change is
  user-visible.
- Code and comments are written in English. Comment the *why*, not the *what*.

### Conventional Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `bench:`, `ci:`, etc.
This keeps the history machine-readable and drives the changelog.

### Developer Certificate of Origin (DCO)

By contributing, you certify the [DCO](https://developercertificate.org/): that
you wrote the patch or otherwise have the right to submit it under the project's
license. Sign off your commits with `git commit -s`, which appends a
`Signed-off-by:` trailer.

## License (dual-license contribution clause)

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
