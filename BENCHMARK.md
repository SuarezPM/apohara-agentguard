# Benchmarks

Honest, reproducible measurements for apohara-agentguard. Two dimensions matter:
**precision** (does it block the right things?) and **latency** (what does the
user pay per tool call?). The headline tradeoff is *slower-but-more-correct than
a fixed-list regex gate* — these numbers make that explicit.

> The corpus is **author-curated and 100% synthetic** (73 benign + 33
> dangerous). The dangerous set *deliberately* includes the obfuscation
> constructs apohara-agentguard is built to catch, so the FN gap is a
> demonstration of the design, not a neutral sample. No real agent session is
> committed or used.

## Precision (FP / FN)

Source: `cargo test --test benchmark -- --nocapture`. A committed CI gate runs
the **real** gate over the **same** synthetic corpus as a naive substring
baseline (the hookify-class fixed-list gate) on every run. A false positive is a
benign command that Blocks; a false negative is a dangerous command that slips.

| Engine (same corpus)                     | Benign N | False positives | Dangerous N | False negatives |
| ---------------------------------------- | -------: | --------------: | ----------: | --------------: |
| Naive substring baseline (hookify-class) |       73 |    8 / 73 (11%) |          33 |  11 / 33 (33%)  |
| apohara-agentguard                       |       73 |      **0 / 73** |          33 |      **0 / 33** |

The build asserts `FP == 0`, `FN == 0`, and `FN < naive FN`. The corpus is **not**
tuned to make it pass; a benign Block or a missed danger is a real bug.

### Per-capability catch / miss

<!-- PLACEHOLDER (other story): per-capability catch/miss rows — e.g. variable
     aliasing, base64 smuggling, pipe-to-shell, find -delete, IFS reassignment,
     prompt-injection families. Fill with measured counts per category. -->

_TBD — filled by the per-capability breakdown story._

## Latency

Source: `cargo bench --bench hook_latency`. Measures the **end-to-end,
in-process** decision cost of `hook::run` — stdin JSON parse, event dispatch to
the gate/firewall, and verdict emission — over 10,000 iterations per scenario.
Timing is `std::time::Instant`; percentiles are nearest-rank over the sorted
sample. The LazyLock regex compilation is warmed up before measuring so it is not
charged to a single call.

Measured on a release build (Ryzen 5 3600, Zen2). Representative scenarios on the
live, no-network decision paths:

| Scenario                  | Path                 | Decision | p50         | p99         | min        | max         |
| ------------------------- | -------------------- | -------- | ----------- | ----------- | ---------- | ----------- |
| Benign Bash (`ls -la`)    | gate::evaluate       | Allow    | **1.012 µs** | **1.232 µs** | 0.982 µs   | 18.855 µs   |
| Blocked Bash (`rm -rf ~`) | gate::evaluate       | Block    | **1.643 µs** | **2.054 µs** | 1.593 µs   | 17.794 µs   |
| Injection prompt          | firewall (UserPrompt)| Warn     | **198.466 µs** | **262.026 µs** | 192.935 µs | 2.276 ms    |

The Bash gate (allow + block) costs ~1–2 µs per call — negligible against tool
execution. The firewall content scan over the full rule set is the heavier path
at ~200 µs p50 (it runs a RegexSet of ~100 patterns plus two-stage validators);
still well under a millisecond at p99, and only on prompt/content surfaces. The
`max` outliers are scheduler jitter on a shared box, not algorithmic blowup — the
[ReDoS guard](benches/regex_redos.rs) separately asserts the scan stays linear.

> Numbers are from one representative run; re-run `cargo bench --bench
> hook_latency` to reproduce on your hardware. Absolute values move with CPU and
> load; the shape (gate in single-digit µs, firewall in low hundreds of µs) is
> stable.

## TensorTrust

<!-- PLACEHOLDER (other story): results against the TensorTrust prompt-injection
     dataset — catch rate, miss rate, methodology, and honest framing of what the
     external corpus does and does not represent. -->

_TBD — filled by the TensorTrust evaluation story._
