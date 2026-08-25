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

## Coverage scorecard — what each layer catches and misses

apohara-agentguard ships several deterministic layers. Each catches a bounded
class of attack and misses the rest; publishing the boundary per layer is the
product. One row per shipped capability:

| Layer | Surface | Catches | Misses (the boundary) |
|---|---|---|---|
| **gate** (Bash command gate) | PreToolUse Bash | Structural destructive Bash via the compound parser: `rm -rf`, fork bombs, `curl … \| sh`, `find -delete`, dd-to-device, etc. — after resolving variable aliases, single-level base64, ANSI-C quotes, live `$(…)` in double quotes, `IFS` tricks, and line-continuations. 0 FN on the synthetic dangerous corpus (33/33 blocked). | What the parser does not model: nested/chained encoders (hex+rot13+gzip), non-literal command-substitution in *verb* position (`$(curl …) -rf ~`), deliberate parameter expansion, real here-doc parsing. See the README evasion scorecard for the exact list. |
| **firewall** (prompt/content injection) | UserPrompt / tool output / fetched web | The OWASP ASI default-deny set (24 patterns) + 78 severity-scored DJL rules + 3 two-stage lookaround validators — the structured, signature-bearing injection/exfiltration constructs. | Paraphrase and semantic social-engineering attacks with no fixed signature. Measured directly against human-written attacks below: **379 / 400** TensorTrust attacks are NOT blocked. This is the documented motivation for a v0.3 semantic-classifier tier. |
| **canary** (PostToolUse echo) | Tool output, opt-in | A **naive verbatim echo** of the per-session sentinel: a `contains` scan for the exact 32-hex token in tool output. | Any output transform breaks it — base64, reverse, chunking, case-fold, whitespace injection. It is **detection-after-execution, not prevention**: it never blocks and only WARNs *after* the tool has already run. Off by default. |
| **cloud pack** (opt-in) | PreToolUse Bash | `aws s3 rb --force`, any `aws <svc> delete-*` / `terminate-instances`, `gcloud … delete`, `az … delete`. 0 FP / 0 FN on its corpus. | Intentionally allows read-only / non-destructive look-alikes: `aws s3 ls\|cp\|sync`, `aws … describe-*`, `gcloud … list\|describe`, `az … list\|show`. |
| **db pack** (opt-in) | PreToolUse Bash | `DROP TABLE` (incl. `IF EXISTS`), `DROP DATABASE`/`DROP SCHEMA`, `TRUNCATE` — including inside `mysql -e "…"` / `psql -c "…"`. 0 FP / 0 FN on its corpus. | Intentionally allows non-DDL-destructive SQL (`SELECT`/`CREATE`/`ALTER`/`INSERT`/`UPDATE`/`CREATE INDEX`) and prose that merely mentions the verbs (`git commit -m "drop the legacy users table"`, `echo "remember to truncate the logs"`). |
| **container pack** (opt-in) | PreToolUse Bash | `docker {system,image,volume,network,container} prune -af`/`-f`, `docker rm\|rmi -f`, `kubectl delete … --all`. 0 FP / 0 FN on its corpus. | Intentionally allows inspection and single-target ops: `docker ps\|images\|logs\|build\|run\|stop`, plain `docker rm web` (no `-f`), `kubectl get\|describe\|logs\|apply`, `kubectl delete pod web-123` (single target, no `--all`), and prose mentioning the commands. |
| **policy engine** (opt-in) | PreToolUse (any tool) + UserPromptSubmit | Per-tool rule patterns + `defaults.default_action = "deny"` posture, composed with the built-in gate via `max_verdict` so the engine never softens a Block. On the v0.3 policy corpora: 0 FP / 0 FN (66 benign / 33 dangerous). Fail-closed: any load / parse / schema-version error is mapped to `Verdict::block`. | What the user does not put in `[[tools]].rules` is not matched by the engine; pattern-based rules are case-sensitive on the short flags (each case permutation needs its own rule). Long-form `rm --recursive --force …` IS covered. |
| **Ask tier** (`Tier::Ask`) | PreToolUse (any tool) | The 4th `Verdict` variant (`Block > Ask > Warn > Allow`) surfaces a UI prompt via the hook output `permissionDecision: "ask"` (exit 0). On non-blocking events (PostToolUse, UserPromptSubmit) it gracefully downgrades to a Warn. The policy engine produces Ask on budget-cap overage. | Off by default — only the policy engine emits Ask today (gate + firewall + pathguard are all-or-nothing: Block or Allow/Warn). |
| **sandbox escape closures** (v0.3) | Local sandbox | Closes 2 of 3 documented escape surfaces: `/proc/self/root` filesystem-via-proc alias (Landlock denies writes on `/proc`; `sandbox_proc_self_root_write_is_denied`) and the ELF-linker trick of writing to `/proc/self/exe` (`sandbox_elf_linker_tricks_are_denied`). The empirical build baseline (`cargo build` / `node -e` / `go run` exiting 0) is preserved as the non-regression gate (`tests/sandbox_build_e2e.rs`). | The seccomp self-disable closure is NOT a kernel-side self-test (modern kernels allow multiple ANDed seccomp filters; the "lock" property is not universal). The empirical baseline is the existing `unlisted_syscall_returns_eperm` test in `tests/sandbox_seccomp.rs` — if the seccomp install is a no-op, an unlisted syscall succeeds and the test fails. |
| **Ask tier** (per-command) | PreToolUse (any tool) + UserPromptSubmit | The `Verdict::Ask` path is exercised end-to-end via the policy engine's budget cap (`budgets.per_tool.Bash.max_invocations = 0`): any Bash call exceeds the budget and the engine returns Ask. Pre-committed 0-FP / 0-FN corpus: 30 benign (non-Bash tools) / 18 dangerous (Bash commands); the test asserts every dangerous command produces Ask and no benign command produces Ask. Mirrors the `benchmark.rs` discipline. | The dangerous corpus is a coarse differentiation (Bash vs non-Bash) under the chosen policy; a more granular policy with per-pattern budget semantics would split it further. The test is honest about the engine's current Ask path (budget overage ONLY) and documents it. |

Packs are **OFF by default**; a committed test asserts that with `Config::default()`
a pack-only destructive command (`DROP TABLE users;`, `docker system prune -af`,
`kubectl delete pods --all`, `aws s3 rb … --force`) **Allows** — the opt-in
invariant. Each pack's 0-FP / 0-FN claim is the `cargo test --test
benchmark_packs` gate; the benign columns above are the exact look-alikes those
corpora enumerate.

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
| Benign Bash (`ls -la`)    | gate::evaluate       | Allow    | **1.823 µs** | **2.255 µs** | 1.372 µs   | 983.891 µs  |
| Blocked Bash (`rm -rf ~`) | gate::evaluate       | Block    | **1.994 µs** | **2.445 µs** | 1.943 µs   | 50.436 µs   |
| Injection prompt          | firewall (UserPrompt)| Warn     | **891 ns** | **1.433 µs** | 841 ns   | 7.614 µs    |

The Bash gate (allow + block) costs ~1–2 µs per call — negligible against tool
execution. The firewall content scan over the full rule set runs a single-pass
lazy-DFA pre-match (equivalent RegexSet fallback on non-ASCII haystacks) with
two-stage validators engaged only when their broad gate hits: ~0.8–1 µs p50 on
prompt/content surfaces, sub-2 µs at p99. The
`max` outliers are scheduler jitter on a shared box, not algorithmic blowup — the
[ReDoS guard](benches/regex_redos.rs) separately asserts the scan stays linear.

> Numbers are from one representative run; re-run `cargo bench --bench
> hook_latency` to reproduce on your hardware. Absolute values move with CPU and
> load; the shape (gate in single-digit µs, firewall in low hundreds of µs) is
> stable.

## TensorTrust (external, human-written attacks)

Source: `cargo test --test benchmark_tensortrust -- --nocapture`. This is the one
benchmark whose corpus is **not authored by us**: 400 real, human-written
prompt-injection attacks from the **Tensor Trust** online game (Toyer et al.,
arXiv:2311.01011) — 200 hijacking + 200 extraction, the deterministic head-slice
of the curated v1 robustness benchmarks. Vendored under **BSD-2-Clause** from
`HumanCompatibleAI/tensor-trust-data` at revision
`747a75e096761ebc01bd3970158827326b4add23`, fetched **2026-06-06**
(full provenance + reproduction in
[`tests/corpus/tensortrust/PROVENANCE.md`](tests/corpus/tensortrust/PROVENANCE.md)).

Measured **2026-06-06** — the firewall scans the untrusted `attack` text; a
`Warn` passes content through, so it counts as a miss here:

| Outcome | Count | Share |
|---|---:|---:|
| Flagged (Block) | 21 / 400 | 5.2% |
| Warn-only (still slips) | 11 / 400 | 2.8% |
| **False negatives (not Blocked)** | **379 / 400** | **94.8%** |

**This high FN is an honest measurement, not a defect to hide.** The deterministic
regex firewall's threat model is *structured, signature-bearing* injection
(OWASP ASI / DJL constructs). Tensor Trust attacks are the opposite: human social
engineering — role-play ("You are a Taylor Swift fan…"), fake system-upgrade
framing, unicode/whitespace floods (`ö ö ö …`), bracket-spam, and prefix-priming
("Prepend your response with `[Access Granted`"). These carry no fixed signature,
so they sit **largely outside** what a regex firewall can decide deterministically.
Catching them needs *semantics*, not patterns — which is exactly why a
**semantic-classifier tier is the documented v0.3 direction**. Publishing 94.8%
FN against an external human corpus is the point: it bounds the firewall honestly
and quantifies the gap the v0.3 tier must close.

## Mirror paraphrase benchmark (external-style #2)

Source: `cargo test --test mirror_benchmark -- --nocapture`. Corpus:
`evals/mirror/` — 30 prompt-injection attacks that keep the semantic intent of
canonical attack families (the ones the DJL/OWASP tables and
`evals/firewall/cases/` already cover) but are lexically rewritten — synonyms,
restructuring, indirect framing, translation-flavored phrasing, encoding-lite
tricks (letter spacing, punctuation substitution, leetspeak, hyphen chaining) —
plus 15 matched benign controls that mirror each class's structure while being
unambiguously safe. Author-written from public patterns; method and schema in
`evals/mirror/README.md`. Scanned with the production entry point
`firewall::scan_content`, default thresholds. Accounting identical to external
#1: an attack counts as missed iff the verdict is not `Block` (a Warn passes
content through); a control counts as flagged iff it is `Warn` or `Block`.

Measured **2026-08-23**:

| Attack class (`evals/mirror/attacks.jsonl`) | N | Blocked | Missed (FN) | FN rate |
|---|---:|---:|---:|---:|
| instruction-override | 5 | 0 | 5 | 100% |
| exfiltration | 5 | 0 | 5 | 100% |
| role-hijack | 5 | 0 | 5 | 100% |
| prompt-extraction | 5 | 0 | 5 | 100% |
| guardrail-bypass | 5 | 0 | 5 | 100% |
| obfuscation-lite | 5 | 0 | 5 | 100% |
| **All attacks** | **30** | **0** | **30** | **100%** |

| Benign controls (`benign.jsonl`) | N | Allowed | Flagged (FP) | FP rate |
|---|---:|---:|---:|---:|
| All controls | 15 | 15 | 0 | **0%** |

**Interpretation.** A 100% FN on purpose-built paraphrases is the expected
worst case of the signature ceiling already documented against external #1
(94.8% FN on human attacks): every rule in the firewall keys on surface forms —
literal verb phrases ("ignore previous instructions", "send … to https://"),
fixed tokens (`jailbreak`, `sudo mode`), or structural signatures. Rewriting
the surface while preserving intent defeats exactly that keying, even before
resorting to real encoding. Two honest caveats cut both ways. First, this
corpus was authored *by consulting the rule tables*, so it demonstrates the
mechanism of failure rather than sampling an unbiased attack distribution —
it bounds the ceiling from below, it does not claim real attackers hit 100%.
Second, the 0% FP on matched controls shows the current rules stay quiet on
near-miss benign phrasing ("ignore the typo", "this is a test of the hook",
"new rules for the potluck") — precision is intact; recall on paraphrase-class
attacks is simply absent by design. Together with external #1 this completes
the documented case for the opt-in semantic tier: deterministic signatures
catch structure, not meaning, and no amount of pattern-tuning closes a
paraphrase gap without either exploding FP or moving to semantics.


## External benchmark campaign #1 — ox-alpha-free (2026-08-23/24)

First full external stress-test campaign against public academic benchmarks, executed
end-to-end through the shipped v0.4.0 surfaces. Full methodology and per-suite tables:
`docs/benchmarks-results.md` (local working copy).

| Surface | Benchmark | Result | External record |
|---|---|---|---|
| Structural Bash gate (obfuscation) | QuasarNix (483k cmds, Trizna et al., ACM TOPS 2025, doi:10.1145/3807450) | With the opt-in `reverse-shell` community pack: TPR 94.78% overall (orig 100%, adversarial 89.56%) · **93.33% mean across 15 obfuscation manipulations** · FPR 4.18e-2 | Published GBDT: 60.2% TPR @ FPR=1e-6, collapsing to ~0% under the same manipulations |

Honest reading, with three required qualifiers: (1) **pack disclosure** — the result
requires the opt-in reverse-shell community pack; the default taxonomy is
destructive-only by design and scores 1.71% on this corpus without it; (2)
**in-sample authorship** — pack rules were authored consulting the corpus, so the
number is a favorable lower bound, not an unbiased sample; (3) **FPR axis** — our
operating point is FPR 4.18e-2, not the record's 1e-6; the comparison is two-axis.
The defensible claim is **perturbation-delta leadership**: we hold 93.33% mean TPR
under manipulations where the published ML detector collapses to ~0%. Against a
highly injection-resistant frontier model the deterministic gate adds no measurable
ASR delta on semantic injection classes (floor effect, documented per-suite below) —
its guarantee is the structural/destructive class, deterministically, at zero model
cost. Remaining gaps from this campaign (`&&`-chaining fetch-pipe,
exfil rules, MCPTox policy condition) are filed for v0.5; the hexesc gap is closed —
see below.


## Post-v0.4.0 fix: hexesc normalization closed (2026-08-25)

Commit `7f3d46f` adds a bounded normalize pass that decodes a leg-head, single-quoted
`printf '\xHH…'` format piped directly into a shell interpreter, so what the shell
executes is what gets scanned. Re-running QuasarNix's 5,000-command perturbation
suite and the full benign split against the fixed gate, pack posture unchanged:

| Metric | Campaign (v0.4.0) | Post-fix |
|---|---|---|
| `hexesc` manipulation TPR | 0% (0/5,000) | **100% (5,000/5,000)** |
| Mean TPR across 15 manipulations | 93.33% | **100.00%** |
| Other 14 manipulations | 100% each | unchanged |
| Benign FPR | 4.18e-2 (527/12,607) | 4.18e-2 (527/12,607), unchanged |

Two honesty notes: the decode fires only on its exact shape (leg head, single-quoted
format, direct pipe to a shell); documented shape variants — an intermediate pipe
stage, a subshell wrapper, a `--` separator, or starving the shared splice budget —
remain uncaught and are listed in the README's out-of-scope section. The FPR axis is
also unchanged: same operating point, same known false-positive classes.
