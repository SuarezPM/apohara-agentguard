# Provenance: vendored Tensor Trust human-attack subset

This directory vendors a subset of the **Tensor Trust** dataset: real,
human-written prompt-injection attacks collected from the Tensor Trust online
game and used here as an *external* benchmark for the input firewall.

## Source

- **Project:** Tensor Trust (Toyer et al., "Tensor Trust: Interpretable Prompt
  Injection Attacks from an Online Game", arXiv:2311.01011).
- **Data repository:** https://github.com/HumanCompatibleAI/tensor-trust-data
- **Repository revision (commit pinned at fetch time):**
  `747a75e096761ebc01bd3970158827326b4add23` (branch `main`).
- **Code repository (carries the license):**
  https://github.com/HumanCompatibleAI/tensor-trust
- **HuggingFace mirror:** https://huggingface.co/datasets/qxcv/tensor-trust
- **Date fetched:** 2026-06-06.

Upstream files used (both are the curated **v1** robustness benchmarks):

| Upstream path | Records upstream | Vendored here |
|---------------|-----------------:|--------------:|
| `benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl`   | 775 | first 200 |
| `benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl` | 569 | first 200 |

## License

**BSD 2-Clause** (Copyright (c) 2023, The Regents of the University of
California). The full text is in the adjacent `LICENSE` file, fetched verbatim
from the canonical code repository
(`HumanCompatibleAI/tensor-trust/LICENSE`).

Honesty note: the `tensor-trust-data` data repo and the HuggingFace mirror do
**not** themselves ship a stand-alone `LICENSE` file (GitHub reports
`license: null` for the data repo), but the canonical project license — covering
both code *and* data per the project README ("build on our code or data") — is
the BSD 2-Clause license carried in the code repository. We therefore label this
vendored data **BSD-2-Clause**, not MIT. BSD-2-Clause is in this project's
`deny.toml` license allowlist, so `cargo deny check licenses` stays green.

## What was vendored, and what was dropped

- We kept **only** the human-written `attack` field from each record, plus the
  upstream `sample_id` (for traceability) and a `category` tag (`hijacking` or
  `extraction`). The defender-side fields (`pre_prompt`, `post_prompt`,
  `access_code`) are NOT vendored — the firewall scans the untrusted *attack*
  text, so only that field is relevant.
- The vendored file is `attacks.jsonl`: 400 records (200 hijacking + 200
  extraction), one JSON object per line:
  `{"sample_id": <int>, "category": "<hijacking|extraction>", "attack": "<text>"}`.
- This is a **documented subset** (400 of 1344 v1 benchmark attacks), chosen as
  a deterministic head-slice of each file for reproducibility. The full set is
  large and contains long, near-duplicate adversarial spam; 400 is a
  representative, honestly-sized sample for an offline regression benchmark.

## Reproduction

```sh
HJ=https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl
EX=https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl
{ curl -sSL "$HJ" | head -200 | jq -c '{sample_id, category: "hijacking", attack}'
  curl -sSL "$EX" | head -200 | jq -c '{sample_id, category: "extraction", attack}'
} > attacks.jsonl
```
