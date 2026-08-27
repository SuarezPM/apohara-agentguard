# RELEASING — apohara-agentguard

Checklist distilled from the real v0.4.1 release run. Follow top-to-bottom;
nothing auto-publishes — every registry step is a maintainer-triggered
`workflow_dispatch`. Steps marked **[secret]** need a repository secret or an
account only a human can set up.

## 0. One-time setup [secret]

| What | Where | Status |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | repo secret (crates.io token with publish rights) | configured |
| `NPM_TOKEN` | repo secret (npm automation/granular token) | **TODO-humano** — configure before the first npm publish |
| `SuarezPM/homebrew-tap` repo | public tap repo, `Formula/` layout | **TODO-humano** — see `packaging/homebrew/README.md` |
| Claude Code marketplace submission | Anthropic marketplace form/account | **TODO-humano** (optional channel) |

Sigstore/cosign and SLSA provenance signing are keyless via GitHub OIDC — no
keys to hold. Scorecard runs automatically on the schedule in
`.github/workflows/scorecard.yml`.

## 1. Version sync

```sh
# bump [package] version in Cargo.toml, then:
bash scripts/sync-version.sh          # propagates to every release surface
cargo test --test readme_sync         # asserts the same invariant from Rust
git commit -m "chore(release): v<version>" && git push origin main
```

## 2. Build the review bundle — BEFORE tagging

Run **Actions → Release → Run workflow** (`workflow_dispatch`) on `main`, wait
for green, then download the `apohara-agentguard-v<version>-release` artifact.
Review the bytes you are about to sign and ship.

Expected bundle contents:

* v0.4.1 baseline (12 files): 7 × `apohara-agentguard-<triple>[.exe]`,
  `plugin.json`, `hooks.json`, `THIRD-PARTY-LICENSES`,
  `agentguard-packs.tar.gz`, `SHA256SUMS`
* from v0.5.2 (sigstore-only, 14+ assets) y desde v0.5.3 minimal (7–13 assets): 2 × `apohara-agentguard-<triple>` + 2 × `agentguard-proxy-<triple>` (=4 bins) + `SHA256SUMS` + `THIRD-PARTY-LICENSES` + `plugin.json` + `hooks.json` + `agentguard-packs.tar.gz` + `apohara-agentguard.cdx.json` + 4 × `.sigstore.json` + 2 × `.intoto.jsonl` (≈13 con firmas; 7–9 sin contar sigstore/intoto). Nota distribución minimal: solo 2 targets prebuilt (`x86_64-unknown-linux-musl`, `aarch64-apple-darwin`); otras plataformas usar `cargo install` fallback — ver `packaging/install.sh` y `packaging/homebrew/README.md`.

> **Nota Signed-Releases 10 (fix-1):** Signed-Releases 10 requiere 5 releases seguidos con `*.intoto.jsonl`; con v0.5.2 sigstore-only + v0.5.3/v0.5.4 intoto, ventana quedará [v0.5.4 10, v0.5.3 10, v0.5.1 8, v0.4.1 10, v0.4.0 0] =7, 10 real en v0.5.7; alternativa retroactiva `gh release upload v0.5.1 *.intoto.jsonl`.

## 3. Tag the exact reviewed SHA, then create the GitHub Release

The tag MUST point at the exact SHA the dispatch run built — that is what ties
the provenance/attestations to what you reviewed:

```sh
SHA=$(git rev-parse origin/main)      # same SHA the workflow ran against
git tag vX.Y.Z "$SHA" && git push origin vX.Y.Z

gh release create vX.Y.Z \
  --target "$SHA" \
  --title "vX.Y.Z" --notes-file <notes.md>

# attach the reviewed bundle:
gh release upload vX.Y.Z /path/to/bundle/*
```

Then fetch each target's SLSA provenance from the `attest` jobs (one per
target, main binary), rename to `<bin>.intoto.jsonl`, and attach as release
assets so users can verify offline. Each `attest` job exposes its bundle as a
workflow artifact:

```sh
# v0.5.3+ minimal: 2 targets; for retroactive upload to old tags adapt the list
targets="x86_64-unknown-linux-musl aarch64-apple-darwin"

mkdir intoto
for t in $targets; do
  gh run download <attest-run-id> --dir "intoto/raw-$t"   # locate the job's artifact id first
  mv "intoto/raw-$t"/<bundle-file> "apohara-agentguard-$t.intoto.jsonl"
done
gh release upload vX.Y.Z apohara-agentguard-*.intoto.jsonl
# alternativa retroactiva para acelerar ventana Scorecard:
# gh release upload v0.5.1 apohara-agentguard-*.intoto.jsonl
```

## 4. Post-release verification

```sh
# SLSA provenance (main binary, all targets):
gh attestation verify apohara-agentguard-x86_64-unknown-linux-gnu \
  -R SuarezPM/apohara-agentguard \
  --signer-workflow SuarezPM/apohara-agentguard/.github/workflows/_attest.yml

# Sigstore keyless signature (every shipped binary):
cosign verify-blob \
  --bundle apohara-agentguard-x86_64-unknown-linux-gnu.sigstore.json \
  --certificate-identity-regexp '^https://github.com/SuarezPM/apohara-agentguard/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  apohara-agentguard-x86_64-unknown-linux-gnu

sha256sum -c SHA256SUMS                # bundle manifest cross-check
```

Review the latest OpenSSF Scorecard run (Actions → Scorecard) and its
dashboard entry; regressions in build/review/provenance checks block the
launch checklist.

## 5. crates.io — IRREVERSIBLE [secret]

Actions → *Publish to crates.io* → Run (`workflow_dispatch`). A published
crate version cannot be deleted, only yanked. Verify the version and tree
state before triggering.

## 6. npm [secret]

Actions → *Publish npx wrapper to npm* → Run (`workflow_dispatch`). Requires
the `NPM_TOKEN` secret (**TODO-humano** until configured); the workflow fails
cleanly without it. It re-runs `scripts/sync-version.sh` as a drift gate, then
publishes `packaging/npx-wrapper/` with `--provenance --access public`.

## 7. Homebrew tap bump [secret]

Repeat steps 2–3 of `packaging/homebrew/README.md`: bump the formula's
`version`, refresh the two sha256 values (minimal 2-target: `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`) from the new `SHA256SUMS`, copy into
`homebrew-tap/Formula/`, push. Requires the tap repo (**TODO-humano** until
created). Legacy 7-target releases used four values — ver historial.

## 8. Optional channels

Claude Code marketplace resubmission (form/account — **TODO-humano**) and any
GHCR container publish (see TODO in `packaging/docker/Dockerfile`).
