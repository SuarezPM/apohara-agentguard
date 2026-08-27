# Homebrew distribution (tap) — TODO-humano checklist

The formula template in this directory makes `apohara-agentguard` installable
via Homebrew once a personal tap exists. Four manual steps; **all four require
human action with GitHub/npm-free accounts** (a GitHub repo you control).

## 1. Create the tap repository

Create a **public** repo named exactly `homebrew-tap` under the `SuarezPM`
account (Homebrew's `<user>/tap` short-form resolves to
`github.com/<user>/homebrew-tap`). Give it a `Formula/` directory:

```
homebrew-tap/
  README.md          (optional)
  Formula/
```

## 2. Fill the checksums and version in the formula

Fetch the release manifest and copy the digests into the formula's
TODO-HUMAN placeholders (minimal distribution v0.5.3+: only 2 bins — `x86_64-unknown-linux-musl` + `aarch64-apple-darwin`; 4 placeholders remain for legacy, missing triples fallback to `cargo install`):

```sh
VER=0.5.3   # keep identical to the formula's `version` line
curl -fsSL -o SHA256SUMS \
  "https://github.com/SuarezPM/apohara-agentguard/releases/download/v${VER}/SHA256SUMS"
grep -E 'apple-darwin|unknown-linux-musl' SHA256SUMS
# minimal: expect 2 lines (x86_64-unknown-linux-musl + aarch64-apple-darwin); legacy 7-target had 4
```

Edit `packaging/homebrew/apohara-agentguard.rb`: set `version "<ver>"` and
paste each `sha256` value over its placeholder. Solo 2 bins disponibles en minimal — otras plataformas usarán `cargo install apohara-agentguard` como fallback (documentado en `RELEASING.md` § bundle).

## 3. Copy the formula into the tap

```sh
cp packaging/homebrew/apohara-agentguard.rb /path/to/homebrew-tap/Formula/
git -C /path/to/homebrew-tap add Formula/ && git -C /path/to/homebrew-tap commit -m "apohara-agentguard <ver>"
git -C /path/to/homebrew-tap push
```

Optional sanity check before pushing: `brew audit --strict --formula` against
the tap copy (it will fail until step 2's placeholders are replaced with real
digests).

## 4. Install

```sh
brew tap SuarezPM/tap
brew install SuarezPM/tap/apohara-agentguard
apohara-agentguard version   # note: sbin — ensure $(brew --prefix)/sbin is on PATH
```

## Per-release maintenance

On each new release repeat steps 2–3 (bump `version`, refresh the two sha256 values for minimal 2-target — legacy used four). This is also the last step of [`RELEASING.md`](../../RELEASING.md).

> **Nota distribución minimal (fix-1 B2):** Desde v0.5.3 solo 2 bins prebuilt (`x86_64-unknown-linux-musl`, `aarch64-apple-darwin`). Homebrew mantiene 4 combos en la fórmula pero 2 quedarán sin URL/sha válido — en esas plataformas Homebrew fallará y el fallback es `cargo install apohara-agentguard` (ver `README.md` y `packaging/install.sh`). No ampliar matrix a 3 sin decisión explícita.
