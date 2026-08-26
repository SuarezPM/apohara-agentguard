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

Fetch the release manifest and copy the four digests into the formula's
TODO-HUMAN placeholders:

```sh
VER=0.5.0   # keep identical to the formula's `version` line
curl -fsSL -o SHA256SUMS \
  "https://github.com/SuarezPM/apohara-agentguard/releases/download/v${VER}/SHA256SUMS"
grep -E 'apple-darwin|unknown-linux-musl' SHA256SUMS
```

Edit `packaging/homebrew/apohara-agentguard.rb`: set `version "<ver>"` and
paste each `sha256` value over its placeholder.

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

On each new release repeat steps 2–3 (bump `version`, refresh the four
sha256 values). This is also the last step of [`RELEASING.md`](../../RELEASING.md).
