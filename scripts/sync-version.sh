#!/usr/bin/env bash
#
# Single-source-of-truth release versioning.
#
# The [package] version in Cargo.toml is THE version. This script propagates
# it to every user-facing release surface so they can never drift from the
# crate:
#
#   - packaging/plugin.json                      ("version")
#   - .claude-plugin/marketplace.json            ("version")
#   - packaging/install.sh                       (VERSION= default)
#   - packaging/npx-wrapper/package.json         ("version")
#   - packaging/npx-wrapper/bin/apohara-agentguard.js  (const VERSION)
#   - .github/workflows/release.yml              (bundle artifact name)
#
# tests/readme_sync.rs::version_sync_across_manifests asserts the same
# invariant from the Rust side; run this script after bumping Cargo.toml.
#
# Idempotent: re-running against an already-synced tree changes nothing.
# Fails loudly (non-zero, clear message) when a target file or its version
# pattern is missing instead of silently skipping it — a half-updated tree
# must never look like success.
#
# Usage: scripts/sync-version.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="${ROOT}/Cargo.toml"

die() {
  printf 'sync-version.sh: %s\n' "$1" >&2
  exit 1
}

[ -f "$CARGO_TOML" ] || die "not found: $CARGO_TOML"

# --- Read the canonical version ([package] version = "x.y.z"). ---------------
version="$(sed -n -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*$/\1/p' "$CARGO_TOML" | head -n 1)"
[ -n "$version" ] || die "could not read [package] version = \"...\" from $CARGO_TOML"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "'$version' (Cargo.toml [package] version) is not a bare x.y.z semver"

# --- Propagate to every release surface. -------------------------------------
# apply <file> <verify-ERE> <sed-program> <expected-literal> <label>
#
# verify-ERE must match the current version line (value-agnostic, so a second
# run still matches and rewrites the SAME value: byte-for-byte idempotent).
# expected-literal is grepped back out afterwards as the post-condition.
apply() {
  local file="$1" verify="$2" rewrite="$3" expect="$4" label="$5"
  [ -f "$file" ] || die "$label: missing file: $file"
  grep -Eq -- "$verify" "$file" ||
    die "$label: version pattern not found in $file (refusing to touch anything)"
  sed -i -E "$rewrite" "$file"
  grep -Fq -- "$expect" "$file" ||
    die "$label: rewrite did not land in $file (expected '$expect')"
  printf 'sync-version.sh: %-52s -> %s\n' "$label" "$version"
}

json_verify='^[[:space:]]*"version"[[:space:]]*:'
json_rewrite="s|^([[:space:]]*\"version\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")|\1${version}\2|"

apply "${ROOT}/packaging/plugin.json" \
  "$json_verify" \
  "$json_rewrite" \
  "\"version\": \"${version}\"" \
  "packaging/plugin.json"

apply "${ROOT}/.claude-plugin/marketplace.json" \
  "$json_verify" \
  "$json_rewrite" \
  "\"version\": \"${version}\"" \
  ".claude-plugin/marketplace.json"

apply "${ROOT}/packaging/install.sh" \
  '^VERSION=' \
  "s|^VERSION=.*$|VERSION=\"\\\${AGENTGUARD_VERSION:-${version}}\"|" \
  "AGENTGUARD_VERSION:-${version}" \
  "packaging/install.sh (VERSION= default)"

apply "${ROOT}/packaging/npx-wrapper/package.json" \
  "$json_verify" \
  "$json_rewrite" \
  "\"version\": \"${version}\"" \
  "packaging/npx-wrapper/package.json"

apply "${ROOT}/packaging/npx-wrapper/bin/apohara-agentguard.js" \
  '^const VERSION' \
  "s|^const VERSION[[:space:]]*=.*$|const VERSION = \"${version}\";|" \
  "const VERSION = \"${version}\";" \
  "packaging/npx-wrapper/bin/apohara-agentguard.js"

apply "${ROOT}/.github/workflows/release.yml" \
  '^[[:space:]]*name:[[:space:]]+apohara-agentguard-v[0-9]+\.[0-9]+\.[0-9]+-release[[:space:]]*$' \
  "s|^([[:space:]]*name:[[:space:]]*apohara-agentguard-v)[0-9]+\.[0-9]+\.[0-9]+(-release)[[:space:]]*\$|\1${version}\2|" \
  "name: apohara-agentguard-v${version}-release" \
  ".github/workflows/release.yml (bundle artifact name)"

printf 'sync-version.sh: all release surfaces now at v%s\n' "$version"
