#!/bin/sh
#
# apohara-agentguard one-command installer (POSIX sh).
#
# Detects platform x arch x libc, downloads the matching release binary,
# verifies its SHA256 against a pinned manifest, places it under the plugin
# directory, and registers the Claude Code plugin/hook config. Because
# apohara-agentguard is a security tool, a checksum mismatch ABORTS — an unverified
# binary is never installed or run.
#
# musl is detected and refused (use `cargo install` instead); musl release
# binaries are deferred to v0.2.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SuarezPM/apohara-agentguard/main/packaging/install.sh | sh
#
# Env overrides:
#   AGENTGUARD_VERSION        release tag to install (default: 0.1.0)
#   AGENTGUARD_DOWNLOAD_BASE  artifact base URL (default: GitHub release)
#   AGENTGUARD_PREFIX         install dir (default: ~/.local/share/apohara-agentguard)

set -eu

VERSION="${AGENTGUARD_VERSION:-0.1.0}"
BASE_URL="${AGENTGUARD_DOWNLOAD_BASE:-https://github.com/SuarezPM/apohara-agentguard/releases/download/v${VERSION}}"
PREFIX="${AGENTGUARD_PREFIX:-${HOME}/.local/share/apohara-agentguard}"

# --- Pinned SHA256 manifest (target triple -> sha256). -----------------------
# Filled in by the release workflow before publish; a literal placeholder means
# this version is not yet pinned and the installer must refuse to download.
sha_for_triple() {
  case "$1" in
    x86_64-unknown-linux-gnu)  echo "REPLACE_WITH_RELEASE_SHA256" ;;
    aarch64-unknown-linux-gnu) echo "REPLACE_WITH_RELEASE_SHA256" ;;
    x86_64-apple-darwin)       echo "REPLACE_WITH_RELEASE_SHA256" ;;
    aarch64-apple-darwin)      echo "REPLACE_WITH_RELEASE_SHA256" ;;
    *) echo "" ;;
  esac
}

err() {
  printf 'apohara-agentguard: %s\n' "$1" >&2
  exit 1
}

# --- Detect target triple. ---------------------------------------------------
detect_triple() {
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"

  case "$uname_m" in
    x86_64 | amd64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *) err "unsupported architecture: $uname_m (supported: x86_64, aarch64)" ;;
  esac

  case "$uname_s" in
    Linux)
      # musl detection: ldd --version mentions musl on musl systems.
      if (ldd --version 2>&1 || true) | grep -qi musl; then
        err "musl libc is not yet supported in v0.1. Install from source instead:
  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked
(musl release binaries are planned for v0.2.)"
      fi
      echo "${arch}-unknown-linux-gnu"
      ;;
    Darwin)
      echo "${arch}-apple-darwin"
      ;;
    *)
      err "unsupported OS: $uname_s (Windows: use the npx wrapper or cargo install)"
      ;;
  esac
}

# --- SHA256 verify (sha256sum or shasum -a 256). -----------------------------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    err "no sha256 tool found (need sha256sum or shasum)"
  fi
}

# --- Download (curl or wget). ------------------------------------------------
download() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest" || err "download failed: $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$dest" || err "download failed: $url"
  else
    err "no downloader found (need curl or wget)"
  fi
}

main() {
  triple="$(detect_triple)"
  expected="$(sha_for_triple "$triple")"

  if [ -z "$expected" ] || [ "$expected" = "REPLACE_WITH_RELEASE_SHA256" ]; then
    err "no pinned SHA256 for target $triple in this installer.
Install from source instead:
  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked"
  fi

  artifact="apohara-agentguard-${triple}"
  url="${BASE_URL}/${artifact}"
  tmp="$(mktemp)"

  printf 'apohara-agentguard: downloading %s\n' "$url" >&2
  download "$url" "$tmp"

  got="$(sha256_of "$tmp")"
  if [ "$got" != "$expected" ]; then
    rm -f "$tmp"
    err "SHA256 mismatch — refusing to install an unverified binary.
  target:   $triple
  expected: $expected
  got:      $got"
  fi

  # --- Place the binary. -----------------------------------------------------
  bin_dir="${PREFIX}/bin"
  mkdir -p "$bin_dir"
  bin_path="${bin_dir}/apohara-agentguard"
  mv "$tmp" "$bin_path"
  chmod 0755 "$bin_path"
  printf 'apohara-agentguard: installed binary at %s\n' "$bin_path" >&2

  # --- Register the plugin/hook config. --------------------------------------
  # Place plugin.json + hooks.json next to the binary so ${CLAUDE_PLUGIN_ROOT}
  # resolves to PREFIX and the hooks invoke ${CLAUDE_PLUGIN_ROOT}/bin/apohara-agentguard.
  printf 'apohara-agentguard: fetching plugin manifest + hook config\n' >&2
  download "${BASE_URL}/plugin.json" "${PREFIX}/plugin.json" || true
  download "${BASE_URL}/hooks.json" "${PREFIX}/hooks.json" || true

  cat >&2 <<EOF
apohara-agentguard: install complete.

To enable the hook in Claude Code, install apohara-agentguard as a plugin pointing at:
  ${PREFIX}

Or add the hook config to your settings.json (~/.claude/settings.json),
substituting ${PREFIX} for \${CLAUDE_PLUGIN_ROOT} in:
  ${PREFIX}/hooks.json

Emergency kill-switch: export AGENTGUARD_DISABLE=1 to bypass the gate.
EOF
}

main "$@"
