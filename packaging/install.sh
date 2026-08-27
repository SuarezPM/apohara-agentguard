#!/bin/sh
#
# apohara-agentguard one-command installer (POSIX sh).
#
# Detects platform x arch x libc, downloads the matching release binary,
# verifies its SHA256 against the release's combined SHA256SUMS manifest
# (fetched at install time from the same release — no hashes are pinned in
# this script), places it under the plugin directory, and registers the Claude
# Code plugin/hook config. Because apohara-agentguard is a security tool, a
# missing checksum manifest or a checksum mismatch ABORTS — an unverified
# binary is never installed or run.
#
# Idempotent and non-destructive:
#   - If the target path already holds a binary whose checksum matches the
#     manifest for this version, the script prints "already installed" and
#     exits 0 without re-downloading anything.
#   - When a different build is already present, it is preserved as
#     <target>.bak.<previous-mtime-timestamp> before the verified download
#     atomically replaces it (temp file in the same directory + rename).
#   - Failed or interrupted runs never leave a partial binary behind, and
#     files the installer does not manage are never touched.
#
# glibc and musl Linux builds are both published since v0.3; libc detection
# selects between them.
#
# Zero-touch wiring (default ON): after the binary is verified and placed,
# the installer detects supported agent hosts and runs `<bin> init --yes`
# automatically, so the hook gates from the shadows with NO second manual
# step. This step is FAIL-OPEN for the installer UX: the binary is already
# installed at that point, so a wiring failure only warns. Opt out with
# AGENTGUARD_NO_INIT=1 or by passing --no-init as the first argument.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SuarezPM/apohara-agentguard/main/packaging/install.sh | sh
#   install.sh --no-init          # skip the automatic host wiring
#
# Env overrides:
#   AGENTGUARD_VERSION        release tag to install (default: pinned by VERSION below)
#   AGENTGUARD_DOWNLOAD_BASE  artifact base URL (default: GitHub release)
#   AGENTGUARD_PREFIX         install dir (default: ~/.local/share/apohara-agentguard)
#   AGENTGUARD_NO_INIT        set to 1 to skip the automatic host wiring

set -eu

VERSION="${AGENTGUARD_VERSION:-0.5.1}"
BASE_URL="${AGENTGUARD_DOWNLOAD_BASE:-https://github.com/SuarezPM/apohara-agentguard/releases/download/v${VERSION}}"
PREFIX="${AGENTGUARD_PREFIX:-${HOME}/.local/share/apohara-agentguard}"

# Temp paths currently in flight; removed by the cleanup trap so a failed or
# interrupted run never leaves partial downloads behind.
sums_file=""
tmp_bin=""
opt_tmp=""

cleanup() {
  rm -f "${sums_file:-}" "${tmp_bin:-}" "${opt_tmp:-}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

err() {
  printf 'apohara-agentguard: %s\n' "$1" >&2
  exit 1
}

# --- Runtime SHA256 resolution from the release manifest. --------------------
# The release publishes a combined SHA256SUMS asset (standard sha256sum output:
# "<hash>  <filename>", one line per artifact). Nothing is pinned in this
# script: the manifest for the exact version being installed is fetched and
# parsed, so a hash can never drift from the release it belongs to.
checksum_for_triple() {
  sums_url="${BASE_URL}/SHA256SUMS"
  sums_file="$(mktemp)"

  printf 'apohara-agentguard: fetching %s\n' "$sums_url" >&2
  if ! try_download "$sums_url" "$sums_file"; then
    err "checksum manifest not available at $sums_url.
Refusing to install an unverified binary. Offline? Install from source instead:
  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked --version ${VERSION}"
  fi

  hash="$(sed -n "s/^\([0-9a-fA-F]\{64\}\)[[:space:]]\{1,\}\*\{0,1\}apohara-agentguard-$1\$/\1/p" "$sums_file" | head -n 1)"
  sums_file=""

  if [ -z "$hash" ]; then
    err "no checksum for target $1 in the v${VERSION} checksum manifest.
Refusing to install an unverified binary. Install from source instead:
  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked --version ${VERSION}"
  fi

  printf '%s\n' "$hash"
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
      # libc detection picks between the glibc and musl builds (both
      # published since v0.3): ldd --version mentions musl on musl systems.
      if (ldd --version 2>&1 || true) | grep -qi musl; then
        echo "${arch}-unknown-linux-musl"
      else
        echo "${arch}-unknown-linux-gnu"
      fi
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

# --- Previous-file mtime (epoch seconds) for backup suffixes. ----------------
# Best effort across GNU stat (-c) and BSD stat (-f); falls back to now.
mtime_of() {
  mtime=""
  if command -v stat >/dev/null 2>&1; then
    mtime="$(stat -c %Y "$1" 2>/dev/null || true)"
    if [ -z "$mtime" ]; then
      mtime="$(stat -f %m "$1" 2>/dev/null || true)"
    fi
  fi
  if [ -z "$mtime" ]; then
    mtime="$(date +%s)"
  fi
  printf '%s\n' "$mtime"
}

# --- Download (curl or wget). ------------------------------------------------
# try_download returns the downloader's exit status so callers can decide how
# to report a failure; download() treats any failure as fatal.
try_download() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$dest"
  else
    err "no downloader found (need curl or wget)"
  fi
}

download() {
  try_download "$1" "$2" || err "download failed: $1"
}

# fetch_optional downloads <url> to a temp file next to <dest> and only moves
# it onto <dest> when the download succeeded, so an existing file is never
# clobbered by a failed or partial download. Failures are non-fatal.
fetch_optional() {
  opt_url="$1"
  opt_dest="$2"
  printf 'apohara-agentguard: fetching %s\n' "$opt_url" >&2
  opt_tmp="$(mktemp "${opt_dest}.tmp.XXXXXXXX")" || return 0
  if try_download "$opt_url" "$opt_tmp"; then
    chmod 0644 "$opt_tmp"
    mv -f "$opt_tmp" "$opt_dest"
  else
    rm -f "$opt_tmp"
    printf 'apohara-agentguard: warning: could not fetch %s; keeping any existing file\n' "$opt_url" >&2
  fi
  opt_tmp=""
}

# extract_packs_safely validates every archived path BEFORE extracting
# anything: absolute paths, any ".." component, empty names, option-looking
# entries, and ANY entry that is not a flat "<name>.toml" manifest are
# rejected, so a hostile tarball can never write outside <dest>. The
# allowlist is deliberate: our pack tarball carries nothing else, so
# symlinks, directories, or payloads in disguise fail validation and the
# caller aborts the install.
extract_packs_safely() {
  packs_archive="$1"
  packs_dest="$2"
  while IFS= read -r entry || [ -n "$entry" ]; do
    [ -n "$entry" ] || continue
    case "$entry" in
      /* | *'..'* | -*) return 1 ;;
      *.toml) ;;
      *) return 1 ;;
    esac
  done <<EOF
$(tar -tzf "$packs_archive")
EOF
  tar -xzf "$packs_archive" -C "$packs_dest"
}

# --- Zero-touch host wiring. -------------------------------------------------
# Detect supported agent hosts and auto-run `<bin> init --yes` so the hook
# starts gating immediately — install once, act from the shadows. Host
# detection mirrors init's own path resolution ($XDG_CONFIG_HOME respected
# for the OpenCode/Kilo plugin dirs). Fail-open BY DESIGN for the installer
# UX: at this point the binary is installed and verified, so a wiring failure
# only warns and points at the manual command; it must never turn a verified
# install into an installer error.
#
# Opt-out: AGENTGUARD_NO_INIT=1 or `--no-init` as the FIRST argument.
# Sets the global `protected` variable (space-separated host labels) so the
# final summary can report the real state.
auto_wire() {
  bin="$1"
  first_arg="${2:-}"
  protected=""

  if [ "${AGENTGUARD_NO_INIT:-0}" = "1" ] || [ "$first_arg" = "--no-init" ]; then
    printf 'apohara-agentguard: automatic wiring skipped (--no-init).\n' >&2
    printf "apohara-agentguard: run '%s init' when ready.\n" "$bin" >&2
    return 0
  fi

  config_root="${XDG_CONFIG_HOME:-${HOME}/.config}"
  hosts=""
  if [ -f "${HOME}/.claude/settings.json" ]; then hosts="${hosts}claude-code "; fi
  if [ -f "${HOME}/.codex/hooks.json" ]; then hosts="${hosts}codex-code "; fi
  if [ -d "${config_root}/opencode" ]; then hosts="${hosts}opencode "; fi
  if [ -d "${config_root}/kilo" ]; then hosts="${hosts}kilo "; fi
  if [ -d "${HOME}/.kitty-code" ]; then hosts="${hosts}kitty-code "; fi

  if [ -z "$hosts" ]; then
    printf "apohara-agentguard: no supported agent config found — run '%s init --yes' after installing a supported coding agent.\n" "$bin" >&2
    return 0
  fi

  printf 'apohara-agentguard: detected agent host(s): %s — wiring hooks automatically\n' "${hosts% }" >&2
  if ! init_out="$("$bin" init --yes 2>&1)"; then
    printf 'apohara-agentguard: warning: automatic wiring FAILED (the binary itself IS installed and verified).\n' >&2
    printf "apohara-agentguard: run '%s init --yes' manually to wire your agents.\n" "$bin" >&2
    return 0
  fi
  if [ -n "$init_out" ]; then
    printf '%s\n' "$init_out" >&2
  fi
  protected="${hosts% }"
  printf 'apohara-agentguard: Wired: %s. Restart your agents.\n' "$protected" >&2
}

# --- Final summary: reflects the REAL post-install state. --------------------
print_summary() {
  cat >&2 <<EOF
apohara-agentguard: install complete.

Protected hosts: ${protected:-none}
Binary: ${bin_path}
Health check: ${bin_path} doctor

Community rule packs extracted under ${PREFIX}/packs (when present in the
release). Enable them with a [community_packs] block in your agentguard config:
  [community_packs]
  enabled = ["reverse-shell"]
  dir = "${PREFIX}/packs"

Emergency kill-switch: export AGENTGUARD_DISABLE=1 to bypass the gate.
EOF
}

main() {
  triple="$(detect_triple)"
  expected="$(checksum_for_triple "$triple")"

  bin_dir="${PREFIX}/bin"
  mkdir -p "$bin_dir"
  bin_path="${bin_dir}/apohara-agentguard"

  # Idempotent fast path: a binary that already matches this version's
  # checksum means nothing to download or rewrite — but the zero-touch
  # wiring still runs (init is idempotent + self-healing, so re-running the
  # installer also heals any stale wiring from a relocated binary).
  if [ -e "$bin_path" ] &&
    [ "$(sha256_of "$bin_path" 2>/dev/null || true)" = "$expected" ]; then
    printf 'apohara-agentguard: already installed (v%s, checksum ok)\n' "$VERSION" >&2
    auto_wire "$bin_path" "${1:-}"
    print_summary
    return 0
  fi

  artifact="apohara-agentguard-${triple}"
  url="${BASE_URL}/${artifact}"
  # Temp file lives in the target directory so the final move is an atomic
  # rename within the same filesystem — the installed path never holds a
  # partial binary.
  tmp_bin="$(mktemp "${bin_dir}/.apohara-agentguard.XXXXXXXX")"

  printf 'apohara-agentguard: downloading %s\n' "$url" >&2
  download "$url" "$tmp_bin"

  got="$(sha256_of "$tmp_bin")"
  if [ "$got" != "$expected" ]; then
    err "SHA256 mismatch — refusing to install an unverified binary.
  target:   $triple
  expected: $expected
  got:      $got"
  fi

  # --- Place the binary: preserve the previous one, then atomic swap. --------
  if [ -e "$bin_path" ]; then
    bak="${bin_path}.bak.$(mtime_of "$bin_path")"
    mv -f "$bin_path" "$bak"
    printf 'apohara-agentguard: kept previous binary as %s\n' "$bak" >&2
  fi
  chmod 0755 "$tmp_bin"
  mv -f "$tmp_bin" "$bin_path"
  tmp_bin=""
  printf 'apohara-agentguard: installed binary at %s\n' "$bin_path" >&2

  # --- Register the plugin/hook config. --------------------------------------
  # Place plugin.json + hooks.json next to the binary so ${CLAUDE_PLUGIN_ROOT}
  # resolves to PREFIX and the hooks invoke ${CLAUDE_PLUGIN_ROOT}/bin/apohara-agentguard.
  # Both are optional and fetched via fetch_optional, so pre-existing files
  # survive a failed download untouched.
  printf 'apohara-agentguard: fetching plugin manifest + hook config\n' >&2
  fetch_optional "${BASE_URL}/plugin.json" "${PREFIX}/plugin.json"
  fetch_optional "${BASE_URL}/hooks.json" "${PREFIX}/hooks.json"

  # --- Community rule packs (optional release asset). -------------------------
  # Fetched non-fatally like the manifests above; extracted only after every
  # archived path passes validation (extract_packs_safely), so a missing
  # asset or an older release simply skips the packs.
  printf 'apohara-agentguard: fetching community rule packs\n' >&2
  mkdir -p "${PREFIX}/packs"
  fetch_optional "${BASE_URL}/agentguard-packs.tar.gz" "${PREFIX}/packs/agentguard-packs.tar.gz"
  if [ -f "${PREFIX}/packs/agentguard-packs.tar.gz" ]; then
    extract_packs_safely "${PREFIX}/packs/agentguard-packs.tar.gz" "${PREFIX}/packs" ||
      err "community packs tarball failed path validation; refusing to extract it.
Remove ${PREFIX}/packs/agentguard-packs.tar.gz if you want to retry the install."
    printf 'apohara-agentguard: installed community rule packs at %s\n' "${PREFIX}/packs" >&2
  fi

  # --- Zero-touch host wiring (fail-open; see auto_wire). ---------------------
  auto_wire "$bin_path" "${1:-}"

  print_summary
}

main "$@"
