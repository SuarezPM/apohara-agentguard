#!/usr/bin/env node
//
// apohara-agentguard npx launcher.
//
// apohara-agentguard is a security tool, so this launcher NEVER runs an unverified
// binary. It resolves the correct release artifact by platform x arch x libc,
// downloads it, verifies its SHA256 against the release's combined SHA256SUMS
// manifest (fetched at resolution time from the same release), and only then
// execs it — forwarding argv and stdio unchanged. A checksum mismatch aborts.
//
// Resolution matrix (v0.3):
//   linux  x86_64  (glibc)  -> x86_64-unknown-linux-gnu
//   linux  aarch64 (glibc)  -> aarch64-unknown-linux-gnu
//   linux  x86_64  (musl)   -> x86_64-unknown-linux-musl
//   linux  aarch64 (musl)   -> aarch64-unknown-linux-musl
//   darwin x86_64           -> x86_64-apple-darwin
//   darwin aarch64          -> aarch64-apple-darwin
//   win32  x86_64           -> x86_64-pc-windows-msvc (.exe)
//
// Expected hashes are NOT pinned in this file. At resolution time the launcher
// downloads the release's SHA256SUMS manifest and looks up the hash for the
// resolved artifact, so a hash can never drift from the release it belongs to.
// If the manifest is unreachable (e.g. offline), the launcher refuses to run
// and points at `cargo install`.

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { spawnSync, execFileSync } = require("child_process");

const VERSION = "0.3.0";

// Base URL for release artifacts. Overridable for testing / mirrors.
const BASE_URL =
  process.env.AGENTGUARD_DOWNLOAD_BASE ||
  `https://github.com/SuarezPM/apohara-agentguard/releases/download/v${VERSION}`;

function fail(msg) {
  process.stderr.write(`apohara-agentguard: ${msg}\n`);
  process.exit(1);
}

// Best-effort musl detection on Linux. ldd --version prints "musl" on musl
// systems; alternatively the dynamic loader path contains "musl". We treat any
// positive signal as musl and resolve to the matching musl target.
function isMusl() {
  if (process.platform !== "linux") return false;
  // Node >= 18 exposes the libc family via report.
  try {
    const report = process.report && process.report.getReport();
    const glibc = report && report.header && report.header.glibcVersionRuntime;
    if (glibc) return false; // glibc runtime present -> not musl
  } catch (_) {
    /* fall through to ldd probe */
  }
  try {
    const out = execFileSync("ldd", ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (/musl/i.test(out)) return true;
  } catch (e) {
    // ldd may print to stderr and exit non-zero; inspect what we captured.
    const text = `${(e && e.stdout) || ""}${(e && e.stderr) || ""}`;
    if (/musl/i.test(text)) return true;
  }
  return false;
}

// Map Node's platform + arch (+ libc) to a Rust target triple and binary name.
function resolveTarget() {
  const platform = process.platform;
  const arch = process.arch; // 'x64' | 'arm64' | ...

  if (platform === "linux") {
    // Both libcs have release binaries since v0.3; resolve accordingly.
    const musl = isMusl();
    if (arch === "x64")
      return {
        triple: musl ? "x86_64-unknown-linux-musl" : "x86_64-unknown-linux-gnu",
        bin: "apohara-agentguard",
      };
    if (arch === "arm64")
      return {
        triple: musl ? "aarch64-unknown-linux-musl" : "aarch64-unknown-linux-gnu",
        bin: "apohara-agentguard",
      };
    fail(`unsupported Linux architecture: ${arch} (supported: x64, arm64)`);
  }

  if (platform === "darwin") {
    if (arch === "x64") return { triple: "x86_64-apple-darwin", bin: "apohara-agentguard" };
    if (arch === "arm64") return { triple: "aarch64-apple-darwin", bin: "apohara-agentguard" };
    fail(`unsupported macOS architecture: ${arch} (supported: x64, arm64)`);
  }

  if (platform === "win32") {
    if (arch === "x64") return { triple: "x86_64-pc-windows-msvc", bin: "apohara-agentguard.exe" };
    fail(`unsupported Windows architecture: ${arch} (supported: x64)`);
  }

  fail(`unsupported platform: ${platform}`);
  return null; // unreachable (fail exits)
}

// Download a URL to a Buffer, following cross-host redirects (GitHub releases
// 302 to objects.githubusercontent.com). Caps the body to guard against an
// unexpectedly huge response.
const MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024; // 64 MiB ceiling for a CLI binary

function download(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    if (redirectsLeft < 0) return reject(new Error("too many redirects"));
    https
      .get(url, { headers: { "user-agent": `apohara-agentguard-npx/${VERSION}` } }, (res) => {
        const { statusCode, headers } = res;
        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          res.resume();
          const next = new URL(headers.location, url).toString();
          return resolve(download(next, redirectsLeft - 1));
        }
        if (statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${statusCode} fetching ${url}`));
        }
        const chunks = [];
        let total = 0;
        res.on("data", (c) => {
          total += c.length;
          if (total > MAX_DOWNLOAD_BYTES) {
            res.destroy();
            return reject(new Error("download exceeded size cap"));
          }
          chunks.push(c);
        });
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Parse a SHA256SUMS manifest (standard sha256sum output: "<hash>  <filename>",
// optionally with a binary-mode "*" marker) into a filename -> hash map.
function parseChecksums(manifestText) {
  const sums = new Map();
  for (const line of manifestText.split("\n")) {
    const m = /^([0-9a-fA-F]{64})\s+\*?(.+)$/.exec(line.trim());
    if (m) sums.set(m[2], m[1].toLowerCase());
  }
  return sums;
}

// Resolve the expected SHA256 for an artifact at run time by fetching the
// release's combined SHA256SUMS manifest. Refuses clearly when the manifest
// cannot be reached or does not cover the artifact.
async function expectedShaFor(artifact) {
  const url = `${BASE_URL}/SHA256SUMS`;
  let buf;
  try {
    buf = await download(url);
  } catch (e) {
    fail(
      `cannot fetch checksum manifest ${url}: ${e.message}\n` +
        "Refusing to run an unverified binary. Offline? Install from source instead:\n" +
        "  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked"
    );
  }
  const expected = parseChecksums(buf.toString("utf8")).get(artifact);
  if (!expected) {
    fail(
      `no checksum for ${artifact} in the v${VERSION} checksum manifest.\n` +
        "Refusing to run an unverified binary. Install from source instead:\n" +
        "  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked"
    );
  }
  return expected;
}

// Cache the verified binary under the OS temp dir keyed by version + triple, so
// repeated `npx apohara-agentguard` invocations don't re-download.
function cachePath(triple, bin) {
  const dir = path.join(os.tmpdir(), `apohara-agentguard-${VERSION}-${triple}`);
  return { dir, file: path.join(dir, bin) };
}

async function ensureBinary() {
  const { triple, bin } = resolveTarget();
  const artifact = `apohara-agentguard-${triple}${bin.endsWith(".exe") ? ".exe" : ""}`;
  const expected = await expectedShaFor(artifact);

  const { dir, file } = cachePath(triple, bin);
  // Reuse a cached binary only if it still matches the expected hash.
  if (fs.existsSync(file)) {
    try {
      if (sha256(fs.readFileSync(file)) === expected) return file;
    } catch (_) {
      /* fall through and re-download */
    }
  }

  const url = `${BASE_URL}/${artifact}`;
  let buf;
  try {
    buf = await download(url);
  } catch (e) {
    fail(`failed to download ${url}: ${e.message}`);
  }

  const got = sha256(buf);
  if (got !== expected) {
    fail(
      "SHA256 mismatch — refusing to run an unverified binary.\n" +
        `  target:   ${triple}\n` +
        `  expected: ${expected}\n` +
        `  got:      ${got}`
    );
  }

  fs.mkdirSync(dir, { recursive: true });
  // Write to a temp file in the cache dir, then rename over the final path so
  // a concurrent or crashed invocation can never observe a partial binary.
  const tmpFile = `${file}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(tmpFile, buf, { mode: 0o755 });
    fs.renameSync(tmpFile, file);
  } catch (e) {
    try {
      fs.unlinkSync(tmpFile);
    } catch (_) {
      /* best-effort cleanup */
    }
    throw e;
  }
  return file;
}

function execBinary(file) {
  const args = process.argv.slice(2);
  const res = spawnSync(file, args, { stdio: "inherit" });
  if (res.error) fail(`failed to exec ${file}: ${res.error.message}`);
  process.exit(res.status === null ? 1 : res.status);
}

async function main() {
  const file = await ensureBinary();
  execBinary(file);
}

// Only run when invoked as a script. When `require`d (e.g. `node -e
// "require('./bin/apohara-agentguard.js')"` in CI smoke tests), do not auto-execute —
// just expose the resolver for inspection.
if (require.main === module) {
  main().catch((e) => fail(e && e.message ? e.message : String(e)));
}

module.exports = { resolveTarget, isMusl, sha256, parseChecksums, VERSION };
