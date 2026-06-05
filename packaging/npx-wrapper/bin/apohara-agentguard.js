#!/usr/bin/env node
//
// apohara-agentguard npx launcher.
//
// apohara-agentguard is a security tool, so this launcher NEVER runs an unverified
// binary. It resolves the correct release artifact by platform x arch x libc,
// downloads it, verifies its SHA256 against a pinned manifest, and only then
// execs it — forwarding argv and stdio unchanged. A checksum mismatch aborts.
//
// Resolution matrix (v0.1):
//   linux  x86_64  (glibc)  -> x86_64-unknown-linux-gnu
//   linux  aarch64 (glibc)  -> aarch64-unknown-linux-gnu
//   linux  *       (musl)   -> NOT SUPPORTED in v0.1 (clear message, no fallback)
//   darwin x86_64           -> x86_64-apple-darwin
//   darwin aarch64          -> aarch64-apple-darwin
//   win32  x86_64           -> x86_64-pc-windows-msvc (.exe)
//
// musl is detected and explicitly refused rather than running a glibc binary
// against a musl loader (which would crash or, worse, behave unpredictably).

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { spawnSync, execFileSync } = require("child_process");

const VERSION = "0.1.0";

// Base URL for release artifacts. Overridable for testing / mirrors.
const BASE_URL =
  process.env.AGENTGUARD_DOWNLOAD_BASE ||
  `https://github.com/SuarezPM/apohara-agentguard/releases/download/v${VERSION}`;

// SHA256 manifest, keyed by Rust target triple. These are the canonical hashes
// of the v0.1.0 release artifacts; they are filled in by the release workflow
// (release.yml emits a SHA256SUMS manifest) and committed here before publish.
// A literal "REPLACE_WITH_RELEASE_SHA256" means the manifest is not yet pinned
// for this version: the launcher refuses to download rather than trust an
// unverifiable artifact.
const SHA256 = {
  "x86_64-unknown-linux-gnu": "REPLACE_WITH_RELEASE_SHA256",
  "aarch64-unknown-linux-gnu": "REPLACE_WITH_RELEASE_SHA256",
  "x86_64-apple-darwin": "REPLACE_WITH_RELEASE_SHA256",
  "aarch64-apple-darwin": "REPLACE_WITH_RELEASE_SHA256",
  "x86_64-pc-windows-msvc": "REPLACE_WITH_RELEASE_SHA256",
};

function fail(msg) {
  process.stderr.write(`apohara-agentguard: ${msg}\n`);
  process.exit(1);
}

// Best-effort musl detection on Linux. ldd --version prints "musl" on musl
// systems; alternatively the dynamic loader path contains "musl". We treat any
// positive signal as musl and refuse (deferred to v0.2).
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
    if (isMusl()) {
      fail(
        "musl libc is not yet supported in v0.1. Install from source instead:\n" +
          "  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked\n" +
          "(musl release binaries are planned for v0.2.)"
      );
    }
    if (arch === "x64") return { triple: "x86_64-unknown-linux-gnu", bin: "apohara-agentguard" };
    if (arch === "arm64") return { triple: "aarch64-unknown-linux-gnu", bin: "apohara-agentguard" };
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

// Cache the verified binary under the OS temp dir keyed by version + triple, so
// repeated `npx apohara-agentguard` invocations don't re-download.
function cachePath(triple, bin) {
  const dir = path.join(os.tmpdir(), `apohara-agentguard-${VERSION}-${triple}`);
  return { dir, file: path.join(dir, bin) };
}

async function ensureBinary() {
  const { triple, bin } = resolveTarget();
  const expected = SHA256[triple];
  if (!expected || expected === "REPLACE_WITH_RELEASE_SHA256") {
    fail(
      `no pinned SHA256 for target ${triple}. This build of the launcher was\n` +
        "published without a release manifest. Install from source instead:\n" +
        "  cargo install --git https://github.com/SuarezPM/apohara-agentguard --locked"
    );
  }

  const { dir, file } = cachePath(triple, bin);
  // Reuse a cached binary only if it still matches the pinned hash.
  if (fs.existsSync(file)) {
    try {
      if (sha256(fs.readFileSync(file)) === expected) return file;
    } catch (_) {
      /* fall through and re-download */
    }
  }

  const url = `${BASE_URL}/apohara-agentguard-${triple}${bin.endsWith(".exe") ? ".exe" : ""}`;
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
  fs.writeFileSync(file, buf, { mode: 0o755 });
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

module.exports = { resolveTarget, isMusl, sha256, SHA256, VERSION };
