//! Base64 decode + bounded rescan of piped payloads.
//!
//! Closes the `echo <b64> | base64 -d | sh` bypass: a payload smuggled through
//! base64 is invisible to a literal pattern match. This module detects a
//! `base64 -d` / `base64 --decode` stage fed by an `echo <payload>` (or a bare
//! literal) earlier in the same pipe, decodes the payload, and returns the
//! decoded text so the gate can rescan it.
//!
//! HARD limits guard against decode bombs and infinite recursion:
//! - [`MAX_DECODE_DEPTH`] caps how deep the gate may recurse into decoded text.
//! - [`MAX_DECODE_BYTES`] caps the decoded payload size.
//!
//! Beyond either limit this returns `None`; the caller WARNs rather than
//! recursing further.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Maximum recursion depth for decode-and-rescan (guards against decode loops).
pub(crate) const MAX_DECODE_DEPTH: u8 = 2;

/// Maximum decoded payload size in bytes (64 KiB). Larger payloads are refused.
pub(crate) const MAX_DECODE_BYTES: usize = 64 * 1024;

/// If `leg` contains a `base64 -d` / `base64 --decode` stage fed by a literal
/// payload, decode the payload and return the decoded UTF-8 text for rescanning.
///
/// Returns `None` when: there is no base64-decode stage, no decodable payload is
/// present, `depth >= MAX_DECODE_DEPTH`, the decoded size exceeds
/// `MAX_DECODE_BYTES`, or the bytes are not valid UTF-8.
pub(crate) fn decode_and_expand(leg: &str, depth: u8) -> Option<String> {
    if depth >= MAX_DECODE_DEPTH {
        return None;
    }
    if !leg.contains("base64") {
        return None;
    }
    if !has_base64_decode_stage(leg) {
        return None;
    }
    let payload = extract_payload(leg)?;
    let decoded = STANDARD.decode(payload.as_bytes()).ok()?;
    if decoded.len() > MAX_DECODE_BYTES {
        return None;
    }
    String::from_utf8(decoded).ok()
}

/// True iff `leg` pipes into a base64 decode stage (e.g. `base64 -d`, `base64 -di`,
/// `base64 -D`, `/usr/bin/base64 -d`, `openssl base64 -d`, `env base64 -d`, `sudo base64 -d`).
fn has_base64_decode_stage(leg: &str) -> bool {
    if !leg.contains("base64") {
        return false;
    }
    leg.split('|').any(|stage| {
        let s = stage.trim();
        let mut tokens = s.split_whitespace().peekable();

        // Skip command wrappers like `env`, `sudo` and flags
        while let Some(&t) = tokens.peek() {
            if t == "env" || t == "sudo" || (t.starts_with('-') && !t.contains("base64")) {
                tokens.next();
            } else {
                break;
            }
        }

        let head = match tokens.next() {
            Some(h) => h,
            None => return false,
        };

        let is_base64_cmd = head == "base64" || head.ends_with("/base64");
        let is_openssl_cmd = head == "openssl" && tokens.peek().copied() == Some("base64");
        if is_openssl_cmd {
            tokens.next(); // consume "base64"
        }

        if !is_base64_cmd && !is_openssl_cmd {
            return false;
        }

        tokens.any(is_decode_flag)
    })
}

fn is_decode_flag(t: &str) -> bool {
    if t == "--decode" || t.starts_with("--decode=") {
        return true;
    }
    if t.starts_with('-') && !t.starts_with("--") {
        return t.contains('d') || t.contains('D');
    }
    false
}

/// Extract the base64 payload feeding the pipe. Handles multiple shapes:
/// - `echo [flags] <payload> | base64 -d ...`
/// - `printf [flags] [%s] <payload> | base64 -d ...`
/// - `cat <<< <payload> | base64 -d ...`
/// - `<payload> | base64 -d ...` (bare literal)
fn extract_payload(leg: &str) -> Option<String> {
    let first_stage = leg.split('|').next()?.trim();
    let mut tokens = first_stage.split_whitespace();
    let head = tokens.next()?;

    let payload_raw = if head == "echo" {
        let rest: Vec<&str> = tokens.collect();
        let mut idx = 0;
        while idx < rest.len() && rest[idx].starts_with('-') {
            if rest[idx] == "--" {
                idx += 1;
                break;
            }
            idx += 1;
        }
        rest[idx..].join(" ")
    } else if head == "printf" {
        let rest: Vec<&str> = tokens.collect();
        let mut idx = 0;
        while idx < rest.len() && rest[idx].starts_with('-') {
            if rest[idx] == "--" {
                idx += 1;
                break;
            }
            idx += 1;
        }
        if idx < rest.len() && rest[idx].contains('%') {
            idx += 1;
        }
        rest[idx..].join(" ")
    } else if head == "cat" {
        let rest = tokens.collect::<Vec<_>>().join(" ");
        if let Some(after) = rest.strip_prefix("<<<") {
            after.trim().to_string()
        } else {
            return None;
        }
    } else {
        head.to_string()
    };

    let trimmed = payload_raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(strip_quotes(trimmed))
    }
}

/// Strip one layer of matching single/double quotes.
fn strip_quotes(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_echo_piped_payload() {
        // `cm0gLXJmIH4K` is base64 for "rm -rf ~\n".
        let leg = "echo cm0gLXJmIH4K | base64 -d | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_combined_flags_and_path_variants() {
        let cases = [
            "echo cm0gLXJmIH4K | base64 -di | sh",
            "echo cm0gLXJmIH4K | base64 -D | sh",
            "echo cm0gLXJmIH4K | /usr/bin/base64 -d | sh",
            "echo cm0gLXJmIH4K | openssl base64 -d | sh",
            "echo cm0gLXJmIH4K | env base64 -d | sh",
            "printf cm0gLXJmIH4K | base64 -d | sh",
            "printf '%s' cm0gLXJmIH4K | base64 -d | sh",
            "cat <<< cm0gLXJmIH4K | base64 -d | sh",
        ];
        for leg in cases {
            let out = decode_and_expand(leg, 0).expect("decode");
            assert_eq!(out.trim(), "rm -rf ~", "failed for: {leg}");
        }
    }

    #[test]
    fn decodes_long_decode_flag() {
        let leg = "echo cm0gLXJmIH4K | base64 --decode";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_bare_literal_payload() {
        let leg = "cm0gLXJmIH4K | base64 -d";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn no_decode_stage_returns_none() {
        assert!(decode_and_expand("echo hello | cat", 0).is_none());
    }

    #[test]
    fn depth_cap_blocks_recursion() {
        let leg = "echo cm0gLXJmIH4K | base64 -d | sh";
        assert!(decode_and_expand(leg, MAX_DECODE_DEPTH).is_none());
    }

    #[test]
    fn invalid_base64_returns_none() {
        let leg = "echo 'not valid base64 !!!' | base64 -d";
        assert!(decode_and_expand(leg, 0).is_none());
    }

    #[test]
    fn oversized_payload_returns_none() {
        // Encode a payload larger than the cap; decode must refuse it.
        let big = "A".repeat(MAX_DECODE_BYTES + 1);
        let encoded = STANDARD.encode(big.as_bytes());
        let leg = format!("echo {encoded} | base64 -d");
        assert!(decode_and_expand(&leg, 0).is_none());
    }
}
