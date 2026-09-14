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
    if !has_base64_decode_stage(leg) {
        return None;
    }
    let payload = extract_payload(leg)?;
    let clean_payload: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = STANDARD.decode(clean_payload.as_bytes()).ok()?;
    if decoded.len() > MAX_DECODE_BYTES {
        return None;
    }
    String::from_utf8(decoded).ok()
}

/// True iff `leg` pipes into a `base64 -d` / `base64 --decode` stage (or openssl base64 -d).
pub(crate) fn has_base64_decode_stage(leg: &str) -> bool {
    if !leg.contains("base64") && !leg.contains("b64") {
        return false;
    }
    leg.split('|').any(is_base64_decode_stage)
}

fn is_base64_decode_stage(stage: &str) -> bool {
    let s = stage.trim();
    let mut tokens = s.split_whitespace();

    let mut head = match tokens.next() {
        Some(h) => h,
        None => return false,
    };
    while is_wrapper(head) {
        head = match tokens.next() {
            Some(h) => h,
            None => return false,
        };
    }

    let bin_name = head.rsplit('/').next().unwrap_or(head);
    if bin_name == "base64" {
        tokens.any(is_base64_decode_flag)
    } else if bin_name == "openssl" {
        let tok_vec: Vec<&str> = tokens.collect();
        let has_b64_mode = tok_vec.iter().any(|t| {
            *t == "base64" || *t == "-base64" || *t == "b64" || *t == "-b64" || *t == "enc"
        });
        let has_dec_flag = tok_vec.iter().any(|t| is_base64_decode_flag(t));
        has_b64_mode && has_dec_flag
    } else {
        false
    }
}

fn is_wrapper(token: &str) -> bool {
    let bin_name = token.rsplit('/').next().unwrap_or(token);
    matches!(bin_name, "env" | "sudo" | "stdbuf" | "time" | "command")
}

fn is_base64_decode_flag(token: &str) -> bool {
    if token == "--decode" {
        return true;
    }
    if token == "-D" {
        return true;
    }
    if token.starts_with('-') && !token.starts_with("--") {
        let flag_body = &token[1..];
        return flag_body.contains('d') || flag_body.contains('D');
    }
    false
}

/// Extract the base64 payload feeding the pipe or herestring. Handles shapes:
/// - `<cmd> <<< <payload>`          — payload is herestring input.
/// - `echo <payload> | ...`          — payload is echo argument(s).
/// - `printf <payload> | ...`        — payload is printf argument(s).
/// - `cat <<< <payload> | ...`       — payload is herestring/cat argument.
/// - `<payload> | base64 -d ...`      — payload is a bare leading token.
fn extract_payload(leg: &str) -> Option<String> {
    if let Some(pos) = leg.find("<<<") {
        let after = leg[pos + 3..].trim();
        let payload_raw = if after.starts_with('"') || after.starts_with('\'') {
            extract_quoted_prefix(after)
        } else {
            after.split_whitespace().next().unwrap_or("")
        };
        return Some(strip_quotes(payload_raw));
    }

    let first_stage = leg.split('|').next()?.trim();
    let mut tokens = first_stage.split_whitespace();
    let mut head = tokens.next()?;

    while is_wrapper(head) {
        head = tokens.next()?;
    }

    let bin_name = head.rsplit('/').next().unwrap_or(head);

    if bin_name == "echo" {
        let rest: Vec<&str> = tokens.collect();
        let rest = skip_echo_flags(&rest);
        let joined = rest.join(" ");
        Some(strip_quotes(joined.trim()))
    } else if bin_name == "printf" {
        let rest: Vec<&str> = tokens.collect();
        if rest.is_empty() {
            return None;
        }
        let first_unquoted = strip_quotes(rest[0]);
        let payload_tok = if first_unquoted.starts_with('%') {
            rest.get(1)?
        } else {
            &rest[0]
        };
        Some(strip_quotes(payload_tok))
    } else if bin_name == "cat" {
        let rest: Vec<&str> = tokens.collect();
        if rest.is_empty() {
            return None;
        }
        Some(strip_quotes(rest[0]))
    } else {
        // Bare literal payload (single token).
        Some(strip_quotes(head))
    }
}

fn skip_echo_flags<'a>(tokens: &'a [&'a str]) -> &'a [&'a str] {
    let mut idx = 0;
    while idx < tokens.len() {
        let t = tokens[idx];
        if t.starts_with('-') && t.len() > 1 && t[1..].chars().all(|c| matches!(c, 'n' | 'e' | 'E'))
        {
            idx += 1;
        } else {
            break;
        }
    }
    &tokens[idx..]
}

fn extract_quoted_prefix(s: &str) -> &str {
    let bytes = s.as_bytes();
    let quote = bytes[0];
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == quote && bytes[i - 1] != b'\\' {
            return &s[..=i];
        }
        i += 1;
    }
    s
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
    fn decodes_pathed_binary() {
        let leg = "echo cm0gLXJmIH4K | /usr/bin/base64 -d | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_combined_flags() {
        let leg = "echo cm0gLXJmIH4K | base64 -di | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");

        let mac = "echo cm0gLXJmIH4K | base64 -D | sh";
        let out_mac = decode_and_expand(mac, 0).expect("decode mac");
        assert_eq!(out_mac.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_wrapper_command() {
        let leg = "echo cm0gLXJmIH4K | sudo env /usr/bin/base64 -d | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_openssl_base64() {
        let leg = "echo cm0gLXJmIH4K | openssl base64 -d | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_printf_payload() {
        let leg = "printf '%s' 'cm0gLXJmIH4K' | base64 -d | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
    }

    #[test]
    fn decodes_herestring_payload() {
        let leg = "base64 -d <<< 'cm0gLXJmIH4K' | sh";
        let out = decode_and_expand(leg, 0).expect("decode");
        assert_eq!(out.trim(), "rm -rf ~");
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
