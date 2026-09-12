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

/// If `leg` contains a base64 decode stage fed by a literal payload, decode the
/// payload and return the decoded UTF-8 text for rescanning.
///
/// Returns `None` when: there is no base64-decode stage, no decodable payload is
/// present, `depth >= MAX_DECODE_DEPTH`, the decoded size exceeds
/// `MAX_DECODE_BYTES`, or the bytes are not valid UTF-8.
pub(crate) fn decode_and_expand(leg: &str, depth: u8) -> Option<String> {
    if depth >= MAX_DECODE_DEPTH {
        return None;
    }
    if !leg.contains("base64") && !leg.contains("openssl") {
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

/// True iff `leg` pipes into a base64 decode stage (e.g. `base64 -d`, `/usr/bin/base64 -di`, `openssl base64 -d`).
pub(crate) fn has_base64_decode_stage(leg: &str) -> bool {
    if !leg.contains("base64") && !leg.contains("openssl") {
        return false;
    }
    leg.split('|').any(|stage| is_base64_decode_stage(stage.trim()))
}

fn is_base64_decode_stage(stage: &str) -> bool {
    let mut tokens = stage.split_whitespace();

    // Skip environment variables (FOO=bar) and wrappers (env, command, builtin, sudo, exec).
    let mut cmd_token = None;
    for t in tokens.by_ref() {
        if is_env_var_assignment(t) || is_wrapper_cmd(t) {
            continue;
        }
        cmd_token = Some(t);
        break;
    }

    let Some(cmd) = cmd_token else { return false };
    let cmd_name = cmd.rsplit('/').next().unwrap_or(cmd);

    if cmd_name == "base64" {
        // Look for decode flag: --decode, --decode=..., or short flag containing 'd' or 'D' (e.g. -d, -D, -di, -dw0)
        tokens.any(is_base64_decode_flag)
    } else if cmd_name == "openssl" {
        // openssl base64 -d or openssl enc -d -base64 or openssl base64 -decode
        let rest: Vec<&str> = tokens.collect();
        let has_base64_subcmd = rest.iter().any(|&t| t == "base64" || t == "-base64");
        let has_decode_flag = rest.iter().any(|&t| t == "-d" || t == "-decode");
        has_base64_subcmd && has_decode_flag
    } else {
        false
    }
}

fn is_env_var_assignment(token: &str) -> bool {
    if let Some(eq_pos) = token.find('=') {
        eq_pos > 0 && token[..eq_pos].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        false
    }
}

fn is_wrapper_cmd(token: &str) -> bool {
    let name = token.rsplit('/').next().unwrap_or(token);
    matches!(name, "env" | "command" | "builtin" | "sudo" | "exec")
}

fn is_base64_decode_flag(token: &str) -> bool {
    if token == "--decode" || token.starts_with("--decode=") {
        return true;
    }
    if token.starts_with('-') && !token.starts_with("--") && token.len() > 1 {
        let flag_body = &token[1..];
        return flag_body.contains('d') || flag_body.contains('D');
    }
    false
}

/// Extract the base64 payload feeding the pipe. Handles echo, printf, cat herestrings, and bare literals.
fn extract_payload(leg: &str) -> Option<String> {
    let first_stage = leg.split('|').next()?.trim();
    let mut tokens = first_stage.split_whitespace().peekable();

    // Skip environment variables and wrappers in first stage
    while let Some(&t) = tokens.peek() {
        if is_env_var_assignment(t) || is_wrapper_cmd(t) {
            tokens.next();
        } else {
            break;
        }
    }

    let head = tokens.next()?;
    let head_name = head.rsplit('/').next().unwrap_or(head);

    if head_name == "echo" {
        while let Some(&t) = tokens.peek() {
            if is_echo_flag(t) {
                tokens.next();
            } else {
                break;
            }
        }
        let rest: Vec<&str> = tokens.collect();
        let joined = rest.join(" ");
        Some(strip_quotes(joined.trim()))
    } else if head_name == "printf" {
        while let Some(&t) = tokens.peek() {
            if t == "--" {
                tokens.next();
                break;
            }
            if is_printf_format_specifier(t) {
                tokens.next();
            } else {
                break;
            }
        }
        let rest: Vec<&str> = tokens.collect();
        if rest.is_empty() {
            None
        } else {
            let joined = rest.join(" ");
            Some(strip_quotes(joined.trim()))
        }
    } else if head_name == "cat" {
        let rest: Vec<&str> = tokens.collect();
        let rest_str = rest.join(" ");
        if let Some(pos) = rest_str.find("<<<") {
            let payload = rest_str[pos + 3..].trim();
            Some(strip_quotes(payload))
        } else if rest.len() == 1 {
            Some(strip_quotes(rest[0]))
        } else {
            None
        }
    } else {
        // Bare literal payload (single token).
        Some(strip_quotes(head))
    }
}

fn is_echo_flag(token: &str) -> bool {
    if token.starts_with('-') && token.len() > 1 {
        token[1..].chars().all(|c| c == 'n' || c == 'e' || c == 'E')
    } else {
        false
    }
}

fn is_printf_format_specifier(token: &str) -> bool {
    let unquoted = strip_quotes(token);
    unquoted == "%s" || unquoted == "%s\n" || unquoted == "%b" || unquoted == "%b\n" || unquoted.starts_with('%')
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

    #[test]
    fn decodes_various_bypass_shapes() {
        // `cm0gLXJmIH4K` is base64 for "rm -rf ~\n".
        let cases = [
            "echo cm0gLXJmIH4K | base64 -di",
            "echo cm0gLXJmIH4K | base64 -D",
            "echo cm0gLXJmIH4K | /usr/bin/base64 -d",
            "echo cm0gLXJmIH4K | /bin/base64 -di",
            "echo cm0gLXJmIH4K | env base64 -d",
            "echo cm0gLXJmIH4K | FOO=1 base64 -d",
            "echo cm0gLXJmIH4K | openssl base64 -d",
            "printf cm0gLXJmIH4K | base64 -d",
            "printf '%s' cm0gLXJmIH4K | base64 -d",
            "echo -ne cm0gLXJmIH4K | base64 -d",
            "cat <<< cm0gLXJmIH4K | base64 -d",
        ];
        for leg in cases {
            let out = decode_and_expand(leg, 0).unwrap_or_else(|| panic!("failed to decode for: {leg}"));
            assert_eq!(out.trim(), "rm -rf ~", "unexpected decode output for: {leg}");
        }
    }
}
