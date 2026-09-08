//! Secret redaction applied to audit command text BEFORE serialization,
//! truncation, and hashing. Two layers: a typed issuer table (shape-based
//! credential formats) and a legacy name-shape token walk. The same
//! discipline as the sandbox env sanitizer — a bounded set, not a PII scrubber.

use std::sync::LazyLock;

use regex::Regex;

/// Mask secret-shaped material in `text` before it is written to disk.
///
/// Two layers, applied in order:
///
/// 1. **Typed issuer table** ([`ISSUERS`]): known credential formats are
///    detected by shape and masked to a short recognizable prefix plus
///    `…[REDACTED-<issuer>]` (e.g. `sk-ant-api03-…[REDACTED-anthropic]`).
///    Each entry documents its minimum-length threshold; benign lookalikes
///    below the threshold (`sk-demo`, the word `skull`, short demo tokens)
///    are NOT flagged. The table runs BEFORE truncation so a secret can
///    never survive a cut, and before the legacy pass below.
/// 2. **Legacy name-shape pass**: `NAME=value` where NAME is secret-shaped
///    (`*KEY`/`*TOKEN`/`*SECRET`/`*PASSWORD`/`*PASSWD`, plus known prefixes)
///    -> `NAME=***`; `-p<password>` and `--password=<val>` -> `-p***`;
///    `Authorization: Bearer <token>` / `Authorization: <token>` (incl.
///    inside a `-H "..."`) -> the token replaced with `***`. Values already
///    carrying a typed `[REDACTED-…]` marker are left as-is so the more
///    informative mask survives.
///
/// This is a deliberate, bounded set — the same secret-name discipline used by
/// the sandbox env sanitizer — not a general PII scrubber.
pub(crate) fn redact_secrets(text: &str) -> String {
    // Layer 1: typed issuer masks (whole-text, handles multi-line PEM blocks
    // and bare tokens the whitespace walk below cannot see).
    let mut out = text.to_string();
    for issuer in ISSUERS.iter() {
        if issuer.re.is_match(&out) {
            out = issuer
                .re
                .replace_all(&out, |caps: &regex::Captures| {
                    let whole = caps.get(0).expect("group 0 always present");
                    let prefix_end = caps
                        .get(1)
                        .map(|g| g.end() - whole.start())
                        .unwrap_or(whole.len());
                    format!(
                        "{}…[REDACTED-{}]",
                        &whole.as_str()[..prefix_end],
                        issuer.name
                    )
                })
                .into_owned();
        }
    }

    // Layer 2: legacy token walk (NAME=, -p, Authorization headers).
    redact_by_token_walk(&out)
}

/// One typed credential issuer. `re` MUST carry capture group 1 = the short
/// recognizable prefix kept visible in the mask (the rest of the match is
/// replaced with `…[REDACTED-<name>]`).
struct Issuer {
    /// Issuer tag embedded in the mask (`REDACTED-<name>`).
    name: &'static str,
    /// Detection regex. Minimum-length thresholds are part of each pattern —
    /// they are what keeps benign lookalikes (`sk-demo`, `skull`, short demo
    /// tokens) unflagged. Documented per entry below.
    re: Regex,
}

/// Ordered most-specific-first: a credential sharing another entry's prefix
/// shape must be caught by its own rule first (`sk-ant-…` and `sk_live_…`
/// before openai's generic `sk-…`; after masking, the remnant no longer
/// satisfies the later rule's minimum length, so double-masking cannot occur).
static ISSUERS: LazyLock<Vec<Issuer>> = LazyLock::new(|| {
    vec![
        // Anthropic: `sk-ant-api03-…` / `sk-ant-admin…` — ≥16 chars after the
        // versioned prefix (real keys are far longer).
        Issuer {
            name: "anthropic",
            re: Regex::new(r"\b(sk-ant-(?:api|admin)\d{2}-)[A-Za-z0-9_-]{16,}").expect("regex"),
        },
        // Stripe live-mode secret/restricted key: `sk_live_`/`rk_live_` +
        // ≥16 chars. Test-mode keys (`sk_test_`) are not flagged. MUST run
        // before the generic openai `sk-…` rule.
        Issuer {
            name: "stripe",
            re: Regex::new(r"\b((?:sk|rk)_live_)[A-Za-z0-9]{16,}").expect("regex"),
        },
        // GitHub: `ghp_`/`gho_`/`ghs_`/`ghu_` classic/app tokens and
        // `github_pat_` fine-grained tokens — ≥20 chars after the prefix.
        Issuer {
            name: "github",
            re: Regex::new(r"\b(gh[posu]_|github_pat_)[A-Za-z0-9_]{20,}").expect("regex"),
        },
        // AWS access key id: `AKIA`/`ASIA` + exactly 16 UPPERCASE alphanumerics
        // (the fixed length is the false-positive guard).
        Issuer {
            name: "aws",
            re: Regex::new(r"\b((?:AKIA|ASIA))[A-Z0-9]{16}\b").expect("regex"),
        },
        // GitLab personal access token: `glpat-` + ≥20 chars.
        Issuer {
            name: "gitlab",
            re: Regex::new(r"\b(glpat-)[A-Za-z0-9_-]{20,}").expect("regex"),
        },
        // GCP OAuth2 access token: `ya29.` + ≥20 chars.
        Issuer {
            name: "gcp",
            re: Regex::new(r"\b(ya29\.)[A-Za-z0-9._-]{20,}").expect("regex"),
        },
        // PyPI API token: `pypi-` + ≥30 chars (real tokens are ~150).
        Issuer {
            name: "pypi",
            re: Regex::new(r"\b(pypi-)[A-Za-z0-9_-]{30,}").expect("regex"),
        },
        // npm automation/deploy token: `npm_` + ≥20 chars.
        Issuer {
            name: "npm",
            re: Regex::new(r"\b(npm_)[A-Za-z0-9]{20,}").expect("regex"),
        },
        // Hugging Face token: `hf_` + ≥20 chars.
        Issuer {
            name: "huggingface",
            re: Regex::new(r"\b(hf_)[A-Za-z0-9]{20,}").expect("regex"),
        },
        // Slack bot/user/app tokens: `xox[baprs]-` + ≥10 chars.
        Issuer {
            name: "slack",
            re: Regex::new(r"\b(xox[baprs]-)[A-Za-z0-9-]{10,}").expect("regex"),
        },
        // JWT: three dot-separated base64url segments, header starting with
        // the `eyJ` signature of `{"alg"`/`{"typ"`, each segment ≥10 chars.
        Issuer {
            name: "jwt",
            re: Regex::new(r"\b(eyJ)[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .expect("regex"),
        },
        // PEM private key block: BEGIN header through END line (multi-line;
        // the recognizable BEGIN header is what stays visible in the mask).
        Issuer {
            name: "pem",
            re: Regex::new(
                r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            )
            .expect("regex"),
        },
        // OpenAI: `sk-…` / `sk-proj-…` — requires ≥20 chars after the prefix
        // (real keys are ≥40); `sk-demo`, `sk-test1` etc. stay unflagged.
        // Runs AFTER anthropic/stripe so their `sk-…` shapes are consumed
        // by their own rules first.
        Issuer {
            name: "openai",
            re: Regex::new(r"\b(sk-(?:proj-)?)[A-Za-z0-9_-]{20,}").expect("regex"),
        },
        // Generic bearer credential outside an Authorization header:
        // `Bearer ` + ≥20 token characters (short words after `Bearer` in
        // prose stay unflagged).
        Issuer {
            name: "bearer",
            re: Regex::new(r"\b([Bb]earer )[A-Za-z0-9._~+/=-]{20,}").expect("regex"),
        },
    ]
});

/// The legacy whitespace-token walk: `NAME=value` with a secret-shaped NAME,
/// `-p<password>` / `--password=` flags, and `Authorization:` headers. Runs
/// AFTER the typed issuer pass (see [`redact_secrets`]).
fn redact_by_token_walk(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    // Tokenize on whitespace but preserve the original separators so the masked
    // text stays readable. We re-split conservatively: secrets we care about are
    // either whitespace-delimited tokens (`NAME=val`, `-pPW`) or follow an
    // `Authorization:` header marker.
    let mut rest = text;
    let mut awaiting_auth_value = false;
    while !rest.is_empty() {
        // Emit leading whitespace verbatim.
        let ws_len = rest.len() - rest.trim_start().len();
        if ws_len > 0 {
            out.push_str(&rest[..ws_len]);
            rest = &rest[ws_len..];
            if rest.is_empty() {
                break;
            }
        }
        // Next token = up to the next whitespace.
        let tok_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..tok_end];
        out.push_str(&mask_token(token, &mut awaiting_auth_value));
        rest = &rest[tok_end..];
    }
    out
}

/// Mask a single whitespace-delimited token. `awaiting_auth_value` carries the
/// `Authorization:`-header state across tokens (the value follows the header
/// name and `Bearer` keyword).
fn mask_token(token: &str, awaiting_auth_value: &mut bool) -> String {
    // Strip an optional surrounding quote so `-H "Authorization: Bearer x"`
    // and bare tokens are handled alike; re-add the quote on the way out.
    let (open_q, body, close_q) = strip_quotes(token);

    // 1) An `Authorization:` header marker: mask everything after it on this
    //    token, and arm `awaiting_auth_value` for the next token(s).
    if let Some(masked) = mask_authorization(body, awaiting_auth_value) {
        return format!("{open_q}{masked}{close_q}");
    }

    // 2) We are mid-Authorization value (the token after `Authorization:` or
    //    `Bearer`): mask the whole token unless it's the `Bearer` keyword.
    //    A value already carrying a typed issuer mask keeps it.
    if *awaiting_auth_value {
        if body.eq_ignore_ascii_case("Bearer") {
            return format!("{open_q}{body}{close_q}");
        }
        *awaiting_auth_value = false;
        if body.contains("[REDACTED") {
            return format!("{open_q}{body}{close_q}");
        }
        return format!("{open_q}***{close_q}");
    }

    // 3) `-p<password>` (mysql-style) and `--password[=val]`.
    if let Some(masked) = mask_password_flag(body) {
        return format!("{open_q}{masked}{close_q}");
    }

    // 4) `NAME=value` with a secret-shaped NAME.
    if let Some(masked) = mask_secret_assignment(body) {
        return format!("{open_q}{masked}{close_q}");
    }

    token.to_string()
}

/// Split a token into (leading quote, inner, trailing quote), peeling a single
/// leading and/or trailing quote character INDEPENDENTLY. This handles tokens
/// where a quoted span straddles whitespace — e.g. `-H "Authorization: Bearer
/// sk-..."` tokenizes to `"Authorization:` (leading quote only) and `sk-..."`
/// (trailing quote only) — so the header marker and its value are still
/// recognized and masked.
fn strip_quotes(token: &str) -> (&str, &str, &str) {
    let b = token.as_bytes();
    let lead = matches!(b.first(), Some(b'"') | Some(b'\''));
    // Only treat a trailing quote as a closer when the token isn't a single
    // quote char already consumed as the leader.
    let trail = b.len() > if lead { 1 } else { 0 } && matches!(b.last(), Some(b'"') | Some(b'\''));
    let start = if lead { 1 } else { 0 };
    let end = if trail { token.len() - 1 } else { token.len() };
    (&token[..start], &token[start..end], &token[end..])
}

/// Mask an `Authorization:` header. Returns `Some(masked)` if `body` starts the
/// header. Sets `awaiting_auth_value` when the value spills to the next token.
fn mask_authorization(body: &str, awaiting_auth_value: &mut bool) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let prefix_len = if lower.starts_with("authorization:") {
        "authorization:".len()
    } else {
        return None;
    };
    let (head, tail) = body.split_at(prefix_len);
    let tail = tail.trim_start();
    if tail.is_empty() {
        // `Authorization:` then the value is in the next token(s).
        *awaiting_auth_value = true;
        return Some(format!("{head} "));
    }
    // `Authorization: Bearer <tok>` or `Authorization: <tok>` on one token
    // (rare without quotes, but handle it): keep an optional `Bearer`, mask the
    // rest.
    let rest = tail
        .strip_prefix("Bearer ")
        .or_else(|| tail.strip_prefix("bearer "));
    match rest {
        Some(_) => Some(format!("{head} Bearer ***")),
        None => Some(format!("{head} ***")),
    }
}

/// Mask `-p<password>` and `--password[=val]`. Returns `None` if not a password
/// flag.
fn mask_password_flag(body: &str) -> Option<String> {
    if let Some(val) = body.strip_prefix("--password=") {
        if !val.is_empty() {
            return Some("--password=***".to_string());
        }
    }
    // `-p<password>` (no space), mysql/redis style. A bare `-p` (no value)
    // prompts interactively and carries no secret — leave it.
    if let Some(val) = body.strip_prefix("-p") {
        if !val.is_empty() && !val.starts_with('-') {
            return Some("-p***".to_string());
        }
    }
    None
}

/// Mask `NAME=value` when NAME is secret-shaped. Returns `None` otherwise.
fn mask_secret_assignment(body: &str) -> Option<String> {
    let eq = body.find('=')?;
    let name = &body[..eq];
    let value = &body[eq + 1..];
    if name.is_empty() || value.is_empty() {
        return None;
    }
    // A value already carrying a typed issuer mask keeps its more
    // informative form — do not collapse it to `***`.
    if value.contains("[REDACTED") {
        return None;
    }
    // `export NAME=value` — peel a leading keyword so the name shape is checked.
    let bare_name = name.rsplit(char::is_whitespace).next().unwrap_or(name);
    if is_secret_name(bare_name) {
        let prefix = &name[..name.len() - bare_name.len()];
        Some(format!("{prefix}{bare_name}=***"))
    } else {
        None
    }
}

/// Whether `name` is a secret-shaped environment/variable name. Mirrors the
/// sandbox env sanitizer's discipline (suffixes + known prefixes + named set).
fn is_secret_name(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    const SUFFIXES: &[&str] = &[
        "_API_KEY",
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSWD",
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
    ];
    const PREFIXES: &[&str] = &[
        "ANTHROPIC_",
        "OPENAI_",
        "AWS_",
        "GCP_",
        "AZURE_",
        "GITHUB_",
        "GITLAB_",
        "STRIPE_",
    ];
    if PREFIXES.iter().any(|p| up.starts_with(p)) || SUFFIXES.iter().any(|s| up.ends_with(s)) {
        return true;
    }
    matches!(
        up.as_str(),
        "GITHUB_TOKEN" | "GH_TOKEN" | "NPM_TOKEN" | "DATABASE_URL" | "REDIS_URL"
    )
}
