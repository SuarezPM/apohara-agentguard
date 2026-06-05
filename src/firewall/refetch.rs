//! C1 out-of-band inspection: obtain the content a tool is *about to* act on so
//! the firewall can scan it BEFORE the tool runs (PreToolUse), instead of only
//! warning after the fact.
//!
//! The network re-fetch sits behind the [`ContentSource`] trait so the posture
//! logic (and its tests) never touch the real network: production wires
//! [`UreqSource`]; tests inject a `MockSource` that returns canned content or a
//! [`FetchError::Timeout`]. The SSRF / host-policy decision is a *pure* function
//! ([`ssrf_check`] / [`ssrf_check_ip`]) tested directly without DNS.
//!
//! ## Committed SSRF controls (resolve-then-check)
//! [`ssrf_check`] resolves the host and DENIES if ANY resolved IP is private,
//! loopback, link-local, ULA, or a cloud-metadata address. Checking the
//! *resolved* IP (not the hostname) is what defeats DNS rebinding. For the
//! production fetch the same predicate is installed as the `ureq` resolver, so it
//! re-fires on every connect AND on every redirect hop — a redirect to an
//! internal address is refused at resolution time.
//!
//! ## DoS controls
//! Connect timeout ~5 s + read timeout ~10 s (on timeout the caller maps to a
//! fail-closed WARN, never a hang); responses are read only up to
//! [`MAX_FETCH_BYTES`] and the firewall scans that prefix.
//!
//! ## Honesty note (README / US-009)
//! WebSearch re-run is **best-effort**: apohara-agentguard cannot reproduce Claude's
//! exact search backend, so [`UreqSource`] performs a plain GET against the
//! target query URL. The load-bearing guarantees here are the per-surface
//! posture and the SSRF guard, not byte-identical search results.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// Hard cap on how many bytes of a fetched body are read and scanned. Oversized
/// bodies are truncated to this prefix rather than buffered whole (DoS guard).
pub const MAX_FETCH_BYTES: usize = 1024 * 1024; // 1 MiB

/// Connect timeout for the production fetch.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Read timeout for the production fetch.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The tool surface a piece of content is arriving from. Drives posture in
/// [`crate::firewall::scan_surface`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// `Read` tool — inspect the target file's bytes (BLOCK-capable).
    ReadFile,
    /// `WebFetch` tool — re-fetch the URL out-of-band (BLOCK-capable).
    WebFetch,
    /// `WebSearch` tool — best-effort out-of-band query re-run (BLOCK-capable).
    WebSearch,
    /// `UserPromptSubmit` — scan the prompt text (WARN-only; never block).
    UserPrompt,
    /// `PostToolUse` Bash stdout — scan after the fact (WARN-only; cannot block).
    BashStdout,
}

/// What to fetch for a given surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchTarget {
    /// A local file path (for [`Surface::ReadFile`]).
    File(String),
    /// A URL to GET (for [`Surface::WebFetch`] / [`Surface::WebSearch`]).
    Url(String),
}

/// A failure while obtaining content for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// Connect/read deadline exceeded — caller fails closed to WARN, never hangs.
    Timeout,
    /// SSRF / host policy refused the target (the resolved IP is internal).
    Ssrf(SsrfRejected),
    /// Local file or network I/O error (with a human-readable detail).
    Io(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Timeout => write!(f, "fetch timed out"),
            FetchError::Ssrf(r) => write!(f, "SSRF refused: {r}"),
            FetchError::Io(e) => write!(f, "fetch I/O error: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Why a host/IP was refused by the SSRF guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfRejected {
    /// Human-readable reason (used in the verdict / error message).
    pub reason: &'static str,
}

impl std::fmt::Display for SsrfRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// Source of content for out-of-band inspection. The seam that keeps tests
/// hermetic: production uses [`UreqSource`]; tests inject canned content.
pub trait ContentSource {
    /// Obtain the content for `target`, returning at most [`MAX_FETCH_BYTES`].
    fn fetch(&self, target: &FetchTarget) -> Result<String, FetchError>;
}

// ---------------------------------------------------------------------------
// SSRF policy (pure, fully tested)
// ---------------------------------------------------------------------------

/// Pure predicate: is this resolved IP safe to fetch?
///
/// DENIES private (RFC1918), loopback, link-local, RFC4193 ULA, and
/// cloud-metadata addresses. Public addresses are allowed. No DNS, no network —
/// tests assert `169.254.169.254` and `127.0.0.1` are refused directly.
pub fn ssrf_check_ip(ip: IpAddr) -> Result<(), SsrfRejected> {
    let reject = |reason| Err(SsrfRejected { reason });
    match ip {
        IpAddr::V4(v4) => check_v4(v4, reject),
        IpAddr::V6(v6) => check_v6(v6, reject),
    }
}

fn check_v4(
    v4: Ipv4Addr,
    reject: impl Fn(&'static str) -> Result<(), SsrfRejected>,
) -> Result<(), SsrfRejected> {
    // Cloud-metadata is the highest-value target; name it explicitly.
    if v4 == Ipv4Addr::new(169, 254, 169, 254) {
        return reject("cloud metadata endpoint (169.254.169.254)");
    }
    if v4.is_loopback() {
        return reject("loopback address (127.0.0.0/8)");
    }
    if v4.is_private() {
        return reject("RFC1918 private address (10/8, 172.16/12, 192.168/16)");
    }
    if v4.is_link_local() {
        return reject("link-local address (169.254.0.0/16)");
    }
    if v4.is_unspecified() {
        return reject("unspecified address (0.0.0.0)");
    }
    Ok(())
}

fn check_v6(
    v6: Ipv6Addr,
    reject: impl Fn(&'static str) -> Result<(), SsrfRejected>,
) -> Result<(), SsrfRejected> {
    // AWS IPv6 metadata endpoint.
    if v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254) {
        return reject("cloud metadata endpoint (fd00:ec2::254)");
    }
    if v6.is_loopback() {
        return reject("loopback address (::1)");
    }
    if v6.is_unspecified() {
        return reject("unspecified address (::)");
    }
    // An IPv4-mapped/compatible address must be judged by its v4 policy.
    if let Some(mapped) = v6.to_ipv4() {
        return check_v4(mapped, reject);
    }
    let seg0 = v6.segments()[0];
    // fe80::/10 link-local.
    if (seg0 & 0xffc0) == 0xfe80 {
        return reject("link-local address (fe80::/10)");
    }
    // fc00::/7 unique-local (ULA).
    if (seg0 & 0xfe00) == 0xfc00 {
        return reject("RFC4193 unique-local address (fc00::/7)");
    }
    Ok(())
}

/// Resolve `host` and apply [`ssrf_check_ip`] to the resolved address(es).
///
/// Returns the first safe resolved [`IpAddr`] on success. If resolution yields
/// any rejected address the whole host is refused (deny-by-default: a host that
/// resolves to a mix is treated as hostile). Checking the *resolved* IP is what
/// defeats DNS rebinding.
pub fn ssrf_check(host: &str) -> Result<IpAddr, SsrfRejected> {
    // `to_socket_addrs` needs a port; 0 is fine for resolution-only.
    let addrs = (host, 0u16).to_socket_addrs().map_err(|_| SsrfRejected {
        reason: "host did not resolve",
    })?;

    let mut first: Option<IpAddr> = None;
    for sa in addrs {
        let ip = sa.ip();
        ssrf_check_ip(ip)?; // any rejected resolution refuses the host
        if first.is_none() {
            first = Some(ip);
        }
    }
    first.ok_or(SsrfRejected {
        reason: "host did not resolve to any address",
    })
}

// ---------------------------------------------------------------------------
// Production source (ureq, rustls, blocking)
// ---------------------------------------------------------------------------

/// Production [`ContentSource`]: reads local files for [`Surface::ReadFile`] and
/// performs an SSRF-guarded, size/time-capped HTTP GET for the web surfaces.
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqSource;

impl UreqSource {
    /// Construct the production source.
    pub fn new() -> Self {
        Self
    }
}

impl ContentSource for UreqSource {
    fn fetch(&self, target: &FetchTarget) -> Result<String, FetchError> {
        match target {
            FetchTarget::File(path) => read_file_prefix(path),
            FetchTarget::Url(url) => fetch_url(url),
        }
    }
}

/// Read at most [`MAX_FETCH_BYTES`] from a local file and lossily decode to text.
fn read_file_prefix(path: &str) -> Result<String, FetchError> {
    let file = std::fs::File::open(path).map_err(|e| FetchError::Io(e.to_string()))?;
    let mut buf = Vec::with_capacity(8 * 1024);
    file.take(MAX_FETCH_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Io(e.to_string()))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// SSRF-guarded, time/size-capped GET. The SSRF predicate is installed as the
/// `ureq` resolver so it re-fires on the initial connect and on every redirect.
fn fetch_url(url: &str) -> Result<String, FetchError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        // Resolve-then-check on EVERY host (connect + each redirect hop). A
        // refusal surfaces as a DNS error, which we translate back to Ssrf.
        .resolver(ssrf_resolver)
        .build();

    match agent.get(url).call() {
        Ok(resp) => {
            let mut buf = Vec::with_capacity(8 * 1024);
            resp.into_reader()
                .take(MAX_FETCH_BYTES as u64)
                .read_to_end(&mut buf)
                .map_err(|e| classify_io(&e))?;
            Ok(String::from_utf8_lossy(&buf).into_owned())
        }
        Err(ureq::Error::Status(code, _)) => {
            // A non-2xx is still content we could not inspect; treat as I/O so the
            // caller fails closed to WARN rather than silently allowing.
            Err(FetchError::Io(format!("HTTP status {code}")))
        }
        Err(ureq::Error::Transport(t)) => Err(classify_transport(t)),
    }
}

/// Custom resolver: resolve, then refuse any internal resolved address. Encodes
/// the SSRF refusal in the io::Error message so [`classify_transport`] can map it
/// back to [`FetchError::Ssrf`].
fn ssrf_resolver(netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
    let host = host_of(netloc);
    let addrs: Vec<SocketAddr> = netloc
        .to_socket_addrs()
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .collect();

    for sa in &addrs {
        if let Err(rej) = ssrf_check_ip(sa.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{SSRF_MARKER}{host}: {}", rej.reason),
            ));
        }
    }
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "host did not resolve",
        ));
    }
    Ok(addrs)
}

/// Sentinel embedded in resolver errors so transport errors can be classified as
/// SSRF refusals (ureq erases the io::ErrorKind across its transport layer).
const SSRF_MARKER: &str = "agentguard-ssrf:";

/// Strip the `:port` from a `host:port` netloc for display.
fn host_of(netloc: &str) -> &str {
    netloc.rsplit_once(':').map(|(h, _)| h).unwrap_or(netloc)
}

/// Map an io::Error from the body read into a [`FetchError`].
fn classify_io(e: &std::io::Error) -> FetchError {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        FetchError::Timeout
    } else {
        FetchError::Io(e.to_string())
    }
}

/// Map a ureq transport error into a [`FetchError`], recovering SSRF refusals and
/// timeouts that ureq flattens into generic transport/IO errors.
fn classify_transport(t: ureq::Transport) -> FetchError {
    let msg = t.to_string();
    if msg.contains(SSRF_MARKER) {
        // Recover the reason after the marker for a clean message.
        return FetchError::Ssrf(SsrfRejected {
            reason: "resolved IP is internal (RFC1918/loopback/link-local/ULA/metadata)",
        });
    }
    match t.kind() {
        ureq::ErrorKind::Io => {
            // ureq surfaces connect/read timeouts as Io transport errors.
            if msg.to_ascii_lowercase().contains("timed out")
                || msg.to_ascii_lowercase().contains("timeout")
            {
                FetchError::Timeout
            } else {
                FetchError::Io(msg)
            }
        }
        ureq::ErrorKind::Dns => FetchError::Io(format!("DNS: {msg}")),
        _ => FetchError::Io(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("parse ip")
    }

    #[test]
    fn metadata_ipv4_refused() {
        assert!(ssrf_check_ip(ip("169.254.169.254")).is_err());
    }

    #[test]
    fn loopback_refused() {
        assert!(ssrf_check_ip(ip("127.0.0.1")).is_err());
        assert!(ssrf_check_ip(ip("::1")).is_err());
    }

    #[test]
    fn rfc1918_refused() {
        assert!(ssrf_check_ip(ip("10.0.0.5")).is_err());
        assert!(ssrf_check_ip(ip("172.16.4.4")).is_err());
        assert!(ssrf_check_ip(ip("192.168.1.1")).is_err());
    }

    #[test]
    fn link_local_refused() {
        assert!(ssrf_check_ip(ip("169.254.10.1")).is_err());
        assert!(ssrf_check_ip(ip("fe80::1")).is_err());
    }

    #[test]
    fn ula_refused() {
        assert!(ssrf_check_ip(ip("fc00::1")).is_err());
        assert!(ssrf_check_ip(ip("fd12:3456::1")).is_err());
    }

    #[test]
    fn metadata_ipv6_refused() {
        assert!(ssrf_check_ip(ip("fd00:ec2::254")).is_err());
    }

    #[test]
    fn public_ip_allowed() {
        assert!(ssrf_check_ip(ip("8.8.8.8")).is_ok());
        assert!(ssrf_check_ip(ip("1.1.1.1")).is_ok());
        assert!(ssrf_check_ip(ip("2606:4700:4700::1111")).is_ok());
    }

    #[test]
    fn ipv4_mapped_loopback_refused() {
        // ::ffff:127.0.0.1 must be judged by its v4 policy.
        assert!(ssrf_check_ip(ip("::ffff:127.0.0.1")).is_err());
    }

    #[test]
    fn ssrf_check_localhost_refused() {
        // localhost resolves to loopback -> refused (resolve-then-check).
        assert!(ssrf_check("localhost").is_err());
    }
}
