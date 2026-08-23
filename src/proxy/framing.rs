//! NDJSON framing for the MCP transport proxy (V4-B).
//!
//! The proxy speaks **newline-delimited JSON only**: one JSON-RPC object per
//! line, `\n`-terminated on output. This mirrors the pinned framing of the
//! in-process MCP server (`src/mcp/mod.rs`) so a client configured for one is
//! wire-compatible with the other.
//!
//! Fail-closed posture (pinned from the V4-B research notes):
//!
//! - **`\r\n` tolerated on input** — the CR is stripped before parsing, so a
//!   Windows-flavored client still works. Output always emits bare `\n`.
//! - **Max line 16 MiB** (default; operator-tunable) — a longer line means
//!   either a broken peer or a framing-desync attack; both are answered by
//!   terminating the session, never by truncating or skipping.
//! - **Invalid UTF-8** — JSON must be UTF-8; a non-UTF-8 line is a protocol
//!   violation and surfaces as an error (the relay treats it as garbage ⇒
//!   fail-closed terminate), never as lossy-mangled content.

use std::io::{self, Read, Write};

/// Default maximum accepted line size: 16 MiB (`16 * 1024 * 1024` bytes),
/// matching the documented MCP message-size ceiling from the V4-B plan.
pub const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Incremental NDJSON line reader over any [`Read`].
///
/// Buffers internally so the underlying reader may deliver partial lines;
/// [`read_line`](LineReader::read_line) returns exactly one logical line per
/// call. Not `Sync`/shared: each direction of the relay owns its own reader
/// thread-side.
pub struct LineReader<R: Read> {
    inner: R,
    /// Scratch buffer for the line currently being accumulated.
    line: Vec<u8>,
    /// One-byte read staging (avoids a per-call read of a larger block for
    /// the common tiny-line case while keeping byte-exact newline handling).
    byte: [u8; 1],
}

impl<R: Read> LineReader<R> {
    /// Wrap `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            line: Vec::with_capacity(4096),
            byte: [0],
        }
    }

    /// Read the next logical line.
    ///
    /// Returns:
    /// - `Ok(Some(line))` — a `\n`-terminated line (or a final unterminated
    ///   line at EOF), with the trailing `\n` and any preceding `\r` stripped.
    /// - `Ok(None)` — clean EOF with no pending bytes.
    /// - `Err` — an oversized line ([`MAX_LINE_EXCEEDED`] message) or an
    ///   underlying I/O error. Invalid UTF-8 is also an error: JSON lines are
    ///   UTF-8 by definition and silently lossy-decoding would corrupt pins
    ///   and gate decisions.
    ///
    /// The size check runs DURING accumulation, so an unbounded line cannot
    /// balloon memory past `max_line_bytes + 1` before failing closed.
    pub fn read_line(&mut self, max_line_bytes: usize) -> io::Result<Option<String>> {
        self.line.clear();
        loop {
            match self.inner.read(&mut self.byte)? {
                0 => {
                    // EOF. A clean EOF with an empty accumulator is the normal
                    // end of stream; a non-empty tail is a final unterminated
                    // line (tolerated — same semantics as `str::lines`).
                    if self.line.is_empty() {
                        return Ok(None);
                    }
                    return self.finish_line(max_line_bytes).map(Some);
                }
                _ => {
                    let b = self.byte[0];
                    if b == b'\n' {
                        return self.finish_line(max_line_bytes).map(Some);
                    }
                    if self.line.len() >= max_line_bytes {
                        return Err(io::Error::other(MAX_LINE_EXCEEDED));
                    }
                    self.line.push(b);
                }
            }
        }
    }

    /// Strip the optional trailing `\r` (CRLF tolerance) and validate UTF-8.
    fn finish_line(&self, max_line_bytes: usize) -> io::Result<String> {
        let mut end = self.line.len();
        if end > 0 && self.line[end - 1] == b'\r' {
            end -= 1;
        }
        if end > max_line_bytes {
            return Err(io::Error::other(MAX_LINE_EXCEEDED));
        }
        String::from_utf8(self.line[..end].to_vec())
            .map_err(|_| io::Error::other("ndjson line is not valid UTF-8"))
    }
}

/// Error text used when a line exceeds the configured maximum. The relay
/// matches on this message to emit its loud fail-closed diagnostic.
pub const MAX_LINE_EXCEEDED: &str = "ndjson line exceeds maximum allowed size";

/// Write one NDJSON line (`line` + `\n`) and flush.
///
/// Flushing per line is deliberate: the relays are interactive request/response
/// pipes where a held-back line deadlocks the peer.
pub fn write_line<W: Write>(w: &mut W, line: &str) -> io::Result<()> {
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// Feed raw bytes through a reader, collecting every produced line.
    fn lines_of(input: &[u8], max: usize) -> io::Result<Vec<String>> {
        let mut r = LineReader::new(input);
        let mut out = Vec::new();
        while let Some(l) = r.read_line(max)? {
            out.push(l);
        }
        Ok(out)
    }

    #[test]
    fn reads_basic_lines_and_strips_newline() {
        let ls = lines_of(b"{\"a\":1}\n{\"b\":2}\n", 1024).expect("ok");
        assert_eq!(ls, vec![r#"{"a":1}"#, r#"{"b":2}"#]);
    }

    #[test]
    fn tolerates_crlf_on_input() {
        let ls = lines_of(b"one\r\ntwo\r\n", 1024).expect("ok");
        assert_eq!(ls, vec!["one", "two"], "CR must be stripped");
    }

    #[test]
    fn cr_alone_is_not_a_line_terminator() {
        // Only LF terminates; a bare CR stays in the payload (JSON strings
        // would escape it anyway).
        let ls = lines_of(b"a\rb\n", 1024).expect("ok");
        assert_eq!(ls, vec!["a\rb"]);
    }

    #[test]
    fn clean_eof_yields_none() {
        let mut r = LineReader::new(&b""[..]);
        assert!(r.read_line(64).expect("ok").is_none());
    }

    #[test]
    fn final_unterminated_line_is_tolerated() {
        let ls = lines_of(b"x\ny", 1024).expect("ok");
        assert_eq!(ls, vec!["x", "y"]);
    }

    #[test]
    fn blank_lines_are_preserved_as_empty_strings() {
        // Skipping is the CALLER's policy (the relay fail-closes on them via
        // the JSON parse); framing itself reports what is on the wire.
        let ls = lines_of(b"\n\n", 1024).expect("ok");
        assert_eq!(ls, vec!["", ""]);
    }

    #[test]
    fn oversized_line_fails_closed_during_accumulation() {
        let err = lines_of(b"a".repeat(100).as_slice(), 64).unwrap_err();
        assert_eq!(err.to_string(), MAX_LINE_EXCEEDED);
        // Exactly at the limit is fine (the limit is a maximum, not exclusive).
        let ls = lines_of(&vec![b'x'; 64].push_newline(), 64).expect("limit is inclusive");
        assert_eq!(ls[0].len(), 64);
    }

    #[test]
    fn invalid_utf8_line_is_an_error_not_lossy() {
        let err = lines_of(&[0xff, 0xfe, b'\n'], 64).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "unexpected error: {err}");
    }

    #[test]
    fn partial_reads_across_chunk_boundaries_reassemble() {
        // BufReader is irrelevant to correctness (LineReader does its own
        // byte-wise loop), but this pins behavior under a chunking source.
        let mut r = LineReader::new(BufReader::new(&b"he\nllo\n"[..]));
        assert_eq!(r.read_line(64).expect("ok"), Some("he".to_string()));
        assert_eq!(r.read_line(64).expect("ok"), Some("llo".to_string()));
        assert!(r.read_line(64).expect("ok").is_none());
    }

    #[test]
    fn write_line_appends_lf_and_flushes() {
        let mut buf: Vec<u8> = Vec::new();
        write_line(&mut buf, "{\"k\":1}").expect("write");
        assert_eq!(buf, b"{\"k\":1}\n");
    }

    /// Tiny helper so the inclusive-limit case can build its input inline.
    trait PushNewline {
        fn push_newline(self) -> Vec<u8>;
    }
    impl PushNewline for Vec<u8> {
        fn push_newline(mut self) -> Vec<u8> {
            self.push(b'\n');
            self
        }
    }
}
