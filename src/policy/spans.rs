//! Typed source spans + a hand-rolled code-frame renderer for policy-load
//! diagnostics (Story D2).
//!
//! Zero dependencies by design: the frame below is rendered with `format!`
//! only (miette / ariadne are deliberately NOT introduced — the default
//! build purity forbids new runtime deps).
//!
//! ## Types (m05: invalid states unrepresentable where cheap)
//!
//! - [`TextPosition`] — a 1-based `{line, col}` pair. Both fields are
//!   [`NonZeroU32`], so the invalid "line 0 / col 0" state simply cannot be
//!   constructed.
//! - [`TextRange`] — a half-open `[start, end)` byte-offset range into the
//!   source text. Constructed via [`TextRange::new`], which rejects
//!   `start > end`; [`TextRange::point`] covers the degenerate empty span.
//! - [`ErrorLocation`] — the file label (the policy path as loaded) plus the
//!   range within it.
//!
//! ## Renderer contract
//!
//! [`render_code_frame`] turns `(source, location)` into a rustc-style frame:
//!
//! ```text
//!   --> policy.toml:12:8
//!    |
//! 12 | tools = ["Bashh"]
//!    |        ^^^^^^^^
//! ```
//!
//! One caret line under the span; multi-line spans are clamped to their
//! starting line; lines longer than [`MAX_LINE_DISPLAY_CHARS`] are shown as a
//! window around the span with `…` ellipsis markers (best-effort visual
//! alignment; display-width of non-ASCII chars is not measured).

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

/// Longest source line shown verbatim. Longer lines are windowed around the
/// span (8 chars of left context, 16 of right) with `…` markers.
const MAX_LINE_DISPLAY_CHARS: usize = 100;

/// A 1-based position in a text file. `line`/`col` are [`NonZeroU32`] so the
/// invalid "position 0" state is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextPosition {
    line: NonZeroU32,
    col: NonZeroU32,
}

impl TextPosition {
    /// Construct a validated position. Returns `None` for a 0 line or col.
    pub fn new(line: u32, col: u32) -> Option<Self> {
        Some(Self {
            line: NonZeroU32::new(line)?,
            col: NonZeroU32::new(col)?,
        })
    }

    /// Compute the 1-based position of a byte offset in `source`. Offsets past
    /// the end clamp to `source.len()`; columns count CHARS within the line
    /// (not bytes), so multibyte content keeps caret alignment honest.
    pub fn from_byte_offset(source: &str, offset: usize) -> Self {
        let offset = offset.min(source.len());
        let line_start = source[..offset].rfind('\n').map_or(0, |i| i + 1);
        let line = source.as_bytes()[..line_start]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1;
        let col = source[line_start..offset].chars().count() + 1;
        Self {
            line: NonZeroU32::new(line as u32).expect("line index is >= 1"),
            col: NonZeroU32::new(col as u32).expect("col index is >= 1"),
        }
    }

    /// 1-based line number.
    pub fn line(&self) -> u32 {
        self.line.get()
    }

    /// 1-based column number (in chars).
    pub fn col(&self) -> u32 {
        self.col.get()
    }
}

/// A half-open `[start, end)` byte-offset range into a source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextRange {
    start: usize,
    end: usize,
}

impl TextRange {
    /// Construct a validated range. Returns `None` when `start > end`.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        (start <= end).then_some(Self { start, end })
    }

    /// The degenerate empty span at `offset` (renders as a single caret).
    pub fn point(offset: usize) -> Self {
        Self {
            start: offset,
            end: offset,
        }
    }

    /// First byte offset (inclusive).
    pub fn start(&self) -> usize {
        self.start
    }

    /// End byte offset (exclusive).
    pub fn end(&self) -> usize {
        self.end
    }
}

/// Where a policy-load error happened: the file label (the policy path as
/// loaded) plus the byte range within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLocation {
    file: PathBuf,
    range: TextRange,
}

impl ErrorLocation {
    /// Label a location with its file and range.
    pub fn new(file: impl Into<PathBuf>, range: TextRange) -> Self {
        Self {
            file: file.into(),
            range,
        }
    }

    /// The labeled file.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// The byte range within the file.
    pub fn range(&self) -> TextRange {
        self.range
    }
}

/// Render the rustc-style code frame for `location` against `source`:
///
/// ```text
///   --> policy.toml:12:8
///    |
/// 12 | tools = ["Bashh"]
///    |        ^^^^^^^^
/// ```
///
/// Graceful degradation: an empty `source` (e.g. an IO error where nothing
/// could be read) still renders the header + gutter skeleton with a single
/// caret. Multi-line spans clamp to their starting line.
pub(crate) fn render_code_frame(source: &str, location: &ErrorLocation) -> String {
    let start = location.range().start().min(source.len());
    let end = location.range().end().min(source.len()).max(start);
    let pos = TextPosition::from_byte_offset(source, start);
    let line_start = source[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_text = source.lines().nth(pos.line() as usize - 1).unwrap_or("");
    let chars: Vec<char> = line_text.chars().collect();

    // Caret window in CHAR columns within this line. A span ending on a later
    // line clamps to the end of the starting line.
    let end_pos = TextPosition::from_byte_offset(source, end);
    let caret_to_raw = if end_pos.line() == pos.line() {
        source[line_start..end].chars().count()
    } else {
        chars.len()
    };
    let caret_from = source[line_start..start].chars().count().min(chars.len());
    let width = (caret_to_raw.saturating_sub(caret_from))
        .max(1)
        .min(chars.len().saturating_sub(caret_from))
        .max(1);

    // Long-line clamp: show a window around the span instead of the whole line.
    let (win_from, win_to) = if chars.len() <= MAX_LINE_DISPLAY_CHARS {
        (0, chars.len())
    } else {
        (
            caret_from.saturating_sub(8),
            (caret_from + width + 16).min(chars.len()),
        )
    };
    let prefix = if win_from > 0 { "…" } else { "" };
    let suffix = if win_to < chars.len() { "…" } else { "" };
    let shown: String = chars[win_from..win_to].iter().collect();

    let num = pos.line().to_string();
    let gutter = " ".repeat(num.len());
    let caret_pad = " ".repeat(caret_from - win_from + prefix.chars().count());
    let carets = "^".repeat(width);

    format!(
        "  --> {}:{}:{}\n{gutter} |\n{num} | {prefix}{shown}{suffix}\n{gutter} | {caret_pad}{carets}\n",
        location.file().display(),
        pos.line(),
        pos.col(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_at(source: &str, file: &str, start: usize, end: usize) -> String {
        render_code_frame(
            source,
            &ErrorLocation::new(file, TextRange::new(start, end).expect("valid range")),
        )
    }

    #[test]
    fn text_position_is_one_based_and_char_counted() {
        let src = "ab\ncdé";
        // Start of file.
        assert_eq!(
            TextPosition::from_byte_offset(src, 0),
            TextPosition::new(1, 1).unwrap()
        );
        // Offset 3 = first char of line 2 ('c').
        assert_eq!(
            TextPosition::from_byte_offset(src, 3),
            TextPosition::new(2, 1).unwrap()
        );
        // Offset 4 = 'd' (col counts CHARS: c=1, d=2).
        assert_eq!(
            TextPosition::from_byte_offset(src, 4),
            TextPosition::new(2, 2).unwrap()
        );
        // Offset 5 = the multibyte 'é' (bytes 5..=6): still char col 3.
        assert_eq!(
            TextPosition::from_byte_offset(src, 5),
            TextPosition::new(2, 3).unwrap()
        );
        // Past-the-end clamps.
        assert_eq!(
            TextPosition::from_byte_offset(src, 999),
            TextPosition::from_byte_offset(src, src.len())
        );
    }

    #[test]
    fn text_position_rejects_zero() {
        assert!(TextPosition::new(0, 1).is_none(), "line 0 unrepresentable");
        assert!(TextPosition::new(1, 0).is_none(), "col 0 unrepresentable");
    }

    #[test]
    fn text_range_rejects_inverted_range() {
        assert!(TextRange::new(5, 4).is_none());
        assert_eq!(TextRange::new(4, 4), Some(TextRange::point(4)));
    }

    #[test]
    fn frame_matches_plan_example_shape() {
        let src = "schema_version = 1\ntools = [\"Bashh\"]\n";
        // Span of the quoted token on line 2. `tools = ["Bashh"]`: the token
        // starts at char col 10 (t=1 … [=9, "=10) and is 7 chars long.
        let tok = "\"Bashh\"";
        let at = src.find(tok).expect("token present");
        let f = frame_at(src, "policy.toml", at, at + tok.len());
        let expected = concat!(
            "  --> policy.toml:2:10\n",
            "  |\n",
            "2 | tools = [\"Bashh\"]\n",
            "  |          ^^^^^^^\n",
        );
        assert_eq!(f, expected, "frame must match the plan example shape");
    }

    #[test]
    fn frame_single_caret_for_point_span() {
        let f = frame_at("k = 1\n", "p.toml", 0, 0);
        assert!(f.contains("  --> p.toml:1:1\n"), "{f}");
        assert!(f.contains("| ^"), "point span renders one caret: {f}");
    }

    #[test]
    fn frame_multiline_span_clamps_to_first_line() {
        let src = "[a]\nb = 1\nc = 2\n";
        // Span from line 2 through line 3.
        let f = frame_at(src, "m.toml", 4, src.len() - 1);
        let carets_line = f.lines().last().expect("caret line");
        assert_eq!(
            carets_match_len(carets_line),
            5,
            "carets clamp to `b = 1` length: {f}"
        );
    }

    fn carets_match_len(caret_line: &str) -> usize {
        caret_line.chars().filter(|&c| c == '^').count()
    }

    #[test]
    fn frame_windows_very_long_lines_with_ellipsis() {
        let long = format!("k = \"{}\"", "x".repeat(200));
        // Span somewhere in the middle of the long value.
        let at = 20;
        let f = frame_at(&long, "long.toml", at, at + 2);
        let shown_line = f
            .lines()
            .find(|l| l.contains('|') && !l.contains("-->") && l.contains('x'))
            .expect("source line shown");
        assert!(shown_line.contains('…'), "long line is ellipsized: {f}");
        // Caret line stays aligned under the span (same prefix width).
        let caret_line = f.lines().last().expect("caret line");
        assert!(caret_line.contains('^'), "{f}");
        assert_eq!(
            shown_line.split('|').next().unwrap().len(),
            caret_line.split('|').next().unwrap().len(),
            "gutter widths agree: {f}"
        );
    }

    #[test]
    fn frame_degrades_gracefully_on_empty_source() {
        // IO errors have no source text: header + skeleton still render.
        let loc = ErrorLocation::new("missing.toml", TextRange::point(0));
        let f = render_code_frame("", &loc);
        assert!(f.starts_with("  --> missing.toml:1:1\n"), "{f}");
        assert!(f.contains('|'), "gutter skeleton present: {f}");
    }
}
