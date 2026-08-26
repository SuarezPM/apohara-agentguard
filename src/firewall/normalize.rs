//! Staged Unicode normalization suite for the firewall (FASE 5-A, Feature A).
//!
//! Injection payloads hide from ASCII-oriented regex rules behind terminal
//! escapes, invisible characters, compatibility forms and homoglyph
//! lookalikes. This module exposes ONE entry point, [`pipeline`], applying
//! four escalating stages (U1..U4); `mod.rs` feeds its output to a SECOND
//! firewall pass when (and only when) the raw pass found nothing and the text
//! actually changed. Decision policy lives there, not here:
//! **normalization alone never blocks** — a Block requires a real pattern hit
//! on either the raw or the normalized text (second-pass hits are reported
//! with a `[normalized-match]` marker).
//!
//! Defaults are ON with no configuration keys this phase (documented
//! decision: F6 will evaluate opt-out toggles once FP telemetry exists).
//!
//! # Stage contract and per-stage cost
//!
//! Every stage is a pure `&str -> Option<String>` returning `None` for an
//! already-clean input. Each carries its own byte-level fast path, so a CLEAN
//! haystack (the overwhelming case for whole-file scans) pays only linear byte
//! probes and ZERO allocations:
//!
//! | Stage | Purpose | Fast-path probe | Cost when firing |
//! |-------|---------|-----------------|------------------|
//! | U1 [`strip_terminal_escapes`] | CSI / OSC / DCS / SOS / PM / APC + C1 singletons | ESC-byte probe + 2-byte C1 window | 1 pass, 1 alloc |
//! | U2 [`strip_invisibles`] | zero-width, bidi controls, tag chars, soft hyphen | lead bytes {C2, E2, EF, F3} | 1 char pass, 1 alloc |
//! | U3 [`fold_compat`] | NFKC-subset compatibility folding to ASCII | lead bytes {C2, E2, EF, F0} | 1 char pass, 1 alloc |
//! | U4 [`skeleton_confusables`] | skeleton folding on MIXED-script words only | lead bytes {CE..D6, E1, E2} | word scan + fold pass |
//!
//! Worst case (fully hostile input) stays linear: each stage touches every
//! character at most twice (detect + transform).
//!
//! # Zero-dependency tradeoff (deliberate)
//!
//! `unicode-normalization` is not in the dependency tree and FASE 5-A may not
//! touch `Cargo.toml`. U3 is therefore a curated **NFKC subset**: the
//! compatibility families whose NFKC image is pure ASCII AND whose fold can
//! actually unmask a pattern — fullwidth ALPHANUMERICS (punctuation is left
//! alone: folding it never helps a rule match but does force a pointless
//! second pass on every CJK document), mathematical alphanumerics, Roman
//! numerals, circled digits/letters,
//! superscript/subscript digits, ff/fi/fl ligatures, and letterlike symbols
//! (Kelvin sign, double-struck/script/black-letter capitals). Canonical
//! decomposition/recomposition is deliberately OMITTED: precomposed accented
//! Latin (`café`, `José`) passes through UNTOUCHED, which both satisfies the
//! accent near-miss requirement and removes an entire FP class. If F6 later
//! swaps in the real crate, [`fold_compat`] is the only code that changes.
//! All constants below were verified against Unicode NFKC reference mappings.

use std::borrow::Cow;

/// Apply the full U1..U4 escalation to `text`.
///
/// Returns [`Cow::Borrowed`] unchanged when NO stage would alter anything —
/// the zero-alloc fast path whole-file scans take on benign content.
pub(crate) fn pipeline(text: &str) -> Cow<'_, str> {
    fn apply(text: &str, buf: &mut Option<String>, stage: fn(&str) -> Option<String>) {
        let current = buf.as_deref().unwrap_or(text);
        if let Some(next) = stage(current) {
            *buf = Some(next);
        }
    }
    let mut buf: Option<String> = None;
    apply(text, &mut buf, strip_terminal_escapes);
    apply(text, &mut buf, strip_invisibles);
    apply(text, &mut buf, fold_compat);
    apply(text, &mut buf, skeleton_confusables);
    match buf {
        Some(s) => Cow::Owned(s),
        None => Cow::Borrowed(text),
    }
}

// ---------------------------------------------------------------------------
// U1 — terminal escape stripping
// ---------------------------------------------------------------------------

/// Strip terminal escape machinery while preserving payload text.
///
/// Removes:
/// - CSI sequences (`ESC [ params intermediates final`, e.g. `\x1b[31m`),
/// - OSC / DCS / SOS / PM / APC strings (`ESC ] … BEL` / `ESC X…ST` etc.),
/// - two-byte singleton escapes (`ESC M`, `ESC c`, charset designators),
/// - bare C1 control characters U+0080..=U+009F.
///
/// A literal `[` WITHOUT the leading ESC is preserved verbatim (JSON arrays,
/// markdown links and `[31m`-style literals must never be mangled).
///
/// Fast path: no `0x1B` byte anywhere AND no UTF-8-encoded C1 (`C2 80..9F`)
/// means nothing to do — one linear byte probe, no allocation.
fn strip_terminal_escapes(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    // C1 controls encode as exactly `C2 80..C2 9F` in UTF-8 (soft hyphen,
    // `C2 AD`, is outside that pair range and belongs to U2).
    let has_c1 = bytes
        .windows(2)
        .any(|w| w[0] == 0xC2 && (0x80..=0x9F).contains(&w[1]));
    if !bytes.contains(&0x1B) && !has_c1 {
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0x1B {
            i += 1;
            if i >= bytes.len() {
                break; // trailing bare ESC: dropped
            }
            match bytes[i] {
                b'[' => {
                    // CSI: parameter bytes 0x30..=0x3F, intermediate bytes
                    // 0x20..=0x2F, single final byte 0x40..=0x7E. Truncated
                    // sequences simply consume to end of input.
                    i += 1;
                    while i < bytes.len() && (0x30..=0x3F).contains(&bytes[i]) {
                        i += 1;
                    }
                    while i < bytes.len() && (0x20..=0x2F).contains(&bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() && (0x40..=0x7E).contains(&bytes[i]) {
                        i += 1;
                    }
                }
                b']' | b'P' | b'X' | b'^' | b'_' => {
                    // String modes (OSC / DCS / SOS / PM / APC): terminated by
                    // BEL (0x07), encoded ST (U+009C) or `ESC \`, else run to
                    // end of input.
                    i += 1;
                    while i < bytes.len() {
                        match bytes[i] {
                            0x07 => {
                                i += 1;
                                break;
                            }
                            0xC2 if i + 1 < bytes.len() && bytes[i + 1] == 0x9C => {
                                i += 2;
                                break;
                            }
                            0x1B => {
                                i += 1;
                                if i < bytes.len() && bytes[i] == b'\\' {
                                    i += 1;
                                }
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
                c if (0x20..=0x2F).contains(&c) => {
                    // Escape sequences with intermediate bytes (e.g. charset
                    // designation `ESC ( B`): consume intermediates + final.
                    while i < bytes.len() && (0x20..=0x2F).contains(&bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                }
                _ => {
                    // Two-byte singleton escape (`ESC M`, `ESC 7`, `ESC c`...).
                    i += 1;
                }
            }
            continue;
        }
        if b == 0xC2 && i + 1 < bytes.len() && (0x80..=0x9F).contains(&bytes[i + 1]) {
            // Encoded C1 control (U+0080..U+009F). A few of them are FUNCTION
            // intros with the same grammar as their ESC-based twins and must
            // consume their operands, not just themselves:
            let c1 = bytes[i + 1];
            match c1 {
                0x9B => {
                    // CSI (U+009B): same params/intermediates/final grammar.
                    i += 2;
                    while i < bytes.len() && (0x30..=0x3F).contains(&bytes[i]) {
                        i += 1;
                    }
                    while i < bytes.len() && (0x20..=0x2F).contains(&bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() && (0x40..=0x7E).contains(&bytes[i]) {
                        i += 1;
                    }
                }
                0x90 | 0x98 | 0x9D | 0x9E | 0x9F => {
                    // DCS / SOS / OSC / PM / APC string intros: terminated by
                    // BEL, raw ST (U+009C) or `ESC \`.
                    i += 2;
                    while i < bytes.len() {
                        match bytes[i] {
                            0x07 => {
                                i += 1;
                                break;
                            }
                            0x9C => {
                                i += 1;
                                break;
                            }
                            0xC2 if i + 1 < bytes.len() && bytes[i + 1] == 0x9C => {
                                i += 2;
                                break;
                            }
                            0x1B => {
                                i += 1;
                                if i < bytes.len() && bytes[i] == b'\\' {
                                    i += 1;
                                }
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
                _ => i += 2, // plain C1 singleton: strip the pair
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    Some(String::from_utf8(out).expect("U1 removes only whole UTF-8 sequences"))
}

// ---------------------------------------------------------------------------
// U2 — invisible character stripping
// ---------------------------------------------------------------------------

/// Strip formatting-invisible characters that splice tokens together or flip
/// text direction without any visual trace:
/// - zero-width: U+200B..U+200D (ZWSP/ZWNJ/ZWJ), U+FEFF (BOM/ZWNBSP),
///   U+00AD (soft hyphen);
/// - bidi controls: U+200E..U+200F (LRM/RLM — same concealment class as the
///   spec'd ranges, added deliberately), U+202A..U+202E, U+2066..U+2069;
/// - word joiners: U+2060..U+2064;
/// - tag characters: U+E0000..U+E007F.
///
/// Fast path: all targets share only four UTF-8 lead bytes {C2, E2, EF, F3};
/// absence of all four proves a clean haystack (pure ASCII and Latin-1
/// accents like `café` exit immediately).
fn strip_invisibles(text: &str) -> Option<String> {
    if !text.bytes().any(|b| matches!(b, 0xC2 | 0xE2 | 0xEF | 0xF3)) {
        return None;
    }
    let first = text
        .char_indices()
        .find(|(_, c)| is_invisible(*c))
        .map(|(i, _)| i)?;
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..first]);
    out.extend(text[first..].chars().filter(|c| !is_invisible(*c)));
    Some(out)
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

// ---------------------------------------------------------------------------
// U3 — NFKC-subset compatibility folding to ASCII
// ---------------------------------------------------------------------------

/// Result of looking up one char in the compatibility table.
enum Folded {
    /// No ASCII image — keep the original char.
    Same,
    /// Fold to a single ASCII char.
    One(char),
    /// Fold to a short ASCII string (`Ⅱ` → "II", `ﬃ` → "ffi").
    Many(&'static str),
}

/// Fold compatibility codepoints whose canonical NFKC image is pure ASCII
/// into that image (see module docs for scope/tradeoff).
///
/// Families covered (all verified against Unicode NFKC mappings):
/// fullwidth ASCII forms FF01..FF5E; mathematical alphanumerics 1D400..1D7FF
/// (13 letter styles + 4 digit styles, reserved holes skipped); Roman
/// numerals incl. multi-char expansions (`Ⅷ` → "VIII"); circled digits
/// ①..⑳ and circled Latin ⓐ..ⓩ; superscript/subscript digits plus `ⁿ`;
/// ff/fi/fl ligatures; letterlike symbols with ASCII images (Kelvin `K`,
/// script ℋ/ℓ, black-letter ℌ/ℜ, double-struck ℂ/ℝ/ℤ, planck `h`, ...).
///
/// Greek-letter math styles (1D6A8+) and halfwidth kana map OUTSIDE ASCII and
/// are intentionally left alone (Greek/CJK text keeps its script).
///
/// Fast path: lead bytes {C2, E2, EF, F0}; pure-ASCII/Latin-1 input exits
/// without a char scan.
fn fold_compat(text: &str) -> Option<String> {
    if !text.bytes().any(|b| matches!(b, 0xC2 | 0xE2 | 0xEF | 0xF0)) {
        return None;
    }
    let mut out: Option<String> = None;
    for (i, c) in text.char_indices() {
        match compat_char(c) {
            Folded::Same => {
                if let Some(o) = out.as_mut() {
                    o.push(c);
                }
            }
            Folded::One(folded) => {
                out.get_or_insert_with(|| text[..i].to_owned()).push(folded);
            }
            Folded::Many(folded) => {
                out.get_or_insert_with(|| text[..i].to_owned())
                    .push_str(folded);
            }
        }
    }
    out
}

fn compat_char(c: char) -> Folded {
    let cp = c as u32;
    // Fullwidth ASCII alphanumerics: digits FF10..FF19, capitals FF21..FF3A,
    // lowercase FF41..FF5A -> their ASCII images. Fullwidth PUNCTUATION
    // (FF01..FF0F, FF1A..FF20, FF3B..FF40, FF5B..FF5E) is deliberately NOT
    // folded although strict NFKC maps it too: no rule matches better with an
    // ASCII comma than with `，`, but CJK documents are FULL of fullwidth
    // punctuation — folding it would flip the pipeline to Owned on every
    // benign CJK file and force a pointless full second scan (measured:
    // 2x scan cost on a mixed-prose corpus).
    if (0xFF10..=0xFF19).contains(&cp) {
        return Folded::One(char::from(b'0' + (cp - 0xFF10) as u8));
    }
    if (0xFF21..=0xFF3A).contains(&cp) {
        return Folded::One(char::from(b'A' + (cp - 0xFF21) as u8));
    }
    if (0xFF41..=0xFF5A).contains(&cp) {
        return Folded::One(char::from(b'a' + (cp - 0xFF41) as u8));
    }
    match cp {
        0x2070 | 0x2074..=0x2079 => {
            return Folded::One(char::from(b'0' + superdigit(cp)));
        }
        0x00B9 => return Folded::One('1'),
        0x00B2 => return Folded::One('2'),
        0x00B3 => return Folded::One('3'),
        0x207F => return Folded::One('n'), // SUPERSCRIPT SMALL N
        0x2080..=0x2089 => return Folded::One(char::from(b'0' + (cp - 0x2080) as u8)),
        _ => {}
    }
    if (0x2160..=0x216F).contains(&cp) {
        return Folded::Many(ROMAN_UPPER[(cp - 0x2160) as usize]);
    }
    if (0x2170..=0x217F).contains(&cp) {
        return Folded::Many(ROMAN_LOWER[(cp - 0x2170) as usize]);
    }
    if (0x2460..=0x2473).contains(&cp) {
        return Folded::Many(CIRCLED_NUM[(cp - 0x2460) as usize]);
    }
    if (0x24D0..=0x24E9).contains(&cp) {
        return Folded::One(char::from(b'a' + (cp - 0x24D0) as u8));
    }
    if let Some(s) = ligature(cp) {
        return Folded::Many(s);
    }
    if let Some(ch) = letterlike(cp) {
        return Folded::One(ch);
    }
    if let Some(ch) = math_alnum(cp) {
        return Folded::One(ch);
    }
    Folded::Same
}

/// Digit value of '⁰' (2070) and '⁴'..'⁹' (2074..2079).
fn superdigit(cp: u32) -> u8 {
    if cp == 0x2070 {
        0
    } else {
        (cp - 0x2074) as u8 + 4
    }
}

fn ligature(cp: u32) -> Option<&'static str> {
    let s = match cp {
        0xFB00 => "ff",
        0xFB01 => "fi",
        0xFB02 => "fl",
        0xFB03 => "ffi",
        0xFB04 => "ffl",
        0xFB05 | 0xFB06 => "st",
        _ => return None,
    };
    Some(s)
}

/// Letterlike symbols (2100 block) whose NFKC image is a single ASCII letter.
/// Verified set — Å (212B) and Ω (2126) are EXCLUDED on purpose (their images
/// stay non-ASCII).
fn letterlike(cp: u32) -> Option<char> {
    let ch = match cp {
        0x2102 => 'C', // DOUBLE-STRUCK CAPITAL C
        0x210A => 'g', // SCRIPT SMALL G
        0x210B => 'H', // SCRIPT CAPITAL H
        0x210C => 'H', // BLACK-LETTER CAPITAL H
        0x210D => 'H', // DOUBLE-STRUCK CAPITAL H
        0x210E => 'h', // PLANCK CONSTANT
        0x2110 => 'I', // SCRIPT CAPITAL I
        0x2111 => 'I', // BLACK-LETTER CAPITAL I
        0x2112 => 'L', // SCRIPT CAPITAL L
        0x2113 => 'l', // SCRIPT SMALL L
        0x2115 => 'N', // DOUBLE-STRUCK CAPITAL N
        0x2119 => 'P', // DOUBLE-STRUCK CAPITAL P
        0x211A => 'Q', // DOUBLE-STRUCK CAPITAL Q
        0x211B => 'R', // SCRIPT CAPITAL R
        0x211C => 'R', // BLACK-LETTER CAPITAL R
        0x2124 => 'Z', // DOUBLE-STRUCK CAPITAL Z
        0x2128 => 'Z', // BLACK-LETTER CAPITAL Z
        0x212A => 'K', // KELVIN SIGN
        0x212C => 'B', // SCRIPT CAPITAL B
        0x212D => 'C', // BLACK-LETTER CAPITAL C
        0x212F => 'e', // SCRIPT SMALL E
        0x2130 => 'E', // SCRIPT CAPITAL E
        0x2131 => 'F', // SCRIPT CAPITAL F
        0x2133 => 'M', // SCRIPT CAPITAL M
        0x2134 => 'o', // SCRIPT SMALL O
        _ => return None,
    };
    Some(ch)
}

/// Unassigned holes inside the math-alphanumeric blocks (verified against the
/// Unicode Character Database): those slots have NO character and must not be
/// mapped by the algorithmic style-block arithmetic.
const MATH_RESERVED: [u32; 24] = [
    0x1D455, // italic h (real char: U+210E)
    0x1D49D, 0x1D4A0, 0x1D4A1, 0x1D4A3, 0x1D4A4, 0x1D4A7, 0x1D4A8, 0x1D4AD, 0x1D4BA, 0x1D4BC,
    0x1D4C4, // script holes (real chars: 2100-block above)
    0x1D506, 0x1D50B, 0x1D50C, 0x1D515, 0x1D51D, // black-letter holes
    0x1D53A, 0x1D53F, 0x1D545, 0x1D547, 0x1D548, 0x1D549, 0x1D551, // double-struck holes
];

/// Style-block base offsets for the 13 LETTER styles, each covering
/// `A..Z` at +0..25 and `a..z` at +26..51 (Unicode order verified).
const MATH_LETTER_BASES: [u32; 13] = [
    0x1D400, // bold
    0x1D434, // italic
    0x1D468, // bold italic
    0x1D49C, // script
    0x1D4D0, // bold script
    0x1D504, // fraktur
    0x1D538, // double-struck
    0x1D56C, // bold fraktur
    0x1D5A0, // sans-serif
    0x1D5D4, // sans-serif bold
    0x1D608, // sans-serif italic
    0x1D63C, // sans-serif bold italic
    0x1D670, // monospace
];

/// Digit-style base offsets (bold, double-struck, sans-serif bold, mono).
const MATH_DIGIT_BASES: [u32; 4] = [0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC];

/// Algorithmic mapping for MATHEMATICAL ALPHANUMERICS (𝐀 𝑎 𝒜 𝔄 𝔸 𝙰 𝟎 ...).
/// Math GREEK letters (1D6A8+) live between the letter and digit blocks and
/// fall through to `None` — they do not fold to ASCII.
fn math_alnum(cp: u32) -> Option<char> {
    if !(0x1D400..=0x1D7FF).contains(&cp) || MATH_RESERVED.binary_search(&cp).is_ok() {
        return None;
    }
    if cp <= 0x1D6A3 {
        let base = *MATH_LETTER_BASES.iter().rev().find(|&&b| cp >= b)?;
        let idx = (cp - base) as usize;
        return Some(if idx < 26 {
            char::from(b'A' + idx as u8)
        } else {
            char::from(b'a' + (idx - 26) as u8)
        });
    }
    for base in MATH_DIGIT_BASES {
        if (base..base + 10).contains(&cp) {
            return Some(char::from(b'0' + (cp - base) as u8));
        }
    }
    None
}

const ROMAN_UPPER: [&str; 16] = [
    "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "L", "C", "D", "M",
];
const ROMAN_LOWER: [&str; 16] = [
    "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii", "l", "c", "d", "m",
];
const CIRCLED_NUM: [&str; 20] = [
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "20",
];

// ---------------------------------------------------------------------------
// U4 — confusable skeleton folding on mixed-script words
// ---------------------------------------------------------------------------

/// Scripts tracked for the mixed-script test. Everything unlisted (CJK,
/// Hangul, Arabic, ...) lumps into [`Script::Other`] — it still counts toward
/// "mixed" but contributes no confusable candidates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Coptic,
    Glagolitic,
    Other,
}

fn script_of(c: char) -> Script {
    let cp = c as u32;
    match cp {
        // Old Coptic letters sit INSIDE the Greek block — classify first.
        0x03E2..=0x03EF => Script::Coptic,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        0x0400..=0x052F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF => Script::Cyrillic,
        0x0530..=0x058F | 0xFB13..=0xFB17 => Script::Armenian,
        0x2C80..=0x2CFF => Script::Coptic,
        0x2C00..=0x2C5F | 0x1E000..=0x1E02F => Script::Glagolitic,
        _ if is_latin(c) => Script::Latin,
        _ => Script::Other,
    }
}

/// Pragmatic Latin-script ranges (basic + Latin-1 letters + extensions +
/// fullwidth forms). Precision beyond this is irrelevant here: a misrouted
/// exotic Latin char lands in [`Script::Other`] and merely cannot vote toward
/// "mixed Latin".
fn is_latin(c: char) -> bool {
    matches!(
        c as u32,
        0x41..=0x5A
            | 0x61..=0x7A
            | 0xAA
            | 0xBA
            | 0xC0..=0xD6
            | 0xD8..=0xF6
            | 0xF8..=0x02B8
            | 0x1E00..=0x1EFF
            | 0xFF21..=0xFF3A
            | 0xFF41..=0xFF5A
    )
}

/// Curated confusable skeleton table `(codepoint, ASCII)` — SORTED by
/// codepoint for binary search. Conservative single-char mappings only:
/// every entry is a well-established visual lookalike (TR39-inspired,
/// simplified to single-char skeletons). Count: 136 pairs.
///
/// Tradeoff vs the `unicode-security` crate: smaller repertory, zero deps;
/// under-folding only costs recall on rare glyphs, and a WRONG mapping can
/// never fire alone because the second pass still needs a real pattern hit.
const SKELETON: [(u32, char); 136] = [
    // --- Greek (0370 block; old-Coptic 03E2..03EF listed under Coptic) ---
    (0x0386, 'A'),
    (0x0388, 'E'),
    (0x0389, 'H'),
    (0x038A, 'I'),
    (0x038C, 'O'),
    (0x038E, 'Y'),
    (0x038F, 'W'), // tonos/dialytika capitals
    (0x0391, 'A'),
    (0x0392, 'B'),
    (0x0395, 'E'),
    (0x0396, 'Z'),
    (0x0397, 'H'),
    (0x0399, 'I'),
    (0x039A, 'K'),
    (0x039C, 'M'),
    (0x039D, 'N'),
    (0x039F, 'O'),
    (0x03A1, 'P'),
    (0x03A4, 'T'),
    (0x03A5, 'Y'),
    (0x03A7, 'X'),
    (0x03AA, 'I'),
    (0x03AB, 'Y'),
    (0x03AC, 'a'),
    (0x03AD, 'e'),
    (0x03AE, 'n'),
    (0x03AF, 'i'),
    (0x03B1, 'a'),
    (0x03B5, 'e'),
    (0x03B7, 'n'),
    (0x03B9, 'i'),
    (0x03BA, 'k'),
    (0x03BC, 'u'),
    (0x03BD, 'v'),
    (0x03BF, 'o'),
    (0x03C0, 'n'),
    (0x03C1, 'p'),
    (0x03C2, 's'),
    (0x03C4, 't'),
    (0x03C5, 'u'),
    (0x03C7, 'x'),
    (0x03C9, 'w'),
    (0x03CC, 'o'),
    (0x03CD, 'y'),
    (0x03CE, 'w'),
    (0x03F1, 'p'), // GREEK RHO SYMBOL
    (0x03F2, 'c'), // GREEK LUNATE SIGMA
    (0x03F3, 'j'), // GREEK YOT
    (0x03F5, 'e'), // GREEK LUNATE EPSILON
    (0x03F9, 'C'), // GREEK CAPITAL LUNATE SIGMA
    // --- Cyrillic ---
    (0x0401, 'E'),
    (0x0404, 'E'),
    (0x0405, 'S'),
    (0x0406, 'I'),
    (0x0408, 'J'),
    (0x0410, 'A'),
    (0x0412, 'B'),
    (0x0415, 'E'),
    (0x041A, 'K'),
    (0x041C, 'M'),
    (0x041D, 'H'),
    (0x041E, 'O'),
    (0x0420, 'P'),
    (0x0421, 'C'),
    (0x0422, 'T'),
    (0x0423, 'Y'),
    (0x0425, 'X'),
    (0x0428, 'W'),
    (0x0429, 'W'),
    (0x042A, 'b'),
    (0x042C, 'b'),
    (0x0430, 'a'),
    (0x0432, 'b'),
    (0x0433, 'r'),
    (0x0435, 'e'),
    (0x0438, 'u'),
    (0x043A, 'k'),
    (0x043C, 'm'),
    (0x043D, 'h'),
    (0x043E, 'o'),
    (0x043F, 'n'),
    (0x0440, 'p'),
    (0x0441, 'c'),
    (0x0442, 't'),
    (0x0443, 'y'),
    (0x0445, 'x'),
    (0x0448, 'w'),
    (0x0449, 'w'),
    (0x044A, 'b'),
    (0x044C, 'b'),
    (0x0451, 'e'),
    (0x0455, 's'),
    (0x0456, 'i'),
    (0x0457, 'i'),
    (0x0458, 'j'),
    (0x0491, 'r'),
    (0x049B, 'k'),
    (0x04AE, 'Y'),
    (0x04AF, 'y'), // STRAIGHT U
    (0x04B0, 'Y'),
    (0x04B1, 'y'), // STRAIGHT U WITH STROKE
    (0x04B3, 'x'), // HA WITH DESCENDER
    (0x04BB, 'h'), // SHHA
    (0x04CF, 'i'), // PALOCHKA
    (0x0501, 'd'), // KOMI DE
    (0x051A, 'Q'),
    (0x051B, 'q'), // KOMI QJE
    (0x051C, 'W'),
    (0x051D, 'w'), // KOMI WJE
    // --- Armenian (conservative: only unambiguous lookalikes) ---
    (0x0570, 'h'), // HO
    (0x0585, 'o'), // OH
    // --- Coptic (old 03E2 block + 2C80 block) ---
    (0x03E5, 'f'), // SMALL LETTER FEI
    (0x03E9, 'h'), // SMALL LETTER HORI
    (0x2C80, 'A'),
    (0x2C81, 'a'), // ALFA
    (0x2C82, 'B'),
    (0x2C83, 'b'), // VIDA
    (0x2C88, 'E'),
    (0x2C89, 'e'), // EIE
    (0x2C94, 'K'),
    (0x2C95, 'k'), // KAPA
    (0x2C98, 'M'),
    (0x2C99, 'm'), // MI
    (0x2C9A, 'N'),
    (0x2C9B, 'n'), // NI
    (0x2CA0, 'N'),
    (0x2CA1, 'n'), // PI (Π-shaped -> n)
    (0x2CA2, 'P'),
    (0x2CA3, 'p'), // RO
    (0x2CA6, 'T'),
    (0x2CA7, 't'), // TAU
    (0x2CB0, 'O'),
    (0x2CB1, 'o'), // OOU
    // --- Glagolitic (only unambiguous shapes) ---
    (0x2C40, 'n'), // NASHI
    (0x2C41, 'o'), // ONU
    (0x2C46, 'y'), // UKU
];

fn skeleton_lookup(c: char) -> Option<char> {
    SKELETON
        .binary_search_by_key(&(c as u32), |&(cp, _)| cp)
        .ok()
        .map(|idx| SKELETON[idx].1)
}

/// Maximal runs of alphabetic characters (script-agnostic word splitting:
/// separators/punctuation/digits delimit words).
struct AlphaWords<'a> {
    rest: &'a str,
}

impl<'a> Iterator for AlphaWords<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let start = self.rest.find(char::is_alphabetic)?;
        self.rest = &self.rest[start..];
        let end = self
            .rest
            .find(|c: char| !c.is_alphabetic())
            .unwrap_or(self.rest.len());
        let word = &self.rest[..end];
        self.rest = &self.rest[end..];
        Some(word)
    }
}

/// A word qualifies for folding ONLY if it mixes ≥2 scripts AND contains at
/// least one potential confusable. Single-script words — pure Latin (`café`),
/// pure Cyrillic (`текст`), pure Greek (`βοήθεια`), CJK — are NEVER altered.
fn word_needs_fold(word: &str) -> bool {
    let mut seen = 0u64;
    let mut distinct = 0usize;
    let mut has_confusable = false;
    for c in word.chars() {
        if !c.is_alphabetic() {
            continue;
        }
        let bit = 1u64
            << match script_of(c) {
                Script::Latin => 0,
                Script::Cyrillic => 1,
                Script::Greek => 2,
                Script::Armenian => 3,
                Script::Coptic => 4,
                Script::Glagolitic => 5,
                Script::Other => 6,
            };
        if seen & bit == 0 {
            seen |= bit;
            distinct += 1;
        }
        has_confusable |= skeleton_lookup(c).is_some();
    }
    distinct >= 2 && has_confusable
}

/// Fold confusable characters inside MIXED-script words only (see
/// [`word_needs_fold`]). Fast path: none of the target scripts' UTF-8 lead
/// bytes ({CE..D6, E1, E2}) present means nothing to inspect — pure ASCII and
/// Latin-1 accented text exits without a char scan.
fn skeleton_confusables(text: &str) -> Option<String> {
    if !text.bytes().any(|b| matches!(b, 0xCE..=0xD6 | 0xE1 | 0xE2)) {
        return None;
    }
    let mut words = AlphaWords { rest: text };
    if !words.any(word_needs_fold) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match rest.find(char::is_alphabetic) {
            Some(i) => {
                out.push_str(&rest[..i]);
                rest = &rest[i..];
            }
            None => {
                out.push_str(rest);
                return Some(out);
            }
        }
        let end = rest
            .find(|c: char| !c.is_alphabetic())
            .unwrap_or(rest.len());
        let word = &rest[..end];
        if word_needs_fold(word) {
            for c in word.chars() {
                match skeleton_lookup(c) {
                    Some(ascii) => out.push(ascii),
                    None => out.push(c),
                }
            }
        } else {
            out.push_str(word);
        }
        rest = &rest[end..];
        if rest.is_empty() {
            return Some(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(text: &str) -> Cow<'_, str> {
        pipeline(text)
    }

    #[test]
    fn clean_ascii_stays_borrowed() {
        assert!(matches!(
            norm("plain text with [brackets] and {json: true}"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn accents_and_cjk_stay_borrowed() {
        assert!(matches!(norm("café José niño"), Cow::Borrowed(_)));
        assert!(matches!(norm("这是一段正常的中文文本"), Cow::Borrowed(_)));
        assert!(matches!(norm("βοήθεια με το σύστημα"), Cow::Borrowed(_)));
        assert!(matches!(norm("текст ыыы here"), Cow::Borrowed(_)));
    }

    #[test]
    fn u1_strips_csi_osc_and_c1_keeps_bare_bracket() {
        assert_eq!(
            strip_terminal_escapes("\u{1b}[31mred\u{1b}[0m").as_deref(),
            Some("red")
        );
        assert_eq!(
            strip_terminal_escapes("ig\u{1b}]0;title\u{7}nore").as_deref(),
            Some("ignore")
        );
        assert_eq!(
            strip_terminal_escapes("Ig\u{1b}Ppayload\u{1b}\\nore").as_deref(),
            Some("Ignore")
        );
        // C1-encoded CSI (U+009B) is stripped too.
        assert_eq!(
            strip_terminal_escapes("Ig\u{9b}31mnore").as_deref(),
            Some("Ignore")
        );
        // Bare '[' without ESC must survive.
        assert_eq!(strip_terminal_escapes("[31m stays"), None);
        assert_eq!(strip_terminal_escapes("Esc \\e[31m literal"), None);
        assert_eq!(
            strip_terminal_escapes("charset \u{1b}(Bdesignator").as_deref(),
            Some("charset designator")
        );
    }

    #[test]
    fn u2_strips_zero_width_bidi_tags_shy() {
        assert_eq!(
            strip_invisibles("ig\u{200B}nore").as_deref(),
            Some("ignore")
        );
        assert_eq!(
            strip_invisibles("pass\u{ad}word").as_deref(),
            Some("password")
        );
        assert_eq!(strip_invisibles("ab\u{202E}cd").as_deref(), Some("abcd"));
        assert_eq!(strip_invisibles("ab\u{2060}cd").as_deref(), Some("abcd"));
        assert_eq!(strip_invisibles("ab\u{FEFF}cd").as_deref(), Some("abcd"));
        assert_eq!(strip_invisibles("ab\u{E0041}cd").as_deref(), Some("abcd")); // tag char
        assert_eq!(strip_invisibles("plain"), None);
        // ZWJ inside an emoji sequence is removed by design; the visible
        // emoji themselves survive.
        assert_eq!(
            strip_invisibles("\u{1F44D}\u{200D}\u{FE0F} ok").as_deref(),
            Some("\u{1F44D}\u{FE0F} ok")
        );
    }

    #[test]
    fn u3_folds_compat_families() {
        assert_eq!(fold_compat("ｉｇｎore").as_deref(), Some("ignore"));
        assert_eq!(fold_compat("ＩＧＮORE").as_deref(), Some("IGNORE"));
        assert_eq!(
            fold_compat("\u{1D408}\u{1D420}\u{1D427}").as_deref(),
            Some("Ign")
        ); // math bold I g n
        assert_eq!(fold_compat("Ⅰgnore").as_deref(), Some("Ignore")); // roman numeral
        assert_eq!(fold_compat("ⅷ").as_deref(), Some("viii"));
        assert_eq!(fold_compat("sup\u{2074}").as_deref(), Some("sup4"));
        assert_eq!(fold_compat("sub\u{2080}").as_deref(), Some("sub0"));
        assert_eq!(
            fold_compat("\u{2468}. restart").as_deref(),
            Some("9. restart")
        );
        assert_eq!(fold_compat("\u{24D0}pp").as_deref(), Some("app")); // circled a
        assert_eq!(fold_compat("ﬁle").as_deref(), Some("file")); // fi ligature
        assert_eq!(fold_compat("\u{212A}ey").as_deref(), Some("Key")); // Kelvin sign
        assert_eq!(fold_compat("\u{2113}ist").as_deref(), Some("list")); // script l
                                                                         // Reserved hole must NOT map (None = nothing changed).
        assert_eq!(fold_compat("\u{1D455}x"), None);
        // Math GREEK letters stay put (no ASCII image).
        assert_eq!(fold_compat("\u{1D6B0}"), None);
        // Accented precomposed Latin untouched (deliberate NFKC-subset scope).
        assert_eq!(fold_compat("café"), None);
    }

    #[test]
    fn u4_folds_only_mixed_script_words() {
        // Cyrillic і inside a Latin word -> folds.
        assert_eq!(skeleton_confusables("іgnore").as_deref(), Some("ignore"));
        // Mixed via Greek omicron.
        assert_eq!(skeleton_confusables("infο").as_deref(), Some("info"));
        // Pure Cyrillic NEVER touched even though о/е/с are in the table.
        assert_eq!(skeleton_confusables("ошибка текст"), None);
        // Pure Greek untouched.
        assert_eq!(skeleton_confusables("βοήθεια"), None);
        // Pure Latin untouched.
        assert_eq!(skeleton_confusables("café latte"), None);
        // CJK untouched.
        assert_eq!(skeleton_confusables("中文测试"), None);
        // Word boundaries respected.
        assert_eq!(
            skeleton_confusables("use іgnore-mode, not ошибка").as_deref(),
            Some("use ignore-mode, not ошибка")
        );
    }

    #[test]
    fn pipeline_composes_all_stages() {
        // CSI escape (U1) + Cyrillic і (U4) + zero-width space (U2) all hide
        // parts of one injection phrase; after the pipeline they reassemble.
        let dirty = "\u{1b}[1mі\u{200B}gnore";
        assert_eq!(pipeline(dirty).as_ref(), "ignore");
    }
}
