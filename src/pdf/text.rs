//! Text with the standard Helvetica font (no embedding needed) and WinAnsiEncoding.

/// Helvetica widths (Adobe AFM) for characters 32..=126, in thousandths of an em.
const HELVETICA_ASCII: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // ' '../
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 0-9
    278, 278, 584, 584, 584, 556, 1015, // :;<=>?@
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667,
    611, 722, 667, 944, 667, 667, 611, // A-Z
    278, 278, 278, 469, 556, 333, // [\]^_`
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
    278, 556, 500, 722, 500, 500, 500, // a-z
    334, 260, 334, 584, // {|}~
];

/// Converts to WinAnsiEncoding; anything that does not fit becomes '?'.
pub fn to_winansi(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c as u32 {
            0x20..=0x7E | 0xA0..=0xFF => c as u32 as u8,
            0x20AC => 0x80,
            0x2018 => 0x91,
            0x2019 => 0x92,
            0x201C => 0x93,
            0x201D => 0x94,
            0x2022 => 0x95,
            0x2013 => 0x96,
            0x2014 => 0x97,
            0x2026 => 0x85,
            _ => b'?',
        })
        .collect()
}

fn byte_width(b: u8) -> u16 {
    match b {
        32..=126 => HELVETICA_ASCII[(b - 32) as usize],
        // Latin letters with diacritics: same width as the base letter.
        0xC0..=0xC5 => 667,
        0xC7 => 722,
        0xC8..=0xCB => 667,
        0xCC..=0xCF => 278,
        0xD1 => 722,
        0xD2..=0xD6 | 0xD8 => 778,
        0xD9..=0xDC => 722,
        0xE0..=0xE5 => 556,
        0xE7 => 500,
        0xE8..=0xEB => 556,
        0xEC..=0xEF => 278,
        0xF1..=0xF6 | 0xF8 => 556,
        0xF9..=0xFC => 556,
        0xAA | 0xBA => 370,
        0xA1 | 0xBF => 333,
        0x96 => 556,
        0x97 => 1000,
        0x91 | 0x92 => 222,
        0x93 | 0x94 => 333,
        _ => 556,
    }
}

pub fn width(text: &[u8], size: f64) -> f64 {
    text.iter().map(|b| byte_width(*b) as f64).sum::<f64>() * size / 1000.0
}

/// Wraps the text into lines that fit in `max_w` points (honours explicit '\n').
pub fn wrap(text: &str, size: f64, max_w: f64) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line: Vec<u8> = Vec::new();
        for word in para.split_whitespace() {
            let word = to_winansi(word);
            let candidate = if line.is_empty() { word.clone() } else { [&line[..], b" ", &word[..]].concat() };
            if width(&candidate, size) <= max_w || line.is_empty() {
                line = candidate;
            } else {
                lines.push(std::mem::take(&mut line));
                line = word;
            }
        }
        lines.push(line);
    }
    lines
}

/// Finds the largest font size (≤ `max_size`) at which the text fits in the box.
pub fn fit(text: &str, w: f64, h: f64, max_size: f64) -> (f64, Vec<Vec<u8>>) {
    let mut size = max_size;
    loop {
        let lines = wrap(text, size, w);
        let fits_h = lines.len() as f64 * size * LINE_HEIGHT <= h;
        let fits_w = lines.iter().all(|l| width(l, size) <= w);
        if (fits_h && fits_w) || size <= 3.0 {
            return (size, lines);
        }
        size -= 0.25;
    }
}

pub const LINE_HEIGHT: f64 = 1.18;

/// Escaped PDF literal string.
pub fn pdf_literal(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(b'(');
    for &b in bytes {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            _ => out.push(b),
        }
    }
    out.push(b')');
    out
}
