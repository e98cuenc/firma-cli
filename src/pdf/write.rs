//! PDF object serialization and incremental update writing.

use std::io::Write as _;

use lopdf::{Dictionary, Object, ObjectId, StringFormat};

pub fn object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => {
            let _ = write!(out, "{i}");
        }
        Object::Real(r) => out.extend_from_slice(real(*r as f64).as_bytes()),
        Object::Name(n) => name(out, n),
        Object::String(s, StringFormat::Hexadecimal) => {
            out.push(b'<');
            for b in s {
                let _ = write!(out, "{b:02X}");
            }
            out.push(b'>');
        }
        Object::String(s, StringFormat::Literal) => out.extend(super::text::pdf_literal(s)),
        Object::Array(items) => {
            out.push(b'[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                object(out, it);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => dictionary(out, d, None),
        Object::Stream(s) => {
            dictionary(out, &s.dict, Some(s.content.len()));
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(&s.content);
            out.extend_from_slice(b"\nendstream");
        }
        Object::Reference((id, gen)) => {
            let _ = write!(out, "{id} {gen} R");
        }
    }
}

fn dictionary(out: &mut Vec<u8>, d: &Dictionary, stream_len: Option<usize>) {
    out.extend_from_slice(b"<<");
    for (k, v) in d.iter() {
        if stream_len.is_some() && k.as_slice() == b"Length" {
            continue;
        }
        name(out, k);
        out.push(b' ');
        object(out, v);
    }
    if let Some(len) = stream_len {
        let _ = write!(out, "/Length {len}");
    }
    out.extend_from_slice(b">>");
}

fn name(out: &mut Vec<u8>, n: &[u8]) {
    out.push(b'/');
    for &b in n {
        let regular = (0x21..=0x7E).contains(&b) && !b"()<>[]{}/%#".contains(&b);
        if regular {
            out.push(b);
        } else {
            let _ = write!(out, "#{b:02X}");
        }
    }
}

pub fn real(v: f64) -> String {
    let s = format!("{v:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" || s.is_empty() { "0".into() } else { s.into() }
}

/// Body of an object in the update.
pub enum Body {
    Obj(Object),
    /// Pre-serialized bytes (the signature dictionary, with its placeholders).
    Raw(Vec<u8>),
}

pub struct Written {
    pub bytes: Vec<u8>,
    /// Offset of each written object, by id.
    pub offsets: Vec<(ObjectId, usize)>,
}

/// Appends `objects` to `original` followed by a new cross-reference section.
pub fn incremental(
    original: &[u8],
    prev_xref: usize,
    trailer: &Dictionary,
    objects: Vec<(ObjectId, Body)>,
) -> Written {
    let mut out = original.to_vec();
    if !out.ends_with(b"\n") && !out.ends_with(b"\r") {
        out.push(b'\n');
    }
    let mut offsets = Vec::new();
    for (id, body) in &objects {
        offsets.push((*id, out.len()));
        let _ = writeln!(out, "{} {} obj", id.0, id.1);
        match body {
            Body::Obj(o) => object(&mut out, o),
            Body::Raw(r) => out.extend_from_slice(r),
        }
        out.extend_from_slice(b"\nendobj\n");
    }

    let uses_xref_stream = !original.get(prev_xref..).is_some_and(|r| r.starts_with(b"xref"));
    let mut size = trailer.get(b"Size").and_then(Object::as_i64).unwrap_or(0) as u32;
    for (id, _) in &objects {
        size = size.max(id.0 + 1);
    }

    let mut new_trailer = Dictionary::new();
    for key in [&b"Root"[..], b"Info", b"ID", b"Encrypt"] {
        if let Ok(v) = trailer.get(key) {
            new_trailer.set(key, v.clone());
        }
    }
    new_trailer.set("Prev", Object::Integer(prev_xref as i64));

    let xref_offset;
    if uses_xref_stream {
        // The original document uses xref streams: keep using one (uncompressed).
        let xref_id = size;
        size += 1;
        xref_offset = out.len();
        offsets.push(((xref_id, 0), xref_offset));
        let mut entries: Vec<(u32, usize, u16)> = offsets.iter().map(|((id, g), off)| (*id, *off, *g)).collect();
        entries.sort();
        let mut index = Vec::new();
        let mut data = Vec::new();
        for run in runs(&entries) {
            index.push(Object::Integer(run[0].0 as i64));
            index.push(Object::Integer(run.len() as i64));
            for (_, off, g) in run {
                data.push(1u8);
                data.extend_from_slice(&(*off as u32).to_be_bytes());
                data.extend_from_slice(&g.to_be_bytes());
            }
        }
        let mut d = new_trailer;
        d.set("Type", Object::Name(b"XRef".to_vec()));
        d.set("Size", Object::Integer(size as i64));
        d.set("W", Object::Array(vec![1.into(), 4.into(), 2.into()]));
        d.set("Index", Object::Array(index));
        let _ = writeln!(out, "{xref_id} 0 obj");
        object(&mut out, &Object::Stream(lopdf::Stream::new(d, data)));
        out.extend_from_slice(b"\nendobj\n");
    } else {
        xref_offset = out.len();
        let mut entries: Vec<(u32, usize, u16)> = offsets.iter().map(|((id, g), off)| (*id, *off, *g)).collect();
        entries.sort();
        out.extend_from_slice(b"xref\n");
        for run in runs(&entries) {
            let _ = writeln!(out, "{} {}", run[0].0, run.len());
            for (_, off, g) in run {
                let _ = write!(out, "{off:010} {g:05} n\r\n");
            }
        }
        new_trailer.set("Size", Object::Integer(size as i64));
        out.extend_from_slice(b"trailer\n");
        object(&mut out, &Object::Dictionary(new_trailer));
        out.push(b'\n');
    }
    let _ = write!(out, "startxref\n{xref_offset}\n%%EOF\n");
    Written { bytes: out, offsets }
}

/// Groups entries with consecutive ids (xref table subsections).
fn runs(entries: &[(u32, usize, u16)]) -> Vec<&[(u32, usize, u16)]> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..=entries.len() {
        if i == entries.len() || entries[i].0 != entries[i - 1].0 + 1 {
            out.push(&entries[start..i]);
            start = i;
        }
    }
    out
}
