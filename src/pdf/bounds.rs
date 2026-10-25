//! Bounds of what a form XObject actually draws, so that a signature can be trimmed to its ink.

use std::collections::HashMap;
use std::io::Read as _;
use std::rc::Rc;

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use super::{numbers, resolve};

type Matrix = [f64; 6];

const IDENTITY: Matrix = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

/// Decompressed size allowed per content stream, and in total.
const MAX_STREAM: u64 = 16 << 20;
const MAX_TOTAL: u64 = 64 << 20;

/// Box, in the form's own space (before its /Matrix), around everything the form paints,
/// clipped to its /BBox. `None` if it draws nothing or uses something this does not measure
/// (text, shadings, inline images); then the /BBox is the best answer.
pub fn ink_bounds(doc: &Document, form: &Stream) -> Option<[f64; 4]> {
    let bbox = numbers(doc, form.dict.get(b"BBox").ok()?).filter(|b| b.len() == 4)?;
    let mut w = Walker { doc, bounds: None, budget: 200_000, bytes_left: MAX_TOTAL, cache: HashMap::new() };
    w.run(form, None, None, IDENTITY, 0)?;
    let b = w.bounds?;
    let (bx0, bx1) = (bbox[0].min(bbox[2]), bbox[0].max(bbox[2]));
    let (by0, by1) = (bbox[1].min(bbox[3]), bbox[1].max(bbox[3]));
    let r = [b[0].max(bx0), b[1].max(by0), b[2].min(bx1), b[3].min(by1)];
    (r[2] > r[0] && r[3] > r[1]).then_some(r)
}

/// `a` applied first, then `b`.
fn concat(a: &Matrix, b: &Matrix) -> Matrix {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]
}

fn apply(m: &Matrix, x: f64, y: f64) -> (f64, f64) {
    (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5])
}

struct Walker<'a> {
    doc: &'a Document,
    bounds: Option<[f64; 4]>,
    /// Operations left: nested forms drawn many times could otherwise take forever.
    budget: u32,
    /// Decompressed bytes left, against compression bombs.
    bytes_left: u64,
    /// Each nested form is decoded once, however many times it is drawn.
    cache: HashMap<ObjectId, Rc<Content<Vec<Operation>>>>,
}

impl Walker<'_> {
    fn add(&mut self, (x, y): (f64, f64), pad: f64) {
        let b = self.bounds.get_or_insert([x, y, x, y]);
        b[0] = b[0].min(x - pad);
        b[1] = b[1].min(y - pad);
        b[2] = b[2].max(x + pad);
        b[3] = b[3].max(y + pad);
    }

    /// The decoded operations of a content stream, within the size limits.
    fn content(&mut self, form: &Stream, id: Option<ObjectId>) -> Option<Rc<Content<Vec<Operation>>>> {
        if let Some(c) = id.and_then(|id| self.cache.get(&id)) {
            return Some(c.clone());
        }
        let data = match form.dict.get(b"Filter").map(|f| resolve(self.doc, f)) {
            Err(_) => form.content.clone(),
            Ok(filter) => {
                let name = match filter {
                    Object::Name(n) => n.as_slice(),
                    Object::Array(a) if a.len() == 1 => a[0].as_name().ok()?,
                    _ => return None,
                };
                if name != b"FlateDecode" || form.dict.has(b"DecodeParms") {
                    return None;
                }
                let mut out = Vec::new();
                let limit = MAX_STREAM.min(self.bytes_left) + 1;
                flate2::read::ZlibDecoder::new(form.content.as_slice()).take(limit).read_to_end(&mut out).ok()?;
                out
            }
        };
        let len = data.len() as u64;
        if len > MAX_STREAM || len > self.bytes_left {
            return None;
        }
        self.bytes_left -= len;
        let content = Rc::new(Content::decode(&data).ok()?);
        if let Some(id) = id {
            self.cache.insert(id, content.clone());
        }
        Some(content)
    }

    fn run(
        &mut self,
        form: &Stream,
        id: Option<ObjectId>,
        parent: Option<&Dictionary>,
        ctm: Matrix,
        depth: u32,
    ) -> Option<()> {
        if depth > 8 {
            return None;
        }
        let resources =
            form.dict.get(b"Resources").ok().and_then(|r| resolve(self.doc, r).as_dict().ok()).or(parent);
        let content = self.content(form, id)?;

        let mut stack: Vec<(Matrix, f64, i64)> = Vec::new();
        let (mut ctm, mut width, mut join) = (ctm, 1.0, 0i64);
        let mut path: Vec<(f64, f64)> = Vec::new();
        let mut cur = (0.0, 0.0);
        for op in &content.operations {
            self.budget = self.budget.checked_sub(1)?;
            let n: Vec<f64> = op.operands.iter().filter_map(|o| o.as_float().ok().map(f64::from)).collect();
            let p = |i: usize| apply(&ctm, n[i], n[i + 1]);
            match (op.operator.as_str(), n.len()) {
                ("q", _) => stack.push((ctm, width, join)),
                ("Q", _) => (ctm, width, join) = stack.pop().unwrap_or((ctm, width, join)),
                ("cm", 6) => ctm = concat(&[n[0], n[1], n[2], n[3], n[4], n[5]], &ctm),
                ("w", 1) => width = n[0],
                ("j", 1) => join = n[0] as i64,
                ("m", 2) | ("l", 2) => {
                    cur = p(0);
                    path.push(cur);
                }
                ("c", 6) => {
                    let (p1, p2, p3) = (p(0), p(2), p(4));
                    bezier(&mut path, cur, p1, p2, p3);
                    cur = p3;
                }
                ("v", 4) => {
                    let (p2, p3) = (p(0), p(2));
                    bezier(&mut path, cur, cur, p2, p3);
                    cur = p3;
                }
                ("y", 4) => {
                    let (p1, p3) = (p(0), p(2));
                    bezier(&mut path, cur, p1, p3, p3);
                    cur = p3;
                }
                ("re", 4) => {
                    let (x, y, w, h) = (n[0], n[1], n[2], n[3]);
                    for (px, py) in [(x, y), (x + w, y), (x, y + h), (x + w, y + h)] {
                        path.push(apply(&ctm, px, py));
                    }
                    cur = apply(&ctm, x, y);
                }
                ("h", _) | ("W", _) | ("W*", _) => {}
                ("f" | "F" | "f*", _) => self.paint(&mut path, 0.0),
                ("S" | "s" | "B" | "B*" | "b" | "b*", _) => {
                    // Half the line width on each side (more for mitred corners), scaled by the CTM.
                    let scale = (ctm[0] * ctm[3] - ctm[1] * ctm[2]).abs().sqrt();
                    let pad = width.max(0.0) * scale * if join == 0 { 1.0 } else { 0.5 };
                    self.paint(&mut path, pad);
                }
                ("n", _) => path.clear(),
                ("Do", _) => {
                    let name = op.operands.first()?.as_name().ok()?;
                    let xobjects = resolve(self.doc, resources?.get(b"XObject").ok()?).as_dict().ok()?;
                    let xobject_ref = xobjects.get(name).ok()?;
                    let xobject_id = xobject_ref.as_reference().ok();
                    let xobject = resolve(self.doc, xobject_ref).as_stream().ok()?;
                    match xobject.dict.get(b"Subtype").and_then(Object::as_name).ok()? {
                        b"Form" => {
                            let m = xobject
                                .dict
                                .get(b"Matrix")
                                .ok()
                                .and_then(|m| numbers(self.doc, m))
                                .filter(|m| m.len() == 6)
                                .map(|m| [m[0], m[1], m[2], m[3], m[4], m[5]])
                                .unwrap_or(IDENTITY);
                            self.run(xobject, xobject_id, resources, concat(&m, &ctm), depth + 1)?;
                        }
                        b"Image" => {
                            for (x, y) in [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)] {
                                self.add(apply(&ctm, x, y), 0.0);
                            }
                        }
                        _ => return None,
                    }
                }
                // Text, shadings and inline images are not measured.
                ("BT" | "sh" | "BI" | "ID", _) => return None,
                // Colours, graphics state, marked content…: no geometry.
                _ => {}
            }
        }
        Some(())
    }

    fn paint(&mut self, path: &mut Vec<(f64, f64)>, pad: f64) {
        for pt in path.drain(..) {
            self.add(pt, pad);
        }
    }
}

/// Points along a cubic Bézier (fine enough for a bounding box).
fn bezier(path: &mut Vec<(f64, f64)>, p0: (f64, f64), p1: (f64, f64), p2: (f64, f64), p3: (f64, f64)) {
    const STEPS: usize = 32;
    for i in 1..=STEPS {
        let t = i as f64 / STEPS as f64;
        let u = 1.0 - t;
        let (a, b, c, d) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
        path.push((a * p0.0 + b * p1.0 + c * p2.0 + d * p3.0, a * p0.1 + b * p1.1 + c * p2.1 + d * p3.1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;

    fn form(content: &str, bbox: [i64; 4]) -> Stream {
        Stream::new(dictionary! { "Subtype" => "Form", "BBox" => bbox.iter().map(|v| Object::from(*v)).collect::<Vec<_>>() }, content.into())
    }

    fn round(b: [f64; 4]) -> [f64; 4] {
        b.map(|v| (v * 10.0).round() / 10.0)
    }

    #[test]
    fn fills_strokes_and_transforms() {
        let doc = Document::new();
        // A filled triangle with lots of empty space around it.
        let b = ink_bounds(&doc, &form("10 20 m 50 20 l 30 60 l f", [0, 0, 300, 120])).unwrap();
        assert_eq!(round(b), [10.0, 20.0, 50.0, 60.0]);
        // A stroke with round joins grows by half its width; cm moves it.
        let b = ink_bounds(&doc, &form("q 1 0 0 1 100 0 cm 4 w 1 j 0 0 m 10 0 l S Q", [0, 0, 300, 120])).unwrap();
        assert_eq!(round(b), [98.0, 0.0, 112.0, 2.0], "clipped at the bottom by the /BBox");
        // A curve bulges beyond its end points, but less than its control points.
        let b = ink_bounds(&doc, &form("0 0 m 0 40 40 40 40 0 c f", [0, 0, 300, 120])).unwrap();
        assert_eq!(round(b), [0.0, 0.0, 40.0, 30.0]);
        // Clipped to the /BBox, and a path that is never painted does not count.
        let b = ink_bounds(&doc, &form("0 0 300 120 re W n 290 100 m 400 200 l 290 200 l f", [0, 0, 300, 120])).unwrap();
        assert_eq!(round(b), [290.0, 100.0, 300.0, 120.0]);
    }

    #[test]
    fn gives_up_on_runaway_nesting() {
        // Each form draws the next one 20 times: 20^levels operations.
        let nested = |levels| {
            let mut doc = Document::new();
            let mut inner = doc.add_object(form("0 0 m 1 1 l S", [0, 0, 1, 1]));
            for _ in 0..levels {
                let mut f = form(&"/X Do ".repeat(20), [0, 0, 1, 1]);
                f.dict.set("Resources", dictionary! { "XObject" => dictionary! { "X" => inner } });
                inner = doc.add_object(f);
            }
            let top = doc.get_object(inner).unwrap().as_stream().unwrap().clone();
            ink_bounds(&doc, &top)
        };
        assert!(nested(3).is_some());
        assert!(nested(7).is_none(), "over budget");
    }

    #[test]
    fn gives_up_on_compression_bombs() {
        use std::io::Write as _;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![b' '; (MAX_STREAM + 1) as usize]).unwrap();
        let bomb = e.finish().unwrap();
        let mut f = Stream::new(dictionary! { "Subtype" => "Form", "BBox" => vec![0.into(), 0.into(), 1.into(), 1.into()] }, bomb);
        f.dict.set("Filter", "FlateDecode");
        assert!(ink_bounds(&Document::new(), &f).is_none());
    }

    #[test]
    fn gives_up_on_text_and_empty_forms() {
        let doc = Document::new();
        assert!(ink_bounds(&doc, &form("BT /F 12 Tf (x) Tj ET", [0, 0, 10, 10])).is_none());
        assert!(ink_bounds(&doc, &form("0 0 m 10 10 l n", [0, 0, 10, 10])).is_none());
    }
}
