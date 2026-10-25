pub mod bounds;
pub mod sign;
pub mod source;
pub mod text;
pub mod write;

use std::collections::HashMap;

use lopdf::{Document, Object, ObjectId};

/// Deep-copies an object graph from `src`, assigning new ids from `next_id`.
pub struct Importer<'a> {
    src: &'a Document,
    map: HashMap<ObjectId, ObjectId>,
    next_id: &'a mut u32,
    pub out: Vec<(ObjectId, Object)>,
}

impl<'a> Importer<'a> {
    pub fn new(src: &'a Document, next_id: &'a mut u32) -> Self {
        Self { src, map: HashMap::new(), next_id, out: Vec::new() }
    }

    /// Imports the object referenced by `id` and returns its new id.
    pub fn import_ref(&mut self, id: ObjectId) -> ObjectId {
        if let Some(new) = self.map.get(&id) {
            return *new;
        }
        let new = (*self.next_id, 0);
        *self.next_id += 1;
        self.map.insert(id, new);
        let obj = self.src.get_object(id).cloned().unwrap_or(Object::Null);
        let copied = self.copy(&obj);
        self.out.push((new, copied));
        new
    }

    pub fn copy(&mut self, obj: &Object) -> Object {
        match obj {
            Object::Reference(id) => Object::Reference(self.import_ref(*id)),
            Object::Array(items) => Object::Array(items.iter().map(|o| self.copy(o)).collect()),
            Object::Dictionary(d) => Object::Dictionary(self.copy_dict(d)),
            Object::Stream(s) => {
                let mut s2 = s.clone();
                s2.dict = self.copy_dict(&s.dict);
                Object::Stream(s2)
            }
            other => other.clone(),
        }
    }

    fn copy_dict(&mut self, d: &lopdf::Dictionary) -> lopdf::Dictionary {
        let mut out = lopdf::Dictionary::new();
        for (k, v) in d.iter() {
            // Links to pages or to the structure tree of the source document are not copied.
            if matches!(k.as_slice(), b"Parent" | b"P" | b"StructParent" | b"StructParents") {
                continue;
            }
            out.set(k.clone(), self.copy(v));
        }
        out
    }
}

pub fn resolve<'a>(doc: &'a Document, obj: &'a Object) -> &'a Object {
    doc.dereference(obj).map(|(_, o)| o).unwrap_or(obj)
}

pub fn numbers(doc: &Document, obj: &Object) -> Option<Vec<f64>> {
    resolve(doc, obj)
        .as_array()
        .ok()?
        .iter()
        .map(|o| match resolve(doc, o) {
            Object::Integer(i) => Some(*i as f64),
            Object::Real(r) => Some(*r as f64),
            _ => None,
        })
        .collect()
}

/// Bounding box of a form after applying its /Matrix: [x0, y0, x1, y1].
pub fn form_extent(doc: &Document, form: &lopdf::Dictionary) -> Option<[f64; 4]> {
    let b = numbers(doc, form.get(b"BBox").ok()?)?;
    if b.len() != 4 {
        return None;
    }
    let m = form
        .get(b"Matrix")
        .ok()
        .and_then(|m| numbers(doc, m))
        .filter(|m| m.len() == 6)
        .unwrap_or_else(|| vec![1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
    let pts = [(b[0], b[1]), (b[2], b[1]), (b[0], b[3]), (b[2], b[3])]
        .map(|(x, y)| (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]));
    let xs = pts.map(|p| p.0);
    let ys = pts.map(|p| p.1);
    let min = |v: [f64; 4]| v.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = |v: [f64; 4]| v.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let e = [min(xs), min(ys), max(xs), max(ys)];
    (e[2] > e[0] && e[3] > e[1]).then_some(e)
}

/// Looks up an inheritable key (MediaBox, CropBox, Rotate) walking up /Parent.
pub fn inherited<'a>(doc: &'a Document, page: ObjectId, key: &[u8]) -> Option<&'a Object> {
    let mut dict = doc.get_dictionary(page).ok()?;
    for _ in 0..64 {
        if let Ok(v) = dict.get(key) {
            return Some(resolve(doc, v));
        }
        let parent = dict.get(b"Parent").ok()?.as_reference().ok()?;
        dict = doc.get_dictionary(parent).ok()?;
    }
    None
}

/// Visible page box (CropBox or MediaBox), normalized.
pub fn page_box(doc: &Document, page: ObjectId) -> [f64; 4] {
    let get = |k: &[u8]| inherited(doc, page, k).and_then(|o| numbers(doc, o)).filter(|v| v.len() == 4);
    let b = get(b"CropBox").or_else(|| get(b"MediaBox")).unwrap_or_else(|| vec![0.0, 0.0, 595.0, 842.0]);
    [b[0].min(b[2]), b[1].min(b[3]), b[0].max(b[2]), b[1].max(b[3])]
}

pub fn page_rotation(doc: &Document, page: ObjectId) -> i64 {
    inherited(doc, page, b"Rotate").and_then(|o| o.as_i64().ok()).unwrap_or(0).rem_euclid(360)
}
