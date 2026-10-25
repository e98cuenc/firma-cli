//! Signature fields already in a document: earlier signatures (so new boxes do not cover them),
//! empty fields prepared for signers, and the author's certification (DocMDP) permissions.

use std::collections::{HashMap, HashSet};

use lopdf::{Dictionary, Document, Object, ObjectId};

use super::{numbers, page_rotation, resolve};

pub struct SigField {
    /// The terminal field dictionary (possibly merged with its only widget).
    pub id: ObjectId,
    /// Fully qualified name (`parent.child`).
    pub name: String,
    /// Signer name (/Name of the signature), for signed fields.
    pub signer: Option<String>,
    pub signed: bool,
    /// A document time-stamp (PAdES B-LTA) rather than a person's signature.
    pub timestamp: bool,
    /// Widgets with a visible area.
    pub widgets: Vec<FieldWidget>,
}

pub struct FieldWidget {
    pub id: ObjectId,
    pub page: ObjectId,
    pub page_num: u32,
    /// /Rect in the page's user space.
    pub rect: [f64; 4],
    pub rotate: i64,
}

/// All signature fields in the /AcroForm.
pub fn signature_fields(doc: &Document, root: ObjectId) -> Vec<SigField> {
    // Widget → page, from the pages' /Annots (more reliable than the optional /P).
    let mut page_of: HashMap<ObjectId, (ObjectId, u32)> = HashMap::new();
    for (num, page_id) in doc.get_pages() {
        let annots = doc.get_dictionary(page_id).ok().and_then(|p| p.get(b"Annots").ok());
        if let Some(Ok(annots)) = annots.map(|a| resolve(doc, a).as_array()) {
            for a in annots {
                if let Ok(id) = a.as_reference() {
                    page_of.insert(id, (page_id, num));
                }
            }
        }
    }
    let mut walker = Walker { doc, page_of, seen: HashSet::new(), out: Vec::new() };
    let fields = doc
        .get_dictionary(root)
        .ok()
        .and_then(|c| c.get(b"AcroForm").ok())
        .and_then(|af| resolve(doc, af).as_dict().ok())
        .and_then(|af| af.get(b"Fields").ok())
        .and_then(|f| resolve(doc, f).as_array().ok());
    for f in fields.into_iter().flatten() {
        if let Ok(id) = f.as_reference() {
            walker.walk(id, "", false, 0);
        }
    }
    walker.out
}

struct Walker<'a> {
    doc: &'a Document,
    page_of: HashMap<ObjectId, (ObjectId, u32)>,
    /// Each object once: a crafted /Kids tree that repeats or loops cannot blow up.
    seen: HashSet<ObjectId>,
    out: Vec<SigField>,
}

impl Walker<'_> {
    fn walk(&mut self, id: ObjectId, parent_name: &str, parent_is_sig: bool, depth: u32) {
        let doc = self.doc;
        if depth > 16 || !self.seen.insert(id) {
            return;
        }
        let Ok(d) = doc.get_dictionary(id) else { return };
        let name = match d.get(b"T").ok().and_then(|t| lopdf::decode_text_string(t).ok()).map(|t| printable(&t)) {
            Some(t) if parent_name.is_empty() => t,
            Some(t) => format!("{parent_name}.{t}"),
            None => parent_name.to_string(),
        };
        let is_sig = match d.get(b"FT").and_then(Object::as_name) {
            Ok(ft) => ft == b"Sig",
            Err(_) => parent_is_sig,
        };
        let kids: Vec<ObjectId> = d
            .get(b"Kids")
            .ok()
            .and_then(|k| resolve(doc, k).as_array().ok())
            .map(|a| a.iter().filter_map(|k| k.as_reference().ok()).collect())
            .unwrap_or_default();
        // Kids with a /T are fields of their own; kids without one are this field's widgets.
        let child_fields = kids.iter().any(|k| doc.get_dictionary(*k).is_ok_and(|kd| kd.has(b"T")));
        if child_fields {
            for k in kids {
                self.walk(k, &name, is_sig, depth + 1);
            }
            return;
        }
        if !is_sig {
            return;
        }
        let widget_ids = if kids.is_empty() { vec![id] } else { kids };
        let widgets = widget_ids
            .into_iter()
            .filter_map(|wid| {
                let w = doc.get_dictionary(wid).ok()?;
                let r = numbers(doc, w.get(b"Rect").ok()?).filter(|r| r.len() == 4)?;
                let rect = [r[0].min(r[2]), r[1].min(r[3]), r[0].max(r[2]), r[1].max(r[3])];
                if rect[2] - rect[0] < 0.5 || rect[3] - rect[1] < 0.5 {
                    return None; // invisible
                }
                let (page, page_num) = self.page_of.get(&wid).copied()?;
                Some(FieldWidget { id: wid, page, page_num, rect, rotate: page_rotation(doc, page) })
            })
            .collect();
        let value = d.get(b"V").ok().map(|v| resolve(doc, v)).and_then(|v| v.as_dict().ok());
        self.out.push(SigField {
            id,
            name,
            signed: value.is_some(),
            timestamp: value.is_some_and(|v| v.get(b"Type").and_then(Object::as_name).ok() == Some(b"DocTimeStamp".as_slice())),
            signer: value.and_then(signer_name),
            widgets,
        });
    }
}

fn signer_name(sig: &Dictionary) -> Option<String> {
    sig.get(b"Name").ok().and_then(|n| lopdf::decode_text_string(n).ok()).map(|n| printable(&n))
}

/// Names come from the document: without control characters they cannot fake lines or
/// terminal escapes in what firma prints.
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// The author's certification, if the document has one: the DocMDP /P value
/// (1 = no changes, 2 = form filling and signing, 3 = also annotations).
pub fn certification(doc: &Document, root: ObjectId) -> Option<i64> {
    let catalog = doc.get_dictionary(root).ok()?;
    let perms = resolve(doc, catalog.get(b"Perms").ok()?).as_dict().ok()?;
    let sig = resolve(doc, perms.get(b"DocMDP").ok()?).as_dict().ok()?;
    let refs = resolve(doc, sig.get(b"Reference").ok()?).as_array().ok()?;
    for r in refs {
        let Ok(r) = resolve(doc, r).as_dict() else { continue };
        if r.get(b"TransformMethod").and_then(Object::as_name).ok() == Some(b"DocMDP".as_slice()) {
            let p = r
                .get(b"TransformParams")
                .ok()
                .and_then(|t| resolve(doc, t).as_dict().ok())
                .and_then(|t| t.get(b"P").ok())
                .and_then(|p| p.as_i64().ok());
            return Some(p.unwrap_or(2));
        }
    }
    Some(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;

    #[test]
    fn survives_looping_kids() {
        let mut doc = Document::with_version("1.7");
        let field = doc.new_object_id();
        let kids: Vec<Object> = (0..50).map(|_| Object::Reference(field)).collect();
        doc.objects.insert(field, Object::Dictionary(dictionary! { "T" => Object::string_literal("a"), "FT" => "Sig", "Kids" => kids }));
        let acroform = doc.add_object(dictionary! { "Fields" => vec![Object::Reference(field)] });
        let root = doc.add_object(dictionary! { "Type" => "Catalog", "AcroForm" => acroform });
        assert!(signature_fields(&doc, root).is_empty());
        assert_eq!(certification(&doc, root), None);
    }

    #[test]
    fn names_cannot_fake_output_lines() {
        assert_eq!(printable("Firma\n  signed:      X\u{1b}[2K"), "Firma  signed:      X[2K");
    }
}
