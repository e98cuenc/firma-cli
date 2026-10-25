//! Import of the handwritten signature saved in macOS Preview.
//!
//! Preview does not keep signatures in an accessible file: since macOS 13 they live in the
//! AnnotationKit keychain, which only Apple apps can read. What we can do is have Preview
//! place it on a PDF and extract the annotation from there, which is vector data. That keeps
//! the original quality of the stroke.

use anyhow::{bail, Context, Result};
use lopdf::{dictionary, Document, Object, ObjectId, Stream};

use crate::pdf::{form_extent, resolve, Importer};

pub struct Candidate {
    pub page: u32,
    pub subtype: String,
    pub apple: bool,
    form: ObjectId,
    extent: [f64; 4],
}

/// Annotations with their own appearance that may be a signature.
pub fn candidates(doc: &Document) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (num, page_id) in doc.get_pages() {
        let Ok(page) = doc.get_dictionary(page_id) else { continue };
        let Ok(annots) = page.get(b"Annots").map(|a| resolve(doc, a)).and_then(Object::as_array) else {
            continue;
        };
        for a in annots {
            let Ok(annot) = resolve(doc, a).as_dict() else { continue };
            let subtype = annot.get(b"Subtype").and_then(Object::as_name).map(|n| String::from_utf8_lossy(n).into_owned());
            let Ok(subtype) = subtype else { continue };
            if matches!(subtype.as_str(), "Widget" | "Link" | "Popup") {
                continue;
            }
            let Some(form) = annot
                .get(b"AP")
                .map(|ap| resolve(doc, ap))
                .and_then(Object::as_dict)
                .and_then(|ap| ap.get(b"N"))
                .and_then(Object::as_reference)
                .ok()
            else {
                continue;
            };
            let Some(extent) = doc.get_object(form).and_then(Object::as_stream).ok().and_then(|s| form_extent(doc, &s.dict))
            else {
                continue;
            };
            let apple = annot.iter().any(|(k, _)| k.starts_with(b"AAPL"));
            out.push(Candidate { page: num, subtype, apple, form, extent });
        }
    }
    out
}

/// Extracts the signature from a PDF saved by Preview and returns it as a one-page PDF,
/// with the vector form available as `/Signature`.
pub fn extract(pdf: &[u8], index: Option<usize>) -> Result<Vec<u8>> {
    let src = Document::load_mem(pdf).context("could not read the PDF")?;
    let cands = candidates(&src);
    let chosen = match index {
        Some(i) => cands.get(i.wrapping_sub(1)).with_context(|| format!("there is no annotation #{i}"))?,
        None => {
            let apple: Vec<&Candidate> = cands.iter().filter(|c| c.apple).collect();
            match (cands.len(), apple.len()) {
                (0, _) => bail!(
                    "no signature found in the PDF. In Preview: Tools > Annotate > Signature, \
                     place it and save with ⌘S (do not use a flattening Export)"
                ),
                (1, _) => &cands[0],
                (_, 1) => apple[0],
                _ => {
                    let list: Vec<String> = cands
                        .iter()
                        .enumerate()
                        .map(|(i, c)| format!("  {}: page {}, /{}{}", i + 1, c.page, c.subtype, if c.apple { " (Preview)" } else { "" }))
                        .collect();
                    bail!("there are several annotations; pick one with --index:\n{}", list.join("\n"))
                }
            }
        }
    };
    build_signature_pdf(&src, chosen.form, chosen.extent)
}

fn build_signature_pdf(src: &Document, form: ObjectId, e: [f64; 4]) -> Result<Vec<u8>> {
    let mut doc = Document::with_version("1.7");
    let mut next = 1u32;
    let mut imp = Importer::new(src, &mut next);
    let form_id = imp.import_ref(form);
    for (id, obj) in imp.out {
        doc.objects.insert(id, obj);
    }
    doc.max_id = next - 1;

    let (w, h) = (e[2] - e[0], e[3] - e[1]);
    let content = format!("q 1 0 0 1 {} {} cm /Signature Do Q", -e[0], -e[1]);
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), Object::Real(w as f32), Object::Real(h as f32)],
        "Contents" => content_id,
        "Resources" => dictionary! { "XObject" => dictionary! { "Signature" => form_id } },
    });
    doc.objects.insert(pages_id, Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 }));
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out)?;
    Ok(out)
}

/// One-page PDF with a box where the user places their signature from Preview.
pub fn template() -> Result<Vec<u8>> {
    let mut doc = Document::with_version("1.7");
    let font = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica", "Encoding" => "WinAnsiEncoding",
    });
    let lines = [
        "1. Tools > Annotate > Signature (or the signature icon in the markup toolbar).",
        "2. Pick your signature and drag it inside the box.",
        "3. Save with Cmd+S and go back to the terminal.",
    ];
    let mut content = String::from("BT /F 16 Tf 60 760 Td (Signature from Preview) Tj ET\n");
    for (i, l) in lines.iter().enumerate() {
        content += &format!("BT /F 11 Tf 60 {} Td ({}) Tj ET\n", 725 - i as i32 * 18, l);
    }
    content += "0.6 G 1 w [4 3] 0 d 60 420 475 220 re S\n";
    let content = crate::pdf::text::to_winansi(&content);
    let content_id = doc.add_object(Stream::new(dictionary! {}, content));
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        "Contents" => content_id,
        "Resources" => dictionary! { "Font" => dictionary! { "F" => font } },
    });
    doc.objects.insert(pages_id, Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 }));
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out)?;
    Ok(out)
}
