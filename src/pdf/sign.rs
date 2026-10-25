//! PAdES signing of a PDF through an incremental update.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream, StringFormat};

use super::write::{real, Body};
use super::source::Source;
use super::{form_extent, page_box, page_rotation, resolve, text, Importer};
use crate::cert::{Credential, Digest};

const MM: f64 = 72.0 / 25.4;
const MARGIN_MM: f64 = 10.0;

#[derive(Debug, Clone, Copy)]
pub enum PageSel {
    /// 1 = first, -1 = last.
    Num(i64),
    All,
}

#[derive(Debug, Clone, Copy)]
pub enum Anchor {
    /// Bottom-left corner, in mm from the bottom-left corner of the page.
    Abs(f64, f64),
    /// (horizontal, vertical): -1 left/bottom, 0 center, 1 right/top.
    Preset(i8, i8),
}

#[derive(Debug, Clone, Copy)]
pub struct Placement {
    pub page: PageSel,
    pub anchor: Anchor,
    /// Width and height in mm.
    pub size: Option<(f64, f64)>,
}

impl std::str::FromStr for Placement {
    type Err = anyhow::Error;

    /// `PAGE:POSITION[:WIDTHxHEIGHT]`, e.g. `last:bottom-right`, `1:120,40:70x30`.
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            bail!("invalid position '{s}'; format is PAGE:POSITION[:WIDTHxHEIGHT]");
        }
        let page = match parts[0].to_lowercase().as_str() {
            "last" => PageSel::Num(-1),
            "first" => PageSel::Num(1),
            "all" => PageSel::All,
            n => PageSel::Num(n.parse().map_err(|_| anyhow!("invalid page '{n}'"))?),
        };
        if matches!(page, PageSel::Num(0)) {
            bail!("pages start at 1");
        }
        let pos = parts[1].to_lowercase();
        let anchor = if let Some((x, y)) = pos.split_once(',') {
            Anchor::Abs(parse_num(x)?, parse_num(y)?)
        } else {
            let (v, h) = pos.split_once('-').unwrap_or((pos.as_str(), "center"));
            let v = match v {
                "bottom" => -1,
                "top" => 1,
                "center" => 0,
                _ => bail!("invalid position '{pos}' (e.g. bottom-right, top-left, 120,40)"),
            };
            let h = match h {
                "left" => -1,
                "right" => 1,
                "center" => 0,
                _ => bail!("invalid position '{pos}' (e.g. bottom-right, top-left, 120,40)"),
            };
            Anchor::Preset(h, v)
        };
        let size = match parts.get(2) {
            Some(sz) => {
                let (w, h) = sz.split_once(['x', 'X']).ok_or_else(|| anyhow!("invalid size '{sz}'; use WIDTHxHEIGHT"))?;
                let (w, h) = (parse_num(w)?, parse_num(h)?);
                if w <= 0.0 || h <= 0.0 {
                    bail!("the size must be positive");
                }
                Some((w, h))
            }
            None => None,
        };
        Ok(Placement { page, anchor, size })
    }
}

fn parse_num(s: &str) -> Result<f64> {
    s.trim().replace(',', ".").parse().map_err(|_| anyhow!("invalid number: '{s}'"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFilter {
    Pades,
    Pkcs7,
}

pub enum GraphicSource<'a> {
    Image(&'a Path),
    Vector(&'a Path),
}

pub struct SignOptions {
    /// Boxes with the handwritten signature (and the stamp text, if any).
    pub placements: Vec<Placement>,
    /// Boxes with only the stamp text.
    pub stamp_placements: Vec<Placement>,
    /// Expanded stamp text.
    pub stamp_text: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
    pub subfilter: SubFilter,
    pub reserve: usize,
    pub date: chrono::DateTime<chrono::Local>,
}

pub const DEFAULT_SIGNATURE_SIZE: (f64, f64) = (60.0, 25.0);
pub const DEFAULT_STAMP_SIZE: (f64, f64) = (80.0, 18.0);

struct Widget {
    page: ObjectId,
    rect: [f64; 4],
    /// Page /Rotate: the appearance is rotated so it reads upright.
    rotate: i64,
    /// Box size as displayed (width, height).
    size: (f64, f64),
    with_graphic: bool,
    with_text: bool,
}

/// Handwritten-signature graphic already added to the update.
enum Graphic {
    Image { id: ObjectId, w: f64, h: f64 },
    Form { id: ObjectId, extent: [f64; 4] },
}

impl Graphic {
    fn natural_size(&self) -> (f64, f64) {
        match self {
            Graphic::Image { w, h, .. } => (*w, *h),
            Graphic::Form { extent, .. } => (extent[2] - extent[0], extent[3] - extent[1]),
        }
    }

    fn id(&self) -> ObjectId {
        match self {
            Graphic::Image { id, .. } | Graphic::Form { id, .. } => *id,
        }
    }

    /// Operators that draw it fitted and centered in (x, y, w, h).
    fn draw(&self, x: f64, y: f64, w: f64, h: f64) -> String {
        let (nw, nh) = self.natural_size();
        let s = (w / nw).min(h / nh);
        let (dw, dh) = (nw * s, nh * s);
        let (ox, oy) = (x + (w - dw) / 2.0, y + (h - dh) / 2.0);
        match self {
            Graphic::Image { .. } => format!("q {} 0 0 {} {} {} cm /Sig Do Q\n", real(dw), real(dh), real(ox), real(oy)),
            Graphic::Form { extent, .. } => format!(
                "q {} 0 0 {} {} {} cm /Sig Do Q\n",
                real(s),
                real(s),
                real(ox - extent[0] * s),
                real(oy - extent[1] * s)
            ),
        }
    }
}

pub struct Signed {
    pub pdf: Vec<u8>,
    /// Full /Contents value (CMS or time-stamp token plus zero padding), used for the /VRI key.
    pub contents: Vec<u8>,
}

pub use crate::cms::Timestamper;

/// A placed box: page, /Rect, page /Rotate and displayed size.
type Located = (ObjectId, [f64; 4], i64, (f64, f64));

/// Objects of one incremental update being assembled.
struct Update<'s, 'a> {
    src: &'s Source<'a>,
    next_id: u32,
    objects: Vec<(ObjectId, Body)>,
}

impl<'s, 'a> Update<'s, 'a> {
    fn new(src: &'s Source<'a>) -> Result<Self> {
        Ok(Self { src, next_id: src.first_free_id()?, objects: Vec::new() })
    }

    fn alloc(&mut self) -> ObjectId {
        let id = (self.next_id, 0);
        self.next_id += 1;
        id
    }

    fn push(&mut self, id: ObjectId, obj: Object) {
        self.objects.push((id, Body::Obj(obj)));
    }

    /// Adds the field's widgets to the pages' /Annots and the field to the /AcroForm.
    fn add_field(&mut self, field_id: ObjectId, annots_by_page: &BTreeMap<ObjectId, Vec<ObjectId>>) -> Result<()> {
        let doc = &self.src.doc;
        for (page_id, new_annots) in annots_by_page {
            let mut page = doc.get_dictionary(*page_id)?.clone();
            let refs = new_annots.iter().map(|id| Object::Reference(*id));
            match page.get(b"Annots").ok().cloned() {
                Some(Object::Reference(arr_id)) => {
                    let mut arr = doc.get_object(arr_id).and_then(Object::as_array).cloned().unwrap_or_default();
                    arr.extend(refs);
                    self.push(arr_id, Object::Array(arr));
                }
                Some(Object::Array(mut arr)) => {
                    arr.extend(refs);
                    page.set("Annots", arr);
                    self.push(*page_id, Object::Dictionary(page));
                }
                _ => {
                    page.set("Annots", refs.collect::<Vec<_>>());
                    self.push(*page_id, Object::Dictionary(page));
                }
            }
        }

        let root_id = self.src.root_id()?;
        let catalog = doc.get_dictionary(root_id)?.clone();
        let (acroform_id, mut acroform) = match catalog.get(b"AcroForm") {
            Ok(Object::Reference(id)) => (Some(*id), doc.get_dictionary(*id).cloned().unwrap_or_default()),
            Ok(Object::Dictionary(d)) => (None, d.clone()),
            _ => (None, Dictionary::new()),
        };
        let mut fields = acroform.get(b"Fields").map(|f| resolve(doc, f)).and_then(Object::as_array).cloned().unwrap_or_default();
        fields.push(Object::Reference(field_id));
        acroform.set("Fields", fields);
        acroform.set("SigFlags", 3);
        match acroform_id {
            Some(id) => self.push(id, Object::Dictionary(acroform)),
            None => {
                let id = self.alloc();
                self.push(id, Object::Dictionary(acroform));
                let mut catalog = catalog;
                catalog.set("AcroForm", id);
                self.push(root_id, Object::Dictionary(catalog));
            }
        }
        Ok(())
    }

    /// Writes the update. `head` is the signature dictionary up to (not including) /ByteRange;
    /// /Contents is reserved with `reserve` bytes and filled with `produce(signed_bytes_digest_input)`,
    /// which receives the two byte ranges covered by the signature.
    fn finish(
        mut self,
        sig_id: ObjectId,
        mut head: Vec<u8>,
        reserve: usize,
        produce: impl FnOnce(&[u8], &[u8]) -> Result<Vec<u8>>,
    ) -> Result<Signed> {
        head.extend_from_slice(b"/ByteRange[0 0000000000 0000000000 0000000000]");
        head.extend_from_slice(b"/Contents<");
        head.extend(std::iter::repeat_n(b'0', reserve * 2));
        head.extend_from_slice(b">>>");
        self.objects.push((sig_id, Body::Raw(head)));

        let written = self.src.write(self.objects)?;
        let mut out = written.bytes;
        let sig_off = written.offsets.iter().find(|(id, _)| *id == sig_id).map(|(_, o)| *o).unwrap();
        let br_pos = sig_off + find(&out[sig_off..], b"/ByteRange[").unwrap() + b"/ByteRange[".len();
        let contents_start = sig_off + find(&out[sig_off..], b"/Contents<").unwrap() + b"/Contents".len();
        let contents_end = contents_start + reserve * 2 + 2;
        let byte_range = format!("0 {:<10} {:<10} {:<10}", contents_start, contents_end, out.len() - contents_end);
        debug_assert_eq!(byte_range.len(), "0 0000000000 0000000000 0000000000".len());
        out[br_pos..br_pos + byte_range.len()].copy_from_slice(byte_range.as_bytes());

        let value = produce(&out[..contents_start], &out[contents_end..])?;
        if value.len() > reserve {
            bail!("the signature takes {} bytes but only {} are reserved; use --reserve {}", value.len(), reserve, value.len() + 4096);
        }
        let hex: String = value.iter().map(|b| format!("{b:02X}")).collect();
        out[contents_start + 1..contents_start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
        let mut contents = value;
        contents.resize(reserve, 0);
        Ok(Signed { pdf: out, contents })
    }
}

pub fn sign_pdf(
    input: &[u8],
    password: Option<&str>,
    cred: &Credential,
    graphic: Option<GraphicSource>,
    opts: &SignOptions,
    timestamp: Option<Timestamper>,
) -> Result<Signed> {
    let src = Source::open(input, password)?;
    let doc = &src.doc;
    let root_id = src.root_id()?;
    let pages = doc.get_pages();
    if pages.is_empty() {
        bail!("the PDF has no pages");
    }
    let mut up = Update::new(&src)?;

    // --- Visible boxes ---
    let mut widgets = Vec::new();
    let has_text = opts.stamp_text.is_some();
    for p in &opts.placements {
        for (page, rect, rotate, size) in resolve_placement(doc, &pages, p, DEFAULT_SIGNATURE_SIZE)? {
            widgets.push(Widget { page, rect, rotate, size, with_graphic: graphic.is_some(), with_text: has_text });
        }
    }
    for p in &opts.stamp_placements {
        for (page, rect, rotate, size) in resolve_placement(doc, &pages, p, DEFAULT_STAMP_SIZE)? {
            widgets.push(Widget { page, rect, rotate, size, with_graphic: false, with_text: true });
        }
    }

    // --- Shared resources: font and signature graphic ---
    let font_id = if widgets.iter().any(|w| w.with_text) {
        let id = up.alloc();
        up.push(
            id,
            Object::Dictionary(dictionary! {
                "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica", "Encoding" => "WinAnsiEncoding",
            }),
        );
        Some(id)
    } else {
        None
    };
    let graphic = match (&graphic, widgets.iter().any(|w| w.with_graphic)) {
        (Some(gs), true) => Some(load_graphic(gs, &mut up)?),
        _ => None,
    };

    // --- Appearances and annotations ---
    let sig_id = up.alloc();
    let field_id = up.alloc();
    let field_name = unique_field_name(doc, root_id);
    let mut widget_ids = Vec::new();
    let mut annots_by_page: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
    let field_entries = |d: &mut Dictionary| {
        d.set("FT", "Sig");
        d.set("T", Object::String(text_string(&field_name), StringFormat::Hexadecimal));
        d.set("V", sig_id);
    };

    if widgets.is_empty() {
        // Invisible signature: a zero-size widget on the first page.
        let first = *pages.values().next().unwrap();
        let mut d = make_widget([0.0; 4], first, None);
        field_entries(&mut d);
        up.push(field_id, Object::Dictionary(d));
        annots_by_page.entry(first).or_default().push(field_id);
    } else {
        for w in &widgets {
            let ap_id = up.alloc();
            let (bw, bh) = w.size;
            let ap = appearance(
                bw,
                bh,
                w.rotate,
                if w.with_graphic { graphic.as_ref() } else { None },
                if w.with_text { opts.stamp_text.as_deref() } else { None },
                font_id,
            );
            up.push(ap_id, ap);
            let widget_id = if widgets.len() == 1 { field_id } else { up.alloc() };
            let mut d = make_widget(w.rect, w.page, Some(ap_id));
            if widgets.len() == 1 {
                field_entries(&mut d);
            } else {
                d.set("Parent", field_id);
            }
            up.push(widget_id, Object::Dictionary(d));
            widget_ids.push(widget_id);
            annots_by_page.entry(w.page).or_default().push(widget_id);
        }
        if widgets.len() > 1 {
            let mut d = Dictionary::new();
            field_entries(&mut d);
            d.set("Kids", widget_ids.iter().map(|id| Object::Reference(*id)).collect::<Vec<_>>());
            up.push(field_id, Object::Dictionary(d));
        }
    }
    up.add_field(field_id, &annots_by_page)?;

    // --- Signature dictionary (strings encrypted if the PDF is) ---
    let info = cred.info();
    let mut head = Vec::new();
    head.extend_from_slice(b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter");
    head.extend_from_slice(match opts.subfilter {
        SubFilter::Pades => b"/ETSI.CAdES.detached",
        SubFilter::Pkcs7 => b"/adbe.pkcs7.detached",
    });
    head.extend_from_slice(b"/M");
    head.extend(src.string(sig_id, pdf_date(&opts.date).into_bytes())?);
    let mut entries = vec![("Name", info.holder.clone())];
    entries.extend(opts.reason.clone().map(|r| ("Reason", r)));
    entries.extend(opts.location.clone().map(|l| ("Location", l)));
    entries.extend(opts.contact.clone().map(|c| ("ContactInfo", c)));
    for (key, value) in entries {
        let _ = write!(head, "/{key}");
        head.extend(src.string(sig_id, text_string(&value))?);
    }
    head.extend_from_slice(b"/Prop_Build<</App<</Name/firma/REx");
    head.extend(src.string(sig_id, env!("CARGO_PKG_VERSION").as_bytes().to_vec())?);
    head.extend_from_slice(b">>>>");

    up.finish(sig_id, head, opts.reserve, |before, after| {
        let digest = cred.digest().hash(&[before, after]);
        crate::cms::sign_detached(cred, &digest, timestamp)
    })
}

/// Adds a document time-stamp (PAdES B-LTA): an invisible signature field whose /Contents is an
/// RFC 3161 token over the whole document. `stamp` receives the SHA-256 digest of the covered bytes.
pub fn add_doc_timestamp(
    input: &[u8],
    password: Option<&str>,
    reserve: usize,
    stamp: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Signed> {
    let src = Source::open(input, password)?;
    let pages = src.doc.get_pages();
    let first = *pages.values().next().context("the PDF has no pages")?;
    let mut up = Update::new(&src)?;
    let ts_id = up.alloc();
    let field_id = up.alloc();
    let mut d = make_widget([0.0; 4], first, None);
    d.set("FT", "Sig");
    let name = unique_field_name(&src.doc, src.root_id()?).replace("Signature", "DocTimeStamp");
    d.set("T", Object::String(text_string(&name), StringFormat::Hexadecimal));
    d.set("V", ts_id);
    up.push(field_id, Object::Dictionary(d));
    up.add_field(field_id, &BTreeMap::from([(first, vec![field_id])]))?;
    let head = b"<</Type/DocTimeStamp/Filter/Adobe.PPKLite/SubFilter/ETSI.RFC3161".to_vec();
    up.finish(ts_id, head, reserve, |before, after| stamp(&Digest::Sha256.hash(&[before, after])))
}

/// Adds (or extends) the /DSS dictionary in a new incremental update (PAdES B-LT).
pub fn append_dss(pdf: &[u8], password: Option<&str>, contents: &[u8], v: &crate::revocation::Validation) -> Result<Vec<u8>> {
    use sha1::Digest as _;
    let src = Source::open(pdf, password).context("could not re-read the signed PDF")?;
    let doc = &src.doc;
    let root_id = src.root_id()?;
    let mut up = Update::new(&src)?;
    let mut add_streams = |items: &[Vec<u8>]| -> Vec<Object> {
        items
            .iter()
            .map(|data| {
                let id = up.alloc();
                up.push(id, Object::Stream(Stream::new(dictionary! { "Filter" => "FlateDecode" }, deflate(data))));
                Object::Reference(id)
            })
            .collect()
    };
    let certs = add_streams(&v.certs);
    let ocsps = add_streams(&v.ocsps);
    let crls = add_streams(&v.crls);

    let mut catalog = doc.get_dictionary(root_id)?.clone();
    let (dss_id, mut dss) = match catalog.get(b"DSS") {
        Ok(Object::Reference(id)) => (*id, doc.get_dictionary(*id).cloned().unwrap_or_default()),
        Ok(Object::Dictionary(d)) => (up.alloc(), d.clone()),
        _ => (up.alloc(), Dictionary::new()),
    };
    if !matches!(catalog.get(b"DSS"), Ok(Object::Reference(_))) {
        catalog.set("DSS", dss_id);
        up.push(root_id, Object::Dictionary(catalog));
    }
    let merge = |dss: &mut Dictionary, key: &str, new: &[Object]| {
        if new.is_empty() {
            return;
        }
        let mut arr = dss.get(key.as_bytes()).map(|o| resolve(doc, o)).and_then(Object::as_array).cloned().unwrap_or_default();
        arr.extend_from_slice(new);
        dss.set(key, arr);
    };
    merge(&mut dss, "Certs", &certs);
    merge(&mut dss, "OCSPs", &ocsps);
    merge(&mut dss, "CRLs", &crls);

    // /VRI: key = uppercase hex SHA-1 of /Contents.
    let key: String = sha1::Sha1::digest(contents).iter().map(|b| format!("{b:02X}")).collect();
    let mut entry = Dictionary::new();
    for (k, arr) in [("Cert", &certs), ("OCSP", &ocsps), ("CRL", &crls)] {
        if !arr.is_empty() {
            entry.set(k, arr.clone());
        }
    }
    let mut vri = dss.get(b"VRI").map(|o| resolve(doc, o)).and_then(Object::as_dict).cloned().unwrap_or_default();
    vri.set(key.as_bytes().to_vec(), entry);
    dss.set("VRI", vri);
    dss.set("Type", "DSS");
    up.push(dss_id, Object::Dictionary(dss));

    Ok(src.write(up.objects)?.bytes)
}

fn make_widget(rect: [f64; 4], page: ObjectId, ap: Option<ObjectId>) -> Dictionary {
    let mut d = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "Rect" => rect.iter().map(|v| Object::Real(*v as f32)).collect::<Vec<_>>(),
        "P" => page,
        "F" => 132, // print + locked
    };
    if let Some(ap) = ap {
        d.set("AP", dictionary! { "N" => ap });
    }
    d
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn resolve_placement(
    doc: &Document,
    pages: &BTreeMap<u32, ObjectId>,
    p: &Placement,
    default_size: (f64, f64),
) -> Result<Vec<Located>> {
    let n = pages.len() as i64;
    let selected: Vec<ObjectId> = match p.page {
        PageSel::All => pages.values().copied().collect(),
        PageSel::Num(i) => {
            let idx = if i < 0 { n + i + 1 } else { i };
            if idx < 1 || idx > n {
                bail!("page {i} does not exist (the document has {n})");
            }
            vec![pages[&(idx as u32)]]
        }
    };
    let (w, h) = p.size.unwrap_or(default_size);
    let (w, h) = (w * MM, h * MM);
    Ok(selected
        .into_iter()
        .map(|page| {
            let b = page_box(doc, page);
            let rotate = page_rotation(doc, page);
            // Coordinates refer to the page as displayed (already rotated).
            let (bw, bh) = (b[2] - b[0], b[3] - b[1]);
            let (pw, ph) = if rotate % 180 == 90 { (bh, bw) } else { (bw, bh) };
            let m = MARGIN_MM * MM;
            let (x, y) = match p.anchor {
                Anchor::Abs(x, y) => (x * MM, y * MM),
                Anchor::Preset(hz, vt) => {
                    let x = match hz {
                        -1 => m,
                        1 => pw - m - w,
                        _ => (pw - w) / 2.0,
                    };
                    let y = match vt {
                        -1 => m,
                        1 => ph - m - h,
                        _ => (ph - h) / 2.0,
                    };
                    (x, y)
                }
            };
            // From displayed coordinates to the page's user space.
            let to_user = |vx: f64, vy: f64| match rotate {
                90 => (bw - vy, vx),
                180 => (bw - vx, bh - vy),
                270 => (vy, bh - vx),
                _ => (vx, vy),
            };
            let (ax, ay) = to_user(x, y);
            let (cx, cy) = to_user(x + w, y + h);
            let rect = [b[0] + ax.min(cx), b[1] + ay.min(cy), b[0] + ax.max(cx), b[1] + ay.max(cy)];
            (page, rect, rotate, (w, h))
        })
        .collect())
}

fn appearance(w: f64, h: f64, rotate: i64, graphic: Option<&Graphic>, text: Option<&str>, font: Option<ObjectId>) -> Object {
    let pad = 2.0;
    let (iw, ih) = (w - 2.0 * pad, h - 2.0 * pad);
    let mut ops = String::new();
    let mut text_area = None;
    match (graphic, text) {
        (Some(r), Some(_)) => {
            if w >= h * 1.6 {
                let rw = iw * 0.42;
                ops += &r.draw(pad, pad, rw, ih);
                text_area = Some((pad + rw + pad, pad, iw - rw - pad, ih));
            } else {
                let th = ih * 0.4;
                ops += &r.draw(pad, pad + th + pad, iw, ih - th - pad);
                text_area = Some((pad, pad, iw, th));
            }
        }
        (Some(r), None) => ops += &r.draw(pad, pad, iw, ih),
        (None, Some(_)) => text_area = Some((pad, pad, iw, ih)),
        (None, None) => {}
    }
    let mut content = ops.into_bytes();
    if let (Some(t), Some((x, y, tw, th))) = (text, text_area) {
        let (size, lines) = text::fit(t, tw, th, 9.0);
        let lead = size * text::LINE_HEIGHT;
        let block = lead * lines.len() as f64;
        let first_baseline = y + (th + block) / 2.0 - size * 0.9;
        let _ = writeln!(
            content,
            "BT /Helv {} Tf {} TL 0.15 0.15 0.15 rg {} {} Td",
            real(size),
            real(lead),
            real(x),
            real(first_baseline)
        );
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                content.extend_from_slice(b"T* ");
            }
            content.extend(text::pdf_literal(line));
            content.extend_from_slice(b" Tj\n");
        }
        content.extend_from_slice(b"ET\n");
    }
    let mut resources = Dictionary::new();
    if let (Some(f), Some(_)) = (font, text) {
        resources.set("Font", dictionary! { "Helv" => f });
    }
    if let Some(r) = graphic {
        resources.set("XObject", dictionary! { "Sig" => r.id() });
    }
    let mut dict = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Form",
        "BBox" => vec![0.into(), 0.into(), Object::Real(w as f32), Object::Real(h as f32)],
        "Resources" => resources,
    };
    // The page is displayed rotated `rotate` degrees clockwise; rotate the appearance
    // by the same amount counter-clockwise so it reads upright.
    let m: Option<[i64; 4]> = match rotate {
        90 => Some([0, 1, -1, 0]),
        180 => Some([-1, 0, 0, -1]),
        270 => Some([0, -1, 1, 0]),
        _ => None,
    };
    if let Some(m) = m {
        dict.set("Matrix", m.iter().map(|v| Object::Integer(*v)).chain([0.into(), 0.into()]).collect::<Vec<_>>());
    }
    Object::Stream(Stream::new(dict, content))
}

fn load_graphic(gs: &GraphicSource, up: &mut Update) -> Result<Graphic> {
    match gs {
        GraphicSource::Image(path) => {
            let img = image::open(path).with_context(|| format!("could not open {}", path.display()))?.to_rgba8();
            let (w, h) = img.dimensions();
            let mut rgb = Vec::with_capacity((w * h * 3) as usize);
            let mut alpha = Vec::with_capacity((w * h) as usize);
            for px in img.pixels() {
                rgb.extend_from_slice(&px.0[..3]);
                alpha.push(px.0[3]);
            }
            let mut dict = dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => w as i64, "Height" => h as i64,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "Filter" => "FlateDecode",
            };
            if alpha.iter().any(|a| *a != 255) {
                let smask_id = up.alloc();
                let smask = dictionary! {
                    "Type" => "XObject", "Subtype" => "Image",
                    "Width" => w as i64, "Height" => h as i64,
                    "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8, "Filter" => "FlateDecode",
                };
                up.push(smask_id, Object::Stream(Stream::new(smask, deflate(&alpha))));
                dict.set("SMask", smask_id);
            }
            let id = up.alloc();
            up.push(id, Object::Stream(Stream::new(dict, deflate(&rgb))));
            Ok(Graphic::Image { id, w: w as f64, h: h as f64 })
        }
        GraphicSource::Vector(path) => {
            let src = Document::load(path).with_context(|| format!("could not open {}", path.display()))?;
            let page = *src.get_pages().values().next().context("vector signature without pages")?;
            let res = resolve(&src, src.get_dictionary(page)?.get(b"Resources")?).as_dict()?;
            let form_ref = resolve(&src, res.get(b"XObject")?).as_dict()?.get(b"Signature")?.as_reference()?;
            let form = src.get_object(form_ref)?.as_stream()?;
            let extent = form_extent(&src, &form.dict).context("the vector signature has no valid /BBox")?;
            let mut imp = Importer::new(&src, &mut up.next_id);
            let id = imp.import_ref(form_ref);
            for (oid, o) in imp.out {
                up.push(oid, o);
            }
            Ok(Graphic::Form { id, extent })
        }
    }
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn unique_field_name(doc: &Document, root: ObjectId) -> String {
    let mut existing = Vec::new();
    if let Ok(cat) = doc.get_dictionary(root) {
        if let Ok(af) = cat.get(b"AcroForm") {
            if let Ok(af) = resolve(doc, af).as_dict() {
                if let Ok(fields) = af.get(b"Fields") {
                    for f in resolve(doc, fields).as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                        if let Ok(Object::String(t, _)) = resolve(doc, f).as_dict().and_then(|d| d.get(b"T")) {
                            existing.push(lopdf::decode_text_string(&Object::String(t.clone(), StringFormat::Literal)).unwrap_or_default());
                        }
                    }
                }
            }
        }
    }
    (1..).map(|i| format!("Signature{i}")).find(|n| !existing.contains(n)).unwrap()
}

/// PDF text string: ASCII as is, otherwise UTF-16BE with a BOM.
fn text_string(s: &str) -> Vec<u8> {
    if s.is_ascii() {
        return s.as_bytes().to_vec();
    }
    let mut out = vec![0xFE, 0xFF];
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_be_bytes());
    }
    out
}

fn pdf_date(d: &chrono::DateTime<chrono::Local>) -> String {
    let off = d.offset().local_minus_utc();
    let sign = if off < 0 { '-' } else { '+' };
    let off = off.abs();
    format!("{}{}{:02}'{:02}'", d.format("D:%Y%m%d%H%M%S"), sign, off / 3600, (off % 3600) / 60)
}

/// Page number, page rotation and size in mm of each box `placements` resolve to (for previews).
/// A box preview: page number, page /Rotate and size in mm.
pub type BoxPreview = (u32, i64, (f64, f64));

pub fn preview_boxes(doc: &Document, placements: &[Placement], default_size: (f64, f64)) -> Result<Vec<BoxPreview>> {
    let pages = doc.get_pages();
    let number: BTreeMap<ObjectId, u32> = pages.iter().map(|(n, id)| (*id, *n)).collect();
    let mut out = Vec::new();
    for p in placements {
        for (page, _, rotate, (w, h)) in resolve_placement(doc, &pages, p, default_size)? {
            out.push((number[&page], rotate, (w / MM, h / MM)));
        }
    }
    Ok(out)
}
