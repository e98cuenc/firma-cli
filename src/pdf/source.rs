//! A PDF opened for an incremental update, encrypted or not.

use anyhow::{anyhow, bail, Context, Result};
use lopdf::encryption::encrypt_object;
use lopdf::{Document, Object, ObjectId, Permissions, StringFormat};

use super::write::{self, Body, Written};

pub struct Source<'a> {
    pub bytes: &'a [u8],
    /// The document, already decrypted if it was encrypted.
    pub doc: Document,
    /// The original trailer's /Encrypt reference (lopdf drops it when decrypting).
    encrypt: Option<Object>,
}

impl<'a> Source<'a> {
    pub fn open(bytes: &'a [u8], password: Option<&str>) -> Result<Self> {
        let loaded = match password {
            Some(p) => Document::load_mem_with_password(bytes, p),
            None => Document::load_mem(bytes),
        };
        let doc = loaded.map_err(|e| match e {
            lopdf::Error::InvalidPassword => anyhow!(
                "the PDF is password-protected and the password is missing or wrong \
                 (use --pdf-password-file or $FIRMA_PDF_PASSWORD)"
            ),
            lopdf::Error::Decryption(d) => anyhow!("could not decrypt the PDF: {d:?}"),
            e => anyhow!(e).context("could not read the PDF"),
        })?;
        if not_decrypted(&doc) {
            bail!(
                "the PDF is password-protected and the password is missing or wrong \
                 (use --pdf-password-file or $FIRMA_PDF_PASSWORD)"
            );
        }
        if doc.xref_start == 0 {
            bail!("the PDF cross-reference table was not found");
        }
        let encrypt = match &doc.encryption_state {
            Some(state) => {
                // Adding a signature field needs the "add or modify annotations / form fields" right.
                if !state.permissions().contains(Permissions::ANNOTABLE) {
                    bail!("the PDF's security settings do not allow adding signatures");
                }
                // lopdf drops exactly the /Encrypt object after decrypting: the right reference is
                // the one that is in the cross-reference table but no longer among the objects.
                let is_encrypt_dict = |id: ObjectId| {
                    doc.reference_table.get(id.0).is_some() && !doc.objects.contains_key(&id)
                };
                Some(
                    find_encrypt_ref(bytes, is_encrypt_dict)
                        .context("encrypted PDF without an indirect /Encrypt dictionary")?,
                )
            }
            None => None,
        };
        Ok(Self { bytes, doc, encrypt })
    }

    /// Whether `bytes` is a PDF that cannot be opened without a password.
    pub fn needs_password(bytes: &[u8]) -> bool {
        match Document::load_mem(bytes) {
            Err(lopdf::Error::InvalidPassword | lopdf::Error::Decryption(_)) => true,
            Ok(doc) => not_decrypted(&doc),
            Err(_) => false,
        }
    }

    pub fn root_id(&self) -> Result<ObjectId> {
        self.doc.trailer.get(b"Root").and_then(Object::as_reference).context("PDF without a catalog (/Root)")
    }

    /// First object number not used by the document: max(max_id + 1, /Size), validated so that a
    /// crafted trailer cannot make new objects overwrite existing ones.
    pub fn first_free_id(&self) -> Result<u32> {
        let size = self.doc.trailer.get(b"Size").and_then(Object::as_i64).unwrap_or(0).max(0);
        let next = (self.doc.max_id as i64 + 1).max(size);
        // ISO 32000 limits object numbers to 8,388,607; leave room for the objects we add.
        if next > 8_000_000 {
            bail!("the PDF has too many objects (or an invalid /Size)");
        }
        Ok(next as u32)
    }

    /// Serializes a text string that belongs to the hand-written object `id`, encrypted if needed.
    pub fn string(&self, id: ObjectId, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let mut obj = Object::String(bytes, StringFormat::Hexadecimal);
        if let Some(state) = &self.doc.encryption_state {
            encrypt_object(state, id, &mut obj).map_err(|e| anyhow!("encrypting a string: {e:?}"))?;
        }
        let mut out = Vec::new();
        write::object(&mut out, &obj);
        Ok(out)
    }

    /// Appends `objects` as an incremental update, encrypting them if the PDF is encrypted.
    /// (Hand-written `Body::Raw` objects must encrypt their own strings with [`Source::string`].)
    pub fn write(&self, mut objects: Vec<(ObjectId, Body)>) -> Result<Written> {
        if let Some(state) = &self.doc.encryption_state {
            for (id, body) in &mut objects {
                if let Body::Obj(obj) = body {
                    encrypt_object(state, *id, obj).map_err(|e| anyhow!("encrypting object {}: {e:?}", id.0))?;
                }
            }
        }
        let mut trailer = self.doc.trailer.clone();
        if let Some(e) = &self.encrypt {
            trailer.set("Encrypt", e.clone());
        }
        Ok(write::incremental(self.bytes, self.doc.xref_start, &trailer, objects))
    }
}

/// lopdf may load an encrypted PDF it could not decrypt without failing: it then keeps /Encrypt
/// in the trailer and has no encryption state.
fn not_decrypted(doc: &Document) -> bool {
    doc.trailer.get(b"Encrypt").is_ok() && doc.encryption_state.is_none()
}

/// The last `/Encrypt N G R` reference in the file that `accept` confirms.
fn find_encrypt_ref(bytes: &[u8], accept: impl Fn(ObjectId) -> bool) -> Option<Object> {
    let key = b"/Encrypt";
    let mut end = bytes.len();
    while let Some(pos) = bytes[..end].windows(key.len()).rposition(|w| w == key) {
        end = pos;
        let mut rest = bytes[pos + key.len()..].iter().copied().peekable();
        let mut number = || {
            while rest.peek().is_some_and(|b| b.is_ascii_whitespace()) {
                rest.next();
            }
            let mut n = String::new();
            while let Some(b) = rest.peek().copied().filter(u8::is_ascii_digit) {
                n.push(b as char);
                rest.next();
            }
            n.parse::<u32>().ok()
        };
        let (Some(id), Some(gen)) = (number(), number()) else { continue };
        while rest.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            rest.next();
        }
        if rest.next() == Some(b'R') && accept((id, gen as u16)) {
            return Some(Object::Reference((id, gen as u16)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_reference() {
        let pdf = b"1 0 obj<</EncryptMetadata false>>endobj trailer<</Root 2 0 R/Encrypt 7 0 R/Size 9>>";
        assert_eq!(find_encrypt_ref(pdf, |_| true), Some(Object::Reference((7, 0))));
        assert_eq!(find_encrypt_ref(b"trailer<</Encrypt<</V 4>>>>", |_| true), None);
        // A decoy after the real trailer is skipped when it is not the dropped object.
        let decoy = b"trailer<</Encrypt 7 0 R>>\n%/Encrypt 99 0 R";
        assert_eq!(find_encrypt_ref(decoy, |id| id.0 == 7), Some(Object::Reference((7, 0))));
    }
}
