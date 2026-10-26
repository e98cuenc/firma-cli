//! XML canonicalization (C14N 1.0 and Exclusive C14N 1.0, both without comments) for XAdES.
//!
//! Documents with a DTD are rejected: no entity expansion, external entities or default
//! attributes, so a document's canonical form depends only on its own text.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// http://www.w3.org/TR/2001/REC-xml-c14n-20010315
    Inclusive,
    /// http://www.w3.org/2001/10/xml-exc-c14n#
    Exclusive,
}

/// A parsed and canonicalized document.
pub struct Canonical {
    pub text: String,
    /// Local name and namespace URI of the root element.
    pub root: (String, String),
    /// Byte offset (in the input) of the root element's end tag, where an enveloped signature goes.
    pub root_end: Option<usize>,
}

struct Frame {
    qname: String,
    in_scope: BTreeMap<String, String>,
    rendered: BTreeMap<String, String>,
}

/// Canonicalizes a whole UTF-8 document.
pub fn canonicalize(xml: &str, mode: Mode) -> Result<Canonical> {
    let mut reader = Reader::from_str(xml);
    let mut out = String::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut text = String::new();
    let mut root: Option<(String, String)> = None;
    let mut root_end = None;
    let mut done = false;
    loop {
        let pos = reader.buffer_position() as usize;
        let event = reader.read_event().map_err(|e| anyhow!("invalid XML at byte {}: {e}", reader.error_position()))?;
        let inside = !stack.is_empty();
        if !matches!(event, Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)) && !text.is_empty() {
            escape_text(&text, &mut out);
            text.clear();
        }
        match event {
            Event::Start(e) | Event::Empty(e) if done => bail!("invalid XML: more than one root element ({})", e.name().0),
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(event, Event::Empty(_));
                let qname = e.name().0.to_string();
                let parent = stack.last();
                let mut in_scope = parent.map(|p| p.in_scope.clone()).unwrap_or_default();
                let mut attrs = Vec::new();
                for a in e.attributes() {
                    let a = a.map_err(|e| anyhow!("invalid XML attribute: {e}"))?;
                    let key = a.key.0;
                    let value = attr_value(&a.value)?;
                    if key == "xmlns" {
                        in_scope.insert(String::new(), value);
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        if value.is_empty() {
                            bail!("invalid XML: empty namespace for prefix '{p}'");
                        }
                        in_scope.insert(p.to_string(), value);
                    } else {
                        attrs.push((key.to_string(), value));
                    }
                }
                let resolve = |prefix: &str| -> Result<String> {
                    match prefix {
                        "xml" => Ok(XML_NS.to_string()),
                        p => in_scope.get(p).cloned().ok_or_else(|| anyhow!("invalid XML: undeclared prefix '{p}'")),
                    }
                };
                let (prefix, local) = split(&qname);
                let ns = if prefix.is_empty() { in_scope.get("").cloned().unwrap_or_default() } else { resolve(prefix)? };
                if !inside {
                    root = Some((local.to_string(), ns.clone()));
                }

                // Attributes sorted by (namespace URI, local name); unqualified ones have no namespace.
                let mut sorted = Vec::new();
                for (k, v) in attrs {
                    let (p, l) = split(&k);
                    let uri = if p.is_empty() { String::new() } else { resolve(p)? };
                    sorted.push(((uri, l.to_string()), k, v));
                }
                sorted.sort_by(|a, b| a.0.cmp(&b.0));

                let parent_rendered = parent.map(|p| p.rendered.clone()).unwrap_or_default();
                let candidates: Vec<String> = match mode {
                    Mode::Inclusive => in_scope.keys().cloned().chain([String::new()]).collect(),
                    Mode::Exclusive => {
                        let mut used = vec![prefix.to_string()];
                        used.extend(sorted.iter().map(|(_, k, _)| split(k).0.to_string()).filter(|p| !p.is_empty()));
                        used
                    }
                };
                let mut rendered = parent_rendered.clone();
                let mut decls = BTreeMap::new();
                for p in candidates {
                    if p == "xml" {
                        continue;
                    }
                    let uri = in_scope.get(&p).cloned().unwrap_or_default();
                    let before = parent_rendered.get(&p).cloned().unwrap_or_default();
                    // An empty URI only matters to undo a rendered default namespace (xmlns="").
                    if uri != before && (!uri.is_empty() || p.is_empty()) {
                        decls.insert(p.clone(), uri.clone());
                        rendered.insert(p, uri);
                    }
                }

                out.push('<');
                out.push_str(&qname);
                for (p, uri) in &decls {
                    out.push_str(if p.is_empty() { " xmlns" } else { " xmlns:" });
                    out.push_str(p);
                    out.push_str("=\"");
                    escape_attr(uri, &mut out);
                    out.push('"');
                }
                for (_, k, v) in &sorted {
                    out.push(' ');
                    out.push_str(k);
                    out.push_str("=\"");
                    escape_attr(v, &mut out);
                    out.push('"');
                }
                out.push('>');
                if empty {
                    out.push_str("</");
                    out.push_str(&qname);
                    out.push('>');
                    if !inside {
                        done = true;
                    }
                } else {
                    stack.push(Frame { qname, in_scope, rendered });
                }
            }
            Event::End(e) => {
                let frame = stack.pop().context("invalid XML: unexpected end tag")?;
                if e.name().0 != frame.qname {
                    bail!("invalid XML: </{}> closes <{}>", e.name().0, frame.qname);
                }
                out.push_str("</");
                out.push_str(&frame.qname);
                out.push('>');
                if stack.is_empty() {
                    root_end = Some(pos);
                    done = true;
                }
            }
            Event::Text(t) => {
                let raw = t.into_inner();
                if inside {
                    text.push_str(&normalize_eol(&raw));
                } else if !raw.trim_matches([' ', '\t', '\r', '\n']).is_empty() {
                    bail!("invalid XML: text outside the root element");
                }
            }
            Event::CData(t) => {
                if !inside {
                    bail!("invalid XML: CDATA outside the root element");
                }
                text.push_str(&normalize_eol(&t.into_inner()));
            }
            Event::GeneralRef(r) => {
                if !inside {
                    bail!("invalid XML: reference outside the root element");
                }
                text.push(resolve_ref(&r.into_inner())?);
            }
            Event::PI(pi) => {
                let raw = normalize_eol(&pi.into_inner());
                let (target, data) = match raw.find([' ', '\t', '\n']) {
                    Some(i) => (&raw[..i], raw[i..].trim_start_matches([' ', '\t', '\n'])),
                    None => (raw.as_str(), ""),
                };
                if done {
                    out.push('\n');
                }
                out.push_str("<?");
                out.push_str(target);
                if !data.is_empty() {
                    out.push(' ');
                    out.push_str(data);
                }
                out.push_str("?>");
                if root.is_none() {
                    out.push('\n');
                }
            }
            Event::DocType(_) => bail!("XML documents with a DTD (<!DOCTYPE>) are not supported"),
            Event::Comment(_) | Event::Decl(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        bail!("invalid XML: <{}> is not closed", stack.last().map(|f| f.qname.as_str()).unwrap_or(""));
    }
    let root = root.context("invalid XML: no root element")?;
    Ok(Canonical { text: out, root, root_end })
}

fn split(qname: &str) -> (&str, &str) {
    qname.split_once(':').unwrap_or(("", qname))
}

/// XML end-of-line handling: CRLF and lone CR become LF.
fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// An attribute's value as the parser reports it (no DTD, so every attribute is CDATA).
fn attr_value(raw: &str) -> Result<String> {
    if raw.contains('<') {
        bail!("invalid XML: '<' in attribute value");
    }
    let raw: String = normalize_eol(raw).chars().map(|c| if matches!(c, '\t' | '\n') { ' ' } else { c }).collect();
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw.as_str();
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let end = rest[i..].find(';').ok_or_else(|| anyhow!("invalid XML: unterminated reference in attribute"))?;
        out.push(resolve_ref(&rest[i + 1..i + end])?);
        rest = &rest[i + end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `amp`, `#38`, `#x26`… → the character. Without a DTD only the predefined entities exist.
fn resolve_ref(name: &str) -> Result<char> {
    Ok(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        n if n.starts_with('#') => {
            let code = match n.strip_prefix("#x") {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => n[1..].parse(),
            };
            code.ok()
                .and_then(char::from_u32)
                .filter(|c| *c != '\0')
                .ok_or_else(|| anyhow!("invalid XML: bad character reference &{n};"))?
        }
        n => bail!("invalid XML: undefined entity &{n};"),
    })
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Escapes text for an element or a double-quoted attribute that firma writes.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    escape_attr(s, &mut out);
    out.replace('>', "&gt;")
}

/// Non-ASCII characters as character references, so that inserted markup reads the same
/// whatever the document's declared encoding.
pub fn ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            out.push_str(&format!("&#x{:X};", c as u32));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str) -> String {
        canonicalize(xml, Mode::Inclusive).unwrap().text
    }

    fn exc(xml: &str) -> String {
        canonicalize(xml, Mode::Exclusive).unwrap().text
    }

    #[test]
    fn spec_example_3_2_whitespace() {
        // C14N 1.0 spec, example 3.2 (no DTD).
        let doc = "<doc>\r\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
        let expected = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
        assert_eq!(c14n(doc), expected);
    }

    #[test]
    fn spec_example_3_1_pis_and_comments() {
        let doc = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->";
        let expected = "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>";
        assert_eq!(c14n(doc), expected);
    }

    #[test]
    fn attributes_namespaces_and_escapes() {
        let doc = r#"<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm" xmlns:b="http://www.ietf.org" xmlns:a="http://www.w3.org" xmlns="http://example.org"><e6 xmlns="" xmlns:a="http://www.w3.org"><e7 xmlns="http://www.ietf.org"><e8 xmlns="" xmlns:a="http://www.w3.org"><e9 xmlns="" xmlns:a="http://www.ietf.org"/></e8></e7></e6></e5>"#;
        let expected = r#"<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"><e6 xmlns=""><e7 xmlns="http://www.ietf.org"><e8 xmlns=""><e9 xmlns:a="http://www.ietf.org"></e9></e8></e7></e6></e5>"#;
        assert_eq!(c14n(doc), expected);
        assert_eq!(c14n("<a b=\"x&#9;y\r\nz &amp; &lt;\">&#13;&gt;<![CDATA[<&>]]></a>"), "<a b=\"x&#x9;y z &amp; &lt;\">&#xD;&gt;&lt;&amp;&gt;</a>");
    }

    #[test]
    fn exclusive_renders_only_used_namespaces() {
        let doc = r#"<r xmlns="urn:d" xmlns:a="urn:a" xmlns:b="urn:b"><a:x b:y="1"><z/></a:x></r>"#;
        assert_eq!(exc(doc), r#"<r xmlns="urn:d"><a:x xmlns:a="urn:a" xmlns:b="urn:b" b:y="1"><z></z></a:x></r>"#);
        assert_eq!(exc(r#"<a:x xmlns:a="urn:a"><a:y xmlns:a="urn:a"><b xmlns=""/></a:y></a:x>"#), r#"<a:x xmlns:a="urn:a"><a:y><b></b></a:y></a:x>"#);
    }

    #[test]
    fn rejects_dtds_and_unknown_entities() {
        assert!(canonicalize("<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>", Mode::Inclusive).is_err());
        assert!(canonicalize("<a>&x;</a>", Mode::Inclusive).is_err());
        assert!(canonicalize("<a><b></a>", Mode::Inclusive).is_err());
        assert!(canonicalize("<p:a/>", Mode::Inclusive).is_err());
    }

    #[test]
    fn finds_root_end() {
        let doc = "<?xml version=\"1.0\"?>\n<r xmlns=\"urn:x\"><a/></r>\n";
        let c = canonicalize(doc, Mode::Inclusive).unwrap();
        assert_eq!(c.root, ("r".to_string(), "urn:x".to_string()));
        assert_eq!(&doc[c.root_end.unwrap()..], "</r>\n");
    }
}
