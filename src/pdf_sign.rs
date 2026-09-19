//! PDF digital signatures (adbe.pkcs7.detached).
//!
//! Signing appends an incremental update to the file: the original bytes
//! stay untouched, a new signature-field object chain is added (catalog
//! copy with `/AcroForm`, page copy with `/Annots`, the field with its
//! `/V` signature dictionary), and a CMS SignedData — produced by the same
//! crypto path as `.p7s` files, GOST engine included — is spliced into the
//! `/Contents` hex placeholder over the `/ByteRange`.

use crate::crypto::{self, SignatureKind};
use lopdf::{Dictionary, Document, IncrementalDocument, Object, ObjectId};
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::{X509, X509Ref};
use std::fmt::Write as _;

/// Where and what to draw as the visible signature stamp.
pub struct StampOpts {
    /// 1-based page number.
    pub page: u32,
    /// Bottom-left corner of the stamp, PDF points (y from the bottom).
    pub x: f64,
    pub y: f64,
    /// Stamp width in points; the height follows the rendered plate.
    pub width: f64,
    /// Plate lines: signer CN, signing date/time, title (position),
    /// organization — the title/org lines are skipped when the certificate
    /// has no such attribute — and the continuous certificate fingerprint.
    pub signer: String,
    pub datetime: String,
    pub organization: String,
    pub title: String,
    pub fingerprint: String,
}

/// Sign a PDF in place (incremental update). `stamp` draws a visible
/// signature plate; without it the signature is still valid, just
/// invisible. Returns the new file bytes — the input always prefixes them.
pub fn sign_pdf(
    bytes: &[u8],
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    chain: &[X509],
    stamp: Option<&StampOpts>,
) -> Result<Vec<u8>, String> {
    let doc = Document::load_mem(bytes).map_err(|e| format!("Not a PDF file: {e}"))?;
    if doc.is_encrypted() {
        return Err(crate::tr!("The PDF is password-protected; signing is not supported."));
    }

    // The CMS size does not depend on the data (only its digest travels in
    // the signed attributes), so a dry run over a dummy digest sizes the
    // /Contents placeholder. The margin covers chain differences between
    // runs.
    let dry = crypto::sign_file(cert, key, &[0u8; 32], SignatureKind::Detached, chain)?;
    let placeholder_len = dry.len() + 64;

    let catalog_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| "PDF has no document catalog".to_string())?;
    let pages = doc.get_pages();
    let n_pages = pages.len().max(1) as u32;
    let page_no = stamp.map_or(1, |s| s.page.clamp(1, n_pages));
    let page_id = *pages
        .get(&page_no)
        .ok_or("PDF has no pages".to_string())?;

    let mut inc = IncrementalDocument::create_from(bytes.to_vec(), doc);
    inc.opt_clone_object_to_new_document(catalog_id)
        .map_err(|e| e.to_string())?;
    inc.opt_clone_object_to_new_document(page_id)
        .map_err(|e| e.to_string())?;

    let field_id = build_field(&mut inc, cert, page_id, stamp, placeholder_len)?;
    update_catalog(&mut inc, catalog_id, field_id)?;
    update_page_annots(&mut inc, page_id, field_id)?;

    let mut out = Vec::new();
    inc.save_to(&mut out).map_err(|e| e.to_string())?;
    splice_signature(&mut out, cert, key, chain, placeholder_len)?;
    Ok(out)
}

/// Create the signature field (+ appearance objects) and return its id.
fn build_field(
    inc: &mut IncrementalDocument,
    cert: &X509Ref,
    page_id: ObjectId,
    stamp: Option<&StampOpts>,
    placeholder_len: usize,
) -> Result<ObjectId, String> {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    if let Some(cn) = crate::crypto::name_cn(cert.subject_name()) {
        sig.set("Name", Object::String(cn.into_bytes(), lopdf::StringFormat::Literal));
    }
    sig.set("M", Object::String(pdf_date_now().into_bytes(), lopdf::StringFormat::Literal));
    // Fixed-width dummy values: after saving, the real offsets are patched
    // into the same character width, so nothing after the array shifts.
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BR_DUMMY),
            Object::Integer(BR_DUMMY),
            Object::Integer(BR_DUMMY),
        ]),
    );
    sig.set(
        "Contents",
        Object::String(
            vec![0u8; placeholder_len],
            lopdf::StringFormat::Hexadecimal,
        ),
    );

    let mut field = Dictionary::new();
    field.set("FT", Object::Name(b"Sig".to_vec()));
    field.set("T", Object::String(b"Signature".to_vec(), lopdf::StringFormat::Literal));
    field.set("V", Object::Dictionary(sig));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("F", Object::Integer(132)); // print + locked
    field.set("P", Object::Reference(page_id));
    match stamp {
        Some(s) => {
            let (rect, ap) = build_appearance(inc, s)?;
            field.set(
                "Rect",
                Object::Array(
                    rect.iter()
                        .map(|v| Object::Real((v * 1000.0).round() as f32 / 1000.0))
                        .collect(),
                ),
            );
            field.set("AP", ap);
        }
        None => {
            field.set(
                "Rect",
                Object::Array((0..4).map(|_| Object::Integer(0)).collect()),
            );
        }
    }
    Ok(inc.new_document.add_object(Object::Dictionary(field)))
}

/// Catalog copy gets `/AcroForm` (or the existing one gains this field).
fn update_catalog(
    inc: &mut IncrementalDocument,
    catalog_id: ObjectId,
    field_id: ObjectId,
) -> Result<(), String> {
    // What /AcroForm looks like in the catalog copy: indirect, inline, or
    // absent. Read in one short borrow, mutate in the next.
    let existing = {
        let new_doc = &mut inc.new_document;
        let catalog = new_doc
            .get_object_mut(catalog_id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| e.to_string())?;
        match catalog.get(b"AcroForm") {
            Ok(Object::Reference(id)) => Some(*id),
            Ok(Object::Dictionary(d)) => Some({
                // Materialize the inline dictionary as its own object so
                // the new definition wins over the old one.
                let mut d = d.clone();
                d.set("SigFlags", Object::Integer(3));
                if !d.has(b"Fields") {
                    d.set("Fields", Object::Array(vec![]));
                }
                new_doc.add_object(Object::Dictionary(d))
            }),
            _ => None,
        }
    };

    let acro_id = match existing {
        Some(id) => id,
        None => {
            let mut acro = Dictionary::new();
            acro.set("SigFlags", Object::Integer(3));
            acro.set("Fields", Object::Array(vec![]));
            let id = inc.new_document.add_object(Object::Dictionary(acro));
            let new_doc = &mut inc.new_document;
            let catalog = new_doc
                .get_object_mut(catalog_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| e.to_string())?;
            catalog.set("AcroForm", Object::Reference(id));
            id
        }
    };
    if let Some(id) = existing {
        // The reference case: bring the dictionary into the update so its
        // /Fields can grow.
        inc.opt_clone_object_to_new_document(id)
            .map_err(|e| e.to_string())?;
        let d = inc
            .new_document
            .get_object_mut(id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| e.to_string())?;
        d.set("SigFlags", Object::Integer(3));
    }

    // Append the field to /Fields (inline array or indirect).
    let fields_ref = inc
        .new_document
        .get_object_mut(acro_id)
        .ok()
        .and_then(|o| o.as_dict().ok())
        .and_then(|d| d.get(b"Fields").ok().cloned());
    match fields_ref {
        Some(Object::Reference(fid)) => {
            inc.opt_clone_object_to_new_document(fid)
                .map_err(|e| e.to_string())?;
            if let Ok(a) = inc
                .new_document
                .get_object_mut(fid)
                .and_then(Object::as_array_mut)
            {
                a.push(Object::Reference(field_id));
            }
        }
        _ => {
            if let Ok(a) = inc
                .new_document
                .get_object_mut(acro_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| e.to_string())?
                .get_mut(b"Fields")
                .and_then(Object::as_array_mut)
            {
                a.push(Object::Reference(field_id));
            }
        }
    }
    Ok(())
}

/// Page copy gains the field widget in `/Annots`.
fn update_page_annots(
    inc: &mut IncrementalDocument,
    page_id: ObjectId,
    field_id: ObjectId,
) -> Result<(), String> {
    let existing = {
        let new_doc = &mut inc.new_document;
        let page = new_doc
            .get_object_mut(page_id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| e.to_string())?;
        match page.get(b"Annots") {
            Ok(Object::Array(_)) => 0,      // inline
            Ok(Object::Reference(_)) => 1, // indirect; the id is re-read below
            Err(_) => 2,                    // missing
            _ => 3,                         // unexpected type
        }
    };
    match existing {
        0 => {
            if let Ok(a) = inc
                .new_document
                .get_object_mut(page_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| e.to_string())?
                .get_mut(b"Annots")
                .and_then(Object::as_array_mut)
            {
                a.push(Object::Reference(field_id));
                return Ok(());
            }
            Err("Unexpected /Annots in the page".to_string())
        }
        1 => {
            let id = inc
                .new_document
                .get_object_mut(page_id)
                .ok()
                .and_then(|o| o.as_dict().ok())
                .and_then(|d| match d.get(b"Annots") {
                    Ok(Object::Reference(id)) => Some(*id),
                    _ => None,
                })
                .ok_or("Unexpected /Annots in the page")?;
            inc.opt_clone_object_to_new_document(id)
                .map_err(|e| e.to_string())?;
            if let Ok(a) = inc
                .new_document
                .get_object_mut(id)
                .and_then(Object::as_array_mut)
            {
                a.push(Object::Reference(field_id));
                return Ok(());
            }
            Err("Unexpected /Annots in the page".to_string())
        }
        2 => {
            let new_doc = &mut inc.new_document;
            let page = new_doc
                .get_object_mut(page_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| e.to_string())?;
            page.set(
                "Annots",
                Object::Array(vec![Object::Reference(field_id)]),
            );
            Ok(())
        }
        _ => Err("Unexpected /Annots in the page".to_string()),
    }
}

/// Dummy ByteRange value; also the field width used when patching in the
/// real offsets.
const BR_DUMMY: i64 = 9_999_999_999;

/// Patch `/ByteRange` with the real offsets, hash the covered ranges,
/// sign, and splice the DER into the `/Contents` placeholder.
fn splice_signature(
    out: &mut [u8],
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    chain: &[X509],
    placeholder_len: usize,
) -> Result<(), String> {
    let total = out.len();
    if total as i64 >= BR_DUMMY {
        return Err("PDF is too large to sign".to_string());
    }

    // Locate the ByteRange dummy — fixed-width numbers keep the patch
    // length-neutral.
    let br_pattern = format!("/ByteRange[0 {BR_DUMMY} {BR_DUMMY} {BR_DUMMY}]");
    let br_at = find_unique(out, br_pattern.as_bytes())?;
    let nums_at = br_at + b"/ByteRange[0 ".len();

    // Locate the /Contents hex placeholder: <000...0>.
    let mut ph = vec![b'<'];
    ph.extend(std::iter::repeat_n(b'0', placeholder_len * 2));
    ph.push(b'>');
    let ph_at = find_unique(out, &ph)?;
    let s = ph_at + 1;
    let e = s + placeholder_len * 2;

    // [0, s, e, total - e], written space-padded to the dummy width.
    let width = BR_DUMMY.to_string().len();
    for (i, v) in [s as i64, e as i64, (total - e) as i64].into_iter().enumerate() {
        let tok = format!("{v:>width$}");
        let at = nums_at + i * (width + 1);
        out[at..at + width].copy_from_slice(tok.as_bytes());
    }

    // CMS over everything except the placeholder.
    let mut data = Vec::with_capacity(total - placeholder_len * 2);
    data.extend_from_slice(&out[..s]);
    data.extend_from_slice(&out[e..]);
    let der = crypto::sign_file(cert, key, &data, SignatureKind::Detached, chain)?;
    if der.len() > placeholder_len {
        return Err("Signature does not fit the reserved space".to_string());
    }
    let mut hex = String::with_capacity(placeholder_len * 2);
    for b in &der {
        let _ = write!(hex, "{b:02X}");
    }
    for _ in der.len()..placeholder_len {
        hex.push_str("00");
    }
    out[s..e].copy_from_slice(hex.as_bytes());
    Ok(())
}

fn find_unique(haystack: &[u8], needle: &[u8]) -> Result<usize, String> {
    let mut at = None;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            if at.is_some() {
                return Err("signature placeholder is not unique".to_string());
            }
            at = Some(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    at.ok_or_else(|| "signature placeholder not found".to_string())
}

/// PDF date string `D:YYYYMMDDHHMMSS+HH'MM'` in the local timezone.
fn pdf_date_now() -> String {
    let dt = gtk::glib::DateTime::now_local()
        .or_else(|_| gtk::glib::DateTime::now_utc())
        .expect("glib datetime");
    let tz = dt.format("%z").unwrap_or_default(); // +0300
    let tz = if tz.len() >= 5 { tz.to_string() } else { "+0000".into() };
    format!(
        "D:{}{sign}{hh}'{mm}'",
        dt.format("%Y%m%d%H%M%S").unwrap_or_default(),
        sign = tz.chars().next().unwrap_or('+'),
        hh = &tz[1..3],
        mm = &tz[3..5],
    )
}

// ---- extraction (verification) ----

/// One embedded PDF signature, ready for CMS verification.
pub struct PdfSignature {
    pub cms: Vec<u8>,
    /// The exact bytes the signature covers.
    pub data: Vec<u8>,
    /// Bytes after the covered range: another signature (a later
    /// incremental revision) or foreign modifications.
    pub trailing: usize,
    pub date: Option<String>,
}

/// All signature fields of the document, in `/Fields` order.
pub fn extract_pdf_signatures(bytes: &[u8]) -> Vec<PdfSignature> {
    let mut out = Vec::new();
    let Ok(doc) = Document::load_mem(bytes) else {
        return out;
    };
    let catalog = match doc.catalog() {
        Ok(c) => c.clone(),
        Err(_) => return out,
    };
    let acro = match catalog.get(b"AcroForm") {
        Ok(o) => doc
            .dereference(o)
            .ok()
            .and_then(|(_, o)| o.as_dict().ok().cloned()),
        Err(_) => None,
    };
    let Some(acro) = acro else { return out };
    let Ok(fields) = acro.get(b"Fields").and_then(Object::as_array) else {
        return out;
    };
    for f in fields {
        let Ok((_, obj)) = doc.dereference(f) else { continue };
        let Ok(dict) = obj.as_dict() else { continue };
    let ft_is_sig = dict
            .get(b"FT")
            .and_then(Object::as_name)
            .is_ok_and(|n| n == b"Sig");
        if !ft_is_sig {
            continue;
        }
        let Ok(v) = dict.get(b"V").and_then(Object::as_dict) else {
            continue;
        };
        let Some(sig) = signature_from_dict(bytes, v) else { continue };
        out.push(sig);
    }
    out
}

fn signature_from_dict(bytes: &[u8], v: &Dictionary) -> Option<PdfSignature> {
    let br = v
        .get(b"ByteRange")
        .and_then(Object::as_array)
        .ok()?
        .iter()
        .map(|o| match o {
            Object::Integer(i) => Some(*i as usize),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    if br.len() != 4 || br[1] < br[0] || br[3] == 0 || br[2] + br[3] > bytes.len() {
        return None;
    }
    let contents = match v.get(b"Contents").ok()? {
        Object::String(s, _) => s.clone(),
        _ => return None,
    };
    // Producers zero-pad the /Contents after the DER; cut at the end of
    // the first ASN.1 structure.
    let der_len = der_total_len(&contents)?;
    if der_len == 0 || der_len > contents.len() {
        return None;
    }
    let cms = contents[..der_len].to_vec();
    let mut data = Vec::with_capacity(br[1] - br[0] + br[3]);
    data.extend_from_slice(&bytes[br[0]..br[1]]);
    data.extend_from_slice(&bytes[br[2]..br[2] + br[3]]);
    let text = |k: &str| -> Option<String> {
        v.get(k.as_bytes())
            .ok()
            .and_then(|o| match o {
                Object::String(s, _) => Some(String::from_utf8_lossy(s).to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
    };
    Some(PdfSignature {
        cms,
        data,
        trailing: bytes.len() - (br[2] + br[3]),
        date: text("M"),
    })
}

/// Length in bytes of the first DER TLV structure.
fn der_total_len(der: &[u8]) -> Option<usize> {
    if der.is_empty() {
        return None;
    }
    let mut i = 1;
    if der[0] & 0x1f == 0x1f {
        // multi-byte tag
        while i < der.len() && der[i] & 0x80 != 0 {
            i += 1;
        }
        i += 1;
    }
    if i >= der.len() {
        return None;
    }
    let len = match der[i] {
        l if l < 0x80 => {
            return Some(i + 1 + l as usize);
        }
        0x80 => return None, // indefinite — not valid DER
        n => {
            let n = n as usize & 0x7f;
            i += 1;
            if n == 0 || i + n > der.len() {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | der[i] as usize;
                i += 1;
            }
            l
        }
    };
    Some(i + len)
}

// ---- the visible stamp plate (cairo) ----

/// One rendered text line of the stamp.
struct StampLine {
    text: String,
    size: f64,
    bold: bool,
    mono: bool,
    /// Extra gap (points) before this line: small within a group, larger
    /// when a new group (name → date → fingerprint) starts.
    lead_before: f64,
}

/// Wrap `text` into lines no wider than `avail` points: by words, and by
/// characters for words that are too wide on their own.
fn wrap_to_width(cr: &gtk::cairo::Context, avail: f64, text: &str) -> Vec<String> {
    let width = |t: &str| cr.text_extents(t).map(|e| e.x_advance()).unwrap_or(0.0);
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        let candidate = if cur.is_empty() {
            word.to_string()
        } else {
            format!("{cur} {word}")
        };
        if width(&candidate) <= avail {
            cur = candidate;
            continue;
        }
        if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if width(word) <= avail {
            cur = word.to_string();
        } else {
            // A single word wider than the line: break it by characters.
            let mut piece = String::new();
            for ch in word.chars() {
                let grown = format!("{piece}{ch}");
                if !piece.is_empty() && width(&grown) > avail {
                    out.push(std::mem::take(&mut piece));
                }
                piece = format!("{piece}{ch}");
            }
            cur = piece;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// The stamp's text laid out for `s.width`: wrapped lines plus the plate
/// height in points. Single source of truth for rendering and for
/// reserving the widget rectangle.
fn stamp_layout(s: &StampOpts) -> (Vec<StampLine>, f64) {
    use gtk::cairo::{Context, FontSlant, FontWeight, Format, ImageSurface};

    let surface = ImageSurface::create(Format::ARgb32, 1, 1).expect("measure surface");
    let cr = Context::new(&surface).expect("measure context");
    let avail = s.width - 28.0 - 8.0; // text starts after the check circle

    let fp_text = fingerprint_text(&s.fingerprint);
    let mut lines: Vec<StampLine> = Vec::new();
    let groups: [(&str, f64, bool, bool); 5] = [
        (&s.signer, 8.5, true, false),
        (&s.datetime, 7.0, false, false),
        (&s.title, 7.0, false, false),
        (&s.organization, 7.0, false, false),
        (&fp_text, 5.4, false, true),
    ];
    for (gi, (text, size, bold, mono)) in groups.iter().enumerate() {
        if text.trim().is_empty() {
            continue;
        }
        cr.select_font_face(
            if *mono { "monospace" } else { "sans" },
            FontSlant::Normal,
            if *bold { FontWeight::Bold } else { FontWeight::Normal },
        );
        cr.set_font_size(*size);
        for (li, part) in wrap_to_width(&cr, avail, text).into_iter().enumerate() {
            lines.push(StampLine {
                text: part,
                size: *size,
                bold: *bold,
                mono: *mono,
                lead_before: if gi == 0 || li > 0 { 2.2 } else { 4.2 },
            });
        }
    }

    let ascent = |l: &StampLine| l.size * 0.78;
    let descent = |l: &StampLine| l.size * 0.22;
    let mut block = ascent(&lines[0]);
    for w in lines.windows(2) {
        block += descent(&w[0]) + w[1].lead_before + ascent(&w[1]);
    }
    block += descent(lines.last().expect("non-empty"));
    let height = (block + 9.0 + 9.0).max(56.0); // card padding, sane minimum
    (lines, height)
}

/// Plate height for the given stamp options — used to reserve the widget
/// rectangle and to convert a click center into the bottom-left corner.
pub fn stamp_height_pt(s: &StampOpts) -> f64 {
    stamp_layout(s).1
}

/// The stamp plate: white rounded card, accent border, check mark, signer
/// name, date/time and the certificate fingerprint.
fn build_appearance(
    inc: &mut IncrementalDocument,
    s: &StampOpts,
) -> Result<([f64; 4], Dictionary), String> {
    let scale = 2.0; // render at 2x for crisp text
    let (lines, h_pt) = stamp_layout(s);
    let w_px = (s.width * scale).round() as i32;
    let h_px = (h_pt * scale).round() as i32;

    let (rgb, alpha) = render_stamp(w_px, h_px, &lines, h_pt);
    let img_id = add_image(inc, &rgb, &alpha, w_px, h_px)?;

    // Form XObject: draw the image scaled into the stamp rectangle.
    let content = format!("q {w} 0 0 {h} 0 0 cm /Im0 Do Q", w = s.width, h = h_pt);
    let mut ap_dict = Dictionary::new();
    ap_dict.set("XObject", {
        let mut x = Dictionary::new();
        x.set("Im0", Object::Reference(img_id));
        x
    });
    let mut form_dict = Dictionary::new();
    form_dict.set("Type", Object::Name(b"XObject".to_vec()));
    form_dict.set("Subtype", Object::Name(b"Form".to_vec()));
    form_dict.set(
        "BBox",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Real(s.width as f32),
            Object::Real(h_pt as f32),
        ]),
    );
    form_dict.set("Resources", Object::Dictionary(ap_dict));
    let stream = lopdf::Stream::new(form_dict, content.into_bytes());
    let ap_id = inc.new_document.add_object(Object::Stream(stream));

    let mut ap = Dictionary::new();
    ap.set("N", Object::Reference(ap_id));
    let rect = [s.x, s.y, s.x + s.width, s.y + h_pt];
    Ok((rect, ap))
}

/// Render the stamp; returns (RGB rows, alpha rows), row-major,
/// top-down as cairo produced them. The lines come from `stamp_layout`
/// so rendering and the reserved rectangle always agree.
fn render_stamp(
    w_px: i32,
    h_px: i32,
    lines: &[StampLine],
    h_pt: f64,
) -> (Vec<u8>, Vec<u8>) {
    use gtk::cairo::{Context, FontSlant, FontWeight, Format, ImageSurface};

    let mut surface = ImageSurface::create(Format::ARgb32, w_px, h_px)
        .expect("stamp surface");
    let cr = Context::new(&surface).expect("stamp context");
    cr.scale(2.0, 2.0);

    let w = w_px as f64 / 2.0;
    let h = h_px as f64 / 2.0;

    // Card with rounded corners and a soft shadow.
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.12);
    rounded_rect(&cr, 2.2, 3.0, w - 4.4, h - 4.2, 6.0);
    let _ = cr.fill();
    cr.set_source_rgba(1.0, 1.0, 1.0, 0.97);
    rounded_rect(&cr, 1.8, 1.8, w - 3.6, h - 3.6, 5.5);
    let _ = cr.fill();
    cr.set_source_rgba(0.21, 0.52, 0.89, 1.0); // GNOME accent blue
    cr.set_line_width(1.1);
    rounded_rect(&cr, 2.35, 2.35, w - 4.7, h - 4.7, 5.0);
    let _ = cr.stroke();

    // Text block metrics (must mirror stamp_layout).
    let ascent = |l: &StampLine| l.size * 0.78;
    let descent = |l: &StampLine| l.size * 0.22;
    let mut block = ascent(&lines[0]);
    for pair in lines.windows(2) {
        block += descent(&pair[0]) + pair[1].lead_before + ascent(&pair[1]);
    }
    block += descent(lines.last().expect("non-empty"));
    let block_top = (h_pt - block) / 2.0;
    let mut baseline = block_top + ascent(&lines[0]);
    let block_cy = block_top + block / 2.0;

    // Check mark in a circle, aligned to the text block.
    let (cx, r) = (15.0, 7.5);
    cr.set_source_rgba(0.30, 0.69, 0.31, 1.0);
    cr.arc(cx, block_cy, r, 0.0, std::f64::consts::PI * 2.0);
    let _ = cr.fill();
    cr.set_source_rgba(1.0, 1.0, 1.0, 1.0);
    cr.set_line_width(1.7);
    cr.set_line_cap(gtk::cairo::LineCap::Round);
    cr.set_line_join(gtk::cairo::LineJoin::Round);
    cr.move_to(cx - 3.1, block_cy + 0.1);
    cr.line_to(cx - 0.9, block_cy + 2.5);
    cr.line_to(cx + 3.3, block_cy - 2.6);
    let _ = cr.stroke();

    let tx = 28.0;
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            baseline += descent(&lines[i - 1]) + line.lead_before + ascent(line);
        }
        cr.select_font_face(
            if line.mono { "monospace" } else { "sans" },
            FontSlant::Normal,
            if line.bold { FontWeight::Bold } else { FontWeight::Normal },
        );
        cr.set_font_size(line.size);
        if line.mono {
            cr.set_source_rgba(0.42, 0.42, 0.42, 1.0);
        } else {
            cr.set_source_rgba(0.13, 0.13, 0.13, 1.0);
        }
        cr.move_to(tx, baseline);
        let _ = cr.show_text(&line.text);
    }

    surface.flush();
    drop(cr);
    let image = surface.data().expect("stamp pixels").to_vec();
    let stride = surface.stride() as usize;
    // Full pixel dimensions — the drawing context was scaled 2x, so the
    // surface holds w_px × h_px samples, not the point-sized halves.
    split_argb(&image, stride, w_px as usize, h_px as usize)
}

/// Split cairo premultiplied ARGB32 rows into straight RGB + gray alpha,
/// both top-down row-major without stride padding.
fn split_argb(argb: &[u8], stride: usize, w: usize, h: usize) -> (Vec<u8>, Vec<u8>) {
    let mut rgb = Vec::with_capacity(w * h * 3);
    let mut alpha = Vec::with_capacity(w * h);
    for row in 0..h {
        for col in 0..w {
            let px = &argb[row * stride + col * 4..row * stride + col * 4 + 4];
            let (b, g, r, a) = (px[0], px[1], px[2], px[3]);
            let a = a as u16;
            let un = |c: u8| match a {
                0 => 255u8,
                _ => (c as u16 * 255 / a).min(255) as u8,
            };
            rgb.push(un(r));
            rgb.push(un(g));
            rgb.push(un(b));
            alpha.push(a as u8);
        }
    }
    (rgb, alpha)
}

fn rounded_rect(
    cr: &gtk::cairo::Context,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    r: f64,
) {
    cr.new_sub_path();
    cr.arc(x + w - r, y + r, r, -std::f64::consts::FRAC_PI_2, 0.0);
    cr.arc(x + w - r, y + h - r, r, 0.0, std::f64::consts::FRAC_PI_2);
    cr.arc(x + r, y + h - r, r, std::f64::consts::FRAC_PI_2, std::f64::consts::PI);
    cr.arc(x + r, y + r, r, std::f64::consts::PI, std::f64::consts::FRAC_PI_2 * 3.0);
    cr.close_path();
}

/// "aa bb cc…" → one continuous uppercase hex string, no separators.
fn fingerprint_text(fp: &str) -> String {
    fp.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Embedded image XObject (+SMask), FlateDecode-compressed.
fn add_image(
    inc: &mut IncrementalDocument,
    rgb: &[u8],
    alpha: &[u8],
    w: i32,
    h: i32,
) -> Result<ObjectId, String> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    let zlib = |data: &[u8]| -> Result<Vec<u8>, String> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).map_err(|e| e.to_string())?;
        enc.finish().map_err(|e| e.to_string())
    };

    let mut smask_dict = Dictionary::new();
    smask_dict.set("Type", Object::Name(b"XObject".to_vec()));
    smask_dict.set("Subtype", Object::Name(b"Image".to_vec()));
    smask_dict.set("Width", Object::Integer(w as i64));
    smask_dict.set("Height", Object::Integer(h as i64));
    smask_dict.set("ColorSpace", Object::Name(b"DeviceGray".to_vec()));
    smask_dict.set("BitsPerComponent", Object::Integer(8));
    smask_dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
    let smask = lopdf::Stream::new(smask_dict, zlib(alpha)?);
    let smask_id = inc.new_document.add_object(Object::Stream(smask));

    let mut img_dict = Dictionary::new();
    img_dict.set("Type", Object::Name(b"XObject".to_vec()));
    img_dict.set("Subtype", Object::Name(b"Image".to_vec()));
    img_dict.set("Width", Object::Integer(w as i64));
    img_dict.set("Height", Object::Integer(h as i64));
    img_dict.set("ColorSpace", Object::Name(b"DeviceRGB".to_vec()));
    img_dict.set("BitsPerComponent", Object::Integer(8));
    img_dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
    img_dict.set("SMask", Object::Reference(smask_id));
    let img = lopdf::Stream::new(img_dict, zlib(rgb)?);
    Ok(inc.new_document.add_object(Object::Stream(img)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        self, CertParams, NewKeyKind, SubjectData, VerifyOutcome,
    };

    fn subject(cn: &str) -> SubjectData {
        SubjectData {
            cn: cn.into(),
            ..Default::default()
        }
    }

    /// A minimal one-page PDF, built by hand so the test does not depend
    /// on the lopdf creator API.
    pub(crate) fn fixture_pdf() -> Vec<u8> {
        let objects: Vec<String> = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".into(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R /Resources << >> >>".into(),
            format!(
                "<< /Length {} >>\nstream\n{}\nendstream",
                32, "0 0 1 rg 10 10 280 180 re S      "
            ),
        ];
        let mut out = String::from("%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (i, body) in objects.iter().enumerate() {
            offsets.push(out.len());
            let _ = write!(out, "{} 0 obj\n{}\nendobj\n", i + 1, body);
        }
        let xref_at = out.len();
        let _ = write!(out, "xref\n0 {}\n", objects.len() + 1);
        let _ = writeln!(out, "0000000000 65535 f ");
        for off in &offsets {
            let _ = writeln!(out, "{off:010} 00000 n ");
        }
        let _ = write!(
            out,
            "trailer << /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        );
        out.into_bytes()
    }

    pub(crate) fn self_signed(
        cn: &str,
    ) -> (openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        let key = crypto::generate_key(NewKeyKind::Rsa2048).unwrap();
        let cert = crypto::build_certificate(
            &subject(cn).build_name().unwrap(),
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 365,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();
        (cert, key)
    }

    #[test]
    fn sign_extract_verify_roundtrip() {
        let (cert, key) = self_signed("PDF Signer");
        let signed = sign_pdf(&fixture_pdf(), cert.as_ref(), key.as_ref(), &[], None).unwrap();

        // Incremental: the original bytes are the prefix.
        assert!(signed.starts_with(&fixture_pdf()));

        let sigs = extract_pdf_signatures(&signed);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].trailing, 0);
        let report =
            crypto::verify_signature_detailed(&sigs[0].cms, Some(&sigs[0].data), std::slice::from_ref(&cert));
        assert_eq!(report.outcome, VerifyOutcome::Trusted);
        assert_eq!(report.signers.len(), 1);

        // A flipped byte inside the signed page content (kept inside the
        // content stream so the file still parses) must invalidate.
        let mut tampered = signed.clone();
        let at = fixture_pdf()
            .windows(5)
            .position(|w| w == b" re S")
            .expect("stream marker");
        tampered[at] ^= 1;
        let sigs2 = extract_pdf_signatures(&tampered);
        assert_eq!(sigs2.len(), 1);
        let report = crypto::verify_signature_detailed(
            &sigs2[0].cms,
            Some(&sigs2[0].data),
            [cert.clone()].as_slice(),
        );
        assert_eq!(report.outcome, VerifyOutcome::Invalid);
    }

    #[test]
    fn double_signature_keeps_both() {
        let (cert1, key1) = self_signed("First");
        let (cert2, key2) = self_signed("Second");
        let once = sign_pdf(&fixture_pdf(), cert1.as_ref(), key1.as_ref(), &[], None).unwrap();
        let twice = sign_pdf(&once, cert2.as_ref(), key2.as_ref(), &[], None).unwrap();
        assert!(twice.starts_with(&once));

        let sigs = extract_pdf_signatures(&twice);
        assert_eq!(sigs.len(), 2);
        // The first signature covers a strict prefix; the second — the
        // whole previous revision.
        assert!(sigs[0].trailing > 0);
        assert_eq!(sigs[1].trailing, 0);
        for (sig, cert) in [&sigs[0], &sigs[1]].into_iter().zip([&cert1, &cert2]) {
            let report =
                crypto::verify_signature_detailed(&sig.cms, Some(&sig.data), [cert.to_owned()].as_slice());
            assert_eq!(report.outcome, VerifyOutcome::Trusted);
        }
    }

    #[test]
    fn visible_stamp_signs_and_verifies() {
        let (cert, key) = self_signed("Stamp Signer");
        let fp = "1a2b3c4d5e6f".repeat(8);
        let signed = sign_pdf(
            &fixture_pdf(),
            cert.as_ref(),
            key.as_ref(),
            &[],
            Some(&StampOpts {
                page: 1,
                x: 40.0,
                y: 120.0,
                width: 200.0,
                signer: "Stamp Signer".into(),
                datetime: "19.09.2026 21:00".into(),
                organization: "МУ «Межотраслевая централизованная бухгалтерия»".into(),
                title: "Ведущий инженер-программист".into(),
                fingerprint: fp,
            }),
        )
        .unwrap();
        let sigs = extract_pdf_signatures(&signed);
        assert_eq!(sigs.len(), 1);
        let report =
            crypto::verify_signature_detailed(&sigs[0].cms, Some(&sigs[0].data), &[cert]);
        assert_eq!(report.outcome, VerifyOutcome::Trusted);
    }

    #[test]
    fn stamp_wraps_long_names() {
        let mk = |signer: &str| StampOpts {
            page: 1,
            x: 0.0,
            y: 0.0,
            width: 210.0,
            signer: signer.into(),
            datetime: "19.09.2026 21:00".into(),
            organization: String::new(),
            title: String::new(),
            fingerprint: "1a2b3c4d".repeat(8),
        };
        let (short, h_short) = stamp_layout(&mk("Денис Егоров"));
        let phrase = "Богданов Алексей Викторович, заместитель генерального директора";
        let (long, h_long) = stamp_layout(&mk(&format!("{phrase} · {phrase}")));
        assert_eq!(
            short.iter().filter(|l| l.bold).count(),
            1,
            "a short name fits one line"
        );
        assert!(
            long.iter().filter(|l| l.bold).count() >= 2,
            "a long name wraps"
        );
        assert!(h_long > h_short);
        assert!(h_short >= 56.0);
    }

    /// The image XObject data must match its declared dimensions exactly —
    /// a mismatch makes viewers stretch a partial bitmap over the whole
    /// stamp (doubled, cut, stretched).
    #[test]
    fn stamp_image_streams_match_dimensions() {
        let (cert, key) = self_signed("Stamp Pixels");
        let signed = sign_pdf(
            &fixture_pdf(),
            cert.as_ref(),
            key.as_ref(),
            &[],
            Some(&StampOpts {
                page: 1,
                x: 40.0,
                y: 120.0,
                width: 210.0,
                signer: "Stamp Pixels".into(),
                datetime: "19.09.2026 21:00".into(),
                organization: String::new(),
                title: String::new(),
                fingerprint: "ab".repeat(32),
            }),
        )
        .unwrap();
        let doc = Document::load_mem(&signed).unwrap();
        let mut checked = 0;
        for obj in doc.objects.values() {
            let Object::Stream(st) = obj else { continue };
            let dict = &st.dict;
            let is_image = dict
                .get(b"Subtype")
                .and_then(Object::as_name)
                .map(|n| n == b"Image")
                .unwrap_or(false);
            if !is_image {
                continue;
            }
            let w = dict.get(b"Width").and_then(Object::as_i64).unwrap() as usize;
            let h = dict.get(b"Height").and_then(Object::as_i64).unwrap() as usize;
            let gray = dict
                .get(b"ColorSpace")
                .and_then(Object::as_name)
                .map(|n| n == b"DeviceGray")
                .unwrap_or(false);
            let per = if gray { 1 } else { 3 };
            let content = st.decompressed_content().unwrap();
            assert_eq!(
                content.len(),
                w * h * per,
                "{w}x{h} {} stream",
                if gray { "smask" } else { "rgb" }
            );
            checked += 1;
        }
        assert_eq!(checked, 2, "one RGB image + one SMask");
    }

    #[test]
    fn stamp_lines_follow_org_and_title() {
        let mk = |org: &str, title: &str| StampOpts {
            page: 1,
            x: 0.0,
            y: 0.0,
            width: 210.0,
            signer: "Егоров Денис Витальевич".into(),
            datetime: "19.09.2026 21:00".into(),
            organization: org.into(),
            title: title.into(),
            fingerprint: "ab".repeat(32),
        };
        let (full, _) = stamp_layout(&mk("Организация", "Ведущий инженер"));
        let (bare, h_bare) = stamp_layout(&mk("", ""));
        // Bold CN line in both; org/title lines only when present.
        assert_eq!(full.iter().filter(|l| l.bold).count(), 1);
        assert!(full.iter().any(|l| l.text == "Организация"));
        assert!(full.iter().any(|l| l.text == "Ведущий инженер"));
        assert!(!bare.iter().any(|l| l.text.is_empty()));
        assert!(full.len() > bare.len(), "org/title add lines");
        assert!(h_bare >= 56.0);
        // The fingerprint is continuous — no spaces inside its lines.
        for l in full.iter().filter(|l| l.mono) {
            assert!(!l.text.contains(' '), "fingerprint stays continuous");
            assert!(!l.text.is_empty());
        }
    }

    #[test]
    fn der_length_helper() {
        assert_eq!(der_total_len(&[0x30, 0x03, 0x02, 0x01, 0x01, 0x00]), Some(5));
        // long form
        let mut v = vec![0x30, 0x82, 0x01, 0x00];
        v.extend(std::iter::repeat_n(0u8, 0x100));
        assert_eq!(der_total_len(&v), Some(4 + 0x100));
        assert_eq!(der_total_len(&[]), None);
    }
}

#[cfg(test)]
mod manual {
    use super::tests::{fixture_pdf, self_signed};
    use super::*;

    /// Writes /tmp/xca-signed-sample.pdf — run with
    /// `cargo test -- --ignored dump_sample` and inspect with `pdfsig`.
    #[test]
    #[ignore]
    fn dump_sample() {
        let (cert, key) = self_signed("Sample Signer");
        let mut pdf = fixture_pdf();
        // Grow the page so the stamp sits on a realistic A4 sheet.
        for (from, to) in [(
            b"/MediaBox [0 0 300 200]".as_slice(),
            b"/MediaBox [0 0 595 842]".as_slice(),
        )] {
            if let Some(at) = pdf.windows(from.len()).position(|w| w == from) {
                pdf.splice(at..at + from.len(), to.to_vec());
            }
        }
        let signed = sign_pdf(
            &pdf,
            cert.as_ref(),
            key.as_ref(),
            &[],
            Some(&StampOpts {
                page: 1,
                x: 340.0,
                y: 60.0,
                width: 210.0,
                signer: "Богданов Алексей Викторович, заместитель генерального директора".into(),
                datetime: "19.09.2026 21:00".into(),
                organization: "МУНИЦИПАЛЬНОЕ УЧРЕЖДЕНИЕ \"МЕЖОТРАСЛЕВАЯ ЦЕНТРАЛИЗОВАННАЯ БУХГАЛТЕРИЯ\"".into(),
                title: "Ведущий инженер-программист".into(),
                fingerprint: "a1b2c3d4e5f60718".repeat(4),
            }),
        )
        .unwrap();
        std::fs::write("/tmp/xca-signed-sample.pdf", signed).unwrap();
        eprintln!("written /tmp/xca-signed-sample.pdf");
    }
}
