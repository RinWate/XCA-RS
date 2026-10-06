//! "Signatures" section: sign arbitrary files with a certificate from
//! the database — CMS detached (`.p7s`) and attached (`.p7m`) signatures,
//! embedded PDF signatures with a visible stamp — and verify them back.

use super::pdf_place::{self, Placement};
use super::{action_row, combo, error_dialog, form_dialog, switch};
use crate::app::App;
use crate::crypto::{self, SignatureKind};
use crate::pdf_sign::{self, StampOpts, STAMP_W};
use crate::tr;
use gtk::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

type PickCallback = Option<Box<dyn Fn(&std::path::Path)>>;

/// A row with a "Choose…" button that opens a file dialog and remembers
/// the picked path (shown as the subtitle); `on_pick` fires after a file
/// is chosen (used to adapt the dialog for PDFs).
fn file_row(
    parent: &adw::ApplicationWindow,
    title: &str,
    on_pick: PickCallback,
) -> (adw::ActionRow, Rc<RefCell<Option<PathBuf>>>) {
    let row = action_row(title, "");
    let path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    type PickShared = Option<Rc<dyn Fn(&std::path::Path)>>;
    let on_pick: PickShared = on_pick.map(Rc::from);
    let btn = gtk::Button::with_label(&tr!("Choose…"));
    btn.add_css_class("flat");
    btn.set_valign(gtk::Align::Center);
    {
        let row = row.clone();
        let path = path.clone();
        let on_pick = on_pick.clone();
        let parent = parent.clone();
        btn.connect_clicked(move |_| {
            let fd = gtk::FileDialog::builder().title(tr!("Choose a File")).build();
            let row = row.clone();
            let path = path.clone();
            let on_pick = on_pick.clone();
            fd.open(Some(&parent), None::<&gtk::gio::Cancellable>, move |res| {
                if let Ok(file) = res
                    && let Some(p) = file.path()
                {
                    row.set_subtitle(&p.to_string_lossy());
                    *path.borrow_mut() = Some(p.clone());
                    if let Some(rc) = on_pick.as_ref() {
                        let cb: &dyn Fn(&std::path::Path) = rc.as_ref();
                        cb(&p);
                    }
                }
            });
        });
    }
    row.add_suffix(&btn);
    (row, path)
}

fn is_pdf_path(p: &std::path::Path) -> bool {
    p.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

/// `Signature Type` combo indexes for PDFs — the same order the items are
/// declared in; every reader goes through these constants.
const PDF_KIND_ATTACHED: u32 = 0;
const PDF_KIND_DETACHED: u32 = 1;

/// `Detached signature file type` combo indexes → signature extensions.
const PDF_SIG_EXTS: [&str; 3] = ["sgn", "p7s", "sig"];

/// `Signature Profile` combo indexes.
const PDF_PROFILE_CADES: u32 = 0;
const PDF_PROFILE_PKCS7: u32 = 1;

/// The bold first line of the stamp plate: the subject CN. Legal-entity
/// certificates (УФК, вузы, администрации…) routinely carry CN identical
/// to O — printing both puts the same long organization string on the
/// plate twice — so when CN duplicates O the line is left EMPTY (the
/// renderer skips it; the full-DN fallback must NOT kick in here, or the
/// header swallows the whole subject). The DN stays the fallback only
/// for subjects with no CN at all.
fn stamp_header(subj: &openssl::x509::X509NameRef, org: &str) -> String {
    let cn = crypto::name_cn(subj).unwrap_or_default();
    if cn.trim().is_empty() {
        crypto::name_to_string(subj)
    } else if cn.trim() == org.trim() {
        String::new()
    } else {
        cn
    }
}

/// A fresh `<stem> подписано` folder next to the source file, suffixed
/// `(2)`, `(3)`… while the name is taken.
fn unique_signed_folder(parent: &std::path::Path, stem: &str) -> PathBuf {

    let mut folder = parent.join(format!("{} {}", stem, tr!("signed")));
    let mut attempt = 2u32;
    while folder.exists() {
        folder = parent.join(format!("{} {} ({attempt})", stem, tr!("signed")));
        attempt += 1;
    }
    folder
}

pub fn open_sign(app: &App) {
    let certs = app.db.lock().unwrap().list_certs().unwrap_or_default();
    let certs: Vec<(i64, String)> = certs
        .iter()
        .filter(|c| c.key_id.is_some())
        .map(|c| {
            // Only the internal name and the Organization field: full
            // subject DNs made the dropdown unreadable.
            let o = crypto::load_cert(&c.pem)
                .ok()
                .and_then(|x| crypto::name_o(x.subject_name()))
                .filter(|o| !o.is_empty());
            let label = match o {
                Some(o) => format!("{} — {}", c.name, o),
                None => c.name.clone(),
            };
            (c.id, label)
        })
        .collect();
    if certs.is_empty() {
        return error_dialog(
            &app.window,
            &tr!("Signing requires a certificate with its private key in the database."),
        );
    }
    let labels: Vec<&str> = certs.iter().map(|(_, l)| l.as_str()).collect();
    let cert_ids: Vec<Option<i64>> = certs.iter().map(|(id, _)| Some(*id)).collect();

    let form = form_dialog(&tr!("Sign File"), 560);
    let cert_row = combo(&tr!("Certificate"), &labels, 0);
    let g = form.group(&tr!("Signer"));
    g.add(&cert_row);

    // Groups first (visual order), widgets right after — the file-picker
    // callback below captures them all.
    let g2 = form.group(&tr!("File"));
    let g_pdf = form.group(&tr!("PDF"));
    let g3 = form.group(&tr!("Signature"));

    // PDF section (visible only when a .pdf file is chosen): the attached
    // vs detached mode, the detached-signature file type, the CMS profile,
    // the visible stamp switch and the click-to-place position row.
    let pdf_kind_row = combo(
        &tr!("Signature Type"),
        &[
            tr!("Attached — the signature is written into the PDF itself").as_str(),
            tr!("Detached — a folder next to the file keeps the stamped PDF, the original and the signature")
                .as_str(),
        ],
        0,
    );
    let profile_row = combo(
        &tr!("Signature Profile"),
        &[
            tr!("CAdES-BES — enhanced signature with the certificate bound in").as_str(),
            tr!("CMS (PKCS#7) — plain signature").as_str(),
        ],
        PDF_PROFILE_CADES,
    );
    let detached_type_row = combo(
        &tr!("Detached signature file type"),
        &[
            tr!("SGN — CryptoPro, SED, SBIS").as_str(),
            tr!("P7S — international CMS").as_str(),
            tr!("SIG — some state portals").as_str(),
        ],
        0,
    );
    let stamp_sw = switch(
        &tr!("Show stamp in the document"),
        &tr!("Draw the signature plate with the signer, date and fingerprint on the page."),
        true,
    );
    let save_orig_sw = switch(
        &tr!("Save the original"),
        &tr!("The original file stays untouched; the signed copy is created next to it."),
        true,
    );
    let pos_row = action_row(&tr!("Stamp Position"), &tr!("Not placed yet"));
    let pos_btn = gtk::Button::with_label(&tr!("Choose on the page…"));
    pos_btn.add_css_class("flat");
    pos_btn.set_valign(gtk::Align::Center);
    pos_row.add_suffix(&pos_btn);
    let placement: Rc<RefCell<Option<Placement>>> = Rc::new(RefCell::new(None));
    let is_pdf: Rc<std::cell::Cell<bool>> = Rc::new(std::cell::Cell::new(false));

    let kind_row = combo(
        &tr!("Signature Type"),
        &[
            tr!("Detached (.p7s)").as_str(),
            tr!("Attached (.p7m)").as_str(),
        ],
        0,
    );
    let chain_sw = switch(
        &tr!("Include CA chain"),
        &tr!("Embed the issuing CA certificates so the signature verifies without this database."),
        true,
    );

    let (file_row, file_path) = file_row(
        &app.window,
        &tr!("File"),
        Some(Box::new({
            let is_pdf = is_pdf.clone();
            let placement = placement.clone();
            let pos_row = pos_row.clone();
            let stamp_sw = stamp_sw.clone();
            let g_pdf = g_pdf.clone();
            let kind_row = kind_row.clone();
            let detached_type_row = detached_type_row.clone();
            let save_orig_sw = save_orig_sw.clone();
            let pdf_kind_row = pdf_kind_row.clone();
            move |p: &std::path::Path| {
                let pdf = is_pdf_path(p);
                is_pdf.set(pdf);
                *placement.borrow_mut() = None;
                pos_row.set_subtitle(&tr!("Not placed yet"));
                pos_row.set_sensitive(pdf && stamp_sw.is_active());
                // The embedded signature replaces the p7s/p7m choice.
                g_pdf.set_visible(pdf);
                kind_row.set_visible(!pdf);
                detached_type_row.set_visible(pdf && pdf_kind_row.selected() == PDF_KIND_DETACHED);
                save_orig_sw.set_visible(pdf && pdf_kind_row.selected() == PDF_KIND_ATTACHED);
            }
        })),
    );
    g2.add(&file_row);
    g_pdf.add(&pdf_kind_row);
    g_pdf.add(&detached_type_row);
    g_pdf.add(&profile_row);
    g_pdf.add(&stamp_sw);
    g_pdf.add(&save_orig_sw);
    g_pdf.add(&pos_row);
    g_pdf.set_visible(false);
    detached_type_row.set_visible(false);
    save_orig_sw.set_visible(false);
    g3.add(&kind_row);
    g3.add(&chain_sw);

    {
        // The mode-specific rows: the signature-file type belongs to the
        // detached mode; "Save the original" — to the attached one, where
        // the source file is overwritten in place.
        let is_pdf = is_pdf.clone();
        let detached_type_row = detached_type_row.clone();
        let save_orig_sw = save_orig_sw.clone();
        pdf_kind_row.connect_notify_local(Some("selected"), move |row, _| {
            let detached = is_pdf.get() && row.selected() == PDF_KIND_DETACHED;
            let attached = is_pdf.get() && row.selected() == PDF_KIND_ATTACHED;
            detached_type_row.set_visible(detached);
            save_orig_sw.set_visible(attached);
        });
    }

    {
        // The stamp switch gates the position row.
        let pos_row = pos_row.clone();
        let is_pdf = is_pdf.clone();
        stamp_sw.connect_notify_local(Some("active"), move |sw, _| {
            pos_row.set_sensitive(is_pdf.get() && sw.is_active());
        });
    }
    {
        // Click-to-place over a poppler page preview.
        let app2 = app.clone();
        let file_path = file_path.clone();
        let placement = placement.clone();
        let pos_row = pos_row.clone();
        pos_btn.connect_clicked(move |_| {
            let Some(path) = file_path.borrow().clone() else {
                return;
            };
            let current = *placement.borrow();
            pdf_place::open_placement(&app2.window, &path, current, {
                let placement = placement.clone();
                let pos_row = pos_row.clone();
                move |p: Placement| {
                    *placement.borrow_mut() = Some(p);
                    pos_row.set_subtitle(&tr!(
                        "Page %{page}, X %{x}, Y %{y}",
                        page = p.page,
                        x = format!("{:.0}", p.cx),
                        y = format!("{:.0}", p.cy),
                    ));
                }
            });
        });
    }

    let cancel = form.close_button(&tr!("Cancel"));
    let sign = form.apply_button(&tr!("Sign"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    // The signing itself, shared by the direct path and the "already
    // signed" confirmation.
    let perform: Rc<dyn Fn()> = {
        let app2 = app.clone();
        let dlg = form.dlg.clone();
        let cert_row = cert_row.clone();
        let cert_ids = cert_ids.clone();
        let file_path = file_path.clone();
        let kind_row = kind_row.clone();
        let pdf_kind2 = pdf_kind_row.clone();
        let pdf_type2 = detached_type_row.clone();
        let profile2 = profile_row.clone();
        let save_orig2 = save_orig_sw.clone();
        let chain_sw = chain_sw.clone();
        let is_pdf2 = is_pdf.clone();
        let placement2 = placement.clone();
        let stamp_sw2 = stamp_sw.clone();
        Rc::new(move || {
        let cert_id = cert_ids.get(cert_row.selected() as usize).copied().flatten();
        let kind = if kind_row.selected() == 0 {
            SignatureKind::Detached
        } else {
            SignatureKind::Attached
        };
        let pdf_mode = is_pdf2.get();
        let pdf_detached = pdf_kind2.selected() == PDF_KIND_DETACHED;
        let profile = if profile2.selected() == PDF_PROFILE_PKCS7 {
            crypto::SignatureProfile::Pkcs7
        } else {
            crypto::SignatureProfile::CadesBes
        };
        let result = (|| -> Result<std::path::PathBuf, String> {
            let cert_id = cert_id.ok_or(tr!("Select a certificate"))?;
            let path = file_path
                .borrow()
                .clone()
                .ok_or(tr!("Select a file"))?;
            let (cert_rec, key_rec, chain) = {
                let db = app2.db.lock().unwrap();
                let cert = db
                    .get_cert(cert_id)
                    .ok()
                    .flatten()
                    .ok_or(tr!("Certificate not found"))?;
                let key = match cert.key_id {
                    Some(kid) => db.get_key(kid).ok().flatten(),
                    None => None,
                }
                .ok_or(tr!("The certificate has no private key in the database."))?;
                // The issuing chain up to the root, minus the signer
                // itself (CMS_sign embeds it automatically).
                let chain = if chain_sw.is_active() {
                    db.cert_chain(cert_id)
                        .unwrap_or_default()
                        .iter()
                        .skip(1)
                        .filter_map(|c| crypto::load_cert(&c.pem).ok())
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                (cert, key, chain)
            };
            let cert = crypto::load_cert(&cert_rec.pem)?;
            let key = crypto::load_private_key(&key_rec.pem)?;

            if pdf_mode {
                // PDF: either an embedded signature written back into the
                // same file, or a detached one dropped into a fresh folder
                // next to it.
                let data = std::fs::read(&path)
                    .map_err(|e| format!("{}: {e}", tr!("Read error")))?;
                let stamp = if stamp_sw2.is_active() {
                    let p = placement2
                        .borrow()
                        .ok_or(tr!("Place the stamp on the page first"))?;
                    let subj = cert.subject_name();
                    let field = |nid: openssl::nid::Nid| {
                        crypto::subject_field(subj, nid).unwrap_or_default()
                    };
                    let org = field(openssl::nid::Nid::ORGANIZATIONNAME);
                    let signer = stamp_header(subj, &org);
                    let now = gtk::glib::DateTime::now_local()
                        .or_else(|_| gtk::glib::DateTime::now_utc())
                        .map(|d| d.format("%d.%m.%Y %H:%M").unwrap_or_default().to_string())
                        .unwrap_or_default();
                    let mut opts = StampOpts {
                        page: p.page,
                        x: p.cx - STAMP_W / 2.0,
                        y: 0.0,
                        width: STAMP_W,
                        signer,
                        datetime: now,
                        organization: org,
                        title: field(openssl::nid::Nid::TITLE),
                        fingerprint: crypto::cert_fingerprint_hex(cert.as_ref())
                            .unwrap_or_default(),
                    };
                    // The plate height adapts to the wrapped lines; the
                    // click placed the CENTER, so keep it centered.
                    opts.y = p.cy - pdf_sign::stamp_height_pt(&opts) / 2.0;
                    Some(opts)
                } else {
                    None
                };

                if pdf_detached {
                    // Detached: the signature is made over the ORIGINAL
                    // document (the formular) — the pair the recipients
                    // verify. The stamped copy is a separate print version,
                    // not the signed artifact. The formular always lands in
                    // the folder next to the signature file and the print
                    // version; the source file itself stays untouched.
                    let der = crypto::sign_file_ex(
                        cert.as_ref(),
                        key.as_ref(),
                        &data,
                        SignatureKind::Detached,
                        &chain,
                        profile,
                    )?;
                    let stamped = match stamp.as_ref() {
                        Some(s) => Some(pdf_sign::stamp_pdf(&data, cert.as_ref(), Some(s))?),
                        None => None,
                    };
                    let parent = path.parent().map(PathBuf::from).unwrap_or_default();
                    let stem = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let folder = unique_signed_folder(&parent, &stem);
                    if let Err(e) = std::fs::create_dir_all(&folder) {
                        let _ = std::fs::remove_dir_all(&folder);
                        return Err(tr!(
                            "Cannot create the output folder: %{err}",
                            err = e.to_string()
                        ));
                    }
                    // A half-written folder is worse than none: drop it on
                    // any write error so a retry starts clean.
                    let write = |name: &str, bytes: &[u8]| -> Result<(), String> {
                        std::fs::write(folder.join(name), bytes).map_err(|e| {
                            format!("{} {name}: {e}", tr!("Write error"))
                        })
                    };
                    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
                    files.push((format!("{stem} ({}).pdf", tr!("form")), data.clone()));
                    let sig_ext = PDF_SIG_EXTS[pdf_type2.selected() as usize % PDF_SIG_EXTS.len()];
                    files.push((format!("{stem}.{sig_ext}"), der));
                    if let Some(stamped) = stamped {
                        files.push((format!("{stem} ({}).pdf", tr!("for printing")), stamped));
                    }
                    for (name, bytes) in files {
                        if let Err(e) = write(&name, &bytes) {
                            let _ = std::fs::remove_dir_all(&folder);
                            return Err(e);
                        }
                    }
                    return Ok(folder);
                }

                // Attached: the signature is written into the file itself.
                // With "Save the original" on, the source file stays
                // untouched and the signed version is created next to it;
                // without it the original is signed in place.
                let signed =
                    pdf_sign::sign_pdf_ex(&data, cert.as_ref(), key.as_ref(), &chain, stamp.as_ref(), profile)?;
                let out_path = if save_orig2.is_active() {
                    let parent = path.parent().map(PathBuf::from).unwrap_or_default();
                    let stem = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let mut out = parent.join(format!("{stem} ({}).pdf", tr!("signed")));
                    let mut attempt = 2u32;
                    while out.exists() {
                        out = parent.join(format!(
                            "{stem} ({} ({attempt})).pdf",
                            tr!("signed")
                        ));
                        attempt += 1;
                    }
                    out
                } else {
                    path.clone()
                };
                std::fs::write(&out_path, signed)
                    .map_err(|e| format!("{}: {e}", tr!("Write error")))?;
                return Ok(out_path);
            }

            let data = std::fs::read(&path)
                .map_err(|e| format!("{}: {e}", tr!("Read error")))?;
            let der = crypto::sign_file(cert.as_ref(), key.as_ref(), &data, kind, &chain)?;
            let ext = match kind {
                SignatureKind::Detached => "p7s",
                SignatureKind::Attached => "p7m",
            };
            let mut out = path.clone().into_os_string();
            out.push(format!(".{ext}"));
            let out = PathBuf::from(out);
            std::fs::write(&out, der).map_err(|e| format!("{}: {e}", tr!("Write error")))?;
            Ok(out)
        })();

        match result {
            Ok(out) => {
                let msg = if pdf_mode && pdf_detached {
                    tr!(
                        "Detached PDF signature created: %{dir}",
                        dir = out.to_string_lossy().to_string()
                    )
                } else if pdf_mode {
                    tr!("PDF signed: %{file}", file = out.to_string_lossy().to_string())
                } else {
                    tr!("Signature created: %{file}", file = out.to_string_lossy().to_string())
                };
                app2.toast(&msg);
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
        })
    };

    // Signing an already-signed PDF keeps every previous revision (and
    // its stamp) forever — make that explicit before adding another one.
    // Detached signing leaves the source file untouched, so it needs no
    // confirmation.
    {
        let app2 = app.clone();
        let is_pdf2 = is_pdf.clone();
        let pdf_kind3 = pdf_kind_row.clone();
        let file_path = file_path.clone();
        let perform = perform.clone();
        sign.connect_clicked(move |_| {
            let already_signed = is_pdf2.get()
                && pdf_kind3.selected() == PDF_KIND_ATTACHED
                && file_path
                    .borrow()
                    .clone()
                    .and_then(|p| std::fs::read(p).ok())
                    .is_some_and(|b| !pdf_sign::extract_pdf_signatures(&b).is_empty());
            if !already_signed {
                perform();
                return;
            }
            let ask = adw::AlertDialog::new(
                Some(&tr!("The document is already signed")),
                Some(&tr!(
                    "The PDF already contains signatures. The new one will be added and the existing stamps stay."
                )),
            );
            ask.add_response("cancel", &tr!("Cancel"));
            ask.add_response("sign", &tr!("Sign"));
            ask.set_response_appearance("sign", adw::ResponseAppearance::Suggested);
            let perform = perform.clone();
            ask.choose(Some(&app2.window), None::<&gtk::gio::Cancellable>, move |answer| {
                if answer == "sign" {
                    perform();
                }
            });
        });
    }

    form.dlg.present(Some(&app.window));
}

pub fn open_verify(app: &App) {
    let form = form_dialog(&tr!("Verify Signature"), 520);
    let (sig_row, sig_path) =
        file_row(&app.window, &tr!("Signature file (.p7s / .p7m / .sgn / .sig)"), None);
    let (data_row, data_path) = file_row(
        &app.window,
        &tr!("Original file (for a detached signature)"),
        None,
    );
    let g = form.group(&tr!("Signature"));
    g.add(&sig_row);
    g.add(&data_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let verify = form.apply_button(&tr!("Verify"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let sig_path = sig_path.clone();
    let data_path = data_path.clone();
    verify.connect_clicked(move |_| {
        let result = (|| {
            let sig_path = sig_path
                .borrow()
                .clone()
                .ok_or(tr!("Select a signature file"))?;
            let sig = std::fs::read(&sig_path)
                .map_err(|e| format!("{}: {e}", tr!("Read error")))?;
            let data = data_path
                .borrow()
                .clone()
                .map(|p| std::fs::read(p).map_err(|e| format!("{}: {e}", tr!("Read error"))))
                .transpose()?;
            // Every certificate in the database is a trust anchor candidate.
            let anchors: Vec<openssl::x509::X509> = app2
                .db
                .lock()
                .unwrap()
                .list_certs()
                .unwrap_or_default()
                .iter()
                .filter_map(|c| crypto::load_cert(&c.pem).ok())
                .collect();

            if is_pdf_path(&sig_path) {
                // PDF: verify every embedded signature.
                let sigs = pdf_sign::extract_pdf_signatures(&sig);
                if sigs.is_empty() {
                    return Err(tr!("No signatures found in the PDF."));
                }
                let reports: Vec<crypto::VerifyReport> = sigs
                    .iter()
                    .map(|s| crypto::verify_signature_detailed(&s.cms, Some(&s.data), &anchors))
                    .collect();
                return Ok((Some(sigs), reports, sig_path, data_path.borrow().clone()));
            }

            let report = crypto::verify_signature_detailed(&sig, data.as_deref(), &anchors);
            Ok((None, vec![report], sig_path, data_path.borrow().clone()))
        })();

        match result {
            Ok((Some(sigs), reports, sig_path, _)) => {
                dlg.close();
                present_pdf_report(&app2, &sig_path, &sigs, &reports);
            }
            Ok((None, reports, sig_path, data)) => {
                dlg.close();
                present_report(&app2, &reports, &sig_path, data.as_deref());
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

fn verdict_parts(outcome: crypto::VerifyOutcome, error: Option<&str>) -> (&'static str, &'static str, String, String) {
    match outcome {
        crypto::VerifyOutcome::Trusted => (
            "emblem-ok-symbolic",
            "success",
            tr!("Signature valid — signer chain verified"),
            tr!("The signer's chain is anchored at a certificate in this database."),
        ),
        crypto::VerifyOutcome::SignatureOnly => (
            "dialog-warning-symbolic",
            "warning",
            tr!("Signature valid — signer not in the database"),
            tr!("The signature is mathematically valid, but the chain could not be traced to certificates in this database."),
        ),
        crypto::VerifyOutcome::Invalid => (
            "dialog-error-symbolic",
            "error",
            tr!("Signature verification failed"),
            error
                .map(str::to_string)
                .unwrap_or_else(|| tr!("The signature does not match the file.")),
        ),
    }
}

/// Verdict banner: colored icon + heading + explanation in a card. The
/// card spans the group's full width (hexpand + Fill, no outer margins);
/// breathing room comes from margins on the children INSIDE the card.
fn add_banner(form: &super::Form, icon: &str, css: &str, title: &str, subtitle: &str) {
    let banner = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    banner.set_hexpand(true);
    banner.set_halign(gtk::Align::Fill);
    let img = gtk::Image::from_icon_name(icon);
    img.set_pixel_size(32);
    img.set_valign(gtk::Align::Center);
    img.set_margin_top(12);
    img.set_margin_bottom(12);
    img.set_margin_start(12);
    img.add_css_class(css);
    let texts = gtk::Box::new(gtk::Orientation::Vertical, 4);
    texts.set_hexpand(true);
    texts.set_margin_top(12);
    texts.set_margin_bottom(12);
    texts.set_margin_end(12);
    let t = gtk::Label::new(Some(title));
    t.set_halign(gtk::Align::Start);
    t.set_xalign(0.0);
    t.set_wrap(true);
    t.add_css_class("heading");
    t.add_css_class(css);
    let s = gtk::Label::new(Some(subtitle));
    s.set_halign(gtk::Align::Start);
    s.set_xalign(0.0);
    s.set_wrap(true);
    s.add_css_class("dim-label");
    texts.append(&t);
    texts.append(&s);
    banner.append(&img);
    banner.append(&texts);
    banner.add_css_class("card");
    let g0 = form.group("");
    g0.add(&banner);
}

/// Signer details and the traced chain, shared by the plain CMS report
/// and the per-signature sections of the PDF report.
fn add_verify_details(form: &super::Form, report: &crypto::VerifyReport) {
    for (i, signer) in report.signers.iter().enumerate() {
        let title = if report.signers.len() == 1 {
            tr!("Signer")
        } else {
            tr!("Signer %{n}", n = i + 1)
        };
        let gs = form.group(&title);
        let cs = crypto::cert_summary(signer.as_ref());
        gs.add(&action_row(&tr!("Subject"), &cs.subject));
        gs.add(&action_row(&tr!("Issuer"), &cs.issuer));
        gs.add(&action_row(&tr!("Serial"), &format!("0x{}", cs.serial)));
        gs.add(&action_row(
            &tr!("Validity"),
            &format!("{} — {}", cs.not_before, cs.not_after),
        ));
        gs.add(&action_row(
            &tr!("Signature Algorithm"),
            &crypto::signature_algorithm(signer.as_ref()),
        ));
        let in_db = report
            .chains
            .get(i)
            .and_then(|c| c.first())
            .map(|l| l.in_db)
            .unwrap_or(false);
        let db_label = if in_db { tr!("Yes") } else { tr!("No") };
        gs.add(&action_row(&tr!("In the database"), &db_label));

        // Chain: signer first, then issuers; the row subtitle says where
        // each certificate came from.
        let gc = form.group(&tr!("Certificate Chain"));
        for (j, link) in report.chains[i].iter().enumerate() {
            let subject = crypto::name_cn(link.cert.subject_name())
                .filter(|cn| !cn.is_empty())
                .unwrap_or_else(|| crypto::name_to_string(link.cert.subject_name()));
            let source = match link.source {
                crypto::ChainSource::Signer => tr!("signer"),
                crypto::ChainSource::Signature => tr!("embedded in the signature"),
                crypto::ChainSource::Database => tr!("from the database"),
            };
            let summary = crypto::cert_summary(link.cert.as_ref());
            let subtitle = format!("{source} · {} {}", tr!("valid until"), summary.not_after);
            let row = action_row(&subject, &subtitle);
            let icon = if j == 0 {
                "object-select-symbolic"
            } else {
                "go-down-symbolic"
            };
            let img = gtk::Image::from_icon_name(icon);
            img.set_valign(gtk::Align::Center);
            row.add_prefix(&img);
            gc.add(&row);
        }
        if report.incomplete.get(i).copied().unwrap_or(false) {
            let row = action_row(
                &tr!("Issuer not found"),
                &tr!("The issuer certificate is neither in the database nor embedded in the signature."),
            );
            row.add_css_class("warning");
            gc.add(&row);
        }
    }
}

/// "D:20260919201727+03'00'" → "19.09.2026 20:17".
fn pdf_date_text(raw: &str) -> Option<String> {
    let t = raw.trim_start_matches('D').trim_start_matches(':');
    let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() < 8 {
        return None;
    }
    let part = |a: usize, b: usize| digits.get(a..b).map(|s| s.to_string()).unwrap_or_default();
    let (y, m, d) = (part(0, 4), part(4, 6), part(6, 8));
    let (h, min) = (part(8, 10), part(10, 12));
    if h.is_empty() {
        Some(format!("{d}.{m}.{y}"))
    } else {
        Some(format!("{d}.{m}.{y} {h}:{min}"))
    }
}

/// Full verification result: verdict banner, the files involved, signer
/// details and the certificate chain as it was traced.
fn present_report(
    app: &App,
    reports: &[crypto::VerifyReport],
    sig_path: &std::path::Path,
    data_path: Option<&std::path::Path>,
) {
    let form = form_dialog(&tr!("Verification Report"), 600);
    let report = reports
        .last()
        .expect("caller guarantees at least one report");
    let (icon, css, title, subtitle) =
        verdict_parts(report.outcome, report.error.as_deref());
    add_banner(&form, icon, css, &title, &subtitle);

    let gf = form.group(&tr!("Files"));
    gf.add(&action_row(
        &tr!("Signature file"),
        &sig_path.to_string_lossy(),
    ));
    if let Some(p) = data_path {
        gf.add(&action_row(&tr!("Original file"), &p.to_string_lossy()));
    }
    let content = if report.detached {
        tr!("Detached (the content travels as a separate file)")
    } else {
        tr!("Attached (the content is embedded in the signature)")
    };
    gf.add(&action_row(&tr!("Content"), &content));

    for report in reports {
        add_verify_details(&form, report);
    }

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| {
            dlg.close();
        });
    }
    form.dlg.present(Some(&app.window));
}


/// PDF verification report: the overall verdict of the newest signature,
/// then every embedded signature with its date, revision status, signer
/// and chain.
fn present_pdf_report(
    app: &App,
    pdf_path: &std::path::Path,
    sigs: &[pdf_sign::PdfSignature],
    reports: &[crypto::VerifyReport],
) {
    let form = form_dialog(&tr!("Verification Report"), 600);
    let last = reports.last().expect("caller guarantees reports");
    let (icon, css, title, subtitle) = verdict_parts(last.outcome, last.error.as_deref());
    let subtitle = if sigs.len() > 1 {
        format!(
            "{subtitle} · {}",
            tr!("%{count} signatures in the document", count = sigs.len())
        )
    } else {
        subtitle
    };
    add_banner(&form, icon, css, &title, &subtitle);

    let gf = form.group(&tr!("Files"));
    gf.add(&action_row(&tr!("PDF file"), &pdf_path.to_string_lossy()));
    gf.add(&action_row(
        &tr!("Signatures"),
        &tr!("%{count} signatures in the document", count = sigs.len()),
    ));

    for (i, (sig, report)) in sigs.iter().zip(reports.iter()).enumerate() {
        let title = if sigs.len() == 1 {
            tr!("Signature")
        } else {
            tr!("Signature %{n}", n = i + 1)
        };
        let gs = form.group(&title);
        gs.add(&action_row(
            &tr!("Signed"),
            sig.date
                .as_deref()
                .and_then(pdf_date_text)
                .as_deref()
                .unwrap_or("—"),
        ));
        // What followed this signature: a later signature (a normal
        // incremental revision) or foreign bytes.
        if i + 1 < sigs.len() {
            gs.add(&action_row(
                &tr!("Signed again later"),
                &tr!("The document has more signatures added after this one."),
            ));
        } else if sig.trailing > 0 {
            let row = action_row(
                &tr!("The file was modified after this signature"),
                &tr!("%{count} bytes follow the signed range.", count = sig.trailing),
            );
            row.add_css_class("warning");
            gs.add(&row);
        }
        add_verify_details(&form, report);
    }

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| {
            dlg.close();
        });
    }
    form.dlg.present(Some(&app.window));
}

#[cfg(test)]
mod tests {
    use super::stamp_header;
    use openssl::nid::Nid;
    use openssl::x509::X509Name;

    fn name(o: Option<&str>, cn: Option<&str>) -> X509Name {
        let mut b = X509Name::builder().unwrap();
        if let Some(o) = o {
            b.append_entry_by_nid(Nid::ORGANIZATIONNAME, o).unwrap();
        }
        if let Some(cn) = cn {
            b.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        }
        b.build()
    }

    #[test]
    fn stamp_header_drops_cn_equal_to_org() {
        // The typical legal-entity certificate: CN is a copy of O — the
        // header must be EMPTY (line skipped), not the full DN fallback.
        let org = "ТОЛЬЯТТИНСКИЙ ГОСУДАРСТВЕННЫЙ УНИВЕРСИТЕТ";
        let n = name(Some(org), Some(org));
        assert_eq!(stamp_header(&n, org), "");
        // Surrounding whitespace must not keep the duplicate alive.
        let n = name(Some(org), Some(&format!("  {org} ")));
        assert_eq!(stamp_header(&n, org), "");
    }

    #[test]
    fn stamp_header_keeps_distinct_cn() {
        let n = name(Some("Организация"), Some("Иванов Иван Иванович"));
        assert_eq!(stamp_header(&n, "Организация"), "Иванов Иван Иванович");
        // No O in the subject at all — the CN line stays too.
        let n = name(None, Some("Иванов Иван Иванович"));
        assert_eq!(stamp_header(&n, ""), "Иванов Иван Иванович");
    }

    #[test]
    fn stamp_header_falls_back_to_dn_without_cn() {
        // No CN — the full DN is the only identifying text for the header.
        let n = name(Some("Организация"), None);
        let s = stamp_header(&n, "Организация");
        assert!(s.contains("Организация"), "header keeps identifying text: {s}");
    }
}
