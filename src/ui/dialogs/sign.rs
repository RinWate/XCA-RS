//! "Signatures" section: sign arbitrary files with a certificate from
//! the database — CMS detached (`.p7s`) and attached (`.p7m`) signatures —
//! and verify signatures back.

use super::{action_row, combo, combo_ids, error_dialog, form_dialog, switch};
use crate::app::App;
use crate::crypto::{self, SignatureKind, VerifyOutcome};
use crate::tr;
use gtk::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

/// A row with a "Choose…" button that opens a file dialog and remembers
/// the picked path (shown as the subtitle).
fn file_row(
    parent: &adw::ApplicationWindow,
    title: &str,
) -> (adw::ActionRow, Rc<RefCell<Option<PathBuf>>>) {
    let row = action_row(title, "");
    let path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let btn = gtk::Button::with_label(&tr!("Choose…"));
    btn.add_css_class("flat");
    btn.set_valign(gtk::Align::Center);
    {
        let row = row.clone();
        let path = path.clone();
        let parent = parent.clone();
        btn.connect_clicked(move |_| {
            let fd = gtk::FileDialog::builder().title(tr!("Choose a File")).build();
            let row = row.clone();
            let path = path.clone();
            fd.open(Some(&parent), None::<&gtk::gio::Cancellable>, move |res| {
                if let Ok(file) = res
                    && let Some(p) = file.path()
                {
                    row.set_subtitle(&p.to_string_lossy());
                    *path.borrow_mut() = Some(p);
                }
            });
        });
    }
    row.add_suffix(&btn);
    (row, path)
}

pub fn open_sign(app: &App) {
    let certs: Vec<(i64, String, String)> = app
        .db
        .lock()
        .unwrap()
        .list_certs()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.key_id.is_some())
        .map(|c| (c.id, c.name, c.subject))
        .collect();
    if certs.is_empty() {
        return error_dialog(
            &app.window,
            &tr!("Signing requires a certificate with its private key in the database."),
        );
    }

    let form = form_dialog(&tr!("Sign File"), 520);
    let (cert_row, cert_ids) = combo_ids(&tr!("Certificate"), &[], &certs, 0);
    super::combo_min_width(&cert_row, 430);
    let g = form.group(&tr!("Signer"));
    g.add(&cert_row);

    let (file_row, file_path) = file_row(&app.window, &tr!("File"));
    let g2 = form.group(&tr!("File"));
    g2.add(&file_row);

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
    let g3 = form.group(&tr!("Signature"));
    g3.add(&kind_row);
    g3.add(&chain_sw);

    let cancel = form.close_button(&tr!("Cancel"));
    let sign = form.apply_button(&tr!("Sign"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let cert_row = cert_row.clone();
    let cert_ids = cert_ids.clone();
    let file_path = file_path.clone();
    let kind_row = kind_row.clone();
    let chain_sw = chain_sw.clone();
    sign.connect_clicked(move |_| {
        let cert_id = cert_ids.get(cert_row.selected() as usize).copied().flatten();
        let kind = if kind_row.selected() == 0 {
            SignatureKind::Detached
        } else {
            SignatureKind::Attached
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
                app2.toast(&tr!("Signature created: %{file}", file = out.to_string_lossy().to_string()));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

pub fn open_verify(app: &App) {
    let form = form_dialog(&tr!("Verify Signature"), 520);
    let (sig_row, sig_path) = file_row(&app.window, &tr!("Signature file (.p7s / .p7m)"));
    let (data_row, data_path) =
        file_row(&app.window, &tr!("Original file (for a detached signature)"));
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
        let result = (|| -> Result<VerifyOutcome, String> {
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
            crypto::verify_signature(&sig, data.as_deref(), &anchors)
        })();

        match result {
            Ok(VerifyOutcome::Trusted) => {
                app2.toast(&tr!("Signature valid — signer chain verified"));
                dlg.close();
            }
            Ok(VerifyOutcome::SignatureOnly) => {
                app2.toast(&tr!("Signature valid — signer not in the database"));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
