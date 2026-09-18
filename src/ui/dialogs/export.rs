//! Export of the selected item to a file (via the native save dialog).

use super::{combo, error_dialog, form_dialog, row_text};
use crate::app::App;
use crate::crypto;
use crate::db::CertRecord;
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
            true => c,
            false => '-',
        })
        .collect();
    if cleaned.is_empty() {
        "export".into()
    } else {
        cleaned
    }
}

fn write_file(app: &App, bytes: Vec<u8>, suggested: String) {
    let fd = gtk::FileDialog::builder().title(tr!("Export to File")).build();
    fd.set_initial_name(Some(suggested.as_str()));
    let app2 = app.clone();
    fd.save(
        Some(&app.window),
        None::<&gtk::gio::Cancellable>,
        move |res| match res {
            Ok(file) => {
                match file.replace_contents(
                    &bytes,
                    None,
                    false,
                    gtk::gio::FileCreateFlags::REPLACE_DESTINATION,
                    None::<&gtk::gio::Cancellable>,
                ) {
                    Ok(_etag) => app2.toast(&tr!("Export done")),
                    Err(e) => error_dialog(&app2.window, &format!("{}: {e}", tr!("Write error"))),
                }
            }
            Err(e) => {
                if !e.matches(gtk::gio::IOErrorEnum::Cancelled) {
                    error_dialog(&app2.window, &format!("{}: {e}", tr!("Export canceled")));
                }
            }
        },
    );
}

pub fn open(app: &App) {
    let page = app
        .pages
        .stack
        .visible_child_name()
        .map(|s| s.to_string())
        .unwrap_or_default();
    match page.as_str() {
        "keys" => export_key(app),
        "certs" => export_cert(app),
        "reqs" => export_req(app),
        "crls" => export_crl(app),
        _ => {}
    }
}

fn export_key(app: &App) {
    let Some(rec) = app.selected_key() else {
        return app.toast(&tr!("Select a key first"));
    };
    // Public-only keys go out as they are; private keys get an optional
    // PEM password.
    if crypto::load_private_key(&rec.pem).is_err() {
        app.toast(&tr!("Note: the key is exported unencrypted"));
        return write_file(app, rec.pem, format!("{}.key", sanitize(&rec.name)));
    }

    let form = form_dialog(&tr!("Export Private Key"), 400);
    let pw1 = super::password_entry(&tr!("Password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));
    let g = form.group(&tr!("Encryption"));
    g.set_description(Some(&tr!("Leave empty to export without a password.")));
    g.add(&pw1);
    g.add(&pw2);

    let cancel = form.close_button(&tr!("Cancel"));
    let export = form.apply_button(&tr!("Export"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let rec = rec.clone();
    let pw1 = pw1.clone();
    let pw2 = pw2.clone();
    export.connect_clicked(move |_| {
        let a = row_text(&pw1);
        if a != row_text(&pw2) {
            return error_dialog(&app2.window, &tr!("Passwords do not match"));
        }
        let result = (|| -> Result<Vec<u8>, String> {
            let key = crypto::load_private_key(&rec.pem)?;
            if a.is_empty() {
                key.private_key_to_pem_pkcs8().map_err(|e| e.to_string())
            } else {
                key.private_key_to_pem_pkcs8_passphrase(
                    openssl::symm::Cipher::aes_256_cbc(),
                    a.as_bytes(),
                )
                .map_err(|e| e.to_string())
            }
        })();
        match result {
            Ok(pem) => {
                dlg.close();
                write_file(&app2, pem, format!("{}.key", sanitize(&rec.name)));
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

fn export_req(app: &App) {
    let Some(rec) = app.selected_req() else {
        return app.toast(&tr!("Select a request first"));
    };
    write_file(app, rec.pem, format!("{}.csr", sanitize(&rec.name)));
}

fn export_crl(app: &App) {
    let Some(rec) = app.selected_crl() else {
        return app.toast(&tr!("Select a revocation list first"));
    };
    write_file(app, rec.pem, format!("{}.crl", sanitize(&rec.name)));
}

fn export_cert(app: &App) {
    let Some(rec) = app.selected_cert() else {
        return app.toast(&tr!("Select a certificate first"));
    };

    // Format chooser first, then (for PFX) a password, then the save dialog.
    let form = form_dialog(&tr!("Export Certificate"), 460);
    let fmt_row = combo(
        &tr!("Format"),
        &[
            tr!("PEM").as_str(),
            tr!("PEM with chain").as_str(),
            "DER",
            "PFX",
            tr!("PFX with chain").as_str(),
        ],
        0,
    );
    let g = form.group(&tr!("Certificate"));
    g.add(&fmt_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let next = form.apply_button(&tr!("Next…"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| { dlg.close(); });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let fmt_row = fmt_row.clone();
    next.connect_clicked(move |_| {
        dlg.close();
        match fmt_row.selected() {
            0 => {
                write_file(&app2, rec.pem.clone(), format!("{}.pem", sanitize(&rec.name)));
            }
            1 => {
                let mut pem = rec.pem.clone();
                if let Ok(chain) = app2.db.lock().unwrap().cert_chain(rec.id) {
                    for c in chain.iter().skip(1) {
                        pem.extend_from_slice(&c.pem);
                    }
                }
                write_file(&app2, pem, format!("{}.pem", sanitize(&rec.name)));
            }
            2 => {
                let bytes = crypto::load_cert(&rec.pem)
                    .and_then(|c| c.to_der().map_err(|e| e.to_string()))
                    .unwrap_or_default();
                write_file(&app2, bytes, format!("{}.crt", sanitize(&rec.name)));
            }
            sel => pfx_export(&app2, &rec, sel == 4),
        }
    });

    form.dlg.present(Some(&app.window));
}

/// PKCS#12 export: needs the private key; asks for a bundle password and
/// includes the issuing chain when `with_chain` is set.
fn pfx_export(app: &App, rec: &CertRecord, with_chain: bool) {
    // Resolve the private key stored for this certificate.
    let key_pem = {
        let db = app.db.lock().unwrap();
        rec.key_id
            .and_then(|id| db.get_key(id).ok().flatten())
            .map(|k| k.pem)
    };
    let Some(key_pem) = key_pem else {
        return error_dialog(
            &app.window,
            &tr!("PFX export requires the certificate's private key in the database"),
        );
    };
    let chain: Vec<openssl::x509::X509> = if with_chain {
        app.db
            .lock()
            .unwrap()
            .cert_chain(rec.id)
            .unwrap_or_default()
            .iter()
            .skip(1)
            .filter_map(|c| crypto::load_cert(&c.pem).ok())
            .collect()
    } else {
        Vec::new()
    };

    let form = form_dialog(&tr!("PFX Export"), 400);
    let pw1 = super::password_entry(&tr!("Password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));
    let g = form.group(&tr!("PKCS#12"));
    g.set_description(Some(&tr!("Leave empty to export without a password.")));
    g.add(&pw1);
    g.add(&pw2);

    let cancel = form.close_button(&tr!("Cancel"));
    let export = form.apply_button(&tr!("Export"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| { dlg.close(); });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let rec = rec.clone();
    let pw1 = pw1.clone();
    let pw2 = pw2.clone();
    export.connect_clicked(move |_| {
        let a = row_text(&pw1);
        // An empty password is allowed (unencrypted PFX); a mismatch is not.
        if a != row_text(&pw2) {
            return error_dialog(&app2.window, &tr!("Passwords do not match"));
        }
        let result = (|| -> Result<Vec<u8>, String> {
            let cert = crypto::load_cert(&rec.pem)?;
            let key = crypto::load_private_key(&key_pem)?;
            crypto::build_pkcs12(cert.as_ref(), key.as_ref(), &chain, &a, &rec.name)
        })();
        match result {
            Ok(der) => {
                dlg.close();
                write_file(&app2, der, format!("{}.pfx", sanitize(&rec.name)));
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
