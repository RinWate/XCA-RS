//! Import from file: PEM/DER certificates, requests, private keys and
//! PKCS#12 bundles (with password prompt when needed).

use super::{error_dialog, form_dialog, password_entry, row_text};
use crate::app::App;
use crate::crypto::{self, Imported};
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;

pub fn open(app: &App) {
    let fd = gtk::FileDialog::builder()
        .title(tr!("Import from File"))
        .build();
    let app2 = app.clone();
    fd.open(
        Some(&app.window),
        None::<&gtk::gio::Cancellable>,
        move |res| match res {
            Ok(file) => match file.load_contents(None::<&gtk::gio::Cancellable>) {
                Ok((data, _)) => {
                    let data = data.to_vec();
                    if crypto::probably_needs_password(&data) {
                        ask_password(&app2, data);
                    } else {
                        do_import(&app2, data, None);
                    }
                }
                Err(e) => error_dialog(&app2.window, &format!("{}: {e}", tr!("Cannot read file"))),
            },
            Err(e) => {
                if !e.matches(gtk::gio::IOErrorEnum::Cancelled) {
                    error_dialog(&app2.window, &format!("{}: {e}", tr!("Import canceled")));
                }
            }
        },
    );
}

fn ask_password(app: &App, data: Vec<u8>) {
    let form = form_dialog(&tr!("Password Required"), 380);
    let pw = password_entry(&tr!("Password"));
    let g = form.group(&tr!("Encrypted File"));
    g.add(&pw);

    let cancel = form.close_button(&tr!("Cancel"));
    let unlock = form.apply_button(&tr!("Unlock"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| { dlg.close(); });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let pw = pw.clone();
    let data = std::rc::Rc::new(data);
    unlock.connect_clicked(move |_| {
        let password = row_text(&pw).to_string();
        dlg.close();
        do_import(&app2, data.as_ref().clone(), Some(&password));
    });

    form.dlg.present(Some(&app.window));
}

pub fn do_import(app: &App, data: Vec<u8>, password: Option<&str>) {
    let items = match crypto::parse_any(&data, password) {
        Ok(items) => items,
        Err(e) => return error_dialog(&app.window, &e),
    };

    let mut n_certs = 0usize;
    let mut n_keys = 0usize;
    let mut n_reqs = 0usize;
    let mut n_dup = 0usize;

    let db = app.db.lock().unwrap();
    for item in items {
        match item {
            Imported::Key { key, name } => {
                let (k, bits, curve) = crypto::key_info(key.as_ref());
                let pem = key.private_key_to_pem_pkcs8().unwrap_or_default();
                if db.key_exists(&pem).unwrap_or(false) {
                    n_dup += 1;
                    continue;
                }
                let label = format!("Imported {k} {bits}");
                let _ = name;
                if db.insert_key(&label, &k, bits, &curve, &pem).is_ok() {
                    n_keys += 1;
                }
            }
            Imported::Cert { cert } => {
                let s = crypto::cert_summary(cert.as_ref());
                let pem = cert.to_pem().unwrap_or_default();
                if db.cert_exists(&pem).unwrap_or(false) {
                    n_dup += 1;
                    continue;
                }
                let cn = crypto::cn_of_name(cert.subject_name())
                    .unwrap_or_else(|| format!("cert-{}", &s.serial[..s.serial.len().min(8)]));
                let rec = crate::db::CertRecord {
                    id: 0,
                    name: cn,
                    subject: s.subject,
                    issuer: s.issuer,
                    serial: s.serial,
                    not_after: s.not_after,
                    expires_days: s.expires_days,
                    ca: s.is_ca,
                    key_id: None,
                    issuer_id: None,
                    pem,
                };
                if db.insert_cert(&rec).is_ok() {
                    n_certs += 1;
                }
            }
            Imported::Req { req } => {
                let subject = crypto::name_to_string(req.subject_name());
                let pem = req.to_pem().unwrap_or_default();
                if db.req_exists(&pem).unwrap_or(false) {
                    n_dup += 1;
                    continue;
                }
                let name = crypto::cn_of_name(req.subject_name())
                    .unwrap_or_else(|| "imported request".into());
                let rec = crate::db::ReqRecord {
                    id: 0,
                    name,
                    subject,
                    key_id: None,
                    pem,
                };
                if db.insert_req(&rec).is_ok() {
                    n_reqs += 1;
                }
            }
            Imported::Pkcs12 { key, cert, ca } => {
                let mut key_id = None;
                if let Some(key) = key {
                    let (k, bits, curve) = crypto::key_info(key.as_ref());
                    let pem = key.private_key_to_pem_pkcs8().unwrap_or_default();
                    if !db.key_exists(&pem).unwrap_or(false) {
                        let label = format!("Imported {k} {bits}");
                        if let Ok(id) = db.insert_key(&label, &k, bits, &curve, &pem) {
                            key_id = Some(id);
                            n_keys += 1;
                        }
                    } else {
                        n_dup += 1;
                    }
                }
                let mut insert = |cert: openssl::x509::X509, key_id: Option<i64>| {
                    let s = crypto::cert_summary(cert.as_ref());
                    let pem = cert.to_pem().unwrap_or_default();
                    if db.cert_exists(&pem).unwrap_or(false) {
                        n_dup += 1;
                        return;
                    }
                    let cn = crypto::cn_of_name(cert.subject_name())
                        .unwrap_or_else(|| format!("cert-{}", &s.serial[..s.serial.len().min(8)]));
                    let rec = crate::db::CertRecord {
                        id: 0,
                        name: cn,
                        subject: s.subject,
                        issuer: s.issuer,
                        serial: s.serial,
                        not_after: s.not_after,
                        expires_days: s.expires_days,
                        ca: s.is_ca,
                        key_id,
                        issuer_id: None,
                        pem,
                    };
                    if db.insert_cert(&rec).is_ok() {
                        n_certs += 1;
                    }
                };
                if let Some(cert) = cert {
                    insert(cert, key_id);
                }
                for c in ca {
                    insert(c, None);
                }
            }
        }
    }
    drop(db);

    app.refresh();
    let mut parts = Vec::new();
    if n_certs > 0 {
        parts.push(tr!("%{count} certificates", count = n_certs as i64));
    }
    if n_keys > 0 {
        parts.push(tr!("%{count} keys", count = n_keys as i64));
    }
    if n_reqs > 0 {
        parts.push(tr!("%{count} requests", count = n_reqs as i64));
    }
    if parts.is_empty() {
        if n_dup > 0 {
            app.toast(&tr!("Nothing imported — all items already exist"));
        } else {
            app.toast(&tr!("Nothing to import"));
        }
    } else {
        let dup = if n_dup > 0 {
            format!(" ({})", tr!("%{count} duplicates skipped", count = n_dup as i64))
        } else {
            String::new()
        };
        app.toast(&format!("{}{dup}", tr!("Imported: %{list}", list = parts.join(", "))));
    }
}
