//! "New Certificate" dialog, also used in "Sign Request" mode: subject
//! (prefilled from a CSR when signing), key choice, issuer CA, validity and
//! common extension presets.

use super::{action_row, combo_ids, entry, entry_default, error_dialog, form_dialog, row_text, spin, switch};
use crate::app::App;
use crate::crypto::{self, CertParams, SubjectData};
use crate::db::{CertRecord, ReqRecord};
use crate::tr;
use crate::ui::dialogs::san as san_dlg;
use crate::ui::dialogs::san::{SanEntry, SanKind};
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;
use openssl::pkey::{PKey, Private, Public};
use std::cell::RefCell;
use std::rc::Rc;

pub fn open(app: &App, from_req: Option<ReqRecord>) {
    let req_info = match &from_req {
        Some(r) => match crypto::load_req(&r.pem) {
            Ok(req) => Some((
                crypto::name_to_string(req.subject_name()),
                crypto::cn_of_name(req.subject_name()),
            )),
            Err(e) => {
                error_dialog(&app.window, &e);
                return;
            }
        },
        None => None,
    };

    let form = form_dialog(
        &(if from_req.is_some() {
            tr!("Sign Request")
        } else {
            tr!("New Certificate")
        }),
        500,
    );

    let default_name = req_info
        .as_ref()
        .and_then(|(_, cn)| cn.clone())
        .unwrap_or_default();
    let name_row = entry_default(&tr!("Internal Name"), &default_name);

    let mut subject_rows = None;
    let mut key_rows = None;
    if let Some((subj, _cn)) = &req_info {
        let g = form.group(&tr!("Request"));
        g.add(&action_row(&tr!("Signing request"), subj));
        g.add(&name_row);
    } else {
        let cn = entry(&tr!("Common Name (CN)"));
        let org = entry(&tr!("Organization (O)"));
        let org_unit = entry(&tr!("Organizational Unit (OU)"));
        let country = entry(&tr!("Country (C)"));
        let email = entry(&tr!("E-Mail (emailAddress)"));
        let g = form.group(&tr!("Subject"));
        g.add(&name_row);
        g.add(&cn);
        g.add(&org);
        g.add(&org_unit);
        g.add(&country);
        g.add(&email);
        subject_rows = Some((cn, org, org_unit, country, email));

        let keys = app.db.lock().unwrap().list_keys().unwrap_or_default();
        let named: Vec<(i64, String, String)> = keys
            .iter()
            .map(|k| (k.id, k.name.clone(), k.type_label()))
            .collect();
        let (key_row, key_ids) = combo_ids(
            &tr!("Private Key"),
            &[
                tr!("Generate new RSA 2048").as_str(),
                tr!("Generate new EC P-256").as_str(),
                tr!("Generate new Ed25519").as_str(),
            ],
            &named,
            0,
        );
        let g = form.group(&tr!("Key"));
        g.add(&key_row);
        key_rows = Some((key_row, key_ids));
    }

    // Issuer: self-signed entry only when not signing a CSR.
    let cas: Vec<(i64, String, String)> = app
        .db
        .lock()
        .unwrap()
        .list_ca_certs()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.key_id.is_some())
        .map(|c| (c.id, c.name, c.subject))
        .collect();
    let (issuer_row, issuer_ids) = if from_req.is_some() {
        if cas.is_empty() {
            error_dialog(
                &app.window,
                &tr!("Signing a request requires a CA certificate with its private key.\nCreate a self-signed CA first."),
            );
            return;
        }
        combo_ids(&tr!("Issuing CA"), &[], &cas, 0)
    } else {
        combo_ids(&tr!("Signed by"), &[tr!("Self-signed").as_str()], &cas, 0)
    };
    let g_issuer = form.group(&tr!("Issuer"));
    g_issuer.add(&issuer_row);

    let validity = spin(&tr!("Validity (days)"), 3650.0, 1.0, 36500.0, 1.0);
    let g_val = form.group(&tr!("Validity"));
    g_val.add(&validity);

    let ca_sw = switch(
        &tr!("Certificate Authority (CA)"),
        "basicConstraints CA:TRUE, keyCertSign",
        from_req.is_none(),
    );
    let server_sw = switch(
        &tr!("TLS Server"),
        "serverAuth, keyEncipherment, SAN entries apply",
        from_req.is_some(),
    );
    let client_sw = switch(&tr!("TLS Client"), "clientAuth", false);
    // SAN entries live in a shared cell; the row subtitle summarizes them
    // and the editor dialog updates them in place.
    let initial_san: Vec<SanEntry> = req_info
        .as_ref()
        .and_then(|(_, cn)| cn.clone())
        .map(|cn| {
            vec![SanEntry {
                kind: SanKind::Dns,
                value: cn,
            }]
        })
        .unwrap_or_default();
    let san: Rc<RefCell<Vec<SanEntry>>> = Rc::new(RefCell::new(initial_san));
    let san_row = action_row(&tr!("Subject Alt Names"), &san_dlg::summary(&san.borrow()));
    let san_edit = gtk::Button::with_label(&tr!("Edit…"));
    san_edit.add_css_class("flat");
    san_edit.set_valign(gtk::Align::Center);
    san_row.add_suffix(&san_edit);
    {
        let app2 = app.clone();
        let san = san.clone();
        let san_row = san_row.clone();
        san_edit.connect_clicked(move |_| {
            let initial = san.borrow().clone();
            let san_row = san_row.clone();
            let san = san.clone();
            san_dlg::open_edit(&app2, initial, move |entries| {
                *san.borrow_mut() = entries;
                san_row.set_subtitle(&san_dlg::summary(&san.borrow()));
            });
        });
    }
    let g_ext = form.group(&tr!("Extensions"));
    g_ext.add(&ca_sw);
    g_ext.add(&server_sw);
    g_ext.add(&client_sw);
    g_ext.add(&san_row);

    // Self-signed implies CA by default; signing by a CA implies a leaf.
    if from_req.is_none() {
        let ca_sw = ca_sw.clone();
        issuer_row.connect_notify_local(Some("selected"), move |row: &adw::ComboRow, _| {
            ca_sw.set_active(row.selected() == 0);
        });
    }

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&(if from_req.is_some() {
        tr!("Sign")
    } else {
        tr!("Create")
    }));

    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| { dlg.close(); });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let name_row = name_row.clone();
    let subject_rows = subject_rows.clone();
    let key_rows = key_rows.clone();
    let issuer_row = issuer_row.clone();
    let issuer_ids = issuer_ids.clone();
    let validity = validity.clone();
    let ca_sw = ca_sw.clone();
    let server_sw = server_sw.clone();
    let client_sw = client_sw.clone();
    let san = san.clone();
    let req_rec = from_req.clone();
    create.connect_clicked(move |_| {
        let result = (|| -> Result<(), String> {
            let params = CertParams {
                validity_days: validity.value() as u32,
                is_ca: ca_sw.is_active(),
                server_auth: server_sw.is_active(),
                client_auth: client_sw.is_active(),
                san: san.borrow().iter().map(|e| e.to_raw()).collect(),
            };

            // Subject: from the CSR when signing, else from the form.
            let x509_subject = match (&req_rec, &subject_rows) {
                (Some(r), _) => crypto::clone_name(
                    crypto::load_req(&r.pem)?.subject_name(),
                )?,
                (None, Some((cn, org, org_unit, country, email))) => SubjectData {
                    cn: row_text(cn).trim().to_string(),
                    org: row_text(org).trim().to_string(),
                    org_unit: row_text(org_unit).trim().to_string(),
                    country: row_text(country).trim().to_string(),
                    email: row_text(email).trim().to_string(),
                }
                .build_name()?,
                (None, None) => return Err("Internal error: no subject source".into()),
            };

            // Public key going into the certificate.
            let (pubkey, key_id, own_key): (PKey<Public>, Option<i64>, Option<PKey<Private>>) =
                match (&req_rec, &key_rows) {
                    (Some(r), _) => {
                        let req = crypto::load_req(&r.pem)?;
                        let pk = req
                            .public_key()
                            .map_err(|e| format!("{}: {e}", tr!("Request key error")))?;
                        let kid = match r.key_id {
                            Some(id) => {
                                let stored = {
                                    let db = app2.db.lock().unwrap();
                                    db.get_key(id).ok().flatten()
                                };
                                match stored {
                                    Some(k) if {
                                        let stored_key = crypto::load_private_key(&k.pem);
                                        stored_key
                                            .map(|sk| crypto::same_public_key(pk.as_ref(), sk.as_ref()))
                                            .unwrap_or(false)
                                    } =>
                                    {
                                        Some(id)
                                    }
                                    _ => None,
                                }
                            }
                            None => None,
                        };
                        (pk, kid, None)
                    }
                    (None, Some((key_row, key_ids))) => {
                        let sel = key_row.selected() as usize;
                        match key_ids.get(sel).copied().flatten() {
                            Some(id) => {
                                let rec = {
                                    let db = app2.db.lock().unwrap();
                                    db.get_key(id).ok().flatten()
                                };
                                let rec = rec.ok_or(tr!("Selected key disappeared"))?;
                                let key = crypto::load_private_key(&rec.pem)?;
                                let pub_only = crypto::public_of(key.as_ref())?;
                                (pub_only, Some(id), Some(key))
                            }
                            None => {
                                let kind = match sel {
                                    1 => crypto::NewKeyKind::EcP256,
                                    2 => crypto::NewKeyKind::Ed25519,
                                    _ => crypto::NewKeyKind::Rsa2048,
                                };
                                let key = crypto::generate_key(kind)?;
                                let pem = key
                                    .private_key_to_pem_pkcs8()
                                    .map_err(|e| e.to_string())?;
                                let key_label = {
                                    let typed = row_text(&name_row).trim().to_string();
                                    if typed.is_empty() { kind.label().to_string() } else { typed }
                                };
                                let id = {
                                    let db = app2.db.lock().unwrap();
                                    db.insert_key(&key_label, &pem)
                                        .map_err(|e| e.to_string())?
                                };
                                let pub_only = crypto::public_of(key.as_ref())?;
                                (pub_only, Some(id), Some(key))
                            }
                        }
                    }
                    (None, None) => return Err("Internal error: no key source".into()),
                };

            // Issuer / signing key.
            let sel = issuer_row.selected() as usize;
            let (issuer_cert, issuer_key, issuer_id): (
                Option<openssl::x509::X509>,
                PKey<Private>,
                Option<i64>,
            ) =
                match issuer_ids.get(sel).copied().flatten() {
                    None => match own_key {
                        Some(k) => (None, k, None),
                    None => {
                        return Err(tr!(
                            "Self-signing needs a private key (generate or pick one)"
                        ))
                    }
                    },
                    Some(ca_id) => {
                        let (ca_rec, key_rec) = {
                            let db = app2.db.lock().unwrap();
                            let ca = db
                                .get_cert(ca_id)
                                .ok()
                                .flatten()
                                .ok_or(tr!("Issuing CA not found"))?;
                            let key = match ca.key_id {
                                Some(kid) => db.get_key(kid).ok().flatten(),
                                None => None,
                            }
                            .ok_or(tr!("The CA has no private key in the database"))?;
                            (ca, key)
                        };
                        let cert = crypto::load_cert(&ca_rec.pem)?;
                        let key = crypto::load_private_key(&key_rec.pem)?;
                        (Some(cert), key, Some(ca_id))
                    }
                };

            let cert = crypto::build_certificate(
                &x509_subject,
                pubkey.as_ref(),
                issuer_key.as_ref(),
                issuer_cert.as_ref().map(|c| c.as_ref()),
                &params,
            )?;

            let verified = match &issuer_cert {
                Some(c) => c
                    .public_key()
                    .ok()
                    .and_then(|p| cert.verify(p.as_ref()).ok()),
                None => cert.verify(pubkey.as_ref()).ok(),
            };
            // A verification *error* must not pass as success either.
            if verified != Some(true) {
                return Err(tr!("Signature verification failed"));
            }

            let s = crypto::cert_summary(cert.as_ref());
            let typed = row_text(&name_row).trim().to_string();
            let name = if typed.is_empty() {
                s.serial.chars().take(8).collect::<String>()
            } else {
                typed
            };
            let pem = cert.to_pem().map_err(|e| e.to_string())?;
            let rec = CertRecord {
                id: 0,
                name,
                subject: s.subject,
                issuer: s.issuer,
                serial: s.serial,
                not_after: s.not_after,
                expires_days: s.expires_days,
                ca: s.is_ca,
                key_id,
                issuer_id,
                pem,
            };
            let db = app2.db.lock().unwrap();
            db.insert_cert(&rec).map_err(|e| e.to_string())?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("Certificate created"));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

/// Token mode: create a self-signed CA whose private key stays on a PKCS#11
/// token (signed on the token, DER assembled locally).
pub fn open_token(
    app: &App,
    token: std::rc::Rc<crate::pkcs11::Token>,
    key: crate::pkcs11::TokenKey,
) {
    let form = form_dialog(&tr!("CA from Token Key"), 500);

    let name_row = entry_default(&tr!("Internal Name"), &key.label);
    let cn = entry(&tr!("Common Name (CN)"));
    let org = entry(&tr!("Organization (O)"));
    let org_unit = entry(&tr!("Organizational Unit (OU)"));
    let country = entry(&tr!("Country (C)"));
    let email = entry(&tr!("E-Mail (emailAddress)"));

    let g_subj = form.group(&tr!("Token key “%{label}” (%{kind})", label = key.label.clone(), kind = key.kind.label()));
    g_subj.set_description(Some(&tr!(
        "Note: a CA created on a token cannot yet issue certificates or CRLs from xca-rs — its private key never leaves the token."
    )));
    g_subj.add(&name_row);
    g_subj.add(&cn);
    g_subj.add(&org);
    g_subj.add(&org_unit);
    g_subj.add(&country);
    g_subj.add(&email);

    let validity = spin(&tr!("Validity (days)"), 3650.0, 1.0, 36500.0, 1.0);
    let g_val = form.group(&tr!("Validity"));
    g_val.add(&validity);

    let san: Rc<RefCell<Vec<SanEntry>>> = Rc::new(RefCell::new(Vec::new()));
    let san_row = action_row(&tr!("Subject Alt Names"), &san_dlg::summary(&san.borrow()));
    let san_edit = gtk::Button::with_label(&tr!("Edit…"));
    san_edit.add_css_class("flat");
    san_edit.set_valign(gtk::Align::Center);
    san_row.add_suffix(&san_edit);
    {
        let app2 = app.clone();
        let san = san.clone();
        let san_row = san_row.clone();
        san_edit.connect_clicked(move |_| {
            let initial = san.borrow().clone();
            let san_row = san_row.clone();
            let san = san.clone();
            san_dlg::open_edit(&app2, initial, move |entries| {
                *san.borrow_mut() = entries;
                san_row.set_subtitle(&san_dlg::summary(&san.borrow()));
            });
        });
    }
    let g_ext = form.group(&tr!("Extensions"));
    g_ext.add(&san_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create on Token"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let name_row = name_row.clone();
    let cn = cn.clone();
    let org = org.clone();
    let org_unit = org_unit.clone();
    let country = country.clone();
    let email = email.clone();
    let validity = validity.clone();
    let san = san.clone();
    create.connect_clicked(move |_| {
        let result = (|| -> Result<(), String> {
            let subject = SubjectData {
                cn: row_text(&cn).trim().to_string(),
                org: row_text(&org).trim().to_string(),
                org_unit: row_text(&org_unit).trim().to_string(),
                country: row_text(&country).trim().to_string(),
                email: row_text(&email).trim().to_string(),
            };
            if subject.cn.is_empty() {
                return Err(tr!("Common Name is required"));
            }
            let params = crypto::CertParams {
                validity_days: validity.value() as u32,
                is_ca: true,
                san: san.borrow().iter().map(|e| e.to_raw()).collect(),
                ..Default::default()
            };
            let x509_name = subject.build_name()?;
            let cert =
                crate::pkcs11::build_certificate_on_token(&token, &key, &x509_name, &params)?;
            let s = crypto::cert_summary(cert.as_ref());
            let typed = row_text(&name_row).trim().to_string();
            let name = if typed.is_empty() {
                subject.cn.clone()
            } else {
                typed
            };
            let pem = cert.to_pem().map_err(|e| e.to_string())?;
            let rec = CertRecord {
                id: 0,
                name,
                subject: s.subject,
                issuer: s.issuer,
                serial: s.serial,
                not_after: s.not_after,
                expires_days: s.expires_days,
                ca: s.is_ca,
                key_id: None, // the private key stays on the token
                issuer_id: None,
                pem,
            };
            let db = app2.db.lock().unwrap();
            db.insert_cert(&rec).map_err(|e| e.to_string())?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("Token CA created (private key stays on the token)"));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
