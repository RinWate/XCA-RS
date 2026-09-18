//! "New Request" dialog: subject + key selection, CSR creation.

use super::{combo_ids, entry, error_dialog, form_dialog, row_text};
use crate::app::App;
use crate::crypto::{self, SubjectData};
use crate::db::ReqRecord;
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;

pub fn open(app: &App) {
    let form = form_dialog(&tr!("New Certificate Request"), 480);

    let name_row = entry(&tr!("Internal Name"));
    let cn = entry(&tr!("Common Name (CN)"));
    let org = entry(&tr!("Organization (O)"));
    let org_unit = entry(&tr!("Organizational Unit (OU)"));
    let country = entry(&tr!("Country (C)"));
    let email = entry(&tr!("E-Mail (emailAddress)"));

    let g_subj = form.group(&tr!("Subject"));
    g_subj.add(&name_row);
    g_subj.add(&cn);
    g_subj.add(&org);
    g_subj.add(&org_unit);
    g_subj.add(&country);
    g_subj.add(&email);

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
    let g_key = form.group(&tr!("Key"));
    g_key.add(&key_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create"));

    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| { dlg.close(); });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let name_row = name_row.clone();
    let cn = cn.clone();
    let org = org.clone();
    let org_unit = org_unit.clone();
    let country = country.clone();
    let email = email.clone();
    let key_row = key_row.clone();
    create.connect_clicked(move |_| {
        let subject = SubjectData {
            cn: row_text(&cn).trim().to_string(),
            org: row_text(&org).trim().to_string(),
            org_unit: row_text(&org_unit).trim().to_string(),
            country: row_text(&country).trim().to_string(),
            email: row_text(&email).trim().to_string(),
        };
        if subject.cn.is_empty() {
            return error_dialog(&app2.window, &tr!("Common Name is required"));
        }

        let sel = key_row.selected() as usize;
        let key_id = key_ids.get(sel).copied().flatten();
        let label = if row_text(&name_row).trim().is_empty() {
            subject.cn.clone()
        } else {
            row_text(&name_row).trim().to_string()
        };

        let result = (|| -> Result<(), String> {
            let (key, key_id) = match key_id {
                Some(id) => {
                    let db = app2.db.lock().unwrap();
                    let rec = db.get_key(id).map_err(|e| e.to_string())?;
                    drop(db);
                    let rec = rec.ok_or("Selected key disappeared")?;
                    (crypto::load_private_key(&rec.pem)?, Some(id))
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
                    // Name the stored key like new_cert does: the typed
                    // internal name, falling back to the CN.
                    let key_label = if label.trim().is_empty() {
                        subject.cn.clone()
                    } else {
                        label.trim().to_string()
                    };
                    let id = {
                        let db = app2.db.lock().unwrap();
                        db.insert_key(&key_label, &pem).map_err(|e| e.to_string())?
                    };
                    (key, Some(id))
                }
            };

            let name = label.clone();
            let x509_name = subject.build_name()?;
            let req = crypto::build_request(&x509_name, key.as_ref())?;
            let pem = req.to_pem().map_err(|e| e.to_string())?;
            let rec = ReqRecord {
                id: 0,
                name,
                subject: crypto::name_to_string(req.subject_name()),
                key_id,
                pem,
            };
            let db = app2.db.lock().unwrap();
            db.insert_req(&rec).map_err(|e| e.to_string())?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("Request “%{name}” created", name = label.clone()));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
