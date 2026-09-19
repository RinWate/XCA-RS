//! "New CRL" dialog: pick a CA, choose validity, generate a CRL containing
//! all revoked serials of that CA.

use super::{action_row, combo_ids, entry_default, error_dialog, form_dialog, spin};
use crate::app::App;
use crate::crypto;
use crate::db::CrlRecord;
use crate::tr;
use gtk::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

pub fn open(app: &App) {
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
    if cas.is_empty() {
        return error_dialog(
            &app.window,
            &tr!("Generating a CRL requires a CA certificate with its private key in the database."),
        );
    }

    let form = form_dialog(&tr!("New Revocation List"), 440);
    let (ca_row, ca_ids) = combo_ids(&tr!("Issuing CA"), &[], &cas, 0);
    super::combo_min_width(&ca_row, 400);
    let validity = spin(&tr!("Validity (days)"), 30.0, 1.0, 3650.0, 1.0);
    let revoked_hint = action_row(&tr!("Revoked entries"), "—");
    let g = form.group(&tr!("CRL"));
    g.add(&ca_row);
    g.add(&validity);
    g.add(&revoked_hint);

    // Show how many entries the CRL would contain for the selected CA.
    {
        let app2 = app.clone();
        let ca_ids = ca_ids.clone();
        let hint = revoked_hint.clone();
        let update = move |row: &adw::ComboRow| {
            let sel = row.selected() as usize;
            if let Some(ca_id) = ca_ids.get(sel).copied().flatten() {
                let n = app2.db.lock().unwrap().list_revoked(ca_id).map(|v| v.len()).unwrap_or(0);
                hint.set_subtitle(&tr!("%{count} certificate(s) will be listed", count = n as i64));
            }
        };
        update(&ca_row);
        ca_row.connect_notify_local(Some("selected"), move |row: &adw::ComboRow, _| update(row));
    }

    let name_row = entry_default(&tr!("Internal Name"), "CRL");
    let g2 = form.group(&tr!("Name"));
    g2.add(&name_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Generate"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let ca_row = ca_row.clone();
    let ca_ids = ca_ids.clone();
    let validity = validity.clone();
    let name_row = name_row.clone();
    create.connect_clicked(move |_| {
        let result = (|| -> Result<(), String> {
            let sel = ca_row.selected() as usize;
            let ca_id = ca_ids
                .get(sel)
                .copied()
                .flatten()
                .ok_or(tr!("Select the issuing CA"))?;
            let (ca_rec, key_rec, revoked) = {
                let db = app2.db.lock().unwrap();
                let ca = db
                    .get_cert(ca_id)
                    .ok()
                    .flatten()
                    .ok_or(tr!("CA not found"))?;
                let key = match ca.key_id {
                    Some(kid) => db.get_key(kid).ok().flatten(),
                    None => None,
                }
                .ok_or(tr!("The CA has no private key in the database"))?;
                let revoked = db
                    .list_revoked(ca_id)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .map(|r| r.serial.clone())
                    .collect::<Vec<_>>();
                (ca, key, revoked)
            };
            let ca_cert = crypto::load_cert(&ca_rec.pem)?;
            let ca_key = crypto::load_private_key(&key_rec.pem)?;
            // RFC 5280: the CRL number must grow monotonically per CA;
            // the counter lives in the XCA `authority` row.
            let crl_no = {
                let db = app2.db.lock().unwrap();
                db.next_crl_number(ca_id).map_err(|e| e.to_string())?
            };
            let crl = crypto::build_crl(
                ca_cert.as_ref(),
                ca_key.as_ref(),
                &revoked,
                validity.value() as u32,
                crl_no,
            )?;
            let issuer = crypto::name_to_string(crl.issuer_name());
            let next_update = crl.next_update().map(|t| t.to_string()).unwrap_or_default();
            let entries = crl.get_revoked().map(|s| s.len() as i64).unwrap_or(0);
            let pem = crl.to_pem().map_err(|e| e.to_string())?;
            let typed = super::row_text(&name_row).trim().to_string();
            let name = if typed.is_empty() {
                tr!("%{name} CRL", name = ca_rec.name.clone())
            } else {
                typed
            };
            let rec = CrlRecord {
                id: 0,
                name,
                ca_id,
                issuer,
                next_update,
                entries,
                pem,
            };
            let db = app2.db.lock().unwrap();
            db.insert_crl(&rec).map_err(|e| e.to_string())?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("CRL generated"));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
