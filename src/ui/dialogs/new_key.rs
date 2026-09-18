//! "New Private Key" dialog: type + size selection, generation, storage.

use super::{combo, entry, error_dialog, form_dialog, row_text};
use crate::app::App;
use crate::crypto::{self, NewKeyKind};
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;

pub fn open(app: &App) {
    let form = form_dialog(&tr!("New Private Key"), 420);

    let name_row = entry(&tr!("Internal Name"));
    let type_row = combo(&tr!("Key Type"), &["RSA", "EC", "Ed25519"], 0);

    let sizes_rsa = gtk::StringList::new(&[&tr!("2048 bits"), &tr!("3072 bits"), &tr!("4096 bits")]);
    let sizes_ec = gtk::StringList::new(&["P-256", "P-384", "P-521"]);
    let sizes_ed = gtk::StringList::new(&["Ed25519"]);
    let size_row = adw::ComboRow::builder().title(tr!("Key Size / Curve")).build();
    size_row.set_model(Some(&sizes_rsa));
    size_row.set_expression(Some(&gtk::StringObject::this_expression("string")));

    {
        let size_row = size_row.clone();
        let ec = sizes_ec.clone();
        let ed = sizes_ed.clone();
        let rsa = sizes_rsa.clone();
        type_row.connect_notify_local(Some("selected"), move |row: &adw::ComboRow, _| {
            let model = match row.selected() {
                1 => ec.clone(),
                2 => ed.clone(),
                _ => rsa.clone(),
            };
            size_row.set_model(Some(&model));
        });
    }

    let group = form.group(&tr!("Private Key"));
    group.add(&name_row);
    group.add(&type_row);
    group.add(&size_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create"));

    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| { dlg.close(); });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let name_row = name_row.clone();
    let type_row = type_row.clone();
    let size_row = size_row.clone();
    create.connect_clicked(move |_| {
        let kind = NewKeyKind::from_combos(type_row.selected(), size_row.selected());
        let typed = row_text(&name_row).trim().to_string();
        let label = if typed.is_empty() {
            kind.label().to_string()
        } else {
            typed
        };

        let result = (|| -> Result<(), String> {
            let key = crypto::generate_key(kind)?;
            let (k, bits, curve) = crypto::key_info(key.as_ref());
            let pem = key
                .private_key_to_pem_pkcs8()
                .map_err(|e| format!("Encoding error: {e}"))?;
            let db = app2.db.lock().unwrap();
            db.insert_key(&label, &k, bits, &curve, &pem)
                .map_err(|e| e.to_string())?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("Key “%{name}” created", name = label.clone()));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
