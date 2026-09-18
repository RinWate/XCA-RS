//! PKCS#11 token dialog: connect to a module, list token keys, and use a
//! token key to create a self-signed CA (the private key never leaves the
//! token).

use super::{error_dialog, form_dialog, password_entry, row_text};
use crate::app::App;
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;
use std::cell::RefCell;
use std::rc::Rc;

const SETTING_MODULE: &str = "pkcs11-module";

pub fn open(app: &App) {
    let stored_module = app
        .db
        .lock()
        .unwrap()
        .get_setting(SETTING_MODULE)
        .unwrap_or_default();

    let form = form_dialog(&tr!("PKCS#11 Token"), 520);

    let module_row = super::entry_default(&tr!("Module path (.so)"), &stored_module);
    let pin_row = password_entry(&tr!("PIN"));
    let g_conn = form.group(&tr!("Connection"));
    g_conn.add(&module_row);
    g_conn.add(&pin_row);

    let g_keys = form.group(&tr!("Token Keys"));
    let hint = adw::ActionRow::builder()
        .title(tr!("No session"))
        .subtitle(tr!("Connect to list the private keys on the token."))
        .build();
    g_keys.add(&hint);

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let connect = {
        let b = gtk::Button::with_label(&tr!("Connect"));
        b.add_css_class("suggested-action");
        form.header.pack_end(&b);
        b
    };

    let app2 = app.clone();
    let module_row = module_row.clone();
    let pin_row = pin_row.clone();
    let keys_state: Rc<RefCell<Vec<crate::pkcs11::TokenKey>>> = Rc::new(RefCell::new(Vec::new()));
    let g_keys = g_keys.clone();
    let dlg = form.dlg.clone();
    connect.connect_clicked(move |_| {
        let module = row_text(&module_row).trim().to_string();
        if module.is_empty() {
            return error_dialog(&app2.window, &tr!("Enter the PKCS#11 module path"));
        }
        let pin = row_text(&pin_row);
        let tok = match crate::pkcs11::connect(&module, &pin) {
            Ok(t) => t,
            Err(e) => return error_dialog(&app2.window, &e),
        };
        let found = match crate::pkcs11::list_keys(&tok) {
            Ok(k) => k,
            Err(e) => return error_dialog(&app2.window, &e),
        };
        let _ = app2.db.lock().unwrap().set_setting(SETTING_MODULE, &module);
        let token_label = tok.token_label.clone();

        // Rebuild the keys group.
        while let Some(child) = g_keys.first_child() {
            g_keys.remove(&child);
        }
        if found.is_empty() {
            let none = adw::ActionRow::builder()
                .title(tr!("No private keys on this token"))
                .build();
            g_keys.add(&none);
        }
        *keys_state.borrow_mut() = found;

        for idx in 0..keys_state.borrow().len() {
            let (title, subtitle) = {
                let keys = keys_state.borrow();
                let key = &keys[idx];
                let title = if key.label.is_empty() {
                    tr!("Key #%{idx}", idx = idx as i64)
                } else {
                    key.label.clone()
                };
                let subtitle = format!(
                    "{} · id {}{}",
                    key.kind.label(),
                    if key.id_hex.is_empty() { "-" } else { key.id_hex.as_str() },
                    if key.spki.is_some() {
                        format!(" · {}", tr!("public key resolved"))
                    } else {
                        format!(" · {}", tr!("public key unreadable"))
                    }
                );
                (title, subtitle)
            };
            let row = adw::ActionRow::builder()
                .title(title)
                .subtitle(subtitle)
                .build();
            let use_btn = gtk::Button::with_label(&tr!("Create CA…"));
            use_btn.add_css_class("suggested-action");
            use_btn.set_valign(gtk::Align::Center);
            row.add_suffix(&use_btn);

            {
                let app3 = app2.clone();
                let token = tok.clone();
                let keys_snapshot = keys_state.clone();
                let dlg2 = dlg.clone();
                use_btn.connect_clicked(move |_| {
                    let key = keys_snapshot.borrow()[idx].clone();
                    dlg2.close();
                    super::new_cert::open_token(&app3, token.clone(), key);
                });
            }
            g_keys.add(&row);
        }

        g_keys.set_title(&tr!(
            "Token “%{label}”, %{count} key(s)",
            label = token_label,
            count = keys_state.borrow().len() as i64
        ));
    });

    form.dlg.present(Some(&app.window));
}
