//! SSH dialogs: new SSH key, new SSH certificate (issued by an SSH CA
//! key), and the properties views for both.

use super::{
    action_row, combo, combo_ids, entry, entry_default, error_dialog, form_dialog, row_text,
    spin, switch, text_block,
};
use crate::app::App;
use crate::db::{SshCertRecord, SshKeyRecord};
use crate::ssh;
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;

/// "New SSH Key": type/size pickers, comment and the CA flag.
pub fn open_new_key(app: &App) {
    if app.pages.ssh_from_storage.get() {
        return open_new_key_storage(app);
    }
    let form = form_dialog(&tr!("New SSH Key"), 440);

    let name_row = entry(&tr!("Internal Name"));
    let type_row = combo(
        &tr!("Key Type"),
        &["Ed25519", "RSA", "ECDSA"],
        0,
    );

    let sizes_ed = gtk::StringList::new(&["Ed25519"]);
    let sizes_rsa = gtk::StringList::new(&["2048", "3072", "4096"]);
    let sizes_ec = gtk::StringList::new(&["nistp256", "nistp384", "nistp521"]);
    let size_row = adw::ComboRow::builder().title(tr!("Key Size / Curve")).build();
    size_row.set_model(Some(&sizes_ed));
    size_row.set_expression(Some(&gtk::StringObject::this_expression("string")));

    {
        let size_row = size_row.clone();
        let (ed, rsa, ec) = (sizes_ed.clone(), sizes_rsa.clone(), sizes_ec.clone());
        type_row.connect_notify_local(Some("selected"), move |row: &adw::ComboRow, _| {
            let model = match row.selected() {
                1 => rsa.clone(),
                2 => ec.clone(),
                _ => ed.clone(),
            };
            size_row.set_model(Some(&model));
        });
    }

    let comment_row = entry(&tr!("Comment"));
    let ca_sw = switch(
        &tr!("CA key"),
        &tr!("Signs SSH certificates (ssh-keygen -s)"),
        false,
    );

    let g = form.group(&tr!("SSH Key"));
    g.add(&name_row);
    g.add(&type_row);
    g.add(&size_row);
    g.add(&comment_row);
    g.add(&ca_sw);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let hook_name = name_row.clone();
    let hook_ca = ca_sw.clone();
    let (name_row, type_row, size_row, comment_row, ca_sw) = (
        name_row.clone(),
        type_row.clone(),
        size_row.clone(),
        comment_row.clone(),
        ca_sw.clone(),
    );
    create.connect_clicked(move |_| {
        let kind = match (type_row.selected(), size_row.selected()) {
            (1, 1) => ssh::NewSshKind::Rsa3072,
            (1, 2) => ssh::NewSshKind::Rsa4096,
            (1, _) => ssh::NewSshKind::Rsa2048,
            (2, 1) => ssh::NewSshKind::EcdsaP384,
            (2, 2) => ssh::NewSshKind::EcdsaP521,
            (2, _) => ssh::NewSshKind::EcdsaP256,
            _ => ssh::NewSshKind::Ed25519,
        };
        let comment = row_text(&comment_row).trim().to_string();
        let typed = row_text(&name_row).trim().to_string();
        let label = if typed.is_empty() {
            kind.label().to_string()
        } else {
            typed
        };

        let result = (|| -> Result<(), String> {
            let key = kind.generate()?;
            let db = app2.db.lock().unwrap();
            db.insert_ssh_key(&label, ca_sw.is_active(), &key, &comment)
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("SSH key “%{name}” created", name = label.clone()));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    // Hidden UI-test hook: fill the form as an Ed25519 CA key and run the
    // real create handler (same pattern as the New Certificate dialog).
    if std::env::var("XCA_UI_TEST").as_deref() == Ok("newsshkey") {
        gtk::prelude::EditableExt::set_text(&hook_name, "ssh smoke ca");
        hook_ca.set_active(true);
        create.emit_clicked();
        return;
    }

    form.dlg.present(Some(&app.window));
}

/// Live subtitle for the validity preview row.
fn update_validity_preview(
    validity: &adw::SpinRow,
    unit_row: &adw::ComboRow,
    forever: &adw::SwitchRow,
    row: &adw::ActionRow,
) {
    if forever.is_active() {
        row.set_subtitle(&tr!("forever"));
    } else {
        let (from, to) = crate::crypto::validity_period(
            validity.value() as u32,
            crate::crypto::ValidityUnit::from_combo(unit_row.selected()),
        );
        row.set_subtitle(&tr!("from %{from} to %{to}", from = from, to = to));
    }
}

/// "New SSH Certificate": pick (or generate) the subject key, a CA key,
/// principals, validity and the certificate options.
pub fn open_new_cert(app: &App) {
    if app.pages.ssh_certs_from_storage.get() {
        return open_new_cert_storage(app);
    }
    let (cas, keys) = {
        let db = app.db.lock().unwrap();
        let keys = db.list_ssh_keys().unwrap_or_default();
        let cas: Vec<(i64, String, String)> = keys
            .iter()
            .filter(|k| k.is_ca && k.has_private)
            .map(|k| (k.id, k.name.clone(), k.type_label()))
            .collect();
        let named: Vec<(i64, String, String)> = keys
            .iter()
            .map(|k| (k.id, k.name.clone(), k.type_label()))
            .collect();
        (cas, named)
    };
    if cas.is_empty() {
        return error_dialog(
            &app.window,
            &tr!(
                "Issuing SSH certificates requires a CA key.\nCreate an SSH key with the “CA key” option first."
            ),
        );
    }

    let form = form_dialog(&tr!("New SSH Certificate"), 560);

    let name_row = entry(&tr!("Internal Name"));
    let (ca_row, ca_ids) = combo_ids(&tr!("Signing CA"), &[], &cas, 0);
    let (key_row, key_ids) = combo_ids(
        &tr!("Subject Key"),
        &[
            tr!("Generate new Ed25519").as_str(),
            tr!("Generate new RSA 3072").as_str(),
            tr!("Generate new ECDSA nistp256").as_str(),
        ],
        &keys,
        0,
    );

    let type_row = combo(
        &tr!("Certificate Type"),
        &[tr!("User").as_str(), tr!("Host").as_str()],
        0,
    );
    let key_id_row = entry(&tr!("Key ID"));

    let g_key = form.group(&tr!("Key"));
    g_key.add(&name_row);
    g_key.add(&ca_row);
    g_key.add(&key_row);
    let g_type = form.group(&tr!("Certificate"));
    g_type.add(&type_row);
    g_type.add(&key_id_row);

    // Principals: one per line, empty = valid for any principal.
    let principals_tv = gtk::TextView::new();
    principals_tv.set_wrap_mode(gtk::WrapMode::Word);
    principals_tv.set_top_margin(6);
    principals_tv.set_bottom_margin(6);
    principals_tv.set_left_margin(6);
    principals_tv.set_right_margin(6);
    let principals_sw = gtk::ScrolledWindow::new();
    principals_sw.set_child(Some(&principals_tv));
    principals_sw.set_height_request(96);
    principals_sw.set_hexpand(true);
    let g_pr = form.group(&tr!("Principals"));
    g_pr.set_description(Some(&tr!("One per line. Empty — valid for any user or host.")));
    g_pr.add(&principals_sw);

    // Serial: 0 assigns the next free serial of the CA.
    let serial_row = spin(&tr!("Serial"), 0.0, 0.0, 9_007_199_254_740_992.0, 1.0);
    serial_row.set_subtitle(&tr!("0 — assign automatically"));

    let validity = spin(&tr!("Validity"), 1.0, 1.0, 1000.0, 1.0);
    let unit_row = combo(
        &tr!("Validity Unit"),
        &[
            tr!("Days").as_str(),
            tr!("Weeks").as_str(),
            tr!("Months").as_str(),
            tr!("Years").as_str(),
        ],
        2,
    );
    let forever_sw = switch(&tr!("Valid forever"), "", false);
    let preview_row = action_row(&tr!("Period"), "");
    {
        let v = validity.clone();
        let u = unit_row.clone();
        let f = forever_sw.clone();
        let p = preview_row.clone();
        validity
            .connect_notify_local(Some("value"), move |_, _| {
                update_validity_preview(&v, &u, &f, &p);
            });
    }
    {
        let v = validity.clone();
        let u = unit_row.clone();
        let f = forever_sw.clone();
        let p = preview_row.clone();
        unit_row
            .connect_notify_local(Some("selected"), move |_, _| {
                update_validity_preview(&v, &u, &f, &p);
            });
    }
    {
        let v = validity.clone();
        let u = unit_row.clone();
        let f = forever_sw.clone();
        let p = preview_row.clone();
        forever_sw.connect_notify_local(Some("active"), move |_, _| {
            let forever = f.is_active();
            v.set_sensitive(!forever);
            u.set_sensitive(!forever);
            update_validity_preview(&v, &u, &f, &p);
        });
    }
    let g_val = form.group(&tr!("Validity"));
    g_val.add(&validity);
    g_val.add(&unit_row);
    g_val.add(&forever_sw);
    g_val.add(&serial_row);
    g_val.add(&preview_row);
    update_validity_preview(&validity, &unit_row, &forever_sw, &preview_row);

    // Critical options (force-command, source-address) and extensions,
    // matching ssh-keygen's option set.
    let force_row = entry(&tr!("force-command"));
    let source_row = entry(&tr!("source-address"));
    let critical_row = adw::ExpanderRow::builder()
        .title(tr!("Critical Options"))
        .build();
    critical_row.add_row(&force_row);
    critical_row.add_row(&source_row);

    let pty_sw = switch(&tr!("permit-pty"), "", true);
    let pf_sw = switch(&tr!("permit-port-forwarding"), "", true);
    let af_sw = switch(&tr!("permit-agent-forwarding"), "", true);
    let x11_sw = switch(&tr!("permit-X11-forwarding"), "", true);
    let rc_sw = switch(&tr!("permit-user-rc"), "", true);
    let ext_row = adw::ExpanderRow::builder().title(tr!("Extensions")).build();
    ext_row.add_row(&pty_sw);
    ext_row.add_row(&pf_sw);
    ext_row.add_row(&af_sw);
    ext_row.add_row(&x11_sw);
    ext_row.add_row(&rc_sw);

    let g_opt = form.group(&tr!("Options"));
    g_opt.add(&critical_row);
    g_opt.add(&ext_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let hook_key_id = key_id_row.clone();
    let hook_principals = principals_tv.clone();
    let (name_row, ca_row, ca_ids, key_row, key_ids) = (
        name_row.clone(),
        ca_row.clone(),
        ca_ids.clone(),
        key_row.clone(),
        key_ids.clone(),
    );
    let (type_row, key_id_row, principals_tv, serial_row) = (
        type_row.clone(),
        key_id_row.clone(),
        principals_tv.clone(),
        serial_row.clone(),
    );
    let (validity, unit_row, forever_sw) =
        (validity.clone(), unit_row.clone(), forever_sw.clone());
    let (force_row, source_row) = (force_row.clone(), source_row.clone());
    let (pty_sw, pf_sw, af_sw, x11_sw, rc_sw) = (
        pty_sw.clone(),
        pf_sw.clone(),
        af_sw.clone(),
        x11_sw.clone(),
        rc_sw.clone(),
    );
    create.connect_clicked(move |_| {
        let result = (|| -> Result<(), String> {
            let (subject_blob, key_item) = {
                let sel = key_row.selected() as usize;
                match key_ids.get(sel).copied().flatten() {
                    Some(id) => {
                        let db = app2.db.lock().unwrap();
                        let rec = db
                            .get_ssh_key(id)
                            .ok()
                            .flatten()
                            .ok_or(tr!("Selected key disappeared"))?;
                        (rec.public, Some(id))
                    }
                    None => {
                        let kind = match sel {
                            1 => ssh::NewSshKind::Rsa3072,
                            2 => ssh::NewSshKind::EcdsaP256,
                            _ => ssh::NewSshKind::Ed25519,
                        };
                        let key = kind.generate()?;
                        let blob = ssh::pubkey_blob(&key)?;
                        let db = app2.db.lock().unwrap();
                        let typed = row_text(&name_row).trim().to_string();
                        let label = if typed.is_empty() {
                            kind.label().to_string()
                        } else {
                            format!("{typed} — {}", kind.label())
                        };
                        let id = db
                            .insert_ssh_key(&label, false, &key, "")
                            .map_err(|e| e.to_string())?;
                        (blob, Some(id))
                    }
                }
            };

            let ca_sel = ca_row.selected() as usize;
            let Some(ca_id) = ca_ids.get(ca_sel).copied().flatten() else {
                return Err(tr!("No CA key selected").into());
            };
            let ca_key = {
                let db = app2.db.lock().unwrap();
                db.ssh_key_private(ca_id)
                    .map_err(|e| e.to_string())?
                    .ok_or(tr!("The CA key has no private part in the database"))?
            };

            let principals: Vec<String> = {
                let buf = principals_tv.buffer();
                buf.text(&buf.start_iter(), &buf.end_iter(), false)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            };

            let mut critical: Vec<(String, Option<String>)> = Vec::new();
            let force = row_text(&force_row).trim().to_string();
            if !force.is_empty() {
                critical.push(("force-command".into(), Some(force)));
            }
            let source = row_text(&source_row).trim().to_string();
            if !source.is_empty() {
                critical.push(("source-address".into(), Some(source)));
            }
            let mut extensions = Vec::new();
            for (sw, name) in [
                (&pty_sw, "permit-pty"),
                (&pf_sw, "permit-port-forwarding"),
                (&af_sw, "permit-agent-forwarding"),
                (&x11_sw, "permit-X11-forwarding"),
                (&rc_sw, "permit-user-rc"),
            ] {
                if sw.is_active() {
                    extensions.push(name.to_string());
                }
            }

            let now = ssh::now_secs();
            let valid_before = if forever_sw.is_active() {
                ssh::FOREVER
            } else {
                let days = crate::crypto::validity_days(
                    validity.value() as u32,
                    crate::crypto::ValidityUnit::from_combo(unit_row.selected()),
                ) as u64;
                now.saturating_add(days.saturating_mul(86_400))
            };
            let serial = if serial_row.value() as u64 == 0 {
                let db = app2.db.lock().unwrap();
                db.next_ssh_serial(ca_id).map_err(|e| e.to_string())?
            } else {
                serial_row.value() as u64
            };

            let typed_key_id = row_text(&key_id_row).trim().to_string();
            let key_id = if typed_key_id.is_empty() {
                principals.first().cloned().unwrap_or_else(|| "ssh-cert".into())
            } else {
                typed_key_id.clone()
            };

            let params = ssh::SshCertParams {
                serial,
                cert_type: if type_row.selected() == 1 {
                    ssh::SshCertType::Host
                } else {
                    ssh::SshCertType::User
                },
                key_id: key_id.clone(),
                principals,
                valid_after: now.saturating_sub(60), // a minute of clock skew
                valid_before,
                critical,
                extensions,
            };
            let cert = ssh::build_cert(&subject_blob, &ca_key, &params)?;

            let typed = row_text(&name_row).trim().to_string();
            let name = if typed.is_empty() { key_id } else { typed };
            let db = app2.db.lock().unwrap();
            db.insert_ssh_cert(&name, &cert, Some(ca_id), key_item, false)
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                app2.refresh();
                app2.toast(&tr!("SSH certificate created"));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    // Hidden UI-test hook: issue a certificate for the first principal
    // through the real create handler.
    if std::env::var("XCA_UI_TEST").as_deref() == Ok("newsshcert") {
        gtk::prelude::EditableExt::set_text(&hook_key_id, "ssh-smoke-id");
        hook_principals.buffer().set_text("smoke-user");
        create.emit_clicked();
        return;
    }

    form.dlg.present(Some(&app.window));
}

/// "New SSH Key" for ~/.ssh: asks for the file name and — as ssh-keygen
/// does — for the key password (empty stores the key unencrypted).
pub fn open_new_key_storage(app: &App) {
    let form = form_dialog(&tr!("New SSH Key"), 460);

    const DEFAULT_NAMES: [&str; 3] = ["id_ed25519", "id_rsa", "id_ecdsa"];
    let name_row = entry_default(&tr!("File Name"), DEFAULT_NAMES[0]);
    let type_row = combo(&tr!("Key Type"), &["Ed25519", "RSA", "ECDSA"], 0);

    let sizes_ed = gtk::StringList::new(&["Ed25519"]);
    let sizes_rsa = gtk::StringList::new(&["2048", "3072", "4096"]);
    let sizes_ec = gtk::StringList::new(&["nistp256", "nistp384", "nistp521"]);
    let size_row = adw::ComboRow::builder().title(tr!("Key Size / Curve")).build();
    size_row.set_model(Some(&sizes_ed));
    size_row.set_expression(Some(&gtk::StringObject::this_expression("string")));
    {
        let size_row = size_row.clone();
        let name_row = name_row.clone();
        let (ed, rsa, ec) = (sizes_ed.clone(), sizes_rsa.clone(), sizes_ec.clone());
        type_row.connect_notify_local(Some("selected"), move |row: &adw::ComboRow, _| {
            let (model, def) = match row.selected() {
                1 => (rsa.clone(), DEFAULT_NAMES[1]),
                2 => (ec.clone(), DEFAULT_NAMES[2]),
                _ => (ed.clone(), DEFAULT_NAMES[0]),
            };
            size_row.set_model(Some(&model));
            // Follow the default name while the user has not typed one.
            if DEFAULT_NAMES.contains(&row_text(&name_row).as_str()) {
                name_row.set_property("text", def);
            }
        });
    }

    let comment_row = entry(&tr!("Comment"));
    let pw1 = super::password_entry(&tr!("Key Password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));

    let g = form.group(&tr!("SSH Key"));
    g.set_description(Some(&tr!("The key is written to ~/.ssh (id-file and .pub).")));
    g.add(&name_row);
    g.add(&type_row);
    g.add(&size_row);
    g.add(&comment_row);
    let gp = form.group(&tr!("Key Password"));
    gp.set_description(Some(&tr!("Leave empty to store without a password.")));
    gp.add(&pw1);
    gp.add(&pw2);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let (name_row, type_row, size_row, comment_row, pw1, pw2) = (
        name_row.clone(),
        type_row.clone(),
        size_row.clone(),
        comment_row.clone(),
        pw1.clone(),
        pw2.clone(),
    );
    create.connect_clicked(move |_| {
        let a = row_text(&pw1);
        if a != row_text(&pw2) {
            return error_dialog(&app2.window, &tr!("Passwords do not match"));
        }
        let kind = match (type_row.selected(), size_row.selected()) {
            (1, 1) => ssh::NewSshKind::Rsa3072,
            (1, 2) => ssh::NewSshKind::Rsa4096,
            (1, _) => ssh::NewSshKind::Rsa2048,
            (2, 1) => ssh::NewSshKind::EcdsaP384,
            (2, 2) => ssh::NewSshKind::EcdsaP521,
            (2, _) => ssh::NewSshKind::EcdsaP256,
            _ => ssh::NewSshKind::Ed25519,
        };
        let result = (|| -> Result<String, String> {
            let name = row_text(&name_row).trim().to_string();
            if !ssh::valid_file_name(&name) {
                return Err(tr!("Invalid file name").into());
            }
            let key = kind.generate()?;
            ssh::write_key_files(&name, &key, row_text(&comment_row).trim(), &a)
                .map_err(|e| e.to_string())?;
            Ok(name)
        })();
        match result {
            Ok(name) => {
                app2.rescan_ssh_storage();
                app2.toast(&crate::notify::key_written_ssh(&name));
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    // Hidden UI-test hook: run the real create handler with the defaults
    // (id_ed25519, no password).
    if std::env::var("XCA_UI_TEST").as_deref() == Ok("newsshkeyfile") {
        create.emit_clicked();
        return;
    }

    form.dlg.present(Some(&app.window));
}

/// Where the signing CA of a ~/.ssh certificate comes from.
#[derive(Clone)]
enum CaSource {
    /// A private key file in ~/.ssh (password needed when encrypted).
    File { path: std::path::PathBuf, encrypted: bool },
    /// A database CA key.
    Db(i64),
}

/// "New SSH Certificate" for ~/.ssh: subject keys come from the storage,
/// the CA from ~/.ssh files or the database; the result is written as
/// `<key>-cert.pub` with a random serial (like ssh-keygen without -z).
pub fn open_new_cert_storage(app: &App) {
    let user_keys: Vec<ssh::UserKey> = app
        .pages
        .ssh_user_keys
        .borrow()
        .iter()
        .filter(|k| k.public_blob.is_some())
        .cloned()
        .collect();
    if user_keys.is_empty() {
        return error_dialog(
            &app.window,
            &tr!("Issuing a certificate requires a key in ~/.ssh.\nCreate the key first."),
        );
    }
    let (db_cas, file_cas) = {
        let db = app.db.lock().unwrap();
        let db_cas: Vec<(i64, String)> = db
            .list_ssh_keys()
            .unwrap_or_default()
            .into_iter()
            .filter(|k| k.is_ca && k.has_private)
            .map(|k| (k.id, k.name))
            .collect();
        let file_cas: Vec<ssh::UserKey> = app
            .pages
            .ssh_user_keys
            .borrow()
            .iter()
            .filter(|k| k.has_private)
            .cloned()
            .collect();
        (db_cas, file_cas)
    };

    let form = form_dialog(&tr!("New SSH Certificate"), 560);

    let subject_labels: Vec<String> = user_keys
        .iter()
        .map(|k| format!("{} — {}", k.file, k.kind_label))
        .collect();
    let subject_refs: Vec<&str> = subject_labels.iter().map(|s| s.as_str()).collect();
    let subject_row = combo(&tr!("Subject Key"), &subject_refs, 0);

    let mut ca_labels: Vec<String> = Vec::new();
    let mut ca_sources: Vec<CaSource> = Vec::new();
    for k in &file_cas {
        let enc = if k.encrypted {
            format!(" · {}", tr!("encrypted"))
        } else {
            String::new()
        };
        ca_labels.push(format!("~/.ssh/{}{}", k.file, enc));
        ca_sources.push(CaSource::File {
            path: k.path.clone(),
            encrypted: k.encrypted,
        });
    }
    for (id, name) in &db_cas {
        ca_labels.push(format!("{name} ({})", tr!("Database")));
        ca_sources.push(CaSource::Db(*id));
    }
    if ca_sources.is_empty() {
        return error_dialog(
            &app.window,
            &tr!(
                "Issuing SSH certificates requires a CA key.\nAny private key in ~/.ssh or a database CA key will do."
            ),
        );
    }
    let ca_refs: Vec<&str> = ca_labels.iter().map(|s| s.as_str()).collect();
    let ca_row = combo(&tr!("Signing CA"), &ca_refs, 0);

    let type_row = combo(
        &tr!("Certificate Type"),
        &[tr!("User").as_str(), tr!("Host").as_str()],
        0,
    );
    let key_id_row = entry(&tr!("Key ID"));

    let g_key = form.group(&tr!("Key"));
    g_key.add(&subject_row);
    g_key.add(&ca_row);
    let g_type = form.group(&tr!("Certificate"));
    g_type.add(&type_row);
    g_type.add(&key_id_row);

    let principals_tv = gtk::TextView::new();
    principals_tv.set_wrap_mode(gtk::WrapMode::Word);
    principals_tv.set_top_margin(6);
    principals_tv.set_bottom_margin(6);
    principals_tv.set_left_margin(6);
    principals_tv.set_right_margin(6);
    let principals_sw = gtk::ScrolledWindow::new();
    principals_sw.set_child(Some(&principals_tv));
    principals_sw.set_height_request(96);
    principals_sw.set_hexpand(true);
    let g_pr = form.group(&tr!("Principals"));
    g_pr.set_description(Some(&tr!("One per line. Empty — valid for any user or host.")));
    g_pr.add(&principals_sw);

    let validity = spin(&tr!("Validity"), 1.0, 1.0, 1000.0, 1.0);
    let unit_row = combo(
        &tr!("Validity Unit"),
        &[
            tr!("Days").as_str(),
            tr!("Weeks").as_str(),
            tr!("Months").as_str(),
            tr!("Years").as_str(),
        ],
        2,
    );
    let forever_sw = switch(&tr!("Valid forever"), "", false);
    let preview_row = action_row(&tr!("Period"), "");
    {
        let v = validity.clone();
        let u = unit_row.clone();
        let f = forever_sw.clone();
        let p = preview_row.clone();
        validity.connect_notify_local(Some("value"), move |_, _| {
            update_validity_preview(&v, &u, &f, &p);
        });
    }
    {
        let v = validity.clone();
        let u = unit_row.clone();
        let f = forever_sw.clone();
        let p = preview_row.clone();
        unit_row.connect_notify_local(Some("selected"), move |_, _| {
            update_validity_preview(&v, &u, &f, &p);
        });
    }
    {
        let v = validity.clone();
        let u = unit_row.clone();
        let f = forever_sw.clone();
        let p = preview_row.clone();
        forever_sw.connect_notify_local(Some("active"), move |_, _| {
            let forever = f.is_active();
            v.set_sensitive(!forever);
            u.set_sensitive(!forever);
            update_validity_preview(&v, &u, &f, &p);
        });
    }
    let g_val = form.group(&tr!("Validity"));
    g_val.add(&validity);
    g_val.add(&unit_row);
    g_val.add(&forever_sw);
    g_val.add(&preview_row);
    update_validity_preview(&validity, &unit_row, &forever_sw, &preview_row);

    let force_row = entry(&tr!("force-command"));
    let source_row = entry(&tr!("source-address"));
    let critical_row = adw::ExpanderRow::builder()
        .title(tr!("Critical Options"))
        .build();
    critical_row.add_row(&force_row);
    critical_row.add_row(&source_row);

    let pty_sw = switch(&tr!("permit-pty"), "", true);
    let pf_sw = switch(&tr!("permit-port-forwarding"), "", true);
    let af_sw = switch(&tr!("permit-agent-forwarding"), "", true);
    let x11_sw = switch(&tr!("permit-X11-forwarding"), "", true);
    let rc_sw = switch(&tr!("permit-user-rc"), "", true);
    let ext_row = adw::ExpanderRow::builder().title(tr!("Extensions")).build();
    ext_row.add_row(&pty_sw);
    ext_row.add_row(&pf_sw);
    ext_row.add_row(&af_sw);
    ext_row.add_row(&x11_sw);
    ext_row.add_row(&rc_sw);

    let g_opt = form.group(&tr!("Options"));
    g_opt.add(&critical_row);
    g_opt.add(&ext_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let create = form.apply_button(&tr!("Create"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let (subject_row, ca_row, type_row, key_id_row) = (
        subject_row.clone(),
        ca_row.clone(),
        type_row.clone(),
        key_id_row.clone(),
    );
    let (principals_tv, validity, unit_row, forever_sw) = (
        principals_tv.clone(),
        validity.clone(),
        unit_row.clone(),
        forever_sw.clone(),
    );
    let (force_row, source_row) = (force_row.clone(), source_row.clone());
    let (pty_sw, pf_sw, af_sw, x11_sw, rc_sw) = (
        pty_sw.clone(),
        pf_sw.clone(),
        af_sw.clone(),
        x11_sw.clone(),
        rc_sw.clone(),
    );
    create.connect_clicked(move |_| {
        let subject = user_keys
            .get(subject_row.selected() as usize)
            .cloned()
            .unwrap_or_else(|| user_keys[0].clone());
        let ca = ca_sources
            .get(ca_row.selected() as usize)
            .map(|src| match src {
                CaSource::File { path, encrypted } => CaSource::File {
                    path: path.clone(),
                    encrypted: *encrypted,
                },
                CaSource::Db(id) => CaSource::Db(*id),
            })
            .unwrap_or_else(|| ca_sources[0].clone());
        let principals: Vec<String> = {
            let buf = principals_tv.buffer();
            buf.text(&buf.start_iter(), &buf.end_iter(), false)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        };
        let mut extensions = Vec::new();
        for (sw, name) in [
            (&pty_sw, "permit-pty"),
            (&pf_sw, "permit-port-forwarding"),
            (&af_sw, "permit-agent-forwarding"),
            (&x11_sw, "permit-X11-forwarding"),
            (&rc_sw, "permit-user-rc"),
        ] {
            if sw.is_active() {
                extensions.push(name.to_string());
            }
        }
        let typed_key_id = row_text(&key_id_row).trim().to_string();
        let form = CertForm {
            key_id: if typed_key_id.is_empty() {
                principals.first().cloned().unwrap_or_else(|| "ssh-cert".into())
            } else {
                typed_key_id
            },
            subject,
            principals,
            forever: forever_sw.is_active(),
            days: validity.value() as u32,
            unit: unit_row.selected(),
            host: type_row.selected() == 1,
            force: row_text(&force_row).trim().to_string(),
            source: row_text(&source_row).trim().to_string(),
            extensions,
        };
        dlg.close();
        match ca {
            CaSource::Db(id) => {
                let key = {
                    let db = app2.db.lock().unwrap();
                    db.ssh_key_private(id)
                        .map_err(|e| e.to_string())
                        .and_then(|k| k.ok_or_else(|| {
                            tr!("The CA key has no private part in the database").to_string()
                        }))
                };
                match key {
                    Ok(k) => finish_storage_cert(&app2, &form, &k),
                    Err(e) => error_dialog(&app2.window, &e),
                }
            }
            CaSource::File { path, encrypted } => {
                let data = match std::fs::read(&path) {
                    Ok(d) => d,
                    Err(e) => return error_dialog(&app2.window, &e.to_string().as_str()),
                };
                if !encrypted {
                    return match ssh::parse_user_private(&data, "") {
                        Ok((k, _)) => finish_storage_cert(&app2, &form, &k),
                        Err(e) => error_dialog(&app2.window, &e),
                    };
                }
                // Ask for the CA key password, then finish.
                let pw_form = form_dialog(&tr!("Password Required"), 400);
                let pw = super::password_entry(&tr!("Password"));
                let g = pw_form.group(&tr!("Encrypted Key"));
                g.set_description(Some(&path.to_string_lossy()));
                g.add(&pw);
                let cancel = pw_form.close_button(&tr!("Cancel"));
                let ok = pw_form.apply_button(&tr!("Unlock"));
                {
                    let dlg = pw_form.dlg.clone();
                    cancel.connect_clicked(move |_| {
                        dlg.close();
                    });
                }
                let app3 = app2.clone();
                let dlg = pw_form.dlg.clone();
                let pw = pw.clone();
                ok.connect_clicked(move |_| {
                    dlg.close();
                    match ssh::parse_user_private(&data, &row_text(&pw)) {
                        Ok((k, _)) => finish_storage_cert(&app3, &form, &k),
                        Err(e) => error_dialog(&app3.window, &e),
                    }
                });
                pw_form.dlg.present(Some(&app2.window));
            }
        }
    });

    form.dlg.present(Some(&app.window));
}

/// Everything the ~/.ssh certificate dialog collected, resolved after
/// the CA private key is available (possibly through a password step).
struct CertForm {
    subject: ssh::UserKey,
    key_id: String,
    principals: Vec<String>,
    forever: bool,
    days: u32,
    unit: u32,
    host: bool,
    force: String,
    source: String,
    extensions: Vec<String>,
}

fn finish_storage_cert(
    app: &App,
    form: &CertForm,
    ca: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) {
    let result = (|| -> Result<String, String> {
        let blob = form
            .subject
            .public_blob
            .clone()
            .ok_or(tr!("Nothing to import: no key data"))?;
        let now = ssh::now_secs();
        let valid_before = if form.forever {
            ssh::FOREVER
        } else {
            let days = crate::crypto::validity_days(
                form.days,
                crate::crypto::ValidityUnit::from_combo(form.unit),
            ) as u64;
            now.saturating_add(days.saturating_mul(86_400))
        };
        let mut critical: Vec<(String, Option<String>)> = Vec::new();
        if !form.force.is_empty() {
            critical.push(("force-command".into(), Some(form.force.clone())));
        }
        if !form.source.is_empty() {
            critical.push(("source-address".into(), Some(form.source.clone())));
        }
        let cert = ssh::build_cert(
            &blob,
            ca,
            &ssh::SshCertParams {
                // No per-CA counter in ~/.ssh — random, like ssh-keygen
                // without -z.
                serial: ssh::random_serial(),
                cert_type: if form.host {
                    ssh::SshCertType::Host
                } else {
                    ssh::SshCertType::User
                },
                key_id: form.key_id.clone(),
                principals: form.principals.clone(),
                valid_after: now.saturating_sub(60),
                valid_before,
                critical,
                extensions: form.extensions.clone(),
            },
        )?;
        let path = ssh::write_cert_file(&form.subject.file, &cert, &form.subject.comment)
            .map_err(|e| e.to_string())?;
        Ok(path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default())
    })();
    match result {
        Ok(file) => {
            app.rescan_ssh_storage();
            app.toast(&crate::notify::cert_written_ssh(&file));
        }
        Err(e) => error_dialog(&app.window, &e),
    }
}

/// The option keys the host editor manages as named fields; everything
/// else travels through the free-form "other options" area.
const HOST_KNOWN_KEYS: [&str; 6] = [
    "HostName",
    "User",
    "Port",
    "IdentityFile",
    "CertificateFile",
    "ProxyJump",
];

/// Add or edit a Host block of ~/.ssh/config. `block_id` = None adds a
/// new host at the end of the file.
pub fn open_host_editor(app: &App, block_id: Option<usize>) {
    let existing = block_id.and_then(|bid| {
        let cfg = app.pages.ssh_config.borrow();
        cfg.host(bid).cloned()
    });
    let title = if existing.is_some() {
        tr!("Host Properties")
    } else {
        tr!("New Host")
    };
    let form = form_dialog(&title, 520);

    let field = |title: &str, key: &str| -> adw::EntryRow {
        let value = existing
            .as_ref()
            .and_then(|h| h.get(key))
            .unwrap_or("")
            .to_string();
        entry_default(title, &value)
    };
    let patterns_row = entry_default(
        &tr!("Host Aliases (space-separated)"),
        &existing
            .as_ref()
            .map(|h| h.patterns.clone())
            .unwrap_or_default(),
    );
    let hostname_row = field(&tr!("Address (HostName)"), "HostName");
    let user_row = field(&tr!("User"), "User");
    let port_row = field(&tr!("Port"), "Port");
    let proxy_row = field(&tr!("ProxyJump"), "ProxyJump");
    let identity_row = field(&tr!("Identity File (IdentityFile)"), "IdentityFile");
    let certfile_row = field(&tr!("Certificate File"), "CertificateFile");

    let g = form.group(&tr!("Host"));
    g.set_description(Some(&tr!("The block is written to ~/.ssh/config.")));
    g.add(&patterns_row);
    g.add(&hostname_row);
    g.add(&user_row);
    g.add(&port_row);
    g.add(&proxy_row);

    let g2 = form.group(&tr!("Key"));
    g2.add(&identity_row);
    g2.add(&certfile_row);

    let extras_tv = gtk::TextView::new();
    extras_tv.set_wrap_mode(gtk::WrapMode::Word);
    extras_tv.set_top_margin(6);
    extras_tv.set_bottom_margin(6);
    extras_tv.set_left_margin(6);
    extras_tv.set_right_margin(6);
    if let Some(h) = &existing {
        extras_tv
            .buffer()
            .set_text(&h.extra_options_text(&HOST_KNOWN_KEYS));
    }
    let extras_sw = gtk::ScrolledWindow::new();
    extras_sw.set_child(Some(&extras_tv));
    extras_sw.set_height_request(96);
    extras_sw.set_hexpand(true);
    let g3 = form.group(&tr!("Other Options"));
    g3.set_description(Some(&tr!("One “Key Value” per line; written to the config as is.")));
    g3.add(&extras_sw);

    let cancel = form.close_button(&tr!("Cancel"));
    let save = form.apply_button(&tr!("Save"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let block_id = block_id;
    let rows = (
        patterns_row.clone(),
        hostname_row.clone(),
        user_row.clone(),
        port_row.clone(),
        proxy_row.clone(),
        identity_row.clone(),
        certfile_row.clone(),
        extras_tv.clone(),
    );
    save.connect_clicked(move |_| {
        let (patterns_row, hostname_row, user_row, port_row, proxy_row, identity_row, certfile_row, extras_tv) =
            &rows;
        let result = (|| -> Result<(bool, String), String> {
            let patterns = row_text(patterns_row).trim().to_string();
            if patterns.is_empty() {
                return Err(tr!("The name cannot be empty").into());
            }
            let alias = patterns.split_whitespace().next().unwrap_or("").to_string();
            let mut entry = existing.clone().unwrap_or_default();
            entry.patterns = patterns;
            let fields = [
                (hostname_row, "HostName"),
                (user_row, "User"),
                (port_row, "Port"),
                (proxy_row, "ProxyJump"),
                (identity_row, "IdentityFile"),
                (certfile_row, "CertificateFile"),
            ];
            for (row, key) in fields {
                let value = row_text(row).trim().to_string();
                if value.is_empty() {
                    entry.remove(key);
                } else {
                    entry.set(key, &value);
                }
            }
            let buf = extras_tv.buffer();
            let extras = buf.text(&buf.start_iter(), &buf.end_iter(), false).to_string();
            entry.set_extra_options(&HOST_KNOWN_KEYS, &extras);

            let mut cfg = app2.pages.ssh_config.borrow_mut();
            match block_id {
                Some(bid) => {
                    if let Some(slot) = cfg.host_mut(bid) {
                        *slot = entry;
                    }
                }
                None => cfg.blocks.push(crate::sshconf::Block::Host(entry)),
            }
            crate::sshconf::save(&cfg).map_err(|e| e.to_string())?;
            Ok((block_id.is_some(), alias))
        })();
        match result {
            Ok((was_edit, alias)) => {
                app2.reload_ssh_hosts();
                let msg = if was_edit {
                    crate::notify::host_saved(&alias)
                } else {
                    crate::notify::host_added(&alias)
                };
                app2.toast(&msg);
                dlg.close();
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    // Hidden UI-test hook: add a host through the real save handler.
    if std::env::var("XCA_UI_TEST").as_deref() == Ok("newhost") && block_id.is_none() {
        patterns_row.set_property("text", "smoke-host");
        hostname_row.set_property("text", "smoke.example.com");
        save.emit_clicked();
        return;
    }

    form.dlg.present(Some(&app.window));
}

/// Properties of a key file from the user's ~/.ssh (read-only view):
/// what could be read without a password, plus the public line when it
/// is known.
pub fn open_details_user_key(app: &App, k: &ssh::UserKey) {
    let form = form_dialog(&tr!("SSH Key Properties"), 520);
    let g = form.group(&tr!("File"));
    g.add(&action_row(&tr!("Name"), &k.file));
    g.add(&action_row(&tr!("Path"), &k.path.to_string_lossy()));
    g.add(&action_row(&tr!("Type"), &k.kind_label));
    let mut state = Vec::new();
    if !k.has_private {
        state.push(tr!("public key only"));
    } else if k.encrypted {
        state.push(tr!("encrypted"));
    } else {
        state.push(tr!("private key available"));
    }
    if k.has_cert {
        state.push(tr!("certificate"));
    }
    g.add(&action_row(&tr!("Status"), &state.join(" · ")));
    g.add(&action_row(&tr!("Comment"), &k.comment));
    if let Some(blob) = &k.public_blob {
        g.add(&action_row(&tr!("Fingerprint"), &ssh::fingerprint(blob)));
    }

    if let Some(blob) = &k.public_blob {
        let g2 = form.group(&tr!("Public Key"));
        g2.set_description(Some(&tr!("Read from ~/.ssh; nothing is modified.")));
        g2.add(&text_block(&ssh::public_line(blob, &k.comment)));
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

/// Copy a ~/.ssh key into the database: public-only entries go straight
/// in, unencrypted private keys are parsed immediately, encrypted ones
/// ask for their password first.
pub fn import_user_key(app: &App) {
    let Some(k) = app.selected_user_key() else {
        return app.toast(&tr!("Select a key first"));
    };
    if !k.has_private || !k.encrypted {
        return import_user_key_now(app, &k, "");
    }
    // Encrypted: ask for the password (kept in the dialog flow only).
    let form = form_dialog(&tr!("Import SSH Key"), 420);
    let pw = super::password_entry(&tr!("Password"));
    let g = form.group(&tr!("Encrypted Key"));
    g.set_description(Some(&k.path.to_string_lossy()));
    g.add(&pw);

    let cancel = form.close_button(&tr!("Cancel"));
    let ok = form.apply_button(&tr!("Import"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let pw = pw.clone();
    let k = k.clone();
    ok.connect_clicked(move |_| {
        dlg.close();
        import_user_key_now(&app2, &k, &super::row_text(&pw));
    });
    form.dlg.present(Some(&app.window));
}

fn import_user_key_now(app: &App, k: &ssh::UserKey, password: &str) {
    let result = (|| -> Result<(), String> {
        // File reading and (for encrypted keys) bcrypt decryption happen
        // before the database lock — the UI must not freeze behind it.
        enum Prepared {
            PublicOnly(Vec<u8>, String),
            Private(openssl::pkey::PKey<openssl::pkey::Private>, Vec<u8>, String),
        }
        let prepared = if !k.has_private {
            let Some(blob) = k.public_blob.clone() else {
                return Err(tr!("Nothing to import: no key data").into());
            };
            Prepared::PublicOnly(blob, k.comment.clone())
        } else {
            let data = std::fs::read(&k.path).map_err(|e| e.to_string())?;
            let (pkey, comment) = ssh::parse_user_private(&data, password)?;
            let blob = ssh::pubkey_blob(&pkey)?;
            let comment = if comment.is_empty() { k.comment.clone() } else { comment };
            Prepared::Private(pkey, blob, comment)
        };
        let db = app.db.lock().unwrap();
        match prepared {
            Prepared::PublicOnly(blob, comment) => {
                if db.ssh_key_exists(&blob).unwrap_or(false) {
                    return Err(tr!("This key is already in the database").into());
                }
                db.insert_ssh_public_key(&k.file, &blob, &comment)
                    .map_err(|e| e.to_string())?;
            }
            Prepared::Private(pkey, blob, comment) => {
                if db.ssh_key_exists(&blob).unwrap_or(false) {
                    return Err(tr!("This key is already in the database").into());
                }
                db.insert_ssh_key(&k.file, false, &pkey, &comment)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            app.refresh();
            app.toast(&crate::notify::key_imported_db(&k.file));
        }
        Err(e) => super::error_dialog(&app.window, &e),
    }
}

/// Properties of an SSH key.
pub fn open_details_key(app: &App, rec: &SshKeyRecord) {
    let form = form_dialog(&tr!("SSH Key Properties"), 520);
    let g = form.group(&tr!("SSH Key"));
    g.add(&action_row(&tr!("Internal Name"), &rec.name));
    g.add(&action_row(&tr!("Type"), &rec.type_label()));
    g.add(&action_row(
        &tr!("Purpose"),
        &if rec.is_ca {
            tr!("CA — signs SSH certificates")
        } else {
            tr!("Regular key")
        },
    ));
    g.add(&action_row(&tr!("Comment"), &rec.comment));
    let private_state = if rec.has_private {
        tr!("stored in the database")
    } else {
        tr!("not available (public part only)")
    };
    g.add(&action_row(&tr!("Private Key"), &private_state));
    g.add(&action_row(&tr!("Fingerprint"), &ssh::fingerprint(&rec.public)));

    let g2 = form.group(&tr!("Public Key"));
    g2.set_description(Some(&tr!("Paste into authorized_keys or known_hosts.")));
    g2.add(&text_block(&ssh::public_line(&rec.public, &rec.comment)));

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| {
            dlg.close();
        });
    }
    form.dlg.present(Some(&app.window));
}

/// Properties of a certificate file from the user's ~/.ssh (read-only
/// view): the parsed fields plus file location; the CA and subject key
/// names are resolved by blob match when they are in the database.
pub fn open_details_user_cert(app: &App, uc: &ssh::UserCert) {
    let cert = &uc.cert;
    let (ca_name, key_name) = {
        let db = app.db.lock().unwrap();
        let keys = db.list_ssh_keys().unwrap_or_default();
        let ca = keys
            .iter()
            .find(|k| k.is_ca && k.public == cert.ca_blob)
            .map(|k| k.name.clone());
        let key = keys
            .iter()
            .find(|k| k.public == cert.public_blob)
            .map(|k| k.name.clone());
        (ca, key)
    };

    let form = form_dialog(&tr!("SSH Certificate Properties"), 560);
    let g = form.group(&tr!("File"));
    g.add(&action_row(&tr!("Name"), &uc.file));
    g.add(&action_row(&tr!("Path"), &uc.path.to_string_lossy()));
    g.add(&action_row(&tr!("Comment"), &uc.comment));

    let gc = form.group(&tr!("SSH Certificate"));
    gc.add(&action_row(&tr!("Key ID"), &cert.key_id));
    gc.add(&action_row(
        &tr!("Type"),
        &if cert.cert_type == ssh::SshCertType::Host {
            tr!("Host")
        } else {
            tr!("User")
        },
    ));
    gc.add(&action_row(&tr!("Serial"), &cert.serial.to_string()));
    gc.add(&action_row(&tr!("Key Type"), &ssh::describe_blob(&cert.public_blob)));
    gc.add(&action_row(&tr!("Fingerprint"), &ssh::fingerprint(&cert.blob)));
    let ca_label = match ca_name {
        Some(n) => n,
        None => tr!("not in the database"),
    };
    gc.add(&action_row(&tr!("Signing CA"), &ca_label));
    let key_label = match key_name {
        Some(n) => n,
        None => tr!("not in the database"),
    };
    gc.add(&action_row(&tr!("Subject Key"), &key_label));

    let g2 = form.group(&tr!("Validity"));
    g2.add(&action_row(&tr!("Valid After"), &ssh::format_time(cert.valid_after)));
    let valid_before = if cert.valid_before == ssh::FOREVER {
        tr!("forever")
    } else {
        ssh::format_time(cert.valid_before)
    };
    g2.add(&action_row(&tr!("Valid Before"), &valid_before));
    g2.add(&action_row(&tr!("Status"), &ssh::status_label(cert)));

    let g3 = form.group(&tr!("Principals"));
    if cert.principals.is_empty() {
        g3.set_description(Some(&tr!("Empty — valid for any user or host.")));
        g3.add(&action_row(&tr!("(any principal)"), ""));
    } else {
        for p in &cert.principals {
            g3.add(&action_row(p, ""));
        }
    }
    if !cert.critical.is_empty() {
        let g4 = form.group(&tr!("Critical Options"));
        for (name, value) in &cert.critical {
            g4.add(&action_row(name, value.as_deref().unwrap_or("")));
        }
    }
    if !cert.extensions.is_empty() {
        let g5 = form.group(&tr!("Extensions"));
        for name in &cert.extensions {
            g5.add(&action_row(name, ""));
        }
    }

    let g6 = form.group(&tr!("Certificate File"));
    g6.set_description(Some(&tr!("Read from ~/.ssh; nothing is modified.")));
    g6.add(&text_block(&ssh::cert_line(cert, &uc.comment)));

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| {
            dlg.close();
        });
    }
    form.dlg.present(Some(&app.window));
}

/// Copy a ~/.ssh certificate into the database, linking the CA and
/// subject keys when their blobs are present there.
pub fn import_user_cert(app: &App) {
    let Some(uc) = app.selected_user_cert() else {
        return app.toast(&tr!("Select a certificate first"));
    };
    let result = (|| -> Result<(), String> {
        let db = app.db.lock().unwrap();
        if db.ssh_cert_exists(&uc.cert.blob).unwrap_or(false) {
            return Err(tr!("This certificate is already in the database").into());
        }
        let keys = db.list_ssh_keys().map_err(|e| e.to_string())?;
        let ca_key = keys
            .iter()
            .find(|k| k.is_ca && k.public == uc.cert.ca_blob)
            .map(|k| k.id);
        let key_item = keys
            .iter()
            .find(|k| k.public == uc.cert.public_blob)
            .map(|k| k.id);
        let name = if uc.cert.key_id.is_empty() {
            uc.file.clone()
        } else {
            uc.cert.key_id.clone()
        };
        db.insert_ssh_cert(&name, &uc.cert, ca_key, key_item, true)
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            app.refresh();
            app.toast(&crate::notify::cert_imported_db(&uc.file));
        }
        Err(e) => super::error_dialog(&app.window, &e),
    }
}

/// Properties of an SSH certificate, mirroring ssh-keygen -L.
pub fn open_details_cert(app: &App, rec: &SshCertRecord) {
    let form = form_dialog(&tr!("SSH Certificate Properties"), 560);
    let cert = &rec.cert;

    // Resolve the CA and subject key names from the database links.
    let (ca_name, key_name) = {
        let db = app.db.lock().unwrap();
        let ca = rec
            .ca_key
            .and_then(|id| db.get_ssh_key(id).ok().flatten())
            .map(|k| k.name)
            .unwrap_or_default();
        let key = rec
            .key_item
            .and_then(|id| db.get_ssh_key(id).ok().flatten())
            .map(|k| k.name)
            .unwrap_or_default();
        (ca, key)
    };

    let g = form.group(&tr!("SSH Certificate"));
    g.add(&action_row(&tr!("Internal Name"), &rec.name));
    g.add(&action_row(
        &tr!("Type"),
        &if cert.cert_type == ssh::SshCertType::Host {
            tr!("Host")
        } else {
            tr!("User")
        },
    ));
    g.add(&action_row(&tr!("Key ID"), &cert.key_id));
    g.add(&action_row(&tr!("Serial"), &cert.serial.to_string()));
    let ca_label = if ca_name.is_empty() { tr!("not in the database") } else { ca_name };
    let key_label = if key_name.is_empty() { tr!("not in the database") } else { key_name };
    g.add(&action_row(&tr!("Signing CA"), &ca_label));
    g.add(&action_row(&tr!("Subject Key"), &key_label));
    g.add(&action_row(&tr!("Key Type"), &ssh::describe_blob(&cert.public_blob)));
    g.add(&action_row(&tr!("Fingerprint"), &ssh::fingerprint(&cert.blob)));

    let g2 = form.group(&tr!("Validity"));
    g2.add(&action_row(&tr!("Valid After"), &ssh::format_time(cert.valid_after)));
    let valid_before = if cert.valid_before == ssh::FOREVER {
        tr!("forever")
    } else {
        ssh::format_time(cert.valid_before)
    };
    g2.add(&action_row(&tr!("Valid Before"), &valid_before));
    g2.add(&action_row(&tr!("Status"), &ssh::status_label(cert)));

    let g3 = form.group(&tr!("Principals"));
    if cert.principals.is_empty() {
        g3.set_description(Some(&tr!("Empty — valid for any user or host.")));
        g3.add(&action_row(&tr!("(any principal)"), ""));
    } else {
        for p in &cert.principals {
            g3.add(&action_row(p, ""));
        }
    }

    if !cert.critical.is_empty() {
        let gc = form.group(&tr!("Critical Options"));
        for (name, value) in &cert.critical {
            gc.add(&action_row(name, value.as_deref().unwrap_or("")));
        }
    }
    if !cert.extensions.is_empty() {
        let ge = form.group(&tr!("Extensions"));
        for name in &cert.extensions {
            ge.add(&action_row(name, ""));
        }
    }

    let g4 = form.group(&tr!("Certificate File"));
    g4.set_description(Some(&tr!("For authorized_keys or the sshd TrustedUserCAKeys file.")));
    g4.add(&text_block(&ssh::cert_line(cert, &rec.name)));

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| {
            dlg.close();
        });
    }
    form.dlg.present(Some(&app.window));
}
