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
    // current_page already resolves the SSH sub-page ("ssh-keys"/…).
    let page = app.current_page().unwrap_or_default();
    match page.as_str() {
        "keys" => export_key(app),
        "certs" => export_cert(app),
        "reqs" => export_req(app),
        "crls" => export_crl(app),
        "ssh-keys" => export_ssh_key(app),
        "ssh-certs" => export_ssh_cert(app),
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

/// SSH key export: the private container (openssh-key-v1, optionally
/// encrypted with its own password) or the plain public-key line.
fn export_ssh_key(app: &App) {
    let Some(rec) = app.selected_ssh_key() else {
        return app.toast(&tr!("Select a key first"));
    };
    if !rec.has_private {
        // Public-only keys get the same choice of target.
        let form = form_dialog(&tr!("Export SSH Key"), 400);
        let fmt_row = combo(
            &tr!("Format"),
            &[
                tr!("Public key (.pub)").as_str(),
                tr!("Into ~/.ssh").as_str(),
            ],
            0,
        );
        let g = form.group(&tr!("SSH Key"));
        g.set_description(Some(&tr!("Note: exporting the public part only")));
        g.add(&fmt_row);
        let cancel = form.close_button(&tr!("Cancel"));
        let next = form.apply_button(&tr!("Next…"));
        {
            let dlg = form.dlg.clone();
            cancel.connect_clicked(move |_| {
                dlg.close();
            });
        }
        let app2 = app.clone();
        let dlg = form.dlg.clone();
        let fmt_row = fmt_row.clone();
        let rec2 = rec.clone();
        next.connect_clicked(move |_| {
            dlg.close();
            if fmt_row.selected() == 1 {
                return ssh_storage_export(&app2, &rec2, false);
            }
            write_file(
                &app2,
                format!("{}\n", crate::ssh::public_line(&rec2.public, &rec2.comment))
                    .into_bytes(),
                format!("{}.pub", sanitize(&rec2.name)),
            );
        });
        form.dlg.present(Some(&app.window));
        return;
    }

    let form = form_dialog(&tr!("Export SSH Key"), 400);
    let fmt_row = combo(
        &tr!("Format"),
        &[
            tr!("Private key (OpenSSH)").as_str(),
            tr!("Public key (.pub)").as_str(),
            tr!("Into ~/.ssh").as_str(),
        ],
        0,
    );
    let g = form.group(&tr!("SSH Key"));
    g.add(&fmt_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let next = form.apply_button(&tr!("Next…"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let fmt_row = fmt_row.clone();
    next.connect_clicked(move |_| {
        dlg.close();
        match fmt_row.selected() {
            1 => write_file(
                &app2,
                format!("{}\n", crate::ssh::public_line(&rec.public, &rec.comment))
                    .into_bytes(),
                format!("{}.pub", sanitize(&rec.name)),
            ),
            2 => ssh_storage_export(&app2, &rec, true),
            _ => ssh_private_export(&app2, &rec),
        }
    });

    form.dlg.present(Some(&app.window));
}

/// Export a database key into ~/.ssh: asks for the file name and, when
/// a private part is exported (`with_private`), for a key password like
/// the new-key dialog (empty stores it open). Public-only keys write
/// just `<name>.pub`.
fn ssh_storage_export(app: &App, rec: &crate::db::SshKeyRecord, with_private: bool) {
    // The export continues in 'static closures — take an owned copy.
    let rec = rec.clone();
    let form = form_dialog(&tr!("Export to ~/.ssh"), 420);
    let name_row = super::entry_default(&tr!("File Name"), &sanitize(&rec.name));
    let g = form.group(&tr!("SSH Key"));
    g.set_description(Some(&tr!("The key is written to ~/.ssh (id-file and .pub).")));
    g.add(&name_row);
    // Password fields only exist for a private part.
    let (pw1, pw2) = if with_private {
        let pw1 = super::password_entry(&tr!("Key Password"));
        let pw2 = super::password_entry(&tr!("Repeat password"));
        let gp = form.group(&tr!("Key Password"));
        gp.set_description(Some(&tr!("Leave empty to store without a password.")));
        gp.add(&pw1);
        gp.add(&pw2);
        (Some(pw1), Some(pw2))
    } else {
        (None, None)
    };

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
    let name_row = name_row.clone();
    let (pw1, pw2) = (pw1.clone(), pw2.clone());
    export.connect_clicked(move |_| {
        let password = match (&pw1, &pw2) {
            (Some(a), Some(b)) => {
                let p = row_text(a);
                if p != row_text(b) {
                    return error_dialog(&app2.window, &tr!("Passwords do not match"));
                }
                p
            }
            _ => String::new(),
        };
        let result = (|| -> Result<String, String> {
            let name = row_text(&name_row).trim().to_string();
            if with_private {
                // Decrypt the private part outside the database lock.
                let key = {
                    let db = app2.db.lock().unwrap();
                    db.ssh_key_private(rec.id)
                        .map_err(|e| e.to_string())?
                        .ok_or(tr!("The key has no private part in the database"))?
                };
                crate::ssh::write_key_files(&name, &key, &rec.comment, &password)
                    .map_err(|e| e.to_string())?;
            } else {
                crate::ssh::write_public_file(&name, &rec.public, &rec.comment)
                    .map_err(|e| e.to_string())?;
            }
            Ok(name)
        })();
        match result {
            Ok(name) => {
                dlg.close();
                app2.rescan_ssh_storage();
                app2.toast(&crate::notify::key_written_ssh(&name));
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

/// Password prompt for the exported SSH private key (empty = no
/// encryption), then the save dialog.
fn ssh_private_export(app: &App, rec: &crate::db::SshKeyRecord) {
    // The save flow continues in 'static closures — take an owned copy.
    let rec = rec.clone();
    let key = {
        let db = app.db.lock().unwrap();
        match db.ssh_key_private(rec.id) {
            Ok(Some(k)) => k,
            Ok(None) => {
                return app.toast(&tr!("Note: exporting the public part only"));
            }
            Err(e) => return error_dialog(&app.window, &e),
        }
    };

    let form = form_dialog(&tr!("Export SSH Private Key"), 400);
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
    let pw1 = pw1.clone();
    let pw2 = pw2.clone();
    export.connect_clicked(move |_| {
        let a = row_text(&pw1);
        if a != row_text(&pw2) {
            return error_dialog(&app2.window, &tr!("Passwords do not match"));
        }
        match crate::ssh::encode_private_pem(&key, &rec.comment, &a) {
            Ok(pem) => {
                dlg.close();
                write_file(&app2, pem, sanitize(&rec.name));
            }
            Err(e) => error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

/// SSH certificate export: the `*-cert.pub` line sshd and ssh expect.
fn export_ssh_cert(app: &App) {
    let Some(rec) = app.selected_ssh_cert() else {
        return app.toast(&tr!("Select a certificate first"));
    };

    let form = form_dialog(&tr!("Export SSH Certificate"), 400);
    let fmt_row = combo(
        &tr!("Format"),
        &[
            tr!("Certificate File").as_str(),
            tr!("Into ~/.ssh").as_str(),
        ],
        0,
    );
    let g = form.group(&tr!("Certificate File"));
    g.add(&fmt_row);

    let cancel = form.close_button(&tr!("Cancel"));
    let next = form.apply_button(&tr!("Next…"));
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let dlg = form.dlg.clone();
    let fmt_row = fmt_row.clone();
    next.connect_clicked(move |_| {
        dlg.close();
        if fmt_row.selected() == 1 {
            return cert_storage_export(&app2, &rec);
        }
        write_file(
            &app2,
            format!("{}\n", crate::ssh::cert_line(&rec.cert, &rec.name)).into_bytes(),
            format!("{}-cert.pub", sanitize(&rec.name)),
        );
    });

    form.dlg.present(Some(&app.window));
}

/// Write a database certificate into ~/.ssh as `<name>-cert.pub`. The
/// line comment follows the subject key's comment, like ssh-keygen.
fn cert_storage_export(app: &App, rec: &crate::db::SshCertRecord) {
    // The export continues in 'static closures — take an owned copy.
    let rec = rec.clone();
    let subject_comment = {
        let db = app.db.lock().unwrap();
        rec.key_item
            .and_then(|id| db.get_ssh_key(id).ok().flatten())
            .map(|k| k.comment)
            .unwrap_or_default()
    };
    let form = form_dialog(&tr!("Export to ~/.ssh"), 400);
    let name_row = super::entry_default(&tr!("File Name"), &sanitize(&rec.name));
    let g = form.group(&tr!("Certificate File"));
    g.set_description(Some(&tr!("The certificate is written as <name>-cert.pub.")));
    g.add(&name_row);

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
    let name_row = name_row.clone();
    export.connect_clicked(move |_| {
        let result = (|| -> Result<String, String> {
            let name = row_text(&name_row).trim().to_string();
            let path = crate::ssh::write_cert_file(&name, &rec.cert, &subject_comment)
                .map_err(|e| e.to_string())?;
            Ok(path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default())
        })();
        match result {
            Ok(file) => {
                dlg.close();
                app2.rescan_ssh_storage();
                app2.toast(&crate::notify::cert_written_ssh(&file));
            }
            Err(e) => error_dialog(&app2.window, &e),
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
