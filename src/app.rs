//! Application state shared by all widgets: database handle, main window,
//! list models. Also hosts the window-level actions (menu entries) and the
//! refresh/delete/about logic.

use crate::crypto;
use crate::db::{
    CertRecord, CrlRecord, Db, KeyRecord, ReqRecord, RevokedRecord, SshCertRecord, SshKeyRecord,
};
use crate::tr;
use crate::ui::dialogs;
use crate::ui::item::PkiItemObject;
use libadwaita::prelude::*;
use libadwaita as adw;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;

#[derive(Clone)]
pub struct App {
    pub db: Rc<Mutex<Db>>,
    pub db_path: PathBuf,
    /// True when the database is password-protected (XCA `pwhash`).
    pub password_protected: bool,
    pub window: adw::ApplicationWindow,
    pub pages: Rc<crate::ui::window::Pages>,
}

fn cert_badge(
    c: &CertRecord,
    revoked: &std::collections::HashMap<i64, std::collections::HashSet<String>>,
    parsed: Option<&openssl::x509::X509>,
) -> String {
    let mut badge = match parsed.map(|x| crypto::cert_summary(x)) {
        Some(s) => crypto::cert_status(&s),
        None => {
            let mut parts = Vec::new();
            if c.ca {
                parts.push("CA".to_string());
            }
            if c.expires_days < 0 {
                parts.push(tr!("expired"));
            }
            parts.join(" · ")
        }
    };
    // Revocation is tracked per issuing CA; serials alone collide across CAs.
    let ca = c.issuer_id.unwrap_or(c.id);
    if revoked.get(&ca).is_some_and(|s| s.contains(&c.serial)) {
        badge = if badge.is_empty() {
            tr!("REVOKED")
        } else {
            format!("{badge} · {}", tr!("REVOKED"))
        };
    }
    badge
}

impl App {
    pub fn toast(&self, msg: &str) {
        self.pages.toast.add_toast(adw::Toast::new(msg));
    }

    pub fn refresh(&self) {
        let db = self.db.lock().unwrap();
        let keys = db.list_keys().unwrap_or_default();
        let certs = db.list_certs().unwrap_or_default();
        let reqs = db.list_reqs().unwrap_or_default();
        let crls = db.list_crls().unwrap_or_default();
        let revoked: std::collections::HashMap<i64, std::collections::HashSet<String>> =
            db.revoked_serials_by_ca().unwrap_or_default();
        let ssh_keys = if self.pages.ssh_from_storage.get() {
            Vec::new() // the keys list reads ~/.ssh, not the database
        } else {
            db.list_ssh_keys().unwrap_or_default()
        };
        let ssh_certs = if self.pages.ssh_certs_from_storage.get() {
            Vec::new() // the certificates list reads ~/.ssh
        } else {
            db.list_ssh_certs().unwrap_or_default()
        };
        drop(db);

        self.pages.keys.remove_all();
        for k in keys {
            self.pages
                .keys
                .append(&PkiItemObject::new(k.id, &k.name, &k.type_label(), "", "", ""));
        }

        // The certificate page is a tree like the original XCA's: a CA
        // row holds the certificates it issued, recursively. Roots are
        // self-signed certificates and those whose issuer is not in the
        // database; children are grouped by their direct issuer.
        // Preserve the user's manual collapses across the rebuild.
        let collapsed: std::collections::HashSet<i64> = self.pages.certs_tree_collapsed();
        self.pages.certs.remove_all();
        let ids: std::collections::HashSet<i64> = certs.iter().map(|c| c.id).collect();
        let parents: std::collections::HashMap<i64, i64> = certs
            .iter()
            .filter_map(|c| {
                c.issuer_id
                    .filter(|i| *i != c.id && ids.contains(i))
                    .map(|i| (c.id, i))
            })
            .collect();
        let mut roots = Vec::new();
        let mut children_ids: std::collections::HashMap<i64, Vec<i64>> = std::collections::HashMap::new();
        for c in &certs {
            // Walk up to find a root; a runaway walk means an issuer
            // cycle — cut it by making this certificate a root.
            let mut cur = c.id;
            let mut steps = 0;
            loop {
                steps += 1;
                if steps > 100 {
                    cur = c.id;
                    break;
                }
                match parents.get(&cur) {
                    Some(p) => cur = *p,
                    None => break,
                }
            }
            if cur == c.id {
                roots.push(c.id);
            } else if let Some(p) = parents.get(&c.id) {
                children_ids.entry(*p).or_default().push(c.id);
            }
        }
        let mut objects = std::collections::HashMap::new();
        for c in &certs {
            let parsed = crypto::load_cert(&c.pem).ok();
            let badge = cert_badge(c, &revoked, parsed.as_ref());
            // The Issuer column stays readable: show the CN alone, the
            // full DN only when there is no CN.
            let issuer = parsed
                .as_ref()
                .and_then(|x| crypto::name_cn(x.issuer_name()))
                .filter(|cn| !cn.is_empty())
                .unwrap_or_else(|| c.issuer.clone());
            let sig = parsed
                .as_ref()
                .map(|x| crypto::signature_algorithm(x.as_ref()))
                .unwrap_or_default();
            objects.insert(
                c.id,
                PkiItemObject::new(c.id, &c.name, &c.subject, &issuer, &badge, &sig),
            );
        }
        *self.pages.certs_children.borrow_mut() = children_ids
            .iter()
            .map(|(parent, kids)| {
                let store = gtk::gio::ListStore::new::<PkiItemObject>();
                for id in kids {
                    if let Some(obj) = objects.get(id) {
                        store.append(obj);
                    }
                }
                (*parent, store)
            })
            .collect();
        for id in roots {
            if let Some(obj) = objects.get(&id) {
                self.pages.certs.append(obj);
            }
        }
        self.pages.restore_certs_collapsed(&collapsed);

        self.pages.reqs.remove_all();
        // A request is "signed" once some certificate in the database was
        // issued for the same public key (same rule as the original XCA).
        let cert_objs: Vec<openssl::x509::X509> = certs
            .iter()
            .filter_map(|c| crypto::load_cert(&c.pem).ok())
            .collect();
        for r in reqs {
            let signed = crypto::load_req(&r.pem)
                .ok()
                .is_some_and(|req| crypto::req_is_signed(req.as_ref(), &cert_objs));
            let status = if signed {
                tr!("Signed")
            } else {
                tr!("Not signed")
            };
            self.pages
                .reqs
                .append(&PkiItemObject::new(r.id, &r.name, &r.subject, &status, "", ""));
        }

        self.pages.crls.remove_all();
        for c in crls {
            let extra = tr!("%{count} entries", count = c.entries);
            self.pages.crls.append(&PkiItemObject::new(
                c.id,
                &c.name,
                &c.issuer,
                &c.next_update,
                &extra,
                "",
            ));
        }

        // The SSH pages: keys first (CA flag and private-part presence in
        // the badge), then certificates with their live validity.
        self.refresh_ssh_keys(&ssh_keys);
        self.refresh_ssh_certs(&ssh_certs);
        self.refresh_hosts();
    }

    /// Rebuild the SSH certificates list for the active source: the
    /// database or the user's ~/.ssh (read-only scan).
    fn refresh_ssh_certs(&self, ssh_certs: &[SshCertRecord]) {
        self.pages.ssh_certs.remove_all();
        if self.pages.ssh_certs_from_storage.get() {
            for (i, uc) in self.pages.ssh_user_certs.borrow().iter().enumerate() {
                let cert = &uc.cert;
                let ctype = if cert.cert_type == crate::ssh::SshCertType::Host {
                    tr!("Host")
                } else {
                    tr!("User")
                };
                let validity = if cert.valid_before == crate::ssh::FOREVER {
                    tr!("forever")
                } else {
                    crate::ssh::format_time(cert.valid_before)
                };
                self.pages.ssh_certs.append(&PkiItemObject::new(
                    i as i64,
                    &uc.file,
                    &cert.key_id,
                    &ctype,
                    &crate::ssh::status_label(cert),
                    &validity,
                ));
            }
            return;
        }
        for c in ssh_certs {
            let cert = &c.cert;
            let ctype = if cert.cert_type == crate::ssh::SshCertType::Host {
                tr!("Host")
            } else {
                tr!("User")
            };
            let validity = if cert.valid_before == crate::ssh::FOREVER {
                tr!("forever")
            } else {
                crate::ssh::format_time(cert.valid_before)
            };
            self.pages.ssh_certs.append(&PkiItemObject::new(
                c.id,
                &c.name,
                &cert.key_id,
                &ctype,
                &crate::ssh::status_label(cert),
                &validity,
            ));
        }
    }

    /// Switch the SSH certificates list between the database and the
    /// user's ~/.ssh; the storage side is rescanned on every switch.
    pub fn set_ssh_certs_source(&self, from_storage: bool) {
        if from_storage == self.pages.ssh_certs_from_storage.get() {
            return;
        }
        self.pages.ssh_certs_from_storage.set(from_storage);
        // Row ids mean different things per source — drop the selection
        // instead of letting it silently point at another item.
        self.pages
            .ssh_certs_sel
            .set_selected(gtk::INVALID_LIST_POSITION);
        let ssh_certs = if from_storage {
            *self.pages.ssh_user_certs.borrow_mut() = crate::ssh::scan_user_certs();
            Vec::new()
        } else {
            self.db.lock().unwrap().list_ssh_certs().unwrap_or_default()
        };
        self.refresh_ssh_certs(&ssh_certs);
    }

    /// Rebuild the SSH keys list for the active source: the database or
    /// the user's ~/.ssh (read-only scan).
    fn refresh_ssh_keys(&self, ssh_keys: &[SshKeyRecord]) {
        self.pages.ssh_keys.remove_all();
        if self.pages.ssh_from_storage.get() {
            for (i, k) in self.pages.ssh_user_keys.borrow().iter().enumerate() {
                let mut badge = Vec::new();
                if k.encrypted {
                    badge.push(tr!("encrypted"));
                }
                if k.has_cert {
                    badge.push(tr!("certificate"));
                }
                if k.pub_only {
                    badge.push(tr!("public key only"));
                }
                self.pages.ssh_keys.append(&PkiItemObject::new(
                    i as i64,
                    &k.file,
                    &k.kind_label,
                    &k.comment,
                    &badge.join(" · "),
                    "",
                ));
            }
            return;
        }
        for k in ssh_keys {
            let mut badge = Vec::new();
            if k.is_ca {
                badge.push("CA".to_string());
            }
            if !k.has_private {
                badge.push(tr!("no private key"));
            }
            self.pages.ssh_keys.append(&PkiItemObject::new(
                k.id,
                &k.name,
                &k.type_label(),
                &k.comment,
                &badge.join(" · "),
                "",
            ));
        }
    }

    /// Switch the SSH keys list between the database and the user's
    /// ~/.ssh; the storage side is rescanned on every switch.
    pub fn set_ssh_source(&self, from_storage: bool) {
        if from_storage == self.pages.ssh_from_storage.get() {
            return;
        }
        self.pages.ssh_from_storage.set(from_storage);
        // Row ids mean different things per source — drop the selection
        // instead of letting it silently point at another item.
        self.pages
            .ssh_keys_sel
            .set_selected(gtk::INVALID_LIST_POSITION);
        let ssh_keys = if from_storage {
            *self.pages.ssh_user_keys.borrow_mut() = crate::ssh::scan_user_ssh_dir();
            Vec::new()
        } else {
            self.db.lock().unwrap().list_ssh_keys().unwrap_or_default()
        };
        self.refresh_ssh_keys(&ssh_keys);
    }

    /// The active page id; the SSH section reports its visible sub-page
    /// ("ssh-keys" / "ssh-certs") so every dispatch keeps working.
    pub fn current_page(&self) -> Option<String> {
        let name = self.pages.stack.visible_child_name()?.to_string();
        if name == "ssh" {
            return Some(
                self.pages
                    .ssh_stack
                    .visible_child_name()
                    .map(|s| format!("ssh-{s}"))
                    .unwrap_or_else(|| "ssh".into()),
            );
        }
        Some(name)
    }

    pub fn selected_key(&self) -> Option<KeyRecord> {
        let id = crate::ui::columns::selected_id(&self.pages.keys_sel)?;
        self.db.lock().unwrap().get_key(id).ok().flatten()
    }

    pub fn selected_cert(&self) -> Option<CertRecord> {
        let id = crate::ui::columns::selected_id(&self.pages.certs_sel)?;
        self.db.lock().unwrap().get_cert(id).ok().flatten()
    }

    pub fn selected_req(&self) -> Option<ReqRecord> {
        let id = crate::ui::columns::selected_id(&self.pages.reqs_sel)?;
        self.db.lock().unwrap().get_req(id).ok().flatten()
    }

    pub fn selected_crl(&self) -> Option<CrlRecord> {
        let id = crate::ui::columns::selected_id(&self.pages.crls_sel)?;
        self.db.lock().unwrap().get_crl(id).ok().flatten()
    }

    pub fn selected_ssh_key(&self) -> Option<SshKeyRecord> {
        // In ~/.ssh mode the row ids are scan indexes, not items.id —
        // an accidental match would rename/delete the wrong key.
        if self.pages.ssh_from_storage.get() {
            return None;
        }
        let id = crate::ui::columns::selected_id(&self.pages.ssh_keys_sel)?;
        self.db.lock().unwrap().get_ssh_key(id).ok().flatten()
    }

    pub fn selected_ssh_cert(&self) -> Option<SshCertRecord> {
        // In ~/.ssh mode the row ids are scan indexes, not items.id.
        if self.pages.ssh_certs_from_storage.get() {
            return None;
        }
        let id = crate::ui::columns::selected_id(&self.pages.ssh_certs_sel)?;
        self.db.lock().unwrap().get_ssh_cert(id).ok().flatten()
    }

    /// The ~/.ssh certificate behind the selected row (storage mode only).
    pub fn selected_user_cert(&self) -> Option<crate::ssh::UserCert> {
        if !self.pages.ssh_certs_from_storage.get() {
            return None;
        }
        let idx = crate::ui::columns::selected_id(&self.pages.ssh_certs_sel)? as usize;
        self.pages.ssh_user_certs.borrow().get(idx).cloned()
    }

    /// The config block index of the selected host row.
    pub fn selected_host_block(&self) -> Option<usize> {
        let idx = crate::ui::columns::selected_id(&self.pages.hosts_sel)? as usize;
        self.pages.ssh_host_ids.borrow().get(idx).copied()
    }

    /// Rescan ~/.ssh (keys, certificates) and rebuild both SSH lists for
    /// their current sources. Called after every storage mutation.
    pub fn rescan_ssh_storage(&self) {
        *self.pages.ssh_user_keys.borrow_mut() = crate::ssh::scan_user_ssh_dir();
        *self.pages.ssh_user_certs.borrow_mut() = crate::ssh::scan_user_certs();
        let db = self.db.lock().unwrap();
        let keys = if self.pages.ssh_from_storage.get() {
            Vec::new()
        } else {
            db.list_ssh_keys().unwrap_or_default()
        };
        let certs = if self.pages.ssh_certs_from_storage.get() {
            Vec::new()
        } else {
            db.list_ssh_certs().unwrap_or_default()
        };
        drop(db);
        self.refresh_ssh_keys(&keys);
        self.refresh_ssh_certs(&certs);
    }

    /// Rebuild the hosts rows from the parsed ~/.ssh/config.
    pub fn refresh_hosts(&self) {
        let ids = self.pages.ssh_config.borrow().host_block_ids();
        self.pages.hosts.remove_all();
        for (i, &bid) in ids.iter().enumerate() {
            // Snapshot the display fields: `h` borrows the config while
            // append() may run nested GTK code.
            let row = {
                let cfg = self.pages.ssh_config.borrow();
                let Some(h) = cfg.host(bid) else { continue };
                let identity = h
                    .get("IdentityFile")
                    .map(|v| v.rsplit('/').next().unwrap_or(v).to_string())
                    .unwrap_or_default();
                (
                    // "Host" without patterns would show as empty.
                    if h.alias().is_empty() {
                        tr!("(no alias)")
                    } else {
                        h.alias().to_string()
                    },
                    h.get("HostName").unwrap_or("").to_string(),
                    h.get("User").unwrap_or("").to_string(),
                    h.get("Port").unwrap_or("").to_string(),
                    identity,
                )
            };
            self.pages.hosts.append(&PkiItemObject::new(
                i as i64,
                &row.0,
                &row.1,
                &row.2,
                &row.3,
                &row.4,
            ));
        }
        *self.pages.ssh_host_ids.borrow_mut() = ids;
    }

    /// Reload ~/.ssh/config from disk and rebuild the rows.
    pub fn reload_ssh_hosts(&self) {
        *self.pages.ssh_config.borrow_mut() = crate::sshconf::load();
        self.refresh_hosts();
    }

    /// Rename the selected ~/.ssh key (or certificate) file set. `cert`
    /// switches between the key pair files and the `-cert.pub` file.
    fn rename_storage_item(&self, cert: bool) {
        let title = if cert {
            tr!("Rename Certificate")
        } else {
            tr!("Rename Key")
        };
        let (current, apply): (String, Box<dyn Fn(&str) -> Result<Vec<String>, String>>) =
            if cert {
                let Some(c) = self.selected_user_cert() else {
                    return self.toast(&tr!("Select a certificate first"));
                };
                let base = c
                    .file
                    .strip_suffix("-cert.pub")
                    .unwrap_or(&c.file)
                    .to_string();
                let apply =
                    move |new: &str| crate::ssh::rename_cert_file(&c, new).map(|f| vec![f]);
                (base, Box::new(apply))
            } else {
                let Some(k) = self.selected_user_key() else {
                    return self.toast(&tr!("Select a key first"));
                };
                let current = k.file.clone();
                let apply = move |new: &str| crate::ssh::rename_key_files(&k, new);
                (current, Box::new(apply))
            };
        let dlg = adw::AlertDialog::new(Some(&title), None);
        let entry = gtk::Entry::new();
        entry.set_text(&current);
        dlg.set_extra_child(Some(&entry));
        dlg.set_default_response(Some("rename"));
        dlg.add_response("cancel", &tr!("Cancel"));
        dlg.add_response("rename", &tr!("Rename"));
        let app = self.clone();
        dlg.choose(
            Some(&self.window),
            None::<&gtk::gio::Cancellable>,
            move |resp| {
                if resp.as_str() != "rename" {
                    return;
                }
                let new = entry.text().trim().to_string();
                if new.is_empty() {
                    return dialogs::error_dialog(&app.window, &tr!("The name cannot be empty"));
                }
                match apply(&new) {
                    Ok(files) => {
                        app.rescan_ssh_storage();
                        app.toast(&crate::notify::renamed_ssh_files(&files));
                    }
                    Err(e) => dialogs::error_dialog(&app.window, &e),
                }
            },
        );
    }

    /// The ~/.ssh entry behind the selected keys row (storage mode only;
    /// row ids are indexes into the scan there).
    pub fn selected_user_key(&self) -> Option<crate::ssh::UserKey> {
        if !self.pages.ssh_from_storage.get() {
            return None;
        }
        let idx = crate::ui::columns::selected_id(&self.pages.ssh_keys_sel)? as usize;
        self.pages.ssh_user_keys.borrow().get(idx).cloned()
    }

    // ---- action entry points ----

    pub fn new_key_dialog(&self) {
        dialogs::new_key::open(self);
    }

    pub fn new_ssh_key_dialog(&self) {
        dialogs::ssh::open_new_key(self);
    }

    pub fn new_ssh_cert_dialog(&self) {
        dialogs::ssh::open_new_cert(self);
    }

    /// Copy the selected ~/.ssh key into the database (asks for the
    /// password when the private part is encrypted).
    pub fn import_selected_user_key(&self) {
        dialogs::ssh::import_user_key(self);
    }

    /// Copy the selected ~/.ssh certificate into the database.
    pub fn import_selected_user_cert(&self) {
        dialogs::ssh::import_user_cert(self);
    }

    pub fn new_host_dialog(&self) {
        dialogs::ssh::open_host_editor(self, None);
    }

    pub fn new_cert_dialog(&self) {
        dialogs::new_cert::open(self, None);
    }

    pub fn new_req_dialog(&self) {
        dialogs::new_req::open(self);
    }

    pub fn new_crl_dialog(&self) {
        dialogs::new_crl::open(self);
    }

    pub fn token_dialog(&self) {
        dialogs::token::open(self);
    }

    pub fn sign_file_dialog(&self) {
        dialogs::sign::open_sign(self);
    }

    pub fn verify_signature_dialog(&self) {
        dialogs::sign::open_verify(self);
    }

    pub fn password_dialog(&self) {
        dialogs::password::set_or_change(self);
    }

    /// Close the current window and open another database file (asks for
    /// its password if the file turns out to be encrypted).
    pub fn open_database(&self) {
        let dlg = gtk::FileDialog::builder()
            .title(tr!("Open Database"))
            .filters(&dialogs::db_file_filters())
            .build();
        let app = self.clone();
        dlg.open(
            Some(&self.window),
            None::<&gtk::gio::Cancellable>,
            move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else { return };
                if path == app.db_path {
                    return app.toast(&tr!("This database is already open"));
                }
                // Verify before closing the current window: a broken file
                // must not kill the running session.
                if let Err(crate::db::OpenError::Other(e)) = crate::db::Db::open(&path, None) {
                    return dialogs::error_dialog(&app.window, &e);
                }
                let Some(adw_app) = adw_app_of(&app) else { return };
                app.window.close();
                crate::launch::open_main(&adw_app, &path, None);
            },
        );
    }

    /// Close the current window and create a new database at a chosen path.
    pub fn new_database(&self) {
        let dlg = gtk::FileDialog::builder()
            .title(tr!("New Database"))
            .filters(&dialogs::db_file_filters())
            .accept_label(tr!("Create"))
            .initial_name("xca-rs.xdb")
            .build();
        let app = self.clone();
        dlg.save(
            Some(&self.window),
            None::<&gtk::gio::Cancellable>,
            move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else { return };
                if path.exists() {
                    return dialogs::error_dialog(
                        &app.window,
                        &tr!("The file already exists, choose another name"),
                    );
                }
                let Some(adw_app) = adw_app_of(&app) else { return };
                app.window.close();
                crate::ui::dialogs::password::setup_new(&adw_app, path);
            },
        );
    }

    /// Mark the selected certificate as revoked for its issuing CA.
    pub fn revoke_selected(&self) {
        let Some(c) = self.selected_cert() else {
            return self.toast(&tr!("Select a certificate first"));
        };
        let ca_id = c.issuer_id.unwrap_or(c.id);
        let now = crate::xca_format::now_plain();
        let res = {
            let db = self.db.lock().unwrap();
            db.insert_revoked(&RevokedRecord {
                ca_id,
                serial: c.serial.clone(),
                revoked_at: now,
                cert_id: Some(c.id),
                reason: String::new(),
            })
            .map_err(|e| e.to_string())
        };
        match res {
            Ok(()) => {
                self.refresh();
                self.toast(&tr!("Certificate “%{name}” revoked", name = c.name.clone()));
            }
            Err(e) => dialogs::error_dialog(&self.window, &e),
        }
    }

    /// Rename the selected key or certificate (its internal name).
    pub fn rename_selected(&self) {
        let (id, name, title) = match self.current_page().as_deref() {
            Some("keys") => match self.selected_key() {
                Some(k) => (k.id, k.name, tr!("Rename Key")),
                None => return self.toast(&tr!("Select a key first")),
            },
            Some("certs") => match self.selected_cert() {
                Some(c) => (c.id, c.name, tr!("Rename Certificate")),
                None => return self.toast(&tr!("Select a certificate first")),
            },
            // ~/.ssh mode renames the files instead of a database row.
            Some("ssh-keys") if self.pages.ssh_from_storage.get() => {
                return self.rename_storage_item(false)
            }
            Some("ssh-certs") if self.pages.ssh_certs_from_storage.get() => {
                return self.rename_storage_item(true)
            }
            Some("ssh-keys") => match self.selected_ssh_key() {
                Some(k) => (k.id, k.name, tr!("Rename Key")),
                None => return self.toast(&tr!("Select a key first")),
            },
            Some("ssh-certs") => match self.selected_ssh_cert() {
                Some(c) => (c.id, c.name, tr!("Rename Certificate")),
                None => return self.toast(&tr!("Select a certificate first")),
            },
            _ => return,
        };
        let dlg = adw::AlertDialog::new(Some(&title), None);
        let entry = gtk::Entry::new();
        entry.set_text(&name);
        dlg.set_extra_child(Some(&entry));
        dlg.set_default_response(Some("rename"));
        dlg.add_response("cancel", &tr!("Cancel"));
        dlg.add_response("rename", &tr!("Rename"));
        let app = self.clone();
        dlg.choose(
            Some(&self.window),
            None::<&gtk::gio::Cancellable>,
            move |resp| {
                if resp.as_str() != "rename" {
                    return;
                }
                let new = entry.text().trim().to_string();
                if new.is_empty() {
                    return dialogs::error_dialog(&app.window, &tr!("The name cannot be empty"));
                }
                if new == name {
                    return;
                }
                let res = app
                    .db
                    .lock()
                    .unwrap()
                    .rename_item(id, &new)
                    .map_err(|e| e.to_string());
                match res {
                    Ok(()) => {
                        app.refresh();
                        app.toast(&crate::notify::renamed_db());
                    }
                    Err(e) => dialogs::error_dialog(&app.window, &e),
                }
            },
        );
    }

    pub fn import_dialog(&self) {
        dialogs::import::open(self);
    }

    pub fn export_selected(&self) {
        dialogs::export::open(self);
    }

    pub fn details_selected(&self) {
        match self.current_page().as_deref() {
            Some("keys") => match self.selected_key() {
                Some(k) => dialogs::details::open_key(self, &k),
                None => self.toast(&tr!("Select a key first")),
            },
            Some("certs") => match self.selected_cert() {
                Some(c) => dialogs::details::open_cert(self, &c),
                None => self.toast(&tr!("Select a certificate first")),
            },
            Some("reqs") => match self.selected_req() {
                Some(r) => dialogs::details::open_req(self, &r),
                None => self.toast(&tr!("Select a request first")),
            },
            Some("crls") => match self.selected_crl() {
                Some(c) => dialogs::details::open_crl(self, &c),
                None => self.toast(&tr!("Select a revocation list first")),
            },
            Some("ssh-keys") => {
                if self.pages.ssh_from_storage.get() {
                    match self.selected_user_key() {
                        Some(k) => dialogs::ssh::open_details_user_key(self, &k),
                        None => self.toast(&tr!("Select a key first")),
                    }
                } else {
                    match self.selected_ssh_key() {
                        Some(k) => dialogs::ssh::open_details_key(self, &k),
                        None => self.toast(&tr!("Select a key first")),
                    }
                }
            }
            Some("ssh-hosts") => match self.selected_host_block() {
                Some(bid) => dialogs::ssh::open_host_editor(self, Some(bid)),
                None => self.toast(&tr!("Select a host first")),
            },
            Some("ssh-certs") => {
                if self.pages.ssh_certs_from_storage.get() {
                    match self.selected_user_cert() {
                        Some(c) => dialogs::ssh::open_details_user_cert(self, &c),
                        None => self.toast(&tr!("Select a certificate first")),
                    }
                } else {
                    match self.selected_ssh_cert() {
                        Some(c) => dialogs::ssh::open_details_cert(self, &c),
                        None => self.toast(&tr!("Select a certificate first")),
                    }
                }
            }
            _ => {}
        }
    }

    pub fn sign_selected_request(&self) {
        match self.selected_req() {
            Some(r) => dialogs::new_cert::open(self, Some(r)),
            None => self.toast(&tr!("Select a request first")),
        }
    }

    pub fn delete_selected(&self) {
        enum Del {
            Key(i64, String),
            Cert(i64, String),
            Req(i64, String),
            Crl(i64, String),
            SshKey(i64, String),
            SshCert(i64, String),
            /// A ~/.ssh key: its files are removed from disk.
            UserKeyFile(Box<crate::ssh::UserKey>),
            /// A ~/.ssh certificate file.
            UserCertFile(Box<crate::ssh::UserCert>),
            /// A Host block of ~/.ssh/config (block index).
            Host(usize, String),
        }
        let del = match self.current_page().as_deref() {
            Some("keys") => match self.selected_key() {
                Some(k) => Del::Key(k.id, k.name),
                None => return self.toast(&tr!("Select a key first")),
            },
            Some("certs") => match self.selected_cert() {
                Some(c) => Del::Cert(c.id, c.name),
                None => return self.toast(&tr!("Select a certificate first")),
            },
            Some("reqs") => match self.selected_req() {
                Some(r) => Del::Req(r.id, r.name),
                None => return self.toast(&tr!("Select a request first")),
            },
            Some("crls") => match self.selected_crl() {
                Some(c) => Del::Crl(c.id, c.name),
                None => return self.toast(&tr!("Select a revocation list first")),
            },
            Some("ssh-keys") if self.pages.ssh_from_storage.get() => {
                match self.selected_user_key() {
                    Some(k) => Del::UserKeyFile(Box::new(k)),
                    None => return self.toast(&tr!("Select a key first")),
                }
            }
            Some("ssh-certs") if self.pages.ssh_certs_from_storage.get() => {
                match self.selected_user_cert() {
                    Some(c) => Del::UserCertFile(Box::new(c)),
                    None => return self.toast(&tr!("Select a certificate first")),
                }
            }
            Some("ssh-keys") => match self.selected_ssh_key() {
                Some(k) => Del::SshKey(k.id, k.name),
                None => return self.toast(&tr!("Select a key first")),
            },
            Some("ssh-certs") => match self.selected_ssh_cert() {
                Some(c) => Del::SshCert(c.id, c.name),
                None => return self.toast(&tr!("Select a certificate first")),
            },
            Some("ssh-hosts") => match self.selected_host_block() {
                Some(bid) => match self.pages.ssh_config.borrow().host(bid) {
                    Some(h) => Del::Host(bid, h.alias().to_string()),
                    None => return self.toast(&tr!("Select a host first")),
                },
                None => return self.toast(&tr!("Select a host first")),
            },
            _ => return,
        };
        // The confirmation carries the specifics of what gets removed.
        let (title, body) = match &del {
            Del::Key(_, n)
            | Del::Cert(_, n)
            | Del::Req(_, n)
            | Del::Crl(_, n)
            | Del::SshKey(_, n)
            | Del::SshCert(_, n) => (
                tr!("Delete “%{name}”?", name = n.clone()),
                tr!("This cannot be undone."),
            ),
            Del::UserKeyFile(k) => (
                tr!("Delete “%{name}” from ~/.ssh?", name = k.file.clone()),
                tr!("The matching .pub and certificate files are removed too."),
            ),
            Del::UserCertFile(c) => (
                tr!("Delete “%{name}” from ~/.ssh?", name = c.file.clone()),
                tr!("This cannot be undone."),
            ),
            Del::Host(_, n) => (
                tr!("Delete “%{name}”?", name = n.clone()),
                tr!("The host block is removed from ~/.ssh/config."),
            ),
        };
        // Which post-delete bookkeeping the confirmed deletion needs.
        enum DelKind {
            Database,
            StorageFiles,
            Host,
        }
        let del_kind = match &del {
            Del::UserKeyFile(_) | Del::UserCertFile(_) => DelKind::StorageFiles,
            Del::Host(..) => DelKind::Host,
            _ => DelKind::Database,
        };
        let dlg = adw::AlertDialog::new(Some(&title), Some(&body));
        dlg.add_response("cancel", &tr!("Cancel"));
        dlg.add_response("delete", &tr!("Delete"));
        dlg.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        let app = self.clone();
        dlg.choose(
            Some(&self.window),
            None::<&gtk::gio::Cancellable>,
            move |resp| {
                if resp.as_str() != "delete" {
                    return;
                }
                let res = match del {
                    Del::Key(i, _) => {
                        let db = app.db.lock().unwrap();
                        db.delete_key(i)
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_db())
                    }
                    Del::Cert(i, _) => {
                        let db = app.db.lock().unwrap();
                        db.delete_cert(i)
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_db())
                    }
                    Del::Req(i, _) => {
                        let db = app.db.lock().unwrap();
                        db.delete_req(i)
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_db())
                    }
                    Del::Crl(i, _) => {
                        let db = app.db.lock().unwrap();
                        db.delete_crl(i)
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_db())
                    }
                    Del::SshKey(i, _) => {
                        let db = app.db.lock().unwrap();
                        db.delete_ssh_key(i)
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_db())
                    }
                    Del::SshCert(i, _) => {
                        let db = app.db.lock().unwrap();
                        db.delete_ssh_cert(i)
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_db())
                    }
                    Del::UserKeyFile(k) => crate::ssh::delete_key_files(&k)
                        .map(|files| crate::notify::deleted_ssh_files(&files)),
                    Del::UserCertFile(c) => crate::ssh::delete_cert_file(&c)
                        .map(|f| crate::notify::deleted_ssh_files(&[f])),
                    Del::Host(bid, name) => {
                        let mut cfg = app.pages.ssh_config.borrow_mut();
                        if bid < cfg.blocks.len() {
                            cfg.blocks.remove(bid);
                        }
                        drop(cfg);
                        crate::sshconf::save(&app.pages.ssh_config.borrow())
                            .map_err(|e| e.to_string())
                            .map(|_| crate::notify::deleted_host(&name))
                    }
                };
                match res {
                    Ok(msg) => {
                        app.toast(&msg);
                        // Storage edits need the rescan/reload the plain
                        // refresh does not do — only those kinds pay for it.
                        match &del_kind {
                            DelKind::StorageFiles => app.rescan_ssh_storage(),
                            DelKind::Host => app.reload_ssh_hosts(),
                            DelKind::Database => {}
                        }
                        app.refresh();
                    }
                    Err(e) => dialogs::error_dialog(&app.window, &e),
                }
            },
        );
    }

    pub fn about(&self) {
        let dlg = adw::AboutDialog::builder()
            .application_name("XCA RS")
            .version(env!("CARGO_PKG_VERSION"))
            .comments(format!(
                "{}\n\n{}\n\nE-mail: rinwate@yandex.ru",
                tr!("Certificate and key management — a Rust rewrite of XCA using GTK4 and libadwaita"),
                tr!("An independent reimplementation of the ideas of XCA — X Certificate and Key Management")
            ))
            .website("https://github.com/RinWate")
            .developer_name("Denis \"RinWate\" Egorov")
            .developers(
                ["Denis \"RinWate\" Egorov https://github.com/RinWate"].as_slice(),
            )
            .license_type(gtk::License::Gpl20Only)
            .build();
        // The original XCA: its author joins the credits (with the project
        // link), and its license gets a dedicated legal section — adw's own
        // layout, no hand-rolled forms.
        dlg.add_credit_section(
            Some(&tr!("The original XCA")),
            ["Christian Hohnstaedt (chris2511) https://github.com/chris2511/xca"].as_slice(),
        );
        dlg.add_legal_section(
            &tr!("The original XCA"),
            Some("Copyright (C) 2001 - 2021 Christian Hohnstaedt."),
            gtk::License::Bsd3,
            None,
        );
        dlg.present(Some(&self.window));
    }
}

fn adw_app_of(app: &App) -> Option<adw::Application> {
    app.window
        .application()
        .and_then(|a| a.downcast::<adw::Application>().ok())
}
