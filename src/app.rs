//! Application state shared by all widgets: database handle, main window,
//! list models. Also hosts the window-level actions (menu entries) and the
//! refresh/delete/about logic.

use crate::crypto;
use crate::db::{CertRecord, CrlRecord, Db, KeyRecord, ReqRecord, RevokedRecord};
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
) -> String {
    let mut badge = match crypto::load_cert(&c.pem).map(|x| crypto::cert_summary(x.as_ref())) {
        Ok(s) => crypto::cert_status(&s),
        Err(_) => {
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
        drop(db);

        self.pages.keys.remove_all();
        for k in keys {
            self.pages
                .keys
                .append(&PkiItemObject::new(k.id, &k.name, &k.type_label(), "", ""));
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
            let badge = cert_badge(c, &revoked);
            objects.insert(
                c.id,
                PkiItemObject::new(c.id, &c.name, &c.subject, &c.issuer, &badge),
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
        for r in reqs {
            self.pages
                .reqs
                .append(&PkiItemObject::new(r.id, &r.name, &r.subject, "", ""));
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
            ));
        }
    }

    fn current_page(&self) -> Option<String> {
        self.pages
            .stack
            .visible_child_name()
            .map(|s| s.to_string())
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

    // ---- action entry points ----

    pub fn new_key_dialog(&self) {
        dialogs::new_key::open(self);
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
            _ => return,
        };
        let name = match &del {
            Del::Key(_, n) | Del::Cert(_, n) | Del::Req(_, n) | Del::Crl(_, n) => n.clone(),
        };
        let dlg = adw::AlertDialog::new(
            Some(&tr!("Delete “%{name}”?", name = name.clone())),
            Some(&tr!("This cannot be undone.")),
        );
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
                let res = {
                    let db = app.db.lock().unwrap();
                    match del {
                        Del::Key(i, _) => db.delete_key(i).map_err(|e| e.to_string()),
                        Del::Cert(i, _) => db.delete_cert(i).map_err(|e| e.to_string()),
                        Del::Req(i, _) => db.delete_req(i).map_err(|e| e.to_string()),
                        Del::Crl(i, _) => db.delete_crl(i).map_err(|e| e.to_string()),
                    }
                };
                match res {
                    Ok(()) => {
                        app.refresh();
                        app.toast(&tr!("Deleted"));
                    }
                    Err(e) => dialogs::error_dialog(&app.window, &e),
                }
            },
        );
    }

    pub fn about(&self) {
        adw::AboutDialog::builder()
            .application_name("XCA RS")
            .version(env!("CARGO_PKG_VERSION"))
            .comments(format!(
                "{}\n\nE-mail: rinwate@yandex.ru",
                tr!("Certificate and key management — a Rust rewrite of XCA using GTK4 and libadwaita")
            ))
            .website("https://github.com/RinWate")
            .developer_name("Denis \"RinWate\" Egorov")
            .developers(
                ["Denis \"RinWate\" Egorov https://github.com/RinWate"].as_slice(),
            )
            .license_type(gtk::License::Gpl20Only)
            .build()
            .present(Some(&self.window));
    }
}

fn adw_app_of(app: &App) -> Option<adw::Application> {
    app.window
        .application()
        .and_then(|a| a.downcast::<adw::Application>().ok())
}
