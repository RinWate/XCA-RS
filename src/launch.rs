//! Startup orchestration: open (and if needed unlock) the database, then
//! build the main window.

use crate::db::{Db, OpenError};
use crate::ui::window;
use libadwaita as adw;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;

pub fn open_main(app: &adw::Application, path: &Path, password: Option<String>) {
    match Db::open(path, password.as_deref()) {
        Ok(db) => {
            let has_password = db.has_password;
            crate::remember_db(path);
            let handle = window::build(
                app,
                Rc::new(Mutex::new(db)),
                path.to_path_buf(),
                has_password,
            );
            // Hidden hook for UI smoke-testing: auto-open a dialog on start.
            match std::env::var("XCA_UI_TEST").as_deref() {
                Ok("newkey") => handle.new_key_dialog(),
                Ok("newcert") => handle.new_cert_dialog(),
                Ok("newcrl") => handle.new_crl_dialog(),
                Ok("token") => handle.token_dialog(),
                Ok("props") => handle.details_selected(),
                _ => {}
            }
        }
        Err(OpenError::WrongPassword) => {
            // Missing or wrong password.
            crate::ui::dialogs::password::unlock(app, path.to_path_buf(), password.is_some());
        }
        Err(OpenError::Other(e)) => {
            eprintln!("Cannot open database at {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

pub fn start(app: &adw::Application, path: PathBuf) {
    if path.exists() {
        open_main(app, &path, None);
    } else {
        crate::ui::dialogs::password::setup_new(app, path);
    }
}
