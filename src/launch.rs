//! Startup orchestration: open (and if needed unlock) the database, then
//! build the main window.

use crate::db::{is_not_database, Db};
use crate::ui::window;
use libadwaita as adw;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;

pub fn open_main(app: &adw::Application, path: &Path, password: Option<String>) {
    match Db::open(path, password.as_deref()) {
        Ok(db) => {
            let encrypted = password.is_some();
            crate::remember_db(path);
            let handle = window::build(app, Rc::new(Mutex::new(db)), path.to_path_buf(), encrypted);
            // Hidden hook for UI smoke-testing: auto-open a dialog on start.
            match std::env::var("XCA_UI_TEST").as_deref() {
                Ok("newkey") => handle.new_key_dialog(),
                Ok("newcert") => handle.new_cert_dialog(),
                Ok("newcrl") => handle.new_crl_dialog(),
                Ok("token") => handle.token_dialog(),
                _ => {}
            }
        }
        Err(e) if is_not_database(&e) => {
            // Missing or wrong password.
            crate::ui::dialogs::password::unlock(app, path.to_path_buf(), password.is_some());
        }
        Err(e) => {
            eprintln!("Cannot open database at {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

pub fn start(app: &adw::Application, path: PathBuf) {
    // sqlite creates the file but not its parent directory.
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if path.exists() {
        open_main(app, &path, None);
    } else {
        crate::ui::dialogs::password::setup_new(app, path);
    }
}
