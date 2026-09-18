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
            db_error_window(app, path, &e);
        }
    }
}

/// The database cannot be opened at all: show why in a small window
/// instead of killing the process from inside a GTK callback.
fn db_error_window(app: &adw::Application, path: &Path, msg: &str) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title(crate::tr!("Cannot open database"))
        .default_width(440)
        .build();
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&adw::HeaderBar::new());
    use gtk::prelude::*;
    use libadwaita::prelude::*;
    let label = gtk::Label::new(Some(&format!(
        "{}\n{}\n\n{msg}",
        crate::tr!("Not an XCA database"),
        path.display()
    )));
    label.set_wrap(true);
    label.set_margin_top(24);
    label.set_margin_bottom(24);
    label.set_margin_start(24);
    label.set_margin_end(24);
    tv.set_content(Some(&label));
    window.set_content(Some(&tv));
    window.present();
}

pub fn start(app: &adw::Application, path: PathBuf) {
    if path.exists() {
        open_main(app, &path, None);
    } else {
        crate::ui::dialogs::password::setup_new(app, path);
    }
}
