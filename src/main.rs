//! XCA RS — a Rust/GTK4 rewrite of XCA (X Certificate and Key Management).
//! GTK4 + libadwaita frontend, OpenSSL crypto backend, databases in the
//! original XCA format, PKCS#11 hardware token support.

mod app;
mod cpcsp;
mod crypto;
mod db;
mod launch;
mod pdf_sign;
mod pkcs11;
mod ui;
mod xca_format;

use gtk::glib;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::path::{Path, PathBuf};

const APP_ID: &str = "org.xca.rs";

// Translations are embedded from xca-rs/locales/*.toml at compile time
// (rust-i18n). Keys are the English source strings, so an untranslated
// entry simply falls back to English.
rust_i18n::i18n!("locales");

/// Translate a string for the current locale. Returns a String because GTK
/// builders take owned/Into values; the key doubles as the English text.
#[macro_export]
macro_rules! tr {
    ($key:expr) => {
        rust_i18n::t!($key).to_string()
    };
    ($key:expr, $($args:tt)*) => {
        rust_i18n::t!($key, $($args)*).to_string()
    };
}

fn detect_locale() -> &'static str {
    if let Ok(l) = std::env::var("XCA_RS_LANG") {
        return if l.starts_with("ru") { "ru" } else { "en" };
    }
    let env = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    if env.starts_with("ru") || env.starts_with("RU") || env.starts_with("be") || env.starts_with("uk") {
        "ru"
    } else {
        "en"
    }
}

// ---- last used database memory (~/.config/xca-rs/config.ini) ----

fn config_file() -> PathBuf {
    glib::user_config_dir().join("xca-rs").join("config.ini")
}

pub fn remember_db(path: &Path) {
    let cfg = config_file();
    // KeyFile::save_to_file does not create parent directories.
    if let Some(dir) = cfg.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let kf = glib::KeyFile::new();
    let _ = kf.load_from_file(&cfg, glib::KeyFileFlags::NONE);
    kf.set_string("database", "last", &path.to_string_lossy());
    if let Err(e) = kf.save_to_file(&cfg) {
        eprintln!("Cannot save config: {e}");
    }
}

pub fn last_db() -> Option<PathBuf> {
    let kf = glib::KeyFile::new();
    kf.load_from_file(config_file(), glib::KeyFileFlags::NONE).ok()?;
    let s = kf.string("database", "last").ok()?;
    let p = PathBuf::from(s);
    p.is_file().then_some(p)
}

fn database_path() -> PathBuf {
    if let Some(p) = std::env::var_os("XCA_RS_DB") {
        return PathBuf::from(p);
    }
    if let Some(p) = last_db() {
        return p;
    }
    glib::user_data_dir().join("xca-rs").join("xca-rs.db")
}

fn main() {
    // GOST keys/certificates need the gost engine loaded before anything
    // parses or generates crypto objects; silently no-ops without it.
    let _ = crypto::init_gost();
    rust_i18n::set_locale(detect_locale());
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gtk::gio::ApplicationFlags::HANDLES_OPEN)
        .build();
    app.connect_activate(|app| {
        launch::start(app, database_path());
    });
    // `xca-rs file.xdb` (and "open with…" from the file manager) opens
    // that database; xca-rs is single-window, so the current one closes.
    app.connect_open(|app, files, _| {
        if let Some(path) = files.first().and_then(|f| f.path()) {
            for w in app.windows() {
                w.close();
            }
            launch::start(app, path);
        }
    });
    app.run();
}

#[cfg(test)]
mod tests {
    /// The locale files must be embedded and interpolated at runtime.
    #[test]
    fn translations_load_and_interpolate() {
        rust_i18n::set_locale("ru");
        assert_eq!(crate::tr!("Keys"), "Ключи");
        assert_eq!(
            crate::tr!("Key “%{name}” created", name = "test"),
            "Ключ «test» создан"
        );
        // Missing key falls back to the key itself.
        assert_eq!(crate::tr!("untranslated string"), "untranslated string");

        rust_i18n::set_locale("en");
        assert_eq!(crate::tr!("Keys"), "Keys");
        assert_eq!(
            crate::tr!("Key “%{name}” created", name = "test"),
            "Key “test” created"
        );
        rust_i18n::set_locale(crate::detect_locale());
    }
}
