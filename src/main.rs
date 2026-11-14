//! XCA RS — a Rust/GTK4 rewrite of XCA (X Certificate and Key Management).
//! GTK4 + libadwaita frontend, OpenSSL crypto backend, databases in the
//! original XCA format, PKCS#11 hardware token support.

mod app;
mod cpcsp;
mod crypto;
mod db;
mod launch;
mod notify;
mod pdf_sign;
mod pkcs11;
mod ssh;
mod sshconf;
mod ui;
mod xca_format;

use gtk::glib;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::path::{Path, PathBuf};

const APP_ID: &str = "org.xca.rs";

// Translations are embedded from xca-rs/locales/*.toml at compile time
// (rust-i18n). Keys are the English source strings; missing entries fall
// back to "en" (identity mapping) and then to the key itself.
rust_i18n::i18n!("locales", fallback = "en");

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

/// Locales that have no file of their own but are understood by a close
/// relative. Extend only when adding a language file does not cover those
/// users (e.g. Ukrainian here falls back to Russian).
const LANG_PROXIMITY: &[(&str, &str)] = &[("be", "ru"), ("uk", "ru")];

/// Detect the UI locale from the environment. Scales to any number of
/// languages: it matches against the locales embedded at compile time
/// (`rust_i18n::available_locales!()`), so adding a `xx.toml` file needs no
/// code change. Returns a lowercase hyphen-separated tag ("zh-tw"), letting
/// rust-i18n's RFC4647 fallback chain resolve variants to their base file.
fn detect_locale() -> String {
    let forced = std::env::var("XCA_RS_LANG").unwrap_or_default();
    let env = if forced.is_empty() {
        std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default()
    } else {
        forced
    };
    // "ru_RU.UTF-8" -> ["ru", "ru"]; "zh-Hant-TW" -> ["zh", "hant", "tw"]
    let tags: Vec<String> = env
        .split('.')
        .next()
        .unwrap_or("")
        .split(['_', '-'])
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect();
    let available = rust_i18n::available_locales!();
    let has = |tag: &str| available.iter().any(|l| l.as_ref() == tag);
    // Full BCP-47 tag first ("zh-tw"), then the base language ("zh").
    if tags.len() >= 2 {
        let full = format!("{}-{}", tags[0], tags[1]);
        if has(&full) {
            return full;
        }
    }
    if let Some(base) = tags.first() {
        if has(base) {
            return base.clone();
        }
        if let Some((_, near)) = LANG_PROXIMITY.iter().find(|(l, _)| l == base) {
            if has(near) {
                return (*near).to_string();
            }
        }
    }
    "en".to_string()
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

// ---- language choice ("auto" or a locale code) in the same config ----

pub fn remember_language(lang: &str) {
    let cfg = config_file();
    if let Some(dir) = cfg.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let kf = glib::KeyFile::new();
    let _ = kf.load_from_file(&cfg, glib::KeyFileFlags::NONE);
    kf.set_string("ui", "language", lang);
    if let Err(e) = kf.save_to_file(&cfg) {
        eprintln!("Cannot save config: {e}");
    }
}

/// The saved language choice; "auto" when never changed in the menu.
pub fn saved_language() -> String {
    let kf = glib::KeyFile::new();
    if kf.load_from_file(config_file(), glib::KeyFileFlags::NONE).is_ok() {
        if let Ok(s) = kf.string("ui", "language") {
            return s.to_string();
        }
    }
    "auto".to_string()
}

/// The locale to start with: the saved menu choice, else the system locale.
pub fn startup_locale() -> String {
    match saved_language().as_str() {
        "auto" | "" => detect_locale(),
        lang => lang.to_string(),
    }
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
    // RC2-encrypted PKCS#12 certbags (CryptoPro CSP exports) need the
    // legacy provider; silently no-ops when the module is absent.
    let _ = crypto::init_legacy_provider();
    rust_i18n::set_locale(&startup_locale());
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
        rust_i18n::set_locale("zh");
        assert_eq!(crate::tr!("Keys"), "密钥");
        assert_eq!(
            crate::tr!("Key “%{name}” created", name = "测试"),
            "密钥“测试”已创建"
        );

        rust_i18n::set_locale(&crate::detect_locale());
    }

    #[test]
    fn detect_locale_maps_environment() {
        for (val, want) in [
            ("ru_RU.UTF-8", "ru"),
            ("be_BY.UTF-8", "ru"),   // proximity fallback
            ("uk_UA.UTF-8", "ru"),   // proximity fallback
            ("zh_CN.UTF-8", "zh"),
            ("zh-Hant-TW.utf8", "zh"),
            ("en_US.UTF-8", "en"),
            ("pt_BR.UTF-8", "en"), // no pt file yet
            ("C", "en"),
        ] {
            // SAFETY: the only test touching XCA_RS_LANG; single-threaded env use.
            unsafe { std::env::set_var("XCA_RS_LANG", val) };
            assert_eq!(crate::detect_locale(), want, "XCA_RS_LANG={val}");
        }
        unsafe { std::env::remove_var("XCA_RS_LANG") };
    }
}
