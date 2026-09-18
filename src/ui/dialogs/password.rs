//! Database password dialogs: first-run setup, unlock of an encrypted
//! database, and in-place encryption of a plain database.

use crate::app::App;
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;
use std::path::PathBuf;

/// Small standalone window (the main window does not exist yet).
fn prompt(
    app: &adw::Application,
    title: &str,
    description: &str,
) -> (adw::ApplicationWindow, adw::PreferencesGroup) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title(title)
        .default_width(420)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(description)
        .build();
    page.add(&group);
    let sw = gtk::ScrolledWindow::new();
    sw.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    sw.set_propagate_natural_height(true);
    sw.set_max_content_height(520);
    sw.set_child(Some(&page));
    toolbar.set_content(Some(&sw));
    window.set_content(Some(&toolbar));
    (window, group)
}

fn button_row() -> gtk::Box {
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    bar.set_halign(gtk::Align::End);
    bar.set_margin_top(12);
    bar.set_margin_bottom(12);
    bar
}

/// First run: choose a database password (empty = no encryption).
pub fn setup_new(app: &adw::Application, path: PathBuf) {
    let (window, group) = prompt(
        app,
        &tr!("Database Password"),
        &tr!("Protect the new database with a password.\nLeave empty to store it unencrypted."),
    );
    let pw1 = super::password_entry(&tr!("Password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));
    group.add(&pw1);
    group.add(&pw2);

    let bar = button_row();
    let skip = gtk::Button::with_label(&tr!("Skip (unencrypted)"));
    skip.add_css_class("flat");
    let ok = gtk::Button::with_label(&tr!("Continue"));
    ok.add_css_class("suggested-action");
    bar.append(&skip);
    bar.append(&ok);
    group.add(&bar);

    {
        let app2 = app.clone();
        let path = path.clone();
        let win = window.clone();
        skip.connect_clicked(move |_| {
            win.close();
            crate::launch::open_main(&app2, &path, None);
        });
    }
    {
        let app2 = app.clone();
        let path = path.clone();
        let win = window.clone();
        let pw1 = pw1.clone();
        let pw2 = pw2.clone();
        ok.connect_clicked(move |_| {
            let a = super::row_text(&pw1);
            let b = super::row_text(&pw2);
            if a != b {
                pw1.add_css_class("error");
                pw2.add_css_class("error");
                return;
            }
            let pw = if a.is_empty() { None } else { Some(a) };
            win.close();
            crate::launch::open_main(&app2, &path, pw);
        });
    }
    window.present();
}

/// Existing encrypted database: ask for the password to unlock.
pub fn unlock(app: &adw::Application, path: PathBuf, wrong: bool) {
    let desc = if wrong {
        tr!("Wrong password, try again.")
    } else {
        tr!("The database is password-protected.")
    };
    let (window, group) = prompt(app, &tr!("Unlock Database"), &desc);
    let pw = super::password_entry(&tr!("Password"));
    if wrong {
        pw.add_css_class("error");
    }
    group.add(&pw);

    let bar = button_row();
    let ok = gtk::Button::with_label(&tr!("Unlock"));
    ok.add_css_class("suggested-action");
    bar.append(&ok);
    group.add(&bar);

    {
        let app2 = app.clone();
        let path = path.clone();
        let win = window.clone();
        let pw = pw.clone();
        ok.connect_clicked(move |_| {
            let pw = super::row_text(&pw);
            win.close();
            crate::launch::open_main(&app2, &path, Some(pw));
        });
    }
    window.present();
}

/// Menu action: encrypt the currently open (plain) database in place.
pub fn encrypt_database(app: &App) {
    if app.encrypted {
        app.toast(&tr!("The database is already encrypted"));
        return;
    }
    let form = super::form_dialog(&tr!("Encrypt Database"), 400);
    let pw1 = super::password_entry(&tr!("Password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));
    let g = form.group(&tr!("SQLCipher Encryption"));
    g.add(&pw1);
    g.add(&pw2);

    let cancel = form.close_button(&tr!("Cancel"));
    let apply = form.apply_button(&tr!("Encrypt"));
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
    apply.connect_clicked(move |_| {
        let a = super::row_text(&pw1);
        let b = super::row_text(&pw2);
        if a.is_empty() || a != b {
            return super::error_dialog(&app2.window, &tr!("Passwords are empty or do not match"));
        }
        match app2.db.lock().unwrap().encrypt_copy(&app2.db_path, &a) {
            Ok(()) => {
                dlg.close();
                let info = adw::AlertDialog::new(
                    Some(&tr!("Database encrypted")),
                    Some(&tr!("The database file is now encrypted.\nQuit now and start xca-rs again.")),
                );
                info.add_response("quit", &tr!("Quit"));
                let app3 = app2.clone();
                info.choose(&app2.window, None::<&gtk::gio::Cancellable>, move |resp| {
                    if resp.as_str() == "quit" {
                        if let Some(a) = app3.window.application() {
                            a.quit();
                        }
                    }
                });
            }
            Err(e) => super::error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}
