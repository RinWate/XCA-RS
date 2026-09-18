//! Database password dialogs: first-run setup, unlock of a
//! password-protected database, and setting/changing the password
//! (XCA-style: it protects the private keys inside the database).

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

/// Enter in any of the rows presses `button` — the Adwaita mechanism for
/// windows: entries with `activates-default` activate the window's default
/// widget (the AdwEntryRow "activate" signal is not reliably emitted by
/// PasswordEntryRow in libadwaita 1.5).
fn enter_submits(
    window: &adw::ApplicationWindow,
    button: &gtk::Button,
    rows: &[&adw::PasswordEntryRow],
) {
    for r in rows {
        r.set_activates_default(true);
    }
    // gtk_window_set_default_widget marks the button as the window default
    // by itself; there is no "can-default" property in GTK4.
    window.set_default_widget(Some(button));
}

/// Enter anywhere in the form presses `button`. For AdwDialogs, which have
/// no window default widget; a bubbling key controller sees the Return
/// that the entry leaves unhandled.
fn enter_key_submits(container: &impl IsA<gtk::Widget>, button: &gtk::Button) {
    let button = button.clone();
    let ec = gtk::EventControllerKey::new();
    ec.connect_key_pressed(move |_, key, _, _| {
        if matches!(key, gtk::gdk::Key::Return | gtk::gdk::Key::KP_Enter) {
            button.emit_clicked();
            gtk::glib::Propagation::Stop
        } else {
            gtk::glib::Propagation::Proceed
        }
    });
    container.add_controller(ec);
}

fn button_row() -> gtk::Box {
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    bar.set_halign(gtk::Align::End);
    bar.set_margin_top(12);
    bar.set_margin_bottom(12);
    bar
}

/// Flat button for the password windows: pick a different database file
/// instead of unlocking/creating the current one. Picking the same file
/// again keeps the window as it is.
fn other_database_button(
    app: &adw::Application,
    window: &adw::ApplicationWindow,
    current: PathBuf,
) -> gtk::Button {
    let b = gtk::Button::with_label(&tr!("Choose another database…"));
    b.add_css_class("flat");
    b.set_halign(gtk::Align::Fill);
    b.set_margin_top(12);
    let app = app.clone();
    let window = window.clone();
    b.connect_clicked(move |_| {
        let dlg = gtk::FileDialog::builder()
            .title(tr!("Open Database"))
            .filters(&super::db_file_filters())
            .build();
        let app = app.clone();
        let current = current.clone();
        let win = window.clone();
        dlg.open(
            Some(&window),
            None::<&gtk::gio::Cancellable>,
            move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else { return };
                if path == current {
                    return;
                }
                win.close();
                crate::launch::open_main(&app, &path, None);
            },
        );
    });
    b
}

/// First run: choose a database password (empty = no password).
pub fn setup_new(app: &adw::Application, path: PathBuf) {
    let (window, group) = prompt(
        app,
        &tr!("Database Password"),
        &tr!("The password protects the private keys stored in the database,\nexactly as in the original XCA.\nLeave empty for no password."),
    );
    let pw1 = super::password_entry(&tr!("Password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));
    group.add(&pw1);
    group.add(&pw2);

    let bar = button_row();
    let skip = gtk::Button::with_label(&tr!("Skip (no password)"));
    skip.add_css_class("flat");
    let ok = gtk::Button::with_label(&tr!("Continue"));
    ok.add_css_class("suggested-action");
    bar.append(&skip);
    bar.append(&ok);
    group.add(&other_database_button(app, &window, path.clone()));
    group.add(&bar);
    enter_submits(&window, &ok, &[&pw1, &pw2]);

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
    group.add(&other_database_button(app, &window, path.clone()));
    group.add(&bar);
    enter_submits(&window, &ok, &[&pw]);

    {
        let app2 = app.clone();
        let path = path.clone();
        let win = window.clone();
        let row = pw.clone();
        ok.connect_clicked(move |_| {
            let pw = super::row_text(&row);
            // Verify before closing: a wrong password keeps this window
            // open (the field is marked) so the user can simply retry.
            match crate::db::Db::open(&path, Some(&pw)) {
                Ok(_) => {
                    win.close();
                    crate::launch::open_main(&app2, &path, Some(pw));
                }
                Err(crate::db::OpenError::WrongPassword) => {
                    row.add_css_class("error");
                }
                Err(crate::db::OpenError::Other(msg)) => {
                    super::error_dialog(&win, &msg);
                }
            }
        });
    }
    window.present();
}

/// Menu action: set or change the database password. Re-encrypts every
/// private key protected by the database password (XCA `pwhash` scheme).
pub fn set_or_change(app: &App) {
    let title = if app.password_protected {
        tr!("Change Database Password")
    } else {
        tr!("Set Database Password")
    };
    let form = super::form_dialog(&title, 400);
    let pw1 = super::password_entry(&tr!("New password"));
    let pw2 = super::password_entry(&tr!("Repeat password"));
    let g = form.group(&tr!("Private Key Protection"));
    g.add(&pw1);
    g.add(&pw2);

    let cancel = form.close_button(&tr!("Cancel"));
    let apply = form.apply_button(&tr!("Apply"));
    enter_key_submits(&g, &apply);
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    let app2 = app.clone();
    let was_protected = app.password_protected;
    let dlg = form.dlg.clone();
    let pw1 = pw1.clone();
    let pw2 = pw2.clone();
    apply.connect_clicked(move |_| {
        let a = super::row_text(&pw1);
        let b = super::row_text(&pw2);
        if a != b {
            return super::error_dialog(&app2.window, &tr!("Passwords do not match"));
        }
        let res = app2.db.lock().unwrap().change_password(&a);
        match res {
            Ok(()) => {
                dlg.close();
                app2.refresh();
                let msg = if a.is_empty() {
                    tr!("Password removed")
                } else if was_protected {
                    tr!("Password changed")
                } else {
                    tr!("Password set")
                };
                app2.toast(&msg);
            }
            Err(e) => super::error_dialog(&app2.window, &e),
        }
    });

    form.dlg.present(Some(&app.window));
}

