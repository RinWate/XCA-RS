//! Main window assembly: Adwaita application window with a view stack of
//! Keys / Certificates / Requests pages, each a `gtk::ColumnView` over a
//! `gio::ListStore` of `PkiItemObject` rows.

use crate::app::App;
use crate::db::Db;
use crate::tr;
use crate::ui::columns::{column_view, text_column};
use crate::ui::item::PkiItemObject;
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;
use std::rc::Rc;
use std::sync::Mutex;

pub struct Pages {
    pub stack: adw::ViewStack,
    pub toast: adw::ToastOverlay,
    pub keys: gtk::gio::ListStore,
    pub certs: gtk::gio::ListStore,
    pub reqs: gtk::gio::ListStore,
    pub crls: gtk::gio::ListStore,
    pub keys_sel: gtk::SingleSelection,
    pub certs_sel: gtk::SingleSelection,
    pub reqs_sel: gtk::SingleSelection,
    pub crls_sel: gtk::SingleSelection,
}

fn page(view: &gtk::ColumnView) -> (gtk::Box, gtk::Box) {
    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    bar.set_margin_top(12);
    bar.set_margin_start(12);
    bar.set_margin_end(12);
    // The table lives in a "card" with side margins, so it does not run
    // wall-to-wall and the selection follows the card's rounded corners.
    let card = gtk::Box::new(gtk::Orientation::Vertical, 0);
    card.add_css_class("card");
    card.set_overflow(gtk::Overflow::Hidden);
    card.set_margin_start(12);
    card.set_margin_end(12);
    card.set_margin_bottom(12);
    let sw = gtk::ScrolledWindow::new();
    sw.set_child(Some(view));
    sw.set_vexpand(true);
    sw.set_hexpand(true);
    card.append(&sw);
    vbox.append(&bar);
    vbox.append(&card);
    (vbox, bar)
}

fn bar_button(label: &str, classes: &[&str], app: &App, bar: &gtk::Box, f: impl Fn(&App) + 'static) {
    let b = gtk::Button::with_label(label);
    for c in classes {
        b.add_css_class(c);
    }
    let app = app.clone();
    b.connect_clicked(move |_| f(&app));
    bar.append(&b);
}

fn window_action(app: &App, name: &str, f: impl Fn(&App) + 'static) {
    let act = gtk::gio::SimpleAction::new(name, None);
    let a = app.clone();
    act.connect_activate(move |_, _| f(&a));
    app.window.add_action(&act);
}

pub fn build(
    ui_app: &adw::Application,
    db: Rc<Mutex<Db>>,
    db_path: std::path::PathBuf,
    encrypted: bool,
) -> App {
    // Show which database is open in the window (taskbar) title.
    let title = db_path
        .file_name()
        .map(|n| format!("XCA RS — {}", n.to_string_lossy()))
        .unwrap_or_else(|| "XCA RS".to_string());
    let window = adw::ApplicationWindow::builder()
        .application(ui_app)
        .title(&title)
        .default_width(1100)
        .default_height(700)
        .build();

    let keys_store = gtk::gio::ListStore::new::<PkiItemObject>();
    let certs_store = gtk::gio::ListStore::new::<PkiItemObject>();
    let reqs_store = gtk::gio::ListStore::new::<PkiItemObject>();
    let crls_store = gtk::gio::ListStore::new::<PkiItemObject>();

    let (keys_view, keys_sel) = column_view(
        &keys_store,
        vec![
            text_column(&tr!("Name"), "name", true),
            text_column(&tr!("Type"), "detail", false),
        ],
    );
    let (certs_view, certs_sel) = column_view(
        &certs_store,
        vec![
            text_column(&tr!("Name"), "name", true),
            text_column(&tr!("Subject"), "detail", true),
            text_column(&tr!("Issuer"), "extra", true),
            text_column(&tr!("Status"), "badge", false),
        ],
    );
    let (reqs_view, reqs_sel) = column_view(
        &reqs_store,
        vec![
            text_column(&tr!("Name"), "name", true),
            text_column(&tr!("Subject"), "detail", true),
        ],
    );
    let (crls_view, crls_sel) = column_view(
        &crls_store,
        vec![
            text_column(&tr!("Name"), "name", true),
            text_column(&tr!("Issuer"), "detail", true),
            text_column(&tr!("Next Update"), "extra", false),
            text_column(&tr!("Entries"), "badge", false),
        ],
    );

    let (keys_page, keys_bar) = page(&keys_view);
    let (certs_page, certs_bar) = page(&certs_view);
    let (reqs_page, reqs_bar) = page(&reqs_view);
    let (crls_page, crls_bar) = page(&crls_view);

    let stack = adw::ViewStack::new();
    stack.add_titled_with_icon(
        &keys_page,
        Some("keys"),
        &tr!("Keys"),
        "system-lock-screen-symbolic",
    );
    stack.add_titled_with_icon(
        &certs_page,
        Some("certs"),
        &tr!("Certificates"),
        "security-high-symbolic",
    );
    stack.add_titled_with_icon(
        &reqs_page,
        Some("reqs"),
        &tr!("Requests"),
        "document-edit-symbolic",
    );
    stack.add_titled_with_icon(
        &crls_page,
        Some("crls"),
        &tr!("Revocation"),
        "security-low-symbolic",
    );

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&stack));

    let header = adw::HeaderBar::new();
    let switcher = adw::ViewSwitcher::builder()
        .policy(adw::ViewSwitcherPolicy::Wide)
        .stack(&stack)
        .build();
    header.set_title_widget(Some(&switcher));

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&toast_overlay));
    let switcher_bar = adw::ViewSwitcherBar::new();
    switcher_bar.set_stack(Some(&stack));
    toolbar.add_bottom_bar(&switcher_bar);

    // On narrow windows move the view switching into the bottom bar.
    fn apply_layout(sb: &adw::ViewSwitcherBar, sw: &adw::ViewSwitcher, width: i32) {
        let narrow = width < 600;
        sb.set_reveal(narrow);
        sw.set_policy(if narrow {
            adw::ViewSwitcherPolicy::Narrow
        } else {
            adw::ViewSwitcherPolicy::Wide
        });
    }
    apply_layout(&switcher_bar, &switcher, window.default_width());
    {
        let sb = switcher_bar.clone();
        let sw = switcher.clone();
        window.connect_notify_local(
            Some("default-width"),
            move |w: &adw::ApplicationWindow, _| apply_layout(&sb, &sw, w.default_width()),
        );
    }

    window.set_content(Some(&toolbar));

    let app = App {
        db,
        db_path,
        encrypted,
        window: window.clone(),
        pages: Rc::new(Pages {
            stack,
            toast: toast_overlay,
            keys: keys_store,
            certs: certs_store,
            reqs: reqs_store,
            crls: crls_store,
            keys_sel,
            certs_sel,
            reqs_sel,
            crls_sel,
        }),
    };

    // ---- toolbar buttons per page ----
    bar_button(&tr!("New Key…"), &["suggested-action"], &app, &keys_bar, |a| {
        a.new_key_dialog()
    });
    bar_button(&tr!("Import…"), &["flat"], &app, &keys_bar, |a| a.import_dialog());
    bar_button(&tr!("Export…"), &["flat"], &app, &keys_bar, |a| a.export_selected());
    bar_button(&tr!("Properties"), &["flat"], &app, &keys_bar, |a| {
        a.details_selected()
    });
    bar_button(&tr!("Delete"), &["flat", "destructive-action"], &app, &keys_bar, |a| {
        a.delete_selected()
    });

    bar_button(
        &tr!("New Certificate…"),
        &["suggested-action"],
        &app,
        &certs_bar,
        |a| a.new_cert_dialog(),
    );
    bar_button(&tr!("Import…"), &["flat"], &app, &certs_bar, |a| a.import_dialog());
    bar_button(&tr!("Export…"), &["flat"], &app, &certs_bar, |a| a.export_selected());
    bar_button(&tr!("Revoke…"), &["flat"], &app, &certs_bar, |a| a.revoke_selected());
    bar_button(&tr!("Properties"), &["flat"], &app, &certs_bar, |a| {
        a.details_selected()
    });
    bar_button(&tr!("Delete"), &["flat", "destructive-action"], &app, &certs_bar, |a| {
        a.delete_selected()
    });

    bar_button(&tr!("New Request…"), &["flat"], &app, &reqs_bar, |a| {
        a.new_req_dialog()
    });
    bar_button(&tr!("Sign…"), &["suggested-action"], &app, &reqs_bar, |a| {
        a.sign_selected_request()
    });
    bar_button(&tr!("Import…"), &["flat"], &app, &reqs_bar, |a| a.import_dialog());
    bar_button(&tr!("Export…"), &["flat"], &app, &reqs_bar, |a| a.export_selected());
    bar_button(&tr!("Properties"), &["flat"], &app, &reqs_bar, |a| {
        a.details_selected()
    });
    bar_button(&tr!("Delete"), &["flat", "destructive-action"], &app, &reqs_bar, |a| {
        a.delete_selected()
    });

    bar_button(&tr!("New CRL…"), &["suggested-action"], &app, &crls_bar, |a| {
        a.new_crl_dialog()
    });
    bar_button(&tr!("Export…"), &["flat"], &app, &crls_bar, |a| a.export_selected());
    bar_button(&tr!("Properties"), &["flat"], &app, &crls_bar, |a| {
        a.details_selected()
    });
    bar_button(&tr!("Delete"), &["flat", "destructive-action"], &app, &crls_bar, |a| {
        a.delete_selected()
    });

    // ---- row activation opens properties ----
    let app2 = app.clone();
    keys_view.connect_activate(move |_, pos| {
        if let Some(obj) = app2
            .pages
            .keys
            .item(pos)
            .and_then(|o| o.downcast::<PkiItemObject>().ok())
        {
            if let Some(rec) = app2.db.lock().unwrap().get_key(obj.id()).ok().flatten() {
                crate::ui::dialogs::details::open_key(&app2, &rec);
            }
        }
    });
    let app2 = app.clone();
    certs_view.connect_activate(move |_, pos| {
        if let Some(obj) = app2
            .pages
            .certs
            .item(pos)
            .and_then(|o| o.downcast::<PkiItemObject>().ok())
        {
            if let Some(rec) = app2.db.lock().unwrap().get_cert(obj.id()).ok().flatten() {
                crate::ui::dialogs::details::open_cert(&app2, &rec);
            }
        }
    });
    let app2 = app.clone();
    reqs_view.connect_activate(move |_, pos| {
        if let Some(obj) = app2
            .pages
            .reqs
            .item(pos)
            .and_then(|o| o.downcast::<PkiItemObject>().ok())
        {
            if let Some(rec) = app2.db.lock().unwrap().get_req(obj.id()).ok().flatten() {
                crate::ui::dialogs::details::open_req(&app2, &rec);
            }
        }
    });
    let app2 = app.clone();
    crls_view.connect_activate(move |_, pos| {
        if let Some(obj) = app2
            .pages
            .crls
            .item(pos)
            .and_then(|o| o.downcast::<PkiItemObject>().ok())
        {
            if let Some(rec) = app2.db.lock().unwrap().get_crl(obj.id()).ok().flatten() {
                crate::ui::dialogs::details::open_crl(&app2, &rec);
            }
        }
    });

    // ---- window actions + primary menu ----
    window_action(&app, "new-key", |a| a.new_key_dialog());
    window_action(&app, "new-cert", |a| a.new_cert_dialog());
    window_action(&app, "new-req", |a| a.new_req_dialog());
    window_action(&app, "new-crl", |a| a.new_crl_dialog());
    window_action(&app, "import", |a| a.import_dialog());
    window_action(&app, "token", |a| a.token_dialog());
    window_action(&app, "open-db", |a| a.open_database());
    window_action(&app, "new-db", |a| a.new_database());
    window_action(&app, "encrypt-db", |a| a.encrypt_database_dialog());
    window_action(&app, "about", |a| a.about());

    ui_app.set_accels_for_action("win.new-key", &["<Control>N"]);
    ui_app.set_accels_for_action("win.new-cert", &["<Control>C"]);
    ui_app.set_accels_for_action("win.new-req", &["<Control>R"]);
    ui_app.set_accels_for_action("win.import", &["<Control>I"]);
    ui_app.set_accels_for_action("win.open-db", &["<Control>O"]);

    let menu = gtk::gio::Menu::new();
    let sec_new = gtk::gio::Menu::new();
    sec_new.append(Some(&tr!("New Private Key…")), Some("win.new-key"));
    sec_new.append(Some(&tr!("New Certificate…")), Some("win.new-cert"));
    sec_new.append(Some(&tr!("New Request…")), Some("win.new-req"));
    menu.append_section(None, &sec_new);
    let sec_file = gtk::gio::Menu::new();
    sec_file.append(Some(&tr!("Import from File…")), Some("win.import"));
    sec_file.append(Some(&tr!("New Revocation List…")), Some("win.new-crl"));
    sec_file.append(Some(&tr!("PKCS#11 Token…")), Some("win.token"));
    menu.append_section(None, &sec_file);
    let sec_db = gtk::gio::Menu::new();
    sec_db.append(Some(&tr!("Open Database…")), Some("win.open-db"));
    sec_db.append(Some(&tr!("New Database…")), Some("win.new-db"));
    sec_db.append(Some(&tr!("Encrypt Database…")), Some("win.encrypt-db"));
    menu.append_section(Some(&tr!("Database")), &sec_db);
    let sec_about = gtk::gio::Menu::new();
    sec_about.append(Some(&tr!("About XCA RS")), Some("win.about"));
    menu.append_section(None, &sec_about);

    let menu_btn = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .primary(true)
        .menu_model(&menu)
        .build();
    header.pack_start(&menu_btn);

    app.refresh();
    window.present();
    app
}
