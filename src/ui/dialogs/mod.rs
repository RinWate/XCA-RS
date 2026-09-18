//! Adwaita dialogs: shared form helpers and per-feature dialogs.

use gtk::glib;
use gtk::prelude::*;
use libadwaita::prelude::*;
use libadwaita as adw;

pub mod details;
pub mod export;
pub mod import;
pub mod new_cert;
pub mod new_crl;
pub mod new_key;
pub mod new_req;
pub mod password;
pub mod san;
pub mod token;

pub fn error_dialog(parent: &adw::ApplicationWindow, msg: &str) {
    let d = adw::AlertDialog::new(Some(&crate::tr!("Error")), Some(msg));
    d.add_response("ok", &crate::tr!("OK"));
    d.present(Some(parent));
}

/// EntryRow/PasswordEntryRow expose no text getters in libadwaita-rs 0.7,
/// so read the property directly.
pub fn row_text<R: glib::object::IsA<glib::Object>>(row: &R) -> String {
    row.property::<String>("text")
}

/// AdwDialog with a header bar over an AdwPreferencesPage — the standard
/// GNOME pattern for task dialogs.
pub struct Form {
    pub dlg: adw::Dialog,
    pub header: adw::HeaderBar,
    pub page: adw::PreferencesPage,
}

pub fn form_dialog(title: &str, width: i32) -> Form {
    let dlg = adw::Dialog::builder()
        .title(title)
        .content_width(width)
        .build();
    let tv = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    tv.add_top_bar(&header);
    let page = adw::PreferencesPage::new();
    // Outside of AdwPreferencesPage's native PreferencesDialog the page does
    // not scroll on its own, so long forms (New Certificate) were clipped.
    // max_content_height keeps the dialog within the window; taller content
    // scrolls instead of running off-screen.
    let sw = gtk::ScrolledWindow::new();
    sw.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    sw.set_propagate_natural_height(true);
    sw.set_max_content_height(520);
    sw.set_child(Some(&page));
    tv.set_content(Some(&sw));
    dlg.set_child(Some(&tv));
    Form { dlg, header, page }
}

impl Form {
    pub fn group(&self, title: &str) -> adw::PreferencesGroup {
        let g = adw::PreferencesGroup::builder().title(title).build();
        self.page.add(&g);
        g
    }

    pub fn apply_button(&self, label: &str) -> gtk::Button {
        let b = gtk::Button::with_label(label);
        b.add_css_class("suggested-action");
        self.header.pack_end(&b);
        b
    }

    pub fn close_button(&self, label: &str) -> gtk::Button {
        let b = gtk::Button::with_label(label);
        self.header.pack_start(&b);
        b
    }
}

pub fn entry(title: &str) -> adw::EntryRow {
    adw::EntryRow::builder().title(title).build()
}

pub fn entry_default(title: &str, text: &str) -> adw::EntryRow {
    let r = entry(title);
    r.set_property("text", text);
    r
}

pub fn password_entry(title: &str) -> adw::PasswordEntryRow {
    adw::PasswordEntryRow::builder().title(title).build()
}

pub fn combo(title: &str, items: &[&str], selected: u32) -> adw::ComboRow {
    let row = adw::ComboRow::builder().title(title).build();
    let model = gtk::StringList::new(items);
    row.set_model(Some(&model));
    row.set_expression(Some(&gtk::StringObject::this_expression("string")));
    row.set_selected(selected);
    row
}

/// ComboRow over dynamic labels: fixed prefix options plus named items with
/// ids. Returns the row and the id list aligned with the model items
/// (`None` for the prefix options).
pub fn combo_ids(
    title: &str,
    generate_labels: &[&str],
    named: &[(i64, String, String)],
    selected: u32,
) -> (adw::ComboRow, Vec<Option<i64>>) {
    let mut items: Vec<String> = Vec::new();
    let mut ids: Vec<Option<i64>> = Vec::new();
    for label in generate_labels {
        items.push((*label).to_string());
        ids.push(None);
    }
    for (id, label, extra) in named {
        items.push(format!("{label} — {extra}"));
        ids.push(Some(*id));
    }
    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    (combo(title, &refs, selected), ids)
}

pub fn switch(title: &str, subtitle: &str, active: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .subtitle(subtitle)
        .active(active)
        .build()
}

pub fn spin(title: &str, value: f64, min: f64, max: f64, step: f64) -> adw::SpinRow {
    let adj = gtk::Adjustment::new(value, min, max, step, step * 10.0, 0.0);
    adw::SpinRow::builder()
        .title(title)
        .adjustment(&adj)
        .digits(0)
        .build()
}

pub fn action_row(title: &str, subtitle: &str) -> adw::ActionRow {
    adw::ActionRow::builder().title(title).subtitle(subtitle).build()
}

/// Read-only monospace text block inside a preferences group.
pub fn text_block(text: &str) -> gtk::Widget {
    let tv = gtk::TextView::new();
    tv.buffer().set_text(text);
    tv.set_editable(false);
    tv.set_cursor_visible(false);
    tv.set_monospace(true);
    tv.set_wrap_mode(gtk::WrapMode::None);
    tv.set_margin_top(12);
    tv.set_margin_bottom(12);
    tv.set_margin_start(12);
    tv.set_margin_end(12);
    let sw = gtk::ScrolledWindow::new();
    sw.set_child(Some(&tv));
    sw.set_height_request(260);
    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 0);
    box_.append(&sw);
    box_.add_css_class("card");
    box_.upcast::<gtk::Widget>()
}
