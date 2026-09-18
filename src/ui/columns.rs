//! `gtk::ColumnView` construction helpers.

use super::item::PkiItemObject;
use gtk::glib;
use gtk::prelude::*;

/// A single text column bound to a string property of `PkiItemObject`.
///
/// Uses a plain ellipsizing Label: GtkInscription's defaults (3–5 chars
/// wide, hard clipping) truncate cell values, while the Label sizes the
/// column to its content and only ellipsizes when the column is narrowed.
pub fn text_column(title: &str, prop: &'static str, expand: bool) -> gtk::ColumnViewColumn {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(move |_, item| {
        let item = item.downcast_ref::<gtk::ListItem>().expect("ListItem");
        let label = gtk::Label::new(None);
        label.set_halign(gtk::Align::Fill);
        label.set_xalign(0.0);
        label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        item.set_child(Some(&label));
        item.property_expression("item")
            .chain_property::<PkiItemObject>(prop)
            .bind(&label, "label", glib::Object::NONE);
    });
    let col = gtk::ColumnViewColumn::new(Some(title), Some(factory));
    col.set_expand(expand);
    col.set_resizable(true);
    col
}

/// A column view with single selection over a `gio::ListStore`.
pub fn column_view(store: &gtk::gio::ListStore, cols: Vec<gtk::ColumnViewColumn>) -> (gtk::ColumnView, gtk::SingleSelection) {
    let selection = gtk::SingleSelection::new(Some(store.clone()));
    let view = gtk::ColumnView::new(Some(selection.clone()));
    for c in cols {
        view.append_column(&c);
    }
    view.set_hexpand(true);
    view.set_vexpand(true);
    view.set_enable_rubberband(true);
    (view, selection)
}

/// Currently selected row id (the `id` property), if any.
pub fn selected_id(selection: &gtk::SingleSelection) -> Option<i64> {
    selection
        .selected_item()
        .and_then(|o| o.downcast::<PkiItemObject>().ok())
        .map(|item| item.id())
}
