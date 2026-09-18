//! `gtk::ColumnView` construction helpers.

use super::item::PkiItemObject;
use gtk::glib;
use gtk::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;

/// Fired on right-click over a row cell: (item, row position in the
/// selection model, widget under the cursor, x/y in widget coordinates).
/// Used by the main window to select the row and show its context menu.
pub type RowMenuCb = Rc<dyn Fn(&PkiItemObject, u32, &gtk::Widget, f64, f64)>;

/// The callback is installed only after the main window (and the shared
/// App state) exist; the column factory keeps this slot and reads it at
/// right-click time.
pub type RowMenuSlot = Rc<RefCell<Option<RowMenuCb>>>;

/// Lazy children of the certificate tree: cert id → model of child rows.
/// Rebuilt by `App::refresh`; read by the `TreeListModel` create function.
pub type ChildrenMap = Rc<RefCell<std::collections::HashMap<i64, gtk::gio::ListStore>>>;

/// A single text column bound to a string property of `PkiItemObject`.
///
/// Uses a plain ellipsizing Label: GtkInscription's defaults (3–5 chars
/// wide, hard clipping) truncate cell values, while the Label sizes the
/// column to its content and only ellipsizes when the column is narrowed.
pub fn text_column(
    title: &str,
    prop: &'static str,
    expand: bool,
    menu: Option<RowMenuSlot>,
) -> gtk::ColumnViewColumn {
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
        if let Some(slot) = &menu {
            // Right-click menu: the gesture lives on the cell, the item is
            // read from the ListItem at press time (cells are recycled).
            let gesture = gtk::GestureClick::new();
            gesture.set_button(3);
            let item = item.clone();
            let slot = slot.clone();
            let cell = label.clone();
            gesture.connect_pressed(move |_, _, x, y| {
                let cb = slot.borrow().clone();
                if let (Some(cb), Some(obj)) = (
                    cb,
                    item.item().and_then(|o| o.downcast::<PkiItemObject>().ok()),
                ) {
                    cb(&obj, item.position(), cell.upcast_ref::<gtk::Widget>(), x, y);
                }
            });
            label.add_controller(gesture);
        }
    });
    let col = gtk::ColumnViewColumn::new(Some(title), Some(factory));
    col.set_expand(expand);
    col.set_resizable(true);
    col
}

/// A column view over an existing single-selection model.
pub fn column_view(selection: &gtk::SingleSelection, cols: Vec<gtk::ColumnViewColumn>) -> gtk::ColumnView {
    let view = gtk::ColumnView::new(Some(selection.clone()));
    for c in cols {
        view.append_column(&c);
    }
    view.set_hexpand(true);
    view.set_vexpand(true);
    view.set_enable_rubberband(true);
    view
}

/// A column over a `TreeListModel` (no passthrough): the list item is a
/// `TreeListRow`, so the property is resolved through its `item`. With
/// `expander` the cell is wrapped in a `GtkTreeExpander` — indentation
/// and the ▸/▾ toggle, like the certificate tree of the original XCA.
pub fn tree_column(
    title: &str,
    prop: &'static str,
    expand: bool,
    menu: Option<RowMenuSlot>,
    expander: bool,
) -> gtk::ColumnViewColumn {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(move |_, item| {
        let item = item.downcast_ref::<gtk::ListItem>().expect("ListItem");
        let label = gtk::Label::new(None);
        label.set_halign(gtk::Align::Fill);
        label.set_xalign(0.0);
        label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        if expander {
            let exp = gtk::TreeExpander::new();
            exp.set_child(Some(&label));
            item.set_child(Some(&exp));
        } else {
            item.set_child(Some(&label));
        }
        item.property_expression("item")
            .chain_property::<gtk::TreeListRow>("item")
            .chain_property::<PkiItemObject>(prop)
            .bind(&label, "label", glib::Object::NONE);
        if let Some(slot) = &menu {
            let gesture = gtk::GestureClick::new();
            gesture.set_button(3);
            let li = item.clone();
            let slot = slot.clone();
            let cell = label.clone();
            gesture.connect_pressed(move |_, _, x, y| {
                let cb = slot.borrow().clone();
                let obj = li
                    .item()
                    .and_then(|o| o.downcast::<gtk::TreeListRow>().ok())
                    .and_then(|r| r.item())
                    .and_then(|o| o.downcast::<PkiItemObject>().ok());
                if let (Some(cb), Some(obj)) = (cb, obj) {
                    let widget = cell.ancestor(gtk::TreeExpander::static_type())
                        .unwrap_or_else(|| cell.clone().upcast::<gtk::Widget>());
                    cb(&obj, li.position(), &widget, x, y);
                }
            });
            label.add_controller(gesture);
        }
    });
    // The expander needs the row itself; expressions cannot pass it, so
    // bind imperatively (cells are recycled, bind fires on each reuse).
    if expander {
        factory.connect_bind(|_, item| {
            let Ok(item) = item.clone().downcast::<gtk::ListItem>() else {
                return;
            };
            let (Some(child), Some(obj)) = (item.child(), item.item()) else {
                return;
            };
            if let (Ok(exp), Ok(row)) = (
                child.downcast::<gtk::TreeExpander>(),
                obj.downcast::<gtk::TreeListRow>(),
            ) {
                exp.set_list_row(Some(&row));
            }
        });
    }
    let col = gtk::ColumnViewColumn::new(Some(title), Some(factory));
    col.set_expand(expand);
    col.set_resizable(true);
    col
}

/// Currently selected row id (the `id` property), if any. Understands
/// both flat rows and `TreeListRow` wrappers (certificate tree).
pub fn selected_id(selection: &gtk::SingleSelection) -> Option<i64> {
    selection
        .selected_item()
        .and_then(|o| {
            if let Ok(row) = o.clone().downcast::<gtk::TreeListRow>() {
                row.item().and_then(|i| i.downcast::<PkiItemObject>().ok())
            } else {
                o.downcast::<PkiItemObject>().ok()
            }
        })
        .map(|item| item.id())
}

#[cfg(test)]
mod tree_probe {
    use super::*;

    #[test]
    fn probe_tree_flattens_children() {
        assert!(gtk::init().is_ok());
        let root = gtk::gio::ListStore::new::<PkiItemObject>();
        root.append(&PkiItemObject::new(1, "CA", "s", "i", "b"));
        let kids = gtk::gio::ListStore::new::<PkiItemObject>();
        kids.append(&PkiItemObject::new(2, "leaf", "s", "i", "b"));
        let children: ChildrenMap = Rc::new(RefCell::new(
            std::iter::once((1i64, kids.clone())).collect(),
        ));
        let slot = children.clone();
        let tree = gtk::TreeListModel::new(
            root.upcast::<gtk::gio::ListModel>(),
            false,
            true,
            move |item: &glib::Object| {
                let id = item.downcast_ref::<PkiItemObject>()?.id();
                slot.borrow()
                    .get(&id)
                    .map(|s| s.clone().upcast::<gtk::gio::ListModel>())
            },
        );
        assert_eq!(tree.n_items(), 2, "root + expanded child");
        let r0 = tree.item(0).unwrap().downcast::<gtk::TreeListRow>().unwrap();
        assert_eq!(
            r0.item().unwrap().downcast::<PkiItemObject>().unwrap().id(),
            1
        );
        let r1 = tree.item(1).unwrap().downcast::<gtk::TreeListRow>().unwrap();
        assert_eq!(r1.depth(), 1);
        assert_eq!(
            r1.item().unwrap().downcast::<PkiItemObject>().unwrap().id(),
            2
        );
    }
}
