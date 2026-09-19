//! Row object backing the list models in the main window. One flat GObject
//! with string properties bound to `gtk::ColumnView` columns via expressions.

use gtk::glib::{self, Object, Properties};
use gtk::glib::subclass::prelude::*;
use std::cell::{Cell, RefCell};

glib::wrapper! {
    pub struct PkiItemObject(ObjectSubclass<imp::PkiItem>);
}

impl PkiItemObject {
    pub fn new(id: i64, name: &str, detail: &str, extra: &str, badge: &str, sig: &str) -> Self {
        Object::builder()
            .property("id", id)
            .property("name", name)
            .property("detail", detail)
            .property("extra", extra)
            .property("badge", badge)
            .property("sig", sig)
            .build()
    }
}

mod imp {
    use super::*;
    use gtk::glib::prelude::*;

    #[derive(Properties, Default)]
    #[properties(wrapper_type = super::PkiItemObject)]
    pub struct PkiItem {
        #[property(get, set)]
        pub id: Cell<i64>,
        #[property(get, set)]
        pub name: RefCell<String>,
        #[property(get, set)]
        pub detail: RefCell<String>,
        #[property(get, set)]
        pub extra: RefCell<String>,
        #[property(get, set)]
        pub badge: RefCell<String>,
        /// Signature algorithm (certificate rows).
        #[property(get, set)]
        pub sig: RefCell<String>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PkiItem {
        const NAME: &'static str = "XcaPkiItem";
        type Type = super::PkiItemObject;
    }

    #[glib::derived_properties]
    impl ObjectImpl for PkiItem {}
}
