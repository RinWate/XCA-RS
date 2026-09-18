//! XCA-style subjectAltName editor: a list of typed entries (DNS, IP,
//! email, URI), each editable in place, with add/remove — replacing the
//! old free-form "DNS:…, IP:…" text field.

use super::{form_dialog, row_text};
use crate::app::App;
use crate::tr;
use gtk::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SanKind {
    Dns,
    Ip,
    Email,
    Uri,
}

impl SanKind {
    pub fn label(&self) -> &'static str {
        match self {
            SanKind::Dns => "DNS",
            SanKind::Ip => "IP",
            SanKind::Email => "email",
            SanKind::Uri => "URI",
        }
    }

    /// The X.509 subjectAltName prefix for this entry type.
    pub fn prefix(&self) -> &'static str {
        match self {
            SanKind::Dns => "DNS:",
            SanKind::Ip => "IP:",
            SanKind::Email => "email:",
            SanKind::Uri => "URI:",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SanEntry {
    pub kind: SanKind,
    pub value: String,
}

impl SanEntry {
    /// "DNS:example.com" — the raw form `CertParams::san` expects.
    pub fn to_raw(&self) -> String {
        format!("{}{}", self.kind.prefix(), self.value)
    }

    /// Parse a raw SAN item; unknown prefixes fall back to a DNS entry.
    /// (Kept for the upcoming cert-reissue/edit flows; exercised by tests.)
    #[allow(dead_code)]
    pub fn parse(s: &str) -> SanEntry {
        let s = s.trim();
        for kind in [SanKind::Dns, SanKind::Ip, SanKind::Email, SanKind::Uri] {
            if let Some(v) = s.strip_prefix(kind.prefix()) {
                return SanEntry {
                    kind,
                    value: v.trim().to_string(),
                };
            }
        }
        SanEntry {
            kind: SanKind::Dns,
            value: s.to_string(),
        }
    }
}

/// Short human-readable list for the parent form row subtitle.
pub fn summary(entries: &[SanEntry]) -> String {
    if entries.is_empty() {
        tr!("no SAN entries")
    } else {
        entries
            .iter()
            .map(|e| e.to_raw())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn kind_at(selected: u32) -> SanKind {
    match selected {
        1 => SanKind::Ip,
        2 => SanKind::Email,
        3 => SanKind::Uri,
        _ => SanKind::Dns,
    }
}

fn selected_of(kind: SanKind) -> u32 {
    match kind {
        SanKind::Dns => 0,
        SanKind::Ip => 1,
        SanKind::Email => 2,
        SanKind::Uri => 3,
    }
}

struct SanRow {
    kind: gtk::DropDown,
    value: adw::EntryRow,
}

fn append_row(
    group: &adw::PreferencesGroup,
    rows: &Rc<RefCell<Vec<SanRow>>>,
    model: &gtk::StringList,
    entry: Option<&SanEntry>,
) {
    let value = adw::EntryRow::builder().title(tr!("Value")).build();
    if let Some(e) = entry {
        value.set_property("text", &e.value);
    }

    let kind = gtk::DropDown::new(
        Some(model.clone().upcast::<gtk::gio::ListModel>()),
        Some(&gtk::StringObject::this_expression("string")),
    );
    kind.set_selected(entry.map(|e| selected_of(e.kind)).unwrap_or(0));
    kind.set_valign(gtk::Align::Center);
    value.add_prefix(&kind);

    let remove = gtk::Button::new();
    remove.set_icon_name("list-remove-symbolic");
    remove.add_css_class("flat");
    remove.set_valign(gtk::Align::Center);
    remove.set_tooltip_text(Some(&tr!("Remove")));
    value.add_suffix(&remove);

    {
        let rows = rows.clone();
        let group = group.clone();
        let removed = value.clone();
        remove.connect_clicked(move |_| {
            group.remove(&removed);
            rows.borrow_mut().retain(|r| r.value != removed);
        });
    }

    group.add(&value);
    rows.borrow_mut().push(SanRow { kind, value });
}

/// Open the editor pre-filled with `initial`; `on_apply` receives the
/// collected entries (empty values skipped).
pub fn open_edit(app: &App, initial: Vec<SanEntry>, on_apply: impl Fn(Vec<SanEntry>) + 'static) {
    let form = form_dialog(&tr!("SAN Editor"), 460);
    let group = form.group(&tr!("Subject Alt Names"));
    // height_request is a minimum, not a clamp: the dialog opens tall
    // enough for three entry rows and still grows when rows are added.
    // (set_content_height must not be used here — it pins the size and
    // the extra rows end up hidden in the scroll area.)
    group.set_height_request(3 * 54 + 40);
    let model = gtk::StringList::new(&[
        SanKind::Dns.label(),
        SanKind::Ip.label(),
        SanKind::Email.label(),
        SanKind::Uri.label(),
    ]);

    let rows: Rc<RefCell<Vec<SanRow>>> = Rc::new(RefCell::new(Vec::new()));
    if initial.is_empty() {
        append_row(&group, &rows, &model, None);
    } else {
        for e in &initial {
            append_row(&group, &rows, &model, Some(e));
        }
    }

    let cancel = form.close_button(&tr!("Cancel"));
    let apply = form.apply_button(&tr!("Apply"));
    let add = gtk::Button::new();
    add.set_icon_name("list-add-symbolic");
    add.add_css_class("flat");
    add.set_tooltip_text(Some(&tr!("Add")));
    form.header.pack_start(&add);
    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    {
        let group = group.clone();
        let rows = rows.clone();
        let model = model.clone();
        add.connect_clicked(move |_| {
            append_row(&group, &rows, &model, None);
        });
    }

    let dlg = form.dlg.clone();
    {
        let rows = rows.clone();
        apply.connect_clicked(move |_| {
            let entries: Vec<SanEntry> = rows
                .borrow()
                .iter()
                .map(|r| SanEntry {
                    kind: kind_at(r.kind.selected()),
                    value: row_text(&r.value).trim().to_string(),
                })
                .filter(|e| !e.value.is_empty())
                .collect();
            dlg.close();
            on_apply(entries);
        });
    }

    form.dlg.present(Some(&app.window));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_roundtrip() {
        let e = SanEntry::parse("IP:10.0.0.5");
        assert_eq!(e.kind, SanKind::Ip);
        assert_eq!(e.value, "10.0.0.5");
        assert_eq!(e.to_raw(), "IP:10.0.0.5");

        let e = SanEntry::parse("email:a@b.c");
        assert_eq!(e.kind, SanKind::Email);

        let e = SanEntry::parse("URI:https://x.example");
        assert_eq!(e.kind, SanKind::Uri);

        // Unknown / bare values become DNS entries.
        let e = SanEntry::parse("bare.example");
        assert_eq!(e.kind, SanKind::Dns);
        assert_eq!(e.to_raw(), "DNS:bare.example");
    }

    #[test]
    fn summary_lists_raw_entries() {
        let entries = vec![
            SanEntry {
                kind: SanKind::Dns,
                value: "a.example".into(),
            },
            SanEntry {
                kind: SanKind::Ip,
                value: "10.0.0.1".into(),
            },
        ];
        assert_eq!(summary(&entries), "DNS:a.example, IP:10.0.0.1");
    }
}
