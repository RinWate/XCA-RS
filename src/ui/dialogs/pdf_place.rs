//! Click-to-place picker for the PDF signature stamp: a poppler-rendered
//! page preview; a click sets the stamp center, shown as a dashed ghost.

use super::{error_dialog, form_dialog};
use crate::tr;
use gtk::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;

/// The chosen stamp position: 1-based page and the stamp CENTER in PDF
/// points (y counted from the page bottom, as in the PDF coordinate
/// system).
#[derive(Clone, Copy, Debug)]
pub struct Placement {
    pub page: u32,
    pub cx: f64,
    pub cy: f64,
}

/// Stamp plate size in points — mirrors the cairo plate in pdf_sign.
pub const STAMP_W: f64 = 210.0;
pub const STAMP_H: f64 = 64.0;

pub fn open_placement<F: Fn(Placement) + 'static>(
    parent: &adw::ApplicationWindow,
    path: &Path,
    current: Option<Placement>,
    done: F,
) {
    let uri = gtk::glib::filename_to_uri(path, None)
        .unwrap_or_else(|_| format!("file://{}", path.to_string_lossy()).into());
    let doc = match poppler::Document::from_file(uri.as_str(), None) {
        Ok(d) => d,
        Err(e) => {
            error_dialog(
                parent,
                &format!("{}: {e}", tr!("Cannot open the PDF for preview")),
            );
            return;
        }
    };
    let n_pages = doc.n_pages().max(1) as u32;

    let form = form_dialog(&tr!("Stamp Position"), 700);
    let page_no: Rc<Cell<u32>> = Rc::new(Cell::new(
        current.map_or(1, |p| p.page.clamp(1, n_pages)) - 1,
    ));
    let chosen: Rc<Cell<Option<Placement>>> = Rc::new(Cell::new(current));

    // Page navigation: ‹ n / N ›
    let nav = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    nav.set_halign(gtk::Align::Center);
    let prev = gtk::Button::from_icon_name("go-previous-symbolic");
    let counter = gtk::Label::new(None);
    let next = gtk::Button::from_icon_name("go-next-symbolic");
    nav.append(&prev);
    nav.append(&counter);
    nav.append(&next);
    let hint = gtk::Label::new(Some(&tr!(
        "Click on the page to place the signature stamp."
    )));
    hint.add_css_class("dim-label");
    hint.set_margin_bottom(6);

    let area = gtk::DrawingArea::new();
    area.set_vexpand(true);
    area.set_hexpand(true);
    area.set_size_request(500, 400);

    // Preview geometry, recomputed on every draw: how the page maps into
    // the widget (fit + center), so clicks translate back to PDF points.
    #[derive(Clone, Copy, Default)]
    struct Geom {
        scale: f64,
        ox: f64,
        oy: f64,
        page_h: f64,
    }
    let geom: Rc<Cell<Geom>> = Rc::new(Cell::new(Geom::default()));

    {
        let doc = doc.clone();
        let page_no = page_no.clone();
        let chosen = chosen.clone();
        let geom = geom.clone();
        area.set_draw_func(move |_area, cr, w, h| {
            let idx = page_no.get() as i32;
            let Some(page) = doc.page(idx) else { return };
            let (pw, ph) = page.size();
            let scale = (w as f64 / pw).min(h as f64 / ph);
            let ox = (w as f64 - pw * scale) / 2.0;
            let oy = (h as f64 - ph * scale) / 2.0;
            geom.set(Geom { scale, ox, oy, page_h: ph });

            cr.save().unwrap();
            cr.translate(ox, oy);
            cr.scale(scale, scale);
            cr.set_source_rgb(1.0, 1.0, 1.0);
            cr.rectangle(0.0, 0.0, pw, ph);
            cr.fill().unwrap();
            page.render(cr);
            cr.restore().unwrap();

            // Ghost stamp at the chosen spot (this page only).
            if let Some(p) = chosen.get()
                && p.page == idx as u32 + 1
            {
                let x = p.cx - STAMP_W / 2.0;
                let y_pdf = p.cy + STAMP_H / 2.0;
                let y = ph - y_pdf;
                cr.save().unwrap();
                cr.translate(ox, oy);
                cr.scale(scale, scale);
                cr.set_source_rgba(0.21, 0.52, 0.89, 0.9);
                cr.set_line_width(1.2 / scale);
                cr.set_dash([5.0 / scale, 3.0 / scale].as_ref(), 0.0);
                cr.rectangle(x, y, STAMP_W, STAMP_H);
                cr.stroke().unwrap();
                cr.restore().unwrap();
            }
        });
    }

    let cancel = form.close_button(&tr!("Cancel"));
    let apply = form.apply_button(&tr!("Choose"));
    apply.set_sensitive(chosen.get().is_none());

    // Click → stamp center in PDF points.
    {
        let chosen = chosen.clone();
        let geom = geom.clone();
        let page_no = page_no.clone();
        let area2 = area.clone();
        let apply2 = apply.clone();
        let click = gtk::GestureClick::new();
        click.connect_pressed(move |_, _, x, y| {
            let g = geom.get();
            let px = (x - g.ox) / g.scale;
            // Widget y is top-down; PDF y is bottom-up.
            let py = g.page_h - (y - g.oy) / g.scale;
            chosen.set(Some(Placement {
                page: page_no.get() + 1,
                cx: px,
                cy: py,
            }));
            apply2.set_sensitive(true);
            area2.queue_draw();
        });
        area.add_controller(click);
    }

    let update_nav = {
        let counter = counter.clone();
        let prev = prev.clone();
        let next = next.clone();
        let page_no = page_no.clone();
        let area = area.clone();
        move || {
            counter.set_text(&format!("{} / {n_pages}", page_no.get() + 1));
            prev.set_sensitive(page_no.get() > 0);
            next.set_sensitive(page_no.get() + 1 < n_pages);
            area.queue_draw();
        }
    };
    update_nav();
    {
        let page_no = page_no.clone();
        let update = update_nav.clone();
        prev.connect_clicked(move |_| {
            page_no.set(page_no.get().saturating_sub(1));
            update();
        });
    }
    {
        let page_no = page_no.clone();
        let update = update_nav.clone();
        next.connect_clicked(move |_| {
            if page_no.get() + 1 < n_pages {
                page_no.set(page_no.get() + 1);
            }
            update();
        });
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 6);
    content.set_margin_top(6);
    content.append(&nav);
    content.append(&hint);
    content.append(&area);
    let g = form.group("");
    g.add(&content);

    {
        let dlg = form.dlg.clone();
        cancel.connect_clicked(move |_| {
            dlg.close();
        });
    }

    {
        let dlg = form.dlg.clone();
        let chosen = chosen.clone();
        apply.connect_clicked(move |_| {
            if let Some(p) = chosen.get() {
                dlg.close();
                done(p);
            }
        });
    }
    form.dlg.present(Some(parent));
}
