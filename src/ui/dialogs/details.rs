//! Properties dialogs for keys, certificates and requests: parsed fields
//! plus the OpenSSL text dump.

use super::{action_row, form_dialog, text_block};
use crate::app::App;
use crate::crypto;
use crate::db::{CertRecord, KeyRecord, ReqRecord};
use crate::tr;
use gtk::prelude::*;
use libadwaita::prelude::*;

pub fn open_key(app: &App, rec: &KeyRecord) {
    let form = form_dialog(&tr!("Key Properties"), 500);
    let g = form.group(&tr!("Private Key"));
    g.add(&action_row(&tr!("Internal Name"), &rec.name));
    g.add(&action_row(
        &tr!("Type"),
        &rec.type_label(),
    ));
    let dump = crypto::load_private_key(&rec.pem)
        .and_then(|k| {
            k.public_key_to_pem()
                .map_err(|e| e.to_string())
        })
        .map(|pem| String::from_utf8_lossy(&pem).to_string())
        .unwrap_or_else(|e| format!("{}: {e}", tr!("Error")));
    let g2 = form.group(&tr!("Public Key (PEM)"));
    g2.add(&text_block(&dump));

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| { dlg.close(); });
    }
    form.dlg.present(Some(&app.window));
}

pub fn open_cert(app: &App, rec: &CertRecord) {
    let form = form_dialog(&tr!("Certificate Properties"), 560);
    let cert = match crypto::load_cert(&rec.pem) {
        Ok(c) => c,
        Err(e) => {
            super::error_dialog(&app.window, &e);
            return;
        }
    };
    let s = crypto::cert_summary(cert.as_ref());
    let g = form.group(&tr!("Certificate"));
    g.add(&action_row(&tr!("Internal Name"), &rec.name));
    g.add(&action_row(&tr!("Subject"), &s.subject));
    g.add(&action_row(&tr!("Issuer"), &s.issuer));
    g.add(&action_row(&tr!("Serial"), &format!("0x{}", s.serial)));
    g.add(&action_row(&tr!("Not Before"), &s.not_before));
    g.add(&action_row(&tr!("Not After"), &s.not_after));
    let expiry = if s.expires_days < 0 {
        tr!("expired %{count} days ago", count = -s.expires_days)
    } else {
        tr!("valid for %{count} days", count = s.expires_days)
    };
    g.add(&action_row(&tr!("Validity"), &expiry));
    g.add(&action_row(
        &tr!("Signature Algorithm"),
        &crypto::signature_algorithm(cert.as_ref()),
    ));
    g.add(&action_row(&tr!("Status"), &crypto::cert_status(&s)));

    // Subject Alt Names, one row per entry (same prefixes as the SAN editor).
    if let Some(sans) = cert.subject_alt_names() {
        let mut rows: Vec<(&str, String)> = Vec::new();
        for name in sans.iter() {
            if let Some(d) = name.dnsname() {
                rows.push(("DNS", d.to_string()));
            }
            if let Some(ip) = name.ipaddress() {
                let text = match ip.len() {
                    4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                    16 => {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(ip);
                        std::net::Ipv6Addr::from(b).to_string()
                    }
                    _ => ip
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                };
                rows.push(("IP", text));
            }
            if let Some(e) = name.email() {
                rows.push(("email", e.to_string()));
            }
            if let Some(u) = name.uri() {
                rows.push(("URI", u.to_string()));
            }
        }
        if !rows.is_empty() {
            let gs = form.group(&tr!("Subject Alt Names"));
            for (kind, value) in rows {
                gs.add(&action_row(kind, &value));
            }
        }
    }

    // Installed X.509v3 extensions, as OpenSSL prints them.
    let exts = crypto::cert_extensions(cert.as_ref());
    if !exts.is_empty() {
        let ge = form.group(&tr!("X.509 v3 Extensions"));
        for (name, critical, value) in exts {
            let title = if critical {
                format!("{name} ({})", tr!("critical"))
            } else {
                name
            };
            let value = value.replace(['\n', '\r'], " ");
            ge.add(&action_row(&title, &value));
        }
    }

    // The chain up to the root, as linked in the database.
    if let Ok(chain) = app.db.lock().unwrap().cert_chain(rec.id)
        && chain.len() > 1 {
            let gc = form.group(&tr!("Certificate Chain"));
            for c in &chain {
                let title = if c.id == rec.id {
                    format!("{} — {}", c.name, tr!("this certificate"))
                } else {
                    c.name.clone()
                };
                gc.add(&action_row(&title, &c.subject));
            }
        }

    let g2 = form.group(&tr!("OpenSSL Dump"));
    g2.add(&text_block(&crypto::dump_cert(cert.as_ref())));

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| { dlg.close(); });
    }
    form.dlg.present(Some(&app.window));
}

pub fn open_req(app: &App, rec: &ReqRecord) {
    let form = form_dialog(&tr!("Request Properties"), 560);
    let req = match crypto::load_req(&rec.pem) {
        Ok(r) => r,
        Err(e) => {
            super::error_dialog(&app.window, &e);
            return;
        }
    };
    let g = form.group(&tr!("Certificate Request"));
    g.add(&action_row(&tr!("Internal Name"), &rec.name));
    g.add(&action_row(
        &tr!("Subject"),
        &crypto::name_to_string(req.subject_name()),
    ));
    let key_desc = req
        .public_key()
        .map(|p| crypto::key_kind_label(p.as_ref()))
        .unwrap_or_else(|e| format!("{}: {e}", tr!("Error")));
    g.add(&action_row(&tr!("Public Key"), &key_desc));

    let g2 = form.group(&tr!("OpenSSL Dump"));
    g2.add(&text_block(&crypto::dump_req(req.as_ref())));

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| { dlg.close(); });
    }
    form.dlg.present(Some(&app.window));
}

pub fn open_crl(app: &App, rec: &crate::db::CrlRecord) {
    let form = form_dialog(&tr!("Revocation List Properties"), 560);
    let crl = match crypto::load_crl(&rec.pem) {
        Ok(c) => c,
        Err(e) => {
            super::error_dialog(&app.window, &e);
            return;
        }
    };
    let g = form.group(&tr!("CRL"));
    g.add(&action_row(&tr!("Internal Name"), &rec.name));
    g.add(&action_row(
        &tr!("Issuer"),
        &crypto::name_to_string(crl.issuer_name()),
    ));
    g.add(&action_row(
        &tr!("Last Update"),
        &crl.last_update().to_string(),
    ));
    g.add(&action_row(
        &tr!("Next Update"),
        &crl.next_update().map(|t| t.to_string()).unwrap_or_default(),
    ));
    g.add(&action_row(&tr!("Revoked entries"), &rec.entries.to_string()));

    // One row per revoked certificate: serial as the title, revocation
    // date and reason (CRL entry extension) as the subtitle.
    let g2 = form.group(&tr!("Revoked Certificates"));
    let mut any = false;
    if let Some(stack) = crl.get_revoked() {
        for rev in stack.iter() {
            let serial = rev
                .serial_number()
                .to_bn()
                .ok()
                .and_then(|b| b.to_hex_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into());
            let reason = rev
                .extension::<openssl::x509::ReasonCode>()
                .ok()
                .flatten()
                .and_then(|(_, e)| e.get_i64().ok())
                .map(crate::xca_format::reason_name);
            let subtitle = match reason {
                Some(r) => format!("{} · {}", rev.revocation_date(), r),
                None => rev.revocation_date().to_string(),
            };
            g2.add(&action_row(&format!("0x{serial}"), &subtitle));
            any = true;
        }
    }
    if !any {
        g2.add(&action_row(&tr!("(no revoked certificates)"), ""));
    }

    let close = form.close_button(&tr!("Close"));
    {
        let dlg = form.dlg.clone();
        close.connect_clicked(move |_| { dlg.close(); });
    }
    form.dlg.present(Some(&app.window));
}
