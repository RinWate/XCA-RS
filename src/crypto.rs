//! Thin wrappers around the `openssl` crate: key generation, certificate and
//! CSR building, import sniffing. The original XCA talks to OpenSSL directly
//! through its C++ classes; here the same operations are exposed as small,
//! `String`-error functions that the UI layer can call safely.

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{HasPrivate, HasPublic, Id, PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::{
    X509, X509Builder, X509Name, X509NameBuilder, X509NameRef, X509Req, X509ReqBuilder,
    X509ReqRef, X509Extension, X509Ref,
};
use foreign_types::{ForeignType, ForeignTypeRef};

pub type CryptoResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    format!("{e}")
}

/// Key kinds offered by the "New Private Key" dialog.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NewKeyKind {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    EcP521,
    Ed25519,
}

impl NewKeyKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Rsa2048 => "RSA 2048",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
            Self::EcP256 => "EC P-256",
            Self::EcP384 => "EC P-384",
            Self::EcP521 => "EC P-521",
            Self::Ed25519 => "Ed25519",
        }
    }

    /// Variant index used by the combo rows in the new-key dialog.
    pub fn from_combos(type_idx: u32, size_idx: u32) -> Self {
        match type_idx {
            1 => match size_idx {
                1 => Self::EcP384,
                2 => Self::EcP521,
                _ => Self::EcP256,
            },
            2 => Self::Ed25519,
            _ => match size_idx {
                1 => Self::Rsa3072,
                2 => Self::Rsa4096,
                _ => Self::Rsa2048,
            },
        }
    }
}

fn curve_nid(name: &str) -> Nid {
    match name {
        "P-256" => Nid::X9_62_PRIME256V1,
        "P-384" => Nid::SECP384R1,
        "P-521" => Nid::SECP521R1,
        _ => Nid::X9_62_PRIME256V1,
    }
}

pub fn generate_key(kind: NewKeyKind) -> CryptoResult<PKey<Private>> {
    match kind {
        NewKeyKind::Rsa2048 => PKey::from_rsa(Rsa::generate(2048).map_err(err)?).map_err(err),
        NewKeyKind::Rsa3072 => PKey::from_rsa(Rsa::generate(3072).map_err(err)?).map_err(err),
        NewKeyKind::Rsa4096 => PKey::from_rsa(Rsa::generate(4096).map_err(err)?).map_err(err),
        NewKeyKind::EcP256 => ec_key("P-256"),
        NewKeyKind::EcP384 => ec_key("P-384"),
        NewKeyKind::EcP521 => ec_key("P-521"),
        NewKeyKind::Ed25519 => PKey::generate_ed25519().map_err(err),
    }
}

fn ec_key(curve: &str) -> CryptoResult<PKey<Private>> {
    let group = EcGroup::from_curve_name(curve_nid(curve)).map_err(err)?;
    let key = EcKey::generate(&group).map_err(err)?;
    PKey::from_ec_key(key).map_err(err)
}

/// (kind, size, curve) describing a key for display and storage. Works
/// for private and public-only keys alike — the private part is never used.
pub fn key_info<P: HasPublic>(key: &PKeyRef<P>) -> (String, i32, String) {
    match key.id() {
        Id::RSA => match key.rsa() {
            Ok(rsa) => ("RSA".into(), rsa.size() as i32 * 8, String::new()),
            Err(_) => ("RSA".into(), 0, String::new()),
        },
        Id::EC => match key.ec_key() {
            Ok(ec) => {
                let curve = ec
                    .group()
                    .curve_name()
                    .map(curve_label)
                    .unwrap_or("unknown")
                    .to_string();
                let bits = ec.group().degree() as i32;
                ("EC".into(), bits, curve)
            }
            Err(_) => ("EC".into(), 0, String::new()),
        },
        Id::ED25519 => ("ED25519".into(), 256, "Ed25519".into()),
        Id::ED448 => ("ED448".into(), 456, "Ed448".into()),
        Id::X25519 => ("X25519".into(), 256, "X25519".into()),
        other => (format!("{other:?}"), 0, String::new()),
    }
}

pub fn curve_label(nid: Nid) -> &'static str {
    match nid {
        Nid::X9_62_PRIME256V1 => "P-256",
        Nid::SECP384R1 => "P-384",
        Nid::SECP521R1 => "P-521",
        _ => "unknown",
    }
}

/// Kind-only description for keys only known by their public part.
pub fn key_kind_label<P: HasPublic>(key: &PKeyRef<P>) -> String {
    match key.id() {
        Id::RSA => "RSA".into(),
        Id::EC => match key.ec_key() {
            Ok(ec) => {
                let curve = ec
                    .group()
                    .curve_name()
                    .map(curve_label)
                    .unwrap_or("unknown");
                format!("EC {curve}")
            }
            Err(_) => "EC".into(),
        },
        Id::ED25519 => "Ed25519".into(),
        other => format!("{other:?}"),
    }
}

pub fn load_private_key(pem: &[u8]) -> CryptoResult<PKey<Private>> {
    PKey::private_key_from_pem(pem).map_err(|e| format!("Cannot load private key: {e}"))
}

/// Public-key view of any key (round-tripped via PEM to normalize the type).
pub fn public_of<P: HasPublic>(key: &PKeyRef<P>) -> CryptoResult<PKey<openssl::pkey::Public>> {
    let pem = key.public_key_to_pem().map_err(err)?;
    PKey::public_key_from_pem(&pem).map_err(err)
}

/// True when both keys carry the same public part.
pub fn same_public_key<P: HasPublic, Q: HasPublic>(a: &PKeyRef<P>, b: &PKeyRef<Q>) -> bool {
    match (a.public_key_to_der(), b.public_key_to_der()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Deep-copy an X509Name (e.g. taken from a CSR) for reuse in a
/// certificate. `to_owned` preserves the RDN value encodings; the former
/// entry-by-entry rebuild mangled non-ASCII BMPString values.
pub fn clone_name(name: &X509NameRef) -> CryptoResult<X509Name> {
    name.to_owned().map_err(err)
}

pub fn load_cert(pem: &[u8]) -> CryptoResult<X509> {
    X509::from_pem(pem).map_err(|e| format!("Cannot load certificate: {e}"))
}

pub fn load_req(pem: &[u8]) -> CryptoResult<X509Req> {
    X509Req::from_pem(pem).map_err(|e| format!("Cannot load request: {e}"))
}

pub fn load_crl(pem: &[u8]) -> CryptoResult<openssl::x509::X509Crl> {
    openssl::x509::X509Crl::from_pem(pem).map_err(|e| format!("Cannot load CRL: {e}"))
}

/// "CN=example.com, O=Org" rendering of an X509 name.
pub fn name_to_string(name: &X509NameRef) -> String {
    name.entries()
        .map(|e| {
            let key = e
                .object()
                .nid()
                .short_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "?".into());
            let val = e
                .data()
                .to_string()
                .map(|s| s.to_string())
                .unwrap_or_default();
            format!("{key}={val}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn cn_of_name(name: &X509NameRef) -> Option<String> {
    for e in name.entries() {
        if let Ok(k) = e.object().nid().short_name()
            && k == "CN" {
                return e.data().to_string().ok();
            }
    }
    None
}

pub fn serial_hex(cert: &X509Ref) -> String {
    cert.serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| "?".into())
}

/// Parsed summary used for the list columns and the details dialog.
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub expires_days: i64,
    pub is_ca: bool,
}

pub fn cert_summary(cert: &X509Ref) -> CertSummary {
    let now = Asn1Time::days_from_now(0).ok();
    let expires_days = match now.as_ref().map(|n| n.diff(cert.not_after())) {
        Some(Ok(d)) => d.days as i64,
        _ => 0,
    };
    let is_ca = unsafe { X509_check_ca(cert.as_ptr()) > 0 };
    CertSummary {
        subject: name_to_string(cert.subject_name()),
        issuer: name_to_string(cert.issuer_name()),
        serial: serial_hex(cert),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        expires_days,
        is_ca,
    }
}

pub fn cert_status(s: &CertSummary) -> String {
    let mut parts = Vec::new();
    if s.is_ca {
        parts.push("CA".into());
    }
    if s.expires_days < 0 {
        parts.push("expired".into());
    } else if s.expires_days < 30 {
        parts.push(format!("expires in {}d", s.expires_days));
    }
    parts.join(" · ")
}

/// Subject entries for certificate/CSR creation.
#[derive(Clone, Debug, Default)]
pub struct SubjectData {
    pub cn: String,
    pub org: String,
    pub org_unit: String,
    pub country: String,
    pub email: String,
}

impl SubjectData {
    pub fn build_name(&self) -> CryptoResult<X509Name> {
        let mut nb = X509NameBuilder::new().map_err(err)?;
        let mut any = false;
        let entries: [(&str, &str); 5] = [
            ("C", &self.country),
            ("O", &self.org),
            ("OU", &self.org_unit),
            ("CN", &self.cn),
            ("emailAddress", &self.email),
        ];
        for (k, v) in entries {
            if !v.trim().is_empty() {
                nb.append_entry_by_text(k, v.trim()).map_err(err)?;
                any = true;
            }
        }
        if !any {
            return Err("Subject must contain at least one field".into());
        }
        Ok(nb.build())
    }

}

/// Unit for the validity picker in the New Certificate dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidityUnit {
    Days,
    Weeks,
    Months,
    Years,
}

impl ValidityUnit {
    /// Index in the dialog's unit combo.
    pub fn from_combo(idx: u32) -> Self {
        match idx {
            0 => ValidityUnit::Days,
            1 => ValidityUnit::Weeks,
            2 => ValidityUnit::Months,
            _ => ValidityUnit::Years,
        }
    }
}

/// Days from today until the date advanced by `count` units. Months and
/// years follow the calendar, so "1 year" keeps the same date across leap
/// years and "Jan 31 + 1 month" lands on the last day of February.
pub fn validity_days(count: u32, unit: ValidityUnit) -> u32 {
    validity_days_at(crate::xca_format::today_days(), count, unit)
}

fn validity_days_at(today: i64, count: u32, unit: ValidityUnit) -> u32 {
    use crate::xca_format as xf;
    let n = count as i64;
    let target = match unit {
        ValidityUnit::Days => today + n,
        ValidityUnit::Weeks => today + n * 7,
        ValidityUnit::Months | ValidityUnit::Years => {
            let (y, m, d) = xf::civil_from_days(today);
            let months = if matches!(unit, ValidityUnit::Years) {
                n * 12
            } else {
                n
            };
            let total = y * 12 + (m - 1) + months;
            let (y2, m2) = (total.div_euclid(12), total.rem_euclid(12) + 1);
            let leap = y2 % 4 == 0 && (y2 % 100 != 0 || y2 % 400 == 0);
            let dim = match m2 {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 if leap => 29,
                _ => 28,
            };
            xf::days_from_civil(y2, m2, d.min(dim))
        }
    };
    (target - today).max(1) as u32
}

/// Parameters for `build_certificate`.
#[derive(Clone, Debug, Default)]
pub struct CertParams {
    pub validity_days: u32,
    pub is_ca: bool,
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
    pub ocsp_signing: bool,
    /// basicConstraints pathlen for CA certificates; None = unlimited.
    pub path_len: Option<u32>,
    /// Raw crlDistributionPoints values, e.g. "URI:http://ca.example/crl.pem".
    pub crl_dp: Vec<String>,
    /// Raw authorityInfoAccess values,
    /// e.g. "OCSP;URI:http://ocsp.example" or "caIssuers;URI:http://...".
    pub aia: Vec<String>,
    /// Raw SAN items, e.g. "DNS:example.com", "IP:10.0.0.1", "email:a@b.c".
    pub san: Vec<String>,
}

// ---- hand-assembled unencrypted PKCS#12 ----
//
// PKCS12_create always encrypts the bags and adds an integrity MAC, even
// with an empty or NULL password — such a file still makes every importer
// prompt for a password (Enter works). A truly password-free PFX keeps the
// safe bags as plain `data` ContentInfos and omits MacData, which is what
// these helpers build (RFC 7292 allows both).

fn der_concat(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// DER OBJECT IDENTIFIER from arcs, e.g. PKCS#7 data 1.2.840.113549.1.7.1.
fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(40 * arcs[0] + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut chunk = [0u8; 10];
        let mut n = 0;
        let mut v = a;
        loop {
            chunk[n] = (v & 0x7f) as u8;
            v >>= 7;
            n += 1;
            if v == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            body.push(chunk[i] | if i == 0 { 0 } else { 0x80 });
        }
    }
    der_tlv(0x06, &body)
}

/// PKCS#9 friendlyName attribute (BMPString / UTF-16BE) as bagAttributes.
fn friendly_name_attr(name: &str) -> Vec<u8> {
    let mut bmp = Vec::new();
    for u in name.encode_utf16() {
        bmp.extend_from_slice(&u.to_be_bytes());
    }
    let attr = der_tlv(
        0x30,
        &der_concat(&[
            der_oid(&[1, 2, 840, 113549, 1, 9, 20]),
            der_tlv(0x31, &der_tlv(0x1e, &bmp)),
        ]),
    );
    der_tlv(0x31, &attr)
}

/// SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT, attributes? }.
fn safe_bag(bag_id: Vec<u8>, value: Vec<u8>, name: &str) -> Vec<u8> {
    let mut parts = vec![bag_id, der_tlv(0xa0, &value)];
    if !name.is_empty() {
        parts.push(friendly_name_attr(name));
    }
    der_tlv(0x30, &der_concat(&parts))
}

/// CertBag with an X.509 certificate.
fn cert_bag_der(cert: &X509Ref) -> Vec<u8> {
    let der = cert.to_der().unwrap_or_default();
    der_tlv(
        0x30,
        &der_concat(&[
            der_oid(&[1, 2, 840, 113549, 1, 9, 22, 1]),
            der_tlv(0xa0, &der_tlv(0x04, &der)),
        ]),
    )
}

/// A `data` ContentInfo wrapping raw payload bytes.
fn p12_data_info(payload: &[u8]) -> Vec<u8> {
    der_tlv(
        0x30,
        &der_concat(&[
            der_oid(&[1, 2, 840, 113549, 1, 7, 1]),
            der_tlv(0xa0, &der_tlv(0x04, payload)),
        ]),
    )
}

/// The unencrypted PFX itself: key bag (plain PKCS#8) and certificate bags
/// as plain data, no MacData.
fn build_pkcs12_plain(
    key: &PKeyRef<Private>,
    cert: &X509Ref,
    chain: &[X509],
    friendly_name: &str,
) -> CryptoResult<Vec<u8>> {
    let pkcs8 = key.private_key_to_pkcs8().map_err(err)?;
    let key_contents = der_tlv(
        0x30,
        &safe_bag(der_oid(&[1, 2, 840, 113549, 1, 12, 10, 1, 1]), pkcs8, friendly_name),
    );

    let mut cert_bags = vec![safe_bag(
        der_oid(&[1, 2, 840, 113549, 1, 12, 10, 1, 3]),
        cert_bag_der(cert),
        friendly_name,
    )];
    for c in chain {
        cert_bags.push(safe_bag(
            der_oid(&[1, 2, 840, 113549, 1, 12, 10, 1, 3]),
            cert_bag_der(c),
            "",
        ));
    }
    let cert_contents = der_tlv(0x30, &der_concat(&cert_bags));

    let auth_safe = der_tlv(
        0x30,
        &der_concat(&[p12_data_info(&key_contents), p12_data_info(&cert_contents)]),
    );
    let pfx = der_tlv(
        0x30,
        &der_concat(&[der_tlv(0x02, &[3]), p12_data_info(&auth_safe)]),
    );
    Ok(pfx)
}

/// Bundle a certificate (plus its private key and optional CA chain) into a
/// password-protected PKCS#12 / PFX file, like XCA's "PKCS#12" export.
/// An empty password produces a completely unencrypted PFX that importers
/// open without any password prompt.
pub fn build_pkcs12(
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    chain: &[X509],
    password: &str,
    friendly_name: &str,
) -> CryptoResult<Vec<u8>> {
    if password.is_empty() {
        return build_pkcs12_plain(key, cert, chain, friendly_name);
    }
    let mut builder = Pkcs12::builder();
    if !chain.is_empty() {
        let mut stack = Stack::new().map_err(err)?;
        for c in chain {
            stack.push(c.clone()).map_err(err)?;
        }
        builder.ca(stack);
    }
    #[allow(deprecated)] // build2 needs OpenSSL 3 setters; build() is fine
    let p12 = builder
        .build(password, friendly_name, key, cert)
        .map_err(|e| format!("PKCS#12 build error: {e}"))?;
    p12.to_der().map_err(err)
}

fn add_ext(
    b: &mut X509Builder,
    issuer_cert: Option<&X509Ref>,
    name: &str,
    value: &str,
    critical: bool,
) -> CryptoResult<()> {
    let value = if critical {
        format!("critical,{value}")
    } else {
        value.to_string()
    };
    let ctx = b.x509v3_context(issuer_cert, None);
    #[allow(deprecated)]
    let ext = X509Extension::new(None, Some(&ctx), name, &value)
        .map_err(|e| format!("Bad extension {name}={value}: {e}"))?;
    b.append_extension(ext).map_err(err)
}

/// Ed25519/Ed448 are pure-EdDSA: OpenSSL needs a NULL digest when signing,
/// which the safe binding cannot express — call the C API directly there.
fn is_pure_eddsa<T>(key: &PKeyRef<T>) -> bool {
    matches!(key.id(), Id::ED25519 | Id::ED448)
}

fn sign_x509<K: HasPrivate>(b: X509Builder, key: &PKeyRef<K>) -> CryptoResult<X509> {
    if is_pure_eddsa(key) {
        let cert = b.build();
        let rc =
            unsafe { openssl_sys::X509_sign(cert.as_ptr(), key.as_ptr(), std::ptr::null()) };
        if rc <= 0 {
            return Err(format!("Ed25519 signing failed: {}", ErrorStack::get()));
        }
        Ok(cert)
    } else {
        let mut b = b;
        b.sign(key, MessageDigest::sha256()).map_err(err)?;
        Ok(b.build())
    }
}

fn sign_req<K: HasPrivate>(b: X509ReqBuilder, key: &PKeyRef<K>) -> CryptoResult<X509Req> {
    if is_pure_eddsa(key) {
        let req = b.build();
        let rc = unsafe {
            openssl_sys::X509_REQ_sign(req.as_ptr(), key.as_ptr(), std::ptr::null())
        };
        if rc <= 0 {
            return Err(format!("Ed25519 signing failed: {}", ErrorStack::get()));
        }
        Ok(req)
    } else {
        let mut b = b;
        b.sign(key, MessageDigest::sha256()).map_err(err)?;
        Ok(b.build())
    }
}

/// Build a certificate. `pubkey` is embedded in the certificate,
/// `sign_key` signs it, `issuer_cert = None` means self-signed.
pub fn build_certificate<P: HasPublic, K: HasPrivate>(
    subject: &X509Name,
    pubkey: &PKeyRef<P>,
    sign_key: &PKeyRef<K>,
    issuer_cert: Option<&X509Ref>,
    params: &CertParams,
) -> CryptoResult<X509> {
    let b = cert_builder(subject, pubkey, issuer_cert, params)?;
    sign_x509(b, sign_key)
}

/// Fill a certificate with all fields and extensions, leaving it unsigned.
/// Used both by the local signing path and by the PKCS#11 token-signing
/// path, which assembles the final DER itself.
pub fn cert_builder<P: HasPublic>(
    subject: &X509Name,
    pubkey: &PKeyRef<P>,
    issuer_cert: Option<&X509Ref>,
    params: &CertParams,
) -> CryptoResult<openssl::x509::X509Builder> {
    let mut b = X509::builder().map_err(err)?;
    b.set_version(2).map_err(err)?;

    let mut bn = BigNum::new().map_err(err)?;
    bn.rand(63, MsbOption::MAYBE_ZERO, false).map_err(err)?;
    let serial = Asn1Integer::from_bn(&bn).map_err(err)?;
    b.set_serial_number(serial.as_ref()).map_err(err)?;

    b.set_subject_name(subject).map_err(err)?;
    match issuer_cert {
        Some(ca) => b.set_issuer_name(ca.subject_name()).map_err(err)?,
        None => b.set_issuer_name(subject).map_err(err)?,
    }

    b.set_pubkey(pubkey).map_err(err)?;
    let nb = Asn1Time::days_from_now(0).map_err(err)?;
    b.set_not_before(nb.as_ref()).map_err(err)?;
    let na = Asn1Time::days_from_now(params.validity_days).map_err(err)?;
    b.set_not_after(na.as_ref()).map_err(err)?;

    add_ext(&mut b, issuer_cert, "subjectKeyIdentifier", "hash", false)?;

    if issuer_cert.is_some() {
        add_ext(&mut b, issuer_cert, "authorityKeyIdentifier", "keyid,issuer", false)?;
    }

    if params.is_ca {
        let bc = match params.path_len {
            Some(n) => format!("CA:TRUE,pathlen:{n}"),
            None => "CA:TRUE".to_string(),
        };
        add_ext(&mut b, issuer_cert, "basicConstraints", &bc, true)?;
        add_ext(
            &mut b,
            issuer_cert,
            "keyUsage",
            "keyCertSign,cRLSign,digitalSignature",
            true,
        )?;
    } else {
        add_ext(&mut b, issuer_cert, "basicConstraints", "CA:FALSE", true)?;
        let mut ku = vec!["digitalSignature"];
        // keyEncipherment is only meaningful for RSA key exchange;
        // EC/EdDSA leafs sign with digitalSignature alone.
        if params.server_auth && pubkey.id() == Id::RSA {
            ku.push("keyEncipherment");
        }
        add_ext(&mut b, issuer_cert, "keyUsage", &ku.join(","), true)?;
    }

    let mut eku = Vec::new();
    if params.server_auth {
        eku.push("serverAuth");
    }
    if params.client_auth {
        eku.push("clientAuth");
    }
    if params.code_signing {
        eku.push("codeSigning");
    }
    if params.email_protection {
        eku.push("emailProtection");
    }
    if params.time_stamping {
        eku.push("timeStamping");
    }
    if params.ocsp_signing {
        eku.push("OCSPSigning");
    }
    if !eku.is_empty() {
        add_ext(&mut b, issuer_cert, "extendedKeyUsage", &eku.join(","), false)?;
    }

    if !params.crl_dp.is_empty() {
        add_ext(
            &mut b,
            issuer_cert,
            "crlDistributionPoints",
            &params.crl_dp.join(","),
            false,
        )?;
    }
    if !params.aia.is_empty() {
        add_ext(
            &mut b,
            issuer_cert,
            "authorityInfoAccess",
            &params.aia.join(","),
            false,
        )?;
    }

    let san: Vec<&str> = params
        .san
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if !san.is_empty() {
        add_ext(&mut b, issuer_cert, "subjectAltName", &san.join(","), false)?;
    }
    Ok(b)
}

// ---- low-level DER helpers for external (token) signature assembly ----

unsafe extern "C" {
    fn i2d_re_X509_tbs(x: *const openssl_sys::X509, out: *mut *mut std::os::raw::c_uchar)
        -> std::os::raw::c_int;
    /// >0 marks a CA certificate (several CA profiles); not bound in the
    /// > openssl crate.
    fn X509_check_ca(cert: *const openssl_sys::X509) -> std::os::raw::c_int;
}

/// The DER-encoded TBSCertificate part of a built (possibly unsigned) cert.
pub fn cert_tbs_der(cert: &X509Ref) -> CryptoResult<Vec<u8>> {
    unsafe {
        let len = i2d_re_X509_tbs(cert.as_ptr(), std::ptr::null_mut());
        if len <= 0 {
            return Err("Cannot encode TBS".into());
        }
        let mut buf = vec![0u8; len as usize];
        let mut p = buf.as_mut_ptr();
        let len2 = i2d_re_X509_tbs(cert.as_ptr(), &mut p);
        if len2 != len {
            return Err("TBS encoding changed".into());
        }
        Ok(buf)
    }
}

/// Signature algorithms used for externally signed certificates.
#[derive(Clone, Copy, Debug)]
pub enum SigAlg {
    RsaSha256,
    Ed25519,
}

impl SigAlg {
    /// The DER-encoded X509 AlgorithmIdentifier.
    pub fn der(&self) -> &'static [u8] {
        match self {
            // SEQ(OID 1.2.840.113549.1.1.11 sha256WithRSAEncryption, NULL)
            Self::RsaSha256 => &[
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
                0x05, 0x00,
            ],
            // SEQ(OID 1.3.101.112 Ed25519)
            Self::Ed25519 => &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70],
        }
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x83);
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    }
    out.extend_from_slice(content);
    out
}

/// Minimal DER INTEGER from unsigned big-endian magnitude bytes.
pub fn der_int_be(magnitude: &[u8]) -> Vec<u8> {
    let mut v = magnitude;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let content = if v.is_empty() {
        vec![0x00]
    } else if v[0] & 0x80 != 0 {
        let mut c = vec![0x00];
        c.extend_from_slice(v);
        c
    } else {
        v.to_vec()
    };
    der_tlv(0x02, &content)
}

/// SubjectPublicKeyInfo DER from raw parts (for token public keys).
pub fn rsa_spki_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let n = der_int_be(modulus);
    let e = der_int_be(exponent);
    let mut rsa_key = der_tlv(0x30, &[n, e].concat());
    rsa_key.insert(0, 0x00); // BIT STRING: 0 unused bits
    let bitstring = der_tlv(0x03, &rsa_key);
    let algid: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
        0x00,
    ];
    der_tlv(0x30, &[algid, &bitstring].concat())
}

pub fn ed25519_spki_der(raw_public: &[u8]) -> Vec<u8> {
    let mut bits = vec![0x00u8];
    bits.extend_from_slice(raw_public);
    let bitstring = der_tlv(0x03, &bits);
    let algid: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    der_tlv(0x30, &[algid, &bitstring].concat())
}

/// Assemble a full certificate DER: SEQ(tbs, signatureAlgorithm, signature).
pub fn assemble_cert_der(tbs: &[u8], alg: SigAlg, sig: &[u8]) -> Vec<u8> {
    let mut bits = vec![0x00u8];
    bits.extend_from_slice(sig);
    let signature = der_tlv(0x03, &bits);
    der_tlv(0x30, &[tbs, alg.der(), &signature].concat())
}

// ---- CRL ----

/// Wrap raw extension content DER into an X509Extension (for CRLs where
/// the safe API offers no v3 context and the mini-language refuses values).
fn ext_from_der(oid: &str, content: &[u8]) -> CryptoResult<X509Extension> {
    use openssl::asn1::Asn1OctetString;
    let oid = openssl::asn1::Asn1Object::from_str(oid).map_err(err)?;
    let octet = Asn1OctetString::new_from_bytes(content).map_err(err)?;
    X509Extension::new_from_der(oid.as_ref(), false, octet.as_ref()).map_err(err)
}

/// AuthorityKeyIdentifier extension from a raw key identifier.
fn aki_extension_der(keyid: &[u8]) -> CryptoResult<X509Extension> {
    // AuthorityKeyIdentifier ::= SEQ( keyIdentifier [0] IMPLICIT OCTET STRING )
    // der_tlv encodes the [0] length properly (the old `as u8` truncated
    // for identifiers longer than 127 bytes).
    let inner = der_tlv(0x80, keyid);
    let aki_value = der_tlv(0x30, &inner);
    ext_from_der("2.5.29.35", &aki_value)
}

/// Build a CRL for `ca_cert`, signed with `ca_key`, containing the given
/// revoked serials (hex strings). `crl_number` must be monotonically
/// increasing per CA (RFC 5280). Ed25519 CAs are not supported here yet.
pub fn build_crl<K: HasPrivate>(
    ca_cert: &X509Ref,
    ca_key: &PKeyRef<K>,
    revoked_serials: &[String],
    validity_days: u32,
    crl_number: i64,
) -> CryptoResult<openssl::x509::X509Crl> {
    use openssl::x509::{X509CrlBuilder, X509RevokedBuilder};
    if is_pure_eddsa(ca_key) {
        return Err("CRL signing for Ed25519 CAs is not supported yet".into());
    }
    let mut b = X509CrlBuilder::new().map_err(err)?;
    b.set_issuer_name(ca_cert.subject_name()).map_err(err)?;
    let lu = Asn1Time::days_from_now(0).map_err(err)?;
    b.set_last_update(lu.as_ref()).map_err(err)?;
    let nu = Asn1Time::days_from_now(validity_days).map_err(err)?;
    b.set_next_update(nu.as_ref()).map_err(err)?;
    // X509_CRL_sign insists on an Authority Key Identifier. The openssl
    // crate exposes no CRL v3 context, so the extension is assembled as
    // raw DER. keyid must match the issuer's SKI: reuse it when present
    // (the normal case), fall back to SHA-1 of the whole certificate.
    let keyid: Vec<u8> = match ca_cert.subject_key_id() {
        Some(ski) => ski.as_slice().to_vec(),
        None => ca_cert.digest(MessageDigest::sha1()).map_err(err)?.to_vec(),
    };
    let aki = aki_extension_der(&keyid)?;
    b.append_extension(aki).map_err(err)?;
    // CrlNumber ::= INTEGER — X509_CRL_sign requires the extension too.
    let crl_number_ext = ext_from_der("2.5.29.20", &der_int_be(&crl_number.to_be_bytes()))?;
    b.append_extension(crl_number_ext).map_err(err)?;
    for hex in revoked_serials {
        let bn = openssl::bn::BigNum::from_hex_str(hex)
            .map_err(|e| format!("Bad revoked serial {hex}: {e}"))?;
        let serial = Asn1Integer::from_bn(bn.as_ref()).map_err(err)?;
        let t = Asn1Time::days_from_now(0).map_err(err)?;
        let mut rb = X509RevokedBuilder::new().map_err(err)?;
        rb.set_serial_number(serial.as_ref()).map_err(err)?;
        rb.set_revocation_date(t.as_ref()).map_err(err)?;
        b.add_revoked(rb.build()).map_err(err)?;
    }
    b.sign(ca_key, MessageDigest::sha256()).map_err(err)?;
    b.build().map_err(err)
}

/// Build a certificate-signing request. Note: the openssl crate does not
/// (yet) support adding extensions to a CSR builder, so CSRs carry only the
/// subject and the public key — SANs are entered again when signing.
pub fn build_request<K: HasPrivate>(subject: &X509Name, key: &PKeyRef<K>) -> CryptoResult<X509Req> {
    let mut rb = X509ReqBuilder::new().map_err(err)?;
    rb.set_version(0).map_err(err)?;
    rb.set_subject_name(subject).map_err(err)?;
    rb.set_pubkey(key).map_err(err)?;
    sign_req(rb, key)
}

/// One recognized item from an imported file.
pub enum Imported {
    Key { key: PKey<Private> },
    Cert { cert: X509 },
    Req { req: X509Req },
    Pkcs12 {
        key: Option<PKey<Private>>,
        cert: Option<X509>,
        ca: Vec<X509>,
    },
}

fn looks_like_der(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == 0x30 && !data.starts_with(b"-----")
}

/// Heuristic: files that need a password before parsing (PKCS#12 or
/// encrypted PEM keys).
pub fn probably_needs_password(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return true;
    }
    if looks_like_der(data) {
        let is_cert = X509::from_der(data).is_ok();
        let is_req = X509Req::from_der(data).is_ok();
        return !is_cert && !is_req;
    }
    false
}

fn import_password_cb(
    password: Option<&str>,
) -> impl FnOnce(&mut [u8]) -> Result<usize, ErrorStack> {
    let pw = password.unwrap_or("").as_bytes().to_vec();
    move |buf: &mut [u8]| {
        let n = pw.len().min(buf.len());
        buf[..n].copy_from_slice(&pw[..n]);
        Ok(n)
    }
}

/// Sniff a file and return every recognizable object inside it.
pub fn parse_any(data: &[u8], password: Option<&str>) -> CryptoResult<Vec<Imported>> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    // Independent passes, not an else-if chain: combo files that carry a
    // certificate and its private key together must yield both.
    if text.contains("-----BEGIN CERTIFICATE-----") {
        match X509::stack_from_pem(data) {
            Ok(certs) => certs.into_iter().for_each(|c| out.push(Imported::Cert { cert: c })),
            Err(e) => return Err(format!("PEM certificate parse error: {e}")),
        }
    }
    if text.contains("CERTIFICATE REQUEST-----") {
        match X509Req::from_pem(data) {
            Ok(req) => out.push(Imported::Req { req }),
            Err(e) => return Err(format!("PEM request parse error: {e}")),
        }
    }
    if text.contains("PRIVATE KEY-----") {
        let key = PKey::private_key_from_pem_callback(data, import_password_cb(password))
            .map_err(|e| format!("Private key parse error: {e} (wrong password?)"))?;
        out.push(Imported::Key { key });
    }
    if out.is_empty() && looks_like_der(data) {
        if let Ok(cert) = X509::from_der(data) {
            out.push(Imported::Cert { cert });
        } else if let Ok(req) = X509Req::from_der(data) {
            out.push(Imported::Req { req });
        } else if let Ok(p12) = openssl::pkcs12::Pkcs12::from_der(data) {
            let parsed = p12
                .parse2(password.unwrap_or(""))
                .map_err(|e| format!("PKCS#12 parse error: {e} (wrong password?)"))?;
            out.push(Imported::Pkcs12 {
                key: parsed.pkey,
                cert: parsed.cert,
                ca: parsed
                    .ca
                    .map(|s| s.iter().map(|c| c.to_owned()).collect())
                    .unwrap_or_default(),
            });
        } else if let Ok(key) = PKey::private_key_from_der(data) {
            out.push(Imported::Key { key });
        } else {
            return Err("Unrecognized file format".into());
        }
    }
    if out.is_empty() {
        return Err("Unrecognized file format".into());
    }
    Ok(out)
}

/// OpenSSL text dump of an object (as shown by `openssl x509 -text`).
pub fn dump_cert(cert: &X509Ref) -> String {
    match cert.to_text() {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => name_to_string(cert.subject_name()),
    }
}

pub fn dump_req(req: &X509ReqRef) -> String {
    match req.to_text() {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => name_to_string(req.subject_name()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(cn: &str) -> SubjectData {
        SubjectData {
            cn: cn.into(),
            ..Default::default()
        }
    }

    #[test]
    fn generate_and_describe_keys() {
        for kind in [
            NewKeyKind::Rsa2048,
            NewKeyKind::EcP256,
            NewKeyKind::Ed25519,
        ] {
            let key = generate_key(kind).unwrap();
            let (k, bits, curve) = key_info(&key);
            assert!(bits > 0, "{kind:?}");
            assert!(!k.is_empty());
            if kind == NewKeyKind::EcP256 {
                assert_eq!(curve, "P-256");
            }
        }
    }

    #[test]
    fn cert_extensions_full_set() {
        let ca_key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let ca_name = subject("Ext Root").build_name().unwrap();
        let ca = build_certificate(
            &ca_name,
            &ca_key,
            &ca_key,
            None,
            &CertParams {
                validity_days: 3650,
                is_ca: true,
                path_len: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        let ca_text = String::from_utf8_lossy(&ca.to_text().unwrap()).to_string();
        assert!(ca_text.contains("pathlen:1"));

        let leaf_key = generate_key(NewKeyKind::EcP256).unwrap();
        let leaf = build_certificate(
            &subject("ext.example.com").build_name().unwrap(),
            &leaf_key,
            &ca_key,
            Some(&ca),
            &CertParams {
                validity_days: 365,
                code_signing: true,
                email_protection: true,
                time_stamping: true,
                ocsp_signing: true,
                crl_dp: vec!["URI:http://ca.example/crl.pem".into()],
                aia: vec![
                    "OCSP;URI:http://ocsp.example".into(),
                    "caIssuers;URI:http://ca.example/ca.pem".into(),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(leaf.verify(ca.public_key().unwrap().as_ref()).unwrap());
        let text = String::from_utf8_lossy(&leaf.to_text().unwrap()).to_string();
        assert!(text.contains("Code Signing"));
        assert!(text.contains("E-mail Protection"));
        assert!(text.contains("Time Stamping"));
        assert!(text.contains("OCSP Signing"));
        assert!(text.contains("http://ca.example/crl.pem"));
        assert!(text.contains("http://ocsp.example"));
        assert!(text.contains("http://ca.example/ca.pem"));
    }

    #[test]
    fn pkcs12_without_password_is_plain() {
        let key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = subject("PlainP12").build_name().unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 30,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();
        let ca = cert.clone();
        let der = build_pkcs12(cert.as_ref(), key.as_ref(), std::slice::from_ref(&ca), "", "plain")
            .unwrap();
        // No password anywhere: parse with an empty one and get everything back.
        let parsed = Pkcs12::from_der(&der).unwrap().parse2("").unwrap();
        assert!(parsed.cert.is_some());
        assert!(parsed.pkey.is_some());
        assert!(same_public_key(parsed.pkey.as_ref().unwrap(), key.as_ref()));
        assert_eq!(parsed.ca.as_ref().map(|s| s.len()).unwrap_or(0), 1);
    }

    #[test]
    fn validity_units_calendar_math() {
        use crate::xca_format as xf;
        // Jan 31 + 1 month → Feb 29 in a leap year = 29 days later.
        let jan31 = xf::days_from_civil(2024, 1, 31);
        assert_eq!(validity_days_at(jan31, 1, ValidityUnit::Months), 29);
        // Feb 29 2024 + 1 year clamps to Feb 28 2025 = 365 days.
        let feb29 = xf::days_from_civil(2024, 2, 29);
        assert_eq!(validity_days_at(feb29, 1, ValidityUnit::Years), 365);
        // A year spanning Feb 29 has 366 days, the next one 365.
        assert_eq!(
            validity_days_at(xf::days_from_civil(2023, 3, 1), 1, ValidityUnit::Years),
            366
        );
        assert_eq!(
            validity_days_at(xf::days_from_civil(2024, 3, 1), 1, ValidityUnit::Years),
            365
        );
        assert_eq!(validity_days_at(0, 2, ValidityUnit::Weeks), 14);
        assert_eq!(validity_days_at(0, 30, ValidityUnit::Days), 30);
        // civil ⇄ days round-trip
        for z in [0i64, 1, 19723, 20000, 25000] {
            let (y, m, d) = xf::civil_from_days(z);
            assert_eq!(xf::days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn self_signed_ca_roundtrip() {
        let key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = subject("Test Root CA").build_name().unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 3650,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(cert.verify(&key).unwrap());
        let s = cert_summary(&cert);
        assert!(s.is_ca);
        assert!(s.subject.contains("Test Root CA"));
        assert!(s.expires_days > 3600);

        let pem = cert.to_pem().unwrap();
        let back = load_cert(&pem).unwrap();
        assert_eq!(serial_hex(&back), s.serial);

        let text = String::from_utf8_lossy(&cert.to_text().unwrap()).to_string();
        assert!(text.contains("Certificate:"));
    }

    #[test]
    fn ca_issues_leaf_and_san() {
        let ca_key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let ca_name = subject("Root").build_name().unwrap();
        let ca = build_certificate(
            &ca_name,
            &ca_key,
            &ca_key,
            None,
            &CertParams {
                validity_days: 3650,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();

        let leaf_key = generate_key(NewKeyKind::EcP256).unwrap();
        let leaf_name = subject("server.example.com").build_name().unwrap();
        let leaf = build_certificate(
            &leaf_name,
            &leaf_key,
            &ca_key,
            Some(&ca),
            &CertParams {
                validity_days: 397,
                is_ca: false,
                server_auth: true,
                san: vec!["DNS:server.example.com".into(), "IP:10.0.0.1".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(leaf.verify(ca.public_key().unwrap().as_ref()).unwrap());
        assert!(!cert_summary(&leaf).is_ca);
        let text = String::from_utf8_lossy(&leaf.to_text().unwrap()).to_string();
        assert!(text.contains("DNS:server.example.com"));
        assert!(text.contains("IP Address:10.0.0.1"));
    }

    #[test]
    fn pkcs12_roundtrip() {
        let ca_key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let ca_name = subject("PFX Root").build_name().unwrap();
        let ca = build_certificate(
            &ca_name,
            &ca_key,
            &ca_key,
            None,
            &CertParams {
                validity_days: 3650,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();

        let key = generate_key(NewKeyKind::EcP256).unwrap();
        let name = subject("pfx.example.com").build_name().unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &ca_key,
            Some(&ca),
            &CertParams {
                validity_days: 397,
                ..Default::default()
            },
        )
        .unwrap();

        let der = build_pkcs12(&cert, &key, std::slice::from_ref(&ca), "secret-pw", "pfx-test").unwrap();
        let p12 = Pkcs12::from_der(&der).unwrap();
        let parsed = p12.parse2("secret-pw").unwrap();
        // ParsedPkcs12_2 (openssl 0.10.8x): all fields are Options.
        let got_cert = parsed.cert.expect("cert in PFX");
        assert!(got_cert.eq(&cert));
        assert!(same_public_key(parsed.pkey.as_ref().unwrap(), &key));
        let chain = parsed.ca.expect("CA chain in PFX");
        assert_eq!(chain.len(), 1);
        for c in chain.iter() {
            assert!(c.eq(&ca));
        }
        // Wrong password must not open the bundle.
        assert!(p12.parse2("wrong").is_err());
    }

    #[test]
    fn csr_roundtrip() {
        let key = generate_key(NewKeyKind::Ed25519).unwrap();
        let name = subject("Ed CSR").build_name().unwrap();
        let req = build_request(&name, &key).unwrap();
        let pem = req.to_pem().unwrap();
        let back = load_req(&pem).unwrap();
        assert_eq!(name_to_string(back.subject_name()), "CN=Ed CSR");
        assert!(back.verify(&key).unwrap());
    }

    #[test]
    fn import_sniffing() {
        let key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = subject("Imp").build_name().unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 30,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();

        let items = parse_any(&cert.to_pem().unwrap(), None).unwrap();
        assert_eq!(items.len(), 1);
        assert!(matches!(items[0], Imported::Cert { .. }));

        let items = parse_any(&cert.to_der().unwrap(), None).unwrap();
        assert_eq!(items.len(), 1);

        let items = parse_any(&key.private_key_to_pem_pkcs8().unwrap(), None).unwrap();
        assert!(matches!(items[0], Imported::Key { .. }));

        let req = build_request(&name, &key).unwrap();
        let items = parse_any(&req.to_pem().unwrap(), None).unwrap();
        assert!(matches!(items[0], Imported::Req { .. }));

        assert!(parse_any(b"garbage", None).is_err());
    }

    #[test]
    fn combo_pem_yields_cert_and_key() {
        let key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = subject("Combo").build_name().unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 30,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut combo = cert.to_pem().unwrap();
        combo.extend_from_slice(&key.private_key_to_pem_pkcs8().unwrap());
        let items = parse_any(&combo, None).unwrap();
        assert_eq!(items.len(), 2, "cert + key from one file");
        assert!(items.iter().any(|i| matches!(i, Imported::Cert { .. })));
        assert!(items.iter().any(|i| matches!(i, Imported::Key { .. })));
    }

    #[test]
    fn crl_roundtrip() {
        let key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = subject("CRL CA").build_name().unwrap();
        let ca = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 3650,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();
        let crl = build_crl(
            ca.as_ref(),
            key.as_ref(),
            &["aabbcc".to_string(), "deadbeef".to_string()],
            30,
            7,
        )
        .unwrap();
        assert_eq!(crate::xca_format::crl_number(crl.as_ref()), 7);
        let pem = crl.to_pem().unwrap();
        let back = openssl::x509::X509Crl::from_pem(&pem).unwrap();
        assert_eq!(back.get_revoked().map(|s| s.len()).unwrap_or(0), 2);
        let serials: Vec<String> = back
            .get_revoked()
            .map(|stack| {
                stack
                    .iter()
                    .map(|rev| serial_of(rev.serial_number()))
                    .collect()
            })
            .unwrap_or_default();
        assert!(serials.iter().any(|s| s.eq_ignore_ascii_case("aabbcc")));
        assert!(serials.iter().any(|s| s.eq_ignore_ascii_case("deadbeef")));
    }

    fn serial_of(serial: &openssl::asn1::Asn1IntegerRef) -> String {
        serial
            .to_bn()
            .ok()
            .and_then(|bn| bn.to_hex_str().ok().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    #[test]
    fn token_style_der_assembly_matches() {
        // The PKCS#11 path re-assembles DER from (tbs, algid, signature);
        // prove byte-equality against a locally signed certificate.
        let key = generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = subject("Asm CA").build_name().unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 365,
                is_ca: true,
                ..Default::default()
            },
        )
        .unwrap();
        let tbs = cert_tbs_der(cert.as_ref()).unwrap();
        let sig = cert.signature().as_slice().to_vec();
        let reassembled = assemble_cert_der(&tbs, SigAlg::RsaSha256, &sig);
        assert_eq!(reassembled, cert.to_der().unwrap());
    }

    #[test]
    fn spki_builders() {
        let key = generate_key(NewKeyKind::Ed25519).unwrap();
        let pub_der = key.public_key_to_der().unwrap();
        // openssl's SPKI for Ed25519: 302a300506032b6570032100 + 32 bytes
        assert_eq!(pub_der.len(), 44);
        let mine = ed25519_spki_der(&pub_der[12..]);
        assert_eq!(mine, pub_der);

        let rsa = generate_key(NewKeyKind::Rsa2048).unwrap();
        let rsa_priv = rsa.rsa().unwrap();
        let rsa_pub = openssl::rsa::Rsa::<openssl::pkey::Public>::from_public_components(
            rsa_priv.n().to_owned().unwrap(),
            rsa_priv.e().to_owned().unwrap(),
        )
        .unwrap();
        let mine2 = rsa_spki_der(&rsa_pub.n().to_vec(), &rsa_pub.e().to_vec());
        let mine2_pkey =
            openssl::pkey::PKey::<openssl::pkey::Public>::public_key_from_der(&mine2).unwrap();
        let expect = crate::crypto::public_of(rsa.as_ref()).unwrap();
        assert!(same_public_key(mine2_pkey.as_ref(), expect.as_ref()));
    }
}
