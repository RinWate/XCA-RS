//! The on-disk format of the original XCA (C++/Qt) database — the only
//! format xca-rs reads and writes.
//!
//! Everything here mirrors lib/database_schema.cpp and lib/pki_evp.cpp of
//! the original: the SQL schema, the base64-DER object columns, the 31-bit
//! SHA-1 reference hashes, the `pwhash` password scheme (salt + 8000×
//! SHA-512) and the 'yyyyMMddHHmmssZ' plain dates.

use foreign_types::ForeignTypeRef;
use openssl::hash::MessageDigest;
use openssl::x509::X509NameRef;
use std::os::raw::{c_int, c_ulong, c_void};
use std::time::{SystemTime, UNIX_EPOCH};

// pki_export.h: enum pki_type
pub const T_KEY: i64 = 1;
pub const T_REQ: i64 = 2;
pub const T_CERT: i64 = 3;
pub const T_CRL: i64 = 4;
/// Templates exist in the schema; xca-rs does not manage them yet.
#[allow(dead_code)]
pub const T_TEMPLATE: i64 = 5;

// pki_base.h: enum pki_source
pub const SRC_IMPORTED: i64 = 1;
pub const SRC_GENERATED: i64 = 2;

// pki_key.h: enum passType
pub const PT_COMMON: i64 = 0;
pub const PT_BOGUS: i64 = 2;

/// The schema below is copied from a database created by XCA 2.x
/// (settings.schema = 8). "IF NOT EXISTS" keeps it a no-op on files the
/// original XCA has already set up.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (key_ CHAR(20) UNIQUE, value TEXT);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, name VARCHAR(128), type INTEGER, source INTEGER, date CHAR(15), comment VARCHAR(2048), stamp INTEGER NOT NULL DEFAULT 0, del SMALLINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS public_keys (item INTEGER, type CHAR(4), hash INTEGER, len INTEGER, "public" TEXT, FOREIGN KEY (item) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS private_keys (item INTEGER, ownPass INTEGER, private TEXT, FOREIGN KEY (item) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS tokens (item INTEGER, card_manufacturer VARCHAR(64), card_serial VARCHAR(64), card_model VARCHAR(64), card_label VARCHAR(64), slot_label VARCHAR(64), object_id VARCHAR(64), FOREIGN KEY (item) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS token_mechanism (item INTEGER, mechanism INTEGER, FOREIGN KEY (item) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS x509super (item INTEGER, subj_hash INTEGER, pkey INTEGER, key_hash INTEGER, FOREIGN KEY (item) REFERENCES items (id), FOREIGN KEY (pkey) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS requests (item INTEGER, hash INTEGER, signed INTEGER, request TEXT, FOREIGN KEY (item) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS certs (item INTEGER, hash INTEGER, iss_hash INTEGER, serial VARCHAR(64), issuer INTEGER, ca INTEGER, cert TEXT, FOREIGN KEY (item) REFERENCES items (id), FOREIGN KEY (issuer) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS authority (item INTEGER, template INTEGER, crlExpire CHAR(15), crlNo INTEGER, crlDays INTEGER, dnPolicy VARCHAR(1024), FOREIGN KEY (item) REFERENCES items (id), FOREIGN KEY (template) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS crls (item INTEGER, hash INTEGER, num INTEGER, iss_hash INTEGER, issuer INTEGER, crl TEXT, FOREIGN KEY (item) REFERENCES items (id), FOREIGN KEY (issuer) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS revocations (caId INTEGER, serial VARCHAR(64), date CHAR(15), invaldate CHAR(15), crlNo INTEGER, reasonBit INTEGER, FOREIGN KEY (caId) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS templates (item INTEGER, version INTEGER, template TEXT, FOREIGN KEY (item) REFERENCES items (id));
CREATE TABLE IF NOT EXISTS takeys (item INTEGER UNIQUE, value TEXT, FOREIGN KEY (item) REFERENCES items (id));
CREATE INDEX IF NOT EXISTS i_settings_key_ ON settings (key_);
CREATE INDEX IF NOT EXISTS i_items_id ON items (id);
CREATE INDEX IF NOT EXISTS i_public_keys_item ON public_keys (item);
CREATE INDEX IF NOT EXISTS i_public_keys_hash ON public_keys (hash);
CREATE INDEX IF NOT EXISTS i_private_keys_item ON private_keys (item);
CREATE INDEX IF NOT EXISTS i_tokens_item ON tokens (item);
CREATE INDEX IF NOT EXISTS i_token_mechanism_item ON token_mechanism (item);
CREATE INDEX IF NOT EXISTS i_x509super_item ON x509super (item);
CREATE INDEX IF NOT EXISTS i_x509super_subj_hash ON x509super (subj_hash);
CREATE INDEX IF NOT EXISTS i_x509super_key_hash ON x509super (key_hash);
CREATE INDEX IF NOT EXISTS i_x509super_pkey ON x509super (pkey);
CREATE INDEX IF NOT EXISTS i_requests_item ON requests (item);
CREATE INDEX IF NOT EXISTS i_requests_hash ON requests (hash);
CREATE INDEX IF NOT EXISTS i_certs_item ON certs (item);
CREATE INDEX IF NOT EXISTS i_certs_hash ON certs (hash);
CREATE INDEX IF NOT EXISTS i_certs_iss_hash ON certs (iss_hash);
CREATE INDEX IF NOT EXISTS i_certs_serial ON certs (serial);
CREATE INDEX IF NOT EXISTS i_certs_issuer ON certs (issuer);
CREATE INDEX IF NOT EXISTS i_certs_ca ON certs (ca);
CREATE INDEX IF NOT EXISTS i_authority_item ON authority (item);
CREATE INDEX IF NOT EXISTS i_crls_item ON crls (item);
CREATE INDEX IF NOT EXISTS i_crls_hash ON crls (hash);
CREATE INDEX IF NOT EXISTS i_crls_iss_hash ON crls (iss_hash);
CREATE INDEX IF NOT EXISTS i_crls_issuer ON crls (issuer);
CREATE INDEX IF NOT EXISTS i_revocations_caId_serial ON revocations (caId, serial);
CREATE INDEX IF NOT EXISTS i_templates_item ON templates (item);
CREATE INDEX IF NOT EXISTS i_items_stamp ON items (stamp);
CREATE VIEW IF NOT EXISTS view_public_keys AS SELECT items.id, items.name, items.type AS item_type, items.date, items.source, items.comment, public_keys.type as key_type, public_keys.len, public_keys."public", private_keys.ownPass, tokens.card_manufacturer, tokens.card_serial, tokens.card_model, tokens.card_label, tokens.slot_label, tokens.object_id FROM public_keys LEFT JOIN items ON public_keys.item = items.id LEFT JOIN private_keys ON private_keys.item = public_keys.item LEFT JOIN tokens ON public_keys.item = tokens.item;
CREATE VIEW IF NOT EXISTS view_certs AS SELECT items.id, items.name, items.type, items.date AS item_date, items.source, items.comment, x509super.pkey, certs.serial AS certs_serial, certs.issuer, certs.ca, certs.cert, authority.template, authority.crlExpire, authority.crlNo AS auth_crlno, authority.crlDays, authority.dnPolicy, revocations.serial, revocations.date, revocations.invaldate, revocations.crlNo, revocations.reasonBit FROM certs LEFT JOIN items ON certs.item = items.id LEFT JOIN x509super ON x509super.item = certs.item LEFT JOIN authority ON authority.item = certs.item LEFT JOIN revocations ON revocations.caId = certs.issuer AND revocations.serial = certs.serial;
CREATE VIEW IF NOT EXISTS view_requests AS SELECT items.id, items.name, items.type, items.date, items.source, items.comment, x509super.pkey, requests.request, requests.signed FROM requests LEFT JOIN items ON requests.item = items.id LEFT JOIN x509super ON x509super.item = requests.item;
CREATE VIEW IF NOT EXISTS view_crls AS SELECT items.id, items.name, items.type, items.date, items.source, items.comment, crls.num, crls.issuer, crls.crl FROM crls LEFT JOIN items ON crls.item = items.id;
CREATE VIEW IF NOT EXISTS view_templates AS SELECT items.id, items.name, items.type, items.date, items.source, items.comment, templates.version, templates.template FROM templates LEFT JOIN items ON templates.item = items.id;
CREATE VIEW IF NOT EXISTS view_private AS SELECT name, private FROM private_keys JOIN items ON items.id = private_keys.item;
INSERT OR IGNORE INTO settings (key_, value) VALUES ('schema', '8');
"#;

// ---- raw libcrypto functions not wrapped by the openssl crate ----

unsafe extern "C" {
    /// OpenSSL >= 3.2:
    /// `unsigned long X509_NAME_hash_ex(const X509_NAME *x,
    ///     OSSL_LIB_CTX *libctx, const char *propq, int *ok)`
    /// (the <= 3.1 variant had `(x, unsigned long *inc)` — do not use).
    fn X509_NAME_hash_ex(
        x: *const c_void,
        libctx: *mut c_void,
        propq: *const std::os::raw::c_char,
        ok: *mut c_int,
    ) -> c_ulong;
    fn X509_CRL_get_ext_d2i(
        crl: *mut c_void,
        nid: c_int,
        crit: *mut c_int,
        idx: *mut c_int,
    ) -> *mut c_void;
    fn ASN1_INTEGER_free(ai: *mut c_void);
    fn ASN1_INTEGER_to_BN(ai: *const c_void, bn: *mut c_void) -> *mut c_void;
    fn BN_free(bn: *mut c_void) -> c_int;
    fn BN_num_bits(bn: *const c_void) -> c_int;
    fn BN_mask_bits(bn: *mut c_void, n: c_int) -> c_int;
    fn BN_bn2bin(bn: *const c_void, to: *mut u8) -> c_int;
}

/// XCA's 31-bit reference hash: first 4 SHA-1 bytes, little-endian,
/// positive (lib/pki_base.cpp).
pub fn sha1_31(data: &[u8]) -> i64 {
    let Ok(md) = openssl::hash::hash(MessageDigest::sha1(), data) else {
        return 0;
    };
    let b = [md[0], md[1], md[2], md[3]];
    (u32::from_le_bytes(b) & 0x7fff_ffff) as i64
}

/// XCA's `x509name::hashNum()`: the OpenSSL X.509 name hash (of the
/// canonical name encoding), positive. Returns 0 when the name cannot be
/// encoded.
pub fn name_hash_31(name: &X509NameRef) -> i64 {
    let mut ok: c_int = 0;
    let h = unsafe {
        X509_NAME_hash_ex(
            name.as_ptr() as *const c_void,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut ok,
        )
    };
    if ok == 0 {
        return 0;
    }
    (h & 0x7fff_ffff) as i64
}

/// The CRL number extension of a CRL, or 0 (stored in the `crls.num`
/// column by the original XCA).
pub fn crl_number(crl: &openssl::x509::X509CrlRef) -> i64 {
    const NID_CRL_NUMBER: c_int = 88; // obj_mac.h
    unsafe {
        let ai = X509_CRL_get_ext_d2i(
            crl.as_ptr() as *mut c_void,
            NID_CRL_NUMBER,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if ai.is_null() {
            return 0;
        }
        let bn = ASN1_INTEGER_to_BN(ai, std::ptr::null_mut());
        let mut n: i64 = 0;
        if !bn.is_null() {
            if BN_num_bits(bn) > 63 {
                BN_mask_bits(bn, 63);
            }
            let mut buf = [0u8; 8];
            let len = BN_bn2bin(bn, buf.as_mut_ptr()).clamp(0, 8) as usize;
            for &byte in &buf[..len] {
                n = (n << 8) | byte as i64;
            }
            BN_free(bn);
        }
        ASN1_INTEGER_free(ai);
        n
    }
}

// ---- base64 (XCA stores B64(DER(object)) in TEXT columns) ----

pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

/// Standard-alphabet base64 decoder; tolerant of whitespace and padding.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ---- the pwhash password scheme (lib/pki_evp.cpp) ----

fn hash_upper_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn sha512_rounds(mut data: Vec<u8>, rounds: u32) -> Option<Vec<u8>> {
    for _ in 0..rounds {
        data = openssl::hash::hash(MessageDigest::sha512(), &data).ok()?.to_vec();
    }
    Some(data)
}

/// Check a password against a stored `pwhash`: "T" = salt + 8000×SHA-512,
/// "S" = legacy salt + SHA-512, plain 32-hex = ancient unsalted MD5.
pub fn check_pwhash(hash: &str, password: &str) -> bool {
    let (salt_len, rounds) = match hash.as_bytes().first() {
        Some(b'T') => (17usize, 8000u32),
        Some(b'S') => (5usize, 1u32),
        _ => {
            if hash.len() != 32 {
                return false;
            }
            return openssl::hash::hash(MessageDigest::md5(), password.as_bytes())
                .map(|d| hash_upper_hex(&d) == hash)
                .unwrap_or(false);
        }
    };
    if hash.len() != salt_len + 128 {
        return false;
    }
    let salt = &hash[..salt_len];
    let mut data = Vec::with_capacity(salt.len() + password.len());
    data.extend_from_slice(salt.as_bytes());
    data.extend_from_slice(password.as_bytes());
    match sha512_rounds(data, rounds) {
        Some(d) => format!("{salt}{}", hash_upper_hex(&d)) == *hash,
        None => false,
    }
}

/// Create a "T"-scheme pwhash for a password.
pub fn make_pwhash(password: &str) -> Option<String> {
    let mut salt_bytes = [0u8; 8];
    openssl::rand::rand_bytes(&mut salt_bytes).ok()?;
    let salt = format!("T{}", hash_upper_hex(&salt_bytes));
    let mut data = format!("{salt}{password}").into_bytes();
    let d = sha512_rounds(std::mem::take(&mut data), 8000)?;
    Some(format!("{salt}{}", hash_upper_hex(&d)))
}

// ---- plain dates and revocation reasons ----

/// Current UTC time in XCA's 'yyyyMMddHHmmssZ' storage format.
pub fn now_plain() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    )
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Civil date to days since the Unix epoch — the inverse of
/// `civil_from_days` (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Whole days since the Unix epoch right now.
pub fn today_days() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0)
}

/// RFC 5280 revocation reason for the `reasonBit` column.
pub fn reason_name(bit: i64) -> &'static str {
    match bit {
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        7 => "removeFromCRL",
        _ => "unspecified",
    }
}

pub fn reason_bit(name: &str) -> i64 {
    match name {
        "keyCompromise" => 1,
        "cACompromise" => 2,
        "affiliationChanged" => 3,
        "superseded" => 4,
        "cessationOfOperation" => 5,
        "certificateHold" => 6,
        "removeFromCRL" => 7,
        _ => 0,
    }
}

/// Serial numbers as a comparable token (XCA and xca-rs both store the
/// lowercase BN hex; leading zeros may differ).
#[allow(dead_code)] // format utility, exercised by its unit test
pub fn norm_serial(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    let t = t.strip_prefix("0x").unwrap_or(&t);
    t.trim_start_matches('0').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", b"\xff\x00\xaa"] {
            assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
        }
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_decode("Zm9v\nYmFy\r\n").unwrap(), b"foobar");
        assert_eq!(b64_decode("Zm9v\nYmFy cg==\r\n").unwrap(), b"foobarr");
        assert!(b64_decode("a!b").is_none());
    }

    #[test]
    fn pwhash_schemes() {
        let h = make_pwhash("s3cret").unwrap();
        assert!(h.starts_with('T') && h.len() == 145);
        assert!(check_pwhash(&h, "s3cret"));
        assert!(!check_pwhash(&h, "wrong"));
        assert!(!check_pwhash("T12", "x"));
        assert!(!check_pwhash(&h, ""));
    }

    #[test]
    fn sha1_31_known_vector() {
        // First four bytes of SHA1("abc") are a9 99 3e 36 → LE 0x363e99a9.
        assert_eq!(sha1_31(b"abc"), 0x363e99a9);
    }

    #[test]
    fn plain_date_shape() {
        let d = now_plain();
        assert_eq!(d.len(), 15);
        assert!(d.ends_with('Z'));
        assert!(d.chars().take(14).all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1)); // 2024-01-01
    }

    #[test]
    fn reason_mapping() {
        assert_eq!(reason_name(1), "keyCompromise");
        assert_eq!(reason_bit("keyCompromise"), 1);
        assert_eq!(reason_bit("unspecified"), 0);
    }

    #[test]
    fn serial_normalization() {
        assert_eq!(norm_serial("0A0B"), "a0b"); // 0x0A0B → a0b
        assert_eq!(norm_serial("0a0b"), norm_serial("0A0B"));
        assert_eq!(norm_serial("00AB"), "ab");
        assert_eq!(norm_serial("ab"), norm_serial("00AB"));
    }
}
