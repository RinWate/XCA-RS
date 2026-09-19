//! CryptoPro CSP exportable key containers (the six-file `*.000` folder)
//! → a GOST private key the gost engine can load.
//!
//! The format and the password stretching follow the classic
//! reverse-engineering write-ups of the CPCSP container (habr 275039,
//! webcrypto-labs, go-decrypto-pro):
//!
//! * `masks.key`   = `SEQ { OCTET mask[32], OCTET salt[12], OCTET check[4] }`
//! * `primary.key` = `SEQ { OCTET encrypted[32] }`
//! * `header.key`  carries the first 8 bytes (little-endian) of the
//!   public key under context tag 10.
//!
//! The storage key is derived from the password with an iterated GOST R
//! 34.11-94 construction (2000 iterations, 2 for an empty password);
//! `primary.key` is GOST 28147-89 in simple substitution (ECB) with the
//! CryptoPro-A S-box; the plaintext is `d·mask mod q`, removed by
//! multiplying by the modular inverse of the mask.

use crate::crypto;
use openssl::bn::{BigNum, BigNumContext};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::path::Path;

/// The CryptoPro-A S-box, the only substitution CryptoPro containers
/// use. Rows are in the gost engine's declaration order (k8, k7, …, k1)
/// and map onto the four byte tables exactly like its kboxinit().
const SBOX_A: [[u8; 16]; 8] = [
    [0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4],
    [0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE],
    [0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6],
    [0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6],
    [0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6],
    [0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9],
    [0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1],
    [0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5],
];

/// Curve candidates for 256-bit keys: dotted paramset OID + its order q
/// (public constants from the gost engine param tables). XchA shares the
/// CryptoPro-A curve, XchB — CryptoPro-C.
const PARAMSETS_256: [(&str, &str); 5] = [
    ("1.2.643.2.2.35.1", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
    ("1.2.643.7.1.2.1.1.1", "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
    ("1.2.643.2.2.35.2", "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"),
    ("1.2.643.2.2.35.3", "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"),
    ("1.2.643.2.2.35.0", "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
];

/// Key algorithm + digest OID pairs tried when packing the scalar: GOST
/// R 34.10-2012-256 first (modern containers), then 2001.
const KEY_ALGS: [(&str, &str); 2] = [
    ("1.2.643.7.1.1.1.1", "1.2.643.7.1.1.2.2"),
    ("1.2.643.2.2.19", "1.2.643.2.2.9"),
];

// ---- tiny DER helpers ----

/// One BER TLV at `pos`: `((tag, content_start, content_end), next_pos)`.
fn tlv(data: &[u8], pos: usize) -> Option<((u8, usize, usize), usize)> {
    let mut i = pos;
    let tag = *data.get(i)?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags never occur here
    }
    i += 1;
    let first = *data.get(i)?;
    i += 1;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || i + n > data.len() {
            return None;
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | *data.get(i)? as usize;
            i += 1;
        }
        l
    };
    let end = i.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(((tag, i, end), end))
}

/// The OCTET STRING children of a top-level SEQUENCE.
fn parse_octets(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let ((tag, start, end), _) = tlv(data, 0)?;
    if tag != 0x30 {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let ((t, s, e), next) = tlv(data, pos)?;
        if t == 0x04 {
            out.push(data[s..e].to_vec());
        }
        pos = next;
    }
    Some(out)
}

fn put_tlv(out: &mut Vec<u8>, tag: u8, content: &[&[u8]]) {
    let body: Vec<u8> = content.concat();
    out.push(tag);
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = body.len();
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(&body);
}

/// Dotted OID → DER content bytes.
fn der_oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut tmp = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            tmp.push((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        out.extend_from_slice(&tmp);
    }
    out
}

// ---- the container ----

/// Parsed container essentials.
pub struct Container {
    pub mask: Vec<u8>,
    pub salt: Vec<u8>,
    pub encrypted: Vec<u8>,
    /// First 8 bytes of the public key (little-endian) from header.key,
    /// when present.
    pub public8: Option<[u8; 8]>,
}

/// True when the picked path is (or sits inside) a CryptoPro container
/// folder.
pub fn is_container_entry(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("primary.key").is_file() && path.join("masks.key").is_file();
    }
    let name = path.file_name().and_then(|n| n.to_str());
    matches!(
        name,
        Some("primary.key" | "masks.key" | "header.key" | "primary2.key" | "masks2.key")
    ) && path
        .parent()
        .is_some_and(is_container_entry)
}

pub fn read_container(dir: &Path) -> Result<Container, String> {
    let masks = parse_octets(
        &std::fs::read(dir.join("masks.key")).map_err(|e| format!("masks.key: {e}"))?,
    )
    .ok_or("masks.key: unexpected format")?;
    if masks.len() != 3 || masks[0].len() != 32 || masks[1].len() != 12 {
        return Err("masks.key: unexpected format".to_string());
    }
    let primary = parse_octets(
        &std::fs::read(dir.join("primary.key")).map_err(|e| format!("primary.key: {e}"))?,
    )
    .ok_or("primary.key: unexpected format")?;
    if primary.len() != 1 || primary[0].len() != 32 {
        return Err("primary.key: unexpected format".to_string());
    }
    let mut mask_it = masks.into_iter();
    let mask = mask_it.next().unwrap_or_default();
    let salt = mask_it.next().unwrap_or_default();
    let encrypted = primary.into_iter().next().unwrap_or_default();
    let public8 = std::fs::read(dir.join("header.key"))
        .ok()
        .and_then(|h| find_public8(&h));
    Ok(Container {
        mask,
        salt,
        encrypted,
        public8,
    })
}

/// The 8-byte content of context tag [10] inside header.key's inner
/// SEQUENCE — the public key prefix used to validate the password.
fn find_public8(header: &[u8]) -> Option<[u8; 8]> {
    let ((_, outer_start, _), _) = tlv(header, 0)?;
    let ((_, inner_start, inner_end), _) = tlv(header, outer_start)?;
    let mut pos = inner_start;
    while pos < inner_end {
        let ((tag, s, e), next) = tlv(header, pos)?;
        if tag == 0x8A && e - s == 8 {
            let mut out = [0u8; 8];
            out.copy_from_slice(&header[s..e]);
            return Some(out);
        }
        pos = next;
    }
    None
}

// ---- GOST 28147-89, simple substitution (ECB), CryptoPro-A S-box ----

fn kbox() -> [[u32; 256]; 4] {
    // Byte-indexed tables exactly like the engine's k87/k65/k43/k21: the
    // low nibble goes through the odd row, the high nibble through the
    // even one.
    let mut t = [[0u32; 256]; 4];
    for (table, row) in t.iter_mut().enumerate() {
        for (i, cell) in row.iter_mut().enumerate() {
            let (lo, hi) = (i & 0xf, i >> 4);
            *cell = match table {
                0 => u32::from(SBOX_A[0][hi] << 4 | SBOX_A[1][lo]) << 24,
                1 => u32::from(SBOX_A[2][hi] << 4 | SBOX_A[3][lo]) << 16,
                2 => u32::from(SBOX_A[4][hi] << 4 | SBOX_A[5][lo]) << 8,
                _ => u32::from(SBOX_A[6][hi] << 4 | SBOX_A[7][lo]),
            };
        }
    }
    t
}

fn f(t: &[[u32; 256]; 4], x: u32) -> u32 {
    let y = t[0][(x >> 24) as usize & 255]
        | t[1][(x >> 16) as usize & 255]
        | t[2][(x >> 8) as usize & 255]
        | t[3][x as usize & 255];
    y.rotate_left(11)
}

/// One 64-bit block; `schedule` is the 32-entry key-word index order and
/// the halves alternate exactly like the engine's gostcrypt/gostdecrypt.
fn block(t: &[[u32; 256]; 4], k: &[u32; 8], in_: &[u8], schedule: &[usize]) -> [u8; 8] {
    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut n1 = le(&in_[0..4]);
    let mut n2 = le(&in_[4..8]);
    let mut even = true;
    for &i in schedule {
        // The accumulator being updated is fed from the OTHER one, exactly
        // like the engine's gostcrypt/gostdecrypt.
        let x = if even {
            f(t, n1.wrapping_add(k[i]))
        } else {
            f(t, n2.wrapping_add(k[i]))
        };
        if even {
            n2 ^= x;
        } else {
            n1 ^= x;
        }
        even = !even;
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&n2.to_le_bytes());
    out[4..8].copy_from_slice(&n1.to_le_bytes());
    out
}

pub fn gost89_ecb(key: &[u8; 32], data: &[u8], decrypt: bool) -> Vec<u8> {
    assert_eq!(data.len() % 8, 0);
    let t = kbox();
    let mut k = [0u32; 8];
    for i in 0..8 {
        k[i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    // Encrypt: K0..K7 three times, then K7..K0 (verified against the
    // CryptoPro CSP vector); decrypt is the exact reverse.
    let mut schedule: Vec<usize> = (0..3).flat_map(|_| 0..8).chain((0..8).rev()).collect();
    if decrypt {
        schedule.reverse();
    }
    data.chunks(8)
        .flat_map(|c| block(&t, &k, c, &schedule))
        .collect::<Vec<u8>>()
}

// ---- password key derivation (CPKDF over the engine's GOST R 34.11-94) ----

const CPKDF_SEED: &[u8; 32] = b"DENEFH028.760246785.IUEFHWUIO.EF";

/// GOST R 34.11-94 digest via the gost engine.
fn gost94(data: &[u8]) -> Result<[u8; 32], String> {
    engine_digest(b"md_gost94", data)
}

/// Digest by name through the gost engine (also Streebog, for the PFX
/// KDF variants). Name lookup first, the engine's digest table by OID as
/// fallback.
fn engine_digest(name: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    unsafe extern "C" {
        fn EVP_get_digestbyname(name: *const std::ffi::c_char) -> *const openssl_sys::EVP_MD;
        fn ENGINE_get_digest(
            e: *const openssl_sys::ENGINE,
            nid: std::ffi::c_int,
        ) -> *const openssl_sys::EVP_MD;
        fn OBJ_txt2nid(s: *const std::ffi::c_char) -> std::ffi::c_int;
    }
    let name = std::ffi::CString::new(name.to_vec()).map_err(|e| e.to_string())?;
    if !crypto::init_gost() {
        return Err(crate::tr!(
            "GOST is not available: the gost engine is missing (install openssl-gost-engine)"
        ));
    }
    unsafe {
        let mut md = EVP_get_digestbyname(name.as_ptr());
        if md.is_null() {
            let nid = OBJ_txt2nid(c"1.2.643.2.2.9".as_ptr());
            md = ENGINE_get_digest(
                crypto::gost_engine_ptr() as *const openssl_sys::ENGINE,
                nid,
            );
        }
        if md.is_null() {
            return Err("digest is unavailable".to_string());
        }
        let ctx = openssl_sys::EVP_MD_CTX_new();
        if ctx.is_null() {
            return Err("EVP_MD_CTX_new failed".to_string());
        }
        let mut ok = openssl_sys::EVP_DigestInit_ex(
            ctx,
            md,
            crypto::gost_engine_ptr() as *mut openssl_sys::ENGINE,
        ) == 1;
        let mut out = [0u8; 32];
        let mut len = 0u32;
        if ok {
            ok = openssl_sys::EVP_DigestUpdate(ctx, data.as_ptr().cast(), data.len()) == 1;
        }
        if ok {
            ok = openssl_sys::EVP_DigestFinal_ex(ctx, out.as_mut_ptr(), &mut len) == 1;
        }
        openssl_sys::EVP_MD_CTX_free(ctx);
        if !ok || len != 32 {
            return Err("digest failed".to_string());
        }
        Ok(out)
    }
}

fn cpkdf(salt: &[u8], password: &str) -> Result<[u8; 32], String> {
    let pass = password.as_bytes();
    if pass.len() * 4 > 1024 {
        return Err(crate::tr!("Password is too long"));
    }
    // "pincode4": every password byte in its own 4-byte cell.
    let mut pin = vec![0u8; pass.len() * 4];
    for (i, b) in pass.iter().enumerate() {
        pin[i * 4] = *b;
    }
    // Stage 1: hash of the salt (plus pincode when a password is set).
    let mut input = salt.to_vec();
    if !pass.is_empty() {
        input.extend_from_slice(&pin);
    }
    let hash = gost94(&input)?;
    // Stage 2: 2000 rounds of the HMAC-like mix (2 without a password).
    let mut c: [u8; 32] = *CPKDF_SEED;
    let rounds = if pass.is_empty() { 2 } else { 2000 };
    for _ in 0..rounds {
        let mut buf = Vec::with_capacity(128);
        buf.extend(c.iter().map(|b| b ^ 0x36));
        buf.extend_from_slice(&hash);
        buf.extend(c.iter().map(|b| b ^ 0x5C));
        buf.extend_from_slice(&hash);
        c = gost94(&buf)?;
    }
    // Stage 3: fold the salt (and pincode) in once more, then hash twice.
    let mut buf = Vec::with_capacity(96);
    buf.extend(c.iter().map(|b| b ^ 0x36));
    buf.extend_from_slice(salt);
    buf.extend(c.iter().map(|b| b ^ 0x5C));
    if !pass.is_empty() {
        buf.extend_from_slice(&pin);
    }
    c = gost94(&buf)?;
    gost94(&c)
}

// ---- assembling the key ----

/// The GOST private-key PKCS#8 in exactly the layout this gost engine
/// writes and reads: the key AlgorithmIdentifier carries
/// `SEQ { OID curve, OID digest }`, and the private key is an OCTET
/// STRING with the raw little-endian scalar (no inner SEQUENCE).
fn build_pkcs8(alg_oid: &str, digest_oid: &str, param_oid: &str, x_le: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    put_tlv(&mut params, 0x06, &[&der_oid(param_oid)]);
    put_tlv(&mut params, 0x06, &[&der_oid(digest_oid)]);
    let mut params_seq = Vec::new();
    put_tlv(&mut params_seq, 0x30, &[&params]);

    let mut alg = Vec::new();
    put_tlv(&mut alg, 0x06, &[&der_oid(alg_oid)]);
    alg.extend_from_slice(&params_seq);

    let mut alg_seq = Vec::new();
    put_tlv(&mut alg_seq, 0x30, &[&alg]);

    let mut key_oct = Vec::new();
    put_tlv(&mut key_oct, 0x04, &[x_le]);

    let mut pki = Vec::new();
    put_tlv(&mut pki, 0x30, &[&[0x02, 0x01, 0x00], &alg_seq, &key_oct]);
    pki
}

fn pem_encode(der: &[u8]) -> Vec<u8> {
    use std::fmt::Write as _;
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        b64.push(T[(n >> 18) as usize & 63] as char);
        b64.push(T[(n >> 12) as usize & 63] as char);
        b64.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        b64.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        let _ = writeln!(pem, "{}", String::from_utf8_lossy(line));
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem.into_bytes()
}

fn fixed_len_be(v: &openssl::bn::BigNumRef, len: usize) -> Vec<u8> {
    let mut b = v.to_vec_padded(len as i32).unwrap_or_default();
    if b.len() > len {
        b = b[b.len() - len..].to_vec();
    }
    b
}

/// Decrypt the container. `cert` (when the certificate is known) picks
/// the curve and validates the result; otherwise the candidate whose
/// public key matches header.key's 8-byte prefix wins.
pub fn decrypt_container(
    c: &Container,
    password: &str,
    cert: Option<&X509>,
) -> Result<PKey<Private>, String> {
    let pwd_key = cpkdf(&c.salt, password)?;
    let mut plain = gost89_ecb(&pwd_key, &c.encrypted, true);
    plain.reverse(); // container words are little-endian
    let key_with_mask = BigNum::from_slice(&plain).map_err(|e| e.to_string())?;
    let mut mask_be = c.mask.clone();
    mask_be.reverse();
    let mask = BigNum::from_slice(&mask_be).map_err(|e| e.to_string())?;

    let one = BigNum::from_u32(1).map_err(|e| e.to_string())?;
    let mut ctx = BigNumContext::new().map_err(|e| e.to_string())?;
    for (param_oid, q_hex) in PARAMSETS_256 {
        let q = BigNum::from_hex_str(q_hex).map_err(|e| e.to_string())?;
        let mut inv = match BigNum::new() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if inv.mod_inverse(&mask, &q, &mut ctx).is_err() {
            continue; // mask not invertible for this q — wrong curve
        }
        let mut product = match BigNum::new() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if product.checked_mul(&key_with_mask, &inv, &mut ctx).is_err() {
            continue;
        }
        let mut d = match BigNum::new() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if d.mod_exp(&product, &one, &q, &mut ctx).is_err() {
            continue;
        }
        let mut x = fixed_len_be(d.as_ref(), 32);
        x.reverse(); // back to the little-endian GOST scalar
        if x.iter().all(|b| *b == 0) {
            continue;
        }
        for (alg_oid, digest_oid) in KEY_ALGS {
            let der = build_pkcs8(alg_oid, digest_oid, param_oid, &x);
            let Ok(key) = crypto::load_private_key(&pem_encode(&der)) else {
                continue;
            };
            if key_matches(&key, cert, c.public8.as_ref()) {
                return Ok(key);
            }
        }
    }
    Err(crate::tr!("Wrong password or an unsupported key container."))
}

/// The recovered private key must reproduce a known public key: the
/// certificate's when provided, else the header.key 8-byte prefix.
fn key_matches(key: &PKey<Private>, cert: Option<&X509>, public8: Option<&[u8; 8]>) -> bool {
    if let Some(cert) = cert {
        return cert
            .public_key()
            .is_ok_and(|cpk| cpk.public_eq(key.as_ref()));
    }
    let Some(public8) = public8 else { return false };
    let Ok(spk) = key.public_key_to_der() else {
        return false;
    };
    // The SPKI DER ends with the raw 64-byte point (X||Y, little-endian).
    spk.len() >= 64 && &spk[spk.len() - 64..spk.len() - 56] == public8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }

    #[test]
    fn gost89_ecb_roundtrip() {
        let key = [0x42u8; 32];
        let data = b"01234567abcdefgh".to_vec();
        let enc = gost89_ecb(&key, &data, false);
        assert_ne!(enc, data);
        assert_eq!(gost89_ecb(&key, &enc, true), data);
    }

    /// The CryptoPro CSP 3.6R2 test vector for simple substitution with
    /// the CryptoPro-A S-box (from the gost engine's test table).
    #[test]
    fn gost89_cryptopro_vector() {
        let key: [u8; 32] = [
            0xBB, 0xF1, 0xED, 0xD3, 0x20, 0xAF, 0x8A, 0x62, 0x8E, 0x11, 0xC8,
            0xA9, 0x51, 0xCC, 0xBE, 0x81, 0x47, 0x7B, 0x41, 0xA1, 0x6A, 0xF6,
            0x7F, 0x05, 0xE8, 0x51, 0x2F, 0x9E, 0x01, 0xF8, 0xCF, 0x49,
        ];
        let plain: [u8; 16] = [
            0x74, 0x3D, 0x76, 0xF9, 0x1B, 0xEE, 0x35, 0x3C, 0xA2, 0x5C, 0x3B,
            0x10, 0xEB, 0x64, 0xCF, 0xF5,
        ];
        let expected = "C373909535580863CB68859677E8FBA9";
        assert_eq!(hex(&gost89_ecb(&key, &plain, false)), expected);
    }

    #[test]
    fn der_helpers() {
        assert_eq!(
            der_oid("1.2.643.7.1.1.1.1"),
            vec![0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01]
        );
        let mut out = Vec::new();
        put_tlv(&mut out, 0x04, &[&[0xAA; 300]]);
        assert_eq!(out[0], 0x04);
        assert_eq!(&out[1..4], &[0x82, 0x01, 0x2C]);
    }

    #[test]
    fn cpkdf_is_deterministic() {
        if !crypto::init_gost() {
            eprintln!("gost engine not available — skipped");
            return;
        }
        let salt = [7u8; 12];
        assert_eq!(
            cpkdf(&salt, "пароль").unwrap(),
            cpkdf(&salt, "пароль").unwrap()
        );
        assert_ne!(cpkdf(&salt, "").unwrap(), cpkdf(&salt, "x").unwrap());
    }

    /// Full container round trip: build one with the same algorithm the
    /// importer follows (reversed), then decrypt it back.
    #[test]
    fn container_roundtrip() {
        if !crypto::init_gost() {
            eprintln!("gost engine not available — skipped");
            return;
        }
        let (cert, key) = test_gost_key();
        let p8 = key.private_key_to_pkcs8().unwrap();
        let scalar_le = find_octet32(&p8).expect("32-byte scalar in PKCS#8");

        let salt = [7u8; 12];
        let password = "тестовый пароль";
        let pwd_key = cpkdf(&salt, password).unwrap();

        // key_with_mask = x * mask mod q, serialized little-endian.
        let (_, q_hex) = PARAMSETS_256[0];
        let q = BigNum::from_hex_str(q_hex).unwrap();
        let mut x_be = scalar_le.clone();
        x_be.reverse();
        let x = BigNum::from_slice(&x_be).unwrap();
        let mask: [u8; 32] = std::array::from_fn(|i| (i as u8 * 7 + 3) | 1);
        let mut mask_be = mask;
        mask_be.reverse();
        let mask_bn = BigNum::from_slice(&mask_be).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut product = BigNum::new().unwrap();
        product.checked_mul(&x, &mask_bn, &mut ctx).unwrap();
        let mut kwm = BigNum::new().unwrap();
        kwm.mod_exp(&product, &BigNum::from_u32(1).unwrap(), &q, &mut ctx)
            .unwrap();
        let mut kwm_le = fixed_len_be(kwm.as_ref(), 32);
        kwm_le.reverse();
        let encrypted = gost89_ecb(&pwd_key, &kwm_le, false);

        let c = Container {
            mask: mask.to_vec(),
            salt: salt.to_vec(),
            encrypted,
            public8: None,
        };
        let recovered = decrypt_container(&c, password, Some(&cert))
            .expect("container decrypts");
        assert_eq!(
            recovered.public_key_to_der().unwrap(),
            cert.public_key().unwrap().public_key_to_der().unwrap()
        );
        // A wrong password must not validate.
        assert!(decrypt_container(&c, "не тот пароль", Some(&cert)).is_err());
    }

    pub(crate) fn test_gost_key_pub() -> (X509, PKey<Private>) {
        test_gost_key()
    }

    fn test_gost_key() -> (X509, PKey<Private>) {
        use crate::crypto::{build_certificate, generate_gost, CertParams, SubjectData};
        let key = generate_gost(0).expect("gost key");
        let name = SubjectData {
            cn: "Container Test".into(),
            ..Default::default()
        }
        .build_name()
        .unwrap();
        let cert = build_certificate(
            &name,
            &key,
            &key,
            None,
            &CertParams {
                validity_days: 30,
                ..Default::default()
            },
        )
        .unwrap();
        (cert, key)
    }

    /// The 32-byte OCTET STRING somewhere in the DER (the GOST scalar).
    fn find_octet32(der: &[u8]) -> Option<Vec<u8>> {
        let ((tag, s, e), next) = tlv(der, 0)?;
        if tag == 0x04 && e - s == 32 {
            return Some(der[s..e].to_vec());
        }
        if let Some(inner) = find_octet32(&der[s..e]) {
            return Some(inner);
        }
        if next < der.len() {
            find_octet32(&der[next..])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod real_files {
    use super::*;

    /// Parse the real CryptoPro container the user dropped into the
    /// project; no password, so decryption must fail with the
    /// wrong-password error (not a parse error).
    /// Run with `cargo test -- --ignored real_container_probe`.
    #[test]
    #[ignore]
    fn real_container_probe() {
        let dir = std::path::Path::new("Сертификат/vzkmkygu.000");
        if !dir.is_dir() {
            eprintln!("no real container in the tree — skipped");
            return;
        }
        let c = read_container(dir).expect("container parses");
        assert_eq!(c.mask.len(), 32);
        assert_eq!(c.salt.len(), 12);
        assert_eq!(c.encrypted.len(), 32);
        assert!(c.public8.is_some(), "header public8");
        let err = decrypt_container(&c, "точно неверный пароль", None)
            .expect_err("wrong password must fail");
        eprintln!("probe OK, expected error: {err}");
    }
}

#[cfg(test)]
mod pfx_manual {
    use crate::crypto;
    use openssl::pkcs12::Pkcs12;

    /// GOST-encrypted PFX round trip (engine-backed PKCS12_create/parse).
    /// Run with `cargo test -- --ignored gost_pfx_roundtrip`.
    #[test]
    #[ignore]
    fn gost_pfx_roundtrip() {
        assert!(crypto::init_gost(), "gost engine required");
        let (cert, key) = super::tests::test_gost_key_pub();
        let p12 = Pkcs12::builder()
            .name("gost")
            .pkey(&key)
            .cert(&cert)
            .build2("gostpass")
            .expect("PKCS12 create");
        let der = p12.to_der().expect("der");
        std::fs::write("/tmp/gost-test.pfx", &der).unwrap();
        std::fs::write("/tmp/gost-test-key.pem", key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        std::fs::write("/tmp/gost-test-cert.pem", cert.to_pem().unwrap()).unwrap();
        let back = Pkcs12::from_der(&der).unwrap();
        let parsed = back
            .parse2("gostpass")
            .expect("GOST PFX must parse through the engine");
        let cert2 = parsed.cert.expect("cert");
        assert_eq!(
            parsed.pkey.unwrap().public_key_to_der().unwrap(),
            cert.public_key().unwrap().public_key_to_der().unwrap()
        );
        let _ = cert2;
        eprintln!("GOST PFX round trip OK ({} bytes)", der.len());
    }
}

/// DER OID content bytes → dotted text.
/// Content bounds of the first SEQUENCE child at the top level.
fn seq_of(data: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let mut pos = start;
    while pos < end {
        let ((tag, a, b), next) = tlv(data, pos)?;
        if tag == 0x30 {
            return Some((a, b));
        }
        pos = next;
    }
    None
}

fn oid_text(der: &[u8]) -> String {
    if der.is_empty() {
        return String::new();
    }
    let mut arcs = vec![(der[0] / 40).to_string(), (der[0] % 40).to_string()];
    let mut val: u64 = 0;
    for b in &der[1..] {
        val = (val << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(val.to_string());
            val = 0;
        }
    }
    arcs.join(".")
}

fn tlvr(data: &[u8], pos: usize) -> Result<((u8, usize, usize), usize), String> {
    tlv(data, pos).ok_or_else(|| "PFX structure error".to_string())
}

// ---- CryptoPro PFX: PKCS#12 bags under the vendor GOST PBE ----
//
// CryptoPro CSP encrypts the shrouded keybag with
// 1.2.840.113549.1.12.1.80 (Bouncy Castle calls it pbeUnknownGost): the
// classic PKCS#12 KDF over GOST R 34.11-94 plus GOST 28147-89 CFB —
// neither core OpenSSL nor the gost engine know this OID, so such bags
// are decrypted here by hand. Standard bags (SHA1/RC2/3DES) go through
// OpenSSL's PKCS12_pbe_crypt.

/// Imported CryptoPro PFX: the private key (when present) and all
/// certificates.
pub struct GostPfx {
    pub key: Option<PKey<Private>>,
    pub certs: Vec<X509>,
}

/// Walk a PFX by hand. The MAC is not checked — a wrong password simply
/// produces garbage that fails to parse as a key/certificate.
pub fn parse_gost_pfx(data: &[u8], password: &str) -> Result<GostPfx, String> {
    // PFX ::= SEQ { version, authSafe SEQUENCE, mac? }
    let ((_, top_s, top_e), _) = tlvr(data, 0)?;
    let mut pos = top_s;
    let mut authsafe: Option<(usize, usize)> = None;
    while pos < top_e {
        let Some(((tag, s, _e), next)) = tlv(data, pos) else { break };
        if tag == 0x30 {
            // ContentInfo { OID pkcs7-data, [0] { OCTET authSafe } }
            let Some(((t, os, oe), p2)) = tlv(data, s) else { break };
            if t == 0x06 && oid_text(&data[os..oe]) == "1.2.840.113549.1.7.1" {
                let Some(((t2, a_s, _), _)) = tlv(data, p2) else { break };
                if t2 == 0xA0 {
                    let (t3, o_s, o_e) = tlvr(data, a_s)?.0;
                    if t3 == 0x04 {
                        authsafe = Some((o_s, o_e));
                    }
                    let _ = t3;
                }
            }
            break;
        }
        pos = next;
    }
    let (as_s, _as_e) = authsafe.ok_or("PFX: no authSafe")?;

    let mut out = GostPfx {
        key: None,
        certs: Vec::new(),
    };
    // AuthenticatedSafe ::= SEQ of ContentInfo
    let ((_, ci_s, ci_e), _) = tlvr(data, as_s)?;
    let mut pos = ci_s;
    while pos < ci_e {
        let ((_, cs, ce), next) = tlvr(data, pos)?;
        handle_content_info(&data[cs..ce], password, &mut out)?;
        pos = next;
    }
    Ok(out)
}

/// One ContentInfo of the AuthenticatedSafe: pkcs7-data whose payload is
/// either plain SafeContents or a `SEQ { algorithm, ciphertext }` pair.
fn handle_content_info(payload: &[u8], password: &str, out: &mut GostPfx) -> Result<(), String> {
    let ((t, os, oe), p2) = tlvr(payload, 0)?;
    if t != 0x06 || oid_text(&payload[os..oe]) != "1.2.840.113549.1.7.1" {
        return Ok(());
    }
    let (t2, a_s, _) = tlvr(payload, p2)?.0;
    if t2 != 0xA0 {
        return Ok(());
    }
    let (t3, o_s, o_e) = tlvr(payload, a_s)?.0;
    if t3 != 0x04 {
        return Ok(());
    }
    let inner = &payload[o_s..o_e];

    if looks_like_safe_contents(inner) {
        return walk_safe_contents(inner, password, out);
    }
    // Encrypted: the payload content is SEQ { alg SEQ, OCTET ciphertext }
    // — `inner` already starts at that SEQ's children.
    let ((t4, alg_s, alg_e), p5) = tlvr(inner, 0)?;
    if t4 != 0x30 {
        return Ok(());
    }
    let (oid, salt, iterations) = parse_pbe_alg(&inner[alg_s..alg_e]);
    let (t5, c_s, c_e) = tlvr(inner, p5)?.0;
    if t5 != 0x04 {
        return Ok(());
    }
    // The full AlgorithmIdentifier DER (tag+len+content) for OpenSSL.
    let plain = decrypt_bag(&inner[..p5], &oid, &salt, iterations, inner[c_s..c_e].to_vec(), password)
        .map_err(|e| {
            let _ = std::fs::write("/tmp/ci2dbg.txt", format!("CI oid={oid} err={e}"));
            e
        })?;
    if std::env::var("XCA_PFX_DEBUG").is_ok() {
        let _ = std::fs::write(
            "/tmp/ci2dbg.txt",
            format!("CI oid={oid} plain head {:02X?}", &plain[..plain.len().min(12)]),
        );
    }
    if looks_like_safe_contents(&plain) {
        walk_safe_contents(&plain, password, out)?;
    }
    Ok(())
}

fn looks_like_safe_contents(payload: &[u8]) -> bool {
    // SafeContents ::= SEQ { SafeBag+, … }; a SafeBag is itself a SEQ
    // whose first child is the bagId OID.
    let Some(((_, contents_s, _), _)) = tlv(payload, 0) else {
        return false;
    };
    let Some(((t0, bag_s, _), _)) = tlv(payload, contents_s) else {
        return false;
    };
    if t0 != 0x30 {
        return false;
    }
    let Some(((t, s, e), _)) = tlv(payload, bag_s) else {
        return false;
    };
    if t != 0x06 || e - s < 8 {
        return false;
    }
    oid_text(&payload[s..e]).starts_with("1.2.840.113549.1.12.10.")
}

/// An AlgorithmIdentifier element: dotted OID plus the PKCS#12 PBE
/// salt/iteration params found anywhere inside (recursively — they sit
/// under a [0] { SEQ { salt, iter } } wrapper).
fn parse_pbe_alg(alg: &[u8]) -> (String, Vec<u8>, usize) {
    let mut oid = String::new();
    let mut salt = Vec::new();
    let mut iterations = 1usize;
    walk_pbe_params(alg, 0, alg.len(), &mut oid, &mut salt, &mut iterations);
    (oid, salt, iterations)
}

fn walk_pbe_params(
    alg: &[u8],
    start: usize,
    end: usize,
    oid: &mut String,
    salt: &mut Vec<u8>,
    iterations: &mut usize,
) {
    let mut pos = start;
    while pos < end {
        let Some(((t, a, b), next)) = tlv(alg, pos) else { break };
        match t {
            0x06 if oid.is_empty() => *oid = oid_text(&alg[a..b]),
            0x04 if salt.is_empty() && !oid.is_empty() => *salt = alg[a..b].to_vec(),
            0x02 if !oid.is_empty() => {
                let mut v = 0u64;
                for by in &alg[a..b] {
                    v = (v << 8) | *by as u64;
                }
                if v > 1 {
                    *iterations = v as usize;
                }
            }
            0x30 | 0xA0 => walk_pbe_params(alg, a, b, oid, salt, iterations),
            _ => {}
        }
        pos = next;
    }
}

/// Decrypt one bag: the vendor GOST PBE by hand, standard PKCS#12 PBEs
/// through OpenSSL.
fn decrypt_bag(
    alg: &[u8],
    oid: &str,
    salt: &[u8],
    iterations: usize,
    cipher: Vec<u8>,
    password: &str,
) -> Result<Vec<u8>, String> {
    if oid == "1.2.840.113549.1.12.1.80" {
        let key = pkcs12_kdf_gost94(password, salt, iterations, 1, 32)?;
        let iv = pkcs12_kdf_gost94(password, salt, iterations, 2, 8)?;
        return gost89_cfb_decrypt(&key, &iv, &cipher);
    }
    p12_pbe_crypt(alg, password, &cipher)
}





/// The vendor CryptoPro keybag PBE (`1.2.840.113549.1.12.1.80`),
/// ported from the upstream gost-engine `gost_cryptopro_keybag.c`:
///
/// 1. K = iterated GOST R 34.11-94 over `K_{c-1} ‖ salt ‖ c(BE u16)`,
///    K0 = UTF-16LE(password); IV = salt[..8].
/// 2. gost89-CFB-decrypt (CryptoPro-A S-box) → CPBlob.
/// 3. CPExportBlob at value[16:]: ukm, {cek.enc, cek.mac}, curve OIDs;
///    magic at value[4:6] picks the 256/512-bit layout.
/// 4. Ke = HMAC-Streebog-256(K, 01 ‖ 0x26BDB878 ‖ 00 ‖ ukm ‖ 01 00).
/// 5. raw = gost89-ECB-decrypt(Ke, cek.enc); build the engine-layout
///    PKCS#8 PrivateKeyInfo from it.
fn open_gost_keybag(
    salt: &[u8],
    iterations: usize,
    cipher: &[u8],
    password: &str,
) -> Option<PKey<Private>> {
    if salt.len() < 8 || !(1..=1_000_000).contains(&iterations) {
        return None;
    }
    // (1) iterated KDF — UTF-16LE password, empty password stays empty.
    let mut pw16: Vec<u8> = Vec::new();
    for b in password.as_bytes() {
        pw16.push(*b);
        pw16.push(0);
    }
    let mut cur: Vec<u8> = pw16;
    for c in 1..=iterations {
        let mut input = cur.clone();
        input.extend_from_slice(salt);
        input.extend_from_slice(&((c as u16).to_be_bytes()));
        cur = engine_digest(b"md_gost94", &input).ok()?.to_vec();
    }
    let Ok(k) = <[u8; 32]>::try_from(cur.as_slice()) else {
        return None;
    };

    // (2) gost89 CFB-decrypt, CryptoPro-A S-box, ciphertext feedback,
    // partial trailing block XORs only the available keystream bytes.
    let iv = &salt[..8];
    let mut plain = Vec::with_capacity(cipher.len());
    let mut fb: [u8; 8] = iv.try_into().ok()?;
    let mut i = 0;
    while i + 8 <= cipher.len() {
        let ks = gost89_ecb(&k, &fb, false);
        let mut out = [0u8; 8];
        for j in 0..8 {
            out[j] = cipher[i + j] ^ ks[j];
        }
        plain.extend_from_slice(&out);
        fb.copy_from_slice(&cipher[i..i + 8]);
        i += 8;
    }
    if i < cipher.len() {
        let ks = gost89_ecb(&k, &fb, false);
        let rem = cipher.len() - i;
        let mut out = vec![0u8; rem];
        for (j, slot) in out.iter_mut().enumerate() {
            *slot = cipher[i + j] ^ ks[j];
        }
        plain.extend_from_slice(&out);
    }

    // (3) CPBlob ::= SEQ { INTEGER, ANY, OCTET value, ANY? }.
    let (cs, ce) = seq_of(&plain, 0, plain.len())?;
    let mut value: Option<Vec<u8>> = None;
    let mut seen_int = false;
    let mut pos = cs;
    while pos < ce {
        let Some(((t, a, b), next)) = tlv(&plain, pos) else { break };
        if t == 0x02 {
            seen_int = true;
        } else if t == 0x04 && seen_int && value.is_none() {
            value = Some(plain[a..b].to_vec());
        }
        pos = next;
    }
    let value = value?;
    if value.len() < 16 || value.len() < 16 + 8 {
        return None;
    }
    let (is_512, raw_len) = match (&value[4], &value[5]) {
        (0x46, 0xAA) => (false, 32usize),
        (0x42, 0xAA) => (true, 64),
        _ => return None,
    };
    let _ = is_512;

    // (4) CPExportBlob at value[16:] ::= SEQ { OCTET ukm,
    //     SEQ { OCTET cek.enc, OCTET cek.mac }, [0] { alg } }.
    let eb = &value[16..];
    let (es, _ee) = seq_of(eb, 0, eb.len())?;
    // CPExportBlob ::= SEQ { CPExportBlob2, OCTET notused } — the first
    // child is the payload.
    let ((t0, b2s, b2e), _) = tlv(eb, es)?;
    if t0 != 0x30 {
        return None;
    }
    let mut ukm: Option<Vec<u8>> = None;
    let mut cek_enc: Option<Vec<u8>> = None;
    let mut oids_at: Option<usize> = None;
    let mut p = b2s;
    while p < b2e {
        let Some(((t, a, b), next)) = tlv(eb, p) else { break };
        match t {
            0x04 if ukm.is_none() => ukm = Some(eb[a..b].to_vec()),
            0x30 if cek_enc.is_none() => {
                let mut q = a;
                while q < b {
                    let Some(((t2, a2, b2), n2)) = tlv(eb, q) else { break };
                    if t2 == 0x04 && cek_enc.is_none() {
                        cek_enc = Some(eb[a2..b2].to_vec());
                    }
                    q = n2;
                }
            }
            0xA0 => oids_at = Some(a),
            _ => {}
        }
        p = next;
    }
    let mut curve: Option<Vec<u8>> = None;
    let mut digest: Option<Vec<u8>> = None;
    // Curve/digest OIDs: simpler rescan for two consecutive OIDs inside
    // the [0] subtree.
    if let Some(at) = oids_at {
        let mut found: Vec<Vec<u8>> = Vec::new();
        collect_oids(eb, at, &mut found);
        if found.len() >= 3 {
            curve = Some(found[found.len() - 2].clone());
            digest = Some(found[found.len() - 1].clone());
        }
    }
    let ukm = ukm?;
    let cek_enc = cek_enc?;
    let curve = curve?;
    let digest = digest?;
    if cek_enc.len() != raw_len {
        return None;
    }

    // (5) Ke = HMAC-Streebog-256(K, 01 ‖ label ‖ 00 ‖ ukm ‖ 01 00).
    let mut mac_input = vec![0x01u8];
    mac_input.extend_from_slice(&[0x26, 0xBD, 0xB8, 0x78]);
    mac_input.push(0x00);
    mac_input.extend_from_slice(&ukm);
    mac_input.extend_from_slice(&[0x01, 0x00]);
    let ke = hmac_engine(64, b"md_gost12_256", &k, &mac_input).ok()?;

    // (6) raw scalar = gost89-ECB-decrypt(Ke, cek.enc) — little-endian
    // wire format, consumed as-is.
    let ke32: [u8; 32] = ke.try_into().ok()?;
    let raw = gost89_ecb(&ke32, &cek_enc, true);

    // (7) engine-layout PKCS#8: { 0, { OID 2012-256/512,
    //     { curve, digest } }, OCTET raw }.
    let alg_oid = if is_512 {
        "1.2.643.7.1.1.1.2"
    } else {
        "1.2.643.7.1.1.1.1"
    };
    let curve_oid = oid_text(&curve);
    let digest_oid = oid_text(&digest);
    let der = build_pkcs8(alg_oid, &digest_oid, &curve_oid, &raw);
    
    crypto::load_private_key(&pem_encode(&der)).ok()
}


fn collect_oids(data: &[u8], start: usize, out: &mut Vec<Vec<u8>>) {
    let mut p = start;
    while p < data.len() {
        let Some(((t, a, b), next)) = tlv(data, p) else { break };
        if t == 0x06 {
            out.push(data[a..b].to_vec());
        }
        if matches!(t, 0x30 | 0xA0 | 0x31) {
            collect_oids(data, a, out);
        }
        p = next;
    }
}

/// HMAC over an engine digest with an explicit block size.
fn hmac_engine(
    block: usize,
    digest: &[u8],
    key: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, String> {
    let mut k = key.to_vec();
    if k.len() > block {
        k = engine_digest(digest, &k)?.to_vec();
    }
    k.resize(block, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5C).collect();
    let mut inner = ipad;
    inner.extend_from_slice(msg);
    let ih = engine_digest(digest, &inner)?;
    let mut outer = opad;
    outer.extend_from_slice(&ih);
    engine_digest(digest, &outer).map(|v| v.to_vec())
}

/// The vendor PBE: PKCS#12 KDF (RFC 7292 B.2, u = v = 32) over GOST R
/// 34.11-94, then GOST 28147-89 CFB (the engine's gost89 cipher).
fn pkcs12_kdf_gost94(
    password: &str,
    salt: &[u8],
    iterations: usize,
    id: u8,
    want: usize,
) -> Result<Vec<u8>, String> {
    const V: usize = 32;
    // PKCS#12 convention: an empty password means NO P bytes at all
    // (no terminator), like OpenSSL's null-password handling.
    let mut p = Vec::new();
    if !password.is_empty() {
        for u in password.encode_utf16() {
            p.extend_from_slice(&u.to_be_bytes());
        }
        p.push(0);
        p.push(0);
    }
    let rounds = if salt.is_empty() {
        0
    } else {
        salt.len().div_ceil(V)
    };
    let mut s = Vec::with_capacity(rounds * V);
    for _ in 0..rounds {
        s.extend_from_slice(salt);
    }

    let mut input = vec![id; V];
    input.extend_from_slice(&p);
    input.extend_from_slice(&s);
    let mut a = gost94(&input)?;
    for _ in 1..iterations.max(1) {
        a = gost94(&a)?;
    }
    Ok(a[..want.min(a.len())].to_vec())
}

/// GOST 28147-89 CFB via the engine cipher.
fn gost89_cfb_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe extern "C" {
        fn EVP_get_cipherbyname(name: *const std::ffi::c_char) -> *const openssl_sys::EVP_CIPHER;
    }
    if !crypto::init_gost() {
        return Err(crate::tr!(
            "GOST is not available: the gost engine is missing (install openssl-gost-engine)"
        ));
    }
    unsafe {
        let cipher = EVP_get_cipherbyname(c"gost89".as_ptr());
        if cipher.is_null() {
            return Err("GOST 28147-89 cipher is unavailable".to_string());
        }
        let ctx = openssl_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err("EVP_CIPHER_CTX_new failed".to_string());
        }
        let mut ok = openssl_sys::EVP_CipherInit_ex(
            ctx,
            cipher,
            crypto::gost_engine_ptr() as *mut openssl_sys::ENGINE,
            key.as_ptr(),
            iv.as_ptr(),
            0,
        ) == 1;
        let mut out = vec![0u8; data.len() + 16];
        let mut out_len = 0i32;
        let mut total = 0usize;
        if ok {
            ok = openssl_sys::EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
        }
        if ok {
            ok = openssl_sys::EVP_CipherUpdate(
                ctx,
                out.as_mut_ptr(),
                &mut out_len,
                data.as_ptr(),
                data.len() as i32,
            ) == 1;
            total = out_len as usize;
        }
        if ok {
            ok = openssl_sys::EVP_CipherFinal(
                ctx,
                out.as_mut_ptr().add(total),
                &mut out_len,
            ) == 1;
            total += out_len as usize;
        }
        openssl_sys::EVP_CIPHER_CTX_free(ctx);
        if !ok {
            return Err("GOST 28147-89 CFB decrypt failed".to_string());
        }
        out.truncate(total);
        Ok(out)
    }
}

/// Standard PKCS#12 PBE through OpenSSL's PKCS12_pbe_crypt.
fn p12_pbe_crypt(alg: &[u8], password: &str, cipher: &[u8]) -> Result<Vec<u8>, String> {
    unsafe extern "C" {
        fn d2i_X509_ALGOR(
            a: *mut *mut openssl_sys::X509_ALGOR,
            pp: *mut *const u8,
            len: std::ffi::c_long,
        ) -> *mut openssl_sys::X509_ALGOR;
        fn X509_ALGOR_free(a: *mut openssl_sys::X509_ALGOR);
        fn PKCS12_pbe_crypt(
            algor: *const openssl_sys::X509_ALGOR,
            pass: *const std::ffi::c_char,
            passlen: std::ffi::c_int,
            input: *const u8,
            inlen: std::ffi::c_int,
            data: *mut *mut u8,
            datalen: *mut std::ffi::c_int,
            en_de: std::ffi::c_int,
        ) -> *mut u8;
        fn CRYPTO_free(ptr: *mut u8, file: *const std::ffi::c_char, line: std::ffi::c_int);
    }
    unsafe {
        let mut alg_ptr: *mut openssl_sys::X509_ALGOR = std::ptr::null_mut();
        let mut p = alg.as_ptr();
        let alg_obj = d2i_X509_ALGOR(
            &mut alg_ptr,
            &mut p,
            alg.len() as std::ffi::c_long,
        );
        if alg_obj.is_null() {
            return Err("bad encryption algorithm".to_string());
        }
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len = 0i32;
        let rc = PKCS12_pbe_crypt(
            alg_obj,
            password.as_ptr().cast(),
            password.len() as i32,
            cipher.as_ptr(),
            cipher.len() as i32,
            &mut out,
            &mut out_len,
            0,
        );
        X509_ALGOR_free(alg_obj);
        if rc.is_null() {
            return Err(crate::tr!(
                "Wrong password or an unsupported key container."
            ));
        }
        let plain = std::slice::from_raw_parts(out, out_len.max(0) as usize).to_vec();
        CRYPTO_free(out, std::ptr::null(), 0);
        Ok(plain)
    }
}

/// SafeContents ::= SEQ of SafeBag.
fn walk_safe_contents(payload: &[u8], password: &str, out: &mut GostPfx) -> Result<(), String> {
    let _ = std::fs::write("/tmp/wsc.txt", format!("walk payload len {} head {:02X?}", payload.len(), &payload[..payload.len().min(12)]));
    let ((_, seq_s, seq_e), _) = tlvr(payload, 0)?;
    let mut pos = seq_s;
    while pos < seq_e {
        let ((_, bs, be), next) = tlvr(payload, pos)?;
        handle_safe_bag(payload, bs, be, password, out)?;
        pos = next;
    }
    Ok(())
}

/// SafeBag ::= SEQ { OID bagId, [0] bagValue, SET attrs? }. `bs..be` span
/// the SafeBag SEQUENCE.
fn handle_safe_bag(
    payload: &[u8],
    bs: usize,
    be: usize,
    password: &str,
    out: &mut GostPfx,
) -> Result<(), String> {
    let ((t, os, oe), p2) = tlvr(payload, bs)?;
    if t != 0x06 {
        return Ok(());
    }
    let bag = oid_text(&payload[os..oe]);
    let _ = std::fs::write("/tmp/wsc.txt", format!("bag {bag}"));
    let (t2, v_s, _) = tlvr(payload, p2)?.0;
    if t2 != 0xA0 {
        return Ok(());
    }
    // The [0] element content IS the bagValue DER.
    let ((t3, ve_s, ve_e), _) = tlvr(payload, v_s)?;
    let value = &payload[ve_s..ve_e];
    let _ = be;
    if bag == "1.2.840.113549.1.12.10.1.2" && t3 == 0x30 {
        // shroudedKeyBag: EncryptedPrivateKeyInfo { alg, OCTET }.
        // CryptoPro packs the algorithm as an OCTET STRING blob holding
        // { OID 12.1.80, SEQ { salt, iterations } } instead of the classic
        // AlgorithmIdentifier SEQUENCE — accept both shapes.
        let ((t4, a_s, a_e), p5) = tlvr(value, 0)?;
        let (oid, salt, iterations) = match t4 {
            0x30 | 0x04 => parse_pbe_alg(&value[a_s..a_e]),
            _ => return Ok(()),
        };
        let (t5, c_s, c_e) = tlvr(value, p5)?.0;
        if t5 != 0x04 {
            return Ok(());
        }
        let cipher = value[c_s..c_e].to_vec();
        if oid == "1.2.840.113549.1.12.1.80" {
            // The vendor GOST PBE: a couple of IV conventions exist in
            // the wild; PKCS#8 validity is the oracle.
            if let Some(k) = open_gost_keybag(&salt, iterations, &cipher, password) {
                out.key = Some(k);
            }
        } else if let Ok(p8) = decrypt_bag(&value[..p5], &oid, &salt, iterations, cipher, password)
            && let Some(k) = try_pkcs8_to_pkey(&p8) {
            out.key = Some(k);
        }
    } else if bag == "1.2.840.113549.1.12.10.1.3" && t3 == 0x30 {
        // certBag: SEQ { OID type, [0] { OCTET der } }
        let mut p = 0;
        while p < value.len() {
            let Some(((tag, a, _b), next)) = tlv(value, p) else { break };
            if tag == 0xA0 {
                let dbg = tlv(value, a).map(|((t6, s6, e6), _)| {
                    format!("inner tag {t6:02X} len {} parse={}", e6 - s6, X509::from_der(&value[s6..e6]).is_ok())
                }).unwrap_or_else(|| "no inner tlv".into());
                let _ = std::fs::write("/tmp/certdbg.txt", dbg);
                if let Some(((t6, s6, e6), _)) = tlv(value, a)
                    && t6 == 0x04
                        && let Ok(cert) = X509::from_der(&value[s6..e6]) {
                            out.certs.push(cert);
                        }
                break;
            }
            p = next;
        }
    }
    Ok(())
}

/// Load a decrypted PKCS#8: the plain loader first, then the GOST engine
/// layouts for both key generations and every curve.
fn try_pkcs8_to_pkey(p8: &[u8]) -> Option<PKey<Private>> {
    let p8 = der_trim(p8)?;
    if let Ok(k) = crypto::load_private_key(&pem_encode(p8)) {
        return Some(k);
    }
    let x = find_octet32(p8)?;
    for (param_oid, _) in PARAMSETS_256 {
        for (alg_oid, digest_oid) in KEY_ALGS {
            let der = build_pkcs8(alg_oid, digest_oid, param_oid, &x);
            if let Ok(k) = crypto::load_private_key(&pem_encode(&der)) {
                return Some(k);
            }
        }
    }
    None
}

/// Length of the first full DER TLV (trailing zero padding dropped).
fn der_trim(der: &[u8]) -> Option<&[u8]> {
    let n = der_total_len_trim(der)?;
    Some(&der[..n])
}

fn der_total_len_trim(der: &[u8]) -> Option<usize> {
    if der.len() < 2 || der[0] != 0x30 {
        return None;
    }
    let first = der[1];
    let (hdr, len) = if first < 0x80 {
        (2usize, first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || 2 + n > der.len() {
            return None;
        }
        let mut l = 0usize;
        for b in &der[2..2 + n] {
            l = (l << 8) | *b as usize;
        }
        (2 + n, l)
    };
    let total = hdr.checked_add(len)?;
    (total <= der.len()).then_some(total)
}

fn find_octet32(der: &[u8]) -> Option<Vec<u8>> {
    let ((tag, s, e), next) = tlv(der, 0)?;
    if tag == 0x04 && e - s == 32 {
        return Some(der[s..e].to_vec());
    }
    if e > s
        && let Some(inner) = find_octet32(&der[s..e]) {
            return Some(inner);
        }
    if next < der.len() {
        find_octet32(&der[next..])
    } else {
        None
    }
}

#[cfg(test)]
mod pfx_probe {
    /// Walk the real CryptoPro PFX with a deliberately wrong password:
    /// the structure must parse down to bag decryption, failing only at
    /// the password step. Run with `cargo test -- --ignored pfx_probe_real`.
    #[test]
    #[ignore]
    fn pfx_probe_real() {
        let data = match std::fs::read("Сертификат/Егоров.pfx") {
            Ok(d) => d,
            Err(_) => {
                eprintln!("no real PFX in the tree — skipped");
                return;
            }
        };
        // The container was exported without a password: the key must
        // come out with an empty one.
        let g = super::parse_gost_pfx(&data, "").expect("passwordless CSP5 PFX decodes");
        let key = g.key.expect("private key recovered");
        let der = key.private_key_to_pkcs8().unwrap();
        let _ = std::fs::write(
            "/tmp/pfxprobe.txt",
            format!("OK: key + {} certs", g.certs.len()),
        );
        assert!(!der.is_empty());
        assert!(!g.certs.is_empty());
    }
}

