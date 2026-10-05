//! OpenSSH keys and certificates (PROTOCOL.certkeys), built on top of
//! OpenSSL key objects: the SSH wire primitives of RFC 4251, the
//! `openssh-key-v1` private-key container (bcrypt-kdf + aes256-ctr for
//! encrypted files), public-key lines and SSH certificates with signing
//! and verification. Everything produced here is byte-compatible with
//! `ssh-keygen` (verified by the interop tests at the bottom of the file).

use crate::tr;
use crate::xca_format as xf;
use foreign_types::ForeignTypeRef;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

// ---- SSH wire primitives (RFC 4251 §5) ----

pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// mpint from an unsigned big-endian magnitude (as `BigNum::to_vec`
/// produces it): strip redundant zeros, prepend 0x00 when the high bit
/// would read as negative.
pub fn put_mpint(out: &mut Vec<u8>, mag: &[u8]) {
    let mut v = mag;
    while !v.is_empty() && v[0] == 0 {
        v = &v[1..];
    }
    let bytes: Vec<u8> = if v.is_empty() {
        Vec::new()
    } else if v[0] & 0x80 != 0 {
        let mut b = vec![0u8];
        b.extend_from_slice(v);
        b
    } else {
        v.to_vec()
    };
    put_string(out, &bytes);
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.remaining() {
            return Err("truncated SSH structure".into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(b);
        Ok(u64::from_be_bytes(v))
    }

    pub fn string(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u32()? as usize;
        if n > 512 * 1024 * 1024 {
            return Err("unreasonable SSH string length".into());
        }
        Ok(self.take(n)?.to_vec())
    }

    /// The next u32 without consuming it (option-form detection).
    pub fn peek_u32(&self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) {
        self.pos = pos.min(self.buf.len());
    }

    pub fn cstring(&mut self) -> Result<String, String> {
        Ok(String::from_utf8_lossy(&self.string()?).into_owned())
    }

    pub fn mpint(&mut self) -> Result<Vec<u8>, String> {
        let raw = self.string()?;
        if raw.len() > 1 && raw[0] == 0 && raw[1] & 0x80 == 0 {
            return Err("non-minimal SSH mpint".into());
        }
        Ok(raw)
    }
}

// ---- algorithms ----

/// SSH public-key algorithms xca-rs understands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SshAlgo {
    Ed25519,
    Rsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl SshAlgo {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Rsa => "ssh-rsa",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
            Self::EcdsaP521 => "ecdsa-sha2-nistp521",
        }
    }

    /// Certificate algorithm, `<base>-cert-v01@openssh.com`.
    pub fn cert_name(self) -> String {
        format!("{}-cert-v01@openssh.com", self.name())
    }

    /// Signature algorithm name used inside the cert signature field.
    pub fn sig_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            // OpenSSH signs certificates with SHA-512 for RSA CAs;
            // every OpenSSH ≥ 7.2 accepts rsa-sha2-512.
            Self::Rsa => "rsa-sha2-512",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
            Self::EcdsaP521 => "ecdsa-sha2-nistp521",
        }
    }

    /// Human label ("Ed25519", "RSA", "ECDSA nistp384").
    pub fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Rsa => "RSA",
            Self::EcdsaP256 => "ECDSA nistp256",
            Self::EcdsaP384 => "ECDSA nistp384",
            Self::EcdsaP521 => "ECDSA nistp521",
        }
    }

    fn curve_name(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "nistp256",
            Self::EcdsaP384 => "nistp384",
            Self::EcdsaP521 => "nistp521",
            _ => "",
        }
    }

    fn curve_nid(self) -> Nid {
        match self {
            Self::EcdsaP256 => Nid::X9_62_PRIME256V1,
            Self::EcdsaP384 => Nid::SECP384R1,
            Self::EcdsaP521 => Nid::SECP521R1,
            _ => Nid::X9_62_PRIME256V1,
        }
    }

    /// From a base ("ssh-rsa") or certificate ("ssh-rsa-cert-v01@…") name.
    pub fn from_name(name: &str) -> Option<Self> {
        let base = name.strip_suffix("-cert-v01@openssh.com").unwrap_or(name);
        Some(match base {
            "ssh-ed25519" => Self::Ed25519,
            "ssh-rsa" => Self::Rsa,
            "ecdsa-sha2-nistp256" => Self::EcdsaP256,
            "ecdsa-sha2-nistp384" => Self::EcdsaP384,
            "ecdsa-sha2-nistp521" => Self::EcdsaP521,
            _ => return None,
        })
    }

    /// The algo of a public-key or certificate blob (its first string).
    pub fn of_blob(blob: &[u8]) -> Result<Self, String> {
        let name = Reader::new(blob).cstring()?;
        Self::from_name(&name)
            .ok_or_else(|| format!("{}: {name}", tr!("Unsupported SSH algorithm")))
    }
}

/// Key kinds offered by the "New SSH Key" dialog.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NewSshKind {
    Ed25519,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl NewSshKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Rsa2048 => "RSA 2048",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
            Self::EcdsaP256 => "ECDSA nistp256",
            Self::EcdsaP384 => "ECDSA nistp384",
            Self::EcdsaP521 => "ECDSA nistp521",
        }
    }

    #[allow(dead_code)] // exercised by the keygen round-trip test
    pub fn algo(&self) -> SshAlgo {
        match self {
            Self::Ed25519 => SshAlgo::Ed25519,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => SshAlgo::Rsa,
            Self::EcdsaP256 => SshAlgo::EcdsaP256,
            Self::EcdsaP384 => SshAlgo::EcdsaP384,
            Self::EcdsaP521 => SshAlgo::EcdsaP521,
        }
    }

    pub fn generate(&self) -> Result<PKey<Private>, String> {
        let kind = match self {
            Self::Ed25519 => crate::crypto::NewKeyKind::Ed25519,
            Self::Rsa2048 => crate::crypto::NewKeyKind::Rsa2048,
            Self::Rsa3072 => crate::crypto::NewKeyKind::Rsa3072,
            Self::Rsa4096 => crate::crypto::NewKeyKind::Rsa4096,
            Self::EcdsaP256 => crate::crypto::NewKeyKind::EcP256,
            Self::EcdsaP384 => crate::crypto::NewKeyKind::EcP384,
            Self::EcdsaP521 => crate::crypto::NewKeyKind::EcP521,
        };
        crate::crypto::generate_key(kind).map_err(|e| e)
    }
}

// ---- public key blobs ↔ OpenSSL PKey ----

/// The SSH public-key blob of any OpenSSL key (private or public),
/// including the algorithm name — exactly the `ssh-keygen .pub` payload.
pub fn pubkey_blob<P: HasPublic>(key: &PKeyRef<P>) -> Result<Vec<u8>, String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    let mut out = Vec::new();
    match key.id() {
        Id::ED25519 => {
            put_string(&mut out, SshAlgo::Ed25519.name().as_bytes());
            let pk = key.raw_public_key().map_err(err)?;
            put_string(&mut out, &pk);
        }
        Id::RSA => {
            let rsa = key.rsa().map_err(err)?;
            put_string(&mut out, SshAlgo::Rsa.name().as_bytes());
            // RFC 4253 §6.6: exponent first, then the modulus.
            put_mpint(&mut out, &rsa.e().to_vec());
            put_mpint(&mut out, &rsa.n().to_vec());
        }
        Id::EC => {
            let ec = key.ec_key().map_err(err)?;
            let algo = match ec.group().curve_name().map(curve_algo) {
                Some(a) => a,
                None => return Err(tr!("Unsupported EC curve for SSH").into()),
            };
            let mut bctx = openssl::bn::BigNumContext::new().map_err(err)?;
            let q = ec
                .public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut bctx)
                .map_err(err)?;
            put_string(&mut out, algo.name().as_bytes());
            put_string(&mut out, algo.curve_name().as_bytes());
            put_string(&mut out, &q);
        }
        id => return Err(format!("{}: {id:?}", tr!("Unsupported key type for SSH"))),
    }
    Ok(out)
}

fn curve_algo(nid: Nid) -> SshAlgo {
    match nid {
        Nid::SECP384R1 => SshAlgo::EcdsaP384,
        Nid::SECP521R1 => SshAlgo::EcdsaP521,
        _ => SshAlgo::EcdsaP256,
    }
}

/// An OpenSSL public key from an SSH public-key blob (with algo name).
pub fn pkey_from_blob(blob: &[u8]) -> Result<PKey<Public>, String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    let mut r = Reader::new(blob);
    let name = r.cstring()?;
    let algo = SshAlgo::from_name(&name)
        .ok_or_else(|| format!("{}: {name}", tr!("Unsupported SSH algorithm")))?;
    match algo {
        SshAlgo::Ed25519 => {
            let pk = r.string()?;
            PKey::public_key_from_raw_bytes(&pk, Id::ED25519).map_err(err)
        }
        SshAlgo::Rsa => {
            let e = BigNum::from_slice(&r.mpint()?).map_err(err)?;
            let n = BigNum::from_slice(&r.mpint()?).map_err(err)?;
            PKey::from_rsa(Rsa::from_public_components(n, e).map_err(err)?).map_err(err)
        }
        algo => {
            let curve = r.cstring()?;
            if curve != algo.curve_name() {
                return Err("curve mismatch in SSH public key".into());
            }
            let q = r.string()?;
            let group = EcGroup::from_curve_name(algo.curve_nid()).map_err(err)?;
            let mut bctx = openssl::bn::BigNumContext::new().map_err(err)?;
            let point = EcPoint::from_bytes(&group, &q, &mut bctx).map_err(err)?;
            PKey::from_ec_key(EcKey::from_public_key(&group, &point).map_err(err)?).map_err(err)
        }
    }
}

/// Short human description of a public blob for list columns:
/// "Ed25519", "RSA 3072", "ECDSA nistp521".
pub fn describe_blob(blob: &[u8]) -> String {
    let Ok(algo) = SshAlgo::of_blob(blob) else {
        return tr!("unknown type");
    };
    if algo == SshAlgo::Rsa {
        let mut r = Reader::new(blob);
        let _ = r.cstring();
        let _e = r.mpint();
        let n = r.mpint().unwrap_or_default();
        let bits = if n.is_empty() {
            0
        } else {
            n.len() * 8 - n[0].leading_zeros() as usize
        };
        return format!("RSA {bits}");
    }
    algo.label().to_string()
}

/// SHA-256 fingerprint in ssh-keygen's form: "SHA256:<base64, no padding>".
pub fn fingerprint(blob: &[u8]) -> String {
    let d = openssl::hash::hash(MessageDigest::sha256(), blob)
        .map(|d| d.to_vec())
        .unwrap_or_default();
    format!("SHA256:{}", xf::b64_encode(&d).trim_end_matches('='))
}

// ---- public-key lines ("ssh-ed25519 AAAA… comment") ----

/// Everything except the leading algorithm name of a blob, as raw bytes.
fn blob_fields(blob: &[u8]) -> Result<&[u8], String> {
    let name = Reader::new(blob).cstring()?;
    let skip = 4 + name.len();
    blob.get(skip..).ok_or_else(|| "empty SSH blob".to_string())
}

pub fn public_line(blob: &[u8], comment: &str) -> String {
    let name = Reader::new(blob)
        .cstring()
        .unwrap_or_default();
    let mut line = format!("{} {}", name, xf::b64_encode(blob));
    if !comment.is_empty() {
        line.push(' ');
        line.push_str(comment);
    }
    line
}

/// Parse one `algo base64 [comment]` line. Returns None for foreign lines.
pub fn parse_public_line(line: &str) -> Option<(Vec<u8>, String)> {
    let mut it = line.trim().splitn(3, ' ');
    let algo = it.next()?.trim();
    let b64 = it.next()?.trim();
    if !algo.starts_with("ssh-") && !algo.starts_with("ecdsa-") {
        return None;
    }
    if algo.contains("-cert-v01@") {
        return None; // certificates are handled separately
    }
    let blob = xf::b64_decode(b64)?;
    if Reader::new(&blob).cstring().ok().as_deref() != Some(algo) {
        return None;
    }
    let comment = it.next().unwrap_or("").trim().to_string();
    Some((blob, comment))
}

// ---- openssh-key-v1 private container ----

const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";
/// bcrypt_pbkdf rounds for encrypted exports (ssh-keygen's default).
const KDF_ROUNDS: u32 = 16;

fn pem_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let begin = text.find(PEM_BEGIN)? + PEM_BEGIN.len();
    let end = text[begin..].find(PEM_END)? + begin;
    xf::b64_decode(&text[begin..end])
}

/// True when the armored key uses a KDF and needs a password.
pub fn pem_needs_password(data: &[u8]) -> bool {
    let Some(mut body) = pem_bytes(data) else { return false };
    if body.len() < MAGIC.len() || &body[..MAGIC.len()] != MAGIC {
        return false;
    }
    body.drain(..MAGIC.len());
    let mut r = Reader::new(&body);
    matches!(
        (r.cstring(), r.cstring()),
        (Ok(cipher), _) if cipher != "none"
    )
}

/// A parsed private key with its comment.
pub struct SshPrivateKey {
    pub pkey: PKey<Private>,
    pub comment: String,
    pub public_blob: Vec<u8>,
}

/// Parse a `-----BEGIN OPENSSH PRIVATE KEY-----` file. `password` is used
/// when the container carries bcrypt/aes256-ctr encryption.
pub fn parse_private_pem(data: &[u8], password: &str) -> Result<SshPrivateKey, String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    let mut body = pem_bytes(data)
        .ok_or_else(|| tr!("Not an OpenSSH private key").to_string())?;
    if body.len() < MAGIC.len() || &body[..MAGIC.len()] != MAGIC {
        return Err(tr!("Not an OpenSSH private key").into());
    }
    body.drain(..MAGIC.len());
    let mut r = Reader::new(&body);
    let cipher = r.cstring()?;
    let kdf = r.cstring()?;
    let kdf_opts = r.string()?;
    let nkeys = r.u32()?;
    if nkeys != 1 {
        return Err(format!("{}: {nkeys}", tr!("Unsupported SSH key file")));
    }
    let public_blob = r.string()?;
    let mut section = r.string()?;

    if cipher != "none" {
        if cipher != "aes256-ctr" || kdf != "bcrypt" {
            return Err(format!(
                "{}: {cipher}/{kdf}",
                tr!("Unsupported SSH key encryption")
            ));
        }
        let mut kr = Reader::new(&kdf_opts);
        let salt = kr.string()?;
        let rounds = kr.u32()?;
        let key_iv = bcrypt_key(password.as_bytes(), &salt, rounds)?;
        section = openssl::symm::decrypt(
            openssl::symm::Cipher::aes_256_ctr(),
            &key_iv[..32],
            Some(&key_iv[32..48]),
            &section,
        )
        .map_err(|e| format!("{}: {e}", tr!("Cannot decrypt the SSH key (wrong password?)")))?;
    }

    let mut s = Reader::new(&section);
    let c1 = s.u32()?;
    let c2 = s.u32()?;
    if c1 != c2 {
        return Err(tr!("Cannot decrypt the SSH key (wrong password?)").into());
    }
    // Current OpenSSH prefixes the private fields with the algorithm name
    // (same as the public blob); files from older versions start with the
    // fields directly. Distinguish by content and rewind for the legacy
    // form — the leading field of a legacy section can never spell a
    // known algorithm name.
    let fields_start = s.pos();
    let algo = match s.cstring() {
        Ok(name) => match SshAlgo::from_name(&name) {
            Some(a) if a == SshAlgo::of_blob(&public_blob)? => a,
            _ => {
                s.seek(fields_start);
                SshAlgo::of_blob(&public_blob)?
            }
        },
        Err(_) => {
            s.seek(fields_start);
            SshAlgo::of_blob(&public_blob)?
        }
    };
    let pkey = match algo {
        SshAlgo::Ed25519 => {
            let pk = s.string()?;
            let sk = s.string()?;
            if sk.len() != 64 {
                return Err("bad ed25519 private key length".into());
            }
            let seed = &sk[..32];
            // The embedded public key must match the container's copy.
            let mut pr = Reader::new(&public_blob);
            let _ = pr.cstring();
            if pr.string().ok().as_deref() != Some(pk.as_slice()) {
                return Err("ed25519 public key mismatch in SSH key".into());
            }
            PKey::private_key_from_raw_bytes(seed, Id::ED25519).map_err(err)?
        }
        SshAlgo::Rsa => {
            let n = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            let e = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            let d = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            let iqmp = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            let p = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            let q = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            PKey::from_rsa(rsa_from_parts(n, e, d, p, q, iqmp)?).map_err(err)?
        }
        algo => {
            let curve = s.cstring()?;
            if curve != algo.curve_name() {
                return Err("curve mismatch in SSH private key".into());
            }
            let q = s.string()?;
            let d = BigNum::from_slice(&s.mpint()?).map_err(err)?;
            let group = EcGroup::from_curve_name(algo.curve_nid()).map_err(err)?;
            let mut bctx = openssl::bn::BigNumContext::new().map_err(err)?;
            let point = EcPoint::from_bytes(&group, &q, &mut bctx).map_err(err)?;
            PKey::from_ec_key(EcKey::from_private_components(&group, &d, &point).map_err(err)?)
                .map_err(err)?
        }
    };
    let comment = s.cstring()?;
    Ok(SshPrivateKey {
        pkey,
        comment,
        public_blob,
    })
}

/// RSA private key from the OpenSSH components (n, e, d, iqmp, p, q):
/// OpenSSL additionally wants dmp1 = d mod (p−1) and dmq1 = d mod (q−1),
/// which are not stored in the SSH format and are recomputed here.
fn rsa_from_parts(
    n: BigNum,
    e: BigNum,
    d: BigNum,
    p: BigNum,
    q: BigNum,
    iqmp: BigNum,
) -> Result<Rsa<Private>, String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    let one = BigNum::from_u32(1).map_err(err)?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(err)?;
    let pm1 = p.as_ref() - one.as_ref();
    let qm1 = q.as_ref() - one.as_ref();
    let mut dmp1 = BigNum::new().map_err(err)?;
    dmp1.nnmod(d.as_ref(), pm1.as_ref(), &mut ctx).map_err(err)?;
    let mut dmq1 = BigNum::new().map_err(err)?;
    dmq1.nnmod(d.as_ref(), qm1.as_ref(), &mut ctx).map_err(err)?;
    Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp).map_err(err)
}

fn bcrypt_key(password: &[u8], salt: &[u8], rounds: u32) -> Result<Vec<u8>, String> {
    if salt.len() < 8 || rounds == 0 {
        return Err("bad bcrypt KDF parameters".into());
    }
    let mut out = vec![0u8; 48];
    bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut out)
        .map_err(|e| format!("bcrypt_pbkdf: {e}"))?;
    Ok(out)
}

/// Encode a private key as an `openssh-key-v1` PEM. An empty password
/// stores the key unencrypted ("none" cipher), a password wraps it in
/// bcrypt-kdf + aes256-ctr exactly like `ssh-keygen`.
pub fn encode_private_pem(
    key: &PKeyRef<Private>,
    comment: &str,
    password: &str,
) -> Result<Vec<u8>, String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    let public_blob = pubkey_blob(key)?;
    let algo = SshAlgo::of_blob(&public_blob)?;

    let mut body = Vec::new();
    let mut check = [0u8; 4];
    openssl::rand::rand_bytes(&mut check).map_err(err)?;
    body.extend_from_slice(&check);
    body.extend_from_slice(&check);
    // The private fields start with the algorithm name, exactly as
    // current ssh-keygen writes them.
    put_string(&mut body, algo.name().as_bytes());
    match algo {
        SshAlgo::Ed25519 => {
            let pk = key.raw_public_key().map_err(err)?;
            let seed = key.raw_private_key().map_err(err)?;
            put_string(&mut body, &pk);
            let mut sk = seed;
            sk.extend_from_slice(&pk);
            put_string(&mut body, &sk);
        }
        SshAlgo::Rsa => {
            let rsa = key.rsa().map_err(err)?;
            let miss = || "RSA key misses CRT factors".to_string();
            put_mpint(&mut body, &rsa.n().to_vec());
            put_mpint(&mut body, &rsa.e().to_vec());
            put_mpint(&mut body, &rsa.d().to_vec());
            put_mpint(&mut body, &rsa.iqmp().ok_or_else(miss)?.to_vec());
            put_mpint(&mut body, &rsa.p().ok_or_else(miss)?.to_vec());
            put_mpint(&mut body, &rsa.q().ok_or_else(miss)?.to_vec());
        }
        algo => {
            let ec = key.ec_key().map_err(err)?;
            let point = ec.private_key();
            put_string(&mut body, algo.curve_name().as_bytes());
            let mut bctx = openssl::bn::BigNumContext::new().map_err(err)?;
            let q = ec
                .public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut bctx)
                .map_err(err)?;
            put_string(&mut body, &q);
            put_mpint(&mut body, &point.to_vec());
        }
    }
    put_string(&mut body, comment.as_bytes());
    // Padding bytes 1,2,3… to the cipher block size (8 for "none", 16 for AES).
    let block = if password.is_empty() { 8 } else { 16 };
    let mut pad = 1u8;
    while body.len() % block != 0 {
        body.push(pad);
        pad = pad.wrapping_add(1);
    }

    let mut out = MAGIC.to_vec();
    if password.is_empty() {
        put_string(&mut out, b"none");
        put_string(&mut out, b"none");
        put_string(&mut out, b"");
    } else {
        let mut salt = [0u8; 16];
        openssl::rand::rand_bytes(&mut salt).map_err(err)?;
        let mut kdf_opts = Vec::new();
        put_string(&mut kdf_opts, &salt);
        put_u32(&mut kdf_opts, KDF_ROUNDS);
        let key_iv = bcrypt_key(password.as_bytes(), &salt, KDF_ROUNDS)?;
        body = openssl::symm::encrypt(
            openssl::symm::Cipher::aes_256_ctr(),
            &key_iv[..32],
            Some(&key_iv[32..48]),
            &body,
        )
        .map_err(err)?;
        put_string(&mut out, b"aes256-ctr");
        put_string(&mut out, b"bcrypt");
        put_string(&mut out, &kdf_opts);
    }
    put_u32(&mut out, 1);
    put_string(&mut out, &public_blob);
    put_string(&mut out, &body);

    let b64 = xf::b64_encode(&out);
    let mut pem = String::from(PEM_BEGIN);
    pem.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(PEM_END);
    pem.push('\n');
    Ok(pem.into_bytes())
}

// ---- SSH signatures ----

/// Ed25519 is pure-EdDSA: the safe bindings cannot express a NULL digest,
/// so sign/verify go through the C API directly.
mod eddsa_ffi {
    #![allow(non_snake_case)]
    use openssl_sys::{EVP_MD_CTX, EVP_PKEY};

    unsafe extern "C" {
        pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
        pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
        pub fn EVP_DigestSignInit(
            ctx: *mut EVP_MD_CTX,
            pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
            md: *const openssl_sys::EVP_MD,
            e: *mut openssl_sys::ENGINE,
            pkey: *mut EVP_PKEY,
        ) -> std::ffi::c_int;
        pub fn EVP_DigestSign(
            ctx: *mut EVP_MD_CTX,
            sigret: *mut u8,
            siglen: *mut usize,
            tbs: *const u8,
            tbslen: usize,
        ) -> std::ffi::c_int;
        pub fn EVP_DigestVerifyInit(
            ctx: *mut EVP_MD_CTX,
            pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
            md: *const openssl_sys::EVP_MD,
            e: *mut openssl_sys::ENGINE,
            pkey: *mut EVP_PKEY,
        ) -> std::ffi::c_int;
        pub fn EVP_DigestVerify(
            ctx: *mut EVP_MD_CTX,
            sigret: *const u8,
            siglen: usize,
            tbs: *const u8,
            tbslen: usize,
        ) -> std::ffi::c_int;
    }
}

fn ed25519_sign(key: &PKeyRef<Private>, data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let ctx = eddsa_ffi::EVP_MD_CTX_new();
        if ctx.is_null() {
            return Err("EVP_MD_CTX_new".into());
        }
        let ok = eddsa_ffi::EVP_DigestSignInit(
            ctx,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            key.as_ptr(),
        );
        let mut out = Vec::new();
        if ok == 1 {
            let mut len = 0usize;
            if eddsa_ffi::EVP_DigestSign(ctx, std::ptr::null_mut(), &mut len, data.as_ptr(), data.len()) == 1 {
                out.resize(len, 0);
                if eddsa_ffi::EVP_DigestSign(ctx, out.as_mut_ptr(), &mut len, data.as_ptr(), data.len()) == 1 {
                    out.truncate(len);
                } else {
                    out.clear();
                }
            }
        }
        eddsa_ffi::EVP_MD_CTX_free(ctx);
        if out.is_empty() {
            return Err(format!("Ed25519 sign: {}", openssl::error::ErrorStack::get()));
        }
        Ok(out)
    }
}

fn ed25519_verify<P: HasPublic>(key: &PKeyRef<P>, sig: &[u8], data: &[u8]) -> Result<bool, String> {
    unsafe {
        let ctx = eddsa_ffi::EVP_MD_CTX_new();
        if ctx.is_null() {
            return Err("EVP_MD_CTX_new".into());
        }
        let init = eddsa_ffi::EVP_DigestVerifyInit(
            ctx,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            key.as_ptr(),
        );
        let ok = if init == 1 {
            eddsa_ffi::EVP_DigestVerify(ctx, sig.as_ptr(), sig.len(), data.as_ptr(), data.len())
        } else {
            -1
        };
        eddsa_ffi::EVP_MD_CTX_free(ctx);
        match ok {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(format!("Ed25519 verify: {}", openssl::error::ErrorStack::get())),
        }
    }
}

/// DER SEQUENCE of two INTEGERs from SSH ECDSA r‖s strings — the form
/// EVP's ECDSA verify expects.
fn ecdsa_sig_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn der_int(mag: &[u8]) -> Vec<u8> {
        let mut v = mag;
        while !v.is_empty() && v[0] == 0 {
            v = &v[1..];
        }
        let content: Vec<u8> = if v.is_empty() {
            vec![0]
        } else if v[0] & 0x80 != 0 {
            let mut c = vec![0u8];
            c.extend_from_slice(v);
            c
        } else {
            v.to_vec()
        };
        let mut out = vec![0x02u8];
        match content.len() {
            n if n < 0x80 => out.push(n as u8),
            n => {
                out.push(0x81);
                out.push(n as u8);
            }
        }
        out.extend_from_slice(&content);
        out
    }
    let body = [der_int(r), der_int(s)].concat();
    let mut out = vec![0x30u8];
    match body.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n <= 0xff => {
            out.push(0x81);
            out.push(n as u8);
        }
        n => {
            out.push(0x82);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(&body);
    out
}

/// SSH signature over `data`: (algorithm name, signature blob). The blob
/// is the raw signature (r‖s strings for ECDSA, PKCS#1 bytes for RSA).
fn ssh_sign(key: &PKeyRef<Private>, algo: SshAlgo, data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    match algo {
        SshAlgo::Ed25519 => Ok((algo.sig_name().into(), ed25519_sign(key, data)?)),
        SshAlgo::Rsa => {
            let mut signer = Signer::new(MessageDigest::sha512(), key).map_err(err)?;
            let sig = signer.sign_oneshot_to_vec(data).map_err(err)?;
            Ok((algo.sig_name().into(), sig))
        }
        algo => {
            let md = match algo {
                SshAlgo::EcdsaP384 => MessageDigest::sha384(),
                SshAlgo::EcdsaP521 => MessageDigest::sha512(),
                _ => MessageDigest::sha256(),
            };
            let mut signer = Signer::new(md, key).map_err(err)?;
            let der = signer.sign_oneshot_to_vec(data).map_err(err)?;
            let sig = openssl::ecdsa::EcdsaSig::from_der(&der).map_err(err)?;
            let mut out = Vec::new();
            put_string(&mut out, &sig.r().to_vec());
            put_string(&mut out, &sig.s().to_vec());
            Ok((algo.sig_name().into(), out))
        }
    }
}

fn ssh_verify<P: HasPublic>(
    key: &PKeyRef<P>,
    sig_name: &str,
    sig: &[u8],
    data: &[u8],
) -> Result<bool, String> {
    let err = |e: openssl::error::ErrorStack| e.to_string();
    match sig_name {
        "ssh-ed25519" => ed25519_verify(key, sig, data),
        "rsa-sha2-512" | "rsa-sha2-256" | "ssh-rsa" => {
            let md = if sig_name == "rsa-sha2-256" {
                MessageDigest::sha256()
            } else if sig_name == "ssh-rsa" {
                MessageDigest::sha1()
            } else {
                MessageDigest::sha512()
            };
            let mut v = Verifier::new(md, key).map_err(err)?;
            v.update(data).map_err(err)?;
            v.verify(sig).map_err(err)
        }
        name if name.starts_with("ecdsa-sha2-") => {
            let mut r = Reader::new(sig);
            let rr = r.string()?;
            let ss = r.string()?;
            let md = match name {
                "ecdsa-sha2-nistp384" => MessageDigest::sha384(),
                "ecdsa-sha2-nistp521" => MessageDigest::sha512(),
                _ => MessageDigest::sha256(),
            };
            let mut v = Verifier::new(md, key).map_err(err)?;
            v.update(data).map_err(err)?;
            v.verify(&ecdsa_sig_der(&rr, &ss)).map_err(err)
        }
        other => Err(format!("unknown SSH signature algorithm: {other}")),
    }
}

// ---- certificates (PROTOCOL.certkeys) ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SshCertType {
    User,
    Host,
}

impl SshCertType {
    fn as_u32(self) -> u32 {
        match self {
            Self::User => 1,
            Self::Host => 2,
        }
    }

    fn from_u32(v: u32) -> Result<Self, String> {
        match v {
            1 => Ok(Self::User),
            2 => Ok(Self::Host),
            _ => Err("bad SSH certificate type".into()),
        }
    }

}

pub const FOREVER: u64 = u64::MAX;

/// Parameters for [`build_cert`].
pub struct SshCertParams {
    pub serial: u64,
    pub cert_type: SshCertType,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Seconds since the epoch.
    pub valid_after: u64,
    /// [`FOREVER`] for an unlimited certificate.
    pub valid_before: u64,
    /// Critical options in encoding order: name plus the value for options
    /// that take one (force-command, source-address).
    pub critical: Vec<(String, Option<String>)>,
    /// Extension flag names ("permit-pty", …).
    pub extensions: Vec<String>,
}

/// A parsed (or freshly built) SSH certificate.
#[derive(Clone, Debug)]
pub struct SshCert {
    pub algo: SshAlgo,
    pub nonce: Vec<u8>,
    /// The certified key's blob (with the algorithm name).
    pub public_blob: Vec<u8>,
    pub serial: u64,
    pub cert_type: SshCertType,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical: Vec<(String, Option<String>)>,
    pub extensions: Vec<String>,
    /// The signing (CA) key's blob, with the algorithm name.
    pub ca_blob: Vec<u8>,
    pub sig_name: String,
    pub signature: Vec<u8>,
    /// The complete serialized certificate (algorithm name included).
    pub blob: Vec<u8>,
}

/// Options that carry a value after their name inside the critical
/// options / extensions sections (everything else is a flag).
fn option_takes_value(name: &str) -> bool {
    matches!(name, "force-command" | "source-address")
}

/// Serialize the critical-options / extensions section in the modern
/// (OpenSSH ≥ 10) form: every option is name + data string, where flags
/// carry an empty data string and value options wrap their value in one
/// more string (PROTOCOL.certkeys: the option data of force-command /
/// source-address is itself an SSH string). The legacy bare-flag form is
/// rejected by current ssh-keygen.
fn options_bytes(opts: &[(String, Option<String>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in opts {
        put_string(&mut out, name.as_bytes());
        match value {
            Some(v) => {
                let mut data = Vec::new();
                put_string(&mut data, v.as_bytes());
                put_string(&mut out, &data);
            }
            None => put_string(&mut out, b""),
        }
    }
    out
}

/// Parse an options section, accepting both encodings: the modern
/// name+data form and the legacy one (bare flag names, unwrapped option
/// values, written by OpenSSH before 10.0).
fn parse_options(mut r: Reader<'_>) -> Result<Vec<(String, Option<String>)>, String> {
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let name = r.cstring()?;
        if option_takes_value(&name) {
            let data = if r.remaining() > 0 { r.string()? } else { Vec::new() };
            // Modern: data = string(value). Legacy: data is the value
            // itself. Take the inner string when it fills the data exactly.
            let inner = Reader::new(&data)
                .string()
                .ok()
                .filter(|v| 4 + v.len() == data.len());
            let value = inner.unwrap_or(data);
            out.push((name, Some(String::from_utf8_lossy(&value).into_owned())));
        } else {
            // Modern form: an empty data string follows every flag.
            // Legacy form: nothing follows — the next option's name length
            // is never zero, so the peek tells the two apart.
            if r.peek_u32() == Some(0) {
                let _ = r.string()?;
            }
            out.push((name, None));
        }
    }
    Ok(out)
}

/// Serialize a certificate. `signature` = None leaves the signature field
/// empty (the pre-signature bytes OpenSSH signs are exactly this form).
fn serialize_cert(
    algo: SshAlgo,
    nonce: &[u8],
    public_blob: &[u8],
    serial: u64,
    cert_type: SshCertType,
    key_id: &str,
    principals: &[String],
    valid_after: u64,
    valid_before: u64,
    critical: &[(String, Option<String>)],
    extensions: &[String],
    ca_blob: &[u8],
    signature: Option<(&str, &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, algo.cert_name().as_bytes());
    put_string(&mut out, nonce);
    out.extend_from_slice(blob_fields(public_blob).unwrap_or(&[]));
    put_u64(&mut out, serial);
    put_u32(&mut out, cert_type.as_u32());
    put_string(&mut out, key_id.as_bytes());
    let mut p = Vec::new();
    for principal in principals {
        put_string(&mut p, principal.as_bytes());
    }
    put_string(&mut out, &p);
    put_u64(&mut out, valid_after);
    put_u64(&mut out, valid_before);
    put_string(&mut out, &options_bytes(critical));
    let mut e = Vec::new();
    for ext in extensions {
        // Same modern option form as the critical section: every option
        // is name + data string, empty data for flags.
        put_string(&mut e, ext.as_bytes());
        put_string(&mut e, b"");
    }
    put_string(&mut out, &e);
    put_string(&mut out, b""); // reserved
    put_string(&mut out, ca_blob);
    // The signature field is appended only when a signature exists:
    // OpenSSH signs the certificate *without* the field entirely (not an
    // empty placeholder), so the None form is exactly the signed bytes.
    if let Some((name, sig)) = signature {
        let mut sig_field = Vec::new();
        put_string(&mut sig_field, name.as_bytes());
        put_string(&mut sig_field, sig);
        put_string(&mut out, &sig_field);
    }
    out
}

/// Build and sign an SSH certificate: `subject_blob` is the certified
/// key's public blob, `ca` its signing key.
pub fn build_cert(
    subject_blob: &[u8],
    ca: &PKeyRef<Private>,
    params: &SshCertParams,
) -> Result<SshCert, String> {
    let algo = SshAlgo::of_blob(subject_blob)?;
    // of_blob only checks the algorithm name; make sure the whole blob
    // assembles into a key so garbage fields cannot enter a certificate.
    pkey_from_blob(subject_blob)
        .map_err(|e| format!("invalid subject key blob: {e}"))?;
    let ca_blob = pubkey_blob(ca)?;
    let mut nonce = vec![0u8; 32];
    openssl::rand::rand_bytes(&mut nonce).map_err(|e| e.to_string())?;

    let unsigned = serialize_cert(
        algo,
        &nonce,
        subject_blob,
        params.serial,
        params.cert_type,
        &params.key_id,
        &params.principals,
        params.valid_after,
        params.valid_before,
        &params.critical,
        &params.extensions,
        &ca_blob,
        None,
    );
    let (sig_name, signature) = ssh_sign(ca, SshAlgo::of_blob(&ca_blob)?, &unsigned)?;
    let blob = serialize_cert(
        algo,
        &nonce,
        subject_blob,
        params.serial,
        params.cert_type,
        &params.key_id,
        &params.principals,
        params.valid_after,
        params.valid_before,
        &params.critical,
        &params.extensions,
        &ca_blob,
        Some((&sig_name, &signature)),
    );
    let cert = SshCert {
        algo,
        nonce,
        public_blob: subject_blob.to_vec(),
        serial: params.serial,
        cert_type: params.cert_type,
        key_id: params.key_id.clone(),
        principals: params.principals.clone(),
        valid_after: params.valid_after,
        valid_before: params.valid_before,
        critical: params.critical.clone(),
        extensions: params.extensions.clone(),
        ca_blob: ca_blob.clone(),
        sig_name,
        signature,
        blob,
    };
    // Never hand out a certificate our own verifier rejects.
    let ca_pub = pkey_from_blob(&ca_blob)?;
    if !verify_cert(&cert, &ca_pub)? {
        return Err(tr!("SSH certificate signature verification failed").into());
    }
    Ok(cert)
}

/// Parse a certificate blob (with the `…-cert-v01@openssh.com` name).
pub fn parse_cert(blob: &[u8]) -> Result<SshCert, String> {
    let mut r = Reader::new(blob);
    let name = r.cstring()?;
    let algo = SshAlgo::from_name(&name)
        .ok_or_else(|| format!("{}: {name}", tr!("Unsupported SSH algorithm")))?;
    if !name.ends_with("-cert-v01@openssh.com") {
        return Err(tr!("Not an SSH certificate").into());
    }
    let nonce = r.string()?;
    // The certified key: rebuild a full public blob from the same fields.
    let mut public_blob = Vec::new();
    put_string(&mut public_blob, algo.name().as_bytes());
    let key_fields = match algo {
        SshAlgo::Ed25519 => {
            let pk = r.string()?;
            vec![pk]
        }
        SshAlgo::Rsa => {
            let e = r.mpint()?;
            let n = r.mpint()?;
            vec![e, n]
        }
        _ => {
            let curve = r.cstring()?;
            let q = r.string()?;
            if curve != algo.curve_name() {
                return Err("curve mismatch in SSH certificate".into());
            }
            vec![curve.into_bytes(), q]
        }
    };
    for f in &key_fields {
        put_string(&mut public_blob, f);
    }
    let serial = r.u64()?;
    let cert_type = SshCertType::from_u32(r.u32()?)?;
    let key_id = r.cstring()?;
    let principals_blob = r.string()?;
    let mut pr = Reader::new(&principals_blob);
    let mut principals = Vec::new();
    while pr.remaining() > 0 {
        principals.push(pr.cstring()?);
    }
    let valid_after = r.u64()?;
    let valid_before = r.u64()?;
    let critical = parse_options(Reader::new(&r.string()?))?;
    let extensions = parse_options(Reader::new(&r.string()?))?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let _reserved = r.string()?;
    let ca_blob = r.string()?;
    let sig_field = r.string()?;
    let mut sr = Reader::new(&sig_field);
    let sig_name = sr.cstring()?;
    let signature = sr.string()?;

    Ok(SshCert {
        algo,
        nonce,
        public_blob,
        serial,
        cert_type,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical,
        extensions,
        ca_blob,
        sig_name,
        signature,
        blob: blob.to_vec(),
    })
}

/// Verify a certificate's signature against a CA key (any view of it).
/// The signed pre-image is re-serialized in the modern option encoding,
/// so certificates in the legacy (pre-OpenSSH-10) form parse but cannot
/// be verified here; nothing in xca-rs verifies imported certificates,
/// so this only affects this function's own callers.
pub fn verify_cert<P: HasPublic>(cert: &SshCert, ca_public: &PKeyRef<P>) -> Result<bool, String> {
    let unsigned = serialize_cert(
        cert.algo,
        &cert.nonce,
        &cert.public_blob,
        cert.serial,
        cert.cert_type,
        &cert.key_id,
        &cert.principals,
        cert.valid_after,
        cert.valid_before,
        &cert.critical,
        &cert.extensions,
        &cert.ca_blob,
        None,
    );
    ssh_verify(ca_public, &cert.sig_name, &cert.signature, &unsigned)
}

/// `algo-cert-v01@openssh.com base64 [comment]` line.
pub fn cert_line(cert: &SshCert, comment: &str) -> String {
    let mut line = format!(
        "{} {}",
        cert.algo.cert_name(),
        xf::b64_encode(&cert.blob)
    );
    if !comment.is_empty() {
        line.push(' ');
        line.push_str(comment);
    }
    line
}

pub fn parse_cert_line(line: &str) -> Option<(SshCert, String)> {
    let mut it = line.trim().splitn(3, ' ');
    let algo = it.next()?.trim();
    if !algo.ends_with("-cert-v01@openssh.com") {
        return None;
    }
    let b64 = it.next()?.trim();
    let blob = xf::b64_decode(b64)?;
    let cert = parse_cert(&blob).ok()?;
    let comment = it.next().unwrap_or("").trim().to_string();
    Some((cert, comment))
}

/// True when the file carries anything SSH-shaped: an openssh private key
/// container or public/certificate lines.
pub fn looks_like_ssh(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    if text.contains(PEM_BEGIN) {
        return true;
    }
    text.lines().any(|l| {
        let first = l.trim().split_whitespace().next().unwrap_or("");
        (first.starts_with("ssh-") || first.starts_with("ecdsa-"))
            && l.trim().split_whitespace().count() >= 2
    })
}

// ---- the user's ~/.ssh storage (read-only view) ----

/// One key found in the user's `~/.ssh` directory.
#[derive(Clone, Debug)]
pub struct UserKey {
    pub path: std::path::PathBuf,
    /// File name (the list shows it as the internal name).
    pub file: String,
    /// "Ed25519", "RSA 3072", … ("unknown type" when nothing can be read).
    pub kind_label: String,
    pub comment: String,
    /// A private key file exists (openssh-key-v1 or classic PEM).
    pub has_private: bool,
    /// The private part is password-protected.
    pub encrypted: bool,
    /// Only a `.pub` line, no private part.
    pub pub_only: bool,
    /// Known even without a password: from the container header, the
    /// `.pub` sidecar or a decrypted private key.
    pub public_blob: Option<Vec<u8>>,
    /// A matching `*-cert.pub` certificate sits next to the key.
    pub has_cert: bool,
}

/// The public-key blob recorded in an openssh-key-v1 container — it stays
/// in the clear even when the private part is encrypted.
pub fn peek_public_blob(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut body = pem_bytes(data)
        .ok_or_else(|| tr!("Not an OpenSSH private key").to_string())?;
    if body.len() < MAGIC.len() || &body[..MAGIC.len()] != MAGIC {
        return Err(tr!("Not an OpenSSH private key").into());
    }
    body.drain(..MAGIC.len());
    let mut r = Reader::new(&body);
    let _cipher = r.cstring()?;
    let _kdf = r.cstring()?;
    let _kdf_opts = r.string()?;
    if r.u32()? != 1 {
        return Err(format!("{}: not 1", tr!("Unsupported SSH key file")));
    }
    r.string()
}

/// Parse any private key file the user may have: an openssh-key-v1
/// container or a classic PEM (PKCS#8 / RSA / EC, via OpenSSL). Returns
/// the key and its comment (empty for PEM).
pub fn parse_user_private(
    data: &[u8],
    password: &str,
) -> Result<(PKey<Private>, String), String> {
    if String::from_utf8_lossy(data).contains(PEM_BEGIN) {
        let k = parse_private_pem(data, password)?;
        return Ok((k.pkey, k.comment));
    }
    let pw = password.as_bytes().to_vec();
    let key = PKey::private_key_from_pem_callback(data, |buf: &mut [u8]| {
        let n = pw.len().min(buf.len());
        buf[..n].copy_from_slice(&pw[..n]);
        Ok(n)
    })
    .map_err(|e| format!("{}: {e}", tr!("Cannot decrypt the SSH key (wrong password?)")))?;
    Ok((key, String::new()))
}

/// Classic (non-openssh) PEM private key?
fn is_pem_private(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("PRIVATE KEY-----") && !text.contains(PEM_BEGIN)
}

/// Read every key-looking file of `dir` (the caller passes `~/.ssh`):
/// private keys (openssh and classic PEM, encrypted or not), `.pub`
/// sidecars and standalone public lines; `*-cert.pub` files only mark
/// their key as certified. Non-key files (config, known_hosts, …) are
/// skipped. Nothing is ever written.
pub fn scan_ssh_dir(dir: &std::path::Path) -> Vec<UserKey> {
    let mut files: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            // fs::metadata follows symlinks (DirEntry::metadata is
            // lstat-only): keys managed through links (secret-store
            // setups) must show up; broken or looping links error out
            // and are skipped.
            .filter(|e| std::fs::metadata(e.path()).is_ok_and(|m| m.is_file()))
            .map(|e| e.path())
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();

    let mut out: Vec<UserKey> = Vec::new();
    let mut by_name: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // 1st pass: private key files.
    for path in &files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".pub") || name.starts_with('.') {
            continue;
        }
        let Ok(data) = std::fs::read(path) else { continue };
        if data.len() > 1024 * 1024 {
            continue;
        }
        let (encrypted, openssh) = if String::from_utf8_lossy(&data).contains(PEM_BEGIN) {
            (pem_needs_password(&data), true)
        } else if is_pem_private(&data) {
            (
                String::from_utf8_lossy(&data).contains("ENCRYPTED PRIVATE KEY"),
                false,
            )
        } else {
            continue; // config, known_hosts, environment, …
        };
        let mut key = UserKey {
            path: path.clone(),
            file: name.to_string(),
            kind_label: tr!("unknown type"),
            comment: String::new(),
            has_private: true,
            encrypted,
            pub_only: false,
            public_blob: None,
            has_cert: false,
        };
        // The public blob is available without a password: decrypted
        // directly, from the container header, or later from the .pub
        // sidecar.
        match if openssh {
            if encrypted {
                peek_public_blob(&data).map(|b| (b, String::new()))
            } else {
                parse_private_pem(&data, "").map(|k| (k.public_blob, k.comment))
            }
        } else {
            match parse_user_private(&data, "") {
                Ok((pkey, _)) => pubkey_blob(&pkey).map(|b| (b, String::new())),
                Err(e) => Err(e),
            }
        } {
            Ok((blob, comment)) => {
                key.public_blob = Some(blob);
                key.comment = comment;
            }
            Err(_) => {}
        }
        if let Some(blob) = &key.public_blob {
            key.kind_label = describe_blob(blob);
        } else if !openssh {
            key.kind_label = "PEM".into();
        }
        by_name.insert(name.to_string(), out.len());
        out.push(key);
    }

    // 2nd pass: .pub sidecars — fill in what an encrypted key hides, and
    // register standalone public keys.
    for path in &files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".pub") || name.ends_with("-cert.pub") {
            continue;
        }
        let base = name.trim_end_matches(".pub").to_string();
        let Ok(data) = std::fs::read(path) else { continue };
        let text = String::from_utf8_lossy(&data);
        let Some((blob, comment)) = text.lines().find_map(parse_public_line) else {
            continue;
        };
        match by_name.get(&base) {
            Some(&i) => {
                if out[i].public_blob.is_none() {
                    out[i].public_blob = Some(blob.clone());
                    out[i].kind_label = describe_blob(&blob);
                }
                if out[i].comment.is_empty() {
                    out[i].comment = comment.clone();
                }
            }
            None => {
                out.push(UserKey {
                    path: path.clone(),
                    file: base,
                    kind_label: describe_blob(&blob),
                    comment,
                    has_private: false,
                    encrypted: false,
                    pub_only: true,
                    public_blob: Some(blob),
                    has_cert: false,
                });
            }
        }
    }

    // 3rd pass: *-cert.pub — only mark the certified key.
    for path in &files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("-cert.pub") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        let Some((cert, _)) = text.lines().find_map(parse_cert_line) else {
            continue;
        };
        if let Some(k) = out
            .iter_mut()
            .find(|k| k.public_blob.as_deref() == Some(cert.public_blob.as_slice()))
        {
            k.has_cert = true;
        }
    }
    out
}

/// The user's own ~/.ssh (HOME override for tests happens through
/// `scan_ssh_dir` directly).
pub fn scan_user_ssh_dir() -> Vec<UserKey> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    scan_ssh_dir(&std::path::Path::new(&home).join(".ssh"))
}

/// One certificate file found in the user's `~/.ssh` directory.
#[derive(Clone, Debug)]
pub struct UserCert {
    pub path: std::path::PathBuf,
    /// File name (the list shows it as the internal name).
    pub file: String,
    pub cert: SshCert,
    /// The comment from the certificate line.
    pub comment: String,
}

/// The certificates of `dir`: every `.pub` file whose lines carry an SSH
/// certificate (typically `*-cert.pub`). Read-only, like the key scan.
pub fn scan_ssh_certs(dir: &std::path::Path) -> Vec<UserCert> {
    let mut files: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            // fs::metadata follows symlinks (see scan_ssh_dir).
            .filter(|e| std::fs::metadata(e.path()).is_ok_and(|m| m.is_file()))
            .map(|e| e.path())
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".pub") {
            continue;
        }
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1024 * 1024) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some((cert, comment)) = text.lines().find_map(parse_cert_line) {
            let file = name.to_string();
            out.push(UserCert {
                path,
                file,
                cert,
                comment,
            });
        }
    }
    out
}

pub fn scan_user_certs() -> Vec<UserCert> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    scan_ssh_certs(&std::path::Path::new(&home).join(".ssh"))
}

// ---- writing to ~/.ssh ----

/// True when `name` is a usable key file base name (no separators, no
/// leading dot, not a traversal).
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

/// The ~/.ssh directory, created with 0700 when missing.
pub fn ensure_ssh_dir() -> Result<std::path::PathBuf, String> {
    let dir = std::env::var_os("HOME")
        .map(|h| std::path::Path::new(&h).join(".ssh"))
        .ok_or_else(|| tr!("Cannot write to ~/.ssh").to_string())?;
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("{}: {e}", tr!("Cannot write to ~/.ssh")))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0700 is what ssh expects; an existing directory with looser
        // rights is normalized on purpose.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

fn write_new_file(path: &std::path::Path, contents: &[u8], mode: u32) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "{}: {}",
            tr!("The file already exists in ~/.ssh"),
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
    }
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(mode);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("{}: {e}", tr!("Cannot write to ~/.ssh")))?;
    use std::io::Write;
    f.write_all(contents)
        .map_err(|e| format!("{}: {e}", tr!("Cannot write to ~/.ssh")))?;
    Ok(())
}

/// Write a key pair into ~/.ssh as `name` / `name.pub` (0600 / 0644).
/// A non-empty passphrase stores the private key encrypted. Existing
/// files are never overwritten.
pub fn write_key_files(
    name: &str,
    key: &PKeyRef<Private>,
    comment: &str,
    passphrase: &str,
) -> Result<std::path::PathBuf, String> {
    let dir = ensure_ssh_dir()?;
    write_key_files_in(&dir, name, key, comment, passphrase)
}

/// The directory-explicit variant of [`write_key_files`].
pub fn write_key_files_in(
    dir: &std::path::Path,
    name: &str,
    key: &PKeyRef<Private>,
    comment: &str,
    passphrase: &str,
) -> Result<std::path::PathBuf, String> {
    if !valid_file_name(name) {
        return Err(tr!("Invalid file name").into());
    }
    let private = dir.join(name);
    let public = dir.join(format!("{name}.pub"));
    // Both names must be free before anything is written, so a leftover
    // sidecar cannot leave a half-created pair behind.
    for p in [&private, &public] {
        if p.exists() {
            return Err(format!(
                "{}: {}",
                tr!("The file already exists in ~/.ssh"),
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
        }
    }
    let pem = encode_private_pem(key, comment, passphrase)?;
    write_new_file(&private, &pem, 0o600)?;
    let blob = pubkey_blob(key)?;
    write_new_file(&public, format!("{}\n", public_line(&blob, comment)).as_bytes(), 0o644)?;
    Ok(private)
}

/// Write a lone public key as `name.pub` (0644) — for public-only
/// entries exported into ~/.ssh.
pub fn write_public_file(
    name: &str,
    blob: &[u8],
    comment: &str,
) -> Result<std::path::PathBuf, String> {
    let dir = ensure_ssh_dir()?;
    write_public_file_in(&dir, name, blob, comment)
}

/// The directory-explicit variant of [`write_public_file`].
pub fn write_public_file_in(
    dir: &std::path::Path,
    name: &str,
    blob: &[u8],
    comment: &str,
) -> Result<std::path::PathBuf, String> {
    if !valid_file_name(name) {
        return Err(tr!("Invalid file name").into());
    }
    let path = dir.join(format!("{name}.pub"));
    write_new_file(
        &path,
        format!("{}\n", public_line(blob, comment)).as_bytes(),
        0o644,
    )?;
    Ok(path)
}

/// Write a certificate as `name-cert.pub` (0644).
pub fn write_cert_file(
    name: &str,
    cert: &SshCert,
    comment: &str,
) -> Result<std::path::PathBuf, String> {
    let dir = ensure_ssh_dir()?;
    write_cert_file_in(&dir, name, cert, comment)
}

/// The directory-explicit variant of [`write_cert_file`].
pub fn write_cert_file_in(
    dir: &std::path::Path,
    name: &str,
    cert: &SshCert,
    comment: &str,
) -> Result<std::path::PathBuf, String> {
    if !valid_file_name(name) {
        return Err(tr!("Invalid file name").into());
    }
    let path = dir.join(format!("{name}-cert.pub"));
    write_new_file(&path, format!("{}\n", cert_line(cert, comment)).as_bytes(), 0o644)?;
    Ok(path)
}

/// `<path>.<suffix>` — the sidecar form. Path::with_extension must not
/// be used here: it would turn "server.2024.pub" into "server.pub".
fn sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".");
    os.push(suffix);
    std::path::PathBuf::from(os)
}

/// `<path>-cert.pub`.
fn cert_sibling(path: &std::path::Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push("-cert.pub");
    std::path::PathBuf::from(os)
}

/// Delete a key from disk: the private file, the `.pub` sidecar and the
/// matching `*-cert.pub` (only when it really certifies this key).
/// Returns the removed file names.
pub fn delete_key_files(k: &UserKey) -> Result<Vec<String>, String> {
    let miss = |e: std::io::Error| e.to_string();
    let mut removed = Vec::new();
    let base = k.path.clone();
    let pub_path = sidecar(&base, "pub");
    let cert_path = cert_sibling(&base);
    std::fs::remove_file(&base).map_err(miss)?;
    removed.push(base.file_name().unwrap_or_default().to_string_lossy().into_owned());
    if pub_path.exists() {
        std::fs::remove_file(&pub_path).map_err(miss)?;
        removed.push(
            pub_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
    }
    if cert_path.exists()
        && let Some(blob) = &k.public_blob
        && let Ok(text) = std::fs::read_to_string(&cert_path)
        && let Some((cert, _)) = text.lines().find_map(parse_cert_line)
        && cert.public_blob == *blob
    {
        std::fs::remove_file(&cert_path).map_err(miss)?;
        removed.push(
            cert_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        );
    }
    Ok(removed)
}

/// Delete a certificate file.
pub fn delete_cert_file(c: &UserCert) -> Result<String, String> {
    let name = c
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    std::fs::remove_file(&c.path).map_err(|e| e.to_string())?;
    Ok(name)
}

/// Rename a key's files to a new base name (private, `.pub` and the
/// matching `-cert.pub`). Returns the new file names.
pub fn rename_key_files(k: &UserKey, new_name: &str) -> Result<Vec<String>, String> {
    if !valid_file_name(new_name) {
        return Err(tr!("Invalid file name").into());
    }
    let dir = k
        .path
        .parent()
        .ok_or_else(|| tr!("Invalid file name").to_string())?
        .to_path_buf();
    let mut renamed = Vec::new();
    // A pub-only entry is the .pub file itself: it renames to the new
    // name plus .pub, keeping the extension.
    let (sources, targets): (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) = if k.pub_only {
        (
            vec![k.path.clone()],
            vec![dir.join(format!("{new_name}.pub"))],
        )
    } else {
        (
            vec![k.path.clone(), sidecar(&k.path, "pub"), cert_sibling(&k.path)],
            vec![
                dir.join(new_name),
                dir.join(format!("{new_name}.pub")),
                dir.join(format!("{new_name}-cert.pub")),
            ],
        )
    };
    for (old, new) in sources.iter().zip(targets.iter()) {
        if !old.exists() {
            continue;
        }
        if new.exists() {
            return Err(format!(
                "{}: {}",
                tr!("The file already exists in ~/.ssh"),
                new.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
        std::fs::rename(old, new).map_err(|e| e.to_string())?;
        renamed.push(new.file_name().unwrap_or_default().to_string_lossy().into_owned());
    }
    if renamed.is_empty() {
        return Err(tr!("Invalid file name").into());
    }
    Ok(renamed)
}

/// Rename a certificate file (`<name>-cert.pub` → `<new>-cert.pub`).
pub fn rename_cert_file(c: &UserCert, new_name: &str) -> Result<String, String> {
    if !valid_file_name(new_name) {
        return Err(tr!("Invalid file name").into());
    }
    let dir = c
        .path
        .parent()
        .ok_or_else(|| tr!("Invalid file name").to_string())?
        .to_path_buf();
    let new_path = dir.join(format!("{new_name}-cert.pub"));
    if new_path.exists() {
        return Err(format!(
            "{}: {}",
            tr!("The file already exists in ~/.ssh"),
            new_path.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    std::fs::rename(&c.path, &new_path).map_err(|e| e.to_string())?;
    Ok(format!("{new_name}-cert.pub"))
}

// ---- display helpers ----

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// "05.10.2026 14:30" for a certificate validity bound, "" for forever.
pub fn format_time(secs: u64) -> String {
    if secs == FOREVER {
        return String::new();
    }
    let days = (secs / 86400) as i64;
    let tod = secs % 86400;
    let (y, m, d) = xf::civil_from_days(days);
    format!("{d:02}.{m:02}.{y:04} {:02}:{:02}", tod / 3600, (tod / 60) % 60)
}

/// Validity status for list badges and properties: valid / expired /
/// not yet valid.
/// A random 64-bit certificate serial — what ssh-keygen uses without -z.
pub fn random_serial() -> u64 {
    let mut b = [0u8; 8];
    let _ = openssl::rand::rand_bytes(&mut b);
    u64::from_be_bytes(b)
}

pub fn status_label(cert: &SshCert) -> String {
    let now = now_secs();
    if now < cert.valid_after {
        tr!("not yet valid")
    } else if cert.valid_before != FOREVER && now > cert.valid_before {
        tr!("expired")
    } else {
        tr!("valid")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(kind: NewSshKind) -> PKey<Private> {
        kind.generate().unwrap()
    }

    #[test]
    fn wire_primitives() {
        let mut b = Vec::new();
        put_string(&mut b, b"abc");
        put_u32(&mut b, 0x01020304);
        put_u64(&mut b, 0x0102030405060708);
        put_mpint(&mut b, &[0x00, 0x81, 0x00]);
        put_mpint(&mut b, &[]);
        let mut r = Reader::new(&b);
        assert_eq!(r.string().unwrap(), b"abc");
        assert_eq!(r.u32().unwrap(), 0x01020304);
        assert_eq!(r.u64().unwrap(), 0x0102030405060708);
        // 0x8100 needs the sign byte back; zero stays empty.
        assert_eq!(r.mpint().unwrap(), vec![0x00, 0x81, 0x00]);
        assert_eq!(r.mpint().unwrap(), Vec::<u8>::new()); // zero
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn keygen_blob_pkey_roundtrip() {
        for kind in [
            NewSshKind::Ed25519,
            NewSshKind::Rsa2048,
            NewSshKind::EcdsaP256,
            NewSshKind::EcdsaP384,
            NewSshKind::EcdsaP521,
        ] {
            let key = test_key(kind);
            let blob = pubkey_blob(&key).unwrap();
            assert_eq!(SshAlgo::of_blob(&blob).unwrap(), kind.algo());
            // The public line survives a parse round-trip.
            let line = public_line(&blob, "тестовый ключ");
            let (blob2, comment) = parse_public_line(&line).unwrap();
            assert_eq!(blob2, blob);
            assert_eq!(comment, "тестовый ключ");
            // Blob → PKey → blob is stable.
            let pkey = pkey_from_blob(&blob).unwrap();
            assert_eq!(pubkey_blob(&pkey).unwrap(), blob);
            assert!(!fingerprint(&blob).is_empty());
        }
    }

    #[test]
    fn private_pem_roundtrip_plain_and_encrypted() {
        for kind in [NewSshKind::Ed25519, NewSshKind::Rsa2048, NewSshKind::EcdsaP521] {
            let key = test_key(kind);
            let blob = pubkey_blob(&key).unwrap();
            for pw in ["", "пароль secret"] {
                let pem = encode_private_pem(&key, "comment", pw).unwrap();
                assert!(pem.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
                assert_eq!(pem_needs_password(&pem), !pw.is_empty());
                let parsed = parse_private_pem(&pem, pw).unwrap();
                assert_eq!(parsed.comment, "comment");
                assert_eq!(parsed.public_blob, blob);
                // Same key material: re-encoding yields the same public blob.
                assert_eq!(pubkey_blob(&parsed.pkey).unwrap(), blob);
            }
        }
        // A wrong password fails cleanly.
        let key = test_key(NewSshKind::Ed25519);
        let pem = encode_private_pem(&key, "", "right").unwrap();
        assert!(parse_private_pem(&pem, "wrong").is_err());
    }

    fn cert_params(serial: u64) -> SshCertParams {
        SshCertParams {
            serial,
            cert_type: SshCertType::User,
            key_id: "xca-rs test".into(),
            principals: vec!["user1".into(), "admin".into()],
            valid_after: now_secs() - 3600,
            valid_before: now_secs() + 86_400 * 90,
            critical: vec![
                ("force-command".into(), Some("uptime".into())),
                ("source-address".into(), Some("127.0.0.0/8".into())),
            ],
            extensions: vec![
                "permit-pty".into(),
                "permit-port-forwarding".into(),
                "permit-agent-forwarding".into(),
                "permit-X11-forwarding".into(),
                "permit-user-rc".into(),
            ],
        }
    }

    #[test]
    fn cert_build_parse_verify_roundtrip() {
        for ca_kind in [NewSshKind::Ed25519, NewSshKind::Rsa2048, NewSshKind::EcdsaP256] {
            let ca = test_key(ca_kind);
            for subject_kind in [NewSshKind::Ed25519, NewSshKind::Rsa2048, NewSshKind::EcdsaP384] {
                let subject = test_key(subject_kind);
                let subject_blob = pubkey_blob(&subject).unwrap();
                let params = cert_params(7);
                let cert = build_cert(&subject_blob, &ca, &params).unwrap();

                assert_eq!(cert.serial, 7);
                assert_eq!(cert.cert_type, SshCertType::User);
                assert_eq!(cert.key_id, "xca-rs test");
                assert_eq!(cert.principals, params.principals);
                assert_eq!(cert.public_blob, subject_blob);
                assert_eq!(cert.critical, params.critical);
                assert_eq!(cert.extensions, params.extensions);

                // Parse back: fields survive and re-serialization is byte-exact.
                let parsed = parse_cert(&cert.blob).unwrap();
                assert_eq!(parsed.blob, cert.blob);
                assert_eq!(parsed.key_id, cert.key_id);
                assert_eq!(parsed.valid_before, cert.valid_before);
                assert_eq!(parsed.critical, cert.critical);
                assert_eq!(parsed.public_blob, subject_blob);
                assert_eq!(parsed.ca_blob, pubkey_blob(&ca).unwrap());

                // Signature verifies; tampering breaks it.
                let ca_pub = pkey_from_blob(&ca_pub_blob(&ca)).unwrap();
                assert!(verify_cert(&parsed, &ca_pub).unwrap());
                let mut bad = parsed.clone();
                bad.serial += 1;
                assert!(!verify_cert(&bad, &ca_pub).unwrap());

                // Line round-trip.
                let line = cert_line(&cert, "host comment");
                let (cert2, comment) = parse_cert_line(&line).unwrap();
                assert_eq!(cert2.blob, cert.blob);
                assert_eq!(comment, "host comment");
            }
        }
    }

    fn ca_pub_blob(ca: &PKeyRef<Private>) -> Vec<u8> {
        pubkey_blob(ca).unwrap()
    }

    // ---- interop with the real ssh-keygen ----

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "xca-ssh-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ssh_keygen(args: &[&str]) -> (bool, String) {
        let out = std::process::Command::new("ssh-keygen")
            .args(args)
            .output()
            .expect("spawn ssh-keygen");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn have_ssh_keygen() -> bool {
        // `-h` exits 1 with the usage text — spawning at all is the signal.
        std::process::Command::new("ssh-keygen")
            .arg("-h")
            .output()
            .is_ok()
    }

    /// ssh-keygen reads the private keys we write (unencrypted and with a
    /// password) and derives exactly our public line.
    #[test]
    fn ssh_keygen_reads_our_private_keys() {
        if !have_ssh_keygen() {
            eprintln!("no ssh-keygen — skipping");
            return;
        }
        let dir = tmpdir("keygen-read");
        for kind in [
            NewSshKind::Ed25519,
            NewSshKind::Rsa2048,
            NewSshKind::EcdsaP256,
        ] {
            for pw in [("", None), ("secret пароль", Some("-P"))] {
                let key = test_key(kind);
                let blob = pubkey_blob(&key).unwrap();
                let path = dir.join(format!(
                    "{}-{}",
                    kind.label().replace(' ', "").to_lowercase(),
                    if pw.1.is_some() { "enc" } else { "plain" }
                ));
                std::fs::write(&path, encode_private_pem(&key, "comment", pw.0).unwrap())
                    .unwrap();
                // ssh-keygen refuses key files with permissive modes.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                let mut args = vec!["-y", "-f"];
                let p = path.to_string_lossy().into_owned();
                args.push(&p);
                if let Some(flag) = pw.1 {
                    args.push(flag);
                    args.push(pw.0);
                }
                let (ok, out) = ssh_keygen(&args);
                assert!(ok, "ssh-keygen -y failed for {}: {out}", kind.label());
                // ssh-keygen appends the key's comment; compare the key itself.
                let got: Vec<&str> = out.trim().splitn(3, ' ').collect();
                let want_line = public_line(&blob, "");
                let want: Vec<&str> = want_line.splitn(3, ' ').collect();
                assert_eq!(
                    &got[..2], &want[..2],
                    "public key mismatch for {}",
                    kind.label()
                );
            }
        }
    }

    /// ssh-keygen parses and lists the certificates we issue.
    #[test]
    fn ssh_keygen_lists_our_certificates() {
        if !have_ssh_keygen() {
            eprintln!("no ssh-keygen — skipping");
            return;
        }
        let dir = tmpdir("keygen-cert");
        let ca = test_key(NewSshKind::Ed25519);
        let subject = test_key(NewSshKind::EcdsaP256);
        let cert = build_cert(
            &pubkey_blob(&subject).unwrap(),
            &ca,
            &SshCertParams {
                serial: 4242,
                cert_type: SshCertType::Host,
                key_id: "xca-rs host".into(),
                principals: vec!["server.example.com".into()],
                valid_after: now_secs() - 60,
                valid_before: now_secs() + 86_400 * 30,
                critical: Vec::new(),
                extensions: vec!["permit-pty".into()],
            },
        )
        .unwrap();
        let path = dir.join("cert.pub");
        std::fs::write(&path, cert_line(&cert, "")).unwrap();
        let _ = std::fs::write("/tmp/ours-lists.pub", cert_line(&cert, ""));
        let p = path.to_string_lossy().into_owned();
        let (ok, out) = ssh_keygen(&["-L", "-f", &p]);
        assert!(ok, "ssh-keygen -L failed: {out}");
        assert!(out.contains("xca-rs host"), "key id missing: {out}");
        assert!(out.contains("4242"), "serial missing: {out}");
        assert!(
            out.contains("server.example.com"),
            "principal missing: {out}"
        );
    }

    /// Certificates issued by ssh-keygen parse with every field intact
    /// and re-serialize byte-exactly — the wire format is pinned from the
    /// reference implementation, including the options encoding.
    #[test]
    fn parses_ssh_keygen_certificates_byte_exact() {
        if !have_ssh_keygen() {
            eprintln!("no ssh-keygen — skipping");
            return;
        }
        let dir = tmpdir("keygen-parse");
        let ca = dir.join("ca");
        let user = dir.join("user");
        for f in [&ca, &user] {
            let fs = f.to_string_lossy().into_owned();
            let (ok, out) = ssh_keygen(&["-t", "ed25519", "-N", "", "-q", "-f", &fs]);
            assert!(ok, "keygen: {out}");
        }
        let user_pub = std::fs::read_to_string(sidecar(&user, "pub")).unwrap();
        let (user_blob, user_comment) = parse_public_line(&user_pub).unwrap();
        let ca_str = ca.to_string_lossy().into_owned();
        let user_str = user.to_string_lossy().into_owned();
        let (ok, out) = ssh_keygen(&[
            "-s", &ca_str,
            "-I", "issued-id",
            "-n", "p1,p2",
            "-V", "-1d:+30d",
            "-z", "9",
            "-O", "clear",
            "-O", "permit-pty",
            "-O", "force-command=uptime",
            &user_str,
        ]);
        assert!(ok, "signing: {out}");

        let cert_pub = dir.join("user-cert.pub");
        let line = std::fs::read_to_string(&cert_pub).unwrap();
        let (cert, comment) = parse_cert_line(&line).unwrap();
        // ssh-keygen carries the subject key's comment over to the cert.
        assert_eq!(comment, user_comment);
        assert_eq!(cert.serial, 9);
        assert_eq!(cert.cert_type, SshCertType::User);
        assert_eq!(cert.key_id, "issued-id");
        assert_eq!(cert.principals, vec!["p1".to_string(), "p2".to_string()]);
        assert_eq!(
            cert.extensions,
            vec!["permit-pty".to_string()],
            "extensions"
        );
        assert_eq!(
            cert.critical,
            vec![("force-command".into(), Some("uptime".into()))],
            "critical"
        );
        assert_eq!(cert.public_blob, user_blob, "certified key mismatch");

        // The CA key parses and the signature verifies against it.
        let ca_pem = std::fs::read(&ca).unwrap();
        let ca_key = parse_private_pem(&ca_pem, "").unwrap();
        assert_eq!(ca_key.public_blob, cert.ca_blob);
        assert!(verify_cert(&cert, &ca_key.pkey.as_ref()).unwrap());
    }

    /// The ~/.ssh scanner recognizes every key flavour: unencrypted and
    /// encrypted openssh containers (the latter still yielding their
    /// public blob from the header), classic PEM keys, .pub sidecars and
    /// standalone public lines; certificates mark their key; noise files
    /// (config, known_hosts) are ignored.
    #[test]
    fn scans_ssh_dir_with_all_key_kinds() {
        let dir = tmpdir("scan");

        // id_ed25519: unencrypted openssh + .pub + a certificate for it.
        let key = test_key(NewSshKind::Ed25519);
        let blob = pubkey_blob(&key).unwrap();
        std::fs::write(
            dir.join("id_ed25519"),
            encode_private_pem(&key, "home key", "").unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("id_ed25519.pub"),
            format!("{}\n", public_line(&blob, "home key")),
        )
        .unwrap();
        let ca = test_key(NewSshKind::Ed25519);
        let cert = build_cert(
            &blob,
            &ca,
            &SshCertParams {
                serial: 1,
                cert_type: SshCertType::User,
                key_id: "home".into(),
                principals: vec!["u".into()],
                valid_after: 0,
                valid_before: FOREVER,
                critical: Vec::new(),
                extensions: Vec::new(),
            },
        )
        .unwrap();
        std::fs::write(dir.join("id_ed25519-cert.pub"), cert_line(&cert, "")).unwrap();

        // secret_rsa: encrypted openssh, no .pub — the public blob must
        // still come from the container header.
        let enc_key = test_key(NewSshKind::Rsa2048);
        std::fs::write(
            dir.join("secret_rsa"),
            encode_private_pem(&enc_key, "", "pw123").unwrap(),
        )
        .unwrap();

        // legacy_ec: classic (PKCS#8) PEM private key.
        let pem_key = test_key(NewSshKind::EcdsaP256);
        std::fs::write(
            dir.join("legacy_ec"),
            pem_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();

        // solo.pub: a standalone public line.
        std::fs::write(
            dir.join("solo.pub"),
            format!("{}\n", public_line(&blob, "")),
        )
        .unwrap();

        // A symlinked key (secret-store style) must be listed too.
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("legacy_ec"), dir.join("linked_ec")).unwrap();

        // Noise that must not appear.
        std::fs::write(dir.join("config"), "Host *\n").unwrap();
        std::fs::write(dir.join("known_hosts"), "h ssh-ed25519 AAAA x\n").unwrap();

        let keys = scan_ssh_dir(&dir);
        let mut names: Vec<&str> = keys.iter().map(|k| k.file.as_str()).collect();
        #[cfg(unix)]
        {
            assert_eq!(
                names,
                vec!["id_ed25519", "legacy_ec", "linked_ec", "secret_rsa", "solo"],
                "entries, sorted, symlinks included"
            );
            names.truncate(0); // silence unused on non-unix below
        }
        #[cfg(not(unix))]
        assert_eq!(names, vec!["id_ed25519", "legacy_ec", "secret_rsa", "solo"]);

        let by_file = |name: &str| {
            keys.iter().find(|k| k.file == name).unwrap_or_else(|| panic!("{name} missing"))
        };
        let id = by_file("id_ed25519");
        assert!(id.has_private && !id.encrypted);
        assert_eq!(id.comment, "home key");
        assert_eq!(id.public_blob.as_deref(), Some(blob.as_slice()));
        assert_eq!(id.kind_label, "Ed25519");
        assert!(id.has_cert);

        let legacy = by_file("legacy_ec");
        assert!(legacy.has_private && !legacy.encrypted);
        assert_eq!(legacy.kind_label, "ECDSA nistp256");
        assert!(legacy.public_blob.is_some());

        #[cfg(unix)]
        {
            let linked = by_file("linked_ec");
            assert!(linked.has_private && linked.public_blob.is_some());
        }

        let enc = by_file("secret_rsa");
        assert!(enc.encrypted);
        assert_eq!(
            enc.public_blob.as_deref(),
            Some(pubkey_blob(&enc_key).unwrap().as_slice()),
            "public blob from the encrypted container header"
        );
        assert_eq!(enc.kind_label, "RSA 2048");

        let solo = by_file("solo");
        assert!(solo.pub_only && !solo.has_private);
        assert!(solo.public_blob.is_some());
    }

    /// Certificates from OpenSSH before 10 encode options in the legacy
    /// form (bare flag names, unwrapped option values): they must parse
    /// with every field intact. The signature is not verified for them —
    /// see the note on verify_cert.
    #[test]
    fn parses_legacy_option_encoding() {
        let ca = test_key(NewSshKind::Ed25519);
        let blob = pubkey_blob(&ca).unwrap();
        let cert = build_cert(
            &blob,
            &ca,
            &SshCertParams {
                serial: 5,
                cert_type: SshCertType::Host,
                key_id: "legacy-form".into(),
                principals: vec!["p1".into()],
                valid_after: 0,
                valid_before: 1000,
                critical: vec![("force-command".into(), Some("uptime".into()))],
                extensions: vec!["permit-pty".into(), "permit-user-rc".into()],
            },
        )
        .unwrap();

        // Rewrite the options sections in the legacy encoding.
        let mut legacy = Vec::new();
        let mut r = Reader::new(&cert.blob);
        put_string(&mut legacy, r.cstring().unwrap().as_bytes()); // cert algo
        put_string(&mut legacy, &r.string().unwrap()); // nonce
        put_string(&mut legacy, &r.string().unwrap()); // subject pk
        legacy.extend_from_slice(&r.take(8).unwrap()); // serial
        legacy.extend_from_slice(&r.take(4).unwrap()); // type
        put_string(&mut legacy, &r.string().unwrap()); // key id
        put_string(&mut legacy, &r.string().unwrap()); // principals
        legacy.extend_from_slice(&r.take(16).unwrap()); // validity
        let _modern_critical = r.string().unwrap();
        let mut crit = Vec::new();
        put_string(&mut crit, b"force-command"); // bare value, no wrapper
        put_string(&mut crit, b"uptime");
        put_string(&mut legacy, &crit);
        let _modern_ext = r.string().unwrap();
        let mut ext = Vec::new();
        put_string(&mut ext, b"permit-pty"); // bare flags, no empty data
        put_string(&mut ext, b"permit-user-rc");
        put_string(&mut legacy, &ext);
        while r.remaining() > 0 {
            let field = r.string().unwrap(); // reserved, ca blob, signature
            put_string(&mut legacy, &field);
        }

        let parsed = parse_cert(&legacy).unwrap();
        assert_eq!(parsed.serial, 5);
        assert_eq!(parsed.cert_type, SshCertType::Host);
        assert_eq!(parsed.key_id, "legacy-form");
        assert_eq!(parsed.principals, vec!["p1".to_string()]);
        assert_eq!(
            parsed.critical,
            vec![("force-command".into(), Some("uptime".into()))]
        );
        assert_eq!(
            parsed.extensions,
            vec!["permit-pty".to_string(), "permit-user-rc".to_string()]
        );
        assert_eq!(parsed.public_blob, blob);
    }

    /// The certificate scan lists every `*-cert.pub` file (symlinked ones
    /// too) with the parsed certificate; plain public keys and noise do
    /// not appear.
    #[test]
    fn scans_ssh_dir_certificates() {
        let dir = tmpdir("scancert");
        let ca = test_key(NewSshKind::Ed25519);
        let subject = test_key(NewSshKind::EcdsaP256);
        let subject_blob = pubkey_blob(&subject).unwrap();
        let cert = build_cert(
            &subject_blob,
            &ca,
            &SshCertParams {
                serial: 77,
                cert_type: SshCertType::Host,
                key_id: "host-cert".into(),
                principals: vec!["gw.example.com".into()],
                valid_after: 0,
                valid_before: FOREVER,
                critical: Vec::new(),
                extensions: vec!["permit-pty".into()],
            },
        )
        .unwrap();
        std::fs::write(
            dir.join("host-cert.pub"),
            format!("{}\n", cert_line(&cert, "gw comment")),
        )
        .unwrap();
        // A symlinked certificate must be listed too.
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("host-cert.pub"), dir.join("alias-cert.pub"))
            .unwrap();
        // Not certificates.
        std::fs::write(
            dir.join("plain.pub"),
            format!("{}\n", public_line(&subject_blob, "")),
        )
        .unwrap();
        std::fs::write(dir.join("known_hosts"), "h ssh-ed25519 AAAA x\n").unwrap();

        let certs = scan_ssh_certs(&dir);
        let names: Vec<&str> = certs.iter().map(|c| c.file.as_str()).collect();
        #[cfg(unix)]
        assert_eq!(names, vec!["alias-cert.pub", "host-cert.pub"]);
        #[cfg(not(unix))]
        assert_eq!(names, vec!["host-cert.pub"]);

        let by_file = |name: &str| {
            certs
                .iter()
                .find(|c| c.file == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        let c = by_file("host-cert.pub");
        assert_eq!(c.cert.key_id, "host-cert");
        assert_eq!(c.cert.serial, 77);
        assert_eq!(c.cert.cert_type, SshCertType::Host);
        assert_eq!(c.comment, "gw comment");
        assert_eq!(c.cert.public_blob, subject_blob);
    }

    /// The ~/.ssh mutation paths: writing a key pair (with permissions
    /// and no-overwrite), writing a certificate, renaming and deleting
    /// file sets — including the "certificate belongs to the key" rule.
    #[test]
    fn ssh_dir_file_operations() {
        let dir = tmpdir("files");
        let key = test_key(NewSshKind::Ed25519);
        let blob = pubkey_blob(&key).unwrap();

        // invalid names are rejected
        assert!(write_key_files_in(&dir, "../evil", &key, "", "").is_err());
        assert!(write_key_files_in(&dir, ".hidden", &key, "", "").is_err());

        let private = write_key_files_in(&dir, "deploy", &key, "deploy key", "pass123")
            .unwrap();
        assert_eq!(private, dir.join("deploy"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(dir.join("deploy.pub")).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        // The pair decrypts with the password and carries the comment.
        let pem = std::fs::read(&private).unwrap();
        assert!(pem_needs_password(&pem));
        let parsed = parse_private_pem(&pem, "pass123").unwrap();
        assert_eq!(parsed.comment, "deploy key");
        assert_eq!(parsed.public_blob, blob);
        // And never overwrites.
        assert!(write_key_files_in(&dir, "deploy", &key, "", "").is_err());

        // A certificate for the key + the scanner's view of both.
        let ca = test_key(NewSshKind::Ed25519);
        let cert = build_cert(
            &blob,
            &ca,
            &SshCertParams {
                serial: 3,
                cert_type: SshCertType::User,
                key_id: "deploy".into(),
                principals: vec!["root".into()],
                valid_after: 0,
                valid_before: 1000,
                critical: Vec::new(),
                extensions: vec!["permit-pty".into()],
            },
        )
        .unwrap();
        let cert_path = write_cert_file_in(&dir, "deploy", &cert, "").unwrap();
        assert_eq!(cert_path, dir.join("deploy-cert.pub"));
        assert!(write_cert_file_in(&dir, "deploy", &cert, "").is_err());

        let scanned = scan_ssh_dir(&dir);
        let deploy = scanned.iter().find(|k| k.file == "deploy").unwrap();
        assert!(deploy.has_cert);

        // Rename moves private + .pub + cert together, refuses collisions.
        std::fs::write(dir.join("busy"), "occupied").unwrap();
        assert!(rename_key_files(deploy, "busy").is_err());
        let renamed = rename_key_files(deploy, "prod2").unwrap();
        assert_eq!(renamed, vec!["prod2", "prod2.pub", "prod2-cert.pub"]);
        assert!(!dir.join("deploy").exists());
        assert!(dir.join("prod2").exists());

        // Delete removes the set; an unrelated certificate file stays.
        std::fs::write(dir.join("other-cert.pub"), "x\n").unwrap();
        let scanned = scan_ssh_dir(&dir);
        let prod = scanned.iter().find(|k| k.file == "prod2").unwrap();
        let removed = delete_key_files(prod).unwrap();
        assert_eq!(removed, vec!["prod2", "prod2.pub", "prod2-cert.pub"]);
        assert!(dir.join("other-cert.pub").exists());

        // Dotted names: sidecars must follow "name.pub", not
        // Path::with_extension semantics ("server.2024" -> "server.pub").
        let dotted = test_key(NewSshKind::EcdsaP256);
        write_key_files_in(&dir, "server.2024", &dotted, "", "").unwrap();
        assert!(dir.join("server.2024.pub").exists());
        let scanned = scan_ssh_dir(&dir);
        let dk = scanned.iter().find(|k| k.file == "server.2024").unwrap();
        let removed = delete_key_files(dk).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!dir.join("server.2024").exists());
        assert!(!dir.join("server.2024.pub").exists());

        // Pub-only entries rename to "<new>.pub", keeping the extension.
        let blob2 = pubkey_blob(&dotted).unwrap();
        std::fs::write(
            dir.join("solo.pub"),
            format!("{}\n", public_line(&blob2, "solo")),
        )
        .unwrap();
        let scanned = scan_ssh_dir(&dir);
        let solo = scanned.iter().find(|k| k.file == "solo").unwrap();
        assert!(solo.pub_only);
        let renamed = rename_key_files(solo, "team").unwrap();
        assert_eq!(renamed, vec!["team.pub"]);
        assert!(dir.join("team.pub").exists());
        assert!(!dir.join("solo.pub").exists());

        // A lone public key file: correct name and mode, never
        // overwritten, invalid names rejected.
        let pub_path = write_public_file_in(&dir, "external", &blob2, "ext key").unwrap();
        assert_eq!(pub_path, dir.join("external.pub"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        assert!(write_public_file_in(&dir, "external", &blob2, "").is_err());
        assert!(write_public_file_in(&dir, ".hidden", &blob2, "").is_err());
    }

    /// A bcrypt-encrypted key written by ssh-keygen itself decrypts with
    /// its password (and only with it).
    #[test]
    fn parses_ssh_keygen_encrypted_private_key() {
        if !have_ssh_keygen() {
            eprintln!("no ssh-keygen — skipping");
            return;
        }
        let dir = tmpdir("keygen-enc-import");
        let key = dir.join("key");
        let ks = key.to_string_lossy().into_owned();
        let (ok, out) = ssh_keygen(&["-t", "ed25519", "-N", "top secret", "-q", "-f", &ks]);
        assert!(ok, "keygen: {out}");
        let pem = std::fs::read(&key).unwrap();
        let parsed = parse_private_pem(&pem, "top secret").unwrap();
        let pub_line = std::fs::read_to_string(sidecar(&key, "pub")).unwrap();
        let (blob, _) = parse_public_line(&pub_line).unwrap();
        assert_eq!(parsed.public_blob, blob);
        assert!(parse_private_pem(&pem, "wrong").is_err());
    }

    /// We can sign with a CA key imported from ssh-keygen (cross-algorithm
    /// CA on top): an RSA CA signing an Ed25519 user certificate.
    #[test]
    fn signs_with_imported_ssh_keygen_ca() {
        if !have_ssh_keygen() {
            eprintln!("no ssh-keygen — skipping");
            return;
        }
        let dir = tmpdir("keygen-ca");
        let ca = dir.join("ca");
        let user = dir.join("user");
        let ca_s = ca.to_string_lossy().into_owned();
        let user_s = user.to_string_lossy().into_owned();
        let (ok, out) = ssh_keygen(&["-t", "rsa", "-b", "2048", "-N", "", "-q", "-f", &ca_s]);
        assert!(ok, "rsa ca: {out}");
        let (ok, out) = ssh_keygen(&["-t", "ed25519", "-N", "", "-q", "-f", &user_s]);
        assert!(ok, "user: {out}");

        let ca_key = parse_private_pem(&std::fs::read(&ca).unwrap(), "").unwrap();
        let user_pub = std::fs::read_to_string(sidecar(&user, "pub")).unwrap();
        let (user_blob, _) = parse_public_line(&user_pub).unwrap();

        let cert = build_cert(
            &user_blob,
            &ca_key.pkey,
            &SshCertParams {
                serial: 1,
                cert_type: SshCertType::User,
                key_id: "cross-algo".into(),
                principals: vec!["root".into()],
                valid_after: now_secs(),
                valid_before: now_secs() + 86_400 * 7,
                critical: Vec::new(),
                extensions: vec!["permit-pty".into()],
            },
        )
        .unwrap();
        assert_eq!(cert.sig_name, "rsa-sha2-512");
        let path = dir.join("cert.pub");
        std::fs::write(&path, cert_line(&cert, "")).unwrap();
        let p = path.to_string_lossy().into_owned();
        let (ok, out) = ssh_keygen(&["-L", "-f", &p]);
        assert!(ok, "ssh-keygen -L failed on our cross-algo cert: {out}");
        assert!(out.contains("cross-algo"), "{out}");
    }
}

