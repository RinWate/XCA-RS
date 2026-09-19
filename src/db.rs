//! Database layer: keys, certificates, requests and CRLs stored in the
//! database format of the **original XCA** — a plain SQLite file with the
//! `items`/`public_keys`/`certs`/… schema (see [`crate::xca_format`]).
//! Files written here are opened by the original XCA and vice versa.
//!
//! The file itself is not encrypted: private keys are stored
//! PKCS#8-encrypted (PBES2, AES-256) with the database password, whose
//! hash lives in the `pwhash` setting — exactly as the original does it.

use crate::crypto;
use crate::tr;
use crate::xca_format as xf;
use openssl::pkey::{PKey, Public};
use openssl::symm::Cipher;
use openssl::x509::{X509, X509Crl, X509Req};
use rusqlite::{params, Connection};
use std::path::Path;

/// Failure modes of [`Db::open`].
#[derive(Debug)]
pub enum OpenError {
    /// The database has a `pwhash` and no (or a wrong) password was given.
    WrongPassword,
    Other(String),
}

impl From<rusqlite::Error> for OpenError {
    fn from(e: rusqlite::Error) -> Self {
        OpenError::Other(e.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct KeyRecord {
    pub id: i64,
    pub name: String,
    pub kind: String,  // "RSA", "EC", "ED25519"
    pub size: i32,
    pub curve: String, // e.g. "P-256", empty for RSA/Ed25519
    pub pem: Vec<u8>,
}

impl KeyRecord {
    pub fn type_label(&self) -> String {
        match self.kind.as_str() {
            "EC" => format!("EC {} ({})", self.curve, self.size),
            "ED25519" => "Ed25519".to_string(),
            k => format!("{} {}", k, self.size),
        }
    }

    /// True when `pem` holds a private key (not only a public part).
    #[allow(dead_code)] // exercised by the storage tests
    pub fn is_private(&self) -> bool {
        crypto::load_private_key(&self.pem).is_ok()
    }
}

#[derive(Clone, Debug)]
pub struct CertRecord {
    pub id: i64,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// Part of the record API; consumers currently read the dates from the
    /// parsed certificate instead.
    #[allow(dead_code)]
    pub not_after: String,
    pub expires_days: i64,
    pub ca: bool,
    pub key_id: Option<i64>,
    pub issuer_id: Option<i64>,
    pub pem: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ReqRecord {
    pub id: i64,
    pub name: String,
    pub subject: String,
    pub key_id: Option<i64>,
    pub pem: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CrlRecord {
    pub id: i64,
    pub name: String,
    pub ca_id: i64,
    pub issuer: String,
    pub next_update: String,
    pub entries: i64,
    pub pem: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RevokedRecord {
    pub ca_id: i64,
    pub serial: String,
    pub revoked_at: String,
    #[allow(dead_code)] // part of the record API
    pub cert_id: Option<i64>,
    pub reason: String,
}

pub struct Db {
    conn: Connection,
    /// The database password ("" when none): encrypts/decrypts the private
    /// keys stored in the file.
    password: String,
    /// True when the file carries a `pwhash` (password-protected).
    pub has_password: bool,
    /// Decrypted private-key PEM by key id. PBKDF2 decryption is not free
    /// and every refresh lists all keys — cache the result for the
    /// lifetime of the connection.
    key_cache: std::cell::RefCell<std::collections::HashMap<i64, Vec<u8>>>,
}

fn s<T: std::fmt::Display>(e: T) -> String {
    e.to_string()
}

/// AES-256-CBC for the PKCS#8 (PBES2) encryption of private keys — the
/// same cipher the original XCA uses.
fn aes256_cbc() -> Cipher {
    Cipher::aes_256_cbc()
}

impl Db {
    /// Open (or create) an XCA-format database.
    ///
    /// Existing files of the retired xca-rs-specific format are migrated
    /// automatically (the original is kept as `*.old.bak`).
    pub fn open(path: &Path, password: Option<&str>) -> Result<Db, OpenError> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let fresh = std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true);
        if !fresh {
            let magic_ok = std::fs::File::open(path)
                .and_then(|mut f| {
                    use std::io::Read;
                    let mut buf = [0u8; 16];
                    f.read_exact(&mut buf)
                        .map(|_| buf == *b"SQLite format 3\0")
                })
                .unwrap_or(false);
            if !magic_ok {
                // Not plain SQLite: either a database of the old xca-rs
                // format encrypted with SQLCipher, or not a database at
                // all. Both surface as WrongPassword, so the unlock
                // dialog lets the user retry or pick another file — a
                // wrong password must never terminate the application.
                return migrate_old(path, password);
            }
            let conn = Connection::open(path)?;
            let old = is_old_schema(&conn)?;
            drop(conn);
            if old {
                return migrate_old(path, password);
            }
        }

        let conn = Connection::open(path)?;
        // The original XCA never enables SQLite foreign-key enforcement, so
        // neither do we: real databases migrated through old XCA versions
        // keep legacy tables (e.g. "revoked") whose FK definitions do not
        // match the v8 schema, and with the pragma on every DELETE FROM
        // certs fails with "foreign key mismatch". Referential cleanup is
        // done in code, like in XCA itself.
        conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
        if !fresh && !is_xca_schema(&conn)? {
            return Err(OpenError::Other(tr!("Not an XCA database")));
        }
        conn.execute_batch(xf::SCHEMA)?;

        let pwhash: Option<String> = conn
            .query_row("SELECT value FROM settings WHERE key_='pwhash'", [], |r| r.get(0))
            .ok();
        let mut has_password = pwhash.as_deref().map(|h| !h.is_empty()).unwrap_or(false);
        let mut pwhash = pwhash.unwrap_or_default();
        if fresh && !has_password {
            // Freshly created: store the hash of the chosen password.
            if let Some(pw) = password.filter(|p| !p.is_empty()) {
                pwhash = xf::make_pwhash(pw)
                    .ok_or_else(|| OpenError::Other("password hashing failed".into()))?;
                conn.execute(
                    "INSERT OR REPLACE INTO settings(key_, value) VALUES ('pwhash', ?1)",
                    params![pwhash],
                )?;
                has_password = true;
            }
        }
        if has_password {
            match password {
                Some(pw) if xf::check_pwhash(&pwhash, pw) => {}
                _ => return Err(OpenError::WrongPassword),
            }
        }
        Ok(Db {
            conn,
            password: password.unwrap_or("").to_string(),
            has_password,
            key_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
        })
    }

    /// Set or change the database password: re-encrypts every private key
    /// protected by the database password and updates `pwhash`. An empty
    /// password removes the protection.
    pub fn change_password(&mut self, new_password: &str) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare("SELECT item, private FROM private_keys WHERE ownPass = ?1")
            .map_err(s)?;
        let rows: Vec<(i64, String)> = stmt
            .query_map(params![xf::PT_COMMON], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(s)?
            .collect::<Result<_, _>>()
            .map_err(s)?;
        drop(stmt);
        let mut updates = Vec::new();
        for (item, b64) in rows {
            let der = xf::b64_decode(&b64).ok_or("corrupt private key blob")?;
            let key = PKey::private_key_from_pkcs8_passphrase(&der, self.password.as_bytes())
                .map_err(|e| format!("{}: {e}", tr!("Cannot decrypt the private key")))?;
            let enc = key
                .private_key_to_pkcs8_passphrase(aes256_cbc(), new_password.as_bytes())
                .map_err(s)?;
            updates.push((item, xf::b64_encode(&enc)));
        }
        let tx = self.conn.transaction().map_err(s)?;
        for (item, b64) in updates {
            tx.execute("UPDATE private_keys SET private=?1 WHERE item=?2", params![b64, item])
                .map_err(s)?;
        }
        if new_password.is_empty() {
            tx.execute("DELETE FROM settings WHERE key_='pwhash'", []).map_err(s)?;
        } else {
            let h = xf::make_pwhash(new_password).ok_or("password hashing failed")?;
            tx.execute(
                "INSERT OR REPLACE INTO settings(key_, value) VALUES ('pwhash', ?1)",
                params![h],
            )
            .map_err(s)?;
        }
        tx.commit().map_err(s)?;
        self.password = new_password.to_string();
        self.has_password = !new_password.is_empty();
        self.key_cache.borrow_mut().clear();
        Ok(())
    }

    fn insert_item(&self, name: &str, itype: i64, source: i64) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO items(name, type, source, date) VALUES (?1, ?2, ?3, ?4)",
                params![name, itype, source, xf::now_plain()],
            )
            .map_err(s)?;
        Ok(self.conn.last_insert_rowid())
    }

    // ---- settings ----

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM settings WHERE key_ = ?1", params![key], |r| {
                r.get(0)
            })
            .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO settings(key_, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(s)?;
        Ok(())
    }

    // ---- keys ----

    /// Store a key. `pem` may be a private or a public key; private keys
    /// are PBES2-encrypted with the database password, exactly as the
    /// original XCA stores them.
    pub fn insert_key(&self, name: &str, pem: &[u8]) -> Result<i64, String> {
        let private = crypto::load_private_key(pem).ok();
        let public = match &private {
            Some(k) => crypto::public_of(k.as_ref()).map_err(s)?,
            None => PKey::public_key_from_pem(pem).map_err(|e| {
                format!("{}: {e}", tr!("Neither a private nor a public key"))
            })?,
        };
        let (kind, bits, _curve) = crypto::key_info(public.as_ref());
        let spki = public.public_key_to_der().map_err(s)?;
        let id = self.insert_item(name, xf::T_KEY, xf::SRC_GENERATED)?;
        self.conn
            .execute(
                "INSERT INTO public_keys(item, type, hash, len, \"public\") VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id,
                    key_type_column(&kind),
                    xf::sha1_31(&spki),
                    bits,
                    xf::b64_encode(&spki),
                ],
            )
            .map_err(s)?;
        if let Some(key) = private {
            let plain = key.private_key_to_pem_pkcs8().map_err(s)?;
            let enc = key
                .private_key_to_pkcs8_passphrase(aes256_cbc(), self.password.as_bytes())
                .map_err(s)?;
            self.conn
                .execute(
                    "INSERT INTO private_keys(item, ownPass, private) VALUES (?1, ?2, ?3)",
                    params![id, xf::PT_COMMON, xf::b64_encode(&enc)],
                )
                .map_err(s)?;
            self.key_cache.borrow_mut().insert(id, plain);
        }
        Ok(id)
    }

    fn key_from_row(&self, id: i64, name: String, public_b64: String, private_b64: Option<String>, own_pass: Option<i64>) -> KeyRecord {
        let password = self.password.clone();
        let cached = private_b64.is_some().then(|| self.key_cache.borrow().get(&id).cloned()).flatten();
        let der = xf::b64_decode(&public_b64).unwrap_or_default();
        let public = PKey::public_key_from_der(&der).ok();
        let (kind, size, curve) = public
            .as_ref()
            .map(|p| crypto::key_info(p.as_ref()))
            .unwrap_or_default();
        // The private part: ptCommon keys decrypt with the database
        // password, ptBogus keys with the literal "Bogus".
        let pw: Option<&str> = match own_pass {
            Some(xf::PT_COMMON) => Some(password.as_str()),
            Some(xf::PT_BOGUS) => Some("Bogus"),
            _ => None,
        };
        let pem = cached
            .or_else(|| {
                let pem = private_b64
                    .as_deref()
                    .and_then(xf::b64_decode)
                    .zip(pw)
                    .and_then(|(enc, pw)| {
                        PKey::private_key_from_pkcs8_passphrase(&enc, pw.as_bytes()).ok()
                    })
                    .and_then(|k| k.private_key_to_pem_pkcs8().ok())
                    .or_else(|| public.as_ref().and_then(|p| p.public_key_to_pem().ok()))?;
                self.key_cache.borrow_mut().insert(id, pem.clone());
                Some(pem)
            })
            .unwrap_or_default();
        KeyRecord {
            id,
            name,
            kind,
            size,
            curve,
            pem,
        }
    }

    fn key_query<P: rusqlite::Params>(&self, tail: &str, p: P) -> Result<Vec<KeyRecord>, String> {
        let sql = format!(
            "SELECT i.id, i.name, pk.\"public\", ik.private, ik.ownPass
             FROM items i
             JOIN public_keys pk ON pk.item = i.id
             LEFT JOIN private_keys ik ON ik.item = i.id
             WHERE i.type = {TY} AND i.del = 0 {tail}",
            TY = xf::T_KEY,
        );
        let mut stmt = self.conn.prepare(&sql).map_err(s)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(s)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(s)?
            .into_iter()
            .map(|(id, name, pubb, privb, ownp)| {
                Ok::<_, String>(self.key_from_row(id, name, pubb, privb, ownp))
            })
            .collect()
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRecord>, String> {
        self.key_query("ORDER BY i.name, i.id", [])
    }

    pub fn get_key(&self, id: i64) -> Result<Option<KeyRecord>, String> {
        Ok(self.key_query("AND i.id = ?1", params![id])?.into_iter().next())
    }

    pub fn delete_key(&self, id: i64) -> Result<(), String> {
        for sql in [
            "DELETE FROM private_keys WHERE item=?1",
            "DELETE FROM tokens WHERE item=?1",
            "DELETE FROM token_mechanism WHERE item=?1",
            "DELETE FROM public_keys WHERE item=?1",
            "UPDATE x509super SET pkey=NULL WHERE pkey=?1",
            "DELETE FROM items WHERE id=?1",
        ] {
            self.conn.execute(sql, params![id]).map_err(s)?;
        }
        self.key_cache.borrow_mut().remove(&id);
        Ok(())
    }

    pub fn key_exists(&self, pem: &[u8]) -> Result<bool, String> {
        let Ok(spki) = public_spki_of(pem) else {
            return Ok(false);
        };
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM public_keys WHERE \"public\" = ?1",
            params![xf::b64_encode(&spki)],
            |r| r.get(0),
        ).map_err(s)?;
        Ok(n > 0)
    }

    // ---- certificates ----

    pub fn insert_cert(&self, rec: &CertRecord) -> Result<i64, String> {
        let cert = X509::from_pem(&rec.pem).map_err(|e| format!("invalid certificate: {e}"))?;
        let der = cert.to_der().map_err(s)?;
        let sum = crypto::cert_summary(cert.as_ref());
        let key_hash = cert
            .public_key()
            .ok()
            .and_then(|p| p.public_key_to_der().ok())
            .map(|d| xf::sha1_31(&d))
            .unwrap_or(0);
        let id = self.insert_item(&rec.name, xf::T_CERT, xf::SRC_IMPORTED)?;
        self.conn
            .execute(
                "INSERT INTO certs(item, hash, iss_hash, serial, issuer, ca, cert)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    xf::sha1_31(&der),
                    xf::name_hash_31(cert.issuer_name()),
                    sum.serial,
                    rec.issuer_id,
                    sum.is_ca as i64,
                    xf::b64_encode(&der),
                ],
            )
            .map_err(s)?;
        self.conn
            .execute(
                "INSERT INTO x509super(item, subj_hash, pkey, key_hash) VALUES (?1, ?2, ?3, ?4)",
                params![
                    id,
                    xf::name_hash_31(cert.subject_name()),
                    rec.key_id,
                    key_hash,
                ],
            )
            .map_err(s)?;
        if sum.is_ca {
            // The authority row carries the per-CA CRL counter, exactly
            // as the original XCA stores it.
            self.conn
                .execute(
                    "INSERT INTO authority(item, crlNo) VALUES (?1, 0)",
                    params![id],
                )
                .map_err(s)?;
        }
        Ok(id)
    }

    /// Next CRL number for a CA (monotonically increasing, RFC 5280) and
    /// the update that reserves it.
    pub fn next_crl_number(&self, ca_id: i64) -> Result<i64, String> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT crlNo FROM authority WHERE item = ?1",
                params![ca_id],
                |r| r.get(0),
            )
            .unwrap_or(0)
            + 1;
        let changed = self
            .conn
            .execute(
                "UPDATE authority SET crlNo = ?1 WHERE item = ?2",
                params![n, ca_id],
            )
            .map_err(s)?;
        if changed == 0 {
            self.conn
                .execute(
                    "INSERT INTO authority(item, crlNo) VALUES (?1, ?2)",
                    params![ca_id, n],
                )
                .map_err(s)?;
        }
        Ok(n)
    }

    fn cert_query<P: rusqlite::Params>(&self, tail: &str, p: P) -> Result<Vec<CertRecord>, String> {
        // c.ca comes straight from the database — recomputing CA-ness via
        // OpenSSL dumps on every refresh was both slow and fragile.
        let sql = format!(
            "SELECT i.id, i.name, c.cert, c.issuer, x.pkey, c.ca
             FROM items i
             JOIN certs c ON c.item = i.id
             LEFT JOIN x509super x ON x.item = i.id
             WHERE i.type = {TY} AND i.del = 0 {tail}",
            TY = xf::T_CERT,
        );
        let mut stmt = self.conn.prepare(&sql).map_err(s)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .map_err(s)?;
        let mut out = Vec::new();
        for row in rows.collect::<Result<Vec<_>, _>>().map_err(s)? {
            let (id, name, cert_b64, issuer_id, key_id, ca) = row;
            let Some(der) = xf::b64_decode(&cert_b64) else { continue };
            let Ok(cert) = X509::from_der(&der) else { continue };
            let sum = crypto::cert_summary(cert.as_ref());
            out.push(CertRecord {
                id,
                name,
                subject: sum.subject,
                issuer: sum.issuer,
                serial: sum.serial,
                not_after: sum.not_after,
                expires_days: sum.expires_days,
                ca: ca != 0,
                key_id,
                issuer_id,
                pem: cert.to_pem().unwrap_or_default(),
            });
        }
        Ok(out)
    }

    pub fn list_certs(&self) -> Result<Vec<CertRecord>, String> {
        self.cert_query("ORDER BY i.name, i.id", [])
    }

    pub fn get_cert(&self, id: i64) -> Result<Option<CertRecord>, String> {
        Ok(self.cert_query("AND i.id = ?1", params![id])?.into_iter().next())
    }

    pub fn list_ca_certs(&self) -> Result<Vec<CertRecord>, String> {
        self.cert_query("AND c.ca != 0 ORDER BY i.name, i.id", [])
    }

    /// Update the key/issuer links of a certificate (ids are `items.id`).
    pub fn set_cert_refs(&self, id: i64, key_id: Option<i64>, issuer_id: Option<i64>) -> Result<(), String> {
        self.conn
            .execute("UPDATE x509super SET pkey=?1 WHERE item=?2", params![key_id, id])
            .map_err(s)?;
        self.conn
            .execute("UPDATE certs SET issuer=?1 WHERE item=?2", params![issuer_id, id])
            .map_err(s)?;
        Ok(())
    }

    pub fn delete_cert(&self, id: i64) -> Result<(), String> {
        for sql in [
            "DELETE FROM certs WHERE item=?1",
            "DELETE FROM x509super WHERE item=?1",
            "DELETE FROM authority WHERE item=?1",
            "DELETE FROM revocations WHERE caId=?1",
            "UPDATE certs SET issuer=NULL WHERE issuer=?1",
            "UPDATE crls SET issuer=NULL WHERE issuer=?1",
            "DELETE FROM items WHERE id=?1",
        ] {
            self.conn.execute(sql, params![id]).map_err(s)?;
        }
        Ok(())
    }

    pub fn cert_exists(&self, pem: &[u8]) -> Result<bool, String> {
        let Ok(cert) = X509::from_pem(pem) else {
            return Ok(false);
        };
        let der = cert.to_der().unwrap_or_default();
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM certs WHERE cert = ?1",
            params![xf::b64_encode(&der)],
            |r| r.get(0),
        ).map_err(s)?;
        Ok(n > 0)
    }

    /// Chain from the given certificate up to its root (self-signed ancestor).
    pub fn cert_chain(&self, id: i64) -> Result<Vec<CertRecord>, String> {
        let mut chain = Vec::new();
        let mut current = id;
        let mut guard = 0;
        while guard < 100 {
            guard += 1;
            match self.get_cert(current)? {
                Some(c) => {
                    let next = c.issuer_id;
                    chain.push(c);
                    match next {
                        Some(n) if n != current => current = n,
                        _ => break,
                    }
                }
                None => break,
            }
        }
        Ok(chain)
    }

    // ---- requests ----

    pub fn insert_req(&self, rec: &ReqRecord) -> Result<i64, String> {
        let req = X509Req::from_pem(&rec.pem).map_err(|e| format!("invalid request: {e}"))?;
        let der = req.to_der().map_err(s)?;
        let key_hash = req
            .public_key()
            .ok()
            .and_then(|p| p.public_key_to_der().ok())
            .map(|d| xf::sha1_31(&d))
            .unwrap_or(0);
        let id = self.insert_item(&rec.name, xf::T_REQ, xf::SRC_IMPORTED)?;
        self.conn
            .execute(
                "INSERT INTO requests(item, hash, signed, request) VALUES (?1, ?2, 0, ?3)",
                params![id, xf::sha1_31(&der), xf::b64_encode(&der)],
            )
            .map_err(s)?;
        self.conn
            .execute(
                "INSERT INTO x509super(item, subj_hash, pkey, key_hash) VALUES (?1, ?2, ?3, ?4)",
                params![
                    id,
                    xf::name_hash_31(req.subject_name()),
                    rec.key_id,
                    key_hash,
                ],
            )
            .map_err(s)?;
        Ok(id)
    }

    fn req_query<P: rusqlite::Params>(&self, tail: &str, p: P) -> Result<Vec<ReqRecord>, String> {
        let sql = format!(
            "SELECT i.id, i.name, r.request, x.pkey
             FROM items i
             JOIN requests r ON r.item = i.id
             LEFT JOIN x509super x ON x.item = i.id
             WHERE i.type = {TY} AND i.del = 0 {tail}",
            TY = xf::T_REQ,
        );
        let mut stmt = self.conn.prepare(&sql).map_err(s)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(s)?;
        let mut out = Vec::new();
        for row in rows.collect::<Result<Vec<_>, _>>().map_err(s)? {
            let (id, name, req_b64, key_id) = row;
            let Some(der) = xf::b64_decode(&req_b64) else { continue };
            let Ok(req) = X509Req::from_der(&der) else { continue };
            out.push(ReqRecord {
                id,
                name,
                subject: crypto::name_to_string(req.subject_name()),
                key_id,
                pem: req.to_pem().unwrap_or_default(),
            });
        }
        Ok(out)
    }

    pub fn list_reqs(&self) -> Result<Vec<ReqRecord>, String> {
        self.req_query("ORDER BY i.name, i.id", [])
    }

    pub fn get_req(&self, id: i64) -> Result<Option<ReqRecord>, String> {
        Ok(self.req_query("AND i.id = ?1", params![id])?.into_iter().next())
    }

    pub fn delete_req(&self, id: i64) -> Result<(), String> {
        for sql in [
            "DELETE FROM requests WHERE item=?1",
            "DELETE FROM x509super WHERE item=?1",
            "DELETE FROM items WHERE id=?1",
        ] {
            self.conn.execute(sql, params![id]).map_err(s)?;
        }
        Ok(())
    }

    pub fn req_exists(&self, pem: &[u8]) -> Result<bool, String> {
        let Ok(req) = X509Req::from_pem(pem) else {
            return Ok(false);
        };
        let der = req.to_der().unwrap_or_default();
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM requests WHERE request = ?1",
            params![xf::b64_encode(&der)],
            |r| r.get(0),
        ).map_err(s)?;
        Ok(n > 0)
    }

    // ---- CRLs ----

    pub fn insert_crl(&self, rec: &CrlRecord) -> Result<i64, String> {
        let crl = X509Crl::from_pem(&rec.pem).map_err(|e| format!("invalid CRL: {e}"))?;
        let der = crl.to_der().map_err(s)?;
        let id = self.insert_item(&rec.name, xf::T_CRL, xf::SRC_GENERATED)?;
        self.conn
            .execute(
                "INSERT INTO crls(item, hash, num, iss_hash, issuer, crl)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    xf::sha1_31(&der),
                    xf::crl_number(crl.as_ref()),
                    xf::name_hash_31(crl.issuer_name()),
                    rec.ca_id,
                    xf::b64_encode(&der),
                ],
            )
            .map_err(s)?;
        Ok(id)
    }

    fn crl_query<P: rusqlite::Params>(&self, tail: &str, p: P) -> Result<Vec<CrlRecord>, String> {
        let sql = format!(
            "SELECT i.id, i.name, l.crl, l.issuer
             FROM items i
             JOIN crls l ON l.item = i.id
             WHERE i.type = {TY} AND i.del = 0 {tail}",
            TY = xf::T_CRL,
        );
        let mut stmt = self.conn.prepare(&sql).map_err(s)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(s)?;
        let mut out = Vec::new();
        for row in rows.collect::<Result<Vec<_>, _>>().map_err(s)? {
            let (id, name, crl_b64, ca_id) = row;
            let Some(der) = xf::b64_decode(&crl_b64) else { continue };
            let Ok(crl) = X509Crl::from_der(&der) else { continue };
            out.push(CrlRecord {
                id,
                name,
                ca_id: ca_id.unwrap_or(0),
                issuer: crypto::name_to_string(crl.issuer_name()),
                next_update: crl.next_update().map(|t| t.to_string()).unwrap_or_default(),
                entries: crl.get_revoked().map(|r| r.len() as i64).unwrap_or(0),
                pem: crl.to_pem().unwrap_or_default(),
            });
        }
        Ok(out)
    }

    pub fn list_crls(&self) -> Result<Vec<CrlRecord>, String> {
        self.crl_query("ORDER BY i.name, i.id", [])
    }

    pub fn get_crl(&self, id: i64) -> Result<Option<CrlRecord>, String> {
        Ok(self.crl_query("AND i.id = ?1", params![id])?.into_iter().next())
    }

    pub fn delete_crl(&self, id: i64) -> Result<(), String> {
        for sql in [
            "DELETE FROM crls WHERE item=?1",
            "DELETE FROM items WHERE id=?1",
        ] {
            self.conn.execute(sql, params![id]).map_err(s)?;
        }
        Ok(())
    }

    // ---- revocation ----

    pub fn insert_revoked(&self, rec: &RevokedRecord) -> Result<(), String> {
        // The XCA schema has no UNIQUE constraint on revocations —
        // duplicates are filtered by the WHERE NOT EXISTS guard.
        self.conn
            .execute(
                "INSERT INTO revocations(caId, serial, date, invaldate, crlNo, reasonBit)
                 SELECT ?1, ?2, ?3, NULL, NULL, ?4
                 WHERE NOT EXISTS (SELECT 1 FROM revocations WHERE caId = ?1 AND serial = ?2)",
                params![
                    rec.ca_id,
                    rec.serial,
                    if rec.revoked_at.is_empty() { xf::now_plain() } else { rec.revoked_at.clone() },
                    xf::reason_bit(&rec.reason),
                ],
            )
            .map_err(s)?;
        Ok(())
    }

    pub fn list_revoked(&self, ca_id: i64) -> Result<Vec<RevokedRecord>, String> {
        let mut stmt = self.conn
            .prepare(
                "SELECT r.serial, r.date, r.reasonBit,
                        (SELECT c.item FROM certs c JOIN items i ON i.id = c.item
                          WHERE i.type = 3 AND i.del = 0 AND c.serial = r.serial
                          ORDER BY c.item LIMIT 1)
                 FROM revocations r WHERE r.caId = ?1 ORDER BY r.serial",
            )
            .map_err(s)?;
        let rows = stmt
            .query_map(params![ca_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(s)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(s)?
            .into_iter()
            .map(|(serial, date, bit, cert_id)| {
                Ok(RevokedRecord {
                    ca_id,
                    serial,
                    revoked_at: date.unwrap_or_default(),
                    cert_id,
                    reason: xf::reason_name(bit.unwrap_or(0)).to_string(),
                })
            })
            .collect()
    }

    /// Revoked serials grouped by the issuing CA — the status badges must
    /// match the pair (CA, serial): serials alone collide across CAs.
    pub fn revoked_serials_by_ca(
        &self,
    ) -> Result<std::collections::HashMap<i64, std::collections::HashSet<String>>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT caId, serial FROM revocations")
            .map_err(s)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map_err(s)?;
        let mut map: std::collections::HashMap<i64, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for (ca, serial) in rows.collect::<Result<Vec<_>, _>>().map_err(s)? {
            map.entry(ca).or_default().insert(serial);
        }
        Ok(map)
    }
}

/// The `public_keys.type` column: a short key-type tag as the original
/// XCA writes it (RSA / EC / ED / DSA).
fn key_type_column(kind: &str) -> String {
    match kind {
        "ED25519" | "ED448" | "X25519" => "ED".into(),
        k => k.chars().take(4).collect(),
    }
}

/// SPKI DER of whatever key a PEM holds (private or public).
fn public_spki_of(pem: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(k) = crypto::load_private_key(pem) {
        return crypto::public_of(k.as_ref()).and_then(|p| p.public_key_to_der().map_err(|e| e.to_string()));
    }
    PKey::<Public>::public_key_from_pem(pem)
        .and_then(|p| p.public_key_to_der())
        .map_err(|e| format!("not a key: {e}"))
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        params![name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// The schema of the original XCA (`items`, `public_keys`, `certs`).
fn is_xca_schema(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(table_exists(conn, "items")?
        && table_exists(conn, "public_keys")?
        && table_exists(conn, "certs")?)
}

/// The retired xca-rs-specific schema (`keys` table, no `items`).
fn is_old_schema(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(table_exists(conn, "keys")? && !table_exists(conn, "items")?)
}

/// One-time migration of the old xca-rs-specific format into the XCA
/// format. The original file is preserved next to the new one as
/// `<name>.old.bak`.
fn migrate_old(path: &Path, password: Option<&str>) -> Result<Db, OpenError> {
    fn qmap<T, F>(conn: &Connection, sql: &str, f: F) -> rusqlite::Result<Vec<T>>
    where
        F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], f)?;
        rows.collect()
    }

    let conn = Connection::open(path)?;
    if let Some(pw) = password {
        let esc = pw.replace('\'', "''");
        conn.execute_batch(&format!("PRAGMA key = '{esc}';"))?;
    }
    let probe = conn.query_row("SELECT COUNT(*) FROM keys", [], |r| r.get::<_, i64>(0));
    if probe.is_err() {
        // A wrong password reads exactly like a foreign file here;
        // either way ask (again) — never exit the application.
        return Err(OpenError::WrongPassword);
    }

    // Read everything out of the old schema.
    #[derive(Debug)]
    struct OldKey(i64, String, Vec<u8>);
    #[derive(Debug)]
    struct OldCert(i64, String, Vec<u8>, Option<i64>, Option<i64>);
    #[derive(Debug)]
    struct OldReq(String, Vec<u8>, Option<i64>);
    #[derive(Debug)]
    struct OldCrl(String, Vec<u8>, i64);
    #[derive(Debug)]
    struct OldRev(i64, String, String, String);

    let keys: Vec<OldKey> = qmap(&conn, "SELECT id, name, pem FROM keys", |r| {
        Ok(OldKey(r.get(0)?, r.get(1)?, r.get(2)?))
    })?;
    let certs: Vec<OldCert> = qmap(
        &conn,
        "SELECT id, name, pem, key_id, issuer_id FROM certs",
        |r| Ok(OldCert(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    let reqs: Vec<OldReq> = qmap(
        &conn,
        "SELECT name, pem, key_id FROM reqs",
        |r| Ok(OldReq(r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let crls: Vec<OldCrl> = qmap(
        &conn,
        "SELECT name, pem, ca_id FROM crls",
        |r| Ok(OldCrl(r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let revoked: Vec<OldRev> = qmap(
        &conn,
        "SELECT ca_id, serial, revoked_at, reason FROM revoked",
        |r| Ok(OldRev(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let settings: Vec<(String, String)> = qmap(
        &conn,
        "SELECT k, v FROM settings WHERE k NOT IN ('pwhash')",
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    drop(conn);

    let bak = {
        let mut os = path.as_os_str().to_os_string();
        os.push(".old.bak");
        std::path::PathBuf::from(os)
    };
    std::fs::rename(path, &bak).map_err(|e| OpenError::Other(format!("migration: {e}")))?;
    let db = Db::open(path, password)?;

    let mut key_ids = std::collections::HashMap::new();
    for OldKey(old, name, pem) in keys {
        if let Ok(id) = db.insert_key(&name, &pem) {
            key_ids.insert(old, id);
        }
    }
    let mut cert_ids = std::collections::HashMap::new();
    let mut links = Vec::new();
    for OldCert(old, name, pem, key_id, issuer_id) in certs {
        let rec = CertRecord {
            id: 0,
            name,
            subject: String::new(),
            issuer: String::new(),
            serial: String::new(),
            not_after: String::new(),
            expires_days: 0,
            ca: false,
            key_id: key_id.and_then(|k| key_ids.get(&k).copied()),
            issuer_id: None,
            pem,
        };
        if let Ok(id) = db.insert_cert(&rec) {
            cert_ids.insert(old, id);
            links.push((id, rec.key_id, issuer_id));
        }
    }
    // Issuer links only make sense once every certificate exists — a cert
    // inserted before its issuer would otherwise lose the reference.
    for (id, key_id, issuer_id) in links {
        let _ = db.set_cert_refs(id, key_id, issuer_id.and_then(|i| cert_ids.get(&i).copied()));
    }
    for OldReq(name, pem, key_id) in reqs {
        let rec = ReqRecord {
            id: 0,
            name,
            subject: String::new(),
            key_id: key_id.and_then(|k| key_ids.get(&k).copied()),
            pem,
        };
        let _ = db.insert_req(&rec);
    }
    for OldCrl(name, pem, ca_id) in crls {
        let Some(ca) = cert_ids.get(&ca_id).copied() else { continue };
        let rec = CrlRecord {
            id: 0,
            name,
            ca_id: ca,
            issuer: String::new(),
            next_update: String::new(),
            entries: 0,
            pem,
        };
        let _ = db.insert_crl(&rec);
    }
    for OldRev(ca_id, serial, revoked_at, reason) in revoked {
        let Some(ca) = cert_ids.get(&ca_id).copied() else { continue };
        let _ = db.insert_revoked(&RevokedRecord {
            ca_id: ca,
            serial,
            revoked_at,
            cert_id: None,
            reason,
        });
    }
    for (k, v) in settings {
        let _ = db.set_setting(&k, &v);
    }
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, CertParams, NewKeyKind, SubjectData};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("xca-rs-db-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ca_cert() -> (PKey<openssl::pkey::Private>, X509, Vec<u8>) {
        let key = crypto::generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = SubjectData {
            cn: "Test Root".into(),
            ..Default::default()
        }
        .build_name()
        .unwrap();
        let cert = crypto::build_certificate(
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
        let pem = cert.to_pem().unwrap();
        (key, cert, pem)
    }

    fn ca_record(pem: Vec<u8>) -> CertRecord {
        CertRecord {
            id: 0,
            name: "Test Root".into(),
            subject: "CN=Test Root".into(),
            issuer: "CN=Test Root".into(),
            serial: "01".into(),
            not_after: "2027".into(),
            expires_days: 300,
            ca: true,
            key_id: None,
            issuer_id: None,
            pem,
        }
    }

    #[test]
    fn password_protects_private_keys_only() {
        let dir = tmpdir("pw");
        let path = dir.join("pw.xdb");
        let key = crypto::generate_key(NewKeyKind::Rsa2048).unwrap();
        let key_pem = key.private_key_to_pem_pkcs8().unwrap();

        {
            let db = Db::open(&path, Some("secret")).unwrap();
            assert!(db.has_password);
            db.insert_key("k", &key_pem).unwrap();
        }
        // Missing and wrong passwords are rejected (pwhash check)…
        assert!(matches!(Db::open(&path, None), Err(OpenError::WrongPassword)));
        assert!(matches!(Db::open(&path, Some("wrong")), Err(OpenError::WrongPassword)));
        // …and the file itself stays a plain SQLite XCA database.
        assert!(is_xca_schema(&Connection::open(&path).unwrap()).unwrap());

        let mut db = Db::open(&path, Some("secret")).unwrap();
        let keys = db.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].is_private());

        // Changing the password re-encrypts the private key in place.
        db.change_password("new-secret").unwrap();
        drop(db);
        assert!(matches!(Db::open(&path, Some("secret")), Err(OpenError::WrongPassword)));
        let db = Db::open(&path, Some("new-secret")).unwrap();
        let keys = db.list_keys().unwrap();
        assert!(keys[0].is_private());
        // …and it decrypts to the same key.
        let restored = crypto::load_private_key(&keys[0].pem).unwrap();
        assert!(crypto::same_public_key(
            crypto::public_of(restored.as_ref()).unwrap().as_ref(),
            crypto::public_of(key.as_ref()).unwrap().as_ref(),
        ));
    }

    #[test]
    fn settings_store() {
        let db = Db::open(&tmpdir("set").join("s.xdb"), None).unwrap();
        assert!(db.get_setting("pkcs11-module").is_none());
        db.set_setting("pkcs11-module", "/lib/softhsm.so").unwrap();
        assert_eq!(
            db.get_setting("pkcs11-module").as_deref(),
            Some("/lib/softhsm.so")
        );
        db.set_setting("pkcs11-module", "/other.so").unwrap();
        assert_eq!(db.get_setting("pkcs11-module").as_deref(), Some("/other.so"));
        assert_eq!(db.get_setting("schema").as_deref(), Some("8"));
    }

    #[test]
    fn keys_crud() {
        let db = Db::open(&tmpdir("keys").join("k.xdb"), None).unwrap();
        let key = crypto::generate_key(NewKeyKind::EcP256).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        let id = db.insert_key("k1", &pem).unwrap();
        let keys = db.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, id);
        assert_eq!(keys[0].name, "k1");
        assert_eq!(keys[0].kind, "EC");
        assert_eq!(keys[0].curve, "P-256");
        assert!(keys[0].is_private());
        assert!(db.key_exists(&pem).unwrap());
        // the public PEM also identifies the same key
        let pub_pem = crypto::public_of(key.as_ref()).unwrap().public_key_to_pem().unwrap();
        assert!(db.key_exists(&pub_pem).unwrap());
        assert!(!db.key_exists(b"junk").unwrap());

        let got = db.get_key(id).unwrap().unwrap();
        assert_eq!(got.kind, "EC");
        db.delete_key(id).unwrap();
        assert!(db.list_keys().unwrap().is_empty());
    }

    #[test]
    fn certs_links_and_chain() {
        let db = Db::open(&tmpdir("certs").join("c.xdb"), None).unwrap();
        let (ca_key, ca, ca_pem) = ca_cert();
        let key_id = db
            .insert_key("ca key", &ca_key.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
        let ca_id = db.insert_cert(&ca_record(ca_pem)).unwrap();
        db.set_cert_refs(ca_id, Some(key_id), None).unwrap();

        let leaf_name = SubjectData {
            cn: "leaf".into(),
            ..Default::default()
        }
        .build_name()
        .unwrap();
        let leaf_key = crypto::generate_key(NewKeyKind::EcP256).unwrap();
        let leaf = crypto::build_certificate(
            &leaf_name,
            &leaf_key,
            &ca_key,
            Some(&ca),
            &CertParams {
                validity_days: 397,
                ..Default::default()
            },
        )
        .unwrap();
        let leaf_id = db
            .insert_cert(&CertRecord {
                id: 0,
                name: "leaf".into(),
                subject: "CN=leaf".into(),
                issuer: "CN=Test Root".into(),
                serial: "02".into(),
                not_after: "2027".into(),
                expires_days: 300,
                ca: false,
                key_id: None,
                issuer_id: Some(ca_id),
                pem: leaf.to_pem().unwrap(),
            })
            .unwrap();

        let chain = db.cert_chain(leaf_id).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].name, "leaf");
        assert_eq!(chain[1].name, "Test Root");

        let cas = db.list_ca_certs().unwrap();
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].id, ca_id);

        let got = db.get_cert(ca_id).unwrap().unwrap();
        assert_eq!(got.key_id, Some(key_id));
        assert!(got.ca);

        assert!(db.cert_exists(&leaf.to_pem().unwrap()).unwrap());
        db.delete_cert(ca_id).unwrap();
        assert!(!db.cert_exists(&ca.to_pem().unwrap()).unwrap());
        // deleting the CA nulls the reference, chain shrinks
        let chain = db.cert_chain(leaf_id).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn crls_and_revocation() {
        let db = Db::open(&tmpdir("crl").join("r.xdb"), None).unwrap();
        let (ca_key, ca, ca_pem) = ca_cert();
        let ca_id = db.insert_cert(&ca_record(ca_pem)).unwrap();
        db.insert_revoked(&RevokedRecord {
            ca_id,
            serial: "deadbeef".into(),
            revoked_at: String::new(),
            cert_id: None,
            reason: "keyCompromise".into(),
        })
        .unwrap();
        // duplicate ignored
        db.insert_revoked(&RevokedRecord {
            ca_id,
            serial: "deadbeef".into(),
            revoked_at: String::new(),
            cert_id: None,
            reason: String::new(),
        })
        .unwrap();
        assert_eq!(db.list_revoked(ca_id).unwrap().len(), 1);
        assert!(db
            .revoked_serials_by_ca()
            .unwrap()
            .get(&ca_id)
            .is_some_and(|s| s.contains("deadbeef")));
        assert_eq!(db.list_revoked(ca_id).unwrap()[0].reason, "keyCompromise");

        let crl_pem = crypto::build_crl(&ca, &ca_key, &[], 30, 1)
            .unwrap()
            .to_pem()
            .unwrap();
        let crl_id = db
            .insert_crl(&CrlRecord {
                id: 0,
                name: "Test Root CRL".into(),
                ca_id,
                issuer: String::new(),
                next_update: String::new(),
                entries: 0,
                pem: crl_pem,
            })
            .unwrap();
        assert_eq!(db.list_crls().unwrap().len(), 1);
        assert_eq!(db.get_crl(crl_id).unwrap().unwrap().ca_id, ca_id);
        db.delete_crl(crl_id).unwrap();
        assert!(db.list_crls().unwrap().is_empty());
        // deleting the CA cascades revocation rows away
        db.delete_cert(ca_id).unwrap();
        assert!(db.revoked_serials_by_ca().unwrap().is_empty());
    }

    /// Real XCA databases migrated through old program versions keep a
    /// legacy "revoked" table whose FK references certs(item); certs has no
    /// unique index on item, so SQLite raises "foreign key mismatch" on
    /// DELETE FROM certs as soon as foreign-key enforcement is on. Deleting
    /// a certificate must work in such a database (original XCA never turns
    /// the pragma on).
    #[test]
    fn delete_cert_tolerates_legacy_revoked_table() {
        let db = Db::open(&tmpdir("legacy").join("legacy.xdb"), None).unwrap();
        db.conn
            .execute_batch(
                "CREATE TABLE revoked(ca INTEGER, serial TEXT, \
                 FOREIGN KEY(ca) REFERENCES certs(item));",
            )
            .unwrap();
        let (_, _, ca_pem) = ca_cert();
        let ca_id = db.insert_cert(&ca_record(ca_pem.clone())).unwrap();
        db.delete_cert(ca_id).unwrap();
        assert!(!db.cert_exists(&ca_pem).unwrap());
    }

    /// The file xca-rs creates must be a faithful XCA database: same
    /// tables, base64-DER blobs, hashes and unlockable private keys.
    #[test]
    fn written_file_is_a_valid_xca_database() {
        let dir = tmpdir("interop");
        let path = dir.join("interop.xdb");
        let (ca_key, ca, ca_pem) = ca_cert();
        {
            let db = Db::open(&path, Some("pw")).unwrap();
            let key_pem = ca_key.private_key_to_pem_pkcs8().unwrap();
            let key_id = db.insert_key("root key", &key_pem).unwrap();
            let cert_id = db.insert_cert(&ca_record(ca_pem)).unwrap();
            db.set_cert_refs(cert_id, Some(key_id), None).unwrap();
        }

        let conn = Connection::open(&path).unwrap();
        for table in [
            "items",
            "public_keys",
            "private_keys",
            "certs",
            "requests",
            "crls",
            "revocations",
            "settings",
            "x509super",
            "templates",
            "tokens",
            "takeys",
            "authority",
            "token_mechanism",
        ] {
            assert!(table_exists(&conn, table).unwrap(), "missing table {table}");
        }
        let schema: String = conn
            .query_row("SELECT value FROM settings WHERE key_='schema'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(schema, "8");

        let (itype, name, date): (i64, String, String) = conn
            .query_row(
                "SELECT type, name, date FROM items WHERE type = 3",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(itype, xf::T_CERT);
        assert_eq!(name, "Test Root");
        assert_eq!(date.len(), 15);

        let (hash, serial, ca_flag, cert_b64, issuer): (i64, String, i64, String, Option<i64>) = conn
            .query_row(
                "SELECT hash, serial, ca, cert, issuer FROM certs",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        let der = xf::b64_decode(&cert_b64).unwrap();
        assert_eq!(&der, &ca.to_der().unwrap());
        assert_eq!(hash, xf::sha1_31(&der));
        assert_eq!(serial, crypto::serial_hex(ca.as_ref()));
        assert_eq!(ca_flag, 1);
        assert_eq!(issuer, None);

        let (spki_b64, len, key_hash): (String, i64, i64) = conn
            .query_row(
                "SELECT \"public\", len, hash FROM public_keys",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let spki = xf::b64_decode(&spki_b64).unwrap();
        assert_eq!(spki, crypto::public_of(ca_key.as_ref()).unwrap().public_key_to_der().unwrap());
        assert_eq!(len, 2048);
        assert_eq!(key_hash, xf::sha1_31(&spki));

        // the stored private key decrypts with the password (PBES2)
        let (priv_b64, own_pass): (String, i64) = conn
            .query_row("SELECT private, ownPass FROM private_keys", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(own_pass, xf::PT_COMMON);
        let key = PKey::private_key_from_pkcs8_passphrase(
            &xf::b64_decode(&priv_b64).unwrap(),
            b"pw",
        )
        .unwrap();
        assert!(crypto::same_public_key(
            crypto::public_of(key.as_ref()).unwrap().as_ref(),
            crypto::public_of(ca_key.as_ref()).unwrap().as_ref(),
        ));

        let pwhash: String = conn
            .query_row("SELECT value FROM settings WHERE key_='pwhash'", [], |r| r.get(0))
            .unwrap();
        assert!(xf::check_pwhash(&pwhash, "pw"));
    }

    /// A database created by the original XCA (synthesized here with the
    /// exact storage rules) opens natively.
    #[test]
    fn opens_database_of_original_xca() {
        let dir = tmpdir("orig");
        let path = dir.join("original.xdb");
        let (ca_key, ca, _) = ca_cert();
        let password = "s3cret";

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(xf::SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO settings(key_, value) VALUES ('pwhash', ?1)",
            params![xf::make_pwhash(password).unwrap()],
        )
        .unwrap();
        // one private key encrypted with the database password
        let enc = ca_key
            .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())
            .unwrap();
        let spki = crypto::public_of(ca_key.as_ref()).unwrap().public_key_to_der().unwrap();
        conn.execute("INSERT INTO items(id, name, type) VALUES (1, 'RNW Sign', 1)", []).unwrap();
        conn.execute(
            "INSERT INTO public_keys(item, type, hash, len, \"public\") VALUES (1,'RSA',0,2048,?1)",
            params![xf::b64_encode(&spki)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO private_keys(item, ownPass, private) VALUES (1, 0, ?1)",
            params![xf::b64_encode(&enc)],
        )
        .unwrap();
        // one cert linked to it
        conn.execute("INSERT INTO items(id, name, type) VALUES (2, 'cert', 3)", []).unwrap();
        conn.execute(
            "INSERT INTO certs(item, hash, iss_hash, serial, issuer, ca, cert) VALUES (2,0,0,'x',NULL,1,?1)",
            params![xf::b64_encode(&ca.to_der().unwrap())],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO x509super(item, subj_hash, pkey, key_hash) VALUES (2, 0, 1, 0)",
            [],
        )
        .unwrap();
        drop(conn);

        // no password → rejected, exactly like the original XCA
        assert!(matches!(Db::open(&path, None), Err(OpenError::WrongPassword)));
        let db = Db::open(&path, Some(password)).unwrap();
        let keys = db.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "RNW Sign");
        assert!(keys[0].is_private());
        let certs = db.list_certs().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].key_id, Some(keys[0].id));
    }

    /// Old xca-rs-specific databases are migrated transparently.
    #[test]
    fn migrates_old_own_format() {
        let dir = tmpdir("mig");
        let path = dir.join("old.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE keys(id INTEGER PRIMARY KEY, name TEXT, kind TEXT, size INTEGER, curve TEXT DEFAULT '', pem BLOB);
                 CREATE TABLE certs(id INTEGER PRIMARY KEY, name TEXT, subject TEXT, issuer TEXT, serial TEXT, not_after TEXT, expires_days INTEGER, ca INTEGER, key_id INTEGER, issuer_id INTEGER, pem BLOB);
                 CREATE TABLE reqs(id INTEGER PRIMARY KEY, name TEXT, subject TEXT, key_id INTEGER, pem BLOB);
                 CREATE TABLE crls(id INTEGER PRIMARY KEY, name TEXT, ca_id INTEGER, issuer TEXT, next_update TEXT, entries INTEGER, pem BLOB);
                 CREATE TABLE revoked(id INTEGER PRIMARY KEY, ca_id INTEGER, serial TEXT, revoked_at TEXT, cert_id INTEGER, reason TEXT DEFAULT '');
                 CREATE TABLE settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);",
            )
            .unwrap();
            let key = crypto::generate_key(NewKeyKind::Rsa2048).unwrap();
            conn.execute(
                "INSERT INTO keys(name, kind, size, curve, pem) VALUES ('old key','RSA',2048,'',?1)",
                params![key.private_key_to_pem_pkcs8().unwrap()],
            )
            .unwrap();
            let (_, _, ca_pem) = ca_cert();
            conn.execute(
                "INSERT INTO certs(name, subject, issuer, serial, not_after, expires_days, ca, pem) VALUES ('old ca','CN=x','CN=x','01','2027',300,1,?1)",
                params![ca_pem],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO revoked(ca_id, serial, revoked_at, reason) VALUES (1,'aa','2026','')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings(k, v) VALUES ('pkcs11-module','/lib/x.so')",
                [],
            )
            .unwrap();
        }

        let db = Db::open(&path, None).unwrap();
        assert!(path.is_file());
        assert!(dir.join("old.db.old.bak").is_file());
        let keys = db.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "old key");
        assert!(keys[0].is_private()); // no password → PBES2 with ""
        let certs = db.list_certs().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].name, "old ca");
        assert!(db
            .revoked_serials_by_ca()
            .unwrap()
            .values()
            .any(|s| s.contains("aa")));
        assert_eq!(db.get_setting("pkcs11-module").as_deref(), Some("/lib/x.so"));
    }

    /// Manual check against a real original-XCA database:
    ///   XCA_TEST_XDB=/path/to/main.xdb cargo test -- real_xca --ignored --nocapture
    #[test]
    #[ignore]
    fn real_xca_db() {
        let path = std::path::PathBuf::from(
            std::env::var("XCA_TEST_XDB").unwrap_or_else(|_| "/tmp/xca-main.xdb".into()),
        );
        if !path.exists() {
            eprintln!("skipping: {} not found", path.display());
            return;
        }
        // No password supplied → WrongPassword (the real DB has a pwhash).
        assert!(matches!(Db::open(&path, None), Err(OpenError::WrongPassword)));
        eprintln!("real database detected and locked, as expected");
    }

    /// Manual migration check against a real old-format xca-rs database:
    ///   XCA_TEST_OLD_DB=... [XCA_TEST_OLD_PW=...] \
    ///     cargo test -- real_old --ignored --nocapture
    #[test]
    #[ignore]
    fn real_old_xca_rs_db() {
        let path = std::path::PathBuf::from(
            std::env::var("XCA_TEST_OLD_DB")
                .unwrap_or_else(|_| "/tmp/xca-rs-old.db".into()),
        );
        if !path.exists() {
            eprintln!("skipping: {} not found", path.display());
            return;
        }
        let pw = std::env::var("XCA_TEST_OLD_PW").ok();
        match Db::open(&path, pw.as_deref()) {
            Err(OpenError::WrongPassword) => {
                eprintln!("encrypted old database: password required (as expected)");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
            Ok(db) => {
                eprintln!(
                    "migrated: keys={} certs={} reqs={} crls={} revoked={}",
                    db.list_keys().unwrap().len(),
                    db.list_certs().unwrap().len(),
                    db.list_reqs().unwrap().len(),
                    db.list_crls().unwrap().len(),
                    db.revoked_serials_by_ca().unwrap().values().map(|s| s.len()).sum::<usize>(),
                );
                assert!(path.with_file_name(format!(
                    "{}.old.bak",
                    path.file_name().unwrap().to_string_lossy()
                ))
                .is_file());
            }
        }
    }

    /// Creates /tmp/xca-ui-probe.xdb with one CA and one leaf certificate
    /// carrying SANs, for manual UI runs:
    ///   XCA_RS_DB=/tmp/xca-ui-probe.xdb XCA_UI_TEST=props ./target/debug/xca-rs
    #[test]
    #[ignore]
    fn make_ui_probe_db() {
        let path = std::path::PathBuf::from("/tmp/xca-ui-probe.xdb");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path, None).unwrap();
        let key = crypto::generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = SubjectData {
            cn: "Probe Root".into(),
            ..Default::default()
        }
        .build_name()
        .unwrap();
        let ca = crypto::build_certificate(
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
        let leaf = crypto::build_certificate(
            &SubjectData {
                cn: "probe.example.com".into(),
                ..Default::default()
            }
            .build_name()
            .unwrap(),
            &key,
            &key,
            Some(&ca),
            &CertParams {
                validity_days: 397,
                server_auth: true,
                san: vec![
                    "DNS:probe.example.com".into(),
                    "DNS:www.probe.example.com".into(),
                    "IP:10.0.0.1".into(),
                    "email:admin@example.com".into(),
                    "URI:https://example.com".into(),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        db.insert_key("probe key", &key.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
        let ca_id = db
            .insert_cert(&CertRecord {
            id: 0,
            name: "Probe Root".into(),
            subject: String::new(),
            issuer: String::new(),
            serial: String::new(),
            not_after: String::new(),
            expires_days: 0,
            ca: true,
            key_id: None,
            issuer_id: None,
            pem: ca.to_pem().unwrap(),
        })
            .unwrap();
        let leaf_id = db
            .insert_cert(&CertRecord {
            id: 0,
            name: "A probe leaf".into(),
            subject: String::new(),
            issuer: String::new(),
            serial: String::new(),
            not_after: String::new(),
            expires_days: 0,
            ca: false,
            key_id: None,
            issuer_id: None,
            pem: leaf.to_pem().unwrap(),
        })
            .unwrap();
        // link the leaf to its issuer so the UI tree has a hierarchy
        db.set_cert_refs(leaf_id, None, Some(ca_id)).unwrap();
        eprintln!("written: {}", path.display());
    }

    /// Probe mirroring the user's signing scenario: a password-protected
    /// database with a CA whose private key is linked to it, so the CA
    /// shows up in the "Signed by" combo of the New Certificate dialog.
    #[test]
    fn make_sign_probe_db() {
        let path = std::path::PathBuf::from("/tmp/xca-sign-probe.xdb");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path, None).unwrap();
        let key = crypto::generate_key(NewKeyKind::Rsa2048).unwrap();
        let name = SubjectData {
            cn: "Sign Root".into(),
            ..Default::default()
        }
        .build_name()
        .unwrap();
        let ca = crypto::build_certificate(
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
        let key_id = db
            .insert_key("sign root key", &key.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
        let ca_id = db
            .insert_cert(&CertRecord {
                id: 0,
                name: "Sign Root".into(),
                subject: String::new(),
                issuer: String::new(),
                serial: String::new(),
                not_after: String::new(),
                expires_days: 0,
                ca: true,
                key_id: None,
                issuer_id: None,
                pem: ca.to_pem().unwrap(),
            })
            .unwrap();
        db.set_cert_refs(ca_id, Some(key_id), None).unwrap();
        eprintln!("written: {}", path.display());
    }
}
