//! SQLite-backed storage for keys, certificates, requests and CRLs.
//!
//! The original XCA keeps everything in its own encrypted `.xdb` database.
//! This rewrite uses SQLCipher (AES-encrypted SQLite, bundled): a database
//! created with a password is encrypted at rest; `None` keeps it plain.
//! The file lives under the XDG data dir.

use rusqlite::{Connection, params};
use std::path::Path;

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
}

#[derive(Clone, Debug)]
pub struct CertRecord {
    pub id: i64,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
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
    pub cert_id: Option<i64>,
    pub reason: String,
}

/// True when the error means "wrong or missing password" for SQLCipher.
pub fn is_not_database(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ffi::ErrorCode::NotADatabase,
                ..
            },
            _,
        )
    )
}

pub struct Db {
    conn: Connection,
}

const SCHEMA: &str = "PRAGMA foreign_keys=ON;
     CREATE TABLE IF NOT EXISTS keys(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        size INTEGER NOT NULL,
        curve TEXT NOT NULL DEFAULT '',
        pem BLOB NOT NULL
     );
     CREATE TABLE IF NOT EXISTS certs(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        subject TEXT NOT NULL,
        issuer TEXT NOT NULL,
        serial TEXT NOT NULL,
        not_after TEXT NOT NULL,
        expires_days INTEGER NOT NULL,
        ca INTEGER NOT NULL DEFAULT 0,
        key_id INTEGER,
        issuer_id INTEGER,
        pem BLOB NOT NULL,
        FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE SET NULL,
        FOREIGN KEY(issuer_id) REFERENCES certs(id) ON DELETE SET NULL
     );
     CREATE TABLE IF NOT EXISTS reqs(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        subject TEXT NOT NULL,
        key_id INTEGER,
        pem BLOB NOT NULL,
        FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE SET NULL
     );
     CREATE TABLE IF NOT EXISTS crls(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        ca_id INTEGER NOT NULL,
        issuer TEXT NOT NULL,
        next_update TEXT NOT NULL,
        entries INTEGER NOT NULL DEFAULT 0,
        pem BLOB NOT NULL,
        FOREIGN KEY(ca_id) REFERENCES certs(id) ON DELETE CASCADE
     );
     CREATE TABLE IF NOT EXISTS revoked(
        id INTEGER PRIMARY KEY,
        ca_id INTEGER NOT NULL,
        serial TEXT NOT NULL,
        revoked_at TEXT NOT NULL,
        cert_id INTEGER,
        reason TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(ca_id) REFERENCES certs(id) ON DELETE CASCADE,
        UNIQUE(ca_id, serial)
     );
     CREATE TABLE IF NOT EXISTS settings(
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL
     );";

impl Db {
    pub fn open(path: &Path, password: Option<&str>) -> Result<Db, rusqlite::Error> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        if let Some(pw) = password {
            let esc = pw.replace('\'', "''");
            conn.execute_batch(&format!("PRAGMA key = '{esc}';"))?;
        }
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    /// Copy the whole (plain) database into an encrypted file and swap it in
    /// place. The current connection keeps using the old plain file until the
    /// application restarts; the caller should prompt for a restart.
    pub fn encrypt_copy(&self, path: &Path, password: &str) -> Result<(), String> {
        let tmp = path.with_extension("xca-enc-tmp");
        for p in [
            tmp.clone(),
            tmp.with_extension("xca-enc-tmp-wal"),
            tmp.with_extension("xca-enc-tmp-shm"),
        ] {
            let _ = std::fs::remove_file(&p);
        }
        let tmp_esc = tmp.to_string_lossy().replace('\'', "''");
        let pw_esc = password.replace('\'', "''");
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(&format!(
            "ATTACH DATABASE '{tmp_esc}' AS xca_enc KEY '{pw_esc}';
             SELECT sqlcipher_export('xca_enc');
             DETACH DATABASE xca_enc;"
        ))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;
        conn.close().map_err(|(_, e)| e.to_string())?;
        for p in [
            tmp.with_extension("xca-enc-tmp-wal"),
            tmp.with_extension("xca-enc-tmp-shm"),
        ] {
            let _ = std::fs::remove_file(&p);
        }
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;
        Ok(())
    }

    // ---- settings ----

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT v FROM settings WHERE k = ?1", params![key], |r| {
                r.get(0)
            })
            .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO settings(k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    // ---- keys ----

    pub fn insert_key(
        &self,
        name: &str,
        kind: &str,
        size: i32,
        curve: &str,
        pem: &[u8],
    ) -> Result<i64, rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO keys(name, kind, size, curve, pem) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, kind, size, curve, pem],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRecord>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, kind, size, curve, pem FROM keys ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(KeyRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                size: r.get(3)?,
                curve: r.get(4)?,
                pem: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_key(&self, id: i64) -> Result<Option<KeyRecord>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, kind, size, curve, pem FROM keys WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |r| {
            Ok(KeyRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                size: r.get(3)?,
                curve: r.get(4)?,
                pem: r.get(5)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn delete_key(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn
            .execute("DELETE FROM keys WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn key_exists(&self, pem: &[u8]) -> Result<bool, rusqlite::Error> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM keys WHERE pem = ?1",
            params![pem],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    // ---- certificates ----

    pub fn insert_cert(&self, rec: &CertRecord) -> Result<i64, rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO certs(name, subject, issuer, serial, not_after, expires_days, ca, key_id, issuer_id, pem)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                rec.name,
                rec.subject,
                rec.issuer,
                rec.serial,
                rec.not_after,
                rec.expires_days,
                rec.ca as i64,
                rec.key_id,
                rec.issuer_id,
                rec.pem
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_certs(&self) -> Result<Vec<CertRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, subject, issuer, serial, not_after, expires_days, ca, key_id, issuer_id, pem
             FROM certs ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CertRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                subject: r.get(2)?,
                issuer: r.get(3)?,
                serial: r.get(4)?,
                not_after: r.get(5)?,
                expires_days: r.get(6)?,
                ca: r.get::<_, i64>(7)? != 0,
                key_id: r.get(8)?,
                issuer_id: r.get(9)?,
                pem: r.get(10)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_cert(&self, id: i64) -> Result<Option<CertRecord>, rusqlite::Error> {
        let rec = self.cert_query("WHERE id = ?1", params![id])?;
        Ok(rec.into_iter().next())
    }

    pub fn list_ca_certs(&self) -> Result<Vec<CertRecord>, rusqlite::Error> {
        self.cert_query("WHERE ca != 0 ORDER BY name", params![])
    }

    fn cert_query<P: rusqlite::Params>(
        &self,
        tail: &str,
        p: P,
    ) -> Result<Vec<CertRecord>, rusqlite::Error> {
        let sql = format!(
            "SELECT id, name, subject, issuer, serial, not_after, expires_days, ca, key_id, issuer_id, pem
             FROM certs {tail}"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(p, |r| {
            Ok(CertRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                subject: r.get(2)?,
                issuer: r.get(3)?,
                serial: r.get(4)?,
                not_after: r.get(5)?,
                expires_days: r.get(6)?,
                ca: r.get::<_, i64>(7)? != 0,
                key_id: r.get(8)?,
                issuer_id: r.get(9)?,
                pem: r.get(10)?,
            })
        })?;
        rows.collect()
    }

    pub fn delete_cert(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn
            .execute("DELETE FROM certs WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn cert_exists(&self, pem: &[u8]) -> Result<bool, rusqlite::Error> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM certs WHERE pem = ?1",
            params![pem],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Chain from the given certificate up to its root (self-signed ancestor).
    pub fn cert_chain(&self, id: i64) -> Result<Vec<CertRecord>, rusqlite::Error> {
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

    pub fn insert_req(&self, rec: &ReqRecord) -> Result<i64, rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO reqs(name, subject, key_id, pem) VALUES (?1, ?2, ?3, ?4)",
            params![rec.name, rec.subject, rec.key_id, rec.pem],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_reqs(&self) -> Result<Vec<ReqRecord>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, subject, key_id, pem FROM reqs ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(ReqRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                subject: r.get(2)?,
                key_id: r.get(3)?,
                pem: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_req(&self, id: i64) -> Result<Option<ReqRecord>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, subject, key_id, pem FROM reqs WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |r| {
            Ok(ReqRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                subject: r.get(2)?,
                key_id: r.get(3)?,
                pem: r.get(4)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn delete_req(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn
            .execute("DELETE FROM reqs WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn req_exists(&self, pem: &[u8]) -> Result<bool, rusqlite::Error> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM reqs WHERE pem = ?1",
            params![pem],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    // ---- CRLs ----

    pub fn insert_crl(&self, rec: &CrlRecord) -> Result<i64, rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO crls(name, ca_id, issuer, next_update, entries, pem)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![rec.name, rec.ca_id, rec.issuer, rec.next_update, rec.entries, rec.pem],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_crls(&self) -> Result<Vec<CrlRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, ca_id, issuer, next_update, entries, pem FROM crls ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CrlRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                ca_id: r.get(2)?,
                issuer: r.get(3)?,
                next_update: r.get(4)?,
                entries: r.get(5)?,
                pem: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_crl(&self, id: i64) -> Result<Option<CrlRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, ca_id, issuer, next_update, entries, pem FROM crls WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |r| {
            Ok(CrlRecord {
                id: r.get(0)?,
                name: r.get(1)?,
                ca_id: r.get(2)?,
                issuer: r.get(3)?,
                next_update: r.get(4)?,
                entries: r.get(5)?,
                pem: r.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn delete_crl(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn
            .execute("DELETE FROM crls WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---- revocation ----

    pub fn insert_revoked(&self, rec: &RevokedRecord) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR IGNORE INTO revoked(ca_id, serial, revoked_at, cert_id, reason)
             VALUES (?1,?2,?3,?4,?5)",
            params![rec.ca_id, rec.serial, rec.revoked_at, rec.cert_id, rec.reason],
        )?;
        Ok(())
    }

    pub fn list_revoked(&self, ca_id: i64) -> Result<Vec<RevokedRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT ca_id, serial, revoked_at, cert_id, reason FROM revoked
             WHERE ca_id = ?1 ORDER BY serial",
        )?;
        let rows = stmt.query_map(params![ca_id], |r| {
            Ok(RevokedRecord {
                ca_id: r.get(0)?,
                serial: r.get(1)?,
                revoked_at: r.get(2)?,
                cert_id: r.get(3)?,
                reason: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// All revoked serials, for the status badges in the certificate list.
    pub fn revoked_serials(&self) -> Result<Vec<String>, rusqlite::Error> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT serial FROM revoked")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdb(name: &str) -> Db {
        let dir = std::env::temp_dir().join(format!("xca-rs-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Db::open(&dir.join(name), None).unwrap()
    }

    #[test]
    fn encrypted_database_roundtrip() {
        let dir = std::env::temp_dir().join(format!("xca-rs-enc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("enc.db");
        let _ = std::fs::remove_file(&path);

        {
            let db = Db::open(&path, Some("secret")).unwrap();
            db.insert_key("k", "RSA", 2048, "", b"pem").unwrap();
        }
        // File is encrypted: plain open fails, wrong password fails too.
        let e1 = Db::open(&path, None).err().expect("plain open must fail");
        assert!(is_not_database(&e1));
        let e2 = Db::open(&path, Some("wrong"))
            .err()
            .expect("wrong password must fail");
        assert!(is_not_database(&e2));
        let db = Db::open(&path, Some("secret")).unwrap();
        let keys = db.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "k");
    }

    #[test]
    fn settings_store() {
        let db = tmpdb("settings.db");
        assert!(db.get_setting("pkcs11-module").is_none());
        db.set_setting("pkcs11-module", "/lib/softhsm.so").unwrap();
        assert_eq!(
            db.get_setting("pkcs11-module").as_deref(),
            Some("/lib/softhsm.so")
        );
        db.set_setting("pkcs11-module", "/other.so").unwrap();
        assert_eq!(db.get_setting("pkcs11-module").as_deref(), Some("/other.so"));
    }

    #[test]
    fn crls_and_revocation() {
        let db = tmpdb("crls.db");
        let ca = CertRecord {
            id: 0,
            name: "ca".into(),
            subject: "CN=ca".into(),
            issuer: "CN=ca".into(),
            serial: "aa".into(),
            not_after: "2027".into(),
            expires_days: 300,
            ca: true,
            key_id: None,
            issuer_id: None,
            pem: b"ca".to_vec(),
        };
        let ca_id = db.insert_cert(&ca).unwrap();
        db.insert_revoked(&RevokedRecord {
            ca_id,
            serial: "deadbeef".into(),
            revoked_at: "now".into(),
            cert_id: None,
            reason: "".into(),
        })
        .unwrap();
        // duplicate ignored
        db.insert_revoked(&RevokedRecord {
            ca_id,
            serial: "deadbeef".into(),
            revoked_at: "now".into(),
            cert_id: None,
            reason: "".into(),
        })
        .unwrap();
        assert_eq!(db.list_revoked(ca_id).unwrap().len(), 1);
        assert_eq!(db.revoked_serials().unwrap(), vec!["deadbeef".to_string()]);

        let crl = CrlRecord {
            id: 0,
            name: "ca CRL".into(),
            ca_id,
            issuer: "CN=ca".into(),
            next_update: "soon".into(),
            entries: 1,
            pem: b"crl".to_vec(),
        };
        let crl_id = db.insert_crl(&crl).unwrap();
        assert_eq!(db.list_crls().unwrap().len(), 1);
        assert_eq!(db.get_crl(crl_id).unwrap().unwrap().entries, 1);
        db.delete_crl(crl_id).unwrap();
        assert!(db.list_crls().unwrap().is_empty());
        // deleting the CA cascades revocation rows away
        db.delete_cert(ca_id).unwrap();
        assert!(db.revoked_serials().unwrap().is_empty());
    }


    #[test]
    fn keys_crud() {
        let db = tmpdb("keys.db");
        let id = db.insert_key("k1", "RSA", 2048, "", b"pem").unwrap();
        let keys = db.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, id);
        assert_eq!(keys[0].name, "k1");
        let got = db.get_key(id).unwrap().unwrap();
        assert_eq!(got.kind, "RSA");
        assert_eq!(got.size, 2048);
        assert!(db.key_exists(b"pem").unwrap());
        assert!(!db.key_exists(b"other").unwrap());
        db.delete_key(id).unwrap();
        assert!(db.list_keys().unwrap().is_empty());
    }

    #[test]
    fn certs_and_chain() {
        let db = tmpdb("certs.db");
        let ca = CertRecord {
            id: 0,
            name: "ca".into(),
            subject: "CN=ca".into(),
            issuer: "CN=ca".into(),
            serial: "01".into(),
            not_after: "2027".into(),
            expires_days: 300,
            ca: true,
            key_id: None,
            issuer_id: None,
            pem: b"ca".to_vec(),
        };
        let ca_id = db.insert_cert(&ca).unwrap();
        let leaf = CertRecord {
            id: 0,
            name: "leaf".into(),
            subject: "CN=leaf".into(),
            issuer: "CN=ca".into(),
            serial: "02".into(),
            not_after: "2027".into(),
            expires_days: 300,
            ca: false,
            key_id: None,
            issuer_id: Some(ca_id),
            pem: b"leaf".to_vec(),
        };
        let leaf_id = db.insert_cert(&leaf).unwrap();
        let chain = db.cert_chain(leaf_id).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].name, "leaf");
        assert_eq!(chain[1].name, "ca");
        // deleting the CA nulls the reference, chain shrinks
        db.delete_cert(ca_id).unwrap();
        assert!(db.cert_exists(b"ca").unwrap() == false);
        let chain = db.cert_chain(leaf_id).unwrap();
        assert_eq!(chain.len(), 1);
    }
}
