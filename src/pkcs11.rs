//! PKCS#11 hardware token support via the `cryptoki` crate.
//!
//! Tokens are key sources like XCA's: a private key stays on the token and
//! never enters the database. Listing works for every key type; signing
//! (and therefore creating a CA with an on-token key) supports RSA
//! (CKM_SHA256_RSA_PKCS) and Ed25519 (pure EdDSA).

use crate::crypto::{
    assemble_cert_der, cert_builder, cert_tbs_der, CertParams, CryptoResult, SigAlg,
};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use openssl::pkey::{PKey, Public};
use openssl::x509::{X509, X509Name};
use std::ops::Deref;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub enum TokenKeyKind {
    Rsa(u32),
    Ed25519,
    Other(String),
}

impl TokenKeyKind {
    pub fn label(&self) -> String {
        match self {
            Self::Rsa(bits) => format!("RSA {bits}"),
            Self::Ed25519 => "Ed25519".into(),
            Self::Other(t) => t.clone(),
        }
    }

    fn sig_alg(&self) -> Option<SigAlg> {
        match self {
            Self::Rsa(_) => Some(SigAlg::RsaSha256),
            Self::Ed25519 => Some(SigAlg::Ed25519),
            Self::Other(_) => None,
        }
    }
}

/// A live connection to one token (slot) of a PKCS#11 module.
pub struct Token {
    _ctx: Pkcs11,
    session: cryptoki::session::Session,
    pub token_label: String,
}

/// One private key found on the token, with its public parts resolved.
#[derive(Clone)]
pub struct TokenKey {
    pub handle: ObjectHandle,
    pub label: String,
    pub id_hex: String,
    pub kind: TokenKeyKind,
    /// SubjectPublicKeyInfo DER (the public half of the token key).
    pub spki: Option<Vec<u8>>,
}

pub fn connect(module: &str, pin: &str) -> CryptoResult<Rc<Token>> {
    let ctx = Pkcs11::new(module).map_err(|e| format!("Cannot load PKCS#11 module: {e}"))?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| format!("Cannot initialize module: {e}"))?;
    let slots = ctx
        .get_slots_with_token()
        .map_err(|e| format!("No token slots: {e}"))?;
    let slot = slots
        .into_iter()
        .next()
        .ok_or("No token present in any slot")?;
    let slot_id = slot.id();
    let label = ctx
        .get_token_info(slot)
        .map(|info| info.label().trim().to_string())
        .unwrap_or_else(|_| format!("slot {slot_id}"));
    let session = ctx
        .open_ro_session(slot)
        .map_err(|e| format!("Cannot open session: {e}"))?;
    let auth = AuthPin::from(pin.to_string());
    session
        .login(UserType::User, Some(&auth))
        .map_err(|e| format!("Login failed (wrong PIN?): {e}"))?;
    Ok(Rc::new(Token {
        _ctx: ctx,
        session,
        token_label: label,
    }))
}

fn attr_bytes(attrs: &[Attribute], want: &AttributeType) -> Option<Vec<u8>> {
    attrs.iter().find_map(|a| match a {
        Attribute::Label(v) if *want == AttributeType::Label => Some(v.clone()),
        Attribute::Id(v) if *want == AttributeType::Id => Some(v.clone()),
        Attribute::Modulus(v) if *want == AttributeType::Modulus => Some(v.clone()),
        Attribute::PublicExponent(v) if *want == AttributeType::PublicExponent => Some(v.clone()),
        Attribute::Value(v) if *want == AttributeType::Value => Some(v.clone()),
        _ => None,
    })
}

/// List private token keys; the public half is resolved from the matching
/// public-key object (matched by CKA_ID).
pub fn list_keys(token: &Token) -> CryptoResult<Vec<TokenKey>> {
    let privates = token
        .session
        .find_objects(&[Attribute::Token(true), Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .map_err(|e| format!("Cannot enumerate keys: {e}"))?;
    let publics = token
        .session
        .find_objects(&[Attribute::Token(true), Attribute::Class(ObjectClass::PUBLIC_KEY)])
        .unwrap_or_default();

    let mut public_info: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (id, spki)
    for handle in publics {
        let attrs = token
            .session
            .get_attributes(
                handle,
                &[
                    AttributeType::Id,
                    AttributeType::KeyType,
                    AttributeType::Modulus,
                    AttributeType::PublicExponent,
                    AttributeType::Value,
                ],
            )
            .unwrap_or_default();
        let key_type = attrs.iter().find_map(|a| match a {
            Attribute::KeyType(t) => Some(*t),
            _ => None,
        });
        let spki = match key_type {
            Some(cryptoki::object::KeyType::RSA) => match (
                attr_bytes(&attrs, &AttributeType::Modulus),
                attr_bytes(&attrs, &AttributeType::PublicExponent),
            ) {
                (Some(n), Some(e)) => Some(crate::crypto::rsa_spki_der(&n, &e)),
                _ => None,
            },
            Some(cryptoki::object::KeyType::EC_EDWARDS) => {
                attr_bytes(&attrs, &AttributeType::Value)
                    .map(|v| crate::crypto::ed25519_spki_der(&v))
            }
            _ => None,
        };
        if let (Some(id), Some(spki)) = (attr_bytes(&attrs, &AttributeType::Id), spki) {
            public_info.push((id, spki));
        }
    }

    let mut out = Vec::new();
    for handle in privates {
        let attrs = token
            .session
            .get_attributes(
                handle,
                &[
                    AttributeType::Label,
                    AttributeType::Id,
                    AttributeType::KeyType,
                    AttributeType::ModulusBits,
                ],
            )
            .map_err(|e| format!("Cannot read key attributes: {e}"))?;
        let label = attr_bytes(&attrs, &AttributeType::Label)
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_else(|| "(no label)".into());
        let id = attr_bytes(&attrs, &AttributeType::Id).unwrap_or_default();
        let id_hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let kind = attrs.iter().find_map(|a| match a {
            Attribute::KeyType(cryptoki::object::KeyType::RSA) => {
                Some(TokenKeyKind::Rsa(bits_of(&attrs)))
            }
            Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS) => {
                Some(TokenKeyKind::Ed25519)
            }
            Attribute::KeyType(t) => Some(TokenKeyKind::Other(format!("{t:?}"))),
            _ => None,
        })
        .unwrap_or_else(|| TokenKeyKind::Other("unknown".into()));
        let spki = public_info
            .iter()
            .find(|(pid, _)| *pid == id)
            .map(|(_, spki)| spki.clone());
        out.push(TokenKey {
            handle,
            label,
            id_hex,
            kind,
            spki,
        });
    }
    Ok(out)
}

fn bits_of(attrs: &[Attribute]) -> u32 {
    attrs
        .iter()
        .find_map(|a| match a {
            Attribute::ModulusBits(bits) => u32::try_from(*bits.deref()).ok(),
            _ => None,
        })
        .unwrap_or(0)
}

/// Sign raw data with a token key.
pub fn token_sign(token: &Token, key: &TokenKey, data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mech = match key.kind {
        TokenKeyKind::Rsa(_) => Mechanism::Sha256RsaPkcs,
        TokenKeyKind::Ed25519 => {
            Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))
        }
        TokenKeyKind::Other(ref t) => {
            return Err(format!("Signing with token keys of type {t} is not supported yet"));
        }
    };
    token
        .session
        .sign(&mech, key.handle, data)
        .map_err(|e| format!("Token signing failed: {e}"))
}

/// Build a self-signed certificate whose private key stays on the token:
/// the TBS part is built locally, signed on the token, and the final DER
/// is assembled by hand.
pub fn build_certificate_on_token(
    token: &Token,
    key: &TokenKey,
    subject: &X509Name,
    params: &CertParams,
) -> CryptoResult<X509> {
    let spki = key
        .spki
        .as_ref()
        .ok_or("The public part of this token key could not be read (unsupported key type)")?;
    let pubkey = PKey::<Public>::public_key_from_der(spki)
        .map_err(|e| format!("Token public key is malformed: {e}"))?;
    let alg = key
        .kind
        .sig_alg()
        .ok_or("Signing with this token key type is not supported")?;

    let builder = cert_builder(subject, pubkey.as_ref(), None, params)?;
    let unsigned = builder.build();
    let tbs = cert_tbs_der(unsigned.as_ref())?;
    let sig = token_sign(token, key, &tbs)?;
    let der = assemble_cert_der(&tbs, alg, &sig);
    let cert = X509::from_der(&der).map_err(|e| format!("Assembled certificate is invalid: {e}"))?;
    if !cert.verify(pubkey.as_ref()).unwrap_or(false) {
        return Err("Token signature verification failed".into());
    }
    Ok(cert)
}
